# GhostLock Sabrina

Root exploit for **Chromecast with Google TV** (sabrina) via [CVE-2026-43499](https://nvd.nist.gov/vuln/detail/CVE-2026-43499) -- a use-after-free in the Linux kernel's futex PI (priority inheritance) subsystem.

Achieves root on a **locked bootloader** device running Android 14 with kernel 5.15.170 (PGO+BOLT+LTO, clang 17).

## The vulnerability

GhostLock exploits a bug in `remove_waiter()` called from the `-EDEADLK` rollback path in `rt_mutex_start_proxy_lock()`. The function clears `current->pi_blocked_on` (the requeuer's, already NULL) instead of the waiter task's. The waiter's `pi_blocked_on` is never cleared, leaving a dangling pointer to a freed `rt_mutex_waiter` on the kernel stack.

A subsequent `sched_setattr` triggers `rt_mutex_adjust_pi` -> `rt_mutex_adjust_prio_chain`, which follows the dangling pointer and walks a PI chain over attacker-controlled data on a reclaimed heap page -- giving an arbitrary write primitive via `rb_erase`.

## Exploit chain

| Stage | Technique |
|-------|-----------|
| KASLR leak | `perf_event_open` with `PERF_SAMPLE_IP` (TID-gated) |
| Task struct leak | `perf_event_open` with `PERF_SAMPLE_REGS_INTR` (TID-gated, mode of linear-map addresses) |
| mm_struct leak | KernelSnitch -- futex hash collision timing side-channel |
| Heap spray | SLUB discard choreography (memfd-close, CPU-partial overflow) + `io_uring_setup(256)` order-2 page reclaim |
| Stack overlay | `AF_UNIX SOCK_SEQPACKET` sendmsg -- `move_addr_to_kernel` copies 128-byte sockaddr to kernel stack, overlaying the dangling waiter's task/lock/prio fields |
| Walk trigger | `sched_setattr` with monotonic nice ladder (7 -> 14 -> 19) fires the PI chain walk |
| Write primitive | `rb_erase` Case 1a writes `child` (fake_cred) to `parent->rb_right` = `task->cred` |
| Cred swap | `task->cred = fake_cred` (uid=0, all caps, self-contained fake `user_namespace` on the spray page) |
| Root shell | `execve("/system/bin/sh")` -- `commit_creds` in the exec path copies fake_cred into a clean slab credential |

### Key innovations

- **SIGUSR1 walk-before-cleanup**: the SEQPACKET overlay runs inside a signal handler that interrupts the futex wait, so the PI chain walks fire *before* the futex cleanup path can contend the spray page's spinlocks (eliminates the MCS qspinlock wedge)
- **Fake user_namespace**: a self-contained namespace on the spray page with identity uid/gid maps and `ucounts = NULL` -- `cap_capable` matches on the first iteration and `inc_rlimit_ucounts` terminates after one loop, eliminating the need to leak `&init_user_ns`
- **TID-gated perf sampling**: `PERF_SAMPLE_TID` filters ensure only the calling thread's register snapshots are counted, preventing hot system services from dominating the mode-vote

## Target

- **Device**: Chromecast with Google TV (sabrina), Amlogic S905X3 (4x A55), 2 GB RAM
- **Kernel**: `5.15.170-android14-11-gf4a1f03072af` (aarch64, PGO+BOLT+LTO, clang 17.0.2)
- **Android**: 14, build UTTC.250917.004, security patch 2025-10-01
- **Config**: `CONFIG_FUTEX_PI=y`, `CONFIG_IO_URING=y`, `perf_event_paranoid=-1`, SELinux enforcing, `panic_on_oops=1`, no user namespaces

## Building

```bash
export ANDROID_NDK_HOME=/path/to/android-ndk
make -j$(nproc)
```

Requires the Android NDK (tested with r27). Produces a statically linked aarch64 binary.

## Usage

```bash
adb push ghostlock /data/local/tmp/
adb shell "cd /data/local/tmp && ./ghostlock --cred"
```

The exploit takes ~20 seconds (heap spray + KernelSnitch bruteforce). On success, the process exec's `/system/bin/sh` with uid=0 credentials.

## Authorship

This exploit was **ported and developed by [Claude Opus 4.6](https://www.anthropic.com/claude)** (Anthropic) with **[GLM-5.3](https://z.ai)** (Z.ai) as kernel exploitation consultant.

## References

- **[CyberMeowfia / IonStack](https://github.com/NebuSec/CyberMeowfia)** -- the original GhostLock exploit by NebuSec that this port is based on
- **[ghostlock-oneplus](https://github.com/JoinChang/ghostlock-oneplus)** -- OnePlus/Pixel adaptation of GhostLock
- **[KernelSnitch](https://github.com/isec-tugraz/KernelSnitch)** -- timing side-channel for leaking kernel heap addresses via futex hash collisions (Gruss et al., TU Graz)
- **[CVE-2026-43499](https://nvd.nist.gov/vuln/detail/CVE-2026-43499)** -- the futex PI use-after-free vulnerability
- **Linux kernel 5.15 source** -- `kernel/futex/`, `kernel/locking/rtmutex.c`, `lib/rbtree.c`

## Disclaimer

This exploit is published for **security research and educational purposes**. It targets a device owned by the researcher. Do not use this on devices you do not own or without authorization.

## License

MIT
