# GhostLock Sabrina

Root exploit for **Chromecast with Google TV** (sabrina) via [CVE-2026-43499](https://nvd.nist.gov/vuln/detail/CVE-2026-43499) -- a use-after-free in the Linux kernel's futex PI (priority inheritance) subsystem.

Achieves root on a **locked bootloader** device running Android 14 with kernel 5.15.170 (PGO+BOLT+LTO, clang 17).

## The vulnerability

GhostLock exploits a bug in `remove_waiter()` called from the `-EDEADLK` rollback path in `rt_mutex_start_proxy_lock()`. The function clears `current->pi_blocked_on` (the requeuer's, already NULL) instead of the waiter task's. The waiter's `pi_blocked_on` is never cleared, leaving a dangling pointer to a freed `rt_mutex_waiter` on the kernel stack.

A subsequent `sched_setattr` triggers `rt_mutex_adjust_pi` -> `rt_mutex_adjust_prio_chain`, which follows the dangling pointer and walks a PI chain over attacker-controlled data on a reclaimed heap page -- giving an arbitrary write primitive via `rb_erase`.

## Exploit chain

| Stage | Technique |
|-------|-----------|
| KASLR leak | `perf_event_open` with `PERF_SAMPLE_IP` (TID-gated) — min kernel IP is in `.entry.text` (+0x10000), `_text` is 2MB-aligned and the KASLR slide is a 2MB multiple, so `min_ip & ~0x1fffff` recovers the runtime `_text` exactly |
| Task struct leak | `perf_event_open` with `PERF_SAMPLE_REGS_INTR` (TID-gated, mode of linear-map addresses) |
| Symbol-table validation | perf-samples `&init_user_ns` out of `security_capable()`'s register arguments during a `setpriority(-20)` storm and matches it against `kaslr_base + off_init_user_ns` — proves the running kernel's `.data/.bss` layout matches the offsets table before any blind write |
| mm_struct leak | KernelSnitch -- futex hash collision timing side-channel |
| Heap spray | SLUB discard choreography (memfd-close, CPU-partial overflow) + `io_uring_setup(256)` order-2 page reclaim |
| Stack overlay | `AF_UNIX SOCK_SEQPACKET` sendmsg -- `move_addr_to_kernel` copies 128-byte sockaddr to kernel stack, overlaying the dangling waiter's task/lock/prio fields |
| Walk trigger | `sched_setattr` with monotonic nice ladder (7 -> 14 -> 19) fires the PI chain walk, one per overlay round |
| Write primitive | `rb_erase` Case 1: `{pc=(TARGET-8)|1, right=VALUE, left=0}` writes `VALUE` to `*TARGET` (plus `pc` to `*VALUE` when VALUE≠0); `{right=0}` is a clean 8-byte **zero**-write at TARGET with no side store |
| SELinux off (walk 0) | 8-byte zero at `selinux_state` clears `enforcing`, `checkreqprot`, `initialized` and `policycap[0..4]` — `avc_denied()` never denies (enforcing=0) and `security_compute_av()` short-circuits to allow-all (!initialized), so the post-swap kernel-SID (`u:r:kernel`) stops mattering |
| Cred swap (walks 1+2) | `task->cred = fake_cred` and `task->real_cred = fake_cred` (uid=0, caps FULL, self-contained fake `user_namespace` on the spray page; both writes required — `commit_creds()` at exec BUG_ONs unless cred == real_cred) |
| Root battery | raw-syscall-only probes (uid/SELinux/`/proc/1`/`/dev/kmsg`/wifi/packages/`/data/data`/kallsyms) into `/data/local/tmp/.ghostlock_out` |
| Root shell | `execve("/system/bin/sh")` — `commit_creds` in the exec path copies fake_cred into a clean slab credential; gated on all planned erases having landed |

### Key innovations

- **SIGUSR1 walk-before-cleanup**: the SEQPACKET overlay runs inside a signal handler that interrupts the futex wait, so the PI chain walks fire *before* the futex cleanup path can contend the spray page's spinlocks (eliminates the MCS qspinlock wedge)
- **Three writes from one reclaim (mode 7)**: SELinux-off + cred + real_cred all fire against the *same* reclaimed page via same-page overlay retry rounds, consuming exactly the three rungs of the nice ladder — the heap-reclaim dice are rolled once for the whole chain
- **SELinux off via zero-write**: the rb_erase primitive with `rb_right = 0` performs a single clean 8-byte zero store at an arbitrary kernel address (no side store, no wild dereferences); zeroing the first qword of `selinux_state` gives double permissive (`enforcing=0` + `!initialized` → allow-all), which unblocks all post-root file I/O despite the kernel SID
- **Device-side symbol validation**: the offsets table comes from a reference vmlinux, but the device kernel is built with a different toolchain — before the blind SELinux write, the exploit perf-leaks `&init_user_ns` from the live `security_capable()` path and aborts to the cred-only flow unless it matches `kaslr_base + off_init_user_ns`
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

The exploit takes ~25 seconds (KASLR/task/layout leaks + heap spray + KernelSnitch bruteforce + three 3-second overlay rounds). On success it writes the root battery to `/data/local/tmp/.ghostlock_out`, the marker to `/data/local/tmp/.ghostlock_root`, and execs `/system/bin/sh` with uid=0 under a permissive kernel.

Environment knobs:

- `GHOST_SELINUX=0` — skip the SELinux write, run the proven cred-only route (mode 6)
- `GHOST_SELINUX_FORCE=1` — arm the SELinux write even if the device symbol-layout validation fails
- `GHOST_EXEC=0` — write the battery and exit(99) instead of execing a shell
- `CRED_ATTEMPTS=n` — full-spray retries when a run misses the reclaim (default 3)

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
