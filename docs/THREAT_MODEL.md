# Threat model and security caveats

minirun is an educational container runtime. This document states what it
tries to protect, against whom, how, and where it falls short. Read it as a
list of known gaps, not as a security guarantee.

## Assets and trust boundaries

| Party | Trust |
|---|---|
| The operator running `minirun` (root) | Trusted. |
| The bundle's `config.json` | Trusted. It is written or approved by the operator; it can bind-mount any host path, name any cgroup path, disable seccomp and keep every capability. minirun validates it for correctness, not for safety. |
| The bundle's root filesystem | Semi-trusted. It may contain hostile symlinks (handled by `SecureJoin`) and hostile binaries (they run inside the container), but minirun assumes nothing on the host modifies it while a container is being set up. |
| The container's processes | Untrusted. The isolation layers below exist to contain them. |

The asset is the host: its files, processes, kernel, other containers and
the minirun binary itself.

## Layers and what each one stops

| Layer | Stops | Verified by |
|---|---|---|
| PID namespace | seeing or signalling host processes | integration: init is pid 1; only container pids visible; exec joins the same namespace |
| Mount namespace + overlayfs + `pivot_root` + detach of the old root | reaching the host filesystem; writing to the bundle rootfs | integration: `/etc/alpine-release` of the bundle, host mount absent, writes land in the upper dir only |
| Masked and read-only paths | `/proc/kcore`, `/proc/keys`, `/proc/sys`, `/sys/firmware`... leaks and host-wide knobs | integration: `/proc/kcore` reads 0 bytes, `/proc/sys` is read-only |
| UTS, IPC, network namespaces | changing the host's hostname, SysV IPC with the host, host network access | integration: hostname set inside and unchanged outside; only `lo` up |
| Capability bounding/effective sets (Docker's 14 by default) | `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_SYS_MODULE`, `CAP_SYS_PTRACE`... | integration: `CapEff`/`CapBnd` = `00000000a80425fb`; `sethostname` fails |
| `no_new_privs` | regaining privileges via setuid binaries or file capabilities | integration: `NoNewPrivs: 1` |
| seccomp (default allow-list) | kernel attack surface: `mount`, `unshare`/`setns`, `clone` with namespace flags, `bpf`, `perf_event_open`, `keyctl`, `ptrace`, module loading, `AF_VSOCK` sockets (family tested on its low 32 bits, the part the kernel reads)... | unit: compiler == reference semantics (property + fuzz), `socket(1<<32\|AF_VSOCK)` denied; integration: filter active, configured errno returned, `unshare` denied, `AF_VSOCK` denied with and without high argument bits |
| cgroup v2 memory/pids/cpu limits | memory exhaustion, fork bombs, CPU monopolisation | integration: OOM kill at `memory.max` (exit 137, `oomKilled`), fork fails at `pids.max`, `cpu.max` written |
| User namespace (opt-in `--userns`) | container root being host root | integration: uid 0 inside maps to host 100000 |
| Sealed memfd re-exec | overwriting the host minirun binary through `/proc/<helper>/exe` (CVE-2019-5736 class) | by construction; not exercised by a test |
| Privilege-drop order | leaving a window where the final process holds more than configured | documented sequence in `sandbox/security_linux.go`, asserted indirectly by the capability checks |

## Known gaps

1. **No user namespace by default.** Container root is host uid 0 with a
   reduced capability set and a seccomp filter, as in Docker's default. A
   kernel bug reachable through the allowed syscalls is a host compromise.
   Use `minirun spec --userns`.
2. **`exec` cannot join a user namespace.** A multithreaded Go process cannot
   `setns(CLONE_NEWUSER)`. minirun refuses `exec` into such containers rather
   than running the process with host credentials. runc uses a C
   constructor (`nsexec`) for this.
3. **Mount-target resolution is not race-free.** `SecureJoin` resolves
   symlinks in userspace before `mount(2)`. A host process that can write
   to the bundle rootfs while minirun sets up a container could swap a
   component for a symlink in between. Container processes cannot exploit
   this because none exist during setup. `openat2(RESOLVE_IN_ROOT)` plus
   `/proc/self/fd` mount targets would close it.
4. **No LSM.** No AppArmor or SELinux profile is applied
   (`process.apparmorProfile`/`selinuxLabel` are reported as unsupported).
5. **No device controller.** cgroup v2 device access control requires
   attaching an eBPF program; minirun does not, so device access is limited
   only by which nodes exist in the container's `/dev` (a fresh tmpfs with
   six bind-mounted character devices by default) and by
   `CAP_MKNOD` + mount restrictions.
6. **seccomp compiler is unaudited.** It is checked against minirun's own
   reference evaluator (and that evaluator against the OCI semantics as
   minirun reads them), not differentially against libseccomp. Semantics
   for multiple rules on one syscall are documented in
   `internal/seccomp/profile.go` and may differ from libseccomp in edge
   cases (libseccomp orders rules by its own internal priority).
7. **The default allow-list is modelled on Docker's, not copied.** Calls
   Docker allows only with specific capabilities (e.g. `chroot` with
   `CAP_SYS_CHROOT`) are allowed or denied statically.
8. **Detached containers are unsupervised.** Nothing records their exit
   status; their status is derived from `/proc` with a pid + start-time
   check to avoid pid reuse confusion.
9. **Configs are trusted.** A config naming an existing system cgroup as a
   parent will cause minirun to enable controllers in it; a config can mount
   `/` of the host read-write into the container.
10. **Resource exhaustion of the runtime itself** (huge configs, enormous
    seccomp profiles) is bounded only coarsely: config files are capped at
    4 MiB and filters at the kernel's 4096 instructions.
11. **seccomp argument tests are 64-bit; `int` arguments are not.** OCI
    profiles compare whole 64-bit registers, while the kernel truncates
    arguments declared `int`/`unsigned int` (e.g. `socket`'s family,
    `personality`) to 32 bits. A deny-style test such as
    `SCMP_CMP_NE 40` can therefore be bypassed by setting the upper 32
    bits, a weakness Docker/libseccomp profiles share. The default profile
    avoids it: `AF_VSOCK` is denied by `SCMP_CMP_MASKED_EQ 0xffffffff == 40`
    (the earlier `SCMP_CMP_NE` rule let `socket(1<<32|40)` create a vsock
    socket on a real kernel), `clone`'s namespace check masks the low half
    (the kernel uses only it), and `personality` is allow-listed by exact
    64-bit value, which only fails closed. minirun does not rewrite custom
    profiles: write tests on `int` arguments with a `0xffffffff` mask.

## Out of scope

- Multi-tenant isolation guarantees, rootless operation, network policy,
  image distribution and signature verification.
- Attacks by the operator or by whoever writes the config.
