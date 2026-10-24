#!/bin/sh
# Integration assertions, run as root inside a privileged Alpine container
# (see run.sh). Prints TAP-style lines and exits non-zero on any failure.
set -u

pass=0
fail=0
n=0
ok() {
	n=$((n + 1)); pass=$((pass + 1))
	echo "ok $n - $1"
}
not_ok() {
	n=$((n + 1)); fail=$((fail + 1))
	echo "not ok $n - $1"
	if [ -n "${2:-}" ]; then printf '#   %s\n' "$2"; fi
}
expect_eq() { # description got want
	if [ "$2" = "$3" ]; then ok "$1"; else not_ok "$1" "got [$2] want [$3]"; fi
}
expect_contains() { # description haystack needle
	case "$2" in
		*"$3"*) ok "$1" ;;
		*) not_ok "$1" "[$2] does not contain [$3]" ;;
	esac
}

STATE=/run/minirun-itest
M="minirun --root $STATE"
BASE=/bundles/base/rootfs

echo "# kernel $(uname -r), $(uname -m)"

# --- host preparation -------------------------------------------------------
# cgroup v2 forbids enabling controllers in a cgroup that has processes, and
# with --cgroupns=private this shell lives in the namespace's root cgroup.
# Move every process into a leaf first, as Docker-in-Docker entrypoints do.
mkdir -p /sys/fs/cgroup/init
for p in $(cat /sys/fs/cgroup/cgroup.procs); do
	echo "$p" >/sys/fs/cgroup/init/cgroup.procs 2>/dev/null || true
done
echo "# cgroup controllers: $(cat /sys/fs/cgroup/cgroup.controllers)"

# Overlayfs cannot use another overlayfs as its upper layer, and this
# container's own root is one. Hosts normally have /run on tmpfs; recreate
# that here for the state directory.
mkdir -p "$STATE"
mount -t tmpfs -o mode=0711 tmpfs "$STATE"

mkdir -p "$BASE"
tar -xzf /alpine.tar.gz -C "$BASE"

mkbundle() { # name [spec flags] [-- command...]
	b=/bundles/$1; shift
	mkdir -p "$b"
	(cd "$b" && minirun spec --force --rootfs "$BASE" "$@" >/dev/null)
}

host_hostname=$(hostname)

# --- isolation basics -------------------------------------------------------
mkbundle pid -- /bin/sh -c 'echo $$'
expect_eq "container init is pid 1" "$($M run --bundle /bundles/pid --rm t-pid)" "1"

mkbundle procs -- /bin/sh -c 'ls /proc | grep -c "^[0-9]"'
count=$($M run --bundle /bundles/procs --rm t-procs)
if [ "$count" -le 4 ]; then ok "pid namespace hides host processes ($count visible)"; else not_ok "pid namespace hides host processes" "$count pids visible"; fi

mkbundle host --hostname minirun-itest -- /bin/hostname
expect_eq "uts namespace sets hostname" "$($M run --bundle /bundles/host --rm t-host)" "minirun-itest"
expect_eq "host hostname unchanged" "$(hostname)" "$host_hostname"

mkbundle release -- /bin/sh -c 'cat /etc/alpine-release; test -e /itest && echo leaked || echo isolated'
out=$($M run --bundle /bundles/release --rm t-release)
expect_eq "pivot_root into the bundle rootfs" "$out" "$(printf '3.20.3\nisolated')"

# A new network namespace may also contain the kernel's fallback tunnel
# devices (tunl0, gre0, ...), which are always down; what matters is that the
# host's interfaces are absent and only loopback is up.
# (IFF_UP is bit 0, so an "up" flags value ends in an odd hex digit.)
mkbundle net -- /bin/sh -c 'for i in /sys/class/net/*; do [ -d $i ] || continue; case $(cat $i/flags) in *[13579bdf]) basename $i ;; esac; done; test -e /sys/class/net/eth0 && echo eth0-visible; true'
expect_eq "network namespace: host interfaces hidden, only lo up" "$($M run --bundle /bundles/net --rm t-net)" "lo"

mkbundle exit -- /bin/sh -c 'exit 7'
$M run --bundle /bundles/exit --rm t-exit
expect_eq "exit status propagates" "$?" "7"

# --- filesystem -------------------------------------------------------------
mkbundle ovl -- /bin/sh -c 'echo hi >/written-by-container'
$M run --bundle /bundles/ovl t-ovl
if [ -f "$STATE/t-ovl/upper/written-by-container" ] && [ ! -e "$BASE/written-by-container" ]; then
	ok "writes land in the overlay upper dir, rootfs untouched"
else
	not_ok "writes land in the overlay upper dir, rootfs untouched"
fi
$M delete t-ovl
if [ ! -e "$STATE/t-ovl" ]; then ok "delete removes the state dir"; else not_ok "delete removes the state dir"; fi

mkbundle ro --readonly -- /bin/sh -c 'touch /x 2>&1; echo rc=$?'
expect_contains "read-only rootfs rejects writes" "$($M run --bundle /bundles/ro --rm t-ro)" "Read-only file system"

mkbundle masked -- /bin/sh -c 'wc -c </proc/kcore; echo x 2>/dev/null >/proc/sys/kernel/domainname || echo ro'
expect_eq "masked and read-only proc paths" "$($M run --bundle /bundles/masked --rm t-masked)" "$(printf '0\nro')"

mkbundle rlimit -- /bin/sh -c 'ulimit -n'
expect_eq "rlimits applied" "$($M run --bundle /bundles/rlimit --rm t-rlimit)" "1024"

# --- privileges -------------------------------------------------------------
mkbundle caps -- /bin/sh -c 'grep -E "^(CapEff|CapBnd|NoNewPrivs|Seccomp):" /proc/self/status | tr -d "\t"; hostname nope 2>&1 || true'
out=$($M run --bundle /bundles/caps --rm t-caps)
expect_contains "effective capabilities are the default set" "$out" "CapEff:00000000a80425fb"
expect_contains "bounding set trimmed" "$out" "CapBnd:00000000a80425fb"
expect_contains "no_new_privs set" "$out" "NoNewPrivs:1"
expect_contains "seccomp filter active" "$out" "Seccomp:2"
expect_contains "sethostname denied without CAP_SYS_ADMIN" "$out" "Operation not permitted"

mkbundle sec --deny-syscall mkdirat:38 --deny-syscall mkdir:38 -- /bin/sh -c 'mkdir /tmp/x 2>&1; touch /tmp/y && echo touched'
out=$($M run --bundle /bundles/sec --rm t-sec)
expect_contains "seccomp profile denies mkdir with the configured errno" "$out" "Function not implemented"
expect_contains "seccomp profile allows other calls" "$out" "touched"

mkbundle unshare -- /bin/sh -c 'unshare -U true 2>&1 || echo denied'
expect_contains "default profile blocks namespace creation" "$($M run --bundle /bundles/unshare --rm t-unshare)" "denied"

mkbundle userns --userns -- /bin/sh -c 'id -u; tr -s " " </proc/self/uid_map | sed "s/^ //"'
expect_eq "user namespace maps root to host 100000" "$($M run --bundle /bundles/userns --rm t-userns)" "$(printf '0\n0 100000 65536')"

# --- cgroup limits ----------------------------------------------------------
mkbundle oom --memory 16M -- /bin/dd if=/dev/zero of=/dev/null bs=64M count=1
$M run --bundle /bundles/oom t-oom 2>/dev/null
expect_eq "memory limit: OOM kill exits 137" "$?" "137"
expect_contains "memory limit: state records oomKilled" "$($M state t-oom)" '"oomKilled": true'
expect_contains "memory limit: memory.max written" "$(cat /sys/fs/cgroup/minirun/t-oom/memory.max)" "16777216"
oomkills=$(grep oom_kill /sys/fs/cgroup/minirun/t-oom/memory.events | head -1 | cut -d' ' -f2)
if [ "${oomkills:-0}" -ge 1 ]; then ok "memory limit: memory.events oom_kill=$oomkills"; else not_ok "memory limit: memory.events oom_kill" "$oomkills"; fi
$M delete t-oom

mkbundle pids --pids 8 -- /bin/sh -c 'i=0; while [ $i -lt 20 ]; do sleep 1 & i=$((i+1)); done; wait'
out=$($M run --bundle /bundles/pids t-pids 2>&1)
expect_contains "pids limit: fork fails" "$out" "can't fork"
hits=$($M stats t-pids | grep pidsLimitHits | tr -dc '0-9')
if [ "${hits:-0}" -ge 1 ]; then ok "pids limit: pids.events max=$hits"; else not_ok "pids limit: pids.events max" "$hits"; fi
$M delete t-pids

# --- lifecycle: detached run, exec, ps, kill, delete ------------------------
mkbundle life --cpus 0.5 -- /bin/sleep 300
expect_eq "run -d prints the id" "$($M run --bundle /bundles/life -d t-life)" "t-life"
expect_contains "ps lists the running container" "$($M ps)" "running"
expect_eq "cpu limit written to cpu.max" "$(cat /sys/fs/cgroup/minirun/t-life/cpu.max)" "50000 100000"
expect_eq "exec sees the container hostname" "$($M exec t-life hostname)" "minirun"
expect_eq "exec joins the pid namespace" "$($M exec t-life cat /proc/1/comm)" "sleep"
expect_eq "exec joins the mount namespace" "$($M exec t-life cat /etc/alpine-release)" "3.20.3"
expect_eq "exec applies capabilities" "$($M exec t-life sh -c 'grep CapEff /proc/self/status | tr -d "\t"')" "CapEff:00000000a80425fb"
expect_eq "exec passes env and cwd" "$($M exec --env GREETING=hi --cwd /tmp t-life sh -c 'echo $GREETING $(pwd)')" "hi /tmp"
$M exec t-life sh -c 'exit 3'
expect_eq "exec exit status propagates" "$?" "3"
expect_eq "ps ID lists the container's processes" "$($M ps t-life | wc -l | tr -d ' ')" "1"
if $M delete t-life 2>/dev/null; then not_ok "delete refuses a running container"; else ok "delete refuses a running container"; fi
$M kill t-life KILL
sleep 1
expect_contains "killed container is stopped" "$($M state t-life)" '"status": "stopped"'
$M delete t-life
if [ ! -d /sys/fs/cgroup/minirun/t-life ]; then ok "delete removes the cgroup"; else not_ok "delete removes the cgroup"; fi
if $M state t-life 2>/dev/null; then not_ok "deleted container is gone"; else ok "deleted container is gone"; fi

mkbundle force -- /bin/sleep 300
$M run --bundle /bundles/force -d t-force >/dev/null
$M delete -f t-force
if [ ! -e "$STATE/t-force" ] && [ ! -d /sys/fs/cgroup/minirun/t-force ]; then ok "delete -f kills and removes"; else not_ok "delete -f kills and removes"; fi

mkbundle unsexec --userns -- /bin/sleep 300
$M run --bundle /bundles/unsexec -d t-unsexec >/dev/null
expect_contains "exec into a user namespace is refused" "$($M exec t-unsexec true 2>&1)" "not supported"
$M delete -f t-unsexec

expect_contains "duplicate id rejected" "$($M run --bundle /bundles/pid t-pid >/dev/null; $M run --bundle /bundles/pid t-pid 2>&1)" "already exists"
$M delete t-pid

echo "1..$n"
echo "# passed $pass, failed $fail"
[ "$fail" -eq 0 ]
