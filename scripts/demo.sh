#!/bin/sh
# Offline end-to-end demo of everything minirun can show without a Linux
# kernel: bundle generation, validation (including a runc-style config with
# unsupported keys), the full launch plan, the cgroup writes it implies
# (executed against the fake cgroupfs), and the seccomp compiler with its
# BPF interpreter. Runs on macOS and Linux; needs no root, network or Docker.
# `make integration` is the part that runs real containers.
set -eu

cd "$(dirname "$0")/.."
bin=${MINIRUN:-bin/minirun}
work=$(mktemp -d "${TMPDIR:-/tmp}/minirun-demo.XXXXXX")
trap 'rm -rf "$work"' EXIT

step() { printf '\n==> %s\n' "$*"; }
run() { printf '$ %s\n' "$*"; "$@"; }

step "1. Generate a bundle config: 32 MiB memory, 16 tasks, half a CPU, default seccomp profile"
mkdir -p "$work/bundle"
run "$bin" spec -o "$work/bundle/config.json" --hostname demo --memory 32M --pids 16 --cpus 0.5 -- /bin/sh -c 'echo hello from $(hostname)'

step "2. Validate it"
run "$bin" validate --bundle "$work/bundle"

step "3. Validate a runc-style config: unsupported keys are reported, not silently dropped"
mkdir -p "$work/runc"
sed 's/"ambient": \[[^]]*\]/"ambient": []/' examples/runc-style/config.json >"$work/runc/config.json"
run "$bin" validate --bundle "$work/runc"

step "4. The launch plan, step by step, with the cgroup writes replayed on a fake cgroupfs"
run "$bin" --root /run/minirun plan --bundle "$work/bundle" --id demo --arch x86_64 --simulate-cgroups "$work/cgroupfs"

step "5. Compile the seccomp profile for both architectures and measure dispatch cost"
run "$bin" seccomp --bundle "$work/bundle" --arch x86_64 --cost
run "$bin" seccomp --bundle "$work/bundle" --arch aarch64 --cost

step "6. Ask the compiled filter (run in the BPF interpreter) about specific calls"
run "$bin" seccomp --bundle "$work/bundle" --arch x86_64 \
	--check read --check mount --check unshare \
	--check clone:0x11 --check clone:0x10000011 --check clone3 \
	--check socket:2 --check socket:40 --check personality:0 --check personality:1

step "7. First instructions of the program (range-tree dispatch)"
"$bin" seccomp --bundle "$work/bundle" --arch x86_64 --disasm | sed -n '2,16p'

step "8. On this OS, starting a container is refused cleanly unless it is Linux"
if [ "$(uname -s)" != Linux ]; then
	"$bin" --root "$work/state" run --bundle "$work/bundle" demo || true
else
	echo "(Linux host: use 'sudo make integration' or 'make integration' for real containers)"
fi
