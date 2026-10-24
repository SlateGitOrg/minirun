#!/bin/sh
# Measures statement coverage of minirun's core logic and enforces a floor.
#
# "Core logic" is every package under internal/ except the Linux kernel glue
# (files named *_linux.go: mount/pivot_root/setns/capset/seccomp(2) calls and
# the re-exec launcher). That glue cannot run in an unprivileged unit test;
# it is exercised by `make integration` against a real kernel instead. On
# macOS those files are not compiled at all, so the number is the same on
# both platforms.
#
# usage: scripts/coverage.sh [MIN_PERCENT]
set -eu
min=${1:-85}
out=${COVERAGE_OUT:-coverage.out}
go test -count=1 -covermode=atomic -coverpkg=./internal/... -coverprofile="$out.all" ./internal/... >/dev/null
grep -v '_linux\.go:' "$out.all" >"$out"
all=$(go tool cover -func="$out.all" | awk '/^total:/ {print $3}')
core=$(go tool cover -func="$out" | awk '/^total:/ {print $3}')
rm -f "$out.all"
echo "coverage: core logic $core (all compiled code incl. Linux glue on this OS: $all), floor $min%"
awk -v c="${core%\%}" -v m="$min" 'BEGIN { exit !(c + 0 >= m + 0) }' || {
	echo "coverage $core is below the $min% floor" >&2
	exit 1
}
