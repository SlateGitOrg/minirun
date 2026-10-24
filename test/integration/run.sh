#!/bin/sh
# Runs the minirun integration suite inside a privileged Linux container.
#
# The outer container is created from the official Alpine minirootfs, fetched
# once into .cache/ and verified against a pinned SHA-256; the same tarball
# is the root filesystem of every container minirun starts inside it. The
# image is tagged p50-39-minirun-itest:* and removed on exit.
#
# Skips (exit 0) when Docker is unavailable, so `make integration` is safe
# to run anywhere.
set -eu

cd "$(dirname "$0")/../.."

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
	echo "SKIP: docker is not available; integration tests need a privileged Linux container"
	exit 0
fi

ALPINE_VERSION=3.20.3
arch=$(docker info --format '{{.Architecture}}')
case "$arch" in
	aarch64 | arm64)
		goarch=arm64 alpine_arch=aarch64
		sha256=041fa34a81788242df9e78fa69b97ab45b8ec47ddbf88864755610414a7bf3de ;;
	x86_64 | amd64)
		goarch=amd64 alpine_arch=x86_64
		sha256=d4e6fd67dcf75e40c451560ac7265166c2b72a0f38ddc9aae756a7de3d1efa0c ;;
	*)
		echo "SKIP: unsupported docker architecture $arch"
		exit 0 ;;
esac

cache=.cache
tarball="$cache/alpine-minirootfs-$ALPINE_VERSION-$alpine_arch.tar.gz"
url="https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VERSION%.*}/releases/$alpine_arch/alpine-minirootfs-$ALPINE_VERSION-$alpine_arch.tar.gz"
mkdir -p "$cache/bin"

sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | cut -d' ' -f1
	else
		shasum -a 256 "$1" | cut -d' ' -f1
	fi
}

if [ ! -f "$tarball" ] || [ "$(sha256_of "$tarball")" != "$sha256" ]; then
	echo "fetching $url"
	curl -fsSL -o "$tarball.part" "$url"
	got=$(sha256_of "$tarball.part")
	if [ "$got" != "$sha256" ]; then
		rm -f "$tarball.part"
		echo "checksum mismatch for $url: got $got, want $sha256" >&2
		exit 1
	fi
	mv "$tarball.part" "$tarball"
fi
echo "rootfs: $tarball (sha256 $sha256)"

echo "building minirun for linux/$goarch"
CGO_ENABLED=0 GOOS=linux GOARCH=$goarch go build -trimpath -o "$cache/bin/minirun" ./cmd/minirun

image="p50-39-minirun-itest:$ALPINE_VERSION-$alpine_arch"
name="p50-39-minirun-itest-$$"
cleanup() {
	docker rm -f "$name" >/dev/null 2>&1 || true
	docker rmi -f "$image" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM
docker import "$tarball" "$image" >/dev/null

docker run --rm --name "$name" --privileged --cgroupns=private \
	-v "$PWD/$cache/bin/minirun:/usr/local/bin/minirun:ro" \
	-v "$PWD/test/integration:/itest:ro" \
	-v "$PWD/$tarball:/alpine.tar.gz:ro" \
	"$image" /bin/sh /itest/inside.sh
