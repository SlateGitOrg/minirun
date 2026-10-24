//go:build linux

package sandbox

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/archit2501/minirun/internal/launch"
	"github.com/archit2501/minirun/internal/mounts"
)

func mount(source, target, fstype string, flags uint64, data string) error {
	if err := unix.Mount(source, target, fstype, uintptr(flags), data); err != nil {
		return fmt.Errorf("mount %q on %s (type %q, flags %s, data %q): %w",
			source, target, fstype, mounts.FlagNames(flags), data, err)
	}
	return nil
}

// lockedFlags returns the per-mount flags of the mount containing path that
// a bind remount must preserve. Inside a user namespace the kernel locks
// these flags on mounts inherited from a more privileged namespace and
// rejects a remount that would clear them with EPERM.
func lockedFlags(path string) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, fmt.Errorf("statfs %s: %w", path, err)
	}
	var f uint64
	for bit, ms := range map[int64]uint64{
		unix.ST_RDONLY: mounts.MSRdonly, unix.ST_NOSUID: mounts.MSNosuid, unix.ST_NODEV: mounts.MSNodev,
		unix.ST_NOEXEC: mounts.MSNoexec, unix.ST_NOATIME: mounts.MSNoatime,
		unix.ST_NODIRATIME: mounts.MSNodiratime, unix.ST_RELATIME: mounts.MSRelatime,
	} {
		if st.Flags&bit != 0 {
			f |= ms
		}
	}
	return f, nil
}

// remount applies MS_BIND|MS_REMOUNT with the requested flags plus whatever
// is locked on the mount.
func remount(path string, flags uint64) error {
	locked, err := lockedFlags(path)
	if err != nil {
		return err
	}
	// Do not let a locked atime mode fight with a requested one.
	if flags&(mounts.MSNoatime|mounts.MSRelatime|mounts.MSStrictatime) != 0 {
		locked &^= mounts.MSNoatime | mounts.MSRelatime | mounts.MSStrictatime
	}
	return mount("", path, "", flags|locked|mounts.MSBind|mounts.MSRemount, "")
}

// setupRootfs assembles the container root on p.Target and pivots into it.
// It runs in the container's new mount namespace.
func setupRootfs(p *launch.Plan) error {
	// Stop mount events propagating between the host and the container.
	if err := mount("", "/", "", p.Propagation, ""); err != nil {
		return err
	}
	if err := mount("overlay", p.Target, "overlay", 0, p.OverlayData); err != nil {
		if errors.Is(err, unix.EINVAL) {
			return fmt.Errorf("%w (overlayfs rejects an upper layer on overlayfs or another filesystem without xattr support; keep the state directory on tmpfs or ext4/xfs, e.g. the default /run/minirun)", err)
		}
		return err
	}
	for _, m := range p.Mounts {
		if err := mountOne(p.Target, m); err != nil {
			return err
		}
	}
	if p.BindDevices {
		if err := bindDevices(p.Target); err != nil {
			return err
		}
	}
	if err := pivotRoot(p.Target); err != nil {
		return err
	}
	for _, path := range p.MaskedPaths {
		if err := maskPath(path); err != nil {
			return err
		}
	}
	for _, path := range p.ReadonlyPaths {
		if err := readonlyPath(path); err != nil {
			return err
		}
	}
	if p.ReadonlyRoot {
		if err := remount("/", mounts.MSRdonly); err != nil {
			return fmt.Errorf("make root read-only: %w", err)
		}
	}
	return nil
}

func mountOne(root string, m mounts.Op) error {
	dest, err := mounts.SecureJoin(root, m.Destination)
	if err != nil {
		return err
	}
	if err := createMountpoint(m, dest); err != nil {
		return err
	}
	if err := mount(m.Source, dest, m.FSType, m.Flags, m.Data); err != nil {
		return err
	}
	if m.RemountFlags != 0 {
		if err := remount(dest, m.RemountFlags&^(mounts.MSBind|mounts.MSRemount)); err != nil {
			return err
		}
	}
	for _, prop := range m.Propagation {
		if err := mount("", dest, "", prop, ""); err != nil {
			return err
		}
	}
	return nil
}

// createMountpoint creates the directory (or, for a bind of a file, the
// empty file) a mount needs.
func createMountpoint(m mounts.Op, dest string) error {
	if m.IsBind() {
		info, err := os.Stat(m.Source)
		if err != nil {
			return fmt.Errorf("bind source %s: %w", m.Source, err)
		}
		if !info.IsDir() {
			return createFile(dest)
		}
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return fmt.Errorf("create mount point %s: %w", dest, err)
	}
	return nil
}

func createFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create mount point %s: %w", path, err)
	}
	// O_NOFOLLOW: SecureJoin never returns a symlink, but if the final
	// component were one, creating through it could touch a host file.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o644)
	if err != nil {
		return fmt.Errorf("create mount point %s: %w", path, err)
	}
	return f.Close()
}

func bindDevices(root string) error {
	for _, dev := range launch.Devices {
		if _, err := os.Stat(dev); err != nil {
			continue // e.g. no /dev/tty without a controlling terminal
		}
		dest, err := mounts.SecureJoin(root, dev)
		if err != nil {
			return err
		}
		if err := createFile(dest); err != nil {
			return err
		}
		if err := mount(dev, dest, "", mounts.MSBind, ""); err != nil {
			return err
		}
	}
	for _, l := range launch.DevSymlinks {
		dest, err := mounts.SecureJoin(root, l[1])
		if err != nil {
			return err
		}
		if err := os.Symlink(l[0], dest); err != nil && !errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("symlink %s -> %s: %w", l[1], l[0], err)
		}
	}
	return nil
}

// pivotRoot makes newRoot the root of the mount namespace using the
// pivot_root(".", ".") idiom: the old root ends up stacked under the new one
// and is lazily detached, so no directory for it is needed in the image.
func pivotRoot(newRoot string) error {
	if err := unix.Chdir(newRoot); err != nil {
		return fmt.Errorf("chdir %s: %w", newRoot, err)
	}
	if err := unix.PivotRoot(".", "."); err != nil {
		return fmt.Errorf("pivot_root %s: %w", newRoot, err)
	}
	if err := unix.Unmount(".", unix.MNT_DETACH); err != nil {
		return fmt.Errorf("detach old root: %w", err)
	}
	if err := unix.Chdir("/"); err != nil {
		return fmt.Errorf("chdir /: %w", err)
	}
	return nil
}

// maskPath hides a path: directories under an empty read-only tmpfs, files
// under /dev/null. Paths that do not exist are skipped.
func maskPath(path string) error {
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("mask %s: %w", path, err)
	}
	if info.IsDir() {
		return mount("tmpfs", path, "tmpfs", mounts.MSRdonly, "size=0")
	}
	return mount("/dev/null", path, "", mounts.MSBind, "")
}

// readonlyPath bind-mounts a path onto itself and remounts it read-only.
func readonlyPath(path string) error {
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err := mount(path, path, "", mounts.MSBind|mounts.MSRec, ""); err != nil {
		return err
	}
	return remount(path, mounts.MSRdonly|mounts.MSRec)
}

// bringUpLoopback sets IFF_UP on lo in the (new) network namespace.
func bringUpLoopback() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("loopback: socket: %w", err)
	}
	defer func() { _ = unix.Close(fd) }()
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return fmt.Errorf("loopback: %w", err)
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return fmt.Errorf("loopback: get flags: %w", err)
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
		return fmt.Errorf("loopback: set flags: %w", err)
	}
	return nil
}
