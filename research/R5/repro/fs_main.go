//go:build linux

// LOCAL_REPRO C: /proc & /sys read semantics, mode gating, xdev, xattr, os.Root, ReadFile sizing.
package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

func sizeOf(p string) string {
	fi, err := os.Lstat(p)
	if err != nil {
		return "err:" + err.Error()
	}
	return fmt.Sprintf("stsize=%d mode=%v", fi.Size(), fi.Mode())
}

func boundedRead(p string, cap int64) (string, bool, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", false, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", false, err
	}
	if !fi.Mode().IsRegular() {
		return "", false, fmt.Errorf("not a regular file: %v", fi.Mode())
	}
	b, err := io.ReadAll(io.LimitReader(f, cap+1))
	trunc := int64(len(b)) > cap
	if trunc {
		b = b[:cap]
	}
	return string(b), trunc, err
}

func main() {
	fmt.Println("== 1. /proc and /sys reported sizes ==")
	for _, p := range []string{"/proc/meminfo", "/proc/cpuinfo", "/proc/self/status",
		"/sys/class/dmi/id/sys_vendor", "/sys/devices/system/cpu/online", "/etc/os-release"} {
		fmt.Printf("  %-38s %s\n", p, sizeOf(p))
	}

	fmt.Println("== 2. os.ReadFile on size-0 /proc files ==")
	for _, p := range []string{"/proc/meminfo", "/proc/cpuinfo"} {
		b, err := os.ReadFile(p)
		fmt.Printf("  os.ReadFile(%s) -> %d bytes, err=%v\n", p, len(b), err)
	}

	fmt.Println("== 3. bounded read with cap ==")
	s, tr, err := boundedRead("/proc/cpuinfo", 200)
	fmt.Printf("  /proc/cpuinfo cap=200 -> %d bytes truncated=%v err=%v\n", len(s), tr, err)
	_, _, err = boundedRead("/dev/null", 100)
	fmt.Printf("  /dev/null (char dev) rejected? err=%v\n", err)
	_, _, err = boundedRead("/dev/zero", 100)
	fmt.Printf("  /dev/zero rejected? err=%v\n", err)

	fmt.Println("== 4. FIFO behavior: O_NONBLOCK vs blocking open ==")
	dir, _ := os.MkdirTemp("", "r5fifo")
	defer os.RemoveAll(dir)
	fifo := filepath.Join(dir, "f")
	if err := syscall.Mkfifo(fifo, 0o600); err == nil {
		fi, _ := os.Lstat(fifo)
		fmt.Printf("  Lstat(fifo).Mode()=%v isNamedPipe=%v\n", fi.Mode(), fi.Mode()&os.ModeNamedPipe != 0)
		done := make(chan error, 1)
		go func() { f, e := os.Open(fifo); if e == nil { f.Close() }; done <- e }()
		select {
		case e := <-done:
			fmt.Printf("  blocking os.Open(fifo) returned immediately err=%v (UNEXPECTED)\n", e)
		case <-time.After(700 * time.Millisecond):
			fmt.Printf("  blocking os.Open(fifo) HUNG for >700ms (confirms: must Lstat-gate before open)\n")
		}
		f2, e2 := os.OpenFile(fifo, os.O_RDONLY|syscall.O_NONBLOCK, 0)
		fmt.Printf("  O_NONBLOCK open(fifo) err=%v (did not hang)\n", e2)
		if e2 == nil { f2.Close() }
	}

	fmt.Println("== 5. xdev via syscall.Stat_t.Dev ==")
	for _, p := range []string{"/", "/proc", "/sys", "/dev", "/run", "/tmp"} {
		fi, err := os.Lstat(p)
		if err != nil { fmt.Printf("  %-8s err=%v\n", p, err); continue }
		st, ok := fi.Sys().(*syscall.Stat_t)
		fmt.Printf("  %-8s ok=%v Dev=%d (major=%d minor=%d) Ino=%d\n", p, ok, st.Dev, st.Dev>>8, st.Dev&0xff, st.Ino)
	}

	fmt.Println("== 6. stdlib syscall xattr on linux ==")
	buf := make([]byte, 4096)
	for _, p := range []string{"/etc/shadow", "/etc/passwd", "/tmp"} {
		n, err := syscall.Getxattr(p, "system.posix_acl_access", buf)
		fmt.Printf("  syscall.Getxattr(%s, system.posix_acl_access) -> n=%d err=%v (ENODATA=%v)\n",
			p, n, err, errors.Is(err, syscall.ENODATA))
	}
	ln, lerr := syscall.Listxattr("/etc/passwd", buf)
	fmt.Printf("  syscall.Listxattr(/etc/passwd) -> n=%d err=%v\n", ln, lerr)
	var sfs syscall.Statfs_t
	serr := syscall.Statfs("/", &sfs)
	fmt.Printf("  syscall.Statfs(/) -> Type=0x%x Flags=0x%x Bsize=%d err=%v\n", sfs.Type, sfs.Flags, sfs.Bsize, serr)

	fmt.Println("== 7. os.Root on /sys and /proc ==")
	r, err := os.OpenRoot("/sys")
	fmt.Printf("  os.OpenRoot(/sys) err=%v\n", err)
	if err == nil {
		defer r.Close()
		b, e := r.ReadFile("class/dmi/id/sys_vendor")
		fmt.Printf("  root.ReadFile(class/dmi/id/sys_vendor) -> %q err=%v\n", trim(b), e)
		// symlink traversal inside root:
		b2, e2 := r.ReadFile("block/loop0/device/model")
		fmt.Printf("  root.ReadFile(block/loop0/device/model) -> %q err=%v\n", trim(b2), e2)
		fi, e3 := r.Lstat("block")
		fmt.Printf("  root.Lstat(block) mode=%v err=%v\n", modeOf(fi), e3)
		_, e4 := r.Open("../etc/passwd")
		fmt.Printf("  root.Open(../etc/passwd) err=%v (escape blocked?)\n", e4)
	}
	// sysfs symlink shape
	for _, p := range []string{"/sys/block", "/sys/class/dmi/id"} {
		ents, err := os.ReadDir(p)
		if err != nil { fmt.Printf("  ReadDir(%s) err=%v\n", p, err); continue }
		sym := 0
		for _, e := range ents { if e.Type()&fs.ModeSymlink != 0 { sym++ } }
		fmt.Printf("  ReadDir(%s): %d entries, %d symlinks\n", p, len(ents), sym)
	}
}

func trim(b []byte) string {
	if len(b) > 40 { b = b[:40] }
	return string(b)
}
func modeOf(fi os.FileInfo) string { if fi == nil { return "<nil>" }; return fi.Mode().String() }
