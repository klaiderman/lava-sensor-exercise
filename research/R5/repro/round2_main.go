//go:build linux

// LOCAL_REPRO D: os.Root symlink-following inside /sys, ACL xattr bytes, orphan survival, JSON determinism.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

func orphan(label string, sleepArg string, pgid, custom bool, wd time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	c := exec.CommandContext(ctx, "/bin/sh", "-c", "sleep "+sleepArg+" | cat")
	if pgid { c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }
	if custom { c.Cancel = func() error { return syscall.Kill(-c.Process.Pid, syscall.SIGKILL) } }
	c.WaitDelay = wd
	_ = c.Run()
	time.Sleep(400 * time.Millisecond)
	out, _ := exec.Command("/bin/sh", "-c", "pgrep -c -x -f 'sleep "+sleepArg+"' || true").Output()
	fmt.Printf("[orphan/%s] pgid=%v customCancel=%v wd=%v => 'sleep %s' still alive: %s", label, pgid, custom, wd, sleepArg, out)
}

func main() {
	fmt.Println("== A. orphan survival ==")
	orphan("waitdelay-only", "2001", false, false, 200*time.Millisecond)
	orphan("pgid-groupkill", "2002", true, true, 200*time.Millisecond)
	exec.Command("/bin/sh", "-c", "pkill -x -f 'sleep 2001'; pkill -x -f 'sleep 2002'").Run()

	fmt.Println("== B. os.Root symlink following inside /sys ==")
	r, err := os.OpenRoot("/sys")
	if err == nil {
		defer r.Close()
		ents, _ := os.ReadDir("/sys/block")
		for i, e := range ents {
			if i >= 2 { break }
			name := e.Name()
			tgt, _ := os.Readlink("/sys/block/" + name)
			b, e1 := r.ReadFile("block/" + name + "/size")
			fmt.Printf("  /sys/block/%s -> %s ; root.ReadFile(block/%s/size)=%q err=%v\n", name, tgt, name, bytes.TrimSpace(b), e1)
			b2, e2 := r.ReadFile("block/" + name + "/device/model")
			fmt.Printf("     root.ReadFile(block/%s/device/model)=%q err=%v\n", name, bytes.TrimSpace(b2), e2)
		}
		b3, e3 := r.ReadFile("devices/system/cpu/online")
		fmt.Printf("  root.ReadFile(devices/system/cpu/online)=%q err=%v\n", bytes.TrimSpace(b3), e3)
	}
	rp, err := os.OpenRoot("/proc")
	if err == nil {
		defer rp.Close()
		b, e := rp.ReadFile("self/status")
		fmt.Printf("  os.Root(/proc).ReadFile(self/status) -> %d bytes err=%v (self is a symlink)\n", len(b), e)
		_, e2 := rp.ReadFile("1/root/etc/passwd")
		fmt.Printf("  os.Root(/proc).ReadFile(1/root/etc/passwd) err=%v\n", e2)
	}

	fmt.Println("== C. POSIX ACL xattr raw bytes ==")
	dir, _ := os.MkdirTemp("", "r5acl")
	defer os.RemoveAll(dir)
	f := filepath.Join(dir, "acltest")
	os.WriteFile(f, []byte("x"), 0o640)
	setfacl, err := exec.LookPath("setfacl")
	if err != nil {
		fmt.Printf("  setfacl not available (%v) -> cannot create ACL locally\n", err)
	} else {
		out, err := exec.Command(setfacl, "-m", "u:1000:rw,g:4:r", f).CombinedOutput()
		fmt.Printf("  setfacl -> err=%v out=%q\n", err, bytes.TrimSpace(out))
		buf := make([]byte, 4096)
		n, gerr := syscall.Getxattr(f, "system.posix_acl_access", buf)
		fmt.Printf("  syscall.Getxattr -> n=%d err=%v\n", n, gerr)
		if gerr == nil && n > 0 {
			raw := buf[:n]
			fmt.Printf("  raw hex: % x\n", raw)
			ver := uint32(raw[0]) | uint32(raw[1])<<8 | uint32(raw[2])<<16 | uint32(raw[3])<<24
			fmt.Printf("  header version=%d, entries=%d (each 8 bytes: tag u16, perm u16, id u32)\n", ver, (n-4)/8)
			for off := 4; off+8 <= n; off += 8 {
				tag := uint16(raw[off]) | uint16(raw[off+1])<<8
				perm := uint16(raw[off+2]) | uint16(raw[off+3])<<8
				id := uint32(raw[off+4]) | uint32(raw[off+5])<<8 | uint32(raw[off+6])<<16 | uint32(raw[off+7])<<24
				fmt.Printf("    tag=0x%02x perm=0%o id=%d\n", tag, perm, int32(id))
			}
		}
		lb := make([]byte, 4096)
		ln, lerr := syscall.Listxattr(f, lb)
		fmt.Printf("  Listxattr -> n=%d err=%v names=%q\n", ln, lerr, bytes.ReplaceAll(bytes.TrimRight(lb[:max(ln,0)], "\x00"), []byte{0}, []byte{','}))
	}

	fmt.Println("== D. deterministic JSON ==")
	type ev struct {
		Path  string            `json:"path"`
		Attrs map[string]string `json:"attrs"`
		Note  string            `json:"note"`
	}
	v := ev{Path: "/etc/ssh/sshd_config", Attrs: map[string]string{"z": "1", "a": "2", "m": "3"}, Note: "a<b & c>d \"q\""}
	b1, _ := json.Marshal(v)
	fmt.Printf("  json.Marshal          -> %s\n", b1)
	var sb bytes.Buffer
	enc := json.NewEncoder(&sb)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	enc.Encode(v)
	fmt.Printf("  Encoder(noHTMLescape) -> %s", sb.String())
	fmt.Printf("  trailing newline from Encode: %v\n", sb.Bytes()[sb.Len()-1] == '\n')
	fmt.Printf("  time RFC3339: %s\n", time.Date(2026, 9, 9, 1, 2, 3, 456000000, time.UTC).Format(time.RFC3339))
	fmt.Printf("  time RFC3339Nano via json: ")
	tb, _ := json.Marshal(time.Date(2026, 9, 9, 1, 2, 3, 456000000, time.UTC))
	fmt.Println(string(tb))
	bigf, _ := json.Marshal(map[string]any{"bytes_float": float64(97938032 * 1024), "bytes_int": int64(97938032 * 1024)})
	fmt.Printf("  float vs int for byte counts: %s\n", bigf)
}
