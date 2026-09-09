package probe

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func linuxOnly(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skipf("linux-only behaviour; run this test binary under WSL (GOOS=%s here)", runtime.GOOS)
	}
}

func notRoot(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "windows" && os.Geteuid() == 0 {
		t.Skip("uid 0 bypasses the mode bits this test depends on")
	}
}

func newTree(t *testing.T) (root string, r *Reader) {
	t.Helper()
	root = t.TempDir()
	for _, d := range []string{"sys", "proc", "etc", "home/mallory"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	r = NewRootedReader(root)
	t.Cleanup(r.Close)
	return root, r
}

// The cap comes from policy and truncation is detected by reading cap+1, so a
// value that hit the cap is known to be a prefix rather than assumed complete.
func TestReadCapAndTruncationDetection(t *testing.T) {
	root, r := newTree(t)
	body := strings.Repeat("a", 5000)
	if err := os.WriteFile(filepath.Join(root, "etc/big"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	obs := r.Read("/etc/big", Policy{Cap: 4096})
	if obs.Status != StatusOK {
		t.Fatalf("status = %s", obs.Status)
	}
	if !obs.Truncated {
		t.Errorf("truncated = false on a 5000-byte file read under a 4096-byte cap")
	}
	if obs.Bytes != 4096 || len(obs.Value) != 4096 {
		t.Errorf("bytes = %d, len(value) = %d, want 4096", obs.Bytes, len(obs.Value))
	}

	// Exactly at the cap: not truncated, and no phantom extra byte.
	if err := os.WriteFile(filepath.Join(root, "etc/exact"), []byte(strings.Repeat("b", 4096)), 0o644); err != nil {
		t.Fatal(err)
	}
	obs = r.Read("/etc/exact", Policy{Cap: 4096})
	if obs.Truncated {
		t.Errorf("a file of exactly cap bytes must not be reported truncated")
	}
	if obs.Bytes != 4096 {
		t.Errorf("bytes = %d, want 4096", obs.Bytes)
	}
}

// st_size is never a cap: /proc reports 0 and /sys reports 4096 whatever the
// real length is. Reading a real pseudo-file proves the sizes are ignored.
func TestZeroStatSizePseudoFile(t *testing.T) {
	linuxOnly(t)
	r := NewReader()
	defer r.Close()
	fi, err := os.Stat("/proc/meminfo")
	if err != nil {
		t.Skip("no /proc/meminfo here")
	}
	if fi.Size() != 0 {
		t.Logf("note: /proc/meminfo reports st_size %d on this kernel", fi.Size())
	}
	obs := r.Read("/proc/meminfo", Small)
	if obs.Status != StatusOK || obs.Bytes == 0 {
		t.Fatalf("read /proc/meminfo: status %s, %d bytes", obs.Status, obs.Bytes)
	}
	if !strings.Contains(obs.Value, "MemTotal") {
		t.Errorf("expected MemTotal in the value")
	}
}

// The fd is fstat-ed and must be a regular file. That single test rejects
// directories, device nodes, FIFOs and sockets, and it is done on the OPEN fd,
// so there is no lstat/open race to win.
func TestNonRegularFilesAreRefused(t *testing.T) {
	linuxOnly(t)
	root, r := newTree(t)

	fifo := filepath.Join(root, "etc/fifo")
	if err := mkfifo(fifo); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	// A FIFO with no writer blocks a plain open forever. O_NONBLOCK plus the
	// mode gate must return promptly; bound the test so a regression hangs the
	// test, not the sensor.
	done := make(chan Observation, 1)
	go func() { done <- r.Read("/etc/fifo", Small) }()
	select {
	case obs := <-done:
		if obs.Status != StatusUnsupported {
			t.Errorf("FIFO: status = %s, want UNSUPPORTED", obs.Status)
		}
		if obs.Value != "" {
			t.Errorf("FIFO: value must be empty")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("reading a writer-less FIFO blocked; O_NONBLOCK or the mode gate is missing")
	}

	// A character device is never opened for reading.
	if _, err := os.Stat("/dev/zero"); err == nil {
		if err := os.Symlink("/dev/zero", filepath.Join(root, "etc/zero")); err == nil {
			obs := r.Read("/etc/zero", Policy{Cap: 1024, Follow: true})
			if obs.Status == StatusOK {
				t.Errorf("/dev/zero was read; device nodes must never be opened")
			}
		}
	}

	// A directory is not a regular file either.
	if obs := r.Read("/etc", Small); obs.Status == StatusOK {
		t.Errorf("a directory was read as a file")
	}
}

// Symlinks are followed only where the policy says so, and never out of a
// system path into a tree a local user can write.
func TestSymlinkPolicy(t *testing.T) {
	linuxOnly(t)
	root, r := newTree(t)

	if err := os.WriteFile(filepath.Join(root, "home/mallory/payload"), []byte("attacker-controlled\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "home/mallory/payload"), filepath.Join(root, "etc/hijacked")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	obs := r.Read("/etc/hijacked", Policy{Cap: 1024, Follow: true})
	if obs.Status == StatusOK {
		t.Errorf("a system path resolving into a user-writable tree was followed; value=%q", obs.Value)
	}
	if !strings.Contains(obs.Detail, "user-writable") {
		t.Errorf("the refusal must say why, got %q", obs.Detail)
	}

	// With Follow off, a symlink is not followed at all.
	if err := os.WriteFile(filepath.Join(root, "etc/real"), []byte("ok\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(root, "etc/link")); err != nil {
		t.Fatal(err)
	}
	if obs := r.Read("/etc/link", Policy{Cap: 1024}); obs.Status == StatusOK {
		t.Errorf("a symlink was followed under a no-follow policy")
	}
	if obs := r.Read("/etc/link", Policy{Cap: 1024, Follow: true}); obs.Status != StatusOK {
		t.Errorf("an in-tree symlink must be followed when the policy allows it: %s %s", obs.Status, obs.Detail)
	}
}

// Inside /sys, symlinks are legitimate and must be followed — 28 of 28
// /sys/block entries are symlinks — while an escape is refused by the kernel.
func TestSysRootFollowsInRootSymlinksAndRefusesEscapes(t *testing.T) {
	linuxOnly(t)
	root, r := newTree(t)
	if err := os.MkdirAll(filepath.Join(root, "sys/devices/nvme0n1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sys/devices/nvme0n1/size"), []byte("1875385008\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "sys/block"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../devices/nvme0n1", filepath.Join(root, "sys/block/nvme0n1")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink("../../home/mallory/payload", filepath.Join(root, "sys/block/escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "home/mallory/payload"), []byte("attacker\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	obs := r.Read("/sys/block/nvme0n1/size", Tiny)
	if obs.Status != StatusOK || !strings.HasPrefix(obs.Value, "1875385008") {
		t.Errorf("an in-root /sys symlink was not followed: %s %q", obs.Status, obs.Value)
	}
	if obs := r.Read("/sys/block/escape", Tiny); obs.Status == StatusOK {
		t.Errorf("a /sys symlink escaping the root was followed: %q", obs.Value)
	}
}

// EACCES is a first-class observation, distinct from ENOENT.
func TestDeniedIsNotAbsent(t *testing.T) {
	linuxOnly(t)
	notRoot(t)
	root, r := newTree(t)
	p := filepath.Join(root, "etc/secret")
	if err := os.WriteFile(p, []byte("x"), 0o000); err != nil {
		t.Fatal(err)
	}
	obs := r.Read("/etc/secret", Small)
	if obs.Status != StatusEACCES || obs.Errno != "EACCES" {
		t.Errorf("denied read: status %s errno %q, want EACCES/EACCES", obs.Status, obs.Errno)
	}
	missing := r.Read("/etc/nope", Small)
	if missing.Status != StatusENOENT || missing.Errno != "ENOENT" {
		t.Errorf("absent read: status %s errno %q, want ENOENT/ENOENT", missing.Status, missing.Errno)
	}
	if obs.Reason() == missing.Reason() {
		t.Errorf("denied and absent collapsed to the same reason %q", obs.Reason())
	}
}

// Stat is metadata only: it records presence, type, mode, owner and size and
// never opens the object.
func TestStatIsMetadataOnly(t *testing.T) {
	root, r := newTree(t)
	if err := os.WriteFile(filepath.Join(root, "etc/key"), []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	obs := r.Stat("/etc/key")
	if obs.Status != StatusOK || obs.Meta == nil {
		t.Fatalf("stat failed: %s", obs.Status)
	}
	if obs.Meta.FileType != "regular" || obs.Meta.Size == nil || *obs.Meta.Size == 0 {
		t.Errorf("metadata = %+v", obs.Meta)
	}
	if strings.Contains(obs.Value, "BEGIN") {
		t.Errorf("Stat leaked file content into the observation value")
	}
	absent := r.Stat("/etc/none")
	if absent.Status != StatusENOENT || absent.Meta == nil || absent.Meta.Exists == nil || *absent.Meta.Exists {
		t.Errorf("an absent path must record exists=false, got %+v", absent.Meta)
	}
}

// ReadDir carries its own boundary: a cap hit is recorded so that "nothing
// found" can never be confused with "the listing stopped early".
func TestReadDirBudgetIsRecorded(t *testing.T) {
	root, r := newTree(t)
	for i := 0; i < 10; i++ {
		if err := os.WriteFile(filepath.Join(root, "etc", string(rune('a'+i))), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	names, obs := r.ReadDirNames("/etc", 4)
	if len(names) != 4 || !obs.Truncated {
		t.Errorf("names = %v truncated = %v, want 4 entries and a recorded cap hit", names, obs.Truncated)
	}
	if obs.Meta == nil || obs.Meta.BudgetExhausted != "entries" {
		t.Errorf("budget_exhausted = %+v, want entries", obs.Meta)
	}
	if _, obs := r.ReadDirNames("/etc", 100); obs.Truncated || obs.Meta.BudgetExhausted != "none" {
		t.Errorf("a completed listing must not claim a budget hit")
	}
}

// The out-of-band read returns on time even when the read itself cannot be
// cancelled, and says that the goroutine was abandoned rather than joined.
func TestReadOOBReturnsOnDeadline(t *testing.T) {
	linuxOnly(t)
	root, r := newTree(t)
	fifo := filepath.Join(root, "etc/slow")
	if err := mkfifo(fifo); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	start := time.Now()
	obs := r.ReadOOB("/etc/slow", Tiny, 100*time.Millisecond)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("ReadOOB took %s; the deadline must not depend on the read returning", elapsed)
	}
	// A FIFO is refused by the mode gate before it can block, so this returns
	// UNSUPPORTED; the timing assertion above is the real subject.
	if obs.Status == StatusOK {
		t.Errorf("status = OK on a FIFO")
	}
}

// TestNoRootOverrideInProduction is the seam guard: the rooted reader exists
// for tests, and no flag or environment variable may reach it. This is a
// deliberate rejection of ghw's GHW_CHROOT and gopsutil's HOST_SYS: in a
// security sensor, anything that can set an environment variable could
// otherwise rewrite every finding while the tool reports success.
func TestNoRootOverrideInProduction(t *testing.T) {
	const definitionSite = "internal/probe/read.go"
	err := filepath.WalkDir("../..", func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		rel := filepath.ToSlash(p)
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		src := string(b)
		if strings.Contains(src, "NewRootedReader") && !strings.HasSuffix(rel, definitionSite) {
			t.Errorf("%s references NewRootedReader; the fixture root must be reachable only from tests", rel)
		}
		if strings.Contains(src, "os.Getenv") || strings.Contains(src, "os.LookupEnv") {
			t.Errorf("%s reads the environment; an ambient root or behaviour override is a production safety hole", rel)
		}
		for _, flagName := range []string{`"root"`, `"as-root"`, `"no-timeout"`, `"unsafe"`, `"skip-check"`} {
			if strings.Contains(src, "flag.") && strings.Contains(src, flagName) {
				t.Errorf("%s appears to define a %s flag; no flag may widen the read root or disable a bound", rel, flagName)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
