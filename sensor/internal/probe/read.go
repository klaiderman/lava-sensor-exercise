package probe

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// Read caps. Caps come from policy and never from st_size: /proc reports 0 and
// /sys reports 4096 regardless of the real content length (L05, R5-F18).
const (
	// CapTiny bounds a single sysfs attribute.
	CapTiny int64 = 4 << 10
	// CapSmall bounds a config file or a /proc table.
	CapSmall int64 = 64 << 10
	// CapLarge bounds the largest file the sensor is willing to read.
	CapLarge int64 = 1 << 20
	// CapHeaderSniff bounds a secret-classification header read. The bytes are
	// classified and discarded; they never reach evidence (L23).
	CapHeaderSniff int64 = 64
)

var (
	errNotRegular    = errors.New("not a regular file")
	errSymlinkEscape = errors.New("symlink resolves into a user-writable tree")
	errSymlinkDenied = errors.New("symlink not followed by policy")
)

// userWritablePrefixes are trees any local user can create objects in. A system
// path that resolves into one of them is refused rather than followed: that is
// the classic "point /etc/x at /home/mallory/y" substitution.
var userWritablePrefixes = []string{"/home/", "/tmp/", "/var/tmp/", "/run/user/", "/dev/shm/", "/media/", "/mnt/"}

// Policy is the per-read bound. There is no unbounded read anywhere.
type Policy struct {
	// Cap is the maximum number of bytes retained. Cap+1 bytes are read so
	// truncation is detectable.
	Cap int64
	// Follow allows a symlink at the final path component to be resolved.
	// Reads of user-controlled trees always leave this false.
	Follow bool
}

// Tiny, Small and Large are the standard policies.
var (
	Tiny        = Policy{Cap: CapTiny}
	Small       = Policy{Cap: CapSmall}
	Large       = Policy{Cap: CapLarge}
	SmallFollow = Policy{Cap: CapSmall, Follow: true}
	TinyFollow  = Policy{Cap: CapTiny, Follow: true}
)

// Files is the read surface the checks use. Production is *Reader; tests may
// substitute a fake where a real fixture tree is not the point of the test.
type Files interface {
	Read(p string, pol Policy) Observation
	ReadTrimmed(p string, pol Policy) (string, Observation)
	ReadOOB(p string, pol Policy, deadline time.Duration) Observation
	Stat(p string) Observation
	ReadDir(p string, max int) ([]fs.DirEntry, Observation)
	ReadDirNames(p string, max int) ([]string, Observation)
	ReadLinkBase(p string) (string, Observation)
	Exists(p string) bool
}

// Reader is the one bounded read path in the sensor.
//
// /sys and /proc are read through *os.Root: openat per component, in-root
// symlinks followed (every /sys/block entry is one, R5-F21) and escapes refused
// by the kernel with no TOCTOU window. Everything else is opened directly with
// O_NOFOLLOW unless the policy explicitly allows a resolved symlink.
type Reader struct {
	base    string // "" in production; a fixture tree root under test
	sys     *os.Root
	proc    *os.Root
	sysErr  error
	procErr error
}

// NewReader opens the production reader. A failure to open /sys or /proc as a
// root is recorded and degrades that subtree to plain bounded reads (L15, F19);
// it is never fatal.
func NewReader() *Reader { return newReader("") }

// NewRootedReader builds a Reader over a fixture tree.
//
// Test-only seam (TEST_STRATEGY §1.1). There is deliberately no flag and no
// environment variable that selects a root: cmd/sensor never calls this, and
// TestNoRootOverrideInProduction asserts it.
func NewRootedReader(base string) *Reader { return newReader(base) }

func newReader(base string) *Reader {
	r := &Reader{base: base}
	r.sys, r.sysErr = os.OpenRoot(filepath.Join(base, "/sys"))
	r.proc, r.procErr = os.OpenRoot(filepath.Join(base, "/proc"))
	return r
}

// Close releases the /sys and /proc root handles.
func (r *Reader) Close() {
	if r.sys != nil {
		r.sys.Close()
	}
	if r.proc != nil {
		r.proc.Close()
	}
}

// RootStatus reports whether the /sys and /proc roots opened, for evidence.
func (r *Reader) RootStatus() (sysOK, procOK bool, detail string) {
	sysOK, procOK = r.sys != nil, r.proc != nil
	switch {
	case !sysOK && !procOK:
		detail = "os.Root unavailable for /sys and /proc; degraded to plain bounded reads"
	case !sysOK:
		detail = "os.Root unavailable for /sys; degraded to plain bounded reads"
	case !procOK:
		detail = "os.Root unavailable for /proc; degraded to plain bounded reads"
	}
	return sysOK, procOK, detail
}

// rootFor returns the *os.Root covering p and p's path relative to it.
func (r *Reader) rootFor(p string) (*os.Root, string) {
	switch {
	case r.sys != nil && (p == "/sys" || strings.HasPrefix(p, "/sys/")):
		return r.sys, relTo(p, "/sys")
	case r.proc != nil && (p == "/proc" || strings.HasPrefix(p, "/proc/")):
		return r.proc, relTo(p, "/proc")
	}
	return nil, ""
}

func relTo(p, root string) string {
	rel := strings.TrimPrefix(strings.TrimPrefix(p, root), "/")
	if rel == "" {
		return "."
	}
	return rel
}

// full maps an absolute host path onto the (possibly rebased) real path.
func (r *Reader) full(p string) string {
	if r.base == "" {
		return p
	}
	return filepath.Join(r.base, p)
}

// Exists reports whether the path can be lstat-ed. It is a capability gate, not
// evidence: absence still has to be proved by a successful listing (L25).
func (r *Reader) Exists(p string) bool {
	obs := r.Stat(p)
	return obs.Status == StatusOK
}

// Read performs the one bounded read.
//
//   - the open uses O_RDONLY|O_NONBLOCK|O_CLOEXEC, plus O_NOFOLLOW outside
//     /sys and /proc, so a FIFO cannot block and a swapped symlink cannot be
//     followed;
//   - the fd (not a prior lstat) is fstat-ed and must be a regular file, which
//     rejects device nodes, FIFOs, sockets and directories in one test;
//   - exactly Cap+1 bytes are requested so truncation is a fact, not a guess.
func (r *Reader) Read(p string, pol Policy) Observation {
	start := time.Now()
	obs := Observation{Source: p, Kind: KindFileRead}
	if pol.Cap <= 0 {
		pol.Cap = CapSmall
	}

	f, resolved, err := r.open(p, pol)
	if err != nil {
		obs.Status, obs.Errno = Classify(err)
		obs.Elapsed = time.Since(start)
		obs.Detail = shortErr(err)
		if resolved != "" {
			obs.Meta = &Meta{ResolvedPath: resolved}
		}
		return obs
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		obs.Status, obs.Errno = Classify(err)
		obs.Elapsed = time.Since(start)
		obs.Detail = shortErr(err)
		return obs
	}
	if !fi.Mode().IsRegular() {
		obs.Status, obs.Errno = Classify(errNotRegular)
		obs.Elapsed = time.Since(start)
		obs.Detail = "refused " + fileTypeOf(fi.Mode()) + " at " + p
		obs.Meta = &Meta{FileType: fileTypeOf(fi.Mode())}
		return obs
	}

	buf, err := io.ReadAll(io.LimitReader(f, pol.Cap+1))
	obs.Elapsed = time.Since(start)
	obs.Bytes = int64(len(buf))
	if int64(len(buf)) > pol.Cap {
		buf = buf[:pol.Cap]
		obs.Bytes = pol.Cap
		obs.Truncated = true
	}
	obs.Value = string(buf)
	if err != nil {
		// A short read after a successful open (EIO on a failing device, EAGAIN
		// on a nonblocking pseudo-file) is a partial observation, not a value.
		obs.Status, obs.Errno = Classify(err)
		obs.Detail = shortErr(err)
		return obs
	}
	obs.Status = StatusOK
	mode := int64(fi.Mode().Perm())
	obs.Meta = &Meta{Mode: &mode, ResolvedPath: resolved}
	if uid, gid, _, _, ok := ownerOf(fi); ok {
		obs.Meta.UID, obs.Meta.GID = &uid, &gid
	}
	return obs
}

// open resolves the symlink policy and returns an open, still-ungated fd.
func (r *Reader) open(p string, pol Policy) (*os.File, string, error) {
	if root, rel := r.rootFor(p); root != nil {
		// Inside an os.Root: in-root symlinks are followed deliberately (they
		// are how /sys is structured) and escapes are refused by the kernel.
		f, err := root.OpenFile(rel, openBase, 0)
		return f, "", err
	}

	target := r.full(p)
	resolved := ""
	if li, err := os.Lstat(target); err == nil && li.Mode()&fs.ModeSymlink != 0 {
		if !pol.Follow {
			return nil, "", errSymlinkDenied
		}
		rp, err := filepath.EvalSymlinks(target)
		if err != nil {
			return nil, "", err
		}
		if escapesToUserTree(r.unbase(target), r.unbase(rp)) {
			return nil, r.unbase(rp), errSymlinkEscape
		}
		resolved, target = r.unbase(rp), rp
	}
	// O_NOFOLLOW on the final open closes the lstat/open race: if the path was
	// swapped for a symlink in between, the open fails with ELOOP.
	f, err := os.OpenFile(target, openBase|openNoFollow, 0)
	return f, resolved, err
}

func (r *Reader) unbase(p string) string {
	if r.base == "" {
		return p
	}
	if rel, err := filepath.Rel(r.base, p); err == nil && !strings.HasPrefix(rel, "..") {
		return "/" + filepath.ToSlash(rel)
	}
	return p
}

// escapesToUserTree reports whether a system path resolves into a tree local
// users can write to.
func escapesToUserTree(from, to string) bool {
	from, to = filepath.ToSlash(from), filepath.ToSlash(to)
	for _, pre := range userWritablePrefixes {
		if strings.HasPrefix(to, pre) && !strings.HasPrefix(from, pre) {
			return true
		}
	}
	return false
}

// Stat records presence, type and permissions without ever opening the object.
// This is the entire secrets surface: metadata is the finding, content is not
// (EVIDENCE_MODEL §2).
func (r *Reader) Stat(p string) Observation {
	start := time.Now()
	obs := Observation{Source: p, Kind: KindFileMetadata}
	var fi fs.FileInfo
	var err error
	if root, rel := r.rootFor(p); root != nil {
		fi, err = root.Lstat(rel)
	} else {
		fi, err = os.Lstat(r.full(p))
	}
	obs.Elapsed = time.Since(start)
	if err != nil {
		obs.Status, obs.Errno = Classify(err)
		obs.Detail = shortErr(err)
		no := false
		if obs.Status == StatusENOENT {
			obs.Meta = &Meta{Exists: &no}
		}
		return obs
	}
	yes := true
	mode := int64(fi.Mode().Perm())
	size := fi.Size()
	obs.Status = StatusOK
	obs.Meta = &Meta{Exists: &yes, FileType: fileTypeOf(fi.Mode()), Mode: &mode, Size: &size}
	if uid, gid, _, _, ok := ownerOf(fi); ok {
		obs.Meta.UID, obs.Meta.GID = &uid, &gid
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		if root, rel := r.rootFor(p); root != nil {
			obs.Meta.SymlinkTarget, _ = root.Readlink(rel)
		} else {
			obs.Meta.SymlinkTarget, _ = os.Readlink(r.full(p))
		}
	}
	obs.Value = fileTypeOf(fi.Mode())
	return obs
}

// ReadDir lists a directory with an entry cap. A cap hit is recorded as
// BudgetExhausted: absence is only provable from a listing that completed (L25).
func (r *Reader) ReadDir(p string, max int) ([]fs.DirEntry, Observation) {
	start := time.Now()
	obs := Observation{Source: p, Kind: KindDirWalk, Meta: &Meta{Root: p, BudgetExhausted: "none"}}
	if max <= 0 {
		max = 4096
	}
	var f *os.File
	var err error
	if root, rel := r.rootFor(p); root != nil {
		f, err = root.Open(rel)
	} else {
		f, err = os.OpenFile(r.full(p), openBase|openNoFollow|openDirectory, 0)
	}
	if err != nil {
		obs.Status, obs.Errno = Classify(err)
		obs.Elapsed = time.Since(start)
		obs.Detail = shortErr(err)
		return nil, obs
	}
	defer f.Close()

	ents, err := f.ReadDir(max + 1)
	obs.Elapsed = time.Since(start)
	if err != nil && !errors.Is(err, io.EOF) {
		obs.Status, obs.Errno = Classify(err)
		obs.Detail = shortErr(err)
		obs.Meta.EntriesScanned = int64(len(ents))
		return ents, obs
	}
	if len(ents) > max {
		ents = ents[:max]
		obs.Truncated = true
		obs.Meta.BudgetExhausted = "entries"
	}
	obs.Meta.EntriesScanned = int64(len(ents))
	obs.Status = StatusOK
	obs.Bytes = int64(len(ents))
	return ents, obs
}

// ReadDirNames returns the sorted entry names of a directory.
func (r *Reader) ReadDirNames(p string, max int) ([]string, Observation) {
	ents, obs := r.ReadDir(p, max)
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		names = append(names, e.Name())
	}
	slices.Sort(names)
	return names, obs
}

// ReadTrimmed reads a small attribute and returns its trimmed text.
func (r *Reader) ReadTrimmed(p string, pol Policy) (string, Observation) {
	obs := r.Read(p, pol)
	return strings.TrimSpace(obs.Value), obs
}

func fileTypeOf(m fs.FileMode) string {
	switch {
	case m.IsRegular():
		return "regular"
	case m.IsDir():
		return "dir"
	case m&fs.ModeSymlink != 0:
		return "symlink"
	case m&fs.ModeCharDevice != 0:
		return "chardev"
	case m&fs.ModeDevice != 0:
		return "blockdev"
	case m&fs.ModeNamedPipe != 0:
		return "fifo"
	case m&fs.ModeSocket != 0:
		return "socket"
	}
	return "other"
}

// shortErr renders an error without leaking a full host path twice.
func shortErr(err error) string {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Op + ": " + pe.Err.Error()
	}
	return err.Error()
}

// ReadLinkBase returns the base name of a symlink target, which is how the bus
// a device sits on is read (/sys/block/<d>/device/subsystem -> ".../nvme").
// The link is read, never followed to a value.
func (r *Reader) ReadLinkBase(p string) (string, Observation) {
	start := time.Now()
	obs := Observation{Source: p, Kind: KindFileMetadata}
	var target string
	var err error
	if root, rel := r.rootFor(p); root != nil {
		target, err = root.Readlink(rel)
	} else {
		target, err = os.Readlink(r.full(p))
	}
	obs.Elapsed = time.Since(start)
	if err != nil {
		obs.Status, obs.Errno = Classify(err)
		obs.Detail = shortErr(err)
		return "", obs
	}
	obs.Status = StatusOK
	obs.Value = path.Base(target)
	obs.Meta = &Meta{SymlinkTarget: target, FileType: "symlink"}
	return obs.Value, obs
}

// Base returns the fixture base (empty in production). Used by checks that must
// build a path for a bounded walk.
func (r *Reader) Base() string { return r.base }

// JoinPath joins an absolute host path with further components.
func JoinPath(elem ...string) string { return path.Join(elem...) }
