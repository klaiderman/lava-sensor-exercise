package probe

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Walk budgets. A walk that hits any of them stops and says so: absence is only
// provable from an enumeration that completed (L25).
const (
	WalkEntries = 200000
	WalkDepth   = 12
	WalkTime    = 8 * time.Second
)

// prunedPrefixes are never descended into during a content-bearing walk: they
// are synthetic, enormous, or device-backed.
var prunedPrefixes = []string{"/proc", "/sys", "/dev", "/run", "/snap", "/var/lib/docker", "/var/lib/containers"}

// NetworkFSTypes are filesystems whose server can stop answering. A read of one
// in that state is uninterruptible: no context, no deadline and no close gets
// control back. The walk refuses to START on one - refusing to CROSS into one
// was never enough, because a scan root can be on it already.
var NetworkFSTypes = map[string]bool{
	"nfs": true, "nfs4": true, "cifs": true, "smb3": true, "smbfs": true,
	"fuse.sshfs": true, "fuse.s3fs": true, "afs": true, "9p": true,
	"ceph": true, "glusterfs": true, "lustre": true, "coda": true, "ncpfs": true,
}

// WalkBudget bounds one enumeration.
type WalkBudget struct {
	MaxDepth   int
	MaxEntries int
	MaxTime    time.Duration
	// Deadline, when non-zero, caps MaxTime from the caller's context.
	Deadline time.Time
	// NetworkFSMounts maps a mount point to its filesystem type. A root under
	// one of them is skipped with the skip recorded, unless AllowNetworkFS.
	NetworkFSMounts map[string]string
	// AllowNetworkFS lets a check that explicitly targets network storage walk
	// it anyway.
	AllowNetworkFS bool
}

// WalkResult is the boundary of an enumeration. It is mandatory evidence: a
// finding that reports "nothing found" without it is invalid.
type WalkResult struct {
	Root           string   `json:"root"`
	EntriesScanned int64    `json:"entries_scanned"`
	DirsPruned     []string `json:"dirs_pruned"`
	UnreadableDirs []string `json:"unreadable_dirs"`
	// UnreadableDirsCount and DirsPrunedCount are counters, not lists: the
	// lists are capped for size, and a boundary that is dropped from a capped
	// list would otherwise disappear from the evidence entirely.
	UnreadableDirsCount int64  `json:"unreadable_dirs_count"`
	DirsPrunedCount     int64  `json:"dirs_pruned_count"`
	ListsTruncated      bool   `json:"boundary_lists_truncated,omitempty"`
	CrossedMounts       bool   `json:"crossed_mounts"`
	BudgetExhausted     string `json:"budget_exhausted"`
	Errno               string `json:"errno,omitempty"`
	// SkippedFSType names the network filesystem this root sits on, when the
	// walk declined to start.
	SkippedFSType string `json:"skipped_network_fstype,omitempty"`
	// SymlinkTarget is set when the root was a symlink the walk followed; the
	// enumeration below is of the target.
	SymlinkTarget string `json:"root_symlink_target,omitempty"`
	// SkipReason, when set, says in one closed-vocabulary phrase why the walk
	// did not start. Every value it can take is listed in walkSkipReasons.
	SkipReason string `json:"root_skip_reason,omitempty"`
}

// WalkSkipReasons is the closed set of phrases Walk uses when it declines to
// start. A reason outside it is a defect: an internal token such as ENOTREG
// reaching a finding tells a reader nothing they can act on.
// TestWalkSkipReasonsAreInTheClosedVocabulary drives every refusal path and
// holds each one to this set.
var WalkSkipReasons = map[string]bool{
	"root is on network storage":                               true,
	"root is not a directory":                                  true,
	"root is a symlink to a non-directory":                     true,
	"root is a symlink whose target is unresolvable":           true,
	"root is a symlink onto network storage":                   true,
	"root is a symlink to a target writable by other accounts": true,
}

// Complete reports whether the enumeration finished, which is the only state in
// which the absence of a match is evidence.
//
// A denied subtree is not a completed enumeration. filepath.WalkDir calls the
// visitor a second time with the error and then carries on, so a walk that
// could not enter /root looks finished unless the boundary is consulted here;
// that is how "no exposed key material" came to be reported for a directory the
// sensor never saw inside.
func (w WalkResult) Complete() bool {
	return w.BudgetExhausted == "none" && w.Errno == "" &&
		w.UnreadableDirsCount == 0 && !w.CrossedMounts
}

// Boundary renders why an enumeration is not evidence of absence.
func (w WalkResult) Boundary() string {
	var parts []string
	if w.Errno != "" {
		parts = append(parts, w.Root+" could not be opened ("+w.Errno+")")
	}
	if w.UnreadableDirsCount > 0 {
		sample := w.UnreadableDirs
		if len(sample) > 4 {
			sample = sample[:4]
		}
		parts = append(parts, itoa(w.UnreadableDirsCount)+" directory/ies under "+w.Root+
			" could not be read ("+strings.Join(sample, ", ")+")")
	}
	if w.CrossedMounts {
		parts = append(parts, "a mount boundary under "+w.Root+" was not crossed")
	}
	if w.BudgetExhausted != "none" && w.BudgetExhausted != "" {
		parts = append(parts, "the "+w.BudgetExhausted+" budget was exhausted under "+w.Root)
	}
	return strings.Join(parts, "; ")
}

// Walk enumerates a tree under explicit bounds.
//
// Symlinks are never followed (WalkDir does not follow them), the walk never
// crosses a mount boundary (xdev, keyed on the root's st_dev), synthetic trees
// are pruned, and depth, entry count and wall time are all capped. An EACCES on
// a subtree is recorded as a boundary and the walk continues: "we could not
// read that directory" is a result, "nothing is in there" is not.
func (r *Reader) Walk(root string, b WalkBudget, visit func(path string, d fs.DirEntry)) (WalkResult, Observation) {
	if b.MaxDepth <= 0 {
		b.MaxDepth = WalkDepth
	}
	if b.MaxEntries <= 0 {
		b.MaxEntries = WalkEntries
	}
	if b.MaxTime <= 0 {
		b.MaxTime = WalkTime
	}
	res := WalkResult{Root: root, BudgetExhausted: "none", DirsPruned: []string{}, UnreadableDirs: []string{}}
	obs := Observation{Source: root, Kind: KindDirWalk}
	start := time.Now()
	deadline := start.Add(b.MaxTime)
	if !b.Deadline.IsZero() && b.Deadline.Before(deadline) {
		deadline = b.Deadline
	}

	if !b.AllowNetworkFS {
		if fstype, on := networkFSFor(root, b.NetworkFSMounts); on {
			res.SkippedFSType = fstype
			res.BudgetExhausted = "network-filesystem"
			obs.Status = StatusUnsupported
			obs.Errno = "ENOTSUP"
			obs.Refused = true
			obs.Truncated = true
			obs.Elapsed = time.Since(start)
			obs.Detail = "not walked: " + root + " is on a " + fstype +
				" mount, whose server can stop answering in a way no deadline can interrupt"
			obs.Meta = &Meta{Root: root, BudgetExhausted: res.BudgetExhausted}
			return res, obs
		}
	}

	base := r.full(root)
	rootInfo, err := os.Lstat(base)
	if err != nil {
		obs.Status, obs.Errno = Classify(err)
		obs.Detail = shortErr(err)
		obs.Elapsed = time.Since(start)
		res.Errno = obs.Errno
		return res, obs
	}
	// A distribution that moves /home to another filesystem leaves /home as a
	// symlink. Refusing to walk it would report "no keys" for every account on
	// the machine, so the symlink is followed ONCE - but only to somewhere this
	// sensor is willing to go: a local directory that no other unprivileged
	// account can rewrite underneath us.
	if rootInfo.Mode()&os.ModeSymlink != 0 {
		target, targetInfo, reason := r.resolveWalkRoot(base, b)
		if reason != "" {
			res.SkipReason = reason
			res.BudgetExhausted = "root-not-walkable"
			obs.Status = StatusUnsupported
			obs.Errno = "ENOTSUP"
			obs.Refused = true
			obs.Truncated = true
			obs.Elapsed = time.Since(start)
			obs.Detail = "not walked: " + reason + " (" + root + ")"
			obs.Meta = &Meta{Root: root, BudgetExhausted: res.BudgetExhausted}
			return res, obs
		}
		res.SymlinkTarget = r.unbase(target)
		base, rootInfo = target, targetInfo
	}
	if !rootInfo.IsDir() {
		obs.Status, obs.Errno = Classify(errNotRegular)
		obs.Detail = "not walked: walk root is not a directory"
		obs.Elapsed = time.Since(start)
		obs.Status = StatusUnsupported
		res.Errno = "ENOTDIR"
		res.SkipReason = "root is not a directory"
		res.BudgetExhausted = "root-not-walkable"
		return res, obs
	}
	_, _, rootDev, _, haveDev := ownerOf(rootInfo)

	_ = filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		host := r.unbase(p)
		if err != nil {
			// A denied subtree is the honest boundary of the enumeration. The
			// count is always kept; the list is capped.
			res.UnreadableDirsCount++
			if len(res.UnreadableDirs) < 64 {
				res.UnreadableDirs = append(res.UnreadableDirs, host)
			} else {
				res.ListsTruncated = true
			}
			return nil
		}
		if time.Now().After(deadline) {
			res.BudgetExhausted = "time"
			return fs.SkipAll
		}
		res.EntriesScanned++
		if res.EntriesScanned > int64(b.MaxEntries) {
			res.BudgetExhausted = "entries"
			return fs.SkipAll
		}
		if d.IsDir() {
			if depth(root, host) > b.MaxDepth {
				res.BudgetExhausted = "depth"
				return fs.SkipDir
			}
			for _, pre := range prunedPrefixes {
				if host == pre || strings.HasPrefix(host, pre+"/") {
					res.DirsPrunedCount++
					if len(res.DirsPruned) < 64 {
						res.DirsPruned = append(res.DirsPruned, host)
					} else {
						res.ListsTruncated = true
					}
					return fs.SkipDir
				}
			}
			if haveDev {
				if fi, e := d.Info(); e == nil {
					if _, _, dev, _, ok := ownerOf(fi); ok && dev != rootDev {
						// xdev: another filesystem is another question, and the
						// fact that one was declined belongs in the evidence.
						res.CrossedMounts = true
						res.DirsPrunedCount++
						if len(res.DirsPruned) < 64 {
							res.DirsPruned = append(res.DirsPruned, host+" (other filesystem, not crossed)")
						} else {
							res.ListsTruncated = true
						}
						return fs.SkipDir
					}
				}
			}
			return nil
		}
		visit(host, d)
		return nil
	})

	obs.Elapsed = time.Since(start)
	obs.Status = StatusOK
	obs.Bytes = res.EntriesScanned
	obs.Meta = &Meta{
		Root: root, EntriesScanned: res.EntriesScanned, DirsPruned: res.DirsPruned,
		UnreadableDirs: res.UnreadableDirs, BudgetExhausted: res.BudgetExhausted,
		CrossedMounts: res.CrossedMounts,
	}
	if !res.Complete() {
		// The observation itself carries the incompleteness, so a check that
		// marks this walk load-bearing cannot return pass from it.
		obs.Truncated = true
		obs.Detail = "enumeration did not complete: " + res.Boundary() + "; absence is not provable from it"
	}
	return res, obs
}

// resolveWalkRoot follows a symlinked walk root exactly one hop and decides
// whether this sensor is willing to enumerate what is on the other side. It
// returns the resolved base path, or a closed-vocabulary reason not to walk.
func (r *Reader) resolveWalkRoot(base string, b WalkBudget) (string, os.FileInfo, string) {
	target, err := filepath.EvalSymlinks(base)
	if err != nil {
		return "", nil, "root is a symlink whose target is unresolvable"
	}
	info, err := os.Stat(target)
	if err != nil {
		return "", nil, "root is a symlink whose target is unresolvable"
	}
	if !info.IsDir() {
		return "", nil, "root is a symlink to a non-directory"
	}
	if !b.AllowNetworkFS {
		if _, on := networkFSFor(r.unbase(target), b.NetworkFSMounts); on {
			return "", nil, "root is a symlink onto network storage"
		}
	}
	// A target another unprivileged account can write is a target it can
	// replace: what we would enumerate would be that account's choice, not the
	// machine's state.
	if info.Mode().Perm()&0o022 != 0 {
		return "", nil, "root is a symlink to a target writable by other accounts"
	}
	return target, info, ""
}

func depth(root, path string) int {
	rel := strings.TrimPrefix(path, root)
	return strings.Count(strings.Trim(rel, "/"), "/")
}

// networkFSFor reports whether a path lies under a network-filesystem mount,
// choosing the longest matching mount point.
func networkFSFor(path string, mounts map[string]string) (string, bool) {
	best, bestType := "", ""
	for mp, fstype := range mounts {
		if !NetworkFSTypes[fstype] {
			continue
		}
		if path == mp || (mp == "/" && strings.HasPrefix(path, "/")) ||
			strings.HasPrefix(path, strings.TrimSuffix(mp, "/")+"/") {
			if len(mp) > len(best) {
				best, bestType = mp, fstype
			}
		}
	}
	return bestType, best != ""
}
