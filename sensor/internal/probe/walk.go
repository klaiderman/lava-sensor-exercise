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

// WalkBudget bounds one enumeration.
type WalkBudget struct {
	MaxDepth   int
	MaxEntries int
	MaxTime    time.Duration
	// Deadline, when non-zero, caps MaxTime from the caller's context.
	Deadline time.Time
}

// WalkResult is the boundary of an enumeration. It is mandatory evidence: a
// finding that reports "nothing found" without it is invalid.
type WalkResult struct {
	Root            string   `json:"root"`
	EntriesScanned  int64    `json:"entries_scanned"`
	DirsPruned      []string `json:"dirs_pruned"`
	UnreadableDirs  []string `json:"unreadable_dirs"`
	CrossedMounts   bool     `json:"crossed_mounts"`
	BudgetExhausted string   `json:"budget_exhausted"`
	Errno           string   `json:"errno,omitempty"`
}

// Complete reports whether the enumeration finished, which is the only state in
// which the absence of a match is evidence.
func (w WalkResult) Complete() bool { return w.BudgetExhausted == "none" && w.Errno == "" }

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

	base := r.full(root)
	rootInfo, err := os.Lstat(base)
	if err != nil {
		obs.Status, obs.Errno = Classify(err)
		obs.Detail = shortErr(err)
		obs.Elapsed = time.Since(start)
		res.Errno = obs.Errno
		return res, obs
	}
	if !rootInfo.IsDir() {
		obs.Status, obs.Errno = Classify(errNotRegular)
		obs.Detail = "walk root is not a directory"
		obs.Elapsed = time.Since(start)
		res.Errno = "ENOTDIR"
		return res, obs
	}
	_, _, rootDev, _, haveDev := ownerOf(rootInfo)

	_ = filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		host := r.unbase(p)
		if err != nil {
			// A denied subtree is the honest boundary of the enumeration.
			if len(res.UnreadableDirs) < 64 {
				res.UnreadableDirs = append(res.UnreadableDirs, host)
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
					res.DirsPruned = append(res.DirsPruned, host)
					return fs.SkipDir
				}
			}
			if haveDev {
				if fi, e := d.Info(); e == nil {
					if _, _, dev, _, ok := ownerOf(fi); ok && dev != rootDev {
						// xdev: another filesystem is another question.
						res.CrossedMounts = false
						res.DirsPruned = append(res.DirsPruned, host+" (other filesystem)")
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
	if res.BudgetExhausted != "none" {
		obs.Truncated = true
		obs.Detail = "enumeration stopped at its " + res.BudgetExhausted + " budget; absence is not provable from it"
	}
	return res, obs
}

func depth(root, path string) int {
	rel := strings.TrimPrefix(path, root)
	return strings.Count(strings.Trim(rel, "/"), "/")
}
