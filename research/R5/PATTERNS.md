# PATTERNS — cited Go patterns for the sensor

Illustrative snippets for the implementation-prompt author to adapt. Each is <= 30 lines and cited to a fact ID and its underlying source. None of this is finished production code.

## 1. Bounded subprocess execution

Cited: R5-F11 (default `Cancel` kills only the leader — `os/exec` source, `os.Process.Kill` doc), R5-F12/R5-F13 (`WaitDelay`, LOCAL_REPRO 30.01s → 0.21s), R5-F14 (LOCAL_REPRO: orphan survives `WaitDelay` alone), R5-F16 (`StdoutPipe` hazard), R5-F15 (stdlib `syscall` suffices).

```go
func run(ctx context.Context, budget time.Duration, cap int64, name string, args ...string) Observation {
    ctx, cancel := context.WithTimeout(ctx, budget)
    defer cancel()

    cmd := exec.CommandContext(ctx, name, args...)
    cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // own process group
    // MUST override: CommandContext's default Cancel is cmd.Process.Kill(), which
    // "only kills the Process itself, not any other processes it may have started".
    cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
    // MUST set: bounds (a) a child ignoring cancellation and (b) a child that exited
    // leaving pipes held open by a grandchild (golang/go#23019, cited in exec.go).
    cmd.WaitDelay = 2 * time.Second

    out := &limitWriter{cap: cap}          // capped io.Writer, sets .Truncated
    cmd.Stdout, cmd.Stderr = out, out      // not StdoutPipe: Wait-before-read is documented as incorrect
    cmd.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}

    start := time.Now()
    err := cmd.Run()
    obs := Observation{Source: name, Kind: "command", Value: out.String(),
        Truncated: out.Truncated, Elapsed: time.Since(start).Milliseconds()}
    var ee *exec.ExitError
    switch {
    case errors.Is(err, exec.ErrWaitDelay), ctx.Err() != nil: obs.Status = TIMEOUT
    case errors.Is(err, exec.ErrNotFound):                    obs.Status = UTILITY_MISSING
    case errors.As(err, &ee):                                 obs.Status = EXEC_ERROR; c := ee.ExitCode(); obs.ExitCode = &c
    case err != nil:                                          obs.Status = EXEC_ERROR; obs.Errno = err.Error()
    default:                                                  obs.Status = OK
    }
    return obs
}
```

Both `Setpgid`+`Cancel` and `WaitDelay` are required: LOCAL_REPRO measured that `WaitDelay` alone returned control to us but left a `sleep` grandchild running on the machine, while the group kill left zero survivors (R5-F14). `ctx.Err()` must be consulted explicitly because `CommandContext` surfaces `signal: killed` rather than the context error (R5-F11).

## 2. Safe bounded file read

Cited: R5-F18 (inode(7)/sysfs.rst — pseudofile sizes lie), R5-F19 (`os.ReadFile` is correct but unbounded), R5-F20 (LOCAL_REPRO: cap+1 truncation detection; `/dev/null` and `/dev/zero` rejected), R5-F24 (LOCAL_REPRO: plain open on a FIFO blocked >700ms).

```go
// readCapped opens with O_NONBLOCK so a FIFO cannot block the open, gates on the
// mode of the OPEN fd (no Lstat/open TOCTOU window), and detects truncation by
// reading cap+1 bytes. Never trust Stat().Size(): /proc reports 0, /sys reports 4096.
func readCapped(path string, cap int64) (data []byte, truncated bool, err error) {
    f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
    if err != nil {
        return nil, false, err // EACCES / ENOENT preserved as errno evidence
    }
    defer f.Close()
    fi, err := f.Stat()
    if err != nil {
        return nil, false, err
    }
    if !fi.Mode().IsRegular() { // rejects device, FIFO, socket, dir in one test
        return nil, false, fmt.Errorf("not a regular file: %v", fi.Mode())
    }
    b, err := io.ReadAll(io.LimitReader(f, cap+1))
    if int64(len(b)) > cap {
        return b[:cap], true, err
    }
    return b, false, err
}
```

## 3. Sysfs traversal with `os.Root`

Cited: R5-F21 (LOCAL_REPRO: 28/28 `/sys/block` entries are symlinks), R5-F22 (LOCAL_REPRO: in-root symlink followed, `../etc/passwd` rejected with "path escapes from parent"), R5-F23 (LOCAL_REPRO: works on `/proc` including the magic `self` symlink), R5-F45 (`os.DirFS` is not a security boundary).

```go
// Open once at startup; keep the handle for the whole scan.
sysRoot, err := os.OpenRoot("/sys")   // Go 1.24+; openat per component
if err != nil { /* degrade to plain bounded reads, record why */ }
defer sysRoot.Close()

// Relative symlinks that stay inside /sys are followed (this is required:
// every /sys/block entry is one). Anything escaping /sys is refused by the kernel.
size, err := sysRoot.ReadFile("block/nvme0n1/size")          // works
model, err := sysRoot.ReadFile("block/nvme0n1/device/model") // works, via symlink
_, escape := sysRoot.Open("../etc/passwd")                   // "path escapes from parent"

// Test seam: production passes sysRoot.FS(); tests pass a fixture fs.FS.
type machineReader struct{ sys fs.FS } // unexported field, set only from _test.go
```

A blanket `O_NOFOLLOW` or symlink-rejection policy here would enumerate zero block devices (R5-F21). `os.DirFS` is not a substitute — its own doc says it does not stop symlink escapes (R5-F45).

## 4. Bounded directory walk with xdev

Cited: R5-F29 (`WalkDir` does not follow symlinks, no built-in budget; `SkipAll` since Go 1.20), R5-F25 (LOCAL_REPRO: distinct `Stat_t.Dev` per mount).

```go
type budget struct {
    deadline time.Time
    maxDepth, maxEntries int
    rootDev  uint64      // from Lstat(root).Sys().(*syscall.Stat_t).Dev
    entries  int
    Exhausted, CrossedMount bool
}

func (b *budget) visit(root, path string, d fs.DirEntry, err error) error {
    if err != nil { return nil }                       // EACCES on a subtree: record, keep walking
    if time.Now().After(b.deadline) { b.Exhausted = true; return fs.SkipAll }
    if b.entries++; b.entries > b.maxEntries { b.Exhausted = true; return fs.SkipAll }
    if strings.Count(path[len(root):], string(os.PathSeparator)) > b.maxDepth { return fs.SkipDir }
    if d.IsDir() {
        if fi, e := d.Info(); e == nil {
            if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Dev != b.rootDev {
                b.CrossedMount = true; return fs.SkipDir // xdev
            }
        }
    }
    return nil
}
```

When `Exhausted` is true the finding must say so in evidence: absence is only provable from a listing that completed (R5-F29).

## 5. Per-check panic isolation and the never-skip guarantee

Cited: R5-F2 (node_exporter has no `recover()` and no per-collector deadline — the prior art is insufficient), R5-F3 (`ErrNoData` as the ancestor of UNKNOWN).

```go
func (r *Runner) runOne(parent context.Context, c Check) (f Finding) {
    f = Finding{CheckID: c.ID, Category: c.Category, Title: c.Title,
        Status: StatusUnknown, Severity: c.Impact, CollectedAt: r.now().UTC().Format(time.RFC3339)}
    if parent.Err() != nil { // whole-scan deadline already gone: still emit a finding
        f.Reason = "scan deadline exhausted before this check ran"
        return f
    }
    defer func() {
        if p := recover(); p != nil {
            f.Status, f.Severity = StatusUnknown, c.Impact
            f.Reason = fmt.Sprintf("check panicked: %v", p)
            f.Evidence = map[string]any{"panic": fmt.Sprint(p), "stack_head": headOfStack(4096)}
        }
    }()
    ctx, cancel := context.WithTimeout(parent, c.Budget)
    defer cancel()
    return c.Run(ctx, r.env) // returns a fully-populated Finding
}
```

The `Finding` is initialised *before* the deferred `recover()` so a panic still produces a complete, schema-valid finding. Every registered check yields exactly one finding per run (D3).

## 6. Deterministic output

Cited: R5-F30 (LOCAL_REPRO: map keys sorted, struct order preserved), R5-F31 (LOCAL_REPRO: `SetEscapeHTML(false)`, trailing newline), R5-F32 (LOCAL_REPRO: `time.Time` marshals as trimmed RFC3339Nano), R5-F56 (avoid `encoding/json/v2`), R5-F58 (validate before writing).

```go
sort.Slice(doc.Findings, func(i, j int) bool {
    if doc.Findings[i].Category != doc.Findings[j].Category {
        return doc.Findings[i].Category < doc.Findings[j].Category
    }
    return doc.Findings[i].CheckID < doc.Findings[j].CheckID
})

var buf bytes.Buffer
enc := json.NewEncoder(&buf)
enc.SetEscapeHTML(false) // keep "<", ">", "&" literal in config/evidence text
enc.SetIndent("", "  ")
if err := enc.Encode(doc); err != nil { return err } // Encode appends a newline

if err := compiledSchema.Validate(anyOf(buf.Bytes())); err != nil {
    return fmt.Errorf("output failed schema validation, refusing to write: %w", err)
}
tmp := outPath + ".tmp"
if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err != nil { return err }
return os.Rename(tmp, outPath) // atomic; no half-written artifact
```

`collected_at` is a pre-formatted string (`t.UTC().Format(time.RFC3339)`), never a marshalled `time.Time`, because RFC3339Nano trims trailing zeros and the field width would vary between runs (R5-F32). Byte counts, sizes, modes, uids and exit codes are `int64`, never floats (R5-F57).
