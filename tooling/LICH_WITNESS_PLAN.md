# Can Lich fence a Go program? Verdict: NO (as shipped), adapter needs one cap change

**Finding.** M5's `run()` protocol (`runners/_base.py::Runner`, both
`PosixPythonRunner` and `bridge.wsl.run_in_wsl`) is hardwired to
`(target_file, function_name, witness)`: the child always does
`importlib.util.spec_from_file_location` on a `.py` file, then
`getattr(mod, function_name)(*args, **kwargs)`. No "run this command" path
exists anywhere — `lich-python`/`lich-typescript` shell out to `ruff`/`tsc`,
but that's a separate, uncapped static-lint call, not the M5 fence.

**Harder blocker.** `limits.py`/`_child_runner.py` set `RLIMIT_NPROC = 0`
inside the fenced child ("hard-zero subprocess creation ... fork-bomb
defense"). That forbids `fork()+exec()` from *inside* the witnessed call —
a naive "Python witness that shells out to `go test`" can't even
`subprocess.run()` once caps apply. Raising it (0 -> 1) is required just to
admit one child exec — the module docstring says relaxation "REQUIRES a
documented security review"; not something to slip in quietly.

**Recommended adapter (minimal, honest about what's real):**
1. Compile OUTSIDE the fence (CI/dev step, not Lich) — a standalone
   linux/amd64 test binary, so `RLIMIT_NPROC=0` never has to survive
   `go build`/`go test`'s own compiler forks (those need many concurrent
   processes, incompatible with any small NPROC bump):
   `GOOS=linux GOARCH=amd64 go test -tags sensor_test_seam -c -o /tmp/sensor.test ./...`
2. Ship a tiny `witness_go.py`, one function per scenario, invoked exactly
   like any Python witness (`flag.file=witness_go.py`, `flag.function=witness_hang`,
   `witness={"args":[binary,argv,input],...}`). Sketch:
   ```python
   def witness_hang(binary, argv, input_bytes=b""):
       import subprocess
       p = subprocess.Popen([binary, *argv], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
       try:
           out, err = p.communicate(input=input_bytes, timeout=8)
       except subprocess.TimeoutExpired:
           p.kill(); raise TimeoutError("binary did not exit under fence")
       if len(out) > 2_000_000: raise AssertionError("stdout flood uncapped")
       if p.returncode not in (0, 1): raise AssertionError(f"exit {p.returncode}: {err[:500]!r}")
   ```
   Raise vs. return-clean is the whole adapter contract — `outcome.classify()`
   (exit0=no-bug, exception=confirmed-bug, alarm=timeout) needs **zero**
   changes beyond one `flag_class` in `outcome.py::_EXPECTED`
   (`"go-runtime": frozenset({"AssertionError","TimeoutError"})`).
3. `witness_synth.py` needs a new synthesizer for scenarios (b)/(c) (malformed
   fixtures, symlink loops) — current synth is div-zero/index-oob/null-deref
   only; new code, not reuse.
**Genuine Lich value over `go test -timeout` + `ulimit`:** CPU/AS/FSIZE/NOFILE
rlimits bind the Python parent *before* `exec()`, so they transitively cap the
Go binary — a hard OS kill a hung/cgo-blocked goroutine can't suppress (unlike
Go's cooperative `-timeout`) — plus 1 MB stdout truncation genuinely defends
witness (a)'s flood case, plus one shared JSONL evidence trail across languages.

**Theatre risk:** Lich's div-zero/index-oob classification does not transfer
to Go — the adapter does 100% of Go outcome interpretation itself. If the
only goal is "does it hang/flood," `timeout`+`ulimit` in a bash script gets
the same signal for far less machinery.

**Recommendation:** worth it only if the unified verdict/run-log pipeline
matters to the team; otherwise `go test -timeout` + `ulimit -v/-f` is
equivalent and cheaper. Lead should choose.
