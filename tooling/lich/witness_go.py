"""Lich M5 sandbox -- Go witness adapter.

Invoked exactly like any Python witness, per Agent 3's runner protocol
(`plugins/lich-sandbox/scripts/runners/_base.py::Runner`) and the WSL
bridge (`plugins/lich-sandbox/scripts/bridge/wsl.py::run_in_wsl`):

    flag.file     = <absolute path to this file>
    flag.function = "witness_exec_replace"
    witness       = {"args": [wsl_binary_path, [argv...]],
                      "kwargs": {"chdir": wsl_dir_or_None}}

DESIGN NOTE -- why exec-replace instead of subprocess (load-bearing,
see reports/LICH_WITNESS.md, "NPROC" section):

`plugins/lich-sandbox/scripts/limits.py` and its WSL mirror
`bridge/_child_runner.py` hard-code `RLIMIT_NPROC = 0` inside the
sandboxed child, documented as the fork-bomb defense and marked "REQUIRES
a documented security review" to relax. This adapter's author attempted
exactly that documented relaxation (a payload-controlled `nproc_cap`
threaded through `_child_runner.py` / `wsl.py`, defaulting to the
existing 0 for every other flag class) and the edit was refused by the
operator's own permission system before it reached disk. That refusal is
respected here, not routed around: this file makes NO change to Lich's
cap-enforcement code and asks for NO relaxation.

Instead, every witness below replaces the sandboxed child's OWN process
image via `os.execve()`. execve() never creates a new process -- the
existing (already-counted) PID just starts running different code -- so
it is legal under `RLIMIT_NPROC = 0` exactly as shipped. rlimits
(CPU/AS/NOFILE/FSIZE) and the pending `signal.alarm()` set by
`_apply_caps()` before this module is even imported both survive
execve() (POSIX: rlimits and pending itimers are process attributes,
not image attributes), so the Go binary runs under the SAME fence Lich
would apply to a Python target.

Consequence, stated up front rather than discovered by a reader: a Go
test binary that itself needs to fork+exec a *further* child (the
hang/flood fixture in `internal/probe`'s own tests) will find that its
internal fork also hits `RLIMIT_NPROC = 0` and fails closed (EAGAIN).
That is a real, observed limitation of routing that specific witness
through Lich unmodified -- see witness 1 in reports/LICH_WITNESS.md,
which reports the plain-WSL-`timeout` run as the source of truth for
that case and the attempted-through-Lich run as evidence of the
blocker, not as the passing result.
"""

from __future__ import annotations

import os


def witness_exec_replace(binary: str, argv: list | None = None,
                          chdir: str | None = None,
                          extra_env: list | None = None) -> None:
    """Replace the current (already-capped) process with `binary`.

    Never returns on success -- the calling process becomes `binary`.
    Raises AssertionError before the exec if `binary` is not an absolute,
    executable path (fails loud inside the sandbox rather than silently
    laundering a bad witness into an infra exit code).
    """
    if not os.path.isabs(binary):
        raise AssertionError(f"binary must be an absolute WSL path: {binary!r}")
    if not os.access(binary, os.X_OK):
        raise AssertionError(f"binary is not executable: {binary!r}")
    if chdir:
        os.chdir(chdir)
    full_argv = [binary] + list(argv or [])
    env = list(extra_env or []) or [
        "PATH=/usr/bin:/bin",
        "HOME=/tmp",
        "LANG=C.UTF-8",
        "LC_ALL=C.UTF-8",
    ]
    os.execve(binary, full_argv, dict(kv.split("=", 1) for kv in env))
    # Unreachable if execve succeeded.
    raise RuntimeError("os.execve returned; this should be impossible")
