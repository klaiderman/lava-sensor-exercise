"""Registry validator for the Tiny Custom Investigator (TCI).

Validates tooling/tci/probes.json:
  - id shape/uniqueness
  - timeout_s / cap_bytes bounds
  - dangling `requires` (fact never produced by any probe's `facts`)
  - forbidden tokens / mutating subcommands in `cmd`
  - first word of `cmd` (and of each pipeline/statement segment) is allowlisted

Importable: `validate_registry(registry) -> (ok: bool, errors: list[str])`.
CLI: `python check_registry.py probes.json` -> prints errors or a summary,
exits 1 on failure.
"""
import json
import re
import sys

ID_RE = re.compile(r'^[a-z0-9_]+(\.[a-z0-9_]+)*$')
VALID_SENSITIVITY = {"low", "paths", "identity", "maybe_secret_adjacent"}

# Base allowlist from the spec, plus a few read-only utilities/wrappers this
# registry needs (timeout, nft/iptables/ufw read-only status, passwd -S).
ALLOWED_FIRST_WORDS = {
    "cat", "head", "tail", "ls", "stat", "readlink", "realpath", "find", "grep",
    "egrep", "awk", "sed", "cut", "sort", "uniq", "wc", "tr", "echo", "printf",
    "test", "[", "id", "hostname", "hostnamectl", "uname", "uptime", "date",
    "nproc", "lscpu", "lsblk", "findmnt", "df", "mount", "getent", "lsmod",
    "lspci", "lsusb", "ip", "ss", "who", "last", "lastlog", "which", "command",
    "type", "systemctl", "systemd-detect-virt", "timedatectl", "journalctl",
    "dmesg", "ssh-keygen", "sshd", "ipmitool", "nvme", "smartctl", "mdadm",
    "dmsetup", "lvs", "vgs", "pvs", "multipath", "iscsiadm", "udevadm",
    "getcap", "getfacl", "dpkg", "rpm", "apt", "apt-get", "sysctl",
    "getenforce", "aa-status", "mokutil", "od", "xxd", "env", "true", "false",
    "sha256sum", "md5sum", "file", "zpool", "zfs", "docker", "crontab",
    "resolvectl", "ethtool", "chronyc", "ntpq", "wsl",
    "timeout", "nft", "iptables", "ufw", "passwd", "swapon", "ssh", "ps",
}
LOOP_KEYWORDS = {
    "do", "done", "if", "then", "elif", "else", "fi", "while", "until",
    "read", "[[", "]]", "in", "case", "esac",
}

SIMPLE_FORBIDDEN_COMMANDS = {
    "sudo", "su", "doas", "pkexec", "rm", "mv", "cp", "dd", "mkfs", "tee",
    "chmod", "chown", "chattr", "kill", "pkill", "reboot", "shutdown",
    "mount", "umount", "modprobe", "insmod", "rmmod", "curl", "wget", "nc",
    "ncat", "eval", "useradd", "usermod", "userdel",
}

FORBIDDEN_PATTERNS = [
    (re.compile(r'\bsystemctl\s+(start|stop|restart|reload|enable|disable|mask|'
                r'kill|edit|set-\S*)\b'), "systemctl mutating verb"),
    (re.compile(r'\bip\s+link\s+set\b'), "ip link set"),
    (re.compile(r'\bip\s+addr\s+(add|del)\b'), "ip addr add/del"),
    (re.compile(r'\biptables\s+-[AIDF]\b'), "iptables -[AIDF]"),
    (re.compile(r'\bnft\s+(add|delete|flush)\b'), "nft add/delete/flush"),
    (re.compile(r'\bapt(-get)?\s+(install|remove|upgrade)\b'), "apt install/remove/upgrade"),
    (re.compile(r'\b(yum|dnf)\s+(install|remove)\b'), "yum/dnf install/remove"),
    (re.compile(r'\bpip\d?\s+install\b'), "pip install"),
    (re.compile(r'\bpython\d?\s+-c\b'), "python -c"),
    (re.compile(r'\bperl\s+-e\b'), "perl -e"),
    (re.compile(r'\bsysctl\s+-w\b'), "sysctl -w"),
    (re.compile(r'\bcrontab\s+-[er]\b'), "crontab -e/-r"),
]

# command -> allowed argument prefixes (checked against the remainder of the
# segment after the command word)
COMMAND_ALLOWED_ARG_PREFIXES = {
    "ipmitool": ["-V", "mc info", "mc guid", "lan print", "user list",
                 "user summary", "channel info", "channel authcap",
                 "sel info", "sdr", "fru", "chassis status", "bmc info",
                 "sol info"],
    "systemctl": ["status", "show", "cat", "is-active", "is-enabled",
                  "list-units", "list-timers", "list-unit-files",
                  "list-sockets", "--version"],
    "apt": ["list"],
    "dpkg": ["-l", "-s", "-S", "--version"],
    "rpm": ["-q"],
    "mdadm": ["--detail", "--examine", "--version"],
    "nvme": ["list", "version", "id-ctrl", "smart-log"],
    "smartctl": ["--scan", "-i", "-H", "--version"],
    "dmsetup": ["ls", "info", "table", "--version"],
    "multipath": ["-ll", "-l"],
    "iscsiadm": ["-m session", "-m node", "--version"],
    "udevadm": ["info"],
    "docker": ["version", "ps", "info"],
    "crontab": ["-l"],
    "journalctl": ["--disk-usage", "-n", "--no-pager"],
    "sshd": ["-T", "-V", "-t", "-G"],
    "nft": ["list"],
    "iptables": ["-S"],
    "ufw": ["status"],
    "passwd": ["-S"],
    "swapon": ["--show"],
    "ssh": ["-V"],
}

REDIRECT_EXCEPTIONS = ["2>&1", "2>/dev/null", "</dev/null"]


def _mask_quotes(cmd):
    """Blank out the contents of quoted strings so a literal '>' or '<'
    used as ordinary text/comparison inside a quoted awk/grep script isn't
    mistaken for shell redirection."""
    out = []
    i, n = 0, len(cmd)
    in_single = in_double = False
    while i < n:
        c = cmd[i]
        if in_single:
            out.append(c if c == "'" else ' ')
            if c == "'":
                in_single = False
            i += 1
            continue
        if in_double:
            if c == '\\' and i + 1 < n:
                out.append('  ')
                i += 2
                continue
            out.append(c if c == '"' else ' ')
            if c == '"':
                in_double = False
            i += 1
            continue
        if c == "'":
            in_single = True
            out.append(c)
            i += 1
            continue
        if c == '"':
            in_double = True
            out.append(c)
            i += 1
            continue
        out.append(c)
        i += 1
    return ''.join(out)


def check_redirection(cmd):
    stripped = _mask_quotes(cmd)
    for exc in REDIRECT_EXCEPTIONS:
        stripped = stripped.replace(exc, "")
    return ">" not in stripped


def _segments(cmd):
    """Split cmd into top-level statement/pipeline segments, respecting
    single/double quotes and $(...) command-substitution nesting so that
    `|` or `;` inside a quoted regex or a nested subshell are not treated
    as real separators."""
    segments = []
    buf = []
    i, n = 0, len(cmd)
    depth = 0
    in_single = in_double = False
    while i < n:
        c = cmd[i]
        if in_single:
            buf.append(c)
            if c == "'":
                in_single = False
            i += 1
            continue
        if in_double:
            buf.append(c)
            if c == '\\' and i + 1 < n:
                buf.append(cmd[i + 1])
                i += 2
                continue
            if c == '"':
                in_double = False
            i += 1
            continue
        if c == "'":
            in_single = True
            buf.append(c)
            i += 1
            continue
        if c == '"':
            in_double = True
            buf.append(c)
            i += 1
            continue
        if c == '$' and cmd[i:i + 2] == '$(':
            depth += 1
            buf.append('$(')
            i += 2
            continue
        if depth > 0 and c == '(':
            depth += 1
            buf.append(c)
            i += 1
            continue
        if depth > 0 and c == ')':
            depth -= 1
            buf.append(c)
            i += 1
            continue
        if depth == 0:
            if cmd[i:i + 2] in ('&&', '||'):
                segments.append(''.join(buf))
                buf = []
                i += 2
                continue
            if c in ('|', ';'):
                segments.append(''.join(buf))
                buf = []
                i += 1
                continue
        buf.append(c)
        i += 1
    if buf:
        segments.append(''.join(buf))
    return [s.strip() for s in segments if s.strip()]


def _leading_command(seg):
    """Return (skip, word, rest) for a segment.

    skip=True means the segment is not itself a command invocation to
    validate (e.g. a `for VAR in LIST` loop header, or a bare loop
    keyword) -- there is nothing further to check.
    `timeout [-k N] SECONDS <cmd>...` is unwrapped so the real command is
    what gets validated.
    """
    tokens = seg.split()
    if not tokens:
        return True, None, ""
    if tokens[0] == "for":
        return True, None, ""
    while tokens and tokens[0] in LOOP_KEYWORDS:
        tokens = tokens[1:]
    if not tokens:
        return True, None, ""
    if tokens[0] == "timeout":
        j = 1
        while j < len(tokens) and (tokens[j].startswith('-') or
                                    tokens[j].replace('.', '', 1).isdigit()):
            j += 1
        tokens = tokens[j:]
        if not tokens:
            return True, None, ""
    word = tokens[0]
    pos = seg.find(word)
    rest = seg[pos + len(word):].strip() if pos != -1 else ""
    return False, word, rest


def check_forbidden_commands(cmd):
    violations = []
    for pat, label in FORBIDDEN_PATTERNS:
        if pat.search(cmd):
            violations.append(f"forbidden pattern ({label}) in cmd: {cmd!r}")
    if not check_redirection(cmd):
        violations.append(f"forbidden redirection '>' in cmd: {cmd!r}")
    for seg in _segments(cmd):
        skip, word, _rest = _leading_command(seg)
        if skip:
            continue
        if word in SIMPLE_FORBIDDEN_COMMANDS:
            violations.append(f"forbidden command '{word}' in cmd: {cmd!r}")
    return violations


def check_first_words(cmd):
    violations = []
    for seg in _segments(cmd):
        skip, word, _rest = _leading_command(seg)
        if skip:
            continue
        if word in ("bash", "sh"):
            if not (seg.startswith("bash -c") or seg.startswith("sh -c")):
                violations.append(
                    f"disallowed bash/sh usage (only 'bash -c' inside a loop "
                    f"is allowed) in segment {seg!r} of cmd: {cmd!r}")
            continue
        if word not in ALLOWED_FIRST_WORDS:
            violations.append(
                f"disallowed leading command '{word}' in segment {seg!r} "
                f"of cmd: {cmd!r}")
    return violations


def check_subcommand_allowlist(cmd):
    violations = []
    for seg in _segments(cmd):
        skip, word, rest = _leading_command(seg)
        if skip:
            continue
        allowed_prefixes = COMMAND_ALLOWED_ARG_PREFIXES.get(word)
        if allowed_prefixes is None:
            continue
        if not any(rest.startswith(p) for p in allowed_prefixes):
            violations.append(
                f"'{word}' used with disallowed subcommand/args in segment "
                f"{seg!r} of cmd: {cmd!r}")
    return violations


def validate_registry(registry):
    errors = []
    probes = registry.get("probes")
    if not isinstance(probes, list) or not probes:
        return False, ["registry has no probes"]

    seen_ids = set()
    fact_producers = {}
    for p in probes:
        pid = p.get("id", "")
        for rule in (p.get("facts") or []):
            fact_producers.setdefault(rule.get("name"), []).append(pid)

    for p in probes:
        pid = p.get("id", "")
        if not pid or not ID_RE.match(pid):
            errors.append(f"invalid or empty id: {pid!r}")
        elif pid in seen_ids:
            errors.append(f"duplicate id: {pid!r}")
        else:
            seen_ids.add(pid)

        timeout_s = p.get("timeout_s")
        if not isinstance(timeout_s, (int, float)) or timeout_s <= 0:
            errors.append(f"[{pid}] missing/non-positive timeout_s")
        elif timeout_s > 60:
            errors.append(f"[{pid}] timeout_s {timeout_s} exceeds max 60")

        cap_bytes = p.get("cap_bytes")
        if not isinstance(cap_bytes, (int, float)) or cap_bytes <= 0:
            errors.append(f"[{pid}] missing/non-positive cap_bytes")
        elif cap_bytes > 1048576:
            errors.append(f"[{pid}] cap_bytes {cap_bytes} exceeds max 1048576")

        cmd = p.get("cmd", "")
        if not cmd:
            errors.append(f"[{pid}] missing cmd")
        else:
            for v in check_forbidden_commands(cmd):
                errors.append(f"[{pid}] {v}")
            for v in check_first_words(cmd):
                errors.append(f"[{pid}] {v}")
            for v in check_subcommand_allowlist(cmd):
                errors.append(f"[{pid}] {v}")

        sensitivity = p.get("sensitivity")
        if sensitivity not in VALID_SENSITIVITY:
            errors.append(f"[{pid}] invalid sensitivity: {sensitivity!r}")

        for req in p.get("requires") or []:
            fact = req.get("fact")
            if fact not in fact_producers:
                errors.append(
                    f"[{pid}] dangling requires: fact {fact!r} is never "
                    f"produced by any probe's facts")

    return (len(errors) == 0), errors


def summarize(registry):
    probes = registry.get("probes", [])
    groups = sorted({p.get("group", "?") for p in probes})
    max_timeout = max((p.get("timeout_s", 0) for p in probes), default=0)
    sum_caps = sum(p.get("cap_bytes", 0) for p in probes)
    lines = [
        f"probes: {len(probes)}",
        f"groups ({len(groups)}): {', '.join(groups)}",
        f"max timeout_s: {max_timeout}",
        f"sum cap_bytes: {sum_caps}",
    ]
    return "\n".join(lines)


def load_registry(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print("usage: check_registry.py <probes.json>", file=sys.stderr)
        return 2
    registry = load_registry(argv[0])
    ok, errors = validate_registry(registry)
    if not ok:
        print(f"REGISTRY INVALID: {len(errors)} error(s)", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1
    print("REGISTRY OK")
    print(summarize(registry))
    return 0


if __name__ == "__main__":
    sys.exit(main())
