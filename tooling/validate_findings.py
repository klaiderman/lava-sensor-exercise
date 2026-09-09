#!/usr/bin/env python3
"""Validate a findings.json against the derived schema plus the contract's extra semantic rules.

Usage:  "$HOME/.lava-workbench/venv/Scripts/python.exe" tooling/validate_findings.py <findings.json> [--schema task/derived/finding.schema.json]
Exit 0 = all checks pass; 1 = violations (printed as JSON pointers / rule ids); 2 = usage/IO error.
Checks beyond the schema (TASK_CONTRACT D1a, D3, D8, B6, C5a, LD-2):
  U1 check_id unique across findings          U2 every collected_at parses as RFC 3339
  U3 no empty string anywhere under machine   U4 no secret-shaped strings anywhere (PEM headers, sk-*, AKIA*, JWT-like, private key blobs)
  U5 findings sorted by (category, check_id)  U6 unknown/fail carry a non-empty reason
  U7 machine numeric 0 only with an unknowns marker for that field   U8 every category has >= 2 findings
  U9 severity rule: pass => info unless the finding is marked observational (evidence.observational true)
Requires: jsonschema>=4 and rfc3339-validator in the venv (installed during the exercise).
"""
import json
import re
import sys
from datetime import datetime

try:
    import jsonschema
    from jsonschema import Draft202012Validator
except ImportError:
    print("jsonschema not installed in this interpreter", file=sys.stderr)
    sys.exit(2)

args = sys.argv[1:]
if not args:
    print(__doc__)
    sys.exit(2)
path = args[0]
schema_path = "task/derived/finding.schema.json"
if "--schema" in args:
    schema_path = args[args.index("--schema") + 1]

doc = json.load(open(path, encoding="utf-8"))
schema = json.load(open(schema_path, encoding="utf-8"))
v = Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
violations = []
for e in sorted(v.iter_errors(doc), key=lambda e: list(e.absolute_path)):
    violations.append(("SCHEMA", "/" + "/".join(str(p) for p in e.absolute_path), e.message[:200]))

findings = doc.get("findings", []) if isinstance(doc.get("findings"), list) else []
ids = [f.get("check_id") for f in findings if isinstance(f, dict)]
dups = sorted({i for i in ids if ids.count(i) > 1})
if dups:
    violations.append(("U1", "/findings", f"duplicate check_id: {dups}"))

rfc = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")
def check_ts(ptr, val):
    if not isinstance(val, str) or not rfc.match(val):
        violations.append(("U2", ptr, f"not RFC 3339: {val!r}"))
        return
    try:
        datetime.fromisoformat(val.replace("Z", "+00:00"))
    except Exception:
        violations.append(("U2", ptr, f"unparseable timestamp: {val!r}"))
check_ts("/collected_at", doc.get("collected_at"))
for i, f in enumerate(findings):
    check_ts(f"/findings/{i}/collected_at", f.get("collected_at") if isinstance(f, dict) else None)

def walk(obj, ptr, fn):
    if isinstance(obj, dict):
        for k, val in obj.items():
            walk(val, f"{ptr}/{k}", fn)
    elif isinstance(obj, list):
        for i, val in enumerate(obj):
            walk(val, f"{ptr}/{i}", fn)
    else:
        fn(ptr, obj)

def machine_empty(ptr, val):
    if isinstance(val, str) and val.strip() == "":
        violations.append(("U3", ptr, "empty string in machine"))
walk(doc.get("machine", {}), "/machine", machine_empty)

secret_rx = [
    ("PEM private key header", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("OpenSSH private key", re.compile(r"BEGIN OPENSSH PRIVATE KEY")),
    ("Anthropic-style key", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}")),
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("JWT-like", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}")),
]
def secrets(ptr, val):
    if isinstance(val, str):
        for name, rx in secret_rx:
            if rx.search(val):
                violations.append(("U4", ptr, f"secret-shaped string ({name})"))
walk(doc, "", secrets)

keys = [(f.get("category", ""), f.get("check_id", "")) for f in findings if isinstance(f, dict)]
if keys != sorted(keys):
    violations.append(("U5", "/findings", "findings not sorted by (category, check_id)"))

for i, f in enumerate(findings):
    if not isinstance(f, dict):
        continue
    if f.get("status") in ("fail", "unknown") and not (isinstance(f.get("reason"), str) and f["reason"].strip()):
        violations.append(("U6", f"/findings/{i}/reason", "missing/empty reason for fail/unknown"))
    ev = f.get("evidence") if isinstance(f.get("evidence"), dict) else {}
    observational = bool(ev.get("observational")) or f.get("observational") is True
    if f.get("status") == "pass" and f.get("severity") != "info" and not observational:
        violations.append(("U9", f"/findings/{i}/severity", f"pass with severity {f.get('severity')!r} (rule: pass => info unless observational)"))

m = doc.get("machine", {}) if isinstance(doc.get("machine"), dict) else {}
unknowns = m.get("unknowns", {}) if isinstance(m.get("unknowns"), dict) else {}
def zero_check(field, val):
    if val == 0 and field not in unknowns:
        violations.append(("U7", f"/machine/{field}", "numeric 0 without a machine.unknowns marker"))
zero_check("memory_bytes", m.get("memory_bytes"))
if isinstance(m.get("cpu"), dict):
    zero_check("cpu.cores", m["cpu"].get("cores"))
for i, d in enumerate(m.get("storage", []) if isinstance(m.get("storage"), list) else []):
    if isinstance(d, dict) and d.get("size_bytes") == 0 and f"storage[{i}].size_bytes" not in unknowns and f"storage.{d.get('device')}.size_bytes" not in unknowns:
        violations.append(("U7", f"/machine/storage/{i}/size_bytes", "size_bytes 0 without an unknowns marker"))

from collections import Counter
cat_counts = Counter(f.get("category") for f in findings if isinstance(f, dict))
for c, n in cat_counts.items():
    if n < 2:
        violations.append(("U8", "/findings", f"category {c} has {n} finding(s) (< 2)"))
for req in ("REMOTE_ACCESS", "SECRETS_ON_DISK", "BMC_INBAND_ACCESS"):
    if req not in cat_counts:
        violations.append(("U8", "/findings", f"required category {req} missing"))

summary = {
    "file": path, "schema": schema_path, "findings": len(findings), "categories": dict(cat_counts),
    "statuses": dict(Counter(f.get("status") for f in findings if isinstance(f, dict))),
    "severities": dict(Counter(f.get("severity") for f in findings if isinstance(f, dict))),
    "violations": len(violations),
}
print(json.dumps(summary, indent=1))
for rule, ptr, msg in violations:
    print(f"VIOLATION {rule} {ptr}: {msg}")
print("RESULT:", "PASS" if not violations else "FAIL")
sys.exit(0 if not violations else 1)
