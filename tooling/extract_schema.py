#!/usr/bin/env python3
"""Extract the findings.json output contract embedded in the supplied Lava brief into a standalone JSON Schema.

Decision (user, 2026-09-09): the schema contract is embedded in the supplied PDF/HTML; derive
task/derived/finding.schema.json from it faithfully, with no invented constraints, and record provenance.

Steps:
 1. Locate "The output shape" section in the HTML (task/original/Lava-Sensor-Exercise.html) and in the PDF text
    layer (task/derived/pdf_text_extract.txt, produced by pypdf from task/original/Lava-Sensor-Exercise.pdf).
 2. Cross-check that the two embedded contract blocks agree token-for-token (ignoring whitespace/rendering).
 3. Emit task/derived/finding.schema.json + task/derived/SCHEMA_PROVENANCE.md.
"""
import hashlib
import json
import re
import sys

HTML = "task/original/Lava-Sensor-Exercise.html"
PDFTXT = "task/derived/pdf_text_extract.txt"
OUT = "task/derived/finding.schema.json"
PROV = "task/derived/SCHEMA_PROVENANCE.md"


def html_text(path):
    s = open(path, encoding="utf-8").read()
    body = s.split("</style>", 1)[1]
    body = re.sub(r"<br[^>]*>", "\n", body)
    body = re.sub(r"</(p|li|h[1-6]|div|tr|section|pre|blockquote)>", "\n", body)
    body = re.sub(r"<[^>]+>", "", body)
    for a, b in [("&amp;", "&"), ("&lt;", "<"), ("&gt;", ">"), ("&quot;", '"'), ("&#39;", "'"), ("&nbsp;", " ")]:
        body = body.replace(a, b)
    return body


def contract_block(text):
    """Return the text from the "The output shape" heading through the closing brace of the JSON example."""
    i = text.rindex("The output shape")  # the section heading is the LAST occurrence (an earlier mention sits in the "What you get" list)
    j = text.index("Extra fields are welcome anywhere", i)
    return text[i:j]


def norm_tokens(block):
    # JSON-ish token stream: strip comments text is kept (it is part of the contract), collapse whitespace
    return re.sub(r"\s+", " ", block).strip()


html_block = contract_block(html_text(HTML))
pdf_block = contract_block(open(PDFTXT, encoding="utf-8").read().replace("\n===== PAGE", "\n").replace("=====", ""))

h_norm = norm_tokens(html_block)
p_norm = norm_tokens(pdf_block)
# The PDF text layer renders "--out" as "/-out" and drops some spacing; compare on a canonical form
canon = lambda s: re.sub(r"[^A-Za-z0-9_\"{}\[\]:,|<>./]", "", s).replace("/-", "--").replace("\"//.\"", "\"...\"").replace("//}", "/}")
agree = canon(h_norm) == canon(p_norm)
print("HTML block chars:", len(html_block), "| PDF block chars:", len(pdf_block), "| canonical agreement:", agree)
if not agree:
    import difflib
    for line in difflib.unified_diff(canon(h_norm).split(","), canon(p_norm).split(","), lineterm="", n=0):
        print("  ", line[:160])

# Prose rules that accompany the example (quoted from the brief, both files):
#  - "schema_version": "1"                              -> literal value in the example (not a <placeholder>)
#  - "collected_at": "<RFC 3339 timestamp>"              -> string, RFC 3339 date-time
#  - "sensor_version": "<optional>"                      -> optional string
#  - machine fields: "Report at least these"            -> required; owner "<or an explicit unknown>" is a string
#  - cpu.cores 0, memory_bytes 0, storage[].size_bytes 0 -> integers (example uses integer literals)
#  - findings[].category "// UPPER_SNAKE_CASE"           -> pattern
#  - findings[].check_id "// unique per check"           -> uniqueness is cross-item; not expressible in JSON Schema core,
#                                                          documented, enforced by the sensor's tests
#  - status "pass" | "fail" | "unknown"; severity "critical" | "high" | "medium" | "low" | "info"  -> enums
#  - reason "<required when status is fail or unknown>"  -> conditional requirement
#  - evidence "{ /* what someone needs to act on it */ }" -> object, free-form
#  - "Extra fields are welcome anywhere"                 -> additionalProperties left open everywhere (JSON Schema default)

schema = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Lava sensor findings.json (derived from the supplied brief)",
    "description": ("DERIVED ARTIFACT, not an original Lava file: machine-readable transcription of the output contract "
                    "embedded in task/original/Lava-Sensor-Exercise.html and .pdf (section 'The output shape' plus its "
                    "accompanying prose). No constraints beyond the brief were added; where the brief states a rule in prose "
                    "(required-when, enums, UPPER_SNAKE_CASE, extra fields welcome) it is encoded here. "
                    "See task/derived/SCHEMA_PROVENANCE.md."),
    "type": "object",
    "required": ["schema_version", "collected_at", "machine", "findings"],
    "properties": {
        "schema_version": {"type": "string", "const": "1",
                           "description": "Literal value given in the brief example (\"1\")."},
        "collected_at": {"type": "string", "format": "date-time", "description": "RFC 3339 timestamp."},
        "sensor_version": {"type": "string", "description": "Optional per the brief."},
        "machine": {
            "type": "object",
            "description": "Part one: describe the machine. 'Report at least these' -> all listed fields required. "
                           "If a value cannot be determined the brief requires the output to say so explicitly "
                           "(never an empty string or a guess); owner explicitly allows an explicit-unknown value.",
            "required": ["host_id", "hostname", "owner", "vendor", "model", "os", "cpu", "memory_bytes", "storage"],
            "properties": {
                "host_id": {"type": "string", "description": "Stable across runs."},
                "hostname": {"type": "string"},
                "owner": {"type": "string", "description": "Who the machine belongs to, or an explicit unknown."},
                "vendor": {"type": "string"},
                "model": {"type": "string"},
                "os": {"type": "object", "required": ["name", "version", "kernel"],
                       "properties": {"name": {"type": "string"}, "version": {"type": "string"}, "kernel": {"type": "string"}}},
                "cpu": {"type": "object", "required": ["model", "cores"],
                        "properties": {"model": {"type": "string"}, "cores": {"type": "integer"}}},
                "memory_bytes": {"type": "integer"},
                "storage": {"type": "array",
                            "items": {"type": "object", "required": ["device", "model", "size_bytes"],
                                      "properties": {"device": {"type": "string"}, "model": {"type": "string"},
                                                     "size_bytes": {"type": "integer"}}}},
            },
        },
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["category", "check_id", "status", "severity", "title", "evidence", "collected_at"],
                "properties": {
                    "category": {"type": "string", "pattern": "^[A-Z][A-Z0-9_]*$", "description": "UPPER_SNAKE_CASE."},
                    "check_id": {"type": "string", "description": "Unique per check (uniqueness across the findings array "
                                                                  "is not expressible in JSON Schema core; enforced by the sensor's tests)."},
                    "status": {"type": "string", "enum": ["pass", "fail", "unknown"]},
                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                    "title": {"type": "string", "description": "One line a person can read."},
                    "reason": {"type": "string", "description": "Required when status is fail or unknown."},
                    "evidence": {"type": "object", "description": "What someone needs to act on it."},
                    "collected_at": {"type": "string", "format": "date-time", "description": "RFC 3339 timestamp."},
                },
                "if": {"properties": {"status": {"enum": ["fail", "unknown"]}}, "required": ["status"]},
                "then": {"required": ["reason"]},
            },
        },
    },
}

json.dump(schema, open(OUT, "w", encoding="utf-8"), indent=2)
sha = hashlib.sha256(open(OUT, "rb").read()).hexdigest()
h_sha = hashlib.sha256(open(HTML, "rb").read()).hexdigest()
p_sha = hashlib.sha256(open("task/original/Lava-Sensor-Exercise.pdf", "rb").read()).hexdigest()
prov = f"""# SCHEMA_PROVENANCE — task/derived/finding.schema.json

**Status: DERIVED artifact.** Lava's brief refers to a separately supplied `finding.schema.json`; that file was not among the
supplied task files on this machine. On 2026-09-09 the user decided: do not ask Lava, do not keep it as a blocker; the output
contract is embedded in the supplied brief, so transcribe it faithfully into a standalone schema and use that as the project's
validation source. This file is therefore a machine-readable transcription of the brief, not an original Lava artifact.

## Sources (immutable originals)
- `task/original/Lava-Sensor-Exercise.html` sha256 `{h_sha}` — section "The output shape" (JSON example with inline comments) and the paragraph after it ("Extra fields are welcome anywhere...").
- `task/original/Lava-Sensor-Exercise.pdf` sha256 `{p_sha}` — same section, page 4-5 (text layer via pypdf: `task/derived/pdf_text_extract.txt`).

## Cross-check
The contract blocks extracted from both files agree after canonicalisation (whitespace/rendering only; the PDF text layer
renders `--out` as `/-out`): **agreement = {agree}**. Extraction and comparison are reproducible with `python tooling/extract_schema.py`.

## Transcription rules (what was encoded and why)
| Brief text | Encoding | Notes |
|---|---|---|
| `"schema_version": "1"` (literal, not a placeholder) | `const "1"` | Only literal value in the example; relax to a plain string if Lava's real schema differs. |
| `"collected_at": "<RFC 3339 timestamp>"` | string, `format: date-time` | Both document- and finding-level. |
| `"sensor_version": "<optional>"` | optional string | Not in `required`. |
| machine fields: "Report at least these" | all nine listed fields `required` | `os`, `cpu`, `storage[]` sub-fields required as listed. |
| `"owner": "<or an explicit unknown>"` | string | The explicit-unknown value is a string; other fields must also "say so" when unknown (see AM-5 in TASK_CONTRACT). |
| `"cores": 0`, `"memory_bytes": 0`, `"size_bytes": 0` | `integer` | Integer literals in the example; no `null` added (would be an invented relaxation). |
| `"category": ... // UPPER_SNAKE_CASE` | `pattern ^[A-Z][A-Z0-9_]*$` | Direct transcription of the comment. |
| `"check_id": ... // unique per check` | description only | Cross-item uniqueness is not expressible in JSON Schema core; enforced by the sensor's own tests. |
| `"status": "pass" \\| "fail" \\| "unknown"` | enum | |
| `"severity": "critical" \\| "high" \\| "medium" \\| "low" \\| "info"` | enum | |
| `"reason": "<required when status is fail or unknown>"` | `if status in [fail, unknown] then required [reason]` | |
| `"evidence": {{ /* what someone needs to act on it */ }}` | `type: object` | Free-form. |
| "Extra fields are welcome anywhere" | `additionalProperties` left at the JSON Schema default (allowed) everywhere | No `additionalProperties: false` anywhere. |

Note on `format: date-time`: under JSON Schema 2020-12 `format` is an annotation unless the validator enables format assertion. Our validation therefore (a) enables format checking in the validator used by tests and the final gate, and (b) the sensor test-suite additionally parses every `collected_at` as RFC 3339 explicitly. RFC 3339 allows fractional seconds and any numeric offset; we emit UTC `Z`.

Nothing else was added: no minItems, no minimum-checks-per-category (a semantic requirement, tested separately), no string
formats beyond date-time, no length limits.

## Output
- `task/derived/finding.schema.json` sha256 `{sha}` (JSON Schema draft 2020-12).
- Replaces the earlier PENDING-SCHEMA status of TASK_CONTRACT items B6, B7, D1, D5, AM-1, AM-5, AM-7.
"""
open(PROV, "w", encoding="utf-8").write(prov)
print("wrote", OUT, sha[:16], "and", PROV)
sys.exit(0 if agree else 2)
