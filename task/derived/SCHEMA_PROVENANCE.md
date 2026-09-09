# SCHEMA_PROVENANCE — task/derived/finding.schema.json

**Status: DERIVED artifact.** Lava's brief refers to a separately supplied `finding.schema.json`; that file was not among the
supplied task files on this machine. On 2026-09-09 the user decided: do not ask Lava, do not keep it as a blocker; the output
contract is embedded in the supplied brief, so transcribe it faithfully into a standalone schema and use that as the project's
validation source. This file is therefore a machine-readable transcription of the brief, not an original Lava artifact.

## Sources (immutable originals)
- `task/original/Lava-Sensor-Exercise.html` sha256 `8293e5767c196760576d0df35b482b9dc3f309a56b7bc4e55b45ad68c9fa89ec` — section "The output shape" (JSON example with inline comments) and the paragraph after it ("Extra fields are welcome anywhere...").
- `task/original/Lava-Sensor-Exercise.pdf` sha256 `42a7c0ea3b24d87a74730bbe0f5c05a43790e471d6c81f577a6d157ea03d2cbc` — same section, page 4-5 (text layer via pypdf: `task/derived/pdf_text_extract.txt`).

## Cross-check
The contract blocks extracted from both files agree after canonicalisation (whitespace/rendering only; the PDF text layer
renders `--out` as `/-out`): **agreement = True**. Extraction and comparison are reproducible with `python tooling/extract_schema.py`.

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
| `"status": "pass" \| "fail" \| "unknown"` | enum | |
| `"severity": "critical" \| "high" \| "medium" \| "low" \| "info"` | enum | |
| `"reason": "<required when status is fail or unknown>"` | `if status in [fail, unknown] then required [reason]` | |
| `"evidence": { /* what someone needs to act on it */ }` | `type: object` | Free-form. |
| "Extra fields are welcome anywhere" | `additionalProperties` left at the JSON Schema default (allowed) everywhere | No `additionalProperties: false` anywhere. |

Note on `format: date-time`: under JSON Schema 2020-12 `format` is an annotation unless the validator enables format assertion. Our validation therefore (a) enables format checking in the validator used by tests and the final gate, and (b) the sensor test-suite additionally parses every `collected_at` as RFC 3339 explicitly. RFC 3339 allows fractional seconds and any numeric offset; we emit UTC `Z`.

Nothing else was added: no minItems, no minimum-checks-per-category (a semantic requirement, tested separately), no string
formats beyond date-time, no length limits.

## Output
- `task/derived/finding.schema.json` sha256 `1e06d312b58ac16eec628c8be4ade1575219606e2f556e80654d3a28646ccb33` (JSON Schema draft 2020-12).
- Replaces the earlier PENDING-SCHEMA status of TASK_CONTRACT items B6, B7, D1, D5, AM-1, AM-5, AM-7.
