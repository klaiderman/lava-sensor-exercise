# Lava sensor exercise — submission

## Run it (one command)

```
./sensor/bin/sensor scan --out findings.json
```

`sensor/bin/sensor` is a static linux/amd64 binary (its SHA-256 is in `sensor/bin/sensor.sha256`). It runs as the unprivileged user you gave us, reads only, opens no device nodes, makes no network calls, never calls `sudo`, and exits 0 once `findings.json` is written (exit 1 only if the output cannot be written or the document fails its own structural self-check — the file is still written).

## Build it from source (Go 1.26, no third-party runtime dependencies)

```
cd sensor && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/sensor ./cmd/sensor
```

Tests: `cd sensor && go test ./...` (Linux-only tests are skipped on other platforms; run them on Linux for the full suite). The only third-party module (`github.com/santhosh-tekuri/jsonschema/v6`) is imported by tests, not by the binary.

## What is in this tarball

| Path | What it is |
|---|---|
| `findings.json` | Output of the final run of this exact binary on the server you provided |
| `NOTES.md` | One page: assumptions, ambiguities, custom categories, another day, what Claude got wrong |
| `sensor/` | Go source, tests and fixtures; `sensor/README.md` explains the architecture, every check, and the PASS/FAIL/UNKNOWN and severity rules |
| `finding.schema.json`, `SCHEMA_PROVENANCE.md` | The output contract transcribed from the brief (no separate schema file was in the material we received) — the file `findings.json` was validated against |
| `transcripts/` | The native Claude Code session transcripts (two files: the session forked) and the sub-agent transcripts, with a manifest; two API-key occurrences in one sub-agent transcript are redacted; both native session files are byte-identical to their originals, per `TRANSCRIPT_MANIFEST.json` |
| `MANIFEST.sha256` | Hashes of every file in this tarball |

## Reading `findings.json`

`machine` describes the host (stable `host_id`, hostname, `owner` or an explicit `unknown`, vendor/model, OS, CPU, memory, storage) with a `*_source` for every field and an `unknowns` object for anything the sensor could not determine. `findings` holds one entry per registered check (26), sorted by category then `check_id`: `status` is `pass`, `fail` or `unknown`; `reason` is present on every `fail`/`unknown` and names why (`EACCES`, `TIMEOUT`, `UTILITY_MISSING`, `POLICY`, …); `evidence` carries the paths read, values found, commands run, exit codes and errno values, plus the typed `observations` the verdict rests on. A run-level `scan` block records duration, deadline, whether the budget was cut, and the result of the document self-check.
