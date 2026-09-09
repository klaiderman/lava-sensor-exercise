# PREFILTER — Staticcheck + Hydra (mechanical, not the primary review)

Run: 2026-09-09T01:57:16Z · module: sensor/ · Hydra pinned e56edc52 (regex single-line prefilter per its README; capped at 2000 lines / 10 findings per file) · Staticcheck staticcheck.exe 2026.1 (v0.7.0)

| tool | rc | output lines | notes |
|---|---|---|---|
| staticcheck ./... (GOOS=linux) | 1 | 2 | rc 0 = no findings |
| go vet ./... (GOOS=linux) | 0 | 0 | |
| hydra vuln-scanner.py per file | files=40 errors=0 | 7240 | finding-shaped lines: 0
0 |
| hydra supply-chain.py . | 0 | 1 | go.mod/go.sum surface |
| hydra entropy-analyzer.py . | 2 | 2 | secret-shaped strings incl. testdata |

## staticcheck
```
internal\lab\support_test.go:37:7: const labTestdata is unused (U1000)
internal\lab\support_test.go:137:6: func buildLabFixture is unused (U1000)
```
## go vet
```
```
## hydra vuln-scanner (first 120 lines)
```
### /c/lava-sensor-exercise/sensor/cmd/sensor/main.go
NO FINDINGS, BUT COVERAGE IS PARTIAL � this is NOT a clean result. Uncovered: credentials, crypto, dos, injection, misconfiguration, path-traversal, ssrf, xxe
{
  "schema": "enchanter.analysis-report/v1",
  "tool": "hydra-vuln-scanner",
  "tool_version": null,
  "target": {
    "path": "C:/lava-sensor-exercise/sensor/cmd/sensor/main.go",
    "language": "go",
    "lines_total": 184,
    "lines_analyzed": 184
  },
  "analysis_status": "partial",
  "truncated": false,
  "false_clean_risk": true,
  "clean": false,
  "coverage": [
    {
      "class": "credentials",
      "engine": "hydra-regex",
      "depth": "pattern",
      "status": "partial",
      "shapes_supported": [
        "same-line literal match"
      ],
      "shapes_unsupported": [
        "argv",
        "environment",
        "config-file",
        "stdin",
        "function-parameter",
        "cross-line",
        "cross-function"
      ],
      "truncated": false,
      "notes": "3 single-line regex rule(s); literal/token match only"
    },
    {
      "class": "crypto",
      "engine": "hydra-regex",
      "depth": "pattern",
      "status": "partial",
      "shapes_supported": [
        "same-line literal match"
      ],
      "shapes_unsupported": [
        "argv",
        "environment",
        "config-file",
        "stdin",
        "function-parameter",
        "cross-line",
        "cross-function"
      ],
      "truncated": false,
      "notes": "10 single-line regex rule(s); literal/token match only"
    },
    {
      "class": "dos",
      "engine": "hydra-regex",
      "depth": "pattern",
      "status": "partial",
      "shapes_supported": [
        "same-line literal match"
      ],
      "shapes_unsupported": [
        "argv",
        "environment",
        "config-file",
        "stdin",
        "function-parameter",
        "cross-line",
        "cross-function"
      ],
      "truncated": false,
      "notes": "1 single-line regex rule(s); literal/token match only"
    },
    {
      "class": "injection",
      "engine": "hydra-regex",
      "depth": "pattern",
      "status": "partial",
      "shapes_supported": [
        "http-handler taint on the same line as the sink"
      ],
      "shapes_unsupported": [
        "argv",
        "environment",
        "config-file",
        "stdin",
        "function-parameter",
        "cross-line",
        "cross-function"
      ],
      "truncated": false,
      "notes": "3 single-line regex rule(s); requires an HTTP taint token on the sink line"
    },
    {
      "class": "misconfiguration",
      "engine": "hydra-regex",
      "depth": "pattern",
      "status": "partial",
      "shapes_supported": [
        "same-line literal match"
      ],
      "shapes_unsupported": [
        "argv",
        "environment",
        "config-file",
        "stdin",
        "function-parameter",
        "cross-line",
        "cross-function"
      ],
      "truncated": false,
      "notes": "3 single-line regex rule(s); literal/token match only"
    },
    {
      "class": "path-traversal",
      "engine": "hydra-regex",
```
## hydra supply-chain
```
[]
```
## hydra entropy (first 60 lines)
```
entropy-analyzer.py: input file not found or not a regular file: .
Usage: entropy-analyzer.py <file_to_scan> [threshold] [min_length]
```

Findings ≠ coverage: a clean result above does not prove the behaviours the independent review must check (false PASS/FAIL/UNKNOWN, EACCES≠absent, bounded exec, secret leakage in evidence).
