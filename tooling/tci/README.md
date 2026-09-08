# TCI -- Tiny Custom Investigator
Safe, bounded, read-only recon of a remote Linux host over SSH. The planner
only selects symbolic ProbeIDs from `probes.json`; a trusted executor maps
each ProbeID to exactly one allowlisted read-only command.

## Usage
```
python tci.py --registry probes.json --dry-run
python check_registry.py probes.json
python tci.py --registry probes.json --env-file /c/lava-sensor-exercise/.env \
  --executor ssh --out-dir state/raw_host \
  --snapshot state/HOST_SNAPSHOT.raw.json [--max-probes N] [--only-group g1,g2]
```
`--executor wsl|local` runs the same protocol via `wsl -e bash -s`/`bash -s`.

## Invariants
- Registry validated before anything runs; refuses to execute on failure.
- `facts` extraction only runs on `OK` evidence; other statuses leave facts
  `unresolved`, never `false`. Absence only via `value_if_nomatch` on `OK`.
- Two OK probes disagreeing on a fact -> `CONTESTED`, not "first wins".
- Budget cuts land in `not_attempted_budget`, never a negative fact.
- Status order: TIMEOUT>UTILITY_MISSING>EACCES>UNSUPPORTED>ENOENT>
  EXECUTION_ERROR>OK.

## Files
`probes.json` (161 probes/9 groups); `tci.py` (CLI/planner/executors/
evidence typing/snapshot); `check_registry.py` (validator); `test_tci.py`
(unittest, no network, FakeExecutor only).

## Outputs
`--out-dir`: `probes/<round>_<id>.json`, `run.log` (no secrets, only
`<HOST>`/`<USER>`/`<KEY>`), `facts.json`, `report.json`. `--snapshot`:
sanitized rollup, masks IPs/MACs/serials, caps secret-adjacent output --
still needs human review.
