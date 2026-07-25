# bench-results/ — the co-SNARK benchmark dataset

Every benchmark run of this repo lands here as one dated directory, plus a
single SQLite database (`bench.sqlite`) aggregating all runs for querying
and visualisation. This README is the pick-up-here doc for humans and
future Claude sessions. The suite itself: `scripts/bench-0_5.sh` (matrix),
`scripts/bench-0_5-launcher.sh` (detached/overnight wrapper),
`scripts/bench-to-site.py` (per-run aggregation), `scripts/bench-ingest.py`
(all-runs → SQLite). Design + full measurement audit table:
`project-docs/22-cosnark-explorer-viz-plan.md` §5a/§5b. Optimisation plans
consuming this data: ch. 23 (single-prover), ch. 24 (MPC path).

## Quick start

```bash
# run the full matrix (~2.5–3.5 h; absolute seconds are load-stamped per row)
BENCH_OUT=bench-results/$(date +%F) bash scripts/bench-0_5.sh

# smoke-test the pipeline on one circuit (~30 s)
BENCH_OUT=/tmp/smoke BENCH_CIRCUITS=poseidon bash scripts/bench-0_5.sh

# aggregate one run for the explorer + humans (also run automatically by the launcher)
python3 scripts/bench-to-site.py bench-results/<date>/results.csv bench-results/<date>/site-anchors.json

# rebuild the database from ALL runs
python3 scripts/bench-ingest.py            # writes bench-results/bench.sqlite
```

⚠ Shared-mainframe rule: this box's load average and fork counters are
HOST-wide (other tenants included). Never gate a run on "quiet load" — run
when convenient; every CSV row records `host_load1m` so each absolute
number carries its own noise context. Use medians across reps; prefer
same-window ratios for fine comparisons. Leave ~20% of cores free
(RAYON_NUM_THREADS=16/party is the measured optimum anyway).

## Per-run directory layout

| path | what |
|---|---|
| `manifest.json` | provenance: UTC start, host, kernel, CPU model, cores, thread cap, co-snarks commit/branch/dirty, bb oracle pin+provenance, nargo version, matrix, reps, timeout, CSV schema. A run without a manifest is not comparable to anything. |
| `results.csv` | one row per timed cell: `circuit,protocol,zk,rep,phase,seconds,rc,max_rss_kb,cpu_pct,host_load1m`. `rc!=0` = failed (124 = 10-min timeout); failed cells are kept, never hidden, excluded from medians. |
| `netstats/*.json` | per MPC phase × party: bytes AND message counts per peer. `recv_msgs` from the ring predecessor ≈ **R**, the sequential round count (exact, CPU-noise-immune). |
| `mem/*.time` | per MPC phase × party: wall / peak-RSS / CPU% (`%e %M %P`) — party-skew data. |
| `features/*.circuit-info.json` | per circuit: trace-block gate composition, lookup gates / tables / table rows, ACIR opcode histogram, public inputs, witness zero-fraction, dyadic size. |
| `features/*.bbgates.json`, `*.nargo-info.json` | independent cross-checks of size/opcode counts. |
| `features/*.artifact-sizes.json` | proof / VK / public-input byte sizes per prover. |
| `RESULTS.md` | human-readable per-circuit tables (read this first). |
| `site-anchors.json` | machine shape the explorer bakes in (nulls = unmeasured, never fabricated). |
| `launcher.log` | progress lines with per-circuit estimate-vs-actual and suite ETA. |

Standalone captures (no timing run needed) live in dated dirs too, e.g.
`circuit-features-2026-07-24/` — features for all 12 matrix circuits,
captured independently of any bench run.

## The database (`bench.sqlite`)

Rebuilt idempotently by `scripts/bench-ingest.py` from all run dirs (plus
the legacy pre-repo run at `~/bench-0_5-results/2026-07-23`). Tables:

- `runs(run_id, dir, started_utc, host, cpu_model, cores, threads_per_party, commit, bb_pin, nargo, …)` — one row per run, from the manifest.
- `cells(run_id, circuit, protocol, zk, rep, phase, seconds, rc, max_rss_kb, cpu_pct, host_load1m)` — every timed cell, including failures.
- `netstats(run_id, circuit, protocol, phase, zk, rep, party, peer, sent_bytes, recv_bytes, sent_msgs, recv_msgs)`.
- `features(run_id, circuit, dyadic_size, finalized_rows, block_arithmetic, block_delta_range, block_lookup, block_elliptic, block_aux, block_poseidon2_external, block_poseidon2_internal, lookup_gates, num_lookup_tables, total_table_rows, public_inputs, witness_len, witness_zero_fraction, acir_opcodes)`.
- `artifact_sizes(run_id, circuit, artifact, bytes)`.

Convenience views: `medians` (per run/circuit/config/zk/phase median of
successful reps) and `overhead` (REP3÷bb prove ratio per circuit, joined
with features — the composition-vs-cost analysis in one query).

Example (the headline question):

```sql
SELECT circuit, lookup_gates, total_table_rows, rep3_over_bb
FROM overhead WHERE zk='zk' ORDER BY lookup_gates;
```

## Rules (why this dataset stays trustworthy)

1. **Absolute seconds are the primary data** — with their per-row load
   stamps. Ratios are the noise-robust derived layer, not a replacement.
2. Nothing is fabricated: failed/timeout cells stay in the CSV with their
   rc; unmeasured cells are null everywhere downstream.
3. Compare runs only after diffing manifests (machine, threads, versions,
   commit). The ingest DB makes cross-run queries easy — comparability
   stays the analyst's responsibility.
4. Timing-affecting changes to the suite bump the manifest `benchmark`
   name (currently "… v2"); pure capture additions don't.

## Current state / history

- **v1 run 2026-07-23** (legacy location `~/bench-0_5-results/2026-07-23`,
  ingested into the DB): 3 circuits, wall-clock only. Headline: REP3÷bb =
  6.0× (poseidon) / 439.6× (sha256) / 29.8× (recursion_zk) — MPC cost
  tracks gate composition, not size.
- **circuit-features-2026-07-24/**: features for all 12 matrix circuits.
  Explains the headline: sha256 is ~70% lookup gates + 33,944 table rows;
  poseidon is pure arithmetic; the sha 2e16→2e20 sweep scales lookup gates
  17× at constant table rows — a natural experiment for the cost model.
- **v2 full run: NOT YET EXECUTED** (armed 2026-07-24, disarmed by Mike
  pending a run window — the old quiet-gate is dead, see shared-mainframe
  rule). First v2 run gives: R vs size, memory, CPU%, party skew,
  artifact sizes, and the features join.
