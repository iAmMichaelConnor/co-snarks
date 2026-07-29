# Bench v4 — 2026-07-29 — setup vs per-proof

One self-contained run directory: every measurement this dataset rests on, plus
the analysis page built from it.

```
2026-07-29-v4/
├── README.md                 <- this file
├── loopback-matrix/          MEASURED HERE: the full prover x circuit x zk matrix
│   ├── manifest.json         host, versions, taxonomy, fairness caveats
│   ├── results.csv           per-cell wall-clock (+ rc, peak RSS, host load)
│   ├── phase-split.csv       the setup / witness / prove resolution
│   ├── phase-timings/*.json  per-cell sub-phase timings (all four provers)
│   ├── netstats/*.json       per-phase, per-party comms (bytes, msgs, rounds)
│   ├── features/*.json       circuit composition, gate blocks, artifact sizes
│   ├── mem/                  per-party wall/RSS/CPU (party skew)
│   ├── *.log                 raw per-cell logs
│   └── launcher.log          run journal with per-circuit timings
├── network-emulation/        REUSED from v3.2 — see REUSED-FROM.txt
├── batch-size-sweep/         REUSED from v3.2 — see REUSED-FROM.txt
└── site/                     GENERATED: explorer.html + site-data.json
```

Reproduce: `BENCH_OUT=<dir>/loopback-matrix scripts/bench-0_5-launcher.sh`, then
`RUN=<dir> scripts/build-explorer.sh`.

## What changed in v4, and why

v2/v3 split the MPC prove cell into **pk-gen** and **prove-proper** at the
binary's own `Build proving key took` log line. That is a *code* boundary, and it
was being read as a *precomputability* boundary — the explorer let you hide
"proving-key generation" as though a deployment could precompute it.

Measurement says otherwise. UltraHonk has no reusable per-circuit proving key:
what the prover calls the proving key holds the precomputed polynomials *and* the
witness polynomials, and building it is dominated by per-proof MPC over the
secret witness. Of that phase, the genuinely circuit-only slice measured

| circuit | pk-gen phase | circuit-only slice | |
|---|---|---|---|
| sha256 2^16 | 139.85 s | 31 ms | **0.02%** |
| bb_sha256_compression | 9.96 s | 6.5 ms | 0.07% |
| poseidon 2^17 | 0.27 s | 20 ms | 7.5% |
| poseidon 2^20 | 3.10 s | 307 ms | 9.9% |

On sha256 the phase is 92% `construct_lookup_read_counts` (turning *secret*
table indices into one-hot vectors over MPC rounds) and 8% the builder's sha
gadget over shared values. Hiding it hid per-proof cost almost exclusively.

So v4 measures three buckets, cut identically for all four provers:

- **setup** — circuit-only, precomputable once, same for every user and proof:
  ACIR parse, structural circuit build (empty witness), selector / permutation /
  lookup-table polynomials, the commitments to them (= the VK), CRS load.
- **witness** — per-proof work before the prover proper: MPC over shared values,
  lookup read-counts and tags, memory records, wire population.
- **prove** — per-proof prover proper: witness commitments, grand products,
  sumcheck, PCS.

Two more columns are deliberately kept out of both, so neither can flatter the
comparison: **alloc** (zeroing the polynomial arena — amortisable by a
long-lived node, neither setup nor mathematically per-proof) and **selfverify**
(bb and plaindriver verify their own proof; co-noir does not).

## The finding that matters for reading the charts

Setup is a *large* share of the single-prover baselines and a *negligible* share
of the MPC pipeline — 20–30% vs well under 1%. Precomputing it therefore **raises**
the privacy multiplier. The old "exclude pk-gen" toggle did the opposite, and
asymmetrically: it removed the MPC phase while leaving bb's internal proving-key
build inside bb's own number, which swung the sha256 2^17 ratio between 8.5x and
250x depending on a switch with no stated meaning.

## New measurements in v4

- `co-noir create-vk` is now a **timed** cell (`protocol=co-noir phase=vkgen`),
  with its internals split (`vkgen/build_structure`, `vkgen/create_key`). v2/v3
  ran it untimed, so the MPC path's setup cost was absent from the dataset.
- `plaindriver` cells run with `CO_NOIR_PHASE_TIMINGS=1`. Its prove run always
  writes a VK, so ~25–30% of the v3 plaindriver number was setup; now visible
  (`vkgen/commit_precomputed`).
- REP3/SHAMIR prove and witext cells emit `pkgen/*`, `setup/*`, `witness/*` and
  `infra/*` sub-phases. The pre-pk-gen setup work (ACIR parse, a **second**
  full structural build inside `compute_circuit_size`, CRS load, VK read) used to
  be invisible — a 6–10% residual of the cell wall on poseidon, charged to
  per-proof cost.
- `bb` needed no new instrumentation: it already logs
  `CircuitProve: Proving key computed in N ms`. Running it once with an empty
  witness (`write_vk`) and once with the real one isolates bb's structural build
  from its witness handling — and they come out nearly equal (39 ms vs 37 ms on
  bb_sha256_compression), i.e. **for a plain prover the proving-key build is
  essentially all structural. The witness-dependent cost is an MPC phenomenon,
  not an UltraHonk one.**

## Circuit list

poseidon is now a contiguous sweep **2^11 – 2^20**: v4 adds 2^12–2^16
(K = 2/5/11/23/46 permutations; rows = 1410·K + 2, each maximally filling its
dyadic bucket). sha256 covers 2^16–2^19 plus the single-compression circuit, and
`recursion_zk` is unchanged.

sha256 2^20 is **dropped**, not censored: every prior attempt hit the 30-minute
per-cell cap without producing a number, so it cost ~2 h of timeout per run for
no data.

## Known caveats carried forward

- bb runs its own thread pool (32 threads observed); `RAYON_NUM_THREADS=16` caps
  only the Rust provers.
- `split-input` and Shamir's `translate-witness` cells are not sub-split; both
  are per-proof by nature and small.
- Shamir cells cover the poseidon family only.
- Shared mainframe: every row carries `host_load1m` at cell start. Use medians
  and same-window ratios for fine comparisons.
