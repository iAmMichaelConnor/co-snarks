# Chapter 24 — Optimising the co-snarkified (MPC) UltraHonk path

*Opened 2026-07-24 (Mike). Companion to ch. 23 (which optimises the plain
single-prover path); this chapter is about the MPC-specific overhead — the
gap between `plaindriver` and REP3, which bench v1 measured as ~1.5× for
poseidon/recursion_zk but ~29× for sha256 at loopback. Status: PLAN Phase 6.2/6.3.*

## 0. Invariants (Mike, binding — no corner-cutting)

1. **Non-ZK proof bytes stay identical to bb.** Every optimisation is gated
   by the existing byte-parity KATs + `fast-check.sh` / `compare_mpc.sh`.
   Anything that would change the transcript is out of scope here (worth a
   note if found, but it belongs to a different conversation with bb).
2. **Secret sharing stays sound.** No opening values early, no computing on
   plaintext where the protocol says shares, no weakening randomness. The
   danger with performance work on MPC code is precisely that the fastest
   "optimisation" is to stop doing MPC; §5's property tests exist to make
   that class of bug loud.
3. One lever per change, measured before/after, gates green in between
   (same discipline as ch. 23 §0/§7).

## 1. Price list: what each REP3 operation costs (read from the code)

From `mpc-core/src/protocols/rep3/` (arithmetic.rs, pointshare.rs,
conversion.rs) and `co-noir-common/src/mpc/rep3.rs`:

| operation | local cost | communication |
|---|---|---|
| add/sub, mul by public, linear combos | ~1 field op | **none** (share linearity) |
| `mul` (shared × shared) | 2 muls + PRSS mask | **1 round** (reshare); batched: `mul_vec`, or `local_mul_vec`+`reshare_vec` for large vecs |
| `inv` / `inv_vec` | 1 field inversion each | **1 round** (Bar-Ilan–Beaver: PRSS random `r` costs nothing, `mul_open(a·r)`, invert publicly, scale) — already batched |
| `open` / `open_vec` | — | 1 round |
| commit (MSM over shared scalars) | full Pippenger MSM on each party's share | **none** for the MSM itself (linear); 1 round to `open_point` the resulting commitment share |
| prefix/grand product | ~3 muls/entry | constant rounds (`CoUtils::array_prod_mul` — already the unbounded-fan-in trick) |
| arithmetic↔binary share conversion (bit ops) | large | multiple rounds per conversion (conversion.rs / yao) — the expensive class; hit during **witext** for boolean-flavoured blackboxes, not during prove |
| PRSS randomness (masks, ZK masking) | AES calls | none |

Two structural consequences:

- **The prove phase is field-only.** Boolean work (bit decompositions,
  AND/XOR) happens in witness extension via share conversion; once shares
  are in the trace, proving is sums, products, inversions, MSMs. So
  "boolean gates" hurt witext directly, and hurt prove only *indirectly*
  via the lookup/delta-range gates they compile into.
- **MSMs are round-free under sharing** — each party commits to its share
  locally. So the MPC prove-side overhead is: ~2× local field work on
  shared (witness) polynomials, plus the round structure, plus wherever
  the implementation multiplies/inverts shared values.

## 2. Round structure of a co-UH proof (and Mike's batching question)

Which messages are inherently sequential, and which could batch?
Fiat–Shamir does NOT serialize individual messages: the transcript holds
only **public** data (commitments are opened before being absorbed), every
party maintains an identical copy, and challenges are computed **locally**
by each party — no communication at all. What FS does force is *phase*
ordering. The observed phase DAG (`co_oink_prover.rs`, `co_decider/`):

1. wire commitments — local MSMs, then one batched `open_point_many`;
2. η, β, γ challenges — local (FS);
3. `w_4` + log-derivative lookup inverses — `mul_many` + one batched
   inversion; z_perm grand product — currently **~8 sequential batched
   rounds** (4× `batched_grand_product_num_denom`, 2× `mul_many`, prefix
   products, `batch_invert`), each over full-length vectors;
4. commit + open, α challenge — local;
5. **sumcheck: ~log₂(n) rounds, inherently sequential** (round i's
   challenge feeds round i+1 — this is the one place FS forces a
   round-by-round chain); within a round, relation evaluations are batched
   `mul_many`s;
6. Gemini/Shplemini folds + (ZK) SmallSubgroupIPA — a few more
   commit/open + fold rounds, sequential across folds;
7. KZG opening.

So the theoretical prove-side R is **O(#relations · log n) + a small
constant** — hundreds of rounds, weakly size-dependent, largely
composition-independent. Witext R by contrast tracks the circuit's
*sequential nonlinear depth* (a chain of K Poseidon permutations is
≥ K·rounds-per-permutation sequential MPC rounds; sha256-as-lookup-tables
is witext-cheap). **Bench v2's netstats measure exactly this per phase.**

**First measured baselines (poseidon, 2^11, loopback, 2026-07-24 smoke):**
witext R = 366 (14.6 KB sent by party 0 — tiny, pure ring-forward);
prove R = 319 non-ZK / **393 ZK** (~6.3 MB sent by party 0; the ZK delta
≈ 74 rounds is the SSIPA/masking flows). 319 ≈ (10 relations × 11
sumcheck rounds) + grand-product/fold/open rounds — matching the
sequential-relation structure above and confirming L1's headroom: one
reshare per sumcheck round instead of one per relation per round would
remove ~100 rounds. WAN reading: at 140 ms one-way, prove-ZK spends
393 × 0.14 ≈ 55 s in latency alone, for ANY small circuit — R is the
whole WAN story, and v2's size sweep will show how R grows with log n.

**Batching opportunities are marked in the code by TACEO themselves** —
`grep -rn "TACEO TODO" co-noir/ mpc-core/` returns ~25 sites, including
`co_oink_prover.rs` ("could batch those 4 as well" — the grand-product
numerator/denominator quartet, and the follow-up `mul_many` pair),
relation evaluations (`elliptic_relation.rs`, `delta_range_…`), and
`shplemini.rs`/`claim_batcher.rs` (batch multiplications, batch inversion
without zero-check, batch `is_zero`). Each collapses sequential rounds
into one and/or removes redundant local passes. These are exactly the
"batch the batchable" work items; none touches the transcript.

## 3. The headline mystery: sha256's ~29× MPC-specific overhead

v1 medians (loopback): REP3/plaindriver = 1.53× (poseidon), 1.49×
(recursion_zk), **29.2× (bb_sha256_compression)**. Loopback rounds are
cheap, so a round-count explanation needs *very* many rounds; a compute
explanation needs sha-specific expensive work. Ranked hypotheses, each
with the measurement that discriminates it (all land with bench v2):

- **H1 — per-row (non-vectorised) shared muls somewhere in the
  lookup/memory path** (e.g. a `T::mul` inside a row loop instead of
  `mul_many`). Signature: netstats prove-R for sha ≫ prove-R for poseidon
  by ~lookup-row count; time ∝ msg count. This is the "protocol followed
  but rounds not batched" case — fix = vectorise (L2).
  **[Partially checked 2026-07-24: REFUTED for the oink log-derivative
  path — `compute_lookup_term`/`compute_table_term` are local
  (`mul_with_public`+`add` only); the whole inverse computation costs 2
  batched rounds (`mul_many` + `batch_invert_leaking_zeros`), over full
  circuit length. Still open for the sumcheck relation path, where each
  round accumulates the ~10 relations SEQUENTIALLY, each taking the
  network (`co_sumcheck_round.rs` lines ~145–212) → prove-R ≈ 10·log n ≈
  150–300 batched rounds; and each relation has a `skip` path whose
  equivalence to bb's public-selector row-skipping needs auditing — if
  co-noir evaluates a relation over rows bb skips, that's pure local
  waste scaled by row count × relation degree (would show as H2, not H1).]**
- **H2 — local compute blow-up over table-length vectors** (the
  log-derivative inverse machinery runs over max(lookup rows, table rows);
  sha's tables are huge relative to its circuit): flamegraph shows
  `batch_invert*` / `mul_many` / masking-RNG dominating, R stays small.
  Fix = trim domains to active ranges (bb restricts to
  `final_active_wire_idx`; check the lookup-inverse domain), avoid
  recomputation, L3/L4 local speedups.
- **H3 — per-message fixed cost × many small messages** (framing,
  flush-per-send): netstats show high msg counts with tiny bytes/msg and
  wall-time ∝ msgs even at loopback. Fix = coalesce sends per logical
  round at the driver layer (L5). (Transport correction, found while
  instrumenting: the co-noir CLI uses `mpc_net::tcp::TcpNetwork` — the
  `[network.tls]` section in the party configs is IGNORED by this binary;
  both transports ride the same instrumented blocking core, but WAN
  deployments would add TLS, so loopback numbers are if anything
  flattering on per-message cost.)
- **H4 — allocation/copy churn** on the many full-length temporary vectors
  (visible in flamegraph as memcpy/alloc). Fix = reuse buffers (bounded
  win, do last).

*(Why not "sha uses binary shares during prove"? Prove is field-only — §1.
The bit-heavy work happened at witext, and sha's witext was FAST (0.215 s),
which is itself evidence the blackbox → lookup-table compilation is doing
its job. The prove-side pain must come from the lookup machinery.)*

### §3a. What bench v2 measured (2026-07-25 run — the discrimination)

- **Lookup GATES, not table rows, drive the MPC overhead.** The clean
  natural experiment: bb_sha256_compression vs sha256_2e16 share dyadic
  size (2^16), table count (12) and table rows (33,944); lookup gates
  differ 15× (2,896 vs 43,440). REP3 prove: 140.5 s vs >600 s timeout
  (>4.3×); REP3÷bb (zk): 473× vs >1,140×. H2's "table-length domains"
  variant can't explain that split (identical tables) — the per-lookup-
  GATE machinery can. The sha 2e17→2e20 sweep (lookup gates to 767k at
  constant table rows) is waiting to size the exponent once a lever
  lands that gets 2e17 under the timeout. Confounder honesty: this pair
  alone doesn't isolate lookup gates (arithmetic gates also differ,
  2,414 vs 16,302) — the poseidon control closes that hole:
  poseidon_2e17 is ~131k rows of pure arithmetic (≈8× sha256_2e16's
  arithmetic content at 2× the dyadic size) yet REP3-proves in ~12 s.
- **SHARPENED 2026-07-25 (same-day log+code dig): the lookup-gate cost
  lives in PK-GEN, not the prover.** Party logs split the
  bb_sha256_compression 140.5 s REP3 "prove" cell into **136.7 s build
  proving key + 3.4 s generate proof**; sha256_2e16's timed-out cell
  dies still inside pk-gen (last log line "Starting proving key
  generation..."). Poseidon is the inverse (2^17: 0.7 s pk-gen /
  10.6 s prove) — so the bench "prove" cell conflates two phases with
  opposite drivers; interpret lookup-heavy cells as pk-gen-bound.
  **MECHANISM ATTRIBUTION — corrected same day by the instrumented
  profile (kept as a cautionary tale).** A code-reading pass first
  "located" the cost in `construct_lookup_read_counts`
  (plain_proving_key.rs:369 — serial per-gate oblivious OHV pipeline,
  O(table_len) traffic/gate), and the rate/traffic arithmetic
  cross-checked (47 ms/gate × 2,896 ✓; ~3 GB ✓; 0 lookups → 0.7 s ✓).
  **The profile then REFUTED that at the top level**: that function is
  8.0 s = 5.8% of the ~138 s pk-gen; **94% (~130 s) is
  `create_circuit`** — building the gate trace from ACIR over shared
  witnesses — at a flat ~50% CPU on party 0 (round-trip-bound
  signature). The cross-checks had been consistent by CONFOUND: in sha
  circuits lookup gates ∝ compression calls ∝ all other sha content,
  so ANY per-sha-content mechanism predicts the same 15× scaling.
  Lesson: code-reading finds *a* mechanism; only measurement ranks it.
  Within the 8 s the profile confirms the OHV-pipeline shape (76%
  ohv_from_index: a2b 2.3 s / OHV gadget 1.2 s / bit-inject 2.6 s;
  21% write_lut; `equal_many` ≈ free — sha tables never take the
  index-map branch). **RESOLVED same day by the second instrumented
  pass (call-counted, all buckets accounted to 94.6% of pk-gen):**
  `create_circuit` does NOT re-run the ACVM blackbox solver (0 calls to
  the witext path co-acvm rep3.rs:1662 / `yao::sha256_from_bristol`).
  The ~130 s is the BUILDER's sha gate-construction gadget
  (`co-builder/src/types/sha_compression.rs::sha256_block`), which
  derives every internal sparse-form intermediate (choose/majority/
  message-schedule per round) via plookup reads with SHARED keys —
  738 `get_lookup_accumulators` calls dispatching **369 separate small
  Yao garbled-circuit sub-protocols**:
  `yao::get_sparse_normalization_values_many` 176 calls × 575 ms avg =
  101.3 s (73% of pk-gen BY ITSELF) +
  `get_sparse_table_with_rotation_values_many` 193 × 147 ms = 28.4 s.
  Control buckets: 24 range opcodes 0.06 s; AssertZero ~0; finalize
  0.16 s. The SAME gadget code under the plain driver: **0.106 s**
  (measured in-process) → a ~1,240× MPC-vs-plain tax that is per-call
  FIXED protocol overhead (fresh delta generation, joint input
  sharing, garbled-circuit transmission + SHA3 consistency check,
  output reconstruction per invocation), round-trip/serialization
  bound — NOT raw compute. pidstat on all 3 parties: flat ~58–61%
  CPU each, refuting garbler/evaluator asymmetry (the rep3 Yao
  blueprint is genuinely 3-party: ID0 evaluates, ID1 garbles, ID2
  contributes input sharing). `get_from_public_luts_internal`
  ("TODO parallelize") measured at 0 calls — ruled out for sha.
  Witext-vs-builder reconciliation: witext solves the opcode with ONE
  buffered Bristol-circuit Yao evaluation (~0.1 s); the builder makes
  369 tiny ones. So the sha MPC story ends at: **fixed per-Yao-call
  overhead × call count in the builder's sha gadget** — lookup GATES
  were merely correlated (every per-compression-call quantity is).
  sha256_2e16 prediction: 15 compression calls ≈ 15 × 130 s ≈ 1,950 s
  pk-gen (still censored; uncapped run still queued to confirm).
- **The MPC path is locally SERIAL: REP3 prove runs at ~260% CPU of a
  1600% (16-thread) budget while bb prove uses ~1,450%.** Party skew
  negligible (101.20–101.35 s at 2e20). So wall-clock is dominated by
  serial local compute and/or comms waiting, not by any party lagging —
  H2-flavoured, and it says L4 (thread the local polynomial passes; the
  ch. 23 C-series only touched the PLAIN driver's code paths) plus the
  serial-inversion audit of REP3 local ops are the highest-value levers.
  [Caveat added 2026-07-25: the CPU% stamp is CELL-level, i.e. averaged
  over pk-gen+prove conflated — per-phase attribution needs the
  profiling run.]
- **RETRO-SPLIT of every REP3 "prove" cell into pk-gen vs prove
  (2026-07-25, Mike's methodology challenge → fix):** the cells
  conflated `Build proving key` + `Generate proof`; both phases are
  separately logged per party, so the split was recovered from the run
  logs without rerunning — `scripts/bench-retro-phase-split.py` →
  `bench-results/2026-07-25/phase-split.csv` (108 party-rows; medians):

  | circuit (zk medians shown as nonzk/zk) | pk-gen s | prove s |
  |---|---|---|
  | poseidon 2^11 | 0.011 | 0.27/0.33 |
  | poseidon 2^17 | 0.72 | 10.6 |
  | poseidon 2^18 | 1.51 | 21.3/21.6 |
  | poseidon 2^19 | 3.55 | 42.5/43.1 |
  | poseidon 2^20 | 7.32 | 86.6/90.2 |
  | recursion_zk (2^20) | 6.77 | 82.5/85.2 |
  | bb_sha256_compression (2^16) | **136.7** | 3.5/3.7 |

  Three structural conclusions (much stronger than the conflated view):
  (1) **REP3 prove-proper scales with dyadic size and is nearly
  circuit-content-independent** — poseidon doubles cleanly per size
  step, and at 2^20 recursion_zk (0 lookup gates, 320k arith) lands
  within 5% of poseidon_2e20 (1.05M arith); sha at 2^16 is ~35% BELOW
  the size-scaled poseidon line. ZK adds ~3–4%.
  (2) **REP3 pk-gen = size-linear baseline (~7 s per 2^20 rows) plus
  the lookup tax**: bb_sha256_compression's 136.7 s sits ~300× above
  its ~0.45 s size baseline → ~47 ms per lookup gate (2,896 gates).
  (3) **Arithmetic-gate count is REFUTED as a driver by a controlled
  in-data comparison**: recursion_zk vs poseidon_2e20 share dyadic size
  with 3.3× different arithmetic gates — pk-gen within 8%, prove within
  5%. (This answers the confound in the bb_sha256_compression vs
  sha256_2e16 natural experiment, which — fair criticism — differs in
  arithmetic gates 6.8× as well as lookup gates 15×.)
  Open items to make the lookup-tax claim fully controlled: the
  47 ms/gate slope rests on ONE circuit (sha256_2e16 is censored at the
  600 s cap); queued: (a) one UNCAPPED sha256_2e16 REP3 pk-gen
  measurement — registered prediction ≈ 2,040 s ± 20% (43,440 gates ×
  47 ms + 0.45 s baseline);
  **[(a) DONE 2026-07-26 02:20–02:54 UT: measured pk-gen
  2,039.6 s (all 3 parties within 3 ms), prove-proper 3.6 s —
  the registered ~2,040 s prediction hit to 0.02%. The
  per-compression-call cost model (15 calls × ~136 s) is CONFIRMED;
  equivalently ~47 ms per lookup gate on this circuit family — but
  note the mechanism behind that slope is the per-intermediate Yao
  field↔binary conversions (L0e), not lookup-gate machinery per se.
  3-party proofs byte-identical (non-ZK). Logs: session-17 scratchpad
  sha2e16-uncapped/.]** (b) a designed sweep: synthetic Noir
  circuits varying lookup-gate count at fixed table set & fixed
  arithmetic, and varying arithmetic at fixed lookups — prediction:
  pk-gen linear in lookup gates (slope set by the per-gate OHV pipeline,
  itself ∝ table-length component), insensitive to arithmetic count;
  (c) profiler apportionment of the 47 ms/gate across a2b / OHV /
  bit-inject / write_lut (agent in flight). Bench v2.1 MUST split
  pk-gen and prove into separate cells at the launcher level (bb's
  vkgen was already split at v2 design time; co-noir's wasn't — design
  miss) and emit separate netstats phases (currently one
  "build-and-generate-proof" blob).
  **[v2.1 measurement fixes LANDED 2026-07-26 (uncommitted): the
  launcher now auto-produces phase-split.csv every run (wired
  bench-retro-phase-split.py into bench-0_5-launcher.sh), and the CLI
  gained CO_NOIR_NET_STATS_JSON_PKGEN — a mid-run netstats snapshot
  after pk-gen (phase "build-proving-key"), wired into the bench's
  REP3 prove cells as netstats/*_pkgen_*.json; subtract from the
  matching *_prove_* totals for true per-phase comms. Smoke-tested on
  a live 3-party 2^17 prove.]**
- **Poseidon (pure-arithmetic) overhead: REP3÷bb (zk) = 3.1× at 2^11,
  rising to a ~13× plateau across 2^17–2^20** (11.0/12.3/13.3/12.8×).
  REP3÷plaindriver ≈ 5.2× at 2^20 (101 s vs 19.3 s). Down from v1's
  6.0× at base size — the C2/C3 elementwise-rayon work helps all
  drivers' local ops.
- **L1 independently confirmed by the wire**: poseidon 2^11 prove R
  319→311 (nonzk), 393→385 (zk) — exactly the −8 rounds L1 removed.
- **R-proxy caveat at scale** (recorded in bench-results/README.md):
  prove msg counts grow ~linearly with size (11.3k at 2e17 → 90k at
  2e20, ~37 KB/msg constant) — application-level batching emits many
  frames per logical round (mpc-net itself never chunks sends;
  verified). recv_msgs is exact as a message count but only an upper
  bound on sequential-round depth for big circuits. Backlog: a logical
  round counter (increment once per synchronisation point, not per
  frame) so the WAN model gets true depth. H3 note: 90k frames at
  loopback cost little, but per-frame overhead × 90k is a real WAN/TLS
  concern — L5 stays live.
- **Witext of sequential-hash circuits is genuinely round-DEEP**:
  poseidon variants show witext R ≈ 33k (2e17) → 270k (2e20) at
  ~39 B/msg — real dependency chains (the hash-chain circuit), not
  batching artifacts. At 140 ms WAN one-way that's a ~10-hour witext
  floor for 2e20: circuit DEPTH, not size, sets the WAN feasibility of
  witness extension, and no bandwidth or batching lever fixes an
  inherently sequential circuit. (recursion_zk witext R≈3 — the other
  extreme.) Worth its own explorer view.
- **Memory: REP3 prove peak RSS ≈ 13× bb** (20.2 GB/party vs 1.5 GB at
  2e20; 3 parties co-hosted = ~60 GB). H4 (alloc/copy churn) has a lot
  of surface; also directly constrains per-party hardware sizing.
- Verifier side: REP3/bb verify ≈ 20 ms, size-independent; verify_bb
  rc=0 across all 12 circuits — verifier-parity is now a per-run
  measured invariant.
- **Measurement backlog elevated to a Mike ask (2026-07-25): per-ROUND
  traffic accounting + distance-tier time estimates.** The logical-round
  counter (increment per synchronisation point) gains a per-round BYTE
  histogram (bytes sent/received between each sync point), so every
  circuit×phase gets a (rounds, bytes-per-round) profile. From that,
  compute per-tier transfer-time estimates: same-machine (loopback,
  ~10 GbE-equivalent, ~0.05 ms RTT), same-rack (10 Gbps / ~0.1 ms),
  same-DC (1–10 Gbps / ~0.5 ms), same-continent (~1 Gbps / 20–40 ms
  RTT), cross-continent (~100–300 ms RTT) — tier definitions to align
  with ch. 22 §5c's netem plan (Scalable-coZK tiers), model =
  Σ_rounds max(RTT, bytes_r/bandwidth), then VALIDATE against real
  netem runs (v3). Implementation rides the mpc-net msg-counter
  infrastructure (already landed); explorer gets the per-tier
  upload/download columns.

**[RESOLVED 2026-07-26 (session 18): the in-process-vs-TCP pk-gen
frame-count "anomaly" was a CONFOUND, not a measurement gap.** Both
backends count identically (1 send = 1 frame = 1 counted msg; no
backend-conditional chunking — mpc-net local.rs/blocking.rs verified,
and a real 3-process TCP run of the SAME small poseidon KAT circuit
reproduces the in-process fence pins byte-for-byte, msgs AND bytes).
The "116 at any size vs 11k–90k over TCP" compared different CIRCUITS:
the fixed 2048-dyadic KAT fixture in-process vs the poseidon_2e17..2e20
family over TCP. pk-gen msgs = big_quad_constraints + 2 in BOTH
harnesses (see lever L8, which is the real finding: those size-linear
frames are one mul_many round per big-quad constraint — a WAN lever).
Caveat: the bb_sha256_compression entry in the floor table's
known_anomalies exercises the lookup/Yao path and was NOT
re-investigated — that one stays open. Floor-table/README provenance
text correction rides the next docs pass.]**

## 4. Optimisation levers (all parity-preserving, ranked)

- **L1 — batch the marked TODOs**: grand-product quartet → 1 round;
  `mul_many` pairs → 1; shplemini/claim-batcher multiplications;
  batch-invert-no-zero-check where zeros are structurally impossible.
  **[FIRST UNIT LANDED 2026-07-24: compute_grand_product comms 16 → 8
  rounds** — helper made communication-free (linear operands only), one
  concatenated mul_many for the 4 independent num/denom products, one for
  the num·num/denom·denom pair, and the two prefix-product chains through
  the existing array_prod_inner_mul_many. Measured on the live 3-party
  flow: −8 ring rounds, −2 open rounds, payload bytes identical, proof
  bytes byte-identical, all KAT gates green on mc/update-co-noir.
  Correlated-randomness totals unchanged (grouping only — mod.rs comment
  updated). NOT batched (data deps): batch_invert → z_perm mul_many.
  Follow-up available: array_prod_inner_mul_many's two internal mul_many
  are independent → −1 more round, but it's shared with co-acvm is_zero —
  separate unit. Note the port history: first implementation validated on
  upstream main by mistake (worktree base trap, see PROGRESS s14) and was
  re-ported + re-gated on our branch.]**
- **L0 — NEW TOP TARGET (2026-07-25 profile, root cause §3a): the
  ~130 s of per-call Yao overhead in the builder's sha gadget.**
  RESOLVED attribution: 369 small GC invocations
  (get_sparse_normalization 176×575 ms + rotation 193×147 ms) issued
  ONE PAIR AT A TIME from co-acvm/src/mpc/rep3.rs:1738/:1809 via
  singular wrappers — **while the batched `_many` kernels ALREADY
  EXIST in our tree** (mpc-core rep3/yao.rs:1401/:1452: arbitrary
  batch → one delta, one input-round pair, one circuit send, one
  output round). Local-research verdict: upstream never fixed this
  either (0 post-merge-base commits touch the hotspots); the gap is
  purely co-noir's call layer. Concrete plan (all
  transcript-preserving; gate/witness ORDER is the one care point,
  byte-KATs are the referee):
  **L0a** — same-table `_many` batching at the call sites (e.g. the two
  Sha256WitnessInput conversions per extend_witness iteration,
  sha_compression.rs:203/:207; initial sparse-form inits); needs
  slice-shaped trait variants of `slice_and_get_sparse_*`
  (co-acvm/src/mpc.rs:367/:384) + plookup dispatch arms.
  Cross-iteration choose/majority batching is blocked by the real
  a/e dependency chain; different base_bits can't share a call.
  **L0b** — run independent GC invocations concurrently on the SECOND
  net channel the acvm driver already holds (rep3.rs:39-40;
  mpc_net::join precedent at :1039/:1075/:1476 and all over co-plonk
  round2/round3): choose(e,f,g) ∥ majority(a,b,c) per iteration →
  halves the serial GC chain even across differing table params.
  **L0c** — merge the two GC input rounds inside
  `decompose_circuit_compose_blueprint!` (mpc-core's OWN TODOs at
  yao.rs:944/:965/:993) — −1 RTT on EVERY GC invocation, S effort,
  keeps paying after batching.
  **[L0c LANDED 2026-07-25 late (agent) + coordinator-verified
  2026-07-26 (uncommitted).** New shared framing primitive
  `joint_input_added_and_id2_as_bits` (rep3/yao.rs) + typed wrappers
  (field, and 4 ring/field combinations in rep3_ring/yao.rs); all four
  decompose blueprints now sample x23 locally up-front and inject it
  with the arithmetic inputs in ONE round-trip. Payloads identical —
  ID2's wire labels are drawn from the same RNG streams in the same
  per-stream order (x2 bits then x23 bits), so every derived value and
  the garbled circuit are unchanged; only frame framing merged. x23
  sampling moved before the input round but uses the separate
  bitcomp1/bitcomp2 streams — no per-stream sequence change. Referee:
  blackbox_and 3-party proofs BYTE-IDENTICAL before/after (md5, all
  parties); poseidon fences UNCHANGED (116,116)/(198,198) — canary
  held; blackbox_and + add3u64 pk-gen fences re-pinned consciously
  (−2 sends at ID2, −1 recv at ID0/ID1 per GC invocation:
  blackbox_and (155,203)/(185,161)/(191,167) → (155,200)/(185,158)/
  (185,167); add3u64 (146,193)/(220,190)/(222,205) → (146,192)/
  (220,189)/(220,205)); fast-check --all-fast PASS incl. live bb
  v5.0.1 cross-verify. Timing: blackbox_and pk-gen 81.8 → 75.0 ms
  (3 GC invocations; the win scales with GC-call count — sha's 369
  calls are the target). Patch: session-16 scratchpad l0c/l0c.patch.]**
  Ceiling: witext's one-shot Bristol evaluation = 0.1 s for the whole
  compression. Note: NO cross-invocation garbling-preprocessing
  (delta reuse) exists in mpc-core — within-call batching is the only
  amortisation lever short of engine work.
  **[L0a+L0b REFUTED BY MEASUREMENT 2026-07-26, REVERTED (patch +
  full analysis preserved: session-17 scratchpad l0ab/).** Implemented
  exactly to spec (agent, coordinator-verified): init + extend_witness
  same-table batching (369→~354 invocations), fetch/finish split of
  get_lookup_accumulators_ct so gate emission stayed
  position-preserving, ChInput∥MajInput per round on the two nets
  (128→64 serial-equivalent). Byte-correct on every referee (sha
  3-party non-ZK proof md5 identical before/after; bb cross-verify
  VK+proof byte-identical; ALL fences unchanged incl. the poseidon
  canary — no re-pin was even needed). Performance: before
  139.3/139.4/139.6 s pk-gen; after 142.3/144.1/142.4 s; isolation
  L0a-only 146.1 s. So L0a's plumbing is ~+7 s (every remaining
  singular call pays batch-1 _many routing overhead; batch-of-2 costs
  ≥2× a singular call) and L0b's concurrency claws back ~−3 s but not
  enough. **Load-bearing mechanism correction to §3a: the per-GC cost
  is SIZE-LINEAR garbling/eval compute (wire labels, SHA3 consistency,
  serialization scale with circuit size), NOT fixed per-call setup —
  the fixed part is ~2.3 ms/call (L0c's own delta). Each sparse
  normalization call garbles a full 254-bit field↔binary conversion
  circuit; K batched conversions cost K× — there is nothing to
  amortise at loopback.** Consequences: (a) witext's 0.1 s ceiling
  comes from working on native 32-bit words in ONE Bristol circuit,
  never round-tripping field↔binary per intermediate — the real L0
  lever is keeping sha's sparse-form intermediates in the binary/Yao
  (or LUT) domain across the whole gadget, or the non-Yao a2b+OHV/LUT
  path (~2 ms/op measured, §3a) — engine-level, effort L, opened as
  L0e below; (b) batching/concurrency WOULD still pay under WAN RTTs
  (each call is still a round-trip) — L0a/b-shaped work is a WAN-tier
  lever, re-evaluate after netem v3; (c) candidate small win: L0b-ONLY
  (join concurrency without the batching plumbing) hinted at ~−3 s —
  a much smaller diff, unproven vs baseline, queued behind L0d/L2.]**
  **L0e (NEW, the surviving sha lever)** — eliminate the per-
  intermediate field↔binary conversions in the builder's sha gadget:
  either one-shot the whole compression's sparse-form derivations in a
  single GC with intermediate wires as outputs (values fed to gate
  emission in original order), or route the sparse table reads through
  the MAESTRO-style LUT path (in-tree since PR #307) instead of
  per-value Yao conversion blueprints. Effort L, engine-level; the
  only path with headroom to approach witext's 0.1 s ceiling.
  **[DESIGN DONE + U1 LANDED 2026-07-26 session 18 (uncommitted).**
  Full design: session-18 scratchpad l0e-design/L0E-DESIGN.md —
  recommendation = design (a), one GC per compression emitting ~42,016
  carry-free bits (all 369 read values are public-weight linear maps of
  them; carry-freeness forced by the 16/28/16 normalization table
  sizes), served to the untouched builder via a driver FIFO cache with
  parity-safe fallback. Registered predictions: pk-gen 136.7 → 9.5 s
  ± 2; sha256_2e16 2,039.6 → ~140 s ± 30. U1 (pure circuit +
  referee) landed: GarbledCircuits::sha256_block_sparse_trace
  (mpc-core yao/circuits.rs:3549) + cleartext referee mirroring the
  REAL plain plookup machinery + real-garbling equivalence test.
  Verified: bit-equality on 22 inputs × 42,016 bits; carry-freeness
  EXHAUSTIVE; ChInput C3 linearity PROVEN coefficient-by-coefficient
  (xor_result(1<<k) = 28^k + 7·Σ 28^((k−rot)%32), rot ∈ {6,11,25});
  measured AND count 92,941 (fence-pinned; ~30% below the design's
  130–200k) ⇒ ~84 ms garble/eval + ~2.8 MB tables per compression.
  fast-check --all-fast PASS (agent + coordinator re-run). BONUS
  FINDING: latent bug in half_adder_const (circuits.rs:105) — returns
  carry = a for b=false (should be 0); currently harmless (all callers
  add odd constant 15) but ticketed in ch. 15; U2+ must not use
  bin_addition_constant_no_carry with even constants. Patch:
  session-18 scratchpad l0e-u1/. **U2 LANDED same day** (kernel
  sha256_block_sparse_trace_kernel + read recombination in new
  mpc-core yao/sha256_sparse_trace.rs; 3-party referee value-equal to
  the 369 singular kernels + U1 cleartext trace on identical shared
  inputs, red-validated by the coordinator, #[ignore]d as the explicit
  L0e-gate referee; all existing fences untouched — kernel unreachable
  from production paths; patch + coordinator report: scratchpad
  l0e-u2/). **U3 LANDED same day — THE SHA HEADLINE IS CLOSED:
  bb_sha256_compression REP3 pk-gen 145.4 → 6.95 s (20.4×), proof+VK
  md5-IDENTICAL before/after across parties and sharing seeds, byte-
  equal to plain and live bb v5.0.1; sha256_2e16 pk-gen 2,039.6 →
  123.9 s (design band 140±30), prove 3.55 s — the timeout-pruned
  bench cell is now feasible.** Registered predictions BEATEN (design
  9.5±2 by ~0.6 s; the 369 calls carried ~8 s of driver/framing
  overhead beyond the garbling attribution). Shape: trait hook
  default-no-op (co-acvm mpc.rs:410), ONE gadget line
  (sha_compression.rs:126), FIFO cache with exact-param tag matching
  (AES excluded), tag-mismatch ⇒ warn + drop-cache + parity-safe
  fallback (force-tested). key_b trivial-zero shares kept (§4a
  analysis: the zero is public circuit structure). U2 debts paid:
  kernel 83.9–87.7 ms/compression, ~3 MB + ≤2–3 blocking rounds
  (≈ design's 4-round shape); RNG-discipline argued from code.
  BONUS FINDING — floor-table sha anomaly CLOSED: the in-process sha
  KAT proves on a PUBLIC witness (Prover.toml enters as public
  AcvmTypes), so its sha gadget takes the public plookup branch — the
  in-process-vs-TCP sha frame gap was public-vs-shared witness, not
  measurement; NO fence re-pin was needed anywhere (predicted in
  writing before measuring). Evidence + patch: scratchpad l0e-u3/.
  REMAINING: U4 = bench rerun (quantify L8+L0e on the full matrix),
  U5 optional (overflow/bitand cache, ~1 s), L2 now the last sha
  pk-gen term (~8 s of read-counts at 2^16-scale).]**
- **L0d — half-share MSM for immediately-opened commitments (NEW,
  from co-groth16 precedent; prove-path, all circuits).**
  `CoUtils::commit` (co-noir-common/src/lib.rs:88-101) runs TWO
  full-size MSMs (rayon::join over a- and b-share bigints) for every
  commitment, yet every oink/shplemini/KZG commitment is opened
  immediately after (co_oink_prover.rs:617/:695/:768,
  co_shplemini_prover.rs:188/:513, lib.rs:74). co-groth16 instead
  MSMs the a-half only and opens via 3-way broadcast
  (msm_public_points_hs + open_half_point, pointshare.rs:150/:117) —
  byte-identical opened point, HALF the MSM CPU, identical leakage.
  ~15+ full-size commitments per prove. Effort M, risk low-medium
  (audit: no commitment share consumed un-opened — agent's audit says
  all are opened immediately; re-verify at implementation).
  **[LANDED 2026-07-26 (coordinator-implemented, uncommitted).**
  Call-site audit re-verified at implementation: ALL 11 commit sites
  open immediately (oink w_l/w_r/w_o, counts/tags/w4,
  inverses/z_perm, gemini masking; zk-data libra concat; SSIPA
  grand-sum + quotient; shplemini folds + Q; KZG:W). Shape: trait
  `commit_and_open{,_many}` with default = msm+open (plain/Shamir
  unchanged); REP3 overrides with `msm_public_points_half` (new,
  mpc-core pointshare) + `open_half_point{,_many}`
  (open_half_point_many new, via broadcast_many). Comms: each
  converted open call = 3-way broadcast (2 sends/2 recvs per party)
  instead of ring reshare (1/1); fences re-pinned EXACTLY as
  predicted pre-measurement: poseidon nonzk prove (198,198)→(204,204)
  (+6 = the 6 non-ZK commit-open calls), zk (272,272)→(282,282)
  (+10 = +4 ZK-only commitments), blackbox_and 198→204, add3u64
  248→254; pk-gen fences UNCHANGED (no commit-opens there); byte pins
  re-pinned, deterministic ×2 runs. Referees: non-ZK proof bytes
  KAT-identical (opened points identical by construction);
  fast-check --all-fast PASS incl. bb cross-verify; view scan clean.
  Measured (poseidon 2^17 ZK prove, 2 reps): 7.94/8.28 s vs ~8.2–8.5 s
  post-L1f ledger baseline — within the registered 7.7–8.2 s
  prediction band (~3–4%; different host window, bench v2.1 rerun is
  the definitive cross-lever measurement; commit-open phase timers
  now 0.07–0.15 s each at 2^17). §4a checklist: see the retro-audit
  list in §4a.]**
- **L2 — RE-SCOPED (2026-07-25, full audit), demoted same day by the
  profile from #1 to "real but minor": batch
  `construct_lookup_read_counts`** (measured 8.0 s = 5.8% of
  bb_sha256_compression pk-gen; ~×15 that for sha256_2e16, so still
  ~2 min of its timeout — worth doing after L0, and the batching
  design below is confirmed accurate in shape by the profile, with
  measured per-gate splits: a2b 0.8 ms / gadget 0.4 ms / inject
  0.9 ms / write_lut 0.6 ms).
  Audited batching design (coordinator code-verified the call-site
  mechanics; mpc-core gadget internals agent-audited):
  the per-gate `calculate_table_index` is local (fine); everything else
  batches across ALL gates and ALL tables:
  (i) one `a2b_many`/`a2y2b_many` for all gates' index bit-decompositions
  (default per-gate path today is Yao via `A2BType::default()`; batched
  Direct a2b pays its extra rounds once and drops bytes to ~64 B/gate);
  (ii) NEW mpc-core primitive **`ohv_many`** — the OHV recursion
  (rep3_ring/gadgets/ohv.rs) is level-synchronous, one independent
  `pack_and` per gate per level → concatenate payloads per level: rounds
  collapse from Σ_g(k_g−1) to k_max−1 (group gates by k or mask);
  (iii) one `bit_inject_from_bits_to_field_many` over all gates'
  concatenated OHV bits (already a `_many`; pure call-site batching);
  (iv) read counts: local commutative sums — values identical by
  construction; (v) read TAGS: the current per-gate `write_lut_from_ohv`
  chain computes t ← t + e·(1−t) = OR (order-independent for 0/1
  values) → replace with an OR-tree: tag = 1 − Π_g(1 − ohv_g) via
  `mul_many`, ⌈log₂ g_max⌉ rounds (phase-2 option: OR in the binary
  domain pre-inject, ~256× fewer tag bytes);
  (vi) AES-only fast path: `requires_index_map()` is true only for
  AesSboxMap, and its per-gate `equal_many` result IS already the
  one-hot vector — use it directly, delete the scalar-index→OHV rebuild.
  Round formula: from ≈ g·(k+5) sequential round-trips (~45–50k for
  bb_sha256_compression, ~700k for sha256_2e16 — latency-bound even at
  loopback) to **~35–40 total, independent of g**. Expected 10–50× on
  lookup-heavy pk-gen; sha256_2e16 goes from timeout to feasible.
  Parity: witness values identical (commutative sum; OR reorder);
  soundness: same primitives, index never opened. Unit boundaries:
  (1a) batched counts path, (1b) OR-tree tags, (1c) AES equal_many-as-OHV,
  (1d) binary-domain tags. Needs `ohv_many` in mpc-core + a `_many`
  trait method on `NoirWitnessExtensionProtocol` (plain impl trivial;
  Shamir already panics on the singular version — no regression).
  **[1a LANDED 2026-07-26 session 18 (uncommitted). Two-pass rework of
  construct_lookup_read_counts: per-gate Yao a2y2b (254-bit garbled
  adder PER GATE) → ONE Direct a2b_many + ONE
  bit_inject_from_bits_to_field_many; ohv_many deferred to 1b (agent's
  delegated call, measurement-confirmed). Proof+VK md5 identical
  (sha + blackbox_and, 3 parties × 2 seeds); msg predictions hit
  12/12 EXACTLY; blackbox_and pk-gen fences re-pinned old→new
  in-code; all canaries + L0e referee green.
  HONEST MISS: the in-process wall prediction (3.0–4.5 s) did not
  materialize — sha pk-gen flat ~7 s. Mechanism: the removed Yao
  adders cost only ~0.3–0.7 s in-process; the phase is dominated by
  ~490 MB/party of field payloads 1a doesn't touch (OHV-bit inject
  ~249 MB + per-gate tag write_luts ~240 MB / 7.5 M field muls).
  1a's real value is STRUCTURE: sha msgs −25%/party, −90.6 MB/party
  GC bytes, ~5,800 serial rounds removed (~3.6 min at 25 ms WAN RTT
  per compression circuit; ×15 for sha256_2e16) — a WAN lever, like
  L8. The in-process wall win lives in 1b: ohv_many
  (Σ(k−1)=28,304→13 rounds) + OR-tree tags (kills the 240 MB write_lut
  term), with 1d binary-domain tags considered simultaneously; also
  chunk the inject frame (single ~3.7 GB at 2^16 scale). Patch +
  registered predictions + evidence: session-18 scratchpad l2-1a/.]**
- **L2b — batch-inverse the post-open scalar loops (C2 class, MPC side;
  code-verified 2026-07-25).** `inv_many_in_place{,_leaking_zeros}`
  (co-noir-common/src/mpc/rep3.rs:212–253, shamir.rs same pattern) and
  mpc-core `inv_vec` (rep3 + shamir arithmetic.rs): comms already
  batched (one `mul_open_many`), but then a serial per-element
  `y.inverse()` on the OPENED (public) values — the exact pattern C2
  fixed in the plain driver with `ark_ff::batch_inversion`. ~4n full
  inversions per REP3 prove (oink logderiv n + batch_invert n +
  array_prod 2(n+1)) ≈ 4.2M at 2^20 ≈ 10–20 s serial CPU — prime
  suspect for the 260%-CPU symptom. Fix: batch_inversion + rayon'd
  multiply. Zero comm change, values identical. Blast radius: mpc-core
  `inv_vec` is also used by co-circom — value-identical, but run their
  build (NOT their test suite — testing-discipline rule; compile check
  only, our own gates are the referee).
- **L2c — route driver `mul_many` through `local_mul_vec` + `reshare_vec`
  (code-verified 2026-07-25).** The REP3 driver's `mul_many`
  (co-noir-common/src/mpc/rep3.rs:118–125) calls `arithmetic::mul_vec`,
  whose own doc says "for small vecs" — serial local multiply with a
  per-element ChaCha mask draw. The parallel pre-squeezed
  `local_mul_vec` sits right above it (mpc-core rep3/arithmetic.rs:133)
  and the sumcheck path already uses it. Oink's grand product pumps
  ~13n elements through `mul_many` → ~13.6M serial muls + 13.6M serial
  ChaCha draws at 2^20. Fix in the DRIVER only (mpc-core `mul_vec`
  stays — co-acvm/co-brillig/co-circom use it for small vecs);
  optionally size-gate. Same for `mul_open_vec` (arithmetic.rs:352,
  used by the inversion paths) — pre-squeeze + par_iter (do with L2b).
- **L1-followup — merge the two independent `mul_many` in
  `array_prod_inner_mul_many` (code-verified 2026-07-25):**
  co-noir-common/src/lib.rs:198 + :202 share no data dependency
  (chain is inv_many → both muls → mul_open_many) → concatenate into
  one call, −1 round. Blast-radius CORRECTION vs the earlier note:
  co-acvm's `is_zero` does NOT use this helper (it uses
  `eq_public_many`); sole caller is co_oink_prover.rs:517. Generic over
  T so plain/Shamir get the merged schedule too.
- **L3 — arkworks `parallel` + `asm` features — DONE/REFUTED** (ch. 23
  B1: features were already on workspace-wide; kept here for the
  historical record only).
- **L4 — thread the remaining local polynomial passes.** Most of the
  original list landed in ae631122 (oink row loops, grand-product
  operands, sumcheck accumulation, shplemini, MSM). Audited residue:
  `compute_honk_style_permutation_lagrange_polynomials_from_mapping`
  (co-builder/src/keys/plain_proving_key.rs:297 — the explicit
  "TACEO TODO Barrettenberg uses multithreading here"; 4 wires × n
  public writes, embarrassingly parallel, ~100–300 ms at 2^20)
  **[DONE 2026-07-26 (uncommitted): wires × rows both rayon'd
  (par_iter_mut zip mapping, min_len 2^12); values identical by
  construction (pure per-row map), byte parity gated by the VK/proof
  KATs in fast-check --all-fast (PASS); local-only, no fence impact.
  Patch: session-17 scratchpad small-levers/]**;
  `get_from_public_luts_internal` b2a loop (mpc-core
  rep3_ring/lut_field.rs:123 "TODO parallelize" — witext path, flag
  only); z_perm writeback + reshare_vec packing (cheap, low priority).
- **L5 — message coalescing / flush discipline** in mpc-net if H3 shows a
  per-message tax (one flush per logical round; the new msg counters make
  the before/after visible). Post-v2 note: 90k frames at 37 KB/msg for
  2^20 prove — loopback-cheap, WAN/TLS-relevant; stays live for v3.
- **L6 — trim inverse/product domains to active rows** where bb provably
  does the same (byte parity is the referee — if bb pads, we pad).
- **L7 — literature tricks** (survey: §6): only those that leave the
  transcript untouched qualify (e.g. cheaper correlated randomness,
  round-compression of openings); anything changing proof bytes is opt-out.
- **L8 — batch pk-gen's big-quad mul_many across constraints (NEW
  2026-07-26, found by the frame-"anomaly" root-cause; WAN-tier).**
  `build_constraints` loops over `big_quad_constraints` one at a time
  (ultra_builder.rs:4214-4216) and each `create_big_quad_constraint`
  issues its own `driver.mul_many` (:340) → one full network round per
  constraint. Confirmed formula (instrumented, disposable worktree):
  **pk-gen msgs per party/direction = big_quad_constraints.len() + 2**,
  exact at both sizes tested (poseidon KAT 114+2=116; poseidon_2e17
  11,125+2=11,127 — byte-equal to the committed v2.1 netstats). That is
  O(#constraints) sequential rounds — 11k at 2^17, ~90k at 2^20:
  loopback-invisible (~253 B frames, µs RTT) but ~30–45 min of pure
  latency at 2^20 under ~25 ms WAN RTT, dwarfing the ~23 MB moved.
  Fix shape: two-pass — collect all constraints' (lhs, rhs) product
  pairs (constraints are independent; the only sequential dep, next-w4
  chaining at :374, is intra-constraint), ONE mul_many, then run the
  unchanged per-constraint gate building in original order consuming
  precomputed products. Expected share-level byte-identity, not just
  value-identity: the mask draws come from the same per-element stream
  in the same total order (verify at implementation). Referees: byte-
  KATs; pk-gen fences will collapse ~116→~O(1)+2 and must be re-pinned
  consciously; poseidon prove canary untouched. Effort S-M.
  **[LANDED 2026-07-26 session 18 (uncommitted; agent + coordinator
  close-out after the agent died at the session limit). Share-level
  identity PROVEN (driver mul_many draws masks per-element sequentially
  → identical sequence when batched; seeded chunked-vs-batched unit
  test + exact byte-pin arithmetic). Fences re-pinned to the
  pre-registered predictions and pass live: poseidon pk-gen
  (116,116)→(3,3) msgs, bytes −904/direction (8 B framing × 113 merged
  frames); blackbox_and/add3u64 pk-gen UNCHANGED (0 big-quad
  constraints — their pk-gen traffic is GC, not big-quad rounds).
  Proof+VK md5 identical before/after; poseidon_2e17 pk-gen
  ~730 → ~306 ms loopback (registered band 250–550); WAN rounds
  11,127 → 3 at 2^17 (~90k → 3 at 2^20 ≈ the ~37 min the tier model
  quantified). §4a in l8/REPORT.md. Patch: scratchpad l8/.]**

Sequencing (updated 2026-07-25 post-PROFILE; supersedes the post-audit
order): **L2b → L2c (incl. mul_open_vec) → L1-followup** (small, safe,
KAT-gated units; the poseidon-prove profile confirms their targets:
gp/array_prod runs 1.6 s at ~101% CPU incl. the serial prefix-product
recombination, batch_invert 0.63 s), **then L0 once its apportionment
lands** (the sha pk-gen headline), then L2 (1a→1b→1c), then the
sumcheck round-structure question (see below), then L4 residue;
L5/L6 as data dictates. Prove-side profile facts to carry (poseidon
2^17: oink 34% / sumcheck 58% / pcs 6%): sumcheck's
`accumulate_relation_univariates_batch` is STRUCTURALLY single-threaded
by design ("no net/state access ever crosses threads") — the relation
math over the batch happens on the caller thread; splitting local
relation arithmetic (parallelizable) from the net-touching reshares is
the L4-class redesign with the biggest prove-side ceiling. Poseidon's
S-box s^5 costs 3 inherently-sequential mul_many rounds per relation
per sumcheck round (~100+ round-trips per prove) — round-structure
reduction there is L7 territory (e.g. correlated power-tuples), NOT a
call-site fix. MSM commits are the only phases reaching full 16-thread
CPU (~1026%). One lever per gated change; re-run bench v2 after each
committed-shaped unit (PLAN 6.4); T2 fences must be green (and
consciously re-pinned) per lever.

## §4a. Per-lever security review checklist (Mike, 2026-07-25 — MANDATORY
## for every optimisation, recorded per lever from now on)

Every lever must answer these in its review, in writing:
1. **No new knowledge at any node**: does any party RECEIVE data beyond
   what the pre-change protocol sent it (extra share limbs, unmasked
   intermediates, early opens)? In REP3 each party already holds 2 of
   the 3 additive summands — receiving the third (or an unmasked
   function of it) is full reconstruction, so the margin is one
   message. Everything received must remain masked by fresh correlated
   randomness exactly as before, or be a value the protocol already
   opened.
2. **Separate-entity discipline**: all cross-party data still flows
   through the `Network` trait (the ONLY channel between parties —
   separate processes/machines in production, separate states +
   explicit channel objects in tests); no code path may read another
   party's state, and no "optimisation" may compute locally what the
   protocol requires to be computed jointly (T2's cheat-detection
   target).
3. Mechanical checks backing 1+2: exact-count message fences (T2) —
   AND byte-level pins (see T2 addendum below) so a leak that keeps
   the frame count but fattens payloads (e.g. accidentally shipping
   both share limbs) also reds the build; T3 share-rerandomization;
   3-party byte-identity vs plain KAT; T4 view-scan once landed.

Retro-audit of today's levers against 1+2 (all PASS):
- L2b: touches only values ALREADY OPENED by the pre-existing protocol
  (blinded y = a·r); zero change to sent data (fences: counts
  unchanged). ✓
- L2c: same reshare schedule, same payloads; only the local multiply
  parallelised and masks pre-squeezed from the SAME correlated
  zero-sharing generator (uniform masking preserved). ✓
- L1-followup: identical payloads coalesced into one round; each party
  receives exactly the same field elements, one frame earlier. ✓
- Seeded-ZK-blinding fence: DELIBERATELY privacy-destroying by design
  (all parties know the masking values) — test-only, unreachable from
  the CLI, doc-marked; the unseeded default is bit-identical (proven
  by fences/KATs). Listed here so nobody ever "optimises" it into a
  production path. ✓
- L0d (2026-07-26): (1) no new knowledge — each party's broadcast
  half-MSM partial is derivable from the opened commitment plus that
  party's own summands: with the opened V = A_0+A_1+A_2 public and
  party i already holding the shares to compute A_i and A_{i-1}, the
  received A_{i+1} = V − A_i − A_{i-1} adds nothing beyond what the
  reshare-based open already revealed. Values are identical by
  construction (same sum), proven by the non-ZK byte-KATs. (2)
  separate-entity discipline — opens still go through the Network
  trait (broadcast_many); the half-MSM result is a doc-marked
  open-immediately-only type (a bare curve point, cannot re-enter
  share arithmetic); default trait impl keeps plain/Shamir on the
  exact pre-change path. (3) mechanical: all four prove fences
  re-pinned to values predicted BEFORE measurement (msg + byte),
  pk-gen fences unchanged, KAT byte-identity, view scan clean,
  --all-fast + bb cross-verify green. ✓
- L0c (checklist written 2026-07-26 at verification; the implementing
  agent was cut off at the session token limit before writing it):
  (1) no new knowledge — every party sends/receives exactly the same
  wire labels as the sequential variant, concatenated into one frame;
  ID2's x23 values were always locally sampled and always entered the
  GC as garbler inputs; nothing is opened earlier and no extra limbs
  ship (fences: ID2 sends FEWER frames, byte totals unchanged in
  spirit — byte pins land with T4). (2) separate-entity discipline —
  all traffic still flows through the Network trait; the merged
  primitive is a pure framing change inside mpc-core's existing
  send/receive helpers. Mechanical: proof md5 identity ×3 parties,
  poseidon fence canary, re-pinned lookup-path fences, --all-fast +
  bb cross-verify. ✓

## 5. Property-preservation tests (PLAN 6.3 — "actually doing MPC" fences)

The failure mode of MPC performance work is silently not doing the MPC.
Fences, cheapest first:

- **T1 (existing, outer gate)**: non-ZK byte-parity KATs, VK byte-KATs,
  3-party proofs byte-identical, bidirectional bb cross-verify, tamper
  negatives — all already in fast-check/compare_mpc; they catch
  wrong-output bugs but NOT protocol-shortcut bugs (a cheating prover can
  emit perfect proofs).
- **T2 — comms floor assertions** (new, powered by bench v2's msg/byte
  counters): after an optimisation lands, each phase must still exchange
  ≥ floor(circuit, phase) messages/bytes, with floors set from measured
  honest baselines (e.g. witext of the poseidon chain must show R within
  [0.5×, 2×] of baseline; prove must show ≥1 reshare round per mul-bearing
  phase). A "10× faster" change that also drops R to ~0 is a cheater, not
  a win — the test makes that a red build, not a code-review hope.
  **T2-lite LANDED 2026-07-25** without waiting for bench v2, using the
  in-process `Network::get_connection_stats()` API directly
  (`poseidon_prove_comms_message_fence_poseidon2sponge` in
  tests/tests/noir/proof_tests/rep3.rs, fast tier, ~2–3 s): pins EXACT
  per-party (sent, recv) framed-message totals — pk-gen (116, 116)×3
  across both nets, prove (199, 199)×3 on net0 — for the non-ZK poseidon
  prove, determinism confirmed across runs, proof bytes cross-checked
  against the plain KAT so it provably runs the real protocol. This is a
  two-sided fence (regression AND cheat detection for this circuit);
  the bench-derived per-phase floors across the full matrix remain the
  T2-proper follow-up once v2 netstats exist.
- **T3 — share re-randomization invariance** — **DONE 2026-07-24**
  (`poseidon_proof_share_rerandomization_invariance_poseidon2sponge` in
  tests/tests/noir/proof_tests/rep3.rs, ~1 s): same secrets split with two
  different seeds → share-sets asserted to DIFFER (anti-vacuity control),
  both proven 3-party non-ZK → proof bytes asserted identical AND equal to
  the plain-prover KAT. Red-validated three ways; the decisive mutation
  (XOR a share byte into the serialized proof) fails at exactly the
  target assert. (ZK mode excluded: its bytes legitimately vary.)
  Found along the way: the public `split_witness_rep3` API hard-codes
  `thread_rng()` — unseedable; the test seeds at the
  `share_field_element` level like the existing harness. If deterministic
  splitting is ever needed at the API level, that signature needs an rng
  parameter.
- **T4 — two-party view scan** (tripwire, documented limits): run a prove
  with instrumented logging of all traffic at one party; assert known
  plaintext witness values do not appear in any sent/received frame
  (heuristic — random shares collide with plaintext with negligible
  probability at 254 bits). Catches gross "open the witness" regressions.
  **[DONE 2026-07-26 (uncommitted), strengthened beyond the spec:
  `poseidon_witness_view_scan_no_plaintext_leak_poseidon2sponge`
  (tests/rep3.rs, fast tier ~3 s) records EVERY frame at ALL THREE
  parties on BOTH networks (a `RecordingNetwork` wrapper over
  `LocalNetwork`) across a full witext + pk-gen + prove run, and scans
  every byte offset of every frame for every high-entropy private
  witness value in BOTH encodings — canonical LE (what
  CanonicalSerialize emits) and raw Montgomery limbs (what a
  memory-dump serialization would emit). Public inputs excluded; low-
  entropy values (<16 nonzero bytes of 32) excluded so zeros can't
  false-positive. Anti-vacuity: ≥32 targets asserted, ≥1 MB traffic
  asserted, scanner must find a deliberately planted value, proof
  bytes must equal the plain KAT (real protocol ran). Result: CLEAN.
  BYTE-level fence pins also landed alongside the msg-count pins in
  all four T2 fences (§4a item 3): exact per-party (sent, recv) byte
  totals for poseidon nonzk+zk both phases and for blackbox_and/
  add3u64 prove; pk-gen totals for the GC-bearing circuits are pinned
  as a ±8-byte BAND because Yao GC serialization contains variable-
  length encodings of randomized values (measured drift ±1 byte on
  multi-MB totals; a systematic leak of 32 B/element lands far outside
  the band). ZK prove byte totals measured EXACTLY deterministic
  (masking values are fixed-length), so ZK pins are exact too.]**
- **T5 (existing)**: ≥4-party Shamir randomness-accounting suite keeps
  guarding degree/resharing correctness for the Shamir path.

## 6. Literature survey (2026-07-24; full agent report in PROGRESS s14)

### §6a. 2026-07-25 web survey addendum (post-L0-discovery; Mike's ask)

Focused sweep: TACEO blog/docs/GitHub + academic lineage, filtered by
the byte-parity constraint. Full cited report in the session-16 agent
transcript; actionable core:

- **UPSTREAM HAS ALREADY SHIPPED much of what we derived today —
  port, don't reinvent** (all upstream `TaceoLabs/co-snarks`, likely
  post-dating our fork point; local drift-check in flight):
  - Batched share conversions: `y2b_many`/`b2y_many` (PR #530,
    2026-04-03), `a2y2b_many` (PR #503, 2026-01-13), vectorized `b2a`
    (PR #393, 2025-07-09) — directly the L0/L2 batching primitives.
  - **The batching principle is TACEO-measured**: April-2025 release
    notes — "executing 10 or 100 witness extensions in batched form
    essentially adds no overhead compared to a single one"; batched
    ChaCha witext (PR #347); batched Poseidon trace (PR #502).
  - mpc-net transport overhaul: zero-copy `Bytes`, unified
    TCP/TLS/QUIC, background reader/writer threads, "post both sends
    before any receive" broadcast (PR #555, 2026-07-03);
    single-serialize broadcast fan-out (PR #557, 2026-07-06);
    ephemeral/blocking TCP session nets (PR #524/#560). Attacks the
    per-frame/per-call fixed overhead we measured.
  - MAESTRO-style LUT protocols in mpc-core (PR #307 2025-01-28; curve
    variant 2025-09-15) — the non-Yao small-domain alternative
    (eprint 2024/1317; follow-on 2025/2109).
  - Poseidon2 accelerators incl. pluggable "component accelerators
    for the MPC VM" (2026-04-03) + permutation dedup (PR #562,
    2026-07-24 — yesterday); Shamir Poseidon2 accel (PR #554).
  - Grand-product inactive-region bit-exactness fix vs bb (PR #411,
    2025-08-11) — CHECK whether our branch has this class of fix;
    it's the exact edge where parity bugs hide.
  - PR #472 "compute transcript in MPC" (2025-10-15) — read the diff
    locally (title squarely in our invariant territory; body
    unavailable via API).
- **Techniques confirmed by the literature** (details + cites in the
  full report): constant-round prefix/grand-product telescoping
  (Ozdemir–Boneh; TACEO blog 2024-10-31) — we already use the
  array_prod machinery, L1/L1-followup are refinements; Bar-Ilan–
  Beaver batch inversion (our L2b is the local-compute half of it);
  GC delta-reuse + pipelined garbled-table streaming (per-call
  amortization for L0 — NOT yet shipped upstream, engine-level work);
  offline/online separation matters ~6× more under WAN (TACEO zkTLS
  post numbers: 8-party SHA-256 online 115 ms LAN / 185 ms WAN vs
  total 2 s / 12.6 s).
- **Documented REJECTS (transcript-altering or wrong-model)**: logUp-
  style permutation swap (eprint 2025/1388 — different committed
  polys); zkSaaS / Scalable-coZK packed-sharing GKR (different proof
  system AND needs n≫3); EOS delegator topology; malicious-security
  shortcut papers (we're already semi-honest; note eprint 2025/1026's
  warning: collaborative proofs on INVALID witnesses can leak honest
  inputs); ML-MPC truncation tricks (approximate arithmetic = fatal).
- **Benchmarking**: no formal netem tier standard exists in the
  literature (Scalable-coZK's repo uses coarse tc-based LAN/WAN only);
  TACEO:Proof's production table (2025-07-23: e.g. sha256 2^16
  delegated 0.672 s vs laptop 0.878 s) is the best public co-SNARK
  latency data — our per-round byte histogram + tier model (§3a)
  would still be first-of-kind.

### §6b. 2026-07-25 LOCAL survey addendum (co-circom diff + upstream drift)

- **Upstream drift verdict**: merge-base with origin/main = 36da0ea8
  (2026-07-06); only 8 upstream commits since, NONE touching mpc-core
  protocols / co-noir / the sha-yao-LUT hotspots. Everything the web
  survey found (y2b_many 5454c3e0, transport overhaul, broadcast
  single-serialize 4bef6f8f, MAESTRO LUTs, accelerators) is ALREADY on
  our branch — the batching gap is purely in co-noir's CALL LAYER, and
  upstream hasn't fixed it either. Post-base pickables: blocking TCP
  session net 696a720d (2026-07-15, M effort, comes with a breaking
  config refactor — bench first); rest is housekeeping/circom-only.
- **co-circom techniques co-noir lacks** (file:line evidence in the
  session-16 agent report): dual-channel concurrency via
  mpc_net::join{,8} (co-plonk round2.rs:163 num∥den, round3.rs:31
  8-way; co-groth16 groth16.rs:299 open∥scalar_mul) → L0b/L8-class;
  half-share MSM + open_half_point (→ NEW lever L0d);
  local_mul_vec+reshare_vec used everywhere (co-noir's driver
  mul_many doesn't → L2c); mem::take/in-place buffer hygiene
  (shplemini clones at co_shplemini_prover.rs:180/:344/:297/:639 →
  L4-class polish).
- **Unused mpc-core inventory relevant to us**: batched GC kernels
  (get_sparse_*_many, slice_and_many, decompose_arithmetic_many,
  input_two_field_id2_many); STREAMING garbler/evaluator (used only by
  a2y_streaming conversion routes — alternative latency/throughput
  trade for large batched GC calls); cmux_vec/eq_public_many;
  get_from_public_lut_no_b2a_conversion. No cross-invocation GC
  preprocessing exists — batching is the amortisation lever.
- **Cross-relation sumcheck stage-batching** (new, L-effort lever,
  logged as L7-adjacent): the 9 relations run sequentially per
  sumcheck round, each with 1–3 own mul_many rounds (≈10–15 net
  rounds/sumcheck round × log n); stage-batching all relations'
  independent first-stage muls into one mul_many → ~3–4
  rounds/sumcheck round. Values unchanged (Fiat–Shamir barrier is the
  per-round open, untouched). Highest payoff at WAN latency;
  bench-gate.

What the field knows, filtered by our parity constraint:

- **TACEO's own trajectory validates the round thesis**: their April 2025
  release notes claim **10–20× improvement in MPC sumcheck, attributed
  chiefly to communication-round reduction** — the single hard published
  datum on Honk-family MPC proving. Our tree (synced from current
  upstream) already contains the post-April code, and the measured
  R=319/2^11 shows the remaining per-relation round structure — i.e. L1
  is the *leftover* of their own program, marked by their own TODOs.
  Their Feb 2025 notes flag MPC lookup tables / secret-index RAM as
  "considerable runtime overhead" — same pain our 440× sha256 exposes.
  Also confirmed practice: deferring resharing after multiplications
  (working additively through linear ops) ≈ 2× compute saving (their
  claim; our `local_mul_vec`/`reshare_vec` split partially does this —
  audit coverage = part of L1/L2).
- **No published lookup-heavy vs arithmetic-heavy overhead split exists**
  for a Honk-family MPC prover: our 6×/29.8×/439.6× composition finding
  appears to be ahead of the public literature. Indirect corroboration:
  MPlookup (eprint 2026/844) builds a dedicated multi-party lookup
  argument because naive lookups under MPC are quadratic; eprint
  2025/1388 designs around inversion/grand-product cost explicitly.
- **Classical primitives we already use are the right ones**: Bar-Ilan–
  Beaver masked-open inversion + constant-round prefix products (both in
  the tree), PRSS randomness (in the tree). The literature's remaining
  parity-safe offers: batch *all* logup denominators per column into one
  opening (Montgomery-tree composition), pipeline witness-independent
  mask generation behind witext (latency, not throughput), and edaBit-
  style A2B/B2A conversions for bit-heavy WITEXT (sha-class circuits).
- **Out of scope for parity, tracked for a future parity-relaxed mode**:
  MPC-friendly permutation checks (eprint 2024/940, 30×+ at scale),
  MPlookup, log-derivative permutation constraints (2025/1388), packed-
  sharing/delegation regimes (zkSaaS, EOS, Pianist — different trust
  models). CRYPTO 2025 (eprint 2025/1026) both warns that naive
  malicious-compiler shortcuts are unsound AND shows honest-majority
  malicious security can ride the proof's own soundness nearly for free —
  relevant if REP3 semi-honest is ever upgraded.
- **Design vindication**: Doerner et al. (CRYPTO 2024) prove some
  RO-based proofs *cannot* be securely distributed; the reason co-noir
  escapes is precisely that all transcript hashing happens over public
  (opened) values — the architecture §2 describes is forced, not chosen.

## 7. Relationship to other chapters

- ch. 23 = plain-prover levers (B1/L3 shared); its Phase-A fair-boundary
  requirement is partly delivered by bench v2's `vkgen`-split + witness-fed
  plaindriver baselines.
- ch. 22 §5a = bench v2 dataset layout (netstats/, features/) that feeds
  §3's hypothesis tests.
- ch. 13 gains the §5 fences once implemented (T2–T4 specs land there as
  test-plan items when built).
- PLAN.md Phase 6 tracks status; this chapter is the HOW/WHY record.
