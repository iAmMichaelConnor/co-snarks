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
  lands that gets 2e17 under the timeout.
- **The MPC path is locally SERIAL: REP3 prove runs at ~260% CPU of a
  1600% (16-thread) budget while bb prove uses ~1,450%.** Party skew
  negligible (101.20–101.35 s at 2e20). So wall-clock is dominated by
  serial local compute and/or comms waiting, not by any party lagging —
  H2-flavoured, and it says L4 (thread the local polynomial passes; the
  ch. 23 C-series only touched the PLAIN driver's code paths) plus the
  serial-inversion audit of REP3 local ops are the highest-value levers.
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
- **L2 — vectorise any per-row shared-op loops** found via H1 (oink lookup
  term / memory record paths are the suspects).
- **L3 — arkworks `parallel` + `asm` features** (ch. 23 B1, shared lever):
  currently OFF ⇒ single-threaded Pippenger MSM and generic Montgomery
  mul for BOTH plaindriver and each REP3 party's local share work.
- **L4 — thread the polynomial passes** bb multithreads (grand product,
  relation evals; `plain_proving_key.rs` carries a "Barrettenberg uses
  multithreading here" TODO) with rayon, under the measured 16-thread cap.
- **L5 — message coalescing / flush discipline** in mpc-net if H3 shows a
  per-message tax (one flush per logical round; the new msg counters make
  the before/after visible).
- **L6 — trim inverse/product domains to active rows** where bb provably
  does the same (byte parity is the referee — if bb pads, we pad).
- **L7 — literature tricks** (survey in flight): only those that leave the
  transcript untouched qualify (e.g. cheaper correlated randomness,
  round-compression of openings); anything changing proof bytes is opt-out.

Sequencing: measure first where hypotheses disagree (netstats + one
flamegraph of a sha256 REP3 party at loopback — party 0, `RAYON_NUM_THREADS=16`),
then L2/L1 (likely dominant for sha), then L3/L4 (helps everything,
including ch. 23), then L5/L6 as the data dictates. One lever per gated
change; re-run bench v2 after each committed-shaped unit (PLAN 6.4).

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
- **T5 (existing)**: ≥4-party Shamir randomness-accounting suite keeps
  guarding degree/resharing correctness for the Shamir path.

## 6. Literature survey (2026-07-24; full agent report in PROGRESS s14)

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
