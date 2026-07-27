# WITEXT-DESIGN — collapsing the round count of MPC witness extension (co-noir)

*Read-only design pass, 2026-07-27. Branch `mc/update-co-noir`. Companion to
project-docs/24 §4 (lever house style). No repo files modified; evidence is
file:line cites + in-repo bench data. Motivation: bench v3
(`bench-results/2026-07-26-v3-netem/README.md`) found witext is the dominant
WAN/LAN cost and was invisible at loopback. This doc roots-causes it and
designs the lever(s).*

---

## 0. TL;DR

- **Root cause.** The bench "poseidon" family is a **sequential chain of
  `poseidon::bn254::permutation::t_8`** that Noir compiles to **pure
  arithmetic gates** — 44,521 `AssertZero` opcodes, **0 poseidon2-blackbox, 0
  lookup, 0 memory** at 2^17 (`bench-results/circuit-features-2026-07-24/poseidon_2e17.circuit-info.json`).
  Witext solves these with `CoSolver::solve_with_output`'s **opcode-at-a-time**
  loop (`co-noir/co-acvm/src/solver.rs:381`), and each `AssertZero` with a
  shared×shared product resolves through `evaluate_mul_terms` →
  `solve_mul_term` → `arithmetic::mul` = **one ring reshare = one network
  round** (`co-noir/co-acvm/src/solver/assert_zero_solver.rs:38`,
  `co-noir/co-acvm/src/mpc/rep3.rs:701`, `mpc-core/src/protocols/rep3/arithmetic.rs:104`).
  There is **no batching** across the many independent products the solver
  encounters — TACEO flag it in-code: *"we could batch this multiplication but
  our currently planned network design should solve this without batching"*
  (`assert_zero_solver.rs:34`). Round count therefore tracks the circuit's
  **sequential nonlinear depth**: 127 rounds for one `t_8` permutation
  (base poseidon), ×92 permutations = 11,276 @ 2^17, ×743 = 92,224 @ 2^20.
- **Recommended lever.** **Two-pass level-scheduled batching of the ACVM solve
  loop** (Design A) — the L8 / L2-1a "collect-then-batch" pattern moved from
  pk-gen into witext. Compute the witness-dependency DAG (public circuit
  structure ⇒ leaks nothing), then solve level-by-level, concatenating every
  independent `solve_mul_term` in a level into one `mul_many` and every
  independent division into one `inv_vec`+`mul_many`. Rounds drop from
  "count of mul-bearing opcodes on the walk" to "DAG depth × O(1) rounds/level".
- **Predicted WAN improvement.** witext is **pure latency-bound** (40–120 B/round,
  so the tier model's per-round term is `max(RTT, tiny) = RTT`), hence
  wall ≈ rounds × RTT and any round-reduction factor *f* buys ~*f* on WAN/LAN.
  For the **chain** bench circuit *f* is bounded by within-permutation
  parallelism (registered band **1.3×–1.9×**, U1 measures the exact ceiling):
  poseidon_2e17 WAN ~451 s → **~240–350 s** (de-censors the 600 s timeout).
  For the **independent-hash** workloads that dominate real Aztec witnesses
  (Merkle membership, many leaves) the same lever collapses *K* independent
  hashes to a single hash's depth — an *f ≈ K* transformation. Loopback delta
  ≈ 0 (accepted; this is a WAN-tier lever).
- **First unit to build: U1** — the DAG level-scheduler as a **pure local
  analysis pass** + a **plain-driver equivalence referee** (identical witness
  vs. the current serial solve) that also emits the per-level width/depth
  histogram. It is comms-free, low-risk, and it *sizes the ceiling of Designs A
  and B before any REP3 code is touched* — exactly the "measurement ranks the
  mechanism" discipline of §3a.

---

## 1. ROOT CAUSE

### 1.1 The witext path, top to bottom

Witness extension = `CoSolver::solve` / `solve_with_output`
(`co-noir/co-acvm/src/solver.rs:376-410`). The driver `T` is
`Rep3AcvmSolver` (`co-noir/co-acvm/src/mpc/rep3.rs`). The solve loop is
**strictly opcode-sequential** (`solver.rs:381`):

```
for opcode in functions[function_index].opcodes.iter() {
    AssertZero(expr)        => solve_assert_zero(expr)          // arithmetic
    MemoryInit / MemoryOp   => memory solver (LUT)              // RAM/ROM
    BlackBoxFuncCall(bb)    => solve_blackbox(bb)               // poseidon2, sha, and, xor, ecc…
    BrilligCall{..}         => brillig_call(..)                 // unconstrained hints
}
```

For an `AssertZero` (`solver/assert_zero_solver.rs:105`), `simplify_expression`
first calls `evaluate_mul_terms` (`:14`), then `evaluate_linear_terms` (`:63`),
then `solve_equation` on the single remaining unknown (`:132`). The two places
that touch the network:

1. **`solve_mul_term`** for a `q_m·w_l·w_r` term where **both** `w_l` and `w_r`
   are already-known **shared** witnesses (`assert_zero_solver.rs:36-40`):
   ```
   solve_mul_term → arithmetic::mul(lhs, rhs, net0, state0)   // rep3.rs:701
   arithmetic::mul: local_a = a·b + mask; net.reshare(local_a) // arithmetic.rs:104-116
   ```
   → **1 reshare round** (send local_a to next party, receive from prev; 1
   frame ≈ 40 B = 32 B field + 8 B framing).
   *(If exactly one operand is known, it is `mul_with_public` — local, no round —
   and the term is deferred as a linear coefficient, `assert_zero_solver.rs:41-50`.)*

2. **`solve_equation`** for the last unknown when its coefficient is shared
   (`assert_zero_solver.rs:132`, `rep3.rs:709`):
   - shared coeff / public const → `div_public_by_shared` = `inv` = **1 round**
     (`arithmetic.rs:202`, `:217`): `inv` does `mul_open(a,r)` — a **broadcast**
     that receives from *both* peers → **2 frames in 1 round** (≈ 80 B).
   - shared / shared → `div` = `inv` (1 round) + `mul` (1 round) = **2 rounds**
     (`arithmetic.rs:180-187`).

This is why the measured witext histogram shows rounds of **40 / 80 / 120 B**
(`bench-results/2026-07-26-v3-netem/loopback/netstats/poseidon_2e17_REP3_witext_r1_p0.json`):
40 = one `mul` reshare; 80 = one `inv` broadcast (2 frames); 120 = an `inv`
followed in the same blocked-recv window, or a 3-frame division. The
`_note` in that file defines a round precisely: *"a round = a recv that found
nothing queued and had to wait."*

### 1.2 The poseidon family is arithmetic, not blackbox

Critical: `poseidon::bn254::permutation::t_8` compiles to **arithmetic gates**,
NOT the `Poseidon2Permutation` blackbox. Evidence
(`bench-results/circuit-features-2026-07-24/poseidon_2e17.circuit-info.json`):

```
opcode_histogram: { "AssertZero": 44521 }
blocks: { arithmetic: 129713, poseidon2_external: 0, poseidon2_internal: 0,
          lookup: 0, memory: 0, elliptic: 0 }
lookup_gates: 0,  num_lookup_tables: 0
```

So for this circuit the poseidon2 driver gadget
(`co-noir/co-acvm/src/mpc/rep3.rs:1349 poseidon2_permutation`, backed by
`mpc-core/src/gadgets/poseidon2/rep3.rs`) is **never called**, and the
LUT/plookup and memory solvers are never hit. **The entire witext round count
is `solve_mul_term`/`solve_equation` network calls from `AssertZero`.**
(The `blackbox_poseidon2` test vector *does* exercise the gadget path —
relevant only to Design C.)

For contrast, `bb_sha256_compression` witext is **2 rounds / 5 msgs**
(`tiers.csv`): sha's witext one-shots the compression in a single buffered
Bristol/Yao evaluation (co-acvm `sha256_compression`), so it is *not* a
poseidon-style round-deep problem. The sha pain is pk-gen (L0e), not witext.
LUT/plookup do not feature in poseidon-family witext at all.

### 1.3 Deriving the numbers and reconciling with the bench

Circuits (`co-noir/co-noir/examples/test_vectors/poseidon_2e17/src/main.nr`, `…2e20`):

```
global K = 92 (2^17) / 743 (2^20);
let mut s = plains; for _ in 0..K { s = permutation::t_8(s); } s[0]
```

A **hard sequential chain**: permutation *k*'s input is permutation *k-1*'s
output. Per-permutation cost calibrated from the base circuit
(`…/poseidon/src/main.nr` = one `t_8`, 477 `AssertZero`, `poseidon.circuit-info.json`):

| circuit | K (perms) | witext rounds | recv_msgs | rounds / K | msgs / round |
|---|---|---|---|---|---|
| poseidon (base, 2^11) | 1 | 127 | 366 | 127.0 | 2.88 |
| poseidon_2e17 | 92 | 11,276 | 33,399 | 122.6 | 2.96 |
| poseidon_2e20 | 743 | 92,224 | 269,712 | 124.1 | 2.93 |

(rounds from `bench-results/2026-07-26-v3-netem/loopback/tiers.csv`.)

- **Rounds scale linearly with chain depth K, not with dyadic size**: 2^17→2^20
  is 8.0× rows but K is 92→743 = 8.08× and rounds are 11,276→92,224 = 8.18×.
  Confirms: **witext depth = (# sequential permutations) × (per-permutation
  sequential nonlinear depth ≈ 123 rounds)**. This is the ch.24 §3 claim
  "circuit DEPTH, not size, sets WAN feasibility of witext" made precise.
- **~123 rounds per `t_8` permutation** decomposes (to be pinned exactly by U1)
  as ≈ (`R_F` full rounds + `R_P` partial rounds) × (sequential mul/open depth
  of the S-box as the ACIR expresses it). For a bn254 `t_8` poseidon that is
  ~71 rounds × ~1.7 comms-ops/round. The 1.7 (not 3) means the ACIR's x^5 is
  *not* a naïve 3-deep multiply chain — U1 must attribute it across
  `solve_mul_term` vs `solve_equation` (division) calls.
- **msgs/round ≈ 3**: a `mul` reshare is 1 frame; an `inv`/division broadcast
  is 2 frames (`mul_open`, `arithmetic.rs:217`) in 1 round, plus its trailing
  `mul`. The mix of muls and divisions gives ~2.9 frames/round.
- **Reconciling ch.24's "witext R ≈ 33k @ 2e17"**: that older figure was the
  **message count** (33,399) used as an R-proxy *before* the logical-round
  counter existed. v3's true sequential depth is **11,276 rounds**; msgs are
  ~3× that. This is exactly the "R-proxy caveat" (ch.24 §3a) resolved — use
  `rounds` for depth, `recv_msgs` for the conservative `dep_hi` bracket.

### 1.4 Classification of round sources

| source | rounds (2^17) | class | batchable? |
|---|---|---|---|
| the K-permutation chain (perm *k* ← perm *k-1*) | ×92 factor | **inherently sequential** (true data dep through the witness) | **No** — irreducible for a chain |
| the ~71 poseidon rounds within a permutation (matmul mixes S-box outputs → next round's inputs) | ×~71 factor | **inherently sequential** | **No** |
| multiplicative depth of one S-box (x^5 ≈ 2–3 deep) | small factor | inherently sequential | reducible to **1** via mask-open precomp (Design B) |
| the ≤8 **independent S-boxes within a full round** (each element's S-box is independent) | serialized as separate blocked recvs | **independent-but-serialized** | **Yes** — `mul_many` |
| independent products/divisions across sibling `AssertZero` opcodes at the same DAG depth | serialized | **independent-but-serialized** | **Yes** — the general lever |
| per-S-box random-power precompute (Design B/C only; input-independent) | — | **independent-but-serialized** | **Yes** — hoist + batch once |

The irreducible floor for poseidon_2e17 is **K × (per-permutation sequential
depth)** ≈ 92 × ~71 ≈ **6,530 rounds** (if every S-box layer becomes a single
open and all within-round parallelism is collapsed). Everything above that
6,530 floor (currently 11,276) is *independent-but-serialized* and is what the
levers reclaim. **For a chain, the 6,530 floor still dominates WAN cost; the
levers help but cannot rescue a chain — that is a circuit-shape property, and
the doc says so honestly.**

---

## 2. LEVER DESIGN(S)

### Design A — Two-pass level-scheduled batching of the ACVM solve loop *(RECOMMENDED)*

**Mechanism.** Replace the single opcode-at-a-time loop (`solver.rs:381`) with:

- **Pass 1 (local, comms-free): level assignment.** Walk opcodes in order;
  maintain `produced_at[witness] = level of the opcode that first assigns it`
  (initial ABI witnesses = level 0). For each opcode compute
  `level = 1 + max(produced_at[w] for w in inputs)` and record `produced_at`
  for its outputs. Opcodes sharing a level are provably mutually independent
  (no output of one is an input of another). The opcode DAG is derived purely
  from the **public** circuit (witness *indices*, not values) — see §3/§6.1,
  it leaks nothing.
- **Pass 2: solve level-by-level, batching the network calls.** For each level:
  1. run `simplify_expression` locally on every opcode, but instead of calling
     `solve_mul_term`'s per-term `arithmetic::mul`, **collect** all
     shared×shared product pairs `(lhs, rhs)` across all opcodes in the level;
  2. issue **one** `mul_many` (`local_mul_vec` + `reshare_vec`,
     `arithmetic.rs:133/:150`) for the whole level → **1 round**;
  3. scatter results back, finish linear reduction, **collect** all
     shared-coefficient divisions into one `inv_vec` (`arithmetic.rs:233`,
     already Montgomery-batched) + one `mul_many` → **≤2 rounds**;
  4. insert solved witnesses.

**Rounds after.** From "≈ count of mul/division-bearing opcodes on the serial
walk" to **Σ_levels (≤ ~3 rounds/level)**. For the chain: levels ≈ the
sequential depth, and the win = (independent muls per level) collapsed —
registered band 1.3×–1.9× (U1 pins it). For **independent-hash** circuits: all
*K* hashes occupy the *same* levels, so a *K*-fold collapse.

**On the wire:** identical field reshare payloads, concatenated per level into
fewer, larger frames (`reshare_many`). Same total field elements moved (minus
per-frame framing bytes), **far fewer rounds**.

**Stays identical:** every solved witness *value*; the set of reshare payloads;
the *number* of mask draws. (RNG *order* changes — see §3.)

**Effort L, risk M–H.** Complexity: the leveler must correctly model deps
through **all** opcode kinds, not just `AssertZero` — `MemoryOp` reads/writes
create deps through the LUT (`solver/memory_solver.rs`), `BrilligCall` outputs
are opaque producers, blackbox opcodes are multi-output. For the poseidon
family this is trivial (only `AssertZero`, no memory/brillig — §1.2), so U1/U2
can gate on poseidon first and treat other opcode classes as **level barriers**
(a memory/brillig/unhandled-blackbox opcode flushes the current batch and forces
a fresh level) — a safe, conservative fallback that still batches the arithmetic
runs and can be relaxed later.

### Design B — mask-open precompute S-box for arithmetic-gate hashes *(L0e analogue, narrower)*

**Mechanism.** The poseidon2 *gadget* already implements the depth-collapsing
S-box: mask x with a precomputed r, open `x-r` (1 round), reconstruct x^5 from
public powers of `(x-r)` and precomputed `r,r²,…,r⁵`
(`mpc-core/src/gadgets/poseidon2/rep3.rs:220 sbox_rep3_precomp`,
`:358 sbox_rep3_precomp_post`). The precompute
(`precompute_rep3`, `:12`) is **input-independent** (3 batched mul rounds over
random `r`) and can be hoisted to the very start of witext and batched across
*every* S-box in the circuit. Design B recognises the x^5 pattern inside the
arithmetic-gate stream and swaps the naïve muls for this 1-round mask-open.

**Rounds after.** Each S-box layer → 1 open round; per-permutation depth →
~71 (the poseidon-round floor) + a single up-front batched precompute for all
`num_sbox × K` powers. poseidon_2e17: 11,276 → ~6,500 (the §1.4 floor).

**Effort L, risk H.** Requires pattern-matching the ACIR's x^5 encoding
(fragile: depends on how nargo lowers the stdlib poseidon; a compiler bump can
silently break the match → must fail *closed* to Design-A/serial, never emit a
wrong witness). Lower ceiling than expected because the chain floor dominates.
**Not the first unit.** Only pursue if U1 shows within-S-box depth is a large
fraction of the 123 rounds/perm.

### Design C — batch the poseidon2-blackbox precompute *(cheap, safe, orthogonal)*

**Mechanism.** For circuits that *do* use the `Poseidon2Permutation` blackbox,
`solve_poseidon2_permutation_opcode` (`blackbox_solver.rs:534`) calls
`driver.poseidon2_permutation` **per opcode**, which does
`precompute_rep3(1)` **per permutation** (`rep3.rs:1366`) = 3 network rounds of
input-independent randomness *every* permutation. The **packed** path already
exists (`gadgets/poseidon2/rep3.rs:612 rep3_permutation_in_place_with_precomputation_packed`,
`precompute_rep3(num_poseidon)`). Lever: pre-scan opcodes, count the poseidon2
permutations, call `precompute_rep3(N)` **once** up front (batched, 3 rounds
total), and have each opcode consume from the shared precomp buffer.
Independent permutations then also batch their per-round S-box opens via the
`_packed` methods.

**Rounds after.** Precompute: 3N → 3. Independent perms: fully packed.
**Effort S–M, risk Low** (primitives exist; input-independent randomness has no
value-parity subtlety). **Zero effect on the current poseidon bench**
(arithmetic, not blackbox) but real value for any blackbox-poseidon2 workload —
worth landing as a standalone unit.

**Recommendation:** Build **Design A** (it subsumes the general problem and is
the house pattern), gated to poseidon/arithmetic first. Land **Design C** in
parallel as a cheap independent win. Hold **Design B** behind U1's ceiling
measurement.

---

## 3. BINDING CONSTRAINTS (how each design stays parity-safe)

- **Witness values identical.** Design A batches *independent* products only
  (leveling guarantees no batched pair depends on another in the same level),
  and `mul_many`/`inv_vec` compute the same per-element values as the serial
  `mul`/`inv` (`inv_vec` doc, `arithmetic.rs:233`: "yields exactly the
  per-element inverses the previous serial loop computed"). Design B/C reuse
  gadget kernels already value-proven against the serial path.
- **Proof/VK bytes byte-identical (KAT referee).** The final proof is over the
  shared witness and the opened (public) transcript values; the non-ZK
  byte-parity KATs + VK KATs + 3-party-identity + bidirectional bb cross-verify
  (`fast-check.sh` / `compare_mpc.sh`, T1) are the outer gate. This is the
  decisive referee for all three designs.
- **Non-ZK proof bytes identical to bb.** Unchanged — witext produces the same
  witness; nothing about the transcript changes. (ZK bytes legitimately vary and
  are excluded from the byte pins, per §5/T4.)
- **RNG-stream discipline — the one care point.** `arithmetic::mul` draws one
  mask per product from the per-party correlated stream
  (`state.rngs.rand.masking_field_element`, `arithmetic.rs:110`);
  `local_mul_vec` draws them up front for the whole batch (`:139`). Serial order
  draws in opcode/term order; level-batched order draws in
  (level, then within-level opcode index) order — a **different total
  sequence**, so the resulting **shares differ bit-for-bit** even though every
  reconstructed value and the proof are identical (the mask cancels in the
  ring; T3 rerandomization-invariance proves seed-independence of proof bytes).
  Consequence, matching the L8/L0c/L0d discipline: **witext/pk-gen share-level
  byte-fences and the witext round-count fence must be consciously re-pinned**
  to the new (lower) round counts; the **proof/VK KATs must not move**. If
  bit-identical shares are also wanted (not required), the leveler can draw
  masks in the *original opcode index order within each level* to minimise
  drift — but the honest position is: proof bytes are the invariant, shares
  re-pin. (L8 set the precedent: mask draws are per-element sequential ⇒
  identical *sequence* when the batch preserves per-element order; verify at
  implementation whether Design A can preserve the exact global sequence or
  only the per-level one.)
- **T2 msg-count fences re-pinned consciously.** witext currently has no
  in-process fence like the poseidon prove/pk-gen ones
  (`tests/tests/noir/proof_tests/rep3.rs`); U1 should add a witext round/byte
  fence for the base poseidon circuit so U2+ regressions and cheats are caught
  (see §5 T2).
- **No MPC-property shortcuts.** Leveling is computed over the **public** opcode
  structure (witness indices + which opcode produces them), never over witness
  values; no value is opened earlier; all cross-party data still flows through
  the `Network` trait (`reshare_many`, `mul_open_vec`). §6 checklist details.

---

## 4. REGISTERED PREDICTIONS (per design)

witext is **pure latency-bound**: per-round bytes are 40–120 B, so the tier
model's per-round term `max(RTT, bytes_r/bandwidth)` = **RTT** at LAN (2 ms) and
WAN (40 ms) (`scripts/bench-tier-model.py:tier_seconds`). Therefore
**wall ≈ rounds × RTT**, and a round-reduction factor *f* buys ~*f* on
LAN/WAN. Loopback (RTT 0.1 ms, but the phase is CPU/reshare-bound there) sees
≈0 change — accepted, this is a WAN-tier lever.

**Design A on the chain bench circuit** (band; U1 pins *f* = current_rounds ÷
DAG_depth before U2 ships):

| circuit / tier | rounds now | wall now | rounds after (f=1.3–1.9) | predicted wall after |
|---|---|---|---|---|
| poseidon_2e17 witext, LAN | 11,276 | 35.9 s (meas.) | 5,900–8,700 | **19–28 s** |
| poseidon_2e17 witext, WAN | 11,276 | ≥600 s (censored; model 451 s pipelined) | 5,900–8,700 | **~240–350 s** (de-censors) |
| poseidon_2e20 witext, LAN | 92,224 | 289.5 s (meas.) | 48k–71k | **150–225 s** |
| poseidon_2e20 witext, WAN | 92,224 | model 3,689 s pipelined | 48k–71k | **~1,960–2,960 s** |
| loopback (any) | — | 1.7 s / 12 s | — | **~unchanged (±10%)** |

Prediction method to run at U2/U4: rerun the circuit, read the new
`recv_bytes_histogram`, feed `bench-tier-model.py` → new `tiers.csv`; compare
LAN/WAN measured against the bracket, exactly as v3 validated the model.

**Design A on an independent-hash circuit** (propose adding `poseidon_2e17_indep`
= K independent `t_8` hashes, no chaining): register *f ≈ K* — witext rounds
~11,276 → **~130** (one hash's depth), WAN ~451 s → **~6–8 s**. This is the
result that matters for real Aztec witnesses and should be benched to prove the
lever's true value.

**Design C** (blackbox-poseidon2 circuit with N perms): precompute 3N → 3
rounds; independent perms fully packed. On `blackbox_poseidon2` (small) expect
a handful of rounds saved; the value is in large N. Register: rounds → the
packed-path depth; proof/VK md5 identical.

**Design B**: poseidon_2e17 → ~6,500 rounds (the §1.4 floor); WAN → ~265 s.
Marginal over Design A on the chain; only register if U1 justifies it.

---

## 5. UNIT BOUNDARIES

Each unit has a referee that must be green before the next. Effort S/M/L, risk L/M/H.

- **U1 — DAG level-scheduler as a pure analysis pass + plain-driver equivalence
  referee. `[effort S–M, risk L]` BUILD FIRST.**
  Deliverable: Pass-1 leveling over the opcode stream + a diagnostic that prints
  (num levels = DAG depth, per-level width histogram, and an attribution of the
  base-poseidon 127 rounds across `solve_mul_term` shared×shared vs
  `solve_equation`/`div` shared). Referee: a **plain-driver** solve that
  processes opcodes in level order produces a witness **bit-identical** to the
  current serial `solve` (comms-free, so zero protocol risk). This *sizes the
  ceiling of A and B* (what is the real DAG depth vs 11,276? what fraction is
  within-S-box depth vs within-round width?) and decides whether B is worth it.
  No network code touched.

- **U2 — REP3 per-level `mul_many` batching. `[effort M, risk M]`**
  Wire Pass-2 step (1)–(2): one `mul_many` per level for all independent
  shared×shared products; memory/brillig/unhandled-blackbox opcodes act as
  level barriers (§2). Referee: 3-party non-ZK proof **byte-identical** to the
  plain KAT and across seeds (T1+T3); poseidon prove/pk-gen fence canaries
  unchanged; witext round count drops to the U1-predicted value and is
  **re-pinned** in a new witext T2 fence; view-scan (T4) clean. Registered
  round/wall predictions from §4 checked via `bench-tier-model.py`.

- **U3 — REP3 per-level division/inversion batching. `[effort S–M, risk M]`**
  Pass-2 step (3): one `inv_vec` + one `mul_many` per level for shared-coeff
  `solve_equation`. `inv_vec` already exists and is value-proven
  (`arithmetic.rs:233`). Referee: same as U2; further round drop re-pinned.

- **U4 — (optional) mask-open precomp S-box (Design B). `[effort L, risk H]`**
  Only if U1 shows within-S-box depth is a large share. Must fail-closed to U2/U3
  on any pattern-match miss. Referee: U2's + an added assertion that the recognised
  S-box witnesses equal the serial ones on a fuzzed input set.

- **U5 — (independent) blackbox-poseidon2 precompute batching (Design C).
  `[effort S–M, risk L]`**
  Pre-scan + `precompute_rep3(N)` once + `_packed` consumption. Referee:
  `blackbox_poseidon2` 3-party proof+VK md5 identical before/after; precompute
  round count 3N→3 pinned.

**Recommendation: build U1 first.** It is cheap, comms-free, decisive, and it
converts the §4 bands into registered point predictions before any REP3 change —
the discipline §3a's "measurement ranks the mechanism" retro demands.

---

## 6. §4a SECURITY CHECKLIST — for the recommended design (A, units U1–U3)

**1. No new knowledge at any node.**
Batching only concatenates the **same reshare payloads** the serial solve
already sent. In `mul_many`/`reshare_vec` each party still sends its own
`local_a_i = a_i·b_i + mask_i` (one masked product per element, fresh
correlated mask per element, `local_mul_vec` `arithmetic.rs:139`) and receives
only its ring-neighbour's corresponding `local_b`, exactly as `mul` did — one
frame per element, now in one batched frame. Divisions use the same
`mul_open`/`inv_vec` broadcast the serial path used; nothing is opened earlier
and no extra share limb is shipped. The margin (§4a: "receiving the third
summand = reconstruction") is untouched: each party still holds 2 of 3 summands
and receives one masked function of the third, as before. ✓

**2. Separate-entity discipline.**
All cross-party data still flows through the `Network` trait
(`reshare_many`, `mul_open_vec` — `arithmetic.rs`). No code path reads another
party's state. The leveling analysis (Pass 1) reads **only public circuit
structure** — witness *indices* and which opcode produces each — which every
party already holds identically (the compiled circuit is public); it never
inspects a witness *value*, never opens anything, and never computes locally
what the protocol requires jointly (it merely re-groups the *same* joint
multiplications into fewer rounds). ✓

**3. Mechanical checks backing 1+2.**
- T1: non-ZK proof + VK **byte-parity KATs**, 3-party byte-identity,
  bidirectional bb cross-verify (`fast-check.sh --all-fast`) — the decisive
  referee; proof/VK bytes MUST NOT move.
- T2: **new witext round/byte fence** (U1 adds it for base poseidon), re-pinned
  consciously at U2/U3 to the lower round counts; a change that dropped witext
  rounds toward ~0 (a cheat that stopped doing the MPC) would red the build
  against the `[0.5×,2×]`-of-honest floor (ch.24 §5 T2). Byte pins guard against
  a leak that keeps frame count but fattens payloads.
- T3: **share-rerandomization invariance** — different seeds ⇒ different shares
  ⇒ identical proof bytes; this is exactly what licenses the mask-draw-order
  change in §3 (proof bytes are seed/order-independent).
- T4: **two-party view-scan** — assert no plaintext witness value appears in any
  frame across a full witext+pk-gen+prove run (already landed,
  `tests/…/rep3.rs poseidon_witness_view_scan_no_plaintext_leak`); rerun after
  U2/U3.
- Determinism: fence + KAT checked ×2 runs.

**Net:** Design A is a pure re-grouping of already-joint multiplications by a
publicly-computable independence relation; it moves the identical field data in
fewer rounds. It cannot leak (checks 1–2) and cannot silently cheat (T2 floor +
T1 KATs). Share-level fences re-pin; proof/VK bytes are invariant. ✓

---

## 7. What an implementation agent MUST verify (flagged uncertainties)

1. **The exact per-permutation round decomposition** (the "~1.7 comms-ops per
   poseidon round"): attribute base-poseidon's 127 rounds across
   `solve_mul_term` (shared×shared `mul`) vs `solve_equation` (`div`/`inv`)
   calls, and measure the true DAG depth and per-level width. This sets *f*.
   (U1's job; §1.3, §4 bands depend on it.)
2. **Whether the level-batched mask draw can preserve the exact global RNG
   sequence** or only the per-level one — decides whether share-fences move at
   all or must be re-pinned (§3). L8 preserved it by per-element ordering;
   confirm the same holds when regrouping across opcodes.
3. **Non-`AssertZero` dep modelling** (memory/brillig/multi-output blackbox) —
   the barrier fallback is safe but conservative; verify the poseidon family
   truly has none (§1.2 says so from circuit-info; re-confirm on the exact
   compiled artifact) before relying on the fast path.
4. **The 80/120-B rounds are divisions** (`inv`/`mul_open`), not already-batched
   muls — confirms the muls are genuinely one-per-round today (headroom real).
   Verify by counting `inv`/`div` calls in base poseidon witext.
5. **`inv_vec` zero-handling** on the batched path (`arithmetic.rs:233` bails on
   any zero) must match the serial `inv`'s per-element bail semantics for the
   witness values actually produced (poseidon intermediates are non-zero w.h.p.,
   but confirm no structural zero divisor exists).

---

## 8. U1 RESULTS (implemented 2026-07-27, session 20, coordinator-verified — uncommitted)

U1 (comms-free level-scheduler analysis pass + plain-driver equivalence referee)
is in-tree. New files: `co-noir/co-acvm/src/solver/level_schedule.rs` (pure
functions over `&[Opcode]`), `co-noir/co-acvm/tests/witext_level_referee.rs`
(referee + red-validation + diagnostics); `solver.rs` extracts a shared
`solve_single_opcode` + `solve_in_order` + env-gated `CO_NOIR_WITEXT_LEVELS`
diagnostics. NO network/MPC code touched.

**Measured DAG depth + width:**

| circuit | opcodes | DAG depth | width max/mean | histogram (width×#levels) |
|---|---|---|---|---|
| poseidon (2^11 base) | 477 | 259 | 16 / 1.84 | 1×229, 8×29, 16×1 |
| poseidon_2e17 | 44,521 | 23,919 | 16 / 1.86 | 1×20,977, 8×2,941, 16×1 |
| poseidon_2e20 | 359,605 | 193,179 | 16 / 1.86 | 1×169,405, 8×23,773, 16×1 |

**Round attribution (all three): 100% shared×shared `mul`, 0 inv, 0 div**,
max 8 muls/level. The taint-sim mul count = measured `recv_msgs − 3` exactly
(the 3 = final return-value open) — an independent reproduction of the bench
message count, validating the attribution.

**Registered f (network-operation / frame units): 1.86 for the chain**
(constant across sizes = top of the §4 1.3–1.9× band); **≈ K·1.86 for K
independent hashes** (synthetic K=8 replication measured f = 14.89 = 8×1.86,
depth unchanged) — the independent-hash win is confirmed and unambiguous.

**§7 uncertainties resolved:**
- #1 decomposition — base = 363 shared×shared muls, depth 259, 0 divisions.
- #3 non-AssertZero — poseidon family is 100% `AssertZero`; nothing barrier'd.
  (Opcode modelling built: AssertZero/BrilligCall/BlackBoxFuncCall precisely
  modelled; MemoryInit/MemoryOp/Call = conservative level BARRIER.)
- #4 "80/120-B rounds are divisions" — **FALSE**. Zero divisions: every output
  is a fresh witness as a *linear* term with a *public* coefficient
  (`z − x·y = 0`), so `solve_equation` is always the LOCAL `div_shared_by_public`
  path. 80/120-B frames are 2–3 coalesced 40-B `mul` reshares. **⇒ U3 (division
  batching) is a no-op for the poseidon family; deprioritise it.**
- #5 inv_vec zero-handling — moot for poseidon (no inversions); note stands for
  circuits that do divide by a shared coefficient.
- #2 RNG draw-order — deferred to U2 (plain driver has no RNG).

**🔴 CRITICAL DESIGN CORRECTION for U2 (from U1's measurement):** the doc's
literal `f = rounds ÷ DAG_depth` gives 127/259 ≈ 0.49 (< 1) because the bench
`rounds` metric is a LOOPBACK UNDERCOUNT — at loopback ~2.9 mul reshares coalesce
per blocked recv, so measured `rounds` sits *below* both the DAG depth and the
network-op count. The 1.86× is real in operation/frame units; the WAN mapping is
the U2 question. **A naïve level-SYNCHRONOUS Design A (global barrier per level)
would pay 17,940 rounds at 2e17 and could REGRESS the loopback metric vs the
current async-pipelined 11,276.** So U2 MUST batch within a level AND pipeline
across levels — NO global per-level barrier. The win is latency-bound (WAN tier);
the independent-hash case is the unambiguous win in both units.

**Gates:** referee 6/6 (bit-identical witness serial-vs-level-ordered; reversed
order red-validated), co-acvm lib 7/7, cargo check --workspace / fmt / clippy -D
on co-acvm all PASS. (`fast-check --all-fast` had one pk-gen fence failure —
`blackbox_and_prove_comms_message_fence` 151→40 — attributed to the concurrent
L2-1b agent's in-flight OHV/read-count edits on a path U1 never touches;
coordinator to reconcile once L2-1b lands.)

**U2 spec (next unit):** wire Pass-2 — collect all shared×shared products per
level → one `mul_many`, NO per-level barrier (pipeline across levels); preserve
per-element mask order within a level or re-pin witext share fences; add a witext
round/byte T2 fence for base poseidon in a NEW test file (pinned 363 muls / 127
loopback rounds); measure on the netem WAN tier (not loopback) + bench a real
independent-hash circuit to confirm f ≈ K. U3 (division batching) deprioritised
for poseidon.

---

## 9. CORRECTION (2026-07-27, Mike) — what "independent-hash" actually means

§0/§4/§8 above call real Aztec Merkle-membership witnesses "independent-hash"
workloads. **That is imprecise and is corrected here.** A SINGLE Merkle
membership check is a SEQUENTIAL CHAIN, not independent hashes: layer k computes
`node_k = hash(node_{k-1}, sib_k)`, consuming the previous layer's OUTPUT, so in
the witext DAG the d layers form a depth-d chain the level-scheduler cannot
batch. The witext lever gives such a single path essentially nothing beyond the
within-one-hash width.

Independence — the thing the lever exploits — comes from two distinct sources,
only one of which is free:

1. **ACROSS multiple membership proofs (FREE, no circuit change).** A circuit
   checking N different notes' membership has N paths over DISJOINT witnesses;
   the scheduler batches all N proofs' layer-k hashes into one `mul_many`, so
   total witext depth ≈ d (one path) instead of N·d ⇒ f ≈ N. The N paths are
   naturally independent in the DAG; no authoring change needed. This is what
   the synthetic `poseidon_2e17_indep` (K disjoint hashes) actually models, and
   it is the honest claim. (Earlier "f ≈ K for Merkle" should be read as
   "K = number of independent membership proofs", NOT "K = tree depth".)

2. **WITHIN a single path (requires co-snark-aware circuit authoring).** Only if
   the circuit is written to take each intermediate node as a prover-supplied
   ADVICE witness `hint_k` (level 0), compute `out_k = hash(hint_k, sib_k)` for
   all layers in parallel, and add BINDING constraints `out_k == hint_{k+1}`
   (+ `out_{d-1} == root`). Then all d hashes have level-0 inputs and batch to
   one hash's depth. Crucially the binding constraints are LINEAR
   (`out_k − hint_{k+1} = 0`, both already-known shared witnesses) ⇒ LOCAL,
   ZERO comms rounds — they are mandatory for soundness (they enforce the chain
   a malicious prover must not break) but cost nothing in the round count witext
   latency is made of. So the *comms* chain is broken while the *soundness*
   chain is preserved. The natural idiom
   (`let mut node = leaf; for sib { node = hash(node, sib); }`) compiles to the
   sequential DAG and gets NONE of this — the win needs the hint+bind style.
   A future Noir compiler pass could hoist intermediates to advice + inject the
   binding automatically (same DAG effect, no author burden); nothing does today.

**Consequence for the lever's value proposition:** the witext win is a function
of how much independence a real circuit's witness DAG has — cross-proof
independence is free, within-chain independence needs rewriting, pure accumulator
chains get nothing. DO NOT assume real Aztec circuits are independence-rich.
**Before committing U2 effort, run U1's level-scheduler (CO_NOIR_WITEXT_LEVELS
diagnostics) on a REAL Aztec kernel/membership circuit and read the measured DAG
width vs depth** — that turns the assumption into a number. Added as the gating
measurement for the U2 go/no-go.
