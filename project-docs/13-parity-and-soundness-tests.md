# Chapter 13 — Parity + soundness/completeness test plan

*What co-noir's test suite must cover to (a) guarantee byte/verifier parity
with Barretenberg and (b) give real soundness & completeness assurance —
beyond what exists today. This is the "definition of done" for phases 0, 2,
and every future sync. Grounded in the existing suite under
`tests/tests/noir/` (`proof_tests/{plain,plaindriver,rep3,shamir}.rs`,
`witness_extension_tests/`).*

## 0. Vocabulary (so "soundness/completeness" is precise here)
- **Completeness**: every *valid* witness produces a proof the verifier
  accepts (and, for us, that real `bb` accepts). A completeness failure = a
  legitimate user can't prove.
- **Soundness**: no *invalid* witness (or tampered proof) produces a proof the
  verifier accepts. A soundness failure = a false statement can be "proven".
- **Parity**: co-noir's proof/VK bytes equal bb's for the same circuit+witness
  (non-ZK), and each accepts the other's proofs (ZK included). Parity is the
  strongest single property — it transfers bb's own assurance to co-noir.
- **MPC-consistency**: the MPC prover (REP3/Shamir) yields the *same* proof as
  the plain prover for the same witness, and no single party's view leaks the
  witness.

## 1. What the suite already does (baseline)
- Proves each test-vector circuit with plain / plaindriver / REP3 / Shamir and
  asserts the resulting **proof bytes equal a committed bb proof KAT**
  (non-ZK, both poseidon2 & keccac). ← parity + MPC-consistency, non-ZK.
- For ZK and for `recursion`/`recursion_zk` (nondeterministic), skips
  byte-equality and only runs the plain `UltraHonk::verify` on the produced
  proof. ← weak: self-verification only.
- Witness-extension tests exercise co-acvm/co-brillig on the vectors.

**Gaps this chapter closes:** (1) no cross-check against a *live* `bb`
verifier in-tree (only stored KAT bytes); (2) ZK proofs are only
self-verified, never `bb`-verified; (3) **almost no negative tests** —
soundness is essentially untested; (4) no VK-byte parity assertion; (5) no
property/fuzz coverage; (6) no MPC privacy check.

## 2. Parity tests to add (co-noir ↔ real bb)
Make the parity oracle a *live* `bb`, not just frozen bytes.

1. **Live 4-way cross-verification** (wire `compare.sh`/`compare_mpc.sh` into
   CI as a test, per ch. 02 §6): for each vector × {poseidon2, keccac} ×
   {ZK, non-ZK}, generate proof+VK with co-noir AND with reference `bb`, then
   verify all four combinations — our-proof/our-vk, our-proof/their-vk,
   their-proof/our-vk, their-proof/their-vk — with both verifiers. All must
   accept. This catches ZK parity (which KAT byte-equality can't).
2. **VK-byte equality**: assert co-noir's `to_buffer` / `to_buffer_keccak`
   VK bytes equal bb's `write_vk` output for every vector (both hashers).
   Today only proofs are byte-checked; the trace-offset work (ch. 11 §2.4)
   changes VKs, so pin them.
3. **Proof-length invariants**: assert produced proofs are exactly 410 (non-ZK)
   / 458 (ZK) fields and VK 115 (ch. 04 §5) — a cheap tripwire for constant
   drift.
4. **KAT provenance note**: record in each `kat/` dir the exact `bb` version
   the bytes came from, so a stale KAT is detectable (avoids "green against
   our own outdated bytes").

## 3. Soundness (negative) tests to add — the biggest gap
For a representative subset of vectors, assert the verifier **rejects**:

1. **Tampered proof**: flip one field element / one byte in the proof → reject.
   Do this at several structural positions (a commitment, a sumcheck
   univariate coefficient, an evaluation, the KZG opening) so a
   "not-fully-checked" region is caught.
2. **Wrong public inputs**: verify a valid proof against altered public inputs
   → reject.
3. **Wrong VK**: verify against a different circuit's VK / a VK with one
   commitment perturbed → reject.
4. **Trailing/short proof**: append or drop field elements → reject. (Directly
   tests the "proof fully consumed" property; this class of check is exactly
   what a robust transcript must enforce.)
5. **Cross-flavor mismatch**: a poseidon2 proof must not verify under the
   keccac verifier, ZK vs non-ZK must not interchange, and proof_type
   HONK(0) vs HONK_ZK(6) must be distinguished.
6. **Invalid witness at proving time**: feed a witness that violates a gate
   (e.g. an out-of-range value where a range constraint applies, or a false
   assert) → proving fails OR the resulting proof is rejected. This is where
   the co-builder must reproduce bb's *implicit* constraints — e.g. the
   implicit ranges bb attaches to AND/XOR/MSM operands (ch. 06 / the RANGE-
   stripping behavior): construct a witness that only fails if that implicit
   range is present, and confirm rejection. **This is the highest-value
   soundness test** because it checks co-noir didn't under-constrain relative
   to bb.
7. **Malformed ACIR / opcode edge cases** (witness-extension side): duplicate
   MemoryInit, out-of-range BrilligCall id, MemoryOp on uninitialized block,
   ToRadix with zero limbs, ABI decode of out-of-range values → structured
   error, never a panic and never silent acceptance of an out-of-domain value.
   (These map to concrete co-acvm/co-brillig entry points; see also §6.)

### 3a. MANDATORY security-regression tests (from the 2026-07-08 rationale
### mining — ch. 03 §6; these port bb's own embargoed-fix regression tests)

These are not optional hardening — each corresponds to a real attack bb
fixed via its private security repo. Port bb's regression tests, not just
the happy path.

8. **SSIPA forgery (ports bb `shplemini.test.cpp` malicious-prover test;
   bb PR #44).** Construct the homogeneous-kernel perturbation
   (δ_A(1)=δ, δ_A(g^j)=−δ/(g−1) for j≥1, δ_s=c) that satisfies the SSIPA
   identity at r but forges the Libra inner-product, and assert the co-noir
   ZK verifier **rejects** it. CRITICAL: the test must exercise the full
   Shplemini-batched path — bb's own README states the standalone
   `check_consistency` identity check *accepts* the forgery, so a test that
   bypasses Shplemini would pass while the real vulnerability remained. This
   is the test that proves co-noir enforces the A(1)=0 boundary claim on the
   VERIFIER side, not just that its prover emits 5 claims.
9. **ROM/RAM field-wrap attack (ports bb `rom_ram.test.cpp`; bb PR #29).**
   Build a circuit whose sorted ROM/RAM index chain starts at the field
   value p−1 (≡ −1) and wraps to 0 — legal under the Δ²+Δ=0 delta relation
   alone — attempting to read/write a forged value at phantom index p−1.
   Assert co-noir **rejects** (the first sorted index must be copy-
   constrained to a genuinely-constrained zero witness, not a free
   `add_variable(0)`). Guards the phase-2 item 2.6 builder work; without the
   pinning gate this test passes-as-vulnerable.
10. **Non-canonical field encodings + trailing data (bb `5f09c55a57`,
    audit findings #2493/#2501/#2513).** A proof/VK field element with value
    ≥ modulus must be **rejected**, not silently reduced (malleability);
    trailing proof bytes must be rejected (subsumes §3.4 and directly
    addresses the Phase 0 finding that co-noir accepts trailing bytes).
    Off-curve points must yield a clean reject, not the ark-ec panic Phase 0
    observed.

## 4. Completeness tests to add
1. **Input diversity per circuit**: today each vector proves one fixed
   witness. Add multiple valid witnesses per circuit (boundary values: 0, max
   field, max-bit-width integers, empty/edge slices, ROM/RAM at capacity) and
   confirm each proves and verifies (co-noir and `bb`).
2. **Circuit-size range**: vectors spanning small → large `log_n` (including
   sizes near the padding boundary `CONST_PROOF_SIZE_LOG_N`) to catch
   off-by-one padding/row errors.
3. **All supported blackboxes exercised** (ch. 06 ✅ column): at least one
   vector each for poseidon2, sha256_compression, blake2s/3, aes128, MSM,
   embedded_curve_add, range, AND/XOR, ROM/RAM, ToRadix, recursion. Prove +
   verify + `bb`-cross-verify. (Guards the co-builder gate layout per
   feature.)

## 5. MPC-specific tests
1. **Plain == MPC bytes**: for each vector, assert the REP3 and Shamir proofs
   equal the plain proof (non-ZK) — already the spirit of the KAT tests;
   make it an explicit plain-vs-MPC equality, not just each-vs-stored-KAT.
2. **Protocol coverage**: run the negative tests (§3) through the MPC provers
   too, not only plain — a soundness gap could be MPC-path-specific.
3. **Share privacy (property test)**: for a sample of witnesses, check that any
   single party's transcript/view is independent of the secret (e.g. the
   distribution of one party's shares is uniform / unchanged when the secret
   changes). This is a sanity check on the sharing, not a full simulation
   proof, but it catches gross leakage regressions.
4. **REP3↔Shamir translation**: translated witnesses/proving-keys produce the
   same proof as native (exercises `translate-witness`/`translate-proving-key`).
5. **Determinism**: the same witness + shares yields identical proof bytes
   across parties and across runs (justifies the orchestrator's byte-equality
   recombination check, ch. 08).

## 6. Property / differential / fuzz coverage
1. **Differential vs bb (the strongest generic test)**: a harness that takes a
   circuit + random valid witness, proves with co-noir and with `bb`, and
   asserts byte-equality (non-ZK) or mutual verification (ZK). Run over many
   random witnesses per circuit. This turns bb into a live differential oracle
   and would catch essentially any parity regression automatically.
2. **Witness-extension differential**: run the ACVM/Brillig on random inputs in
   co-acvm vs stock Noir's ACVM (via nargo) and assert identical extended
   witnesses — catches opcode-semantics divergence (the co-acvm/co-brillig
   mirror risk from ch. 06).
3. **Structured proof fuzz**: mutate valid proofs (bit flips, truncation,
   field-element boundary values ≥ p) and assert reject — an automated
   generalization of §3.1/§3.4.

## 7. How this plugs into the phases
- **Phase 0** (validate at pin): stand up §2.1 (live cross-verify) and a first
  cut of §3 (tampered proof/public-input/VK reject) — this is what makes
  "the pipeline works" a *trustworthy* claim, not just "it ran".
- **Phase 2** (sync): the §2 parity matrix + §3 negatives are the green-up
  gate (ch. 11 §6, ch. 12 Prompt D). VK-byte parity (§2.2) is essential
  because the trace-offset change rewrites every VK.
- **Phase 4** (drift): the §6.1 differential harness against nightly `bb` is
  the drift detector.
- Every future sync re-runs the whole matrix; nothing ships red (ch. 12 §1).

## 8. Priority order (build these first)
1. Live 4-way cross-verify vs `bb` (§2.1) + VK-byte parity (§2.2) — highest
   assurance per unit effort; makes bb the oracle.
2. Core negative tests (§3.1–3.4) — soundness is currently ~untested.
3. Implicit-constraint soundness test (§3.6) — the specific place co-noir
   could under-constrain vs bb.
4. Differential-vs-bb harness (§6.1) — automates parity forever.
5. Input-diversity/completeness (§4) and MPC-consistency (§5).
6. Witness-extension differential + opcode edge cases (§6.2, §3.7).

## 9. MANDATORY security regressions (added 2026-07-08 from ch. 03 §6 rationale mining)

Two of the ported bb changes are embargoed soundness fixes. Byte-parity
alone does NOT prove we inherited the fix — these two tests must exist and
pass before Phase 2 is called done (they join §8's priority list at rank 2):

1. **SSIPA kernel-forgery regression** (from bb `shplemini.test.cpp`, PR
   #44): simulate the malicious prover that perturbs A by the
   one-dimensional kernel (δ at X=1, −δ/(g−1) on the rest of H, matching
   δ_s) and ignores the prover-side fail-fast; co-noir's verifier MUST
   reject. Specifically verifies the untransmitted A(1)=0 claim rides the
   Shplemini/Shplonk batched opening — the local identity check alone
   accepts the forgery (bb's README says so explicitly).
2. **ROM/RAM field-wrap regression** (from bb `rom_ram.test.cpp`, PR #29):
   build a circuit whose first sorted index witness is forced to p−1
   (start the chain at −1, wrap to 0); proving must fail or the proof must
   be rejected. Verifies the first sorted index is copy-constrained to a
   genuinely-fixed zero witness, not a fresh unconstrained variable.

Plus (audit posture, from `5f09c55a57`): non-canonical field encodings
(≥ modulus) and trailing proof bytes must be REJECTED by co-noir's
deserialization — merges with Phase 0 