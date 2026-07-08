# Chapter 5 — Approach assessment & recommendation

*Written 2026-07-08, based on chapters 01–04. PLAN.md posed: approach 1 =
add co-snarkification to barretenberg (C++); approach 2 = update the Rust
co-noir to match latest UH; or something better.*

## 0. Three premises in PLAN.md that the evidence revised

1. **"Taceo did this over a year ago … very outdated"** → False. Taceo syncs
   co-noir with bb every 1–2 months; the pin is 2026-03-24, ~3.5 months old,
   and compatibility is enforced by byte-level proof KATs in their CI.
2. **"Shards of co-snark proofs recombined into a single co-snark"** → Not a
   thing: the MPC opens each proof element inside the protocol, so every party
   emits the same complete, standard proof. The tooling gap is *upstream* of
   proving (share submission/encryption, orchestration), not downstream.
3. **"The reference implementation is `~/aztec-packages-private`"** → This
   hides a fork split: public aztec-packages is still v5-nightly; the private
   v6 line has exactly **two** private-only UH-breaking commits (full-width FS
   challenges; ROM-via-logup). Taceo cannot see them. "Latest UH" must be
   defined as *public v5 tip* or *private v6 HEAD* — they are different
   targets with different logistics (ch. 03).

## 1. Approach 1 — co-snarkify barretenberg (C++)

What it would actually require:

- **An MPC runtime in C++**: REP3 + Shamir field/point arithmetic, correlated
  randomness, networking, A2B conversions, garbled circuits for bit-heavy ops
  — i.e. reimplement `mpc-core` + `mpc-net` (~years of Taceo's accumulated
  work, incl. subtle, carefully-tuned code), or FFI-bind the Rust crates into
  bb (awkward: sumcheck's inner loops need share ops at fine granularity).
- **Templating bb's prover over a "share driver"**: bb's prover assumes plain
  field elements everywhere. The MPC-ification seam that co-noir expresses as
  the ~60-method `NoirUltraHonkProver` trait would have to be threaded through
  oink, sumcheck, Shplemini, and the circuit builder. That is either (a) an
  invasive rewrite of the battle-tested hot path — exactly what PLAN.md's
  "minimize changes to the proven C++" criterion favors avoiding — or (b) a
  parallel copy of the prover (new files, as PLAN.md hoped), which *is* a
  reimplementation anyway, just in C++ and starting from zero MPC code.
- **The argument inverts.** The proven, extensively-exercised artifact is bb's
  *single-prover* code path. A co-prover is new code in any language. Choosing
  C++ doesn't inherit that maturity; it just discards the one existing,
  tested, KAT-verified MPC implementation. Meanwhile approach 2 leaves the bb
  C++ entirely unmodified — the strongest way to keep its proven code intact.
- **Witness extension would also need porting**: co-acvm/co-brillig (MPC ACVM)
  have no C++ analogue; bb doesn't execute ACIR — Noir's ACVM does (Rust).
  A C++-only strategy still ends up depending on Rust for witness extension,
  or reimplementing the ACVM too.

**Effort estimate: 6–12+ engineer-months to first working proof, high risk.**
**Verdict: reject**, unless there's a strategic reason to own an in-house C++
MPC stack that outweighs ~an order of magnitude more work.

## 2. Approach 2 — bring Rust co-noir up to latest UH

Decomposes cleanly along the fork split (ch. 03):

- **2a. Sync to public v5 tip** — the four consensus deltas (permutation
  subrelation, trace-offset/VK shift, ZK/SSIPA rework, relation reorder) +
  builder gate changes. Mechanical but exacting; the KAT test harness gives a
  crisp definition of done. Estimate: **2–4 engineer-weeks** for someone
  fluent in the codebase (Taceo's historical syncs suggest similar). It is
  also plausible Taceo does this themselves on their normal cadence —
  worth one conversation before spending our time. Everything here is
  public-repo-derivable, so work can be upstreamed to TaceoLabs/co-snarks.
- **2b. Port the two private v6 commits** — small with code access
  (**~1 engineer-week**): full-width challenges are a transcript-core change
  mirrored in `co-noir-common/src/transcript.rs`; ROM-via-logup adds 2
  subrelations + 1 challenge + builder ROM gates. Must live in a **private
  fork** of co-snarks until v6 goes public (licensing: co-noir crates are
  MIT/Apache — forking privately is clean).
- **2c. (Deferred) blackbox gaps** — ECDSA k1/r1, keccak, BigInt remain
  unimplemented in co-noir regardless of sync. Irrelevant for Poseidon2-based
  Aztec private-function circuits; becomes a real workstream (each is weeks,
  in *both* co-builder and co-acvm) only if target circuits need them.

**Verdict: this is the right approach.** It exactly satisfies the PLAN.md
"done" criteria (cross-verifiable proofs, existing tooling reused, tests
exist), minimizes bb changes to zero, and converts the problem from
"build a system" to "track a diff".

## 3. Approach 3 (new) — pin the deployment; prove co-snarks *today*

Do nothing to co-noir: it works **now** against bb `v5.0.0-nightly.20260324`
(that bb tag builds from either repo). A co-snark demo end-to-end — split
witness, 3-party MPC prove, verify with stock `bb verify` — should be runnable
this week. This isn't the end-state (the pin ages; current aztec-nr expects
current bb), but as **phase 0** it validates the whole pipeline, gives us
benchmarks, and de-risks everything downstream. Recommended as the immediate
next step regardless of the chosen end-state.

## 4. Recommended strategy (phased — UPDATED 2026-07-08 after Mike's decisions)

*(Original proposal kept in git-less history via PROGRESS.md; this reflects
the decided state. PLAN.md is authoritative for phase status.)*

1. **Phase 0 (days): prove the pipeline at the pin.** Run co-noir's 3-party
   examples + KAT tests; build bb at the pin; cross-verify both directions
   (Rust proof ↔ C++ verifier and vice versa); measure timings on real
   circuits. Educates us and produces the benchmark baseline.
2. **Phase 1: decisions — DONE.** Target `origin/v5-next` (≡ public v5 tip);
   no Taceo engagement for now; ZK flavor default (HONK_ZK=6, ch. 04 §5);
   3-party semi-honest REP3 accepted; **strict no-push rule** (all work
   local; content derives from the private repo).
3. **Phase 2 (2–4 wks): sync co-noir to v5-next** — local only, using
   Taceo's own compare.sh/compile.sh harness as the oracle (ch. 02 §6).
4. **Phase 3: contingency only** — the two v6-line commits, activated only
   if the target moves to the v6 line.
5. **Phase 4: maintenance machinery** — local CI/scripts that run co-noir
   KATs against bb nightlies so UH-breaking changes are *detected on merge*;
   a "co-snark impact" watchlist of the ~6 proof-format-defining bb dirs.
6. **Phase 5: Aztec integration** — modernize the monty-hall-aztec pattern
   (orchestrator + nodes + capsule-delivered proofs + MPC-nullifiable notes)
   onto current aztec-nr; build the user→MPC share-submission/encryption
   channel; and the **PXE secret-sharer module** (a key project output per
   Mike: generate a co-snark from PXE secrets/notes/secret keys — paths and
   recommendation in ch. 09).

## 5. Mapping to PLAN.md's "done" definition

| PLAN.md criterion | How the strategy meets it |
|---|---|
| Co-snark over simple Noir circuits | Phase 0 (immediately, at pin); phases 2–3 (at latest UH) |
| Verifies against latest UH verifier; valid+invalid inputs | KAT byte-equality + cross-verification + negative tests (Taceo's harness already has the structure; extend with invalid-proof cases) |
| Blackbox difficulty assessed | Ch. 02 §4 table; ECDSA/keccak are the gaps; weeks each, deferred until needed |
| Wrapper tooling reused | Entirely — approach 2 changes only prover internals behind the driver traits |
| monty-hall/PXE pattern understood | Ch. 04; modernization is phase 5 |
| Speed to "working" | Days (pin) / ~a month (public tip) / +1 week (private v6) |
| Minimal bb changes / keep bb's proven C++ intact | Zero bb changes (only additive CI in phase 4) |
| Ongoing maintenance | Phase 4 machinery + Taceo relationship |

## 6. Open questions for Mike — ANSWERED 2026-07-08

1. **Target line** → `origin/v5-next` of aztec-packages-private. Verified
   equal to public tag `v5.0.0-nightly.20260708` in its barretenberg tree, and
   the two v6-only breaking commits are NOT in it. Consequence: the effective
   sync gap is (A) only; the v6 port (phase 3) is a contingency.
   **⛔ Binding rule: no code/docs pushed anywhere public; no PRs to Taceo;
   all work local** (content derives from the private repo).
2. **Taceo relationship** → not engaging for now; possibly later. (Their sync
   process/tooling investigated — see PROGRESS.md / ch. 02 addendum.)
3. **ZK flavor** → clarified: Taceo DOES implement the ZK flavors (UltraZK/
   UltraKeccakZK equivalents, `ZeroKnowledge::Yes`, KAT-tested via verifier
   round-trip). The open sub-question is whether Aztec's in-contract
   `verify_proof` path (aztec-nr on v5-next) verifies non-ZK, ZK, or both —
   investigation recorded in ch. 06 / PROGRESS.md. Requirement added to the
   definition of done: **the co-snark proof must be verifiable by an Aztec
   smart contract (private function, recursive UH verification).**
4. **Blackbox priority** → maintain a full support/difficulty matrix
   (ch. 06); implement gaps only when a target circuit needs them.
5. **Threat model** → 3-party honest-majority semi-honest REP3 accepted for now.
