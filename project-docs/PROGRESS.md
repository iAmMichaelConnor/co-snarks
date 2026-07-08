# Progress log

Append-only, newest session last. Each entry: date, what was done, decisions,
open questions, next steps.

## Session 1 — 2026-07-08

**Done:**
- Read PLAN.md; established repo ground truth (both repos current: co-snarks
  @ 2026-07-06 upstream main; aztec-packages-private @ 2026-07-07, v6-nightly era).
- Deep exploration (4 parallel research passes + direct verification) of:
  co-noir proving stack, co-snarks wrapper tooling, monty-hall-aztec, and the
  bb UltraHonk diff v5.0.0-nightly.20260324 → HEAD.
- Wrote chapters 01 (co-SNARK primer), 02 (co-snarks repo map),
  04 (monty-hall/Aztec integration). Chapter 03 (bb diff) and 05 (assessment)
  in progress.

**Key discoveries (change the shape of the project):**
- PLAN.md's premise "Rust UH is very outdated (>1 year)" is FALSE: Taceo syncs
  co-noir to bb every 1–2 months; current pin is bb v5.0.0-nightly.20260324
  (~3.5 months behind HEAD, spanning a v5→v6 major bump).
- bb-compat is enforced by byte-level proof KAT tests in-tree — a sync has a
  crisp, mechanically checkable definition of done.
- No "proof shard recombination" tooling is needed — parties emit identical
  complete proofs (opens happen inside the MPC).
- co-noir blackbox gaps: ECDSA, keccak, BigInt, Schnorr (witext + builder).
- monty-hall-aztec is the reference integration pattern but is itself ~1 year
  stale and unfinished (on-chain submission stubbed; various rough edges).

- Completed bb diff analysis (ch. 03): "latest UH" splits at the public/private
  fork boundary. Public v5 pin→tip = 4 consensus-breaking changes + builder
  changes (MEDIUM, Taceo-visible). Private v6 = exactly 2 breaking commits
  (full-width FS challenges `a69ffdf8a1`, ROM-via-logup `d3e42f9d3a`) —
  SMALL but invisible to Taceo. Spot-verified in working tree.
- Wrote ch. 05 assessment: **recommend approach 2** (update Rust co-noir),
  phased: 0) validate at pin now, 1) decisions/Taceo, 2) public sync (2–4wk),
  3) private port (~1wk), 4) CI anti-drift, 5) Aztec/PXE integration.
  Approach 1 (C++ co-snarkify bb) rejected — see ch. 05 §1.
- Appended the actionable phased plan to PLAN.md (checkboxes = live status).
- Saved cross-session memory (project + user profile).

**Open questions for Mike:** `05-approach-assessment.md` §6 — target line
(public v5 vs private v6), Taceo engagement, ZK-flavor requirement, blackbox
priority, threat-model acceptance of 3-party semi-honest REP3.

**Next steps:** Phase 0 (run pipeline at pin: tests, 3-party demo, bb
cross-verify, benchmarks) — can start immediately; Phase 1 blocked on Mike.

## Session 1 (continued) — 2026-07-08, Mike's decisions

**Decisions received** (recorded in PLAN.md "Decisions" + ch. 05 §6):
target = `origin/v5-next` (private repo); **⛔ strict no-push/no-PR
confidentiality rule added everywhere**; no Taceo contact for now; 3-party
semi-honest REP3 accepted; blackbox matrix to be documented (ch. 06).

**Verified this session:** `origin/v5-next`'s barretenberg tree is identical
to public tag `v5.0.0-nightly.20260708`, and neither v6-only breaking commit
(`a69ffdf8a1`, `d3e42f9d3a`) is in it → Phase 3 demoted to contingency; the
whole sync gap is the four (A) changes + builder deltas of ch. 03 §2.

**New requirement added to definition of done:** the co-snark proof must be
verifiable inside an Aztec smart contract private function (aztec-nr
recursive UH verification path).

**Done:** garbled-circuits/A2B explainer added to ch. 01 §2.3 (grounded in
`mpc-core/src/protocols/rep3/yao/`, `conversion.rs`, `A2BType`).

**Research passes completed:** (a) Taceo sync process → ch. 02 §6 (manual
port + scripted compare.sh oracle; big sync = 2 people × 16 days); (b)
aztec-nr verify_proof on v5-next → ch. 04 §5 (HONK=0 / HONK_ZK=6 both work
in private functions; poseidon2 mandatory; 410/458 proof + 115 VK fields;
inner proof never published); (c) blackbox matrix → ch. 06 (keccak=medium,
ECDSA=hard, Shamir has no binary layer, brillig blackboxes = ToRadix only).

**Docs deepened on Mike's request (2026-07-08):** ch. 01 rewritten at
maths-degree depth (REP3 mult derivation, DN07, mask-and-open, Yao detail,
co-snark security statement); new ch. 07 (UltraHonk from Plonk + per-stage
MPC mapping); new ch. 08 (data-flow diagrams D1–D7); ch. 06 unconstrained
caveat rewritten in plain language; ch. 02 §5.4 explains the missing share
submission layer = Taceo's commercial TACEO:Proof product (live since
2025-07), not part of the open-source repo.

**PLAN updates:** decision 3 (ZK) resolved — default ZK flavor (HONK_ZK=6),
non-ZK acceptable for self-delegation; phase 1 fully done.

**Primer sourcing (Mike's request):** ch. 01 now cites and incorporates the
prominent public explainers — Ozdemir–Boneh (eprint 2021/1530), Taceo's
Collaborative SNARKs Primer, their honest-majority-efficiency post (REP3 ≈2×
CPU, Shamir ≈1×, constant-communication Groth16 trick — integrated into §2.4
as the "defer resharing through linear postprocessing" principle), the PSS
and TACEO:Proof materials. New §7 "Sources & further reading" lists them and
marks where our primer goes beyond public sources.

**Next steps:** Phase 0 (build + tests + 3-party demo + bb cross-verify at
the pin + benchmarks) is now the frontier and is unblocked.

## Session 1 (continued further) — 2026-07-08, PXE workstream + critique

- **New decision 6 recorded** (PLAN.md): key output = co-snarks from PXE
  secrets; lightest-weight extraction preferred; `~/ap-next` (public
  aztec-packages v5-next, current) is where PXE dev continues.
- **Ch. 04 §6 added**: design critique of monty-hall-aztec (hackathon
  shortcuts: non-ZK in PSS, positional witness indices, single-tenant
  destructive state, placeholder key management, version-frozen constants…)
  plus what it gets right.
- **Ch. 09 written** (PXE Secret Sharer). Headline findings, verified:
  PXE on v5-next is an in-process object (no RPC layer);
  `pxe.getAccountSecretKeys` already exists as the sanctioned key-export
  primitive (account migration); notes have no API at all — full plaintext
  preimages (incl. randomness) sit in NoteStore; oracle path is app-siloed
  by design; spending/signing keys are NOT in the PXE. Recommendation:
  wallet-side TS module = Path A (raw PXE key API) + Path B (PXE store
  classes over the same KV store, the TXE-precedented pattern) with
  capability-manifest-shaped consent; REP3 split via WASM-compiled
  co-noir-types. Path D (tiny upstream note-export API) kept in back pocket.
- **Doc-currency pass**: ch. 05 §4 aligned with decisions; PLAN phase 5.0
  added; README index/key-facts refreshed.
- **Open questions for Mike (ch. 09 §5):** Q1 do target circuits need
  signing keys or only privacy keys + notes? Q2 v1 deployment: CLI/server
  wallet or browser? Q3 is a self-controlled wallet acceptable for v1?

## Session 1 (continued) — 2026-07-08, architecture + secret-sharer scope

- **Q1 answered by Mike**: share ALL secret types (privacy keys, signing/
  spending keys, authwits, nonces, note preimages, tagging secrets) in a tidy
  unified way. Recorded in PLAN decision 6 / phase 5.0.
- **Ch. 10 written** (PXE/wallet architecture, teach-from-scratch): the v5-next
  client stack is not what older docs describe. Key facts (code-verified):
  the PXE is an in-process library object inside the wallet (no PXE server;
  `createPXEClient`/`PXESchema` gone); there are TWO separate KV databases —
  `pxe_data` (PXE: privacy keys + notes + tagging) and a separate WalletDB
  (wallet: root secret, **signing key**, authwits). Signing keys/authwits live
  in the wallet/account layer, NOT the PXE (removed from PXE by commit
  `5cd500e043e`). Diagrams: layer cake, store containment, tx flow. Secret→
  location table included.
- **Consequence for the sharer (ch. 09/10 §7):** must be a *layered* extractor
  touching three seams — PXE KeyStore (privacy keys), PXE note/tagging stores
  (notes/nonces/tagging), and the wallet/account layer via
  `getAuthWitnessProvider` (signing keys/authwits; an MPC threshold signer is
  the direct analogue of the existing SSH-agent signer variant).
- **Stability note:** accounts/entrypoints/aztec.js-account layers are stable
  (safe signer-interposition target); PXE KeyStore + tagging/note stores are
  churning (189 pxe commits since April; the "keys out of PXE" refactor) — pin
  and re-verify on every Aztec bump.

**Wrote ch. 11–13:** ch. 11 deep phase-2 sync work plan (file-by-file: the
four proof-format changes → co-noir files, builder/DSL gate changes, KAT
regen, green-up order, effort/risk; grounded by spot-checking co-noir files —
e.g. `permutation_relation.rs` NUM_RELATIONS=2 must become 3); ch. 12
reusable sync runbook + 5 copy-paste agent prompts + gotcha checklist +
unsupported-feature guardrails + drift detection; ch. 13 parity + soundness
(negative) + completeness + MPC-consistency + differential-vs-bb test plan
(closes the current gap: negatives ~untested, ZK only self-verified, no
live-bb cross-check, no VK-byte parity).

**Docs reorganized** into the current chapter set; the plan/docs/memory are
the authoritative record. (Mike's immutable PLAN.md top text is untouched.)

**Q2/Q3 still open for Mike** (ch. 09 §5): v1 deployment target (CLI/server vs
browser wallet); self-controlled wallet acceptable for v1?

**Next steps:** Phase 0 remains the unblocked build frontier (ch. 11 §1 +
ch. 13 §7 give the exact first steps). Chapters 01–13 complete.

## Session 2 — 2026-07-08 (Phase 0 execution)

**Done (full command record with failures/root-causes: ch. 14, new):**
- Pins re-verified: `origin/v5-next` moved same-day (→ `d5cfa2a32f`) but its
  `barretenberg/` + `noir/` trees are UNCHANGED — still ≡ public
  `v5.0.0-nightly.20260708`. Gap analysis (ch. 03/11) remains valid.
- 0.1 build: needs **rustc 1.90** (workspace `rust-version`; no
  rust-toolchain.toml → default 1.85 fails). `rustup override set 1.90`,
  build green in 1m17s. Test suite (`cargo test -p tests --release`)
  FINAL: **603 passed / 0 failed** (circom 346, mpc 163, noir 94 incl. the
  bb-KAT proof byte-equality tests; 118 default-skipped slow tests).
- 0.2 3-party REP3 demo ✅: proof verified; **all 3 parties' proofs
  byte-identical** (empirically confirms no-recombination); ~752 ms/party
  proving, 3.3 ms verify (poseidon/keccak/non-ZK).
- 0.3 cross-verify vs real bb ✅ COMPLETE: installed nargo beta.20 (noirup)
  + bb 5.0.0-nightly.20260324 (direct release tarball — old bbup uses wrong
  URL shape for v5 nightly tags, "not in gzip format"). `compare_mpc.sh`
  FINAL: **29/29 circuits, 0 errors** — proof-byte equality + 4-way bb
  cross-verify, poseidon2+keccak, ZK+non-ZK. Slow set (aes128,
  sha256_compression, recursion_zk) not run (TEST_SLOWER_CIRCUITS=1).
- 0.4 soundness spot-checks ✅: isolated rig (plaindriver), 7 tamper cases ×
  {co-noir, bb} verifiers — **no false accepts**. Artifact sizes confirm
  410-field proof / 115-field VK (ch. 04 §5). **Two divergences found**:
  (1) co-noir accepts trailing proof bytes, bb rejects (predicted ch. 13
  §3.4); (2) off-curve point in proof/VK → ark-ec `is_on_curve` PANIC
  instead of clean reject (DoS-robustness). Both → Phase 2 fix list.
- 0.5 partial: first data points (MPC ≈10× plain bb, small circuit,
  loopback — ch. 14 §6.2). Full matrix TODO.
- Docs: **ch. 14** (Phase 0 command log + doc-improvement notes, per Mike's
  request this session: record ALL commands incl. failures, in order);
  README index updated; local ✏️ edits to `co-noir/co-noir/Readme.md`
  (Rust 1.90, examples-cwd requirement, bbup fallback URL). PLAN Phase 0
  checkboxes updated.

**Env for future sessions:** rustc 1.90 (override set in repo),
nargo 1.0.0-beta.20, bb 5.0.0-nightly.20260324 at `~/.bb/bb`.

**Phase 0 verdict: PASSED.** The pipeline at the pin is fully validated —
603/603 tests, 29/29 bb cross-verified circuits, sound under tampering.

**Next steps:** (1) finish 0.5 benchmark matrix (incl. Shamir + the slow
circuit set; ideally with simulated WAN latency); (2) Phase 2 sync per
ch. 11, folding in the two 0.4 findings (trailing-bytes check, fallible
point deserialization); Q2/Q3 (ch. 09 §5) still open for Mike.

## Session 2 addendum — 2026-07-08 (ops post-mortem + thread-cap question)

- **Post-mortem recorded (ch. 14 §11)**: the "compare_mpc still running"
  status I reported for ~50 min was false — the job finished at 14:31; my
  `pgrep -f` check was matching its own shell. Ch. 14 §11 now consolidates
  all five session-ops gotchas (pgrep self-match, pipe-masked exit codes,
  cwd resets, background-task timeout cap, cleanup.sh races) so future
  sessions don't repeat them.
- **Mike's thread-cap question answered by measurement (ch. 14 §6.3)**:
  raising RAYON_NUM_THREADS from nproc/3 to 50%/party would OVERSUBSCRIBE
  (3 parties × 50% = 150%) and measures ~23% SLOWER; all-cores-each is +80%.
  Small circuits are fastest at ~16 threads/party. Script default kept at
  nproc/3, now env-overridable (✏️ local edit, ch. 14 §10.2). The run_full_*
  demo scripts set no cap (each party grabs all cores — 3× oversubscribed);
  that explains demo 752 ms vs 520 ms at nproc/3. Re-measure at larger
  circuit sizes during 0.5.

## Session 2 (continued) — 2026-07-08, Phase 2 started: pre-analysis + steps ①②

**Pre-analysis (3 parallel code-verification agents; ch. 14 §13):** plan
approach confirmed; 3 real gaps found+fixed in docs — (1) CRITICAL:
EntityId/get_all reorder missed (proof sumcheck-eval order + VK commitment
order both change; new work item 2.5a); (2) ACIR MemOp overhaul missing
from the beta.22 bump plan; (3) third relation mirror
(honk_verifier/verifier_relations) under-specified. Noir target confirmed
beta.22. PAIRING_POINTS_SIZE corrected 16→8. Committed a1b7fa15.

**Working set pinned** (PLAN.md Phase 2 header): branch mc/update-co-noir
(pushurl disabled), diff range v5.0.0-nightly.20260324..20260708,
oracles ~/.bb/bb (old) + ~/.bb-target/bb (rc.2 ≡ v5-next UH). Decision 6a
recorded: implementation independence (no C++ structure copying; enables
differential fuzzing; KAT boundary is the only coupling).

**Step ① (beta.22 bump) DONE — commit 4e7abb95:** real breaking change was
ark 0.5→0.6 (dep-graph split; predicted type errors were cascade noise);
2 Taceo registry crates vendored with ark-0.6; MemOp → MemOpKind;
EC (0,0)-sentinel with MPC infinity detection (2 eq + 1 mult shared);
new upstream `predicate` field handled. Gates: check/fmt/clippy(-D,
full tree, after fixing 2 pre-existing mpc-net lints — baseline was
clippy-dirty under rustc 1.90, fmt-clean)/circom+mpc suites 509/509/
4 e2e smokes incl. ram + embedded_curve_add. Per-commit gate standard set
= Taceo CI bar (fmt + clippy -D + compile + targeted tests).

**Step ② (vectors+KATs at target) DONE — commit e70252e1:** 32 vectors
recompiled (nargo beta.22); 4 proof KATs regenerated with target bb.
**Lengths at target pin: 410/458/115 — identical to old pin** (settles the
ZK-length question; sync changes byte content/order only). Noir proof
tests now red BY DESIGN until 2.2–2.6.

**Ops lessons recorded** (ch. 14 §11): pgrep self-match; watcher timeout
< slowest job → silent death (~6 min dead time, Mike caught it);
dep-bump → suspect duplicated transitive deps (`cargo tree -d`) before
believing error text.

**Next steps:** work item 2.2 (perm 3rd subrelation, THREE mirrors:
ultrahonk/co-ultrahonk/verifier_relations) in lockstep with 2.5+2.5a
(relation-tuple + entity reorders — same bb commit c075fc182e; TS flavor
specs at scripts/flavor-codegen/src/flavors/*.ts are the cleanest
reference); then 2.4+2.6 (trace offset + ZK/SSIPA, entangled); then 2.3
builder/DSL gates; green-up per ch. 11 §6 with plain poseidon KAT first.
Shamir CRAND_PAIRS_FACTOR re-derivation needed if the new subrelation
adds MPC mults (co_ultra_prover.rs:163-202).

## Session 2 (continued) — 2026-07-08 evening — HANDOFF (token pause; step ④ agent in flight)

### Committed state (branch mc/update-co-noir, all LOCAL, never pushed)
```
5bc7b050 docs: bb-spec-audit soundness lens → ch.13/11/PLAN
9244b8d1 docs: mine WHY behind UH changes + mandatory security-regression tests
5bc7b05..e70252e1 e70252e1 test: regenerate vectors (beta.22) + bb KATs at target pin (step ②)
4e7abb95 feat: Noir beta.22 bump / ark 0.6 / MemOp / (0,0) sentinel (step ①)
1a13fcdc feat: perm 3rd subrelation + relation/entity reorder (step ③)
a1b7fa15 docs: Phase 2 pre-analysis
74ab4cc3 docs: Phase 0 record + chapters 01–14
```
Phase 0 DONE; Phase 2 steps ①②③ DONE and committed. Green-up (2.7) not reached.

### ⚠ UNCOMMITTED work in the tree = step ④ (items 2.4 trace-offset + 2.6 ZK/SSIPA)
A background coding agent (Fable) is implementing 2.4+2.6. At pause it had:
done the plain prover (SSIPA 5th claim A(1)=0 untransmitted; disabled-rows
moved to trace top; honest virtual-round univariates replacing zero-padding),
and was mid-way through the **co-ultrahonk MPC prover**; verifiers + the gate
battery (incl. the KAT milestone) NOT yet done. `git status` shows ~22 modified
source files under co-noir/{ultrahonk,co-ultrahonk,co-builder,co-noir-common}
plus 4 modified `test_vectors/noir/*/kat/*` files.
- Agent transcript (its full actions + final report if it finished):
  `/tmp/claude-1011/-mnt-user-data-mike-co-snarks/08047b1f-880c-4cbd-984a-5ca7935f41da/tasks/a8dec8195a8170913.output`
  (JSONL — read the LAST assistant message for the report; do NOT cat whole).

### RECOVERY CHECKLIST for the next session (do in order)
1. `git -C ~/co-snarks status -s` and `git branch --show-current` (expect
   mc/update-co-noir). `git log --oneline -1` should be 5bc7b050.
2. Read the agent transcript's final message. Three cases:
   a. **Agent finished cleanly** (report present, gates run): review the diff
      (`git diff`), independently re-run the step-④ gate (cargo check
      --workspace; fmt+clippy touched crates; plaindriver poseidon self-verify
      non-ZK+ZK; **the KAT milestone** `cargo test -p tests --release --test
      noir -- plain`; ZK bb cross-verify with ~/.bb-target/bb; REP3 demo), then
      commit as step ④ + append ch. 14 §17 result.
   b. **Agent killed mid-flight** (no report; tree likely does NOT compile —
      MPC prover / verifiers half-ported): either finish the remaining files
      by hand using ch. 11 §2.4/§2.5/§2.6 + bb NEW-tag source, OR
      `git checkout -- <the 22 co-noir source files>` to discard and re-run the
      step-④ agent fresh (prompt is in this session's history / ch. 14 §17).
      Do NOT commit a non-compiling tree.
   c. **Still running**: wait for its notification; then case (a).
3. **KAT files caution**: `test_vectors/noir/*/kat/*_proof_with_*` show as
   modified. They MUST remain the target-bb bytes committed in e70252e1 (the
   oracle), NOT be overwritten by co-noir's own output. Before committing step
   ④, verify: `git diff e70252e1 -- test_vectors/noir/*/kat` should be empty,
   OR the change must be a deliberate, bb-regenerated update — confirm with
   ~/.bb-target/bb, never accept co-noir-generated KATs.
4. Reference bb binaries: OLD pin `~/.bb/bb` (5.0.0-nightly.20260324); TARGET
   `~/.bb-target/bb` (5.0.0-rc.2 ≡ v5-next UH). nargo = beta.22.
5. Env: rustc 1.90 override in ~/co-snarks; RAYON cap = 80% of cores
   (nproc*8/30 per party); watcher discipline memory applies.

### After step ④: remaining Phase 2 = item 2.3 (builder/DSL gates: ROM/RAM
### index-pinning security fix ch.13 §3a#9, EC gate-count parity TODO from
### step ①), then 2.7 green-up (full suite + compare_mpc.sh both oracles +
### the 3 mandatory security-regression tests, ch. 13 §3a).

## Session 3 — 2026-07-08 night (recovery + step ④ landed)

**Recovery from the token pause** (per the handoff checklist): the step-④
agent had died at its session limit at 19:15 with the tree compiling and
ONE edit unfired. Full forensics from its transcript, then completed and
gated the step. Committed `571c1305` (36 files, +628/−1095).

**⚠ Key discovery (agent's, verified independently): rc.2 is NOT a valid
oracle.** `~/.bb-target/bb` (prebuilt 5.0.0-rc.2) emits OLD entity-order
VKs — the release binary predates the entity reorder even though the rc.2
source tree doesn't. The agent built bb FROM SOURCE at the true target tag
v5.0.0-nightly.20260708; preserved at `~/.bb-target-src/bb` (+PROVENANCE).
Step-② KATs were regenerated with it (this session re-verified all 4
byte-identical against fresh proofs). PLAN pinned-set corrected; ch. 12
gotcha added; ch. 14 §17.1 records the full story.

**Step ④ completion (this session):**
- Applied the agent's unfired Shamir randomness-accounting edit after
  verifying every term against the actual consumers, and fixed a real
  omission: 8 mask_polynomial sites × NUM_MASKED_ROWS(3) = 24 ZK draws it
  undercounted. Caveat noted: 3-party Shamir tests bypass the accounting
  (on-the-fly path) — only ≥4-party runs exercise it.
- Gates: check/fmt/clippy(-D) 0 warnings; noir suite **94/0** (incl. THE
  MILESTONE — plain KAT byte-equality vs true-target bb, both circuits ×
  both hashers); **ZK bidirectional cross-verify vs source-built bb PASS**
  (our proof → bb verifier w/ both VKs; bb proof → our verifier); VK
  byte-identical; proof sizes 410 non-ZK / 458 ZK ✓.

**Phase 2 status: 2.1–2.5a DONE.** Remaining: 2.6 builder residue (ROM/RAM
sorted-index pinning soundness fix; EC gate-count parity; recursion size
assert) and 2.7 green-up (example suite; compare_mpc.sh needs a
~/.bb-target-src/bb slot; ch. 13 §3a security regressions).

**Mike's steer this session: don't overdo testing — prioritize feature
progress.** Testing footprint kept to the 39 s suite + seconds-fast ZK
cross-verify; heavy compare_mpc.sh sweep deferred to 2.7.

## Session 3 (continued) — 2026-07-08 night: item 2.6 landed → Phase 2 code-complete

**2.6 builder residue DONE — commit 5ac55600** (full record ch. 14 §19):
- ROM/RAM sorted-chain pinning (bb 1f7ed2ea79 soundness fix: index-delta
  roots {0,−1} allowed a p−1 chain start → forged reads/writes; pinned
  first index to zero_idx in ROM+RAM public+MPC-shared paths, last ROM
  index to constant N−1).
- Two EXTRA proof-breaking changes found by parity-testing beyond the KAT
  circuits: lookup table_index now starts at 1 (logup beta³ guarantee) and
  SHA-256 CH-L2 tables are 10-bit + w[0] range constraint (both bb
  soundness/audit fixes). uint multitable slot count mirrored
  (byte-neutral). Recursion proof-size assert + compile-time 410/458/115
  invariants added. secp256k1/r1 tables not ported (ECDSA unimplemented).
- Parity vs source-built target bb, all VK+proof byte-identical: ram,
  rom_shared, embedded_curve_add, bb_sha256_compression, blackbox_and,
  blackbox_xor, get_bytes. Suite 94/0, clippy 0 warnings.
- Ops: repeated the §11 pipe-masking gotcha (silent /dev/null failures
  looked like parity diffs); examples vectors are largely still
  beta.20-compiled — 2.7 must recompile the whole set (serde error
  "invalid type: integer 11" = beta.20 artifact).

**Phase 2 status: 2.1–2.6 ALL DONE. Remaining: 2.7 green-up only**
(examples recompile + compare*.sh with ~/.bb-target-src/bb slot + ch. 13
§3a security regressions incl. mirroring bb's Rom/RamMaliciousFieldWrap +
slow circuit set).
