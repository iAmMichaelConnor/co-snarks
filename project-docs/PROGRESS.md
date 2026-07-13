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
5bc7b050 docs: soundness-claim lens → ch.13/11/PLAN
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
  roots {0,−1} allowed a p−1 chain start → reads/writes at an index that
  wasn't genuinely constrained; pinned first index to zero_idx in
  ROM+RAM public+MPC-shared paths, last ROM
  index to constant N−1).
- Two EXTRA proof-breaking changes found by parity-testing beyond the KAT
  circuits: lookup table_index now starts at 1 (logup beta³ guarantee) and
  SHA-256 CH-L2 tables are 10-bit + w[0] range constraint (both bb
  soundness fixes). uint multitable slot count mirrored
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

## Session 3 (continued) — 2026-07-08 late — ⚠ RECOVERY STATE (multi-branch, mid-flight)

**Read this first if the session was interrupted/disconnected.** Work is split
across 4 branches in 4 git worktrees (parallel agents). Nothing is pushed
(confidentiality rule). Recovery anchor + merge plan below.

### Backup anchor (recover-from-anything)
- Tag `backup/phase2-code-complete-6c528309` → commit `6c528309` = Phase-2
  code-complete (items 2.1–2.6 done). `git reset --hard
  backup/phase2-code-complete-6c528309` restores that state. Tags are immune
  to branch ops.

### Branches + worktrees (all local, never pushed)
- `mc/update-co-noir` @ `6c528309` — MAIN working branch, checked out in the
  main worktree `~/co-snarks`. Has UNCOMMITTED sweep changes (script pins):
  `co-noir/co-noir/Readme.md`, `examples/{compare,compare_mpc,compile}.sh`,
  `test_vectors/noir/compile.sh`. These are legit 2.7 artifacts — commit them
  before merging. This is the merge TARGET.
- `mc/secreg-27` @ `bac2fe03` — worktree `.claude/worktrees/secreg27`.
  Verifier hardening + security-regression tests (ch.13 §3a). 4 commits on
  6c528309: `a7621aa4` (off-curve + trailing-bytes fix + tests), `e713391d`
  (ROM/RAM field-wrap tests), `bac2fe03` (ZK tamper tests). Touches only
  co-builder/co-noir-common/ultrahonk/tests — DISJOINT from docs.
- `mc/docs-27` @ `fea0f8a6` — worktree `.claude/worktrees/docs27`. Docs:
  ch.11 AS-BUILT, README refresh, NEW ch.15 improvement backlog (37 items),
  ch.13/ch.15 §3a status reconciliation, this recovery note. Commits
  `737db8ee`, `fea0f8a6`. Touches PLAN.md + project-docs/* only.
- `mc/recgen-27` @ `6c528309` — worktree `.claude/worktrees/recgen27`. A
  background Sonnet agent is regenerating recursion/recursion_zk inner-proof
  vectors (see task #8) to fix the one 2.7 failure. May have uncommitted
  Prover.toml + target/ changes; read its report before merging.
- (ignore `…/baseline-lint` detached worktree — unrelated, from an old session.)

### Merge plan (execute once both background agents finish; all conflict-free —
### verified disjoint file sets + `git merge-tree` shows no conflicts)
1. In the main worktree, commit the sweep's uncommitted script pins on
   `mc/update-co-noir`.
2. `git merge mc/secreg-27` then `git merge mc/docs-27` (fast/clean).
3. Read the recgen agent report; if recursion is fixed, merge `mc/recgen-27`
   (regenerated Prover.toml). If it found a real code issue, do NOT merge —
   see task #8.
4. `git worktree remove` the three side worktrees after merge.
5. DO NOT merge into `mc/update-co-noir` while the sweep agent is still
   running there (it runs cargo test in that tree) — wait for its completion
   notification.

### Background agents in flight (outputs are JSONL under
### `/tmp/claude-1011/-mnt-user-data-mike-co-snarks/<session>/tasks/`)
- SWEEP (2.7 parity): running in main tree; last seen mid cargo-test-suite.
  Result so far: ALL non-recursion circuits pass plain + MPC vs
  `~/.bb-target-src/bb`; only recursion/recursion_zk fail (stale vectors).
  Logs: `scratchpad/sweep27/{compare_plain,compare_mpc,cargo_tests}.log`.
- RECGEN (task #8): regenerating recursion vectors; verdict pending
  (staleness-fixed vs a genuine recursion-verifier issue).

### Oracle reminder
THE bb oracle = `~/.bb-target-src/bb` (source-built at v5.0.0-nightly.20260708;
`--version` prints zeros — expected). NOT `~/.bb-target/bb` (rc.2, wrong).

### Open tasks (harness task list): #7 merge+reconcile, #8 recursion regen.
### Deferred: SSIPA A(1)=0 kernel-perturbation test (ch.13 §3a#8). Open: non-canonical
### (≥-modulus) field-encoding rejection (ch.15 §1.3).

## Session 3 (continued) — 2026-07-08 — MERGED secreg-27 + docs-27 into mc/update-co-noir
The RECOVERY STATE block above is now partly superseded: `mc/secreg-27`
(verifier hardening + ch.13 §3a security tests + `fast-check.sh`) and
`mc/docs-27` (ch.15 backlog + reconciliation + recovery notes) are MERGED into
`mc/update-co-noir` (merge commits `b8552d38`, `eb2790a3`; script pins
`39d202b6`). Merged tree green: `./fast-check.sh --sec` PASS. Backup tag
`backup/phase2-code-complete-6c528309` still valid. STILL OUTSTANDING:
`mc/recgen-27` (recursion regen/diagnosis) — do NOT merge until its report is
reviewed; the recursion regression is confirmed (sweep + recgen agree), so
recgen's value is the pinpointed locus, not a vector fix.

**⛔ TESTING DISCIPLINE (Mike, 2026-07-08, firm):** NEVER run circom tests or
bare `cargo test -p tests`. Use `./fast-check.sh` (inner loop ~1.5s) — tiers
`--sec/--mpc/--bb/--all-fast`; `--full` (~60min) is a milestone-only gate.
Memory: [[cosnark-testing-discipline]].

## Session 3 (continued) — 2026-07-08 — RECURSION RESOLVED; Phase 2 code+vectors complete
recgen agent verdict (task #8): recursion/recursion_zk failures were TEST-
VECTOR issues, not a verifier-code regression — (1) stale beta.20 inner proof
in Prover.toml, (2) main.nr `public_inputs` K=3 should be K=1 (pairing points
live inside `proof`, not public_inputs). Fixed, merged (`61100009` →
`4b4a8f51`). Verified: old pin 36da0ea8 recursion worked (so it was ours);
both circuits now self-verify + bb-cross-verify on main. Merge-time gotcha:
gitignored target/*.json+*.gz went stale → build-panic until `nargo
compile && execute` (0.6s). Prevention → ch.12 §3 + new §4a (recursion-vector
regen: WHEN-only + bb command sequence) + ch.14 §20.

**Phase 2 status: DONE except two tracked follow-ups** — deferred SSIPA A(1)=0
kernel-perturbation test (ch.13 §3a#8) and non-canonical (≥modulus) field-encoding
rejection (ch.15 §1.3). All circuits (incl. recursion) pass; security
regressions in place; fast-check.sh is the iteration tool.

## Session 3 (continued) — 2026-07-08 late — documentation tidy-up + Phase 2 wrap

- Documentation pass across PLAN + project-docs + memory for consistency and
  a calm, self-contained technical register; verified with a whole-tree grep.
- Merges landed: `mc/ncrobust-27` (co-acvm/co-brillig robustness hardening +
  tests) and `mc/docreframe-27` (docs pass). Tree green (`fast-check` PASS).
- All side worktrees removed; only the main checkout remains. Nothing pushed;
  backup tag `backup/phase2-code-complete-6c528309` intact.

**State: Phase 2 complete.** All circuits (incl. recursion) pass vs the
source-built oracle; hardening + regression tests in place; docs current.
Non-blocking follow-up: the deferred SSIPA A(1)=0 boundary-claim consistency
test. Iteration tool = `fast-check.sh`.

**Overall state: Phase 2 COMPLETE.** All circuits (incl. recursion) pass vs the
source-built oracle; verifier hardening + §3a regressions in place; docs calm
and self-contained. Non-blocking follow-up: the deferred SSIPA A(1)=0
boundary-claim consistency test. Backup tag `backup/phase2-code-complete-6c528309`
still valid; nothing pushed.

## Session 4 — 2026-07-08 23:48 → 09 ~00:32 — overnight backlog run (ended at usage limit; entry reconstructed next morning)

Autonomous run through `15-improvement-backlog.md` (Mike's standing ask).
Ended MID-ITEM at the usage limit; this entry was reconstructed from the
transcript on 2026-07-09 morning. All work UNCOMMITTED on
`mc/update-co-noir`; verified green next morning (`fast-check.sh` PASS,
`--sec` 8/8 PASS). Full command-level record: ch. 14 §21.

- **Backlog closed (code):** §1.4 VK `log_circuit_size` range-check +
  panic-proof header reads + Gemini fold underflow guard (+ new
  security-regression tests); §2.4 entity-order lock tests; §3.1
  compile-time invariant block extended; §4.4 `rust-toolchain.toml`;
  §4.5 `versions.env` pin single-sourcing; §4.6 `scripts/build-bb-oracle.sh`
  (smoke-tested byte-identical vs `~/.bb-target-src/bb`); §4.7 parity-script
  hardening.
- **Backlog closed (analysis):** §1.5 gemini-masking commit byte-neutral;
  §1.8 builder-determinism sweep clean; §1.10 (0,0)-sentinel
  collision-freeness proven for BN254 G1 + Grumpkin.
- **🔴 §1.9 headline finding — recursion VK/proof PARITY BREAK confirmed**
  (twice, independently, fresh ACIR both sides): co-noir and bb build
  different circuits for `recursion`/`recursion_zk` — VK differs at byte
  112, ~21/28 precomputed commitments differ (incl. LAGRANGE_LAST ⇒ real
  gate-count delta), cross-verify FAILS both ways; each side self-verifies;
  all 31 non-recursion circuits stay byte-identical. **Corrects session 3:**
  the earlier "recursion bb-cross-verifies" was a same-key check (co-noir
  proof + co-noir VK), which tests internal consistency only. Localization
  agent died with the session (~2 min in) — NO diagnosis yet. PLAN item
  2.9 opened.
- **In flight at cutoff:** §2.3/§4.3 VK byte-KATs — bb VKs generated
  (scratchpad `vkkat/`) but not committed as KAT vectors; `plain_test` VK
  byte-parity assertion not yet written. Resume point in ch. 14 §21.

## Session 5 — 2026-07-09 morning — recovery/reconstruction

State recovered from the overnight transcript; this PROGRESS entry, ch. 14
§21, and PLAN 2.7/2.9 written (the overnight session died before logging).
Tree re-verified: `fast-check.sh` PASS + `--sec` 8/8 PASS (new tests
included). recvk2 repro artifacts copied into today's scratchpad.

Mike then directed: commit the overnight batch, do 2.10, start 2.9, and
farm small backlog items to cheaper agents.
- Overnight batch committed: `cee1ffb1` (code) + `6c8c2eff` (reconstruction
  docs).
- **PLAN 2.10 DONE** (ch. 14 §22): VK byte-KATs for add3u64+poseidon ×
  both hashers committed with PROVENANCE.txt; `plain_test` asserts VK
  byte-parity in both zk modes; flipped-byte tripwire validated; 4/4 plain
  tests green. Recursion VK KAT deferred to 2.9 (would be red today).
- **PLAN 2.9 started**: read-only localization agent running (default
  model) on the recursion gate-emission divergence, re-using the preserved
  overnight prompt + recvk2 artifacts.
- **PLAN 2.9 localization LANDED** (ch. 14 §23): three divergences account
  for the gate deltas exactly — (1) `mask_points` missing bb's ∞-asserts
  (ALSO a security gap: they protect the ROM point tables from a malicious
  prover), (2) `unsafe_assert_less_than` top-limb range at 68 bits vs bb's
  50 (weaker bound), (3) ZK row-disabling factor applied once vs per
  subrelation. All three fixes applied (uncommitted), mirroring bb's
  emission order. Non-recursion parity intact (4/4 plain KATs;
  fast-check --sec PASS). Recursion VK moved (19/28 blocks changed) but
  still ≠ bb (21/28 differ) — residual divergence under re-instrumented
  diagnosis by the same agent.
- **PLAN 2.9 RESOLVED** (ch. 14 §23; four fix rounds, iterating with the
  localization agent's per-phase → per-row instrumentation): seven root
  causes total — the three above plus compute_naf's unpinned top NAF
  entry (SECURITY: unconstrained witness; the real source of the arith
  deficit, the ∞-asserts being gate-free), gate-separator multiply
  operand order, self_reduce quotient-max off-by-one, and SmallSubgroupIPA
  claim-batching emission order (in add_zk_data, not check_consistency as
  first attributed). **End state: recursion + recursion_zk VK
  byte-identical to bb; bidirectional cross-verification PASS in both zk
  modes; 0/703,658 trace rows differ.** Proof bytes are prover-specific
  by design (random masking offset generator) — VK identity + mutual
  verification is the parity criterion, and compare.sh's proof-diff
  exclusion for recursion is legitimate.
- **Bonus finds along the way**: the cargo suite's own recursion vectors
  were STILL stale (K=3 + beta.20 inner proof — 2.7's regen only fixed
  the examples copies; never caught because the suite's recursion tests
  are #[ignore]d as slow) — refreshed from the examples set. plaindriver
  stack-overflows proving recursion_zk at default stack size (ch. 15
  §1.11, workaround `ulimit -s unlimited`).
- **Anti-regression landed**: always-on ~5 s `recursion{,_zk}_vk_kat`
  suite tests (VK byte-KATs vs source-built bb, PROVENANCE.txt per dir)
  + compare.sh now byte-diffs VKs for EVERY circuit. This class of break
  can no longer hide.
- Commits: `23e694ee` (fix rounds 1–3, recursion at parity) + final
  round/KATs/docs commit following. Gates green throughout: plain suite
  6/6, fast-check --sec PASS, clippy 0 warnings.
- Parallel cheap-agent work (Sonnet, isolated worktrees): backlog §2.2
  transcript-consumption property test; backlog §2.7 lookup
  `table_index≥1` + SHA CH-L2 10-bit regression tests. Reports pending;
  merge after review.
- §2.2 agent outcome: **DONE, merged** (`9224ad0b`, ff onto main).
  Byte-level transcript-consumption sweep replacing the field-level
  property test, ZK shape added, all verifies panic-guarded via
  catch_unwind. Sweep found zero malformed-input panics in either shape.
  Post-merge `fast-check.sh --sec`: 9/9 PASS. Worktree removed.
- §2.7 agent outcome: **already done** — yesterday-evening commit
  `930efd48` had landed both §2.7 tests AND the 5-party Shamir test
  (closing §1.6/§2.1 too); the overnight backlog pass missed marking
  them. Agent re-validated revert-detection for both (flip fix → red);
  ch.15 §1.6/§2.1/§2.7 now marked done. Lesson: grep the tree before
  farming out backlog items — stale backlog entries cost a redundant
  agent. Worktree gotcha (recorded for future parallel-agent sessions):
  agent worktrees fork from the STALE branch base (36da0ea8), not the
  current tip — agents must `git merge --ff-only mc/update-co-noir`
  before working; §2.2 agent warned mid-flight.

## Session 6 — 2026-07-13 — Phase-2 record closed out; Phase 5 kicked off (5.1 workplan)

- Reconstructed session state: the uncommitted working-tree diff was the
  doc-reconciliation pass matching the already-committed PLAN-2.9 fix
  (`23e694ee`/`fa596e8a`), plus Mike's hand-edits scoping Phase 5 items
  5.1/5.2. Verified tree green (`fast-check.sh` PASS, 1.6 s).
- Backlog (ch. 15) confirmed at a sensible stopping point: remaining open
  items are all deferrable (perf §3, negative-test ideas §2.5/2.6/2.8/2.8a,
  §4.2 manifest, §4.9 diff-fuzz = Phase 4 on hold, §1.11 stack-overflow nit).
- **Mike's decisions**: Phase 5 starts with **5.1** (monty-hall
  modernization, Rust first, TS orchestration after); commit the doc pass.
  Committed as `d8970588` (incl. PLAN 5.1 STARTED marker).
- **PLAN 5.1 started.** Code-level survey of `~/monty-hall-aztec` @
  `d333404` (mpc.rs seam, orchestrator verify, contract, circuits, DB) +
  verified the current co-noir API shapes in our tree. Headline deltas:
  `Rep3MpcNet` is gone (→ `TcpNetwork::networks::<2>`, two `&N` handles);
  `prove` now takes `has_zk` + the bb-format VK and returns proof and
  public inputs SEPARATED (load-bearing for capsule/DB/gRPC shapes);
  `generate_proving_key_rep3` takes the CRS. Defects re-confirmed in
  source: ZK No-prove/Yes-verify mismatch, hardcoded witness-index
  extraction, Postgres table mismatch, finish_game vk_hash[2]/[1] bug,
  TACEONote::pack .x duplication, GAME_OPENED_DOOR==GAME_DONE.
- **Ch. 16 written** (5.1 workplan): ground rules (branch + no-push rail
  in ~/monty-hall-aztec, path-deps into ~/co-snarks, ZK everywhere),
  as-is inventory, API delta table, work items 5.1a A0–A4 (Rust; gate =
  3-party e2e with bb-oracle cross-verify) / 5.1b B1–B4 (contract to
  v5-next aztec-nr; TXE negatives) / 5.1c on-chain / 5.1d TS port; open
  questions Q1–Q4 for Mike (game-phase scope, Postgres, on-chain glue,
  aztec-nr tag parity check). README table updated.
- Ch. 16 + README row + this entry left UNCOMMITTED pending Mike's review.
  Next session: Mike answers Q1/Q2 (Q4 is a 10-min check we can just do),
  then execute A0–A2.

## Session 6 (continued) — 2026-07-13 — Q1/Q2/Q4 answered; aztec-nr delta surveyed; A0 done

- **Mike**: do the ch. 16 recommendations for Q1 (init + ONE `open_door`
  round; rest of the game out of scope — pulls the state-transition
  circuit/endpoints INTO scope as new item A5) and Q2 (keep Postgres);
  and survey ~/ap-next v5-next for current aztec-nr syntax, since the
  demo extends aztec-nr with cosnark state-variable types.
- **Pin re-verification (session-start rule)**: private v5-next moved
  since 2026-07-08 but bb drift = wsdb tooling + foundry.toml only —
  ZERO UH-relevant commits; Phase-2 parity target + oracle stand.
- **Q4 answered by tree-hash diff**: public tag ≡ public v5-next HEAD
  for aztec-nr; private delta (~39 files) is messaging/tagging/oracles/
  test-helpers only — nothing in state_vars/note/macros/capsules → pin
  contract deps + toolchain to public release v5.0.0-nightly.20260708.
- **aztec-nr API delta surveyed** (Sonnet Explore agent over ~/ap-next,
  spot-anchored file:line cites; table now in ch. 16 §5.0). Headlines:
  `#[private]`→`#[external("private")]`; enqueue_self replaces bare
  unsafe public calls; PrivateMutable/Immutable now OWNED (demo's bare
  semantics = SinglePrivate*) — re-fork PrivateSharedMutable on
  SinglePrivateMutable; NoteEmission/.discard() → #[must_use]
  NoteMessage (no discard — design point for commitment-only notes);
  NoteHash trait gained owner/randomness args, unconstrained nullifier
  returns Option; **push_nullifier_for_note_hash is now a first-class
  public primitive** → the external-nullifier fork shrinks to ~a screen;
  Packable is assoc-const form; popCapsule oracle GONE → keyed
  CapsuleArray/capsules::{store,load} (kills the pop-order fragility);
  UintNote is a struct literal (owner at state-var layer); std
  poseidon2 gone → aztec::protocol::hash::poseidon2_hash;
  verify_proof_with_type unchanged; RECURSIVE_PROOF_LENGTH=410 +
  ULTRA_VK_LENGTH_IN_FIELDS=115 importable, HONK_ZK still literal 6, no
  exported ZK proof-length (458 stays a local const + build-time check).
  value-note + easy-private-state crates NO LONGER EXIST (demo deps —
  unused, drop). Ch. 16 §5 rewritten: delta table + B1/B1b/B2–B4.
- **A0 DONE**: ~/monty-hall-aztec origin pushurl DISABLED
  (confidentiality rail — Taceo's repo), branch `mc/modernize` @ base
  `d333404`. Bonus check: upstream `themis/reveal_door_circuit` branch
  is an ancestor of main (no circuit ever pushed) — nothing to salvage,
  A5 is new work as planned.
- Next: A1 (recompile noir_logic at beta.22) → A2 (port mpc workspace).
  Ch. 16 + README + PROGRESS still uncommitted pending Mike's word.

## Session 6 (continued) — 2026-07-13 — 5.1a EXECUTED: A0–A4 DONE, e2e milestone PASS

Mike: "proceed as you think best" + fold aztec-nr syntax survey into ch. 16
(done, see previous entry) + Q1/Q2 as recommended.

- **A1 DONE** — noir_logic at beta.22. Churn confined to pss_utils (+1
  game-lib line): poseidon2_permutation 1-arg; Poseidon2::hash → external
  poseidon crate v0.3.0; u1→bool; EmbeddedCurvePoint {x,y} with (0,0)
  infinity; u32 array indices; `Field as bool` removed — random-bit draw
  made explicit LSB (`(rand as u8) % 2`) after noting the compiler's
  `!= 0` suggestion would be a BIASED bit; game tests pin the semantics.
  Old compare*.sh retired → new check.sh + versions.env + oracle_stub.py
  (TACEO_store is side-effect-only; stub = empty values; MPC path handles
  it in co-brillig). Gate PASS incl. bb prove/verify + tamper reject.
  Poseidon2 unchanged across the jump (old Prover.toml still verifies).
- **A2+A3 DONE** — mpc workspace on path-deps to local co-snarks.
  ark 0.5→0.6 (must match co-snarks); protoc v29.3 installed to
  ~/.local/bin; rust-toolchain 1.90. Port per ch. 16 §3 delta table;
  co-noir re-exports shrank (import NetworkConfig/CrsParser/VK types
  from mpc_net/co_noir_common). Defects fixed: ZK::Yes everywhere;
  ABI-based extract_public_returns replaces witness_share[i]; TRUNCATE
  table fix; proof/public_inputs separation through protos+DB+
  orchestrator; CRS sized from compute_circuit_size; node computes its
  own bb-format VK (ZK prover needs it). Build green; clippy leftovers =
  pre-existing demo cruft.
- **A4 MILESTONE PASS** — `mpc/e2e.sh` (repeatable): 3 docker Postgres +
  3 nodes + orchestrator; sample_rand + init_game HTTP-driven; 3
  byte-identical proofs+public inputs; our verifier accepts vs the
  bb-WRITTEN VK; **source-built target bb verifies the MPC-produced ZK
  proof** (458 fields); tampered byte rejected both sides. Timings/party
  (loopback): witext 0.85s, pk 0.15s, ZK prove 1.74s.
  ⇒ First end-to-end validation that our Phase-2 synced co-noir works in
  the real orchestrated Aztec pattern.
- Gotchas recorded: bb `prove` at this tag requires `-k vk`; bb verify
  exit codes only meaningful un-piped ($? of a pipe = tail's); pgrep
  self-match trap hit AGAIN during teardown ([[watcher-discipline]] —
  use [r]elease bracket trick); orchestrator returns HTTP 200 on verify
  failure (log-only) — flagged for the 5.1d TS rewrite.
- **State: ALL monty-hall work uncommitted on `mc/modernize`** (base
  d333404, push disabled). co-snarks docs (ch. 16 updates + this entry)
  also uncommitted. Next: commit on Mike's word; then A5 (open_door
  round) or 5.1b (contract port) — A5 recommended first (completes the
  Rust pattern before the contract consumes it).

## Session 6 (continued) — 2026-07-13 — quality review + batch-1 fixes; ch. 17

Mike: commit; review monty-hall work + original code (tests/quality/docs/
refactors), Noir vs aztec-nr idioms + noir-contracts; read the HackMD
design write-up; keep PROGRESS + command log current; NO TS until Rust is
solid. 5.1a committed as monty-hall `455893f`; docs `4a7d5550`+`3649d095`.

- Two review agents (Rust workspace; Noir vs ap-next idioms) + HackMD
  read. Synthesis = **ch. 17** (statuses in place).
- **Headline find (Noir review, confirmed): the ORIGINAL game logic was
  broken** — `choose_door` with winning==chosen==1 opened the winning
  door ~half the time, and winning==chosen==2 PANICKED (u8 underflow in
  the eagerly-evaluated discarded branch). All original tests used seed
  123 = winning door 0. FIXED + exhaustive (winning,chosen) sweep,
  coin-flip coverage, 3 state-machine negatives (11 tests green).
- **Rust batch-1 fixed** (ch. 17 §1): verify-failure now 502 (was
  log-only 200); error taxonomy + no handler unwraps; VK parsed at
  startup; GET→POST + TraceLayer; per-node session lock (EADDRINUSE
  race) + run_mpc_session dedupe + distinct gRPC statuses; singleton-row
  atomic upserts (new migration) + fallible DB deser; CryptoDevice/key-
  phrase deleted (explicit rustls-provider install for sqlx); ABI
  param-name fail-fast; config parsed once; timing-log delta bug; orphan
  orchestrator/data/ deleted; compose image pinned; clippy 0 warnings.
- Gates re-run: check.sh PASS + e2e.sh PASS (fresh artifacts staged).
- Open backlog (ch. 17 §2–§5): LocalNetwork in-process 3-party tests
  (top lever), pss_utils crypto tests+KATs, stale "Aztec compatible"
  hash claim (DOM_SEP__* now), to_address_point sqrt panic (#8970),
  transport security (TLS config silently ignored!), contract F7–F11
  (unpack 2nd bug, write-only game_phase, no access control) → 5.1b.

## Session 6 (continued) — 2026-07-13 — test harness landed; SCOPE EXPANDED by Mike

- Rust harness DONE (monty-hall `71037a8`): MPC fns generic over Network;
  LocalNetwork 3-party in-process e2e test (byte-identity + verify-true +
  tampered-false, ~1.3s) + extract_public_returns + data_store unit
  tests; 7 tests green, clippy 0. e2e.sh stays as the docker+bb gate.
- **Mike's decisions (2026-07-13, supersede ch.16 Q1 + ch.17 options):**
  1. **Implement ALL game rounds** (not just init+open_door), with e2e
     tests running the ENTIRE game over an **Aztec local network** — see
     aztec docs in ~/ap-next for how to run a local node/sandbox (Mike
     doesn't know how; we must work it out) + TXE/.nr contract tests
     (docs also in ~/ap-next). This pulls 5.1b (contract port) and 5.1c
     (on-chain wiring) INTO the current work stream.
  2. **Hash scheme: option (b)** — rework pss_utils commit/nullifier to
     match CURRENT aztec-nr conventions (DOM_SEP__NOTE_HASH=116501019,
     DOM_SEP__NOTE_NULLIFIER=50789342, poseidon2_hash_with_separator,
     current preimage shapes). "Generator index" terminology is stale.
     CHECK: aztec macros may already produce domain-separated notes —
     read aztec-nr code in ap-next before hand-rolling.
  3. **TLS: option (b)** — wire transport security properly (mpc-net
     TlsNetwork with correctly-shaped tls config + tonic gRPC security),
     understanding the deployment context first.
- NEXT (continuation): update ch.16 (A5→full-game plan, fold 5.1b/5.1c),
  ch.17 statuses; then Noir pss_utils tests + DOM_SEP rework; contract
  port; all-rounds circuits/endpoints; TLS; Aztec local-network e2e.

## Session 7 — 2026-07-13 — TLS landed; note-compat + local-network specs (ch. 18)

- ch. 16 restructured for the expanded scope (A5a/A5b/A5c; 5.1c pulled in).
- prng+ae tests w/ KATs; dead SAFE-commit helper deleted (mh `06d3c26`).
- **TLS batch DONE (mh `70154c6`)**: TlsNetwork mesh (pinned certs) via
  NodeNetwork enum; tonic mTLS on gRPC (all-or-nothing flags); committed
  key material deleted+gitignored; scripts/gen_dev_certs.sh (rcgen mesh
  DER + openssl dev-CA PEM). Gotcha: BOTH binaries need an explicit
  rustls CryptoProvider install (orchestrator panicked without). e2e.sh
  PASS fully secured; cargo tests 7/7; clippy 0.
- Mike Q answered: e2e.sh = full process separation (real sockets/TLS/
  separate DBs; only loopback+shared-CPU are unreal); cargo-test tier is
  deliberately in-process for speed.
- **Two deep-dives distilled into ch. 18**: (1) exact DOM_SEP formulas
  for bit-identical notes/nullifiers (decision: pss_utils depends on the
  REAL protocol_types crate at our tag — no reimplementation); external
  circuits reproduce only the INNER note hash; no-delivery notes are
  legal (push happens before NoteMessage); nhk_app = plain formula over
  MPC-held sk_m; (2) local-network runbook (`aztec start --local-network`,
  no sandbox; capsules are aztec.js-ONLY → TS driver required; TXE via
  `aztec test`; ⚠ verify_proof_with_type is a NO-OP in TXE/witness-gen
  AND local network defaults realProofs:false → the e2e MUST enable real
  proving + include a tampered-proof-rejected negative).
- NEXT: implement A5a (aztec_note.nr on protocol_types + PrivateState
  rework + circuits + node/protos), then A5b full-game circuits.

## Session 7 (continued) — 2026-07-13 — A5a+A5b circuits DONE (mh `6f76591`)

- aztec_note.nr (canonical formulas via real protocol_types path-dep);
  private_state.nr rewritten (verify_and_nullify + npk identity); 45 lib
  tests incl. negatives/KATs; GameState::from_field_array codec; full-game
  circuits: taceo_commit+init reworked, open_door+finish NEW (player
  UintNote binding = F3 closed in-circuit); legacy bins deleted; check.sh
  extended (4 circuits, bb prove/verify init+open_door) PASS.
- Gotcha: `git checkout <file>` after fixture-gen reverted UNCOMMITTED
  same-file edits — re-applied. Fixtures via temp println test (seed=111).
- **⚠ DELIVERABLE (Mike, mid-turn): when the contract port lands, produce
  a review write-up of ALL aztec contract changes**: step-by-step,
  assume-nothing explainer of WHY PrivateShared{Immutable,Mutable} exist
  (the executor/orchestrator must handle only commitments+nullifiers,
  never preimages — HackMD §abstractions), HOW the reworked versions
  work, WHERE stock aztec-nr state vars are used vs not (justify each),
  and an honest assessment of how to flatten the learning curve further
  (minimal-mental-overhead PSS abstractions). Format: rendered write-up
  for review.
- NEXT: 5.1b contract port (with the A5b public-input contract design),
  then A5c node/orchestrator (KEY: persist state shares between rounds —
  execute_circuit_rep3 returns the PssStore; store shares in Postgres;
  requests carry deployment context), then TS driver + local-network e2e
  (ch.18 §5; realProofs caveat).
