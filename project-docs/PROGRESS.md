# Progress log

Append-only, newest session last. Each entry: date, what was done, decisions,
open questions, next steps.

**Quick link — benchmark explorer (live site, v2 dataset 2026-07-25):**
<https://claude.ai/code/artifact/90d4bf98-8b70-4f9e-814b-5d07b20daefa>

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

## Session 7 (continued) — 2026-07-13 — contract port DONE; write-up published

- **Contract ported to v5-next aztec-nr (mh `50692e2`)**: new
  private_shared_state.nr with PrivateSharedImmutable/PrivateSharedMutable
  (fork of SinglePrivateMutable; reads return ConfirmedNote, mutation takes
  MPC-proven nullifier as input via push_nullifier_for_note_hash);
  TACEONote = #[derive(Packable)] hash-carrier (kills pack/unpack bugs);
  ALL six rounds; enforced phase machine + msg_sender access control;
  keyed capsules; imported proof constants. Player door/switch = stock
  SinglePrivateImmutable<UintNote>, bound to proof by value comparison
  (F3, simpler than in-circuit hash binding). Compiles clean.
- Contract design recorded in ch.16 §5.1b before implementing.
- **Write-up published** (Mike's deliverable): artifact
  https://claude.ai/code/artifact/28061f43-5114-490d-8ed4-1c57790759df —
  why PSS abstractions exist (blind executor), how they work, stock-vs-
  custom storage table, rest-of-port summary, learning-curve critique +
  4 improvement proposals (verify_pss_transition helper; typed
  public-input builder; drop the NoteMessage sink; PrivateSharedSet).
- **aztec toolchain INSTALLED + RUNS**: npm @aztec/aztec@5.0.0-nightly.
  20260708 into scratchpad/aztec-cli/pkg; `aztec --version` prints the
  pinned version (no docker needed for that). TXE/local-network e2e now
  reachable next session (may need docker for the network; `aztec test`
  starts a TXE server).
- NEXT: TXE contract tests (assert flow/phase/access-control — NOT proof
  validity, which is a no-op in TXE per ch.18); A5c node/orchestrator for
  all rounds (persist state shares between rounds via execute_circuit_rep3
  PssStore); then TS driver + real-proving local-network e2e with a
  tampered-proof-rejected negative (the definitive soundness gate).

## Session 8 — 2026-07-13 — TXE tests GREEN (6/6); local network validated; e2e planned

- aztec toolchain (@aztec/aztec@5.0.0-nightly.20260708) drives compile +
  TXE + local-network — all pure Node, no docker needed for CLI.
- **Contract TXE suite DONE (6/6, mh `f23c29c`)**: workspace restructure
  (montyhall + montyhall_test); tests cover deploy + round-1 capsule proof
  verification + VK-hash rejection + operator/player access control on all
  rounds. Refinements found via TXE: ProofData nominal capsule struct;
  init_game de-#[initializer]'d (capsule-before-deploy); slot-only PSS init
  nullifier (siloing makes it sound, drops contract-keys need); PSS notes
  owned+delivered to operator; `contract` is a reserved keyword.
- **KEY FINDING (matches HackMD): PSS note discovery has no ordinary path.**
  A TACEONote is hash-only (no discoverable preimage) → `deliver()` +
  cross-tx `get_note()` fails "Failed to get a note". This IS the gap Taceo
  flagged as needing `add_note_hash()`. TXE therefore validates only
  pre-note-read logic; full-game flow needs the local-network e2e with the
  discovery workaround. Also confirmed: verify_proof_with_type is a TXE
  no-op (proof validity untestable in TXE).
- **Local network VALIDATED**: `aztec start --local-network` brings up
  node :8080 + anvil + protocol contracts + test accounts at the pin.
  Toolchain proven; full e2e is now pure integration work.
- **e2e plan (ch.18 §6)**: TS aztec.js driver (aztec-kit patterns:
  setupLocalNetwork + Capsule) — deploy, real co-SNARK proof per round as
  a Capsule, + solve PSS discovery. Recommended discovery fix: store the
  current PSS note as a CAPSULE the operator restages each round (option
  b), sidestepping note discovery — settle with Mike (also feeds 5.0
  PXE-secret-sharer, the mirror-image problem).
- aztec-kit cloned to scratchpad for reference (embedded-wallet.ts capsule
  usage; common/setupLocalNetwork fixture).
- NEXT: the local-network e2e TS driver (real proving + tamper-reject =
  the definitive soundness gate); resolve the PSS-discovery design fork.

## Session 9 — 2026-07-13 — Mike's refactor review executed: ch.17 §6 primitives BUILT; full game green in TXE

Mike's review comments on the monty-hall code (better comments; no
recalculated-hash params; kill PrivateState/TACEONote; existence proofs
via kernel read requests; audit aztec_note helpers; README) — all
landed on `mc/modernize` (uncommitted). They confirmed ch.17 §6, which
is now AS BUILT (full record: ch.17 §6.7; ch.16 5.1b banner has the
as-built public-input shapes; ch.18 §6 updated).

- **Circuits**: PrivateState/PrivateStateTrait deleted, aztec_note calls
  inlined in the 4 round mains; recomputed hashes are now OUTPUTS not
  params (init: seed_note_hash; open/finish: nhfn); TACEO_store oracle →
  pss_utils::mpc_store; dead code deleted (commit.nr, uint_note_hash,
  initialization_nullifier); npk_m_hash via protocol hash_public_key;
  sk decomposition via stdlib EmbeddedCurveScalar::from_field (closes
  ch.17 F4); commented-out state-var-style wrapper sketch + assessment
  in pss_utils/src/state_var_style.nr per Mike's "both versions" ask.
  Gates: 4 circuits compile, 42 lib tests green (KATs unchanged →
  formulas byte-identical), check.sh PASS (bb prove/verify + tamper).
- **Contract**: raw context primitives inlined in the round functions
  (push_note_hash / assert_note_exists(for_settled) /
  push_nullifier_for_note_hash; Mike follow-up: no pss.nr wrappers);
  TACEONote + PrivateShared* fork deleted; old-state leaves are function
  args bound via proof publics; hash-only `assert_note_exists` reads.
  **Player door/switch: private ChoiceNotes** (Mike's correction of an
  intermediate public-storage iteration — co-SNARK publics are NOT
  chain-public; the proof verifies inside a private function, so its
  public inputs exist only in the executing party's simulation). Owner =
  player via Owned<PrivateImmutable> (NOT SinglePrivate*, whose init
  nullifier needs CONTRACT keys — documented; latent bug in the previous
  port), deliver_to(operator), host rounds read via get_note. Getting
  that to work surfaced a REAL upstream defect: note DISCOVERY skips any
  note whose unconstrained nullifier it can't compute ("skipping PXE
  insertion", Linear F-265) → third-party deliver_to of stock #[note]
  notes is silently broken (or aborts sync with "Key validation request
  denied" when the owner's public keys are known — always in TXE).
  Maintainer-ready write-up (Mike's ask): monty-hall repo
  upstream-issues/third-party-note-delivery-is-silently-broken.md.
  Workaround: ChoiceNote's nullifier is KEYLESS
  (P2(DOM_SEP__NOTE_NULLIFIER, nhfn); never pushed; sound for an
  immutable note) — with it, REAL delivery + tagged-log discovery works
  in TXE under the default tagging strategy.
- **KEY RESULT: full game green in TXE (10/10)** — first-ever full-flow
  run, incl. real player-note delivery/discovery. Hash-only settled
  reads resolve via note-hash-tree lookup
  (verified in ap-next TS + empirically); ch.17 §6.6 Q1 = YES, the
  add_note_hash gap is gone. New negatives: wrong seed tx-position
  (read request fails), replayed spent state (duplicate nullifier),
  open_door before any door was chosen (note read fails).
- **Repo hygiene**: real README (stage ordering table, why init is
  round 2, layout, trust model); stale target-residue dirs deleted
  (monty_hall_choose/switch/test, dh_test); "I have" typo (stray IDE
  input) fixed; uint_note deps dropped.
- **A5c spec updated** (ch.16 banner): node/orchestrator were already
  pre-A5a-stale; must now target the as-built ABIs + carry deployment
  context + persist mpc_store shares.
- **Design audited against the aztec-nr docs/API reference** (Mike's
  steer; agent over ap-next docs + source doc-comments). Two fixes
  applied: nullify_pss_note now uses the documented note-nullifier call
  `push_nullifier_for_note_hash(nullifier, 0)` (docs: never
  push_nullifier_unsafe for note nullifiers; the notify oracle is safe
  for untracked notes); init_game rejects zero operator/player (direct
  public-entrypoint invocation has msg_sender==0 — visibility.md danger
  note — so the guards must fail closed). Confirmed fine: raw
  push_note_hash (documented low-level primitive; kernel silos+
  uniquifies), hash-only for_settled reads (1 of 16-per-call budget,
  anchor-block semantics), the enqueued public bind-assert (the
  documented "check validity condition on public state" idiom with tx
  atomicity), capsule usage (validated in-circuit per the docs warning),
  and utility getters for off-chain public reads.
- **Nonce/naming review (Mike)**: circuits + start_game now take ONE
  protocol `note_nonce` (not first_nullifier+index; self-verifying via
  the read request; for PSS notes it must be a caller hint since no PXE
  ever stores these notes); all "nhfn"/leaf naming replaced with
  aztec-nr vocabulary (siloed_note_hash / unique_note_hash /
  note_hash_for_nullification); aztec_note::unique_siloed_note_hash →
  unique_note_hash(contract_address, note_hash, note_nonce), mirroring
  compute_note_existence_request's settled branch (not callable
  directly — it takes a HintedNote, which needs a preimage). Fixtures
  regenerated; check.sh PASS; TXE 10/10.
- NEXT: A5c (node/orchestrator all rounds), then the TS local-network
  e2e with real proving + tamper negative (ch.18 §6, now simpler — no
  discovery workaround needed). Ch.17 §6.6 Q3 soundness write-up still
  owed; session-7 write-up artifact describes the OLD PrivateShared*
  design and needs refreshing after Mike reviews this rework.

## Session 9 (continued) — 2026-07-13 night — A5c DONE (all-rounds MPC stack); local-network e2e driver; soundness + ae/dh write-ups

- **A5c COMPLETE (Rust)**: protos v2 (4 rpcs, every round returns
  proof+publics; requests carry the deployment context + note_nonce);
  mpc-node reworked — 4 circuits with startup ABI checks, per-circuit
  bb-format VKs, CRS sized over all, round 1 now PROVES taceo_commit
  (the old demo never did) and samples mpc_sk alongside seed+blinding;
  game-state preimage shares flow back via execute_circuit_rep3's
  PssStore ("game_state" key) and persist in Postgres as tag-encoded
  mixed public/shared vectors (new migration: root_rand{seed,
  seed_randomness,mpc_sk}, game_state{fields,randomness},
  round_proofs); orchestrator: per-round VKs, JSON HTTP API (hex
  fields in, proof+publics out — shaped for the TS driver), byte-
  identity + verify per round. clippy 0.
- **Gates**: `three_party_full_game` cargo test (~8 s, LocalNetwork):
  all 4 rounds byte-identical across parties, every proof verifies,
  tamper rejected, cross-round chaining asserted (seed hash, npk_m_hash
  equality). `mpc/e2e.sh` reworked to the FULL GAME: 4 rounds over
  HTTP with a deployment context, every proof bb-cross-verified against
  bb-written VKs, tamper negative, seed-chaining check — PASS.
  GOTCHA: bundled test CRS was a 4096-point prefix; new circuits need
  more → 32k-point prefix cut from ~/.bb-crs (ch.14 §26).
- **TS local-network e2e (e2e/)**: pinned aztec.js driver + run.sh
  (brings up local network + MPC stack; MPC pg ports moved to 15432+ —
  the aztec node owns :8080). Driver: EmbeddedWallet + initial local-
  network accounts; initializerless deploy; per-round orchestrator
  fetch → proof staged as an operator-scoped Capsule; nonces/leaves
  mined from tx effects via node.getTxEffect + computeNoteHashNonce
  (same data the TXE tests use); cross-checks MPC publics vs chain
  leaves each round; asserts final phase/opened_door/win; tamper
  negative runs BEFORE the honest finish and only under
  EXPECT_REAL_PROOFS=1 (verify is a no-op under simulated proving).
  Node-24 packaging gotchas (foundation subpath exports; @aztec/
  accounts lazy dynamic JSON import missing `with {type:'json'}` →
  load-hook shim) recorded in ch.14 §26.
  **RESULT: PASS (simulated-proving mode)** — the ENTIRE game played
  on-chain for the first time: real capsule staging, real ChoiceNote
  delivery+discovery, real hash-only read requests, real nullifiers;
  every MPC-derived leaf matched the chain's tx effects; final
  phase/opened_door/win asserted. Real-proving mode
  (EXPECT_REAL_PROOFS=1 → PROVER_REAL_PROOFS + wallet proverEnabled)
  wired and attempted: **FAILS at this tag, and the bb-proof
  substitution probe proves it is NOT co-noir's fault** — the
  in-circuit verify_proof_with_type(HONK_ZK) path itself breaks under
  real ClientIVC client proving (deploy proves fine; bb.js
  "Failed to verify the generated proof!"; vk-hash conventions verified
  equal; no app contract upstream ever calls verify_proof_with_type →
  likely untested there). Full record + next steps: ch. 18 §6. The
  soundness-definitive tamper negative therefore remains BLOCKED on
  resolving that (upstream-facing) issue.
- **Ch.17 §6.8 written** (Q3 soundness argument: binding layer;
  malicious-minority → DoS only; full-collusion → privacy gone,
  integrity intact, seed-bias-before-choice caveat; assumptions
  inventory). **§6.9 written** (ae.nr/dh.nr: the dormant encrypted
  user→MPC channel — never wired in the original repo (dh_test only),
  not needed in the as-built demo since no user secret ever travels to
  the MPC (all sampled in-network; transport mTLS), becomes
  load-bearing for private player inputs (prove-decryption pattern)
  and PLAN 5.0/5.2).
- **Write-up artifact refreshed to rev 2 (as-built)** — same URL as
  session 7; PLAN 5.1 status block updated; ch.14 §26 command log.

## Session 9 (continued) — 2026-07-13 night — real-proving failure DIAGNOSED (barretenberg-side, untested path)

Mike: "diagnose and try to fix; if it needs barretenberg fixes I'll file
a private bug report." Diagnosed to a bb defect; no speculative fix to
audited proving C++ — produced a maintainer-ready report instead.

- **Root cause located**: `verify_proof_with_type` inside a ClientIVC
  **Mega app** circuit → `ChonkProve`'s own sanity verifier fails at
  `ChonkVerifier: verification failed at batched translator+joint
  reduction` (chonk_verifier.cpp:89; `reduction_succeeded==false`, the
  Goblin Translator+joint-PCS step). Same binary proves+verifies, so the
  PROVER emits a translator/joint sub-proof that fails its own verifier
  for the recursive verifier's ~700-Goblin-ECC-op pattern.
- **Discriminated** with a minimal probe contract (`contract/verify_probe`,
  one fn per flavor): deploy PROVES; verify-containing app FAILS for
  HONK=0/410 AND HONK_ZK=6/458, and with bb-generated inner proofs too →
  not the ZK flavor, not co-noir, not vk_hash (verified bb hash ==
  poseidon2(vk) == pin). Sole trigger: a Mega app carrying the UH
  recursive verifier. And `verify_proof_with_type` has NO app-contract
  caller in the whole aztec-packages tree — an unexercised path upstream.
- **Deliverable**: `upstream-issues/clientivc-recursive-verify-fails-in-app.md`
  + `clientivc-recursive-verify-repro/` (gzipped real 6-circuit folding
  stack + captured output) — deterministic file-based repro
  (`bb prove --scheme chonk --ivc_inputs_path …`), discrimination table,
  capture technique, and a suggested bb-team C++ test. Ready for Mike to
  file in the private bb repo.
- Tooling built en route: `e2e/probe_driver.mjs` + `run_probe.sh` (real-
  proof VerifyProbe driver); the bb-prover execution-steps dump hook and
  bb.js native-logger patches (documented in the report — node_modules is
  gitignored so the patches were reverted to keep the tree pristine).
  Real-proving toggle wired into the main e2e (EXPECT_REAL_PROOFS=1 →
  PROVER_REAL_PROOFS + wallet proverEnabled). run.sh cleanup hardened
  (setsid + anvil sweep; a stale anvil otherwise makes the next start
  die "Ethereum node is out of sync").
- **CONSEQUENCE**: the tamper-reject soundness gate is BLOCKED on the bb
  fix. Everything short of real ClientIVC proving is green. ch.04 §5's
  recipe was verified at artifact/constant level + TXE, never end-to-end
  under real proving — this is what surfaced that gap.

## Session 9 (continued) — 2026-07-13 night — DECISIVE: Aztec's own documented example fails the same way

Mike pushed back on "nobody tries this pattern" (correctly). Chased it:
- The pattern is DOCUMENTED: Aztec tutorial "Verify Noir Proofs in Aztec
  Contracts" + `docs/examples/contracts/recursive_verification_contract`
  (ValueNotEqual, verify_honk_proof from bb_proof_verification). Also
  community demos (satyambnsal/critesjosh aztec-noir-verify) at aztec
  2.0.3. My earlier "untested/no caller" claim was WRONG and is
  corrected in the report + ch.18.
- Ran the OFFICIAL example verbatim at our pin under real proving:
  deploy OK, counter=10, `increment()` (→ verify_honk_proof) fails
  identically ("Failed to verify the generated proof!" from
  createChonkProof). So the failure is NOT ours — Aztec's own tutorial
  example is broken end-to-end at v5.0.0-nightly.20260708. It escapes CI
  because docs examples aren't in the proving matrix + local networks
  default realProofs:false (simulated → verify is a no-op).
- Report upgraded to lead with this (upstream-issues/…-fails-in-app.md
  + official-example-run.log + e2e/official_example_driver.mjs +
  run_official.sh). Added the regression-vs-never-worked open question
  and a "reproduce the official example" recipe.
- Still not a speculative-fix candidate (audited Goblin/Translator C++);
  it's a maintainer bug report — now a much stronger one.

## Session 10 — 2026-07-17 — RESOLVED: the bb bug is real AND already fixed on `next`

Built the C++ reproduction the report's "suggested next step" called for and
ran it on `next` (branch `mc/fix-clientivc-recursive-verify` in
aztec-packages-private, based on next; commit 91e7212adb).

- **New test** `barretenberg/cpp/src/barretenberg/dsl/acir_format/chonk_honk_recursion.test.cpp`
  (`ChonkHonkRecursionTests`): injects a `UltraZKRecursiveFlavor_<MegaCircuitBuilder>`
  recursive verifier into one Chonk app slot (via a new `app_finalizer` hook on
  `PrivateFunctionExecutionMockCircuitProducer`), accumulates app+kernels,
  `ivc.prove()`, verifies with `ChonkNativeVerifier`.
- **VerifyHonkProofInApp → PASSES on next.** `num ultra ops = 581` vs a 504-op
  baseline for the same producer without the injected verifier (the +77 goblin
  ops are the recursive verifier's deferred group ops → it's genuinely present).
- **BadInnerProofIsRejected (negative control) → PASSES**: corrupt inner proof
  is rejected. Proves the verifier actually constrains the proof and the harness
  can tell accept from reject, so the green result is meaningful.
- **VERDICT**: There WAS a real barretenberg bug at v5.0.0-nightly.20260708
  (confirmed at session 9 with Aztec's own tutorial example → not our monty-hall
  work). It does NOT reproduce on `next`. Leading (NOT bisect-confirmed) fix:
  **a69ffdf8a1 (#500)** — full-width Fiat-Shamir + `enforce op = 0 in odd rows in
  translator (port #378)` + shift-size + single VK regen. It's the only PIN..next
  commit touching the failing translator subsystem + the VK regen, BUT its
  sub-fixes are soundness-framed (why an honest proof flips fail→pass is
  inferred), PIN..next has 60+ commits, and there's a v5/v6 divergence (next is
  v6-based; #500 is a v6-line commit — the same one PLAN Phase 3 already flags
  for the co-noir transcript port). Only a bisect confirms attribution.
- **Project resolution**: to unblock in-contract UH verify under REAL proving
  (and the ch.04 §5 tamper-reject soundness gate), move co-snarks/monty-hall to a
  pin containing a69ffdf8a1, or cherry-pick #500 (+ its VK regen). TXE/simulated
  proving was never affected.
- Fidelity caveat: reproduction builds the verifier via stdlib on the Mega
  builder (same circuit the DSL emits), not the identical failing PXE artifact
  (its 4576-byte Mega VKs no longer load post-regen). Final end-to-end proof on
  next = a real-proving e2e with a next client (official_example_driver.mjs).

## Session 11 — 2026-07-17 — RETRACTION: the C++ repro does NOT reproduce the bug; "fixed on next" is unproven

Ran the bisect Mike asked for. It overturned session 10:
- **#500 is NOT the fix**: built + ran ChonkHonkRecursionTests at a69ffdf8a1's
  parent a1f07c9fda → PASS. If the parent passes, #500 can't be the fix.
- **The C++ test does NOT reproduce the bug**: ported it to
  aztec-packages-private:v5.0.0-nightly.20260708 (the tag where the bug IS
  validated via e2e) and clean-built → PASS (637 ops vs 581 on v6, so the build
  is faithful, not stale). The test passes exactly where the bug is real.
- **Therefore RETRACTED**: session-10's "real bug, FIXED on next, confirmed via
  negative control" was overstated. The negative control only proved the
  verifier is wired in — NOT that the test reproduces the bug. "Fixed on next" is
  UNPROVEN (the only C++ evidence was a test that can't see the bug). #500 /
  full-width-FS attribution withdrawn.
- **Still solid**: the bug manifests at v5.0.0-nightly.20260708 under real
  proving (e2e, Aztec's own example, session 9). That's the only hard fact.
- **Why the C++ test misses it (hypotheses)**: injects the recursive verifier via
  stdlib directly instead of the real DSL create_honk_recursion_constraints /
  create_circuit<Mega>(program,{.ivc}) path; mock kernels simpler than real
  private kernels; mock inner proof differs from the co-noir/bb one.
- **Next to get a VALID repro**: (a) rebuild the test through the real DSL path
  (what the bug report's "suggested next step" actually specified — I only
  approximated it); if it fails at the v5 pin it's a faithful guard and a bisect
  can find the real fix. (b) real e2e on a next/v6 client (gold standard, heavy).
- Bug md rewritten with a status table + bisect log; branches bisect-v5pin /
  bisect-fix-parent hold the ported test. LESSON: don't call something a
  reproduction until it has actually failed on the real bug.

## Session 11 (cont.) — FAITHFUL no-mock result: bug present on v5 AND early-v6

After Mike said "never use mock circuits" + "maybe there was never a bug",
re-examined the ONLY non-mock evidence and ran the REAL captured stack through
multiple bb binaries (no mocks, no network):
- Re-scrutinized session-9 e2e: Aztec's OWN official example (ValueNotEqual)
  fails at increment() under real proving; native log shows failure at
  `batched translator+joint reduction` (NOT the pairing check → bb-bug shape,
  not invalid-inner-proof), with REAL kernels (private_kernel_init/reset/tail +
  hiding_kernel), and a positive control (same verify as standalone Ultra proof
  verifies fine). So the bug is REAL, not a monty-hall artifact.
- Ran the real failing stack (failing-ivc-inputs.msgpack) through bb CLI:
  - 6.0.0-nightly.20260605 (early v6): **FAILS** identically (698 ops, translator
    reduction). So the bug is on the v6 line too.
  - 5.0.0-nightly.20260703 (produced the stack) / 5.0.0-nightly.20260708 (pin):
    FAIL.
  - 5.0.0-nightly.20260710 (in npm 5.0.0-n.715 / 5.1.0-n.717): can't load the
    stack (VK format 4576→5216 changed ~07-10) → inconclusive.
- NET: bug confirmed on v5 AND early-v6 via REAL circuits. "Fixed on next" is
  retracted and looks UNLIKELY. Testing the current next tip needs regenerating
  the stack with a post-07-10 client (full e2e or source build) — no such client
  on npm. ALL mock C++ results are VOID (mocks hide the bug — Mike's instruction).

## Session 11 (cont. 2) — DEFINITIVE: bug FIXED on v6/next (real-proving, no mocks)

Got the from-source next node running (earlier exit-144s were from pkill -f /
foreground sleep in my commands, NOT the node). Ran the REAL test:
- Built next bb CLI + started `aztec start --local-network` (real proofs) from
  source (anvil for L1). Node came up on :8080.
- Generated a real inner UH-ZK proof with next bb; deployed the compiled
  HonkVerifier contract; called increment() (which runs verify_honk_proof) from
  an EmbeddedWallet with proverEnabled=true → REAL ClientIVC proving, REAL kernels.
- RESULT: deploy + increment() both generated ClientIVC proofs with NO error;
  counter 10→11. The identical flow FAILS on v5 (session 9). So the in-contract
  UH-verify bug is **FIXED on the v6/next line, broken on v5**.
- Driver: aztec-packages-private:yarn-project/verify_driver.mjs (+ register.mjs
  shim), commit 781b21f6f3. Run: node --import ./register.mjs verify_driver.mjs
  with ARTIFACT=honk_verifier_contract-HonkVerifier.json, INNER_DIR=<inner/out>,
  BB_BINARY_PATH=<next bb>, PROVER_REAL_PROOFS=true.
- The mock ivc-integration cross-check (581 ops, verifier present, reduction:true)
  passed on next but is inconclusive alone (mocks pass on v5 too); the real-kernel
  run above is the conclusive one.
- Task #17 (app-side-only fix on immutable v5.0.1): ANSWERED NO. The fix spans
  protocol machinery — Honk VK format changed 4576→5216 + transcript/translator
  changes — so it rotates immutable VKs and is not app-side-only. Deployed/immutable
  v5 cannot be fixed in place; the resolution is to move to the v6/next line.
- Report RESOLVED: monty-hall upstream-issues/…-fails-in-app.md (commit ed6a71b).

## Session 11 (cont. 3) — BISECT: fix commit = a69ffdf8a1 (#500), full-width Fiat-Shamir

Real-stack (NO-MOCK) git bisect over the next line pins the fix:
- Oracle: build bb per commit + `bb prove --scheme chonk` the REAL captured stack
  (real private_kernel_* + hiding_kernel + real verify-app, dumped from the
  passing next PXE run). FIXED = exit 0 + proof written; BROKEN = fails/won't-load.
  (First oracle attempt was VOID — it detected success by log message, but bb
  prove succeeds silently; recalibrated to exit-code + proof-file.)
- Result: parent a1f07c9fda BROKEN, **a69ffdf8a1 (#500) FIXED** → #500 is the fix.
- Operative sub-change: **full-width Fiat-Shamir** (in-circuit convert_challenge →
  convert_full_challenge, exact fr→fq). The other two sub-fixes in #500 (op=0 #378,
  shift-size #409) were ALREADY in the failing v5 pin …20260708, so ruled out.
- Fix == VK-format change (4576→5216) by construction: full-width FS rotates all
  Honk VKs, so the completeness fix and the format regen are the same commit.
  (Couldn't test the parent with an old stack — new stack won't load, old v5 stack
  no longer parses "Missing field kind"; the op=0/shift-size elimination is the
  independent confirmation.)
- NOTE: this VINDICATES the original #500 hypothesis that was wrongly retracted on
  the void mock bisect. Real circuits only, always (Mike's rule).

## Session 12 — 2026-07-20 — v5.0.1 resync: built the new oracle, found the true diff is EMPTY, full Stage-4 green, pin flipped

New task, separate from the sessions 9–11 monty-hall/bb-bug thread above:
re-sync co-noir's bb pin from `v5.0.0-nightly.20260708` to `v5.0.1`, run with
the same rigor as the original Phase 2 sync (ch. 03/11/12/13 methodology).
Full write-up: **project-docs ch. 19** (new chapter). Summary:

- **Stage 1 (oracle)**: built `bb` from source at `~/ap-next`'s `v5.0.1` tag
  (`b97ff8c3e88f`, release commit `72666f8d1d6`) via `git worktree add
  --detach` off `~/ap-next` (never touched its checkout, which stayed on
  branch `v5`) — same recipe as the existing oracle (clang-20, `cmake
  --preset default -DAVM=OFF`, ~129s build). Saved to
  `~/.bb-target-src-v5.0.1/bb` + `PROVENANCE.txt`; old oracle untouched.
- **Stage 2 (gap analysis) — the real finding**: the C++ source for every
  UltraHonk-critical directory (relations/ultra_honk/flavor/
  commitment_schemes/sumcheck/stdlib_circuit_builders, plus a wider net:
  transcript/honk/constants.hpp/dsl/plonk_honk_shared) is **byte-identical**
  between co-noir's TRUE current baseline and `v5.0.1`. This was not
  assumed — it followed a genuine puzzle (bb's lookup `table_index`
  numbering looked contradictory between what co-noir's own shipped test
  asserts and what the naive tag diff showed) that got resolved via a
  coordinator note (relayed from the sibling monty-hall-aztec task) and then
  **independently re-derived from scratch in this session**: the existing
  oracle was actually built from private-repo commit `289aaec1e027` (per its
  own `PROVENANCE.txt`), which shares the nightly *tag name*
  `v5.0.0-nightly.20260708` with a **different, divergent** commit
  (`a455b9a943e7`) in the public `~/ap-next` mirror — two separate
  merge-train branches, neither an ancestor of the other, that happened to
  get the same nightly label. Verified four independent ways: (1) rebuilt bb
  from source at `289aaec1e027` in a fresh worktree off
  `~/aztec-packages-private` (never touched its checkout) — the resulting
  45,391,032-byte binary is `cmp`-identical to `~/.bb-target-src/bb`; (2)
  `git diff 289aaec1e027 v5.0.1` restricted to the UltraHonk dirs (and a
  wider net) is empty, 0 files — the only diff anywhere in
  `barretenberg/cpp/src/barretenberg` is 7 unrelated `world_state`/`wsdb`
  files; (3) the Noir/ACIR submodule pin is also byte-identical at both
  commits; (4) co-noir's own original-sync commit messages (`5ac55600`,
  `1a13fcdc`) turn out to already describe exactly the content that a naive
  public-tag diff made to look like new v5.0.1 work (ROM sorted-chain pinned
  at both ends, lookup `table_index` 1-based, entity/relation reorder) —
  confirmed by reading `co-builder/src/ultra_builder.rs`'s
  `process_rom_array_{public,shared}_inner` directly, which already has the
  exact both-ends pin. **Net: Stage 3 (porting) is empty by construction.**
  Chapter 19 keeps the code-reading method (which files were read in full,
  how the Mega-only `IsOffsetOnlyRelation` generalization in
  `sumcheck_round.hpp`/`relations/utils.hpp` was confirmed byte-neutral for
  Ultra) as a transferable technique for the next sync, even though it
  turned out to be reading an already-absorbed diff.
- **Stage 4 (validation) — run in full regardless**, not skipped on the
  strength of the tree-diff argument alone: direct bb-vs-bb (old oracle vs
  new oracle, no co-noir involved) gives 100% VK/proof byte parity across
  all 32 committed-KAT circuits, both hashers, non-ZK, plus 100% VK parity +
  100% mutual ZK verification in ZK mode. Then the real gate — co-noir vs
  the new oracle: `fast-check.sh --all-fast` green; full
  `cargo test -p tests --release --test noir` 106/106 (8 intentionally
  `#[ignore]`d slow recursion-prove tests); `compare.sh` (plain, all 32
  circuits × both hashers × ZK/non-ZK × 4-way cross-verify, VK-diff
  including recursion) 0 errors; `compare_mpc.sh` (REP3 3-party, same
  matrix, **including the slow set** aes128/bb_sha256_compression/
  recursion_zk) 0 errors. ≥4-party Shamir already covered by the in-tree
  5-party-threshold-2 poseidon test. Matches the original Phase 2 bar in
  full.
- **Two incidental pre-existing bugs found + fixed while running Stage 4**
  (both unrelated to v5.0.1's content, recorded in ch. 19 §4): (1)
  `compare_mpc.sh` had a hardcoded `TEST_SLOWER_CIRCUITS=0` that silently
  overrode the caller's env var, so `fast-check.sh --full`'s attempt to
  enable the slow set never actually worked — fixed to
  `${TEST_SLOWER_CIRCUITS:-0}`; (2) `fast-check.sh` hardcoded its own copy of
  the oracle path instead of reading `versions.env`, which would have made
  it silently keep validating against the *old* pin forever after this
  session's pin flip — fixed to `source versions.env`.
- **Stage 5 (pin flip) — DONE**: `versions.env` now
  `BARRETENBERG_VERSION=5.0.1`,
  `BARRETENBERG_BINARY_DEFAULT=~/.bb-target-src-v5.0.1/bb`, comments rewritten
  to explain the tag-provenance caveat (not just find-replaced); `Readme.md`'s
  version mentions updated to match (and its prebuilt-binary instructions
  re-verified: unlike the old rc.2 lesson, the real `v5.0.1` GitHub release
  asset genuinely is `write_vk`-byte-identical to the source build — checked,
  not assumed). Old oracle + old pin values left on disk/documented, not
  deleted.
- **Confidentiality correction mid-session (Mike)**: earlier PLAN.md guidance
  that local commits were "fine and expected... at real milestones" was
  retracted — **no commits of any kind this session**, everything above is
  uncommitted working-tree state. Flagging here so the next session doesn't
  assume any of this landed via `git log`.
- Resource use: two source builds (~130s/~150s each) + two ~9-min
  BARRETENBERG_BINARY-driven sweeps, all within the 80%-of-186-cores budget
  (`RAYON_NUM_THREADS` capped per the scripts' own existing formulas). No
  circom, no unrelated test suites, per standing testing discipline.

## Session 13 — 2026-07-23 — full code-level verification of the doc record; monty-hall deps → release-tag git deps; both trees committed

Mike's brief: comprehend project state, but "don't necessarily trust the md
files — look at the code too." So this session re-verified the record
empirically before acting on it, then (on Mike's explicit ask) committed the
accumulated working-tree state in BOTH repos.

**Verification sweep (docs vs code/artifacts) — the record holds up:**
- Two Explore agents checked 25 load-bearing claims against source. co-snarks:
  all 12 CONFIRMED at the cited lines (relation tuple reorder + perm
  NUM_RELATIONS=3, `lookup_table_index_starts_at_one`, ROM/RAM both-ends
  pinning, 410/458/115 compile-time asserts, always-on `recursion{,_zk}_vk_kat`,
  trailing-bytes + off-curve hardening, `fast-check.sh`→versions.env fix,
  `compare_mpc.sh` env fix, deferred-SSIPA-test absence is deliberate and
  documented in-code, Shamir ZK randomness accounting incl. 8×NUM_MASKED_ROWS).
- Live gates re-run: `fast-check.sh --all-fast` PASS vs the v5.0.1 oracle
  (KAT byte-parity, 9/9 security regressions, 7/7 REP3+Shamir incl. 5-party,
  bb cross-verify proof+VK byte-identical); recursion VK KATs 2/2.
- **Strongest new fact: `cmp` shows the old (`~/.bb-target-src/bb`) and new
  (`~/.bb-target-src-v5.0.1/bb`) oracles are BYTE-IDENTICAL binaries** (all
  45,391,032 bytes) — ch. 19's empty-diff conclusion confirmed at the whole-
  binary level, doc-independent.
- monty-hall: 12/13 claims confirmed (TXE 10 tests incl. full game + wrong-vk
  + replay + access-control negatives; ZK::Yes in the prover; keyless
  ChoiceNote nullifier; raw context primitives + HONK_ZK=6; postgres
  migrations; e2e trial logs 3×PASS with exactly one deliberate tamper
  BBApiException each). ONE CONTRADICTION found: `noir_logic/pss_utils`'s
  `protocol_types` was still a live path dep into `~/ap-next` — the exact
  drift-hazard class behind the 2026-07-20 confound; the re-pin had fixed the
  contract but missed the circuits.

**Monty-hall dependency rework (Mike: vendored snapshot = code smell; use the
released package):** the 22 MB `contract/.pinned-aztec-packages-v5.0.1/`
snapshot AND the pss_utils `~/ap-next` path dep were replaced by nargo git
deps pinned to the immutable public release tag (`{ git = aztec-packages,
tag = "v5.0.1", directory = ... }`) — the documented aztec-nr consumption
path; npm (e2e) and aztec-up (toolchain) were already on released 5.0.1.
Equivalence PROVEN, not assumed: differential compile git-dep-vs-snapshot →
artifacts byte-identical modulo `file_map` source paths; `aztec_process` all
6 VKs cache-hit; `check.sh` PASS (incl. note-hash/nullifier byte KATs that
would catch any protocol_types drift); TXE 10/10; mpc full-game cargo test
4/4 re-run against freshly restaged `data/circuits/*.json` (bytecode+ABI
byte-identical to prior copies). Snapshot retired to session scratchpad
(regenerable from the tag). Honest caveats recorded in the finding doc §10:
`mpc/e2e.sh` + real-proving `e2e/run.sh` not re-run (inputs proven identical,
but the real-proving run remains the definitive gate — do once, after scoping
`run.sh`'s indiscriminate `pkill -x anvil`); git tags are immutable by
convention not mechanism (nargo's local cache + the KATs mitigate).

**Housekeeping:** stray `codegenCache.json` (aztec.js debris from bisection
work) deleted from co-snarks root. `~/.bb-target-src-v5.0.1/PROVENANCE.txt`
corrected: v5.0.1 DOES ship prebuilt bb release assets (GitHub API-checked;
the file claimed none exist) — policy stays source-built-oracle regardless.
Raw e2e evidence logs left untracked + gitignored in monty-hall (decisive
lines are quoted in the reports) per Mike.

**Commits (Mike's explicit ask, local only, never pushed):** monty-hall
`fdaa8de` (deps re-pin) + `f028b73` (the five 2026-07-20 investigation
reports); co-snarks: this session's two commits (v5.0.1 pin flip + script
fixes; ch. 19 + PLAN/PROGRESS).

**Known-stale items deliberately NOT fixed in this session's commits (next
docs pass):** PLAN 5.1 status blocks still end at the session-11 saga (don't
yet record the 2026-07-20 resolution: game passes at consistent v5.0.1, bug
was a pin-mismatch confound); the committed
`clientivc-recursive-verify-fails-in-app.md` header ("BROKEN on v5") is
superseded by the newer reports; monty-hall `versions.env` still names the
old oracle path (harmless — binaries proven byte-identical). NEXT: that
reconciliation pass, then one real-proving e2e re-run, then 5.1d (TS
orchestration port).

## Session 13 (cont.) — 2026-07-23 evening — next stages kicked off: docs reconciled, ch. 20 + ch. 21 written, full sweep run with parallel-isolated suites

Command-level record: ch. 14 §27. Mike's steers this stretch: kick off the
plan's next stages; full test sweep via a Sonnet agent; then (after the
serial sweep stalled and history repeated the unnoticed-completion problem)
**parallelize testing** — suites as main-session background tasks with
isolated resources, never one serial mega-agent (memory:
[[parallel-test-orchestration]]); be meticulous that script changes don't
drop any gate; keep PROGRESS + ch. 14 current; write a pre-TS tidying plan.

- **Docs reconciliation landed** (the items the morning entry flagged):
  PLAN 5.1 RESOLUTION block (final story: vintage-mismatch confound → 3/3
  real-proving PASS at consistent v5.0.1 → release-tag git deps; upstream
  frozen-fixture contradiction open but not ours) + Phase-3 moot note;
  status-correction banner on the committed clientivc bug report; ch. 18 §6
  banner'd resolved/historical; monty-hall `versions.env` oracle pointer
  aligned to `~/.bb-target-src-v5.0.1/bb` (byte-identical binary — label
  alignment only); README index gained the missing ch. 19 row.
- **Ch. 20 written** (5.1d TS orchestration workplan; grounded in a full
  read of the Rust orchestrator + protos + driver): only the orchestrator
  ports (nodes stay Rust; driver already TS); frozen HTTP/error contract so
  driver + e2e suites are the acceptance gates unchanged; bb.js-verify
  spike T1 (bb-CLI fallback); the ark-LE vs JSON-BE field-codec trap;
  T0–T6 ≈ 2 sessions. ch. 16 §7 stub now points at it. **Decision (Mike):
  5.1d executes in a FRESH session** — ch. 20 is written to be cold-start
  self-contained.
- **e2e scripts made parallel-safe** (mpc/e2e.sh + e2e/run.sh): env knobs
  MPC_GRPC_BASE_PORT / MESH_BASE_PORT (suite-local party*.toml generated on
  offset, with a 10001/10002 cascade guard) / PG_BASE_PORT / PG_PREFIX /
  ORCH_PORT; cleanup traps converted from pattern-pkill to PID-scoped kills
  (pattern kills would take down a concurrent suite); run.sh's anvil/network
  sweep additionally cwd-scoped (the 2026-07-20 collateral-kill hazard,
  fixed BEFORE any e2e was launched tonight). Meticulousness audit: full
  diffs reviewed; defaults identical to the old literals; suite-B log shows
  all 9 gate sections executed (4 bb cross-verifies + tamper + chained-value
  sanity); no leftover processes/containers after runs.
- **Sweep results (fresh, tonight)**: A1 check.sh PASS ×2; A2 TXE 10/10 ×2;
  A3 mpc cargo 4/4 ×2; **B mpc/e2e.sh PASS** on isolated ports (its first
  attempt FAILED only because the default gRPC port 8000 is squatted by an
  unrelated python http.server — node0 EADDRINUSE; do-not-kill rule
  respected, isolation knobs are the fix); **C real-proving on-chain e2e
  PASS** — 7 genuine multi-second ClientIVC proofs, exactly 1 deliberate
  tamper rejection, GAME COMPLETE — the FIRST full real-proving run since
  the git-dep re-pin, closing that loop end-to-end. B ∥ C ∥ D1 ran
  concurrently without interference (the redesign validated in anger).
  D1 (fast-check --full) + D2 (compare.sh) still in flight at this entry;
  results to be appended.
- **Fresh MPC proof timings** (suite C, driver-side, contended box):
  sample_rand 0.51 s; init_game 3.76 s; open_door 3.97 s; finish_game
  3.84 s — same order as the client's own ClientIVC tx proving (3.4–5.4 s)
  in the same run. Uncontended per-party record remains ch. 14 §26 / A4
  (witext 0.85 s + pk 0.15 s + ZK prove 1.74 s).
- **Why D-tier is slow + serial** (Mike asked): compare.sh/compare_mpc.sh
  write into the same test_vectors/<circuit>/ paths (verified — both rm -f
  the same files), so they can't overlap today; the acceptance matrix is
  128 cells (32 circuits × 2 hashers × 2 zk-modes) each with a 3-party MPC
  prove. Sharding fix filed as ch. 15 §4.9a.
- **Ch. 21 written**: pre-5.1d tidying plan (M1–M7 monty-hall incl. the
  now-stale README pins paragraph; C1–C6 co-snarks incl. TODO triage and
  the deferred SSIPA A(1)=0 test as the one real engineering item; X1–X3
  cross-repo). Decision recorded: tidy the tree, not the git log (branches
  never push, history = audit trail).
- All of tonight's work is UNCOMMITTED pending Mike's word (X1).

## Session 13 (cont. 2) — 2026-07-23 night — tidying executed in parallel; D-tier sharded (~2.2×); SSIPA test closed; reviews + overnight bench launched

Mike's steers: stop/parallelize D1/D2 (D1 finished on its own first — full
serial PASS: 106/106 cargo + 128/128 compare_mpc cells, rc=0, ~27 min);
implement ch. 21 in parallel; be meticulous that no gate is lost; spawn
adversarial correctness reviews of both codebases; schedule the 0.5
benchmark overnight after explaining its worth + a WAN-latency estimate.

- **D-tier parallelization (ch. 15 §4.9a) DONE + validated**: compare.sh +
  compare_mpc.sh gained `CIRCUIT_FILTER` (unknown-name = hard error),
  `CONFIG_DIR` (per-shard REP3 mesh ports), and per-circuit
  `cleanup_circuit` replacing the global cleanup.sh (which would have let
  concurrent shards wipe each other). New `scripts/acceptance-parallel.sh`
  extracts the circuit lists FROM the scripts, weight-packs into shards,
  and hard-asserts shard-union == full matrix (the assertion caught its
  own first bug — an empty-element artifact — by refusing to run).
  **Validated: full 33-circuit plain+MPC matrix PASS in 1003 s (~17 min)
  vs ~36 min serial for the same coverage (~2.2×), with perfectly balanced
  shard weights (20/20/20/20).** `fast-check.sh --full` now routes through
  it (and thus now includes the plain compare.sh matrix it never ran).
- **Ch. 21 tidying: all items except M3/M7/C6-commit DONE** (two Sonnet
  agents + orchestrator; per-item annotations in ch. 21). Highlights:
  monty-hall README/pins truth pass; stale 20260708 labels fixed; 4 repro
  drivers → `upstream-issues/repro-tools/`; cargo fmt/clippy + nargo fmt
  clean; gates re-run green. co-snarks: TODO triage (162/163 upstream,
  the 1 ours deleted with an as-verified replacement note); debris sweep
  CLEAN (no 2.9 instrumentation leaked — all tracing/allows byte-identical
  to upstream base); 4 truth banners (ch. 02/04×2/05). Open for Mike:
  delete tracked dead dev-certs `noir_logic/network/data/*.der`? Also
  killed our own orphaned 2026-07-13 `oracle_stub.py` (port 5599).
- **C4 / ch. 13 §3a#8 CLOSED — the last deferred security regression**:
  new `zk_proof_ssipa_evaluation_tamper_rejected` (tampers each of the 4
  transmitted Libra/SSIPA evaluation fields; clean reject, no panic),
  implemented in an isolated worktree with red-mutation validation and
  transplanted; main-tree suite now 10/10. **Bonus finding: co-noir binds
  the SSIPA evaluations twice independently (Shplemini/KZG batched opening
  AND the consistency identity) — defense-in-depth; the test only goes red
  with BOTH backstops neutralized.** The historical "kernel-perturbation"
  framing is a prover-side forgery not reachable by byte-tampering (evals
  are absorbed pre-Shplonk-challenges); the byte-tamper form is the right
  regression. PLAN 2.7 + ch. 13 updated.
- **Adversarial correctness reviews launched** (Mike's ask, full-strength
  model, read-only): (1) co-snarks sync diff — verifier laxity vs bb, MPC
  shortcuts, swallowed errors, test integrity; (2) monty-hall — contract
  binding layer, circuit soundness, operator replay/proof-swap, ch. 17
  §6.8 claims vs code. Results to be appended when they land (M3's ch. 17
  status pass deliberately waits on the monty-hall one).
- **PLAN 0.5 benchmark SCHEDULED overnight**: `scripts/bench-0_5.sh`
  (3 circuits × REP3/Shamir-best-effort × zk/non-zk × 3 reps, per-phase
  timings vs bb + plaindriver baselines, 16 threads/party) +
  `bench-0_5-launcher.sh` (waits for a genuinely quiet box — 2×5-min
  checks — 10 h cap then runs flagged CONTENDED). Results →
  `~/bench-0_5-results/2026-07-23/results.csv`. WAN estimate recorded for
  Mike: cost model T ≈ compute + R×latency with R ≈ 1–3k sequential rounds
  (Poseidon2-depth-dominated witext) → same-DC ~1.2×, same-region ~3–15×,
  equidistant-planet (RTT 200–350 ms) **~2–9 min/proof (~30–150×)** —
  latency-bound, bandwidth irrelevant; pinning R exactly (mpc-net
  ConnectionStats) is the natural bench v2.
- Fresh monty-hall proof timings re-confirmed for Mike (suite C driver-side,
  contended): 0.51/3.76/3.97/3.84 s per round vs client's own ClientIVC tx
  proving 3.4–5.4 s in the same run.
- Still open: M3 (ch. 17 status pass, waits on review), M7/C6/X1 (commits —
  Mike's word), X3 (memory refresh at session end), review results, bench
  results.

## Session 13 (cont. 3) — 2026-07-23 night — R1 committed; overnight 0.5 bench armed with self-documenting output (Mike → bed)

- **R1 fix committed** (`672ade11`): non-canonical basefield limb encodings
  now rejected at the parse boundary (transcript + VK loaders) in RELEASE
  builds — closes the co-snarks-review finding. Red-validated; security_
  regression 10→11; VK byte-KATs unchanged (honest parity intact);
  fast-check --all-fast PASS. Transplanted from the agent worktree, worktree
  removed. **All this-session work is committed on both branches; nothing
  pushed. Trees clean (only .claude/ untracked, now gitignored).**
- **Overnight PLAN 0.5 benchmark ARMED** (Mike going to bed; must
  self-document). Detached launcher (`nohup`, survives logout):
  `scripts/bench-0_5-launcher.sh` → waits for a genuinely idle box (2×5-min
  quiet checks, load<25 + no heavy procs; 10 h cap then runs flagged
  CONTENDED) → `scripts/bench-0_5.sh`.
  - **What it collects (the data the explorer needs):** per-phase wall-clock
    (split / witext / prove / verify) × {poseidon, sha256_compression,
    recursion_zk} × {bb, plaindriver, REP3, Shamir} × {ZK, non-ZK} × 3 reps,
    16 threads/party, loopback. That fixes the site's COMPUTE anchors and
    the REP3-vs-bb ratio + ZK overhead at 3 real circuit sizes. Distance/
    latency and comms-rounds R stay MODELED by construction (can't place
    nodes across the planet locally; bench v2 = netem + mpc-net
    ConnectionStats would measure them).
  - **Where results land:** `~/bench-0_5-results/2026-07-23/` —
    `launcher.log` (progress), `results.csv` (raw), `site-anchors.json`
    (medians for the site; nulls where unmeasured, never fabricated),
    **`RESULTS.md`** (human-readable per-circuit tables — the entry point for that run's data).
    A CONTENDED run is banner-flagged in both.
  - **Overnight/next-session plan (for whoever the completion notification
    wakes):** on `BENCH_DONE`, (1) read `RESULTS.md`/`site-anchors.json`,
    (2) append a results entry HERE, (3) bake `site-anchors.json` into the
    explorer's ANCHOR/CIRCUITS block + flip those cells' badges to measured
    (ch.22 V7), (4) redeploy the SAME artifact file path to keep the URL
    (https://claude.ai/code/artifact/90d4bf98-8b70-4f9e-814b-5d07b20daefa).
    Redeploy of a private artifact is autonomous-safe.
- **Explorer link** recorded in `ARTIFACTS.md` (gitignored, top-level) and
  ch.22 V6. tmux clipboard help in ARTIFACTS.md; MacBook→ssh→tmux specifics
  added this session (mouse-off toggle / iTerm2 ⌥-select+⌘-click /
  Terminal.app Fn-select).
- **STILL OPEN for Mike:** F1 (cross-deployment seed reuse — VK/ABI-breaking,
  design in ch.17 §7) awaiting greenlight; F3/F6; the small stale-doc pass;
  5.1d TS port (ch.20, fresh session). None blocking.

## Session 14 — 2026-07-24 morning — PLAN 0.5 bench RAN CLEAN overnight; results baked into the explorer (V7 done)

- **The overnight bench ran, clean and fresh**: launcher waited out a busy
  box (~1.3 h of load-83–178 readings from the session-13 parallel work),
  got its 2×5-min quiet checks (load 20→16), ran 22:11:39→22:46:19 UTC
  (2026-07-23), `BENCH_DONE rc=0`, NOT contended. Dataset (outside the
  repo by design — hence a clean git tree): `~/bench-0_5-results/2026-07-23/`
  (manifest.json / results.csv / site-anchors.json / RESULTS.md / logs).
  Provenance: co-snarks `101544e8`, bb v5.0.1 source-built oracle,
  nargo beta.22, 16 threads/party, loopback, medians of 3.
- **Headline numbers (ZK, medians)** — and the headline FINDING: REP3÷bb is
  NOT a constant factor, it tracks gate COMPOSITION, not circuit size:
  | circuit | bb | plaindriver | REP3 3-party | REP3÷bb |
  |---|---|---|---|---|
  | poseidon (2^11) | 0.170 s | 0.671 s | 1.026 s | **6.0×** |
  | bb_sha256_compression (2^15) | 0.355 s | 5.337 s | 156.067 s | **439.6×** |
  | recursion_zk (2^19.4, 704k rows) | 4.493 s | 89.830 s | 133.773 s | **29.8×** |
  sha256's boolean-heavy gates are disproportionately expensive in
  arithmetic MPC — the REP3 cost curve is genuinely non-monotonic in gate
  count (sha256 at 2^15 costs MORE than recursion_zk at 2^19.4). Other
  reads: ZK overhead is small (1.00–1.13× per circuit — REP3 proving is
  already randomness-heavy); split/witext/verify are noise next to prove
  (≤0.35 / ≤0.55 / 0.015 s); plaindriver (ch. 23's target) is 3.9–20×
  slower than bb single-prover.
- **Shamir cells: all SKIPPED (rc=1), by design not by crash** — co-noir's
  `split-input` is REP3-only (`co-noir.rs:1078`). Bench v2 fix: split as
  REP3 then `translate-witness` REP3→Shamir. Recorded in the explorer as
  modeled (REP3×1.05), badge unflipped.
- **Aggregator bug found + fixed** (`scripts/bench-to-site.py`,
  uncommitted): split/witext rows are stamped `zk="-"` in the CSV but were
  looked up under `zk=nonzk/zk` → emitted as null/`—` despite being
  measured. Fixed the lookup, regenerated site-anchors.json + RESULTS.md
  from the untouched results.csv (their 08:28 UTC mtime is this
  regeneration; the raw data is last night's).
- **Explorer V7 DONE, same URL** (ch. 22 §7 V7 ticked): CIRCUITS/ANCHOR
  block now carries the measured medians (all three circuits × bb/plain/
  REP3 × zk/nonzk + REP3 phase times); the old constant-factor model
  (rep3=2.0×bb, zkMul 1.18) REPLACED by log-log interpolation THROUGH the
  measured anchors per config×zk-mode (verified: model at every anchor
  reproduces the measured value exactly); comms model now adds only
  above-loopback latency (measured loopback points already contain loopback
  comms); ◆ markers on every exactly-measured point; assumptions table +
  footer rewritten (measured rows cite the bench, Shamir/plain-nonzk/R
  stay modeled). Antipodal sanity check: model gives ~5.1 min/proof at
  RTT 280 ms — inside session-13's 2–9 min WAN estimate.
- Uncommitted (Mike's word required): `scripts/bench-to-site.py` fix,
  ch. 22 V7 tick, ARTIFACTS.md note, this entry.

## Session 14 (cont.) — 2026-07-24 — bench v2 built + smoked (R measured!); ch. 24 opened; lit survey in; ch. 23 B1 refuted by measurement

Mike's asks this burst (all tracked in PLAN 0.5 v2-block + new PLAN Phase 6):
results in-repo; measure comms rounds R ("is R constant?"); theory-driven
circuit features (read the UH prover code, not just guesses); bench-runtime
optimisation w/o accuracy loss; size sweeps (poseidon 2^11/2^17..2^20,
sha256 2^15..2^20, 10-min cell cap); start optimising before the re-run;
new plan for optimising the co-snarkification itself (parity + sound
sharing preserved, NO cheating); property-preservation tests; batching-vs-
sequential question; lit survey.

- **Bench v2 pipeline WORKS end-to-end** (smoke on poseidon, scratchpad):
  v1's `bench-0_5.sh` rewritten — in-repo `bench-results/<date>/`,
  netstats/ + features/ capture, ascending size sweeps with 600 s timeout
  pruning + 2 reps ≥2^18, fair baselines (bb `vkgen` split out + `-k`;
  plaindriver witness-fed via `--input`+`--witness` — needed both, `input`
  is a required field; old solve+prove kept as `solveprove` phase), dead
  Shamir cells dropped (v2.1 = translate-witness), REP3 VK hoisted out of
  the rep loop, `BENCH_CIRCUITS` smoke override. bench-to-site.py v2:
  netstats R/bytes aggregation, features join, new phases; regression-
  tested against the v1 dataset (identical medians, nulls where v2-only).
- **mpc-net message counters + CLI stats LANDED** (agent; fast-check PASS,
  all 5 backends): `ConnectionStats` gains per-peer msg counts;
  `CO_NOIR_NET_STATS_JSON` dumps per-phase JSONs from generate-witness /
  build-and-generate-proof / translate-* / etc. `circuit-info` subcommand
  extended (was plain-text): block composition, lookup gates/tables/table
  rows, opcode histogram, witness zero-fraction. CAVEAT found: co-noir CLI
  uses TCP, NOT the TLS section in party*.toml (ignored by this binary).
- **FIRST MEASURED R (poseidon 2^11, loopback)**: witext R=366 (14.6 KB);
  prove R=319 nonzk / 393 zk (~6.3 MB party-0 sent; ZK delta ≈74 rounds =
  SSIPA/masking). 319 ≈ 10 relations × 11 sumcheck rounds + grand-product/
  fold/open — confirms the sequential-per-relation reshare structure in
  `co_sumcheck_round.rs` and sizes L1's headroom (~100 rounds). WAN: at
  140 ms one-way, prove-ZK = 393×0.14 ≈ 55 s latency floor for ANY small
  circuit. Mike's batching q answered in ch. 24 §2: FS forces phase order
  only (challenges are computed locally from the public transcript);
  sumcheck rounds are the one inherent sequential chain; within-phase is
  batchable — TACEO's own `TACEO TODO could batch` markers (~25 sites)
  inventoried.
- **Ch. 24 written + indexed** (MPC-path optimisation): REP3 op price
  list from code; round DAG; sha-440× hypotheses H1–H4 ranked with
  discriminating measurements (H1 REFUTED for oink logderiv — properly
  batched, 2 rounds; still open for sumcheck relation path + skip-parity
  audit); levers L1–L7; §5 property tests (comms-floor asserts off the new
  msg counters, share re-randomization invariance → identical non-ZK
  bytes, view-scan tripwire); §6 lit survey.
- **Lit survey (agent, full report in its transcript; distilled ch. 24
  §6)**: TACEO Apr-2025 measured 10–20× MPC-sumcheck gain "chiefly from
  round reduction" (our tree post-dates it; R=319 is the leftover);
  no published lookup-vs-arithmetic overhead split exists — our
  6×/29.8×/439.6× composition finding is ahead of the public literature;
  MPlookup (2026/844) + eprint 2025/1388 corroborate lookups-as-pain;
  parity-safe leftovers = Montgomery-tree batched openings, mask
  pipelining, edaBit witext conversions; transcript-changing tricks
  parked for a parity-relaxed future.
- **Ch. 23 B1 REFUTED + corrected in place**: arkworks `parallel` (+ ff
  `asm`) were ALREADY ON via feature unification (cargo tree verified;
  explicit-features edit rebuilt nothing). Features now pinned explicitly
  in workspace Cargo.toml (drift protection, no behavior change). Fair
  witness-fed sha256 plaindriver baseline: ~4.67 s (v1's 5.34 included
  ~0.6 s witness solving) vs bb 0.36 s — the gap is co-ultrahonk's own
  single-threaded passes (Phase C) / allocation (Phase D). Profile is now
  mandatory before the next lever (samply installing; box must also be
  quiet — variants agent still compiling poseidon_2e20, K=743).
- All 9 size variants landed + verified on-target (poseidon_2e17..2e20,
  sha256_2e16..2e20; e.g. poseidon_2e20 rows 1,047,632 → dyadic 2^20).
  Final runtime cuts before launch (Mike's ask, checked): skip
  `nargo execute` when the witness exists (minutes/big circuit), non-ZK
  plaindriver only <2^18, solveprove only on base circuits; re-smoked
  green (33 rows, 0 failures). **Bench v2 ARMED 09:52 UTC 2026-07-24**
  (launcher waiting for quiet; ~2.5–3.5 h run; watcher armed on
  BENCH_DONE). Results → `bench-results/2026-07-24/`.
- Data enrichment pass (Mike: "gobble up all data for the site"), landed
  BEFORE the run started (launcher was still idle-waiting; verified with a
  non-self-matching pgrep): per-cell **peak RSS + CPU%** (new CSV columns
  max_rss_kb/cpu_pct via /usr/bin/time; MPC cells report max-RSS over the
  3 parties, per-party wall/RSS/CPU% in `mem/` → party-skew data);
  **artifact sizes** per circuit (`features/<c>.artifact-sizes.json` —
  smoke shows proof = 14,656 B identical across bb/plaindriver/REP3);
  manifest + kernel + cpu_model; aggregator + RESULTS.md updated (Peak
  memory line, rss_mb fields, artifact_sizes in site-anchors.json).
  Smoke 5: 0 failures, all new fields populated.

**⚠ 12:05 UTC: bench v2 DISARMED before ever starting (Mike).** The
launcher's load<25 quiet-gate never passed — and the reason reframes the
methodology: mike-box is a sysbox on a SHARED mainframe, so /proc/loadavg
and fork counters are HOST-wide; the "load 70–114, ~1,000 forks/s with no
visible processes" I chased for an hour was other tenants. Quiet time may
simply never come. Bench v2 relaunch needs a gate rethink first (see the
runbook addendum below). Launcher + BENCH_DONE watcher both killed; all
script/aggregator enrichments (progress+ETA logging incl.) are in the
tree, smoke-tested, ready.

### NEXT STEPS (written down in case of context loss — the runbook)

**Step 0 (NEW, before any relaunch) — replace the launcher's quiet-gate:**
load average is host-wide and useless here. Options: gate only on OUR
processes (no compare/cargo/nargo/party procs of ours), run at a fixed
time regardless and stamp host load into the manifest per-cell
(loadavg before/after each cell as noise columns), raise reps + rely on
medians, and prefer same-window relative ratios (REP3÷bb) over absolute
seconds. Decide with Mike when to actually run.

**On BENCH_DONE (watcher fires; results in `bench-results/<date>/`):**
1. Read `RESULTS.md` + `launcher.log` (CONTENDED? rc? timeout-pruned rows
   rc=124?). Sanity: medians vs v1 for the 3 base circuits (bb/REP3 cells
   should reproduce v1 within noise; plaindriver prove is now witness-fed
   so LOWER than v1 — expected, not a regression).
2. The two headline questions: **R vs size** (netstats: is prove-R ~
   10·log n + const across the poseidon sweep? sha vs poseidon at equal
   dyadic?) and **features vs time** (join features/*.circuit-info.json:
   does lookup_gates+table_rows predict the REP3÷bb ratio across the
   sweep?). Append findings HERE + ch. 24 §3 (which hypothesis won).
3. Bake into the explorer: `site-anchors.json` now has many more anchors +
   net data — extend the ANCHOR/CIRCUITS block (same file
   `/tmp/claude-1011/-mnt-user-data-mike-co-snarks/54a7d64f-f266-4b16-8a50-4d55433d7a15/scratchpad/cosnark-explorer.html`,
   pass url to keep https://claude.ai/code/artifact/90d4bf98-8b70-4f9e-814b-5d07b20daefa;
   consider swapping the modeled R slider default to measured R).
4. Ch. 22 §5a/V7 note the v2 dataset; PLAN 0.5 → mark v2 RAN.

**Then (PLAN Phase 6, order per ch. 23/24):**
5. Ch. 23 clean Phase A on the now-idle box: per-phase wall attribution
   (oink/sumcheck/shplemini/PCS coarse timers or tracing spans) × 3 base
   circuits + samply with symbols (release now has debug=true); pick
   Phase C items by share. Then LTO(+cg1) and target-cpu=native as two
   separate gated units (fast-check parity + before/after sha256 timing).
6. Ch. 24 L1 (round batching, TACEO TODOs) in a worktree, one batching
   per gated change; T3 share re-randomization test alongside (cheap,
   fences the work). T2 comms-floor thresholds: derive from tonight's
   netstats medians (that data now exists).
7. Bench v2.1 backlog: Shamir via REP3-split + translate-witness;
   netem latency sweeps (distance axis → measured); rerun after each
   landed optimisation unit (PLAN 6.4).

**Afternoon burst (12:00–13:00): dataset infrastructure + parallel units.**
- Bench v2 DISARMED pre-start (Mike; shared-mainframe quiet-gate is dead —
  see 12:05 note + memory update). Absolute seconds stay primary; every
  CSV row now stamps `host_load1m` (smoke-verified at host load 86–88).
- Mike's measurement-audit table → ch. 22 **§5b** (every measured quantity,
  unit, mechanism, ✅/⏳ status — grep-verifiable against the script).
- **Circuit features captured for all 12 matrix circuits WITHOUT the bench**
  (`bench-results/circuit-features-2026-07-24/`): sha256 = ~70% lookup
  gates + constant 33,944 table rows (dyadic 2^16 with tables — v1's
  "2^15" label was pre-table, explorer to be corrected at the v2 bake);
  poseidon variants pure arithmetic, witness ~74% zeros; recursion_zk =
  the delta-range+aux+elliptic mix, no plookup. The sha 2e16→2e20 sweep
  scales lookup gates 17× at CONSTANT table rows — clean natural
  experiment separating the two lookup-cost suspects.
- **`bench-results/bench.sqlite`** (Mike: "store in a db for later
  visualisation"): `scripts/bench-ingest.py` rebuilds it idempotently from
  all run dirs (+ legacy v1). Tables runs/cells/medians/netstats/features/
  artifact_sizes + `overhead` view (REP3÷bb joined with composition).
  Validated: medians == v1 RESULTS.md exactly. Gitignored (derived).
- **`bench-results/README.md`** = the pick-up-here doc (layout, schema,
  quick-start, shared-mainframe rules, current state).
- Launched in parallel worktrees: T3 share-re-randomization test
  (ch. 24 §5) and L1 grand-product round batching (ch. 24 §4).
- **T3 LANDED in main tree** (~13:20): test green in 4.3 s, red-validated
  3 ways (decisive: XOR a share byte into the serialized proof → fails at
  the exact target assert). ch. 24 §5 T3 marked DONE. API finding:
  `split_witness_rep3` hard-codes thread_rng() — unseedable.
- **L1 validated on the WRONG BASE — being re-ported.** The agent's
  result is strong: grand-product comms 16 rounds → 8 (helper made
  communication-free + one concatenated mul_many for the 4 independent
  products; num/denom pair merged; the two prefix-product chains through
  the existing array_prod_inner_mul_many utility), measured −8 ring
  rounds −2 open rounds, proof bytes identical, gates green — BUT the
  worktree harness based it on Taceo's origin/main (86340f52), not
  mc/update-co-noir: our co_oink differs by ~95 lines (ZK-aware gp_start/
  final_active_wire_idx structure) and its parity gates prove nothing
  about our tree. Port agent relaunched on a manually-created worktree
  off 53801f59 with explicit base verification. TRAP RECORDED in memory
  (worktree-agents-wrong-base): always check `isolation: worktree` base
  before trusting/transplanting. T3 was audited for the same trap — its
  patch is additive, applied cleanly, and its gates were re-run in OUR
  tree before landing, so it stands.
- Agent's bonus finding for later: array_prod_inner_mul_many's two
  internal mul_many calls are independent → one more −1 round available;
  left for a follow-up unit because it's shared with co-acvm's is_zero.

**Late-afternoon burst (13:30–15:00): L1 LANDED on our branch; B2/B3 measured out; Phase A delegated.**
- **L1 port LANDED in main tree**: re-implemented against 53801f59
  preserving our ZK-aware gp_start/final_active_wire_idx structure; gates
  on OUR branch: plain 2/2, rep3+shamir 41/41 (incl. T3), rep3::poseidon
  proof-byte KATs 4/4, recursion_vk_kat 1/1, then 7/7 after transplant
  (with-LTO build). compute_grand_product comms: **16 → 8 rounds**,
  correlated-randomness totals unchanged. ch. 24 L1 entry updated.
- **B2 (LTO) MEASURED + DROPPED**: byte-parity green first (compare.sh
  poseidon+sha vs bb oracle, 0 errors, LTO binary); then interleaved A/B
  (8 pairs fat-vs-none: "−5%" at load 80–135) and a calmer 3-way (6
  triples none/thin/fat: ALL within ±2% — noise floor; the −5% was
  noise). Cost side: fat link ≈ 4.5 min/rebuild vs ~40 s. Flags removed,
  measured-rationale note left in Cargo.toml, debug=true kept. ch. 23 B2
  updated in place. **B3 (target-cpu) deprioritised**: ark asm is inline
  asm independent of target-cpu; after B1+B2 both refuted, revisit only
  if the profile shows generic field-code leaf time. Ch. 23's whole
  Phase-B shelf is now empty-by-measurement — the gap is algorithmic
  (Phase C), exactly what the §A-prelim ~68%-parked-workers sample said.
- **Phase A delegated** (agent, main tree, docs off-limits): check
  existing tracing spans first; else env-gated permanent phase timers
  (CO_NOIR_PHASE_TIMINGS=1) in the plain path only; 3 circuits × 3 reps,
  loadavg stamped; deliverable = per-phase % table + parallelisation
  order. Results pending — do not assume.
- LTO A/B binaries kept in scratchpad for reference; main tree rebuilt
  no-LTO (1m05s), consistent state.
- **Phase A MEASURED (agent; ch. 23 §A table now authoritative):
  sumcheck = 60.5% (sha 2^16) / 54.0% (recursion 2^20, 26 s of 48.3 s)
  of plain proving; oink second (25.5% at 2^20); shplemini 6%; opening
  MSM ~1%; small circuits bound by the 0.33 s JSON parse (61% of
  poseidon!).** Permanent env-gated timers landed
  (`CO_NOIR_PHASE_TIMINGS=1`, stderr, zero effect otherwise; parity
  re-verified): co-ultrahonk lib.rs + co_ultra_prover.rs +
  co_decider_prover.rs + plaindriver.rs. Phase-C order fixed by
  evidence: C1 sumcheck edge loop → C2 oink (grand-product prefix scan /
  inverse batches; its MSMs already parallel) → C3 shplemini batching.
- **C1 agent LAUNCHED** (main tree, sumcheck files only, co_oink
  off-limits): rayon the per-edge relation accumulation for the plain
  driver, exact tree-reduce (field sums exact ⇒ bytes provably stable),
  ZK row-disabling/skip logic preserved per-row; gates = plain KATs,
  rep3+shamir suite, recursion VK KAT, phase-timer before/after on
  sha+recursion. Results pending — do not assume.

**Evening burst (Mike: "fuck yeah, keep optimising" + test discipline):**
- fast-check re-run on the full landed stack (T3 + L1 + phase timers):
  **PASS, 1.52 s inner loop** — the discipline holds after each unit.
- **Test-tier convention (Mike's fast/slow ask), applied henceforth:**
  every optimisation unit ships with tests that are (a) reachable by
  fast-check's existing filters and sub-5 s in-process → FAST tier, or
  (b) marked #[ignore] with a comment naming the suite that runs them
  (acceptance-parallel/full sweep) → SLOW tier. This session's additions
  are all FAST: T3 rerandomization (~1 s, rides the rep3::poseidon
  filter), C1's thread-count-invariance test (requested from the agent
  mid-flight: 1-thread vs 16-thread scoped rayon pools must yield
  byte-identical plain proofs — catches nondeterministic-reduction bugs
  structurally, not just for KAT-pinned circuits). T2 comms-floors stay
  queued until bench v2 netstats set the thresholds.
- **JSON-parse quick-win agent LAUNCHED** in parallel (disjoint files:
  parsing path only, co-ultrahonk off-limits): root-cause the 0.33 s
  read_circuit (61% of small-circuit total; classic suspect: unbuffered
  serde_json::from_reader), fix only if accidental, add a fast parsing
  unit test. Results pending — do not assume.
- Optimisation queue after C1: C2 oink internals (grand-product prefix
  scan + inverse batches — now both round-batched by L1 AND
  parallelisation targets), C3 shplemini batching, ch. 24 L1 follow-up
  (−1 round in array_prod_inner_mul_many, shared with co-acvm is_zero).
- **C1 LANDED: sumcheck ~8.2× on recursion 2^20 (32→4 s), prove_total
  ~2.5× (52→20.5 s); sha 2^16 sumcheck ~6.2×, total ~2.8×.** Hybrid
  design (plain: per-chunk build+accumulate, exact-addition merge; MPC:
  order-preserving concat reproduces the sequential batch exactly —
  scheduling untouched). Full record: ch. 23 §C ledger. Gates green in
  MY tree after landing: fast-check PASS + thread-invariance test 0.32 s.
  C1 agent's fine split of sumcheck internals also recorded (relation
  accumulation 16.3 s vs build 1.1 s pre-change). C2 (oink) agent
  launched at the new dominant phase (~12.5–14.5 s: plain.rs elementwise
  ops, logderiv/grand-product row loops; measure-first brief). Sumcheck
  residual ~4 s (partially_evaluate) = C1b candidate.
- **JSON-parse fix LANDED (~80×: read_circuit 0.33 s → 0.004 s).** Root
  cause was one read(2) PER BYTE (unbuffered File into
  serde_json::from_reader; strace 317,557 syscalls → 26). One-function
  fix in noir-types (`read_to_end` + `from_slice`), mends every CLI call
  site incl. MPC party startup. Fast unit test added (~0 s,
  `noir-types tests::parses_program_artifact` + 810-byte fixture — note
  fixture lives in test_fixtures/ because target/ is gitignored).
  Gates: plain KATs 3/3, fast-check PASS. ch. 23 §A note updated.
- **C2 LANDED: oink 12.33 → 2.54 s (4.9×); prove_total 20.0 → 12.2 s
  (1.64×, conservative — after-reps at loadavg 71–106 vs before 12–20).**
  The root cause deserves its headline: plain `inv_many*` did ONE FULL
  EXTENDED-EUCLID INVERSION PER ELEMENT, serially — ~3M inversions
  ≈ 9.5 s of oink. Now ark_ff::batch_inversion (Montgomery, parallel):
  batch_invert ~300×, array_prod 14.7×. Plus plain.rs elementwise ops →
  rayon (helps all phases); oink row loops par-mapped order-preservingly
  (safe for all drivers — pure local ops; L1 structure preserved);
  permanent oink sub-timers. REP3/Shamir 0-line diff. Kept serial:
  RNG streams (thread-invariance!), prefix scans, MSMs (already
  parallel). New fast test batched_inversion_matches_serial_reference
  (0.05 s). Gates green; re-verified in main tree (fast-check PASS).
  Full record ch. 23 §C ledger. Note for ch. 24: the SAME serial-inv_many
  finding suggests checking whether the REP3 driver's local inversion
  work shares this class of issue.
- **C1b+C3 LANDED** (decider residuals): prove_total 10.2 → 8.0 s at
  2.5× higher after-load (matched-load rep: 7.80 s); partially_evaluate
  2.8×, shplemini batched_polys 6.5×, batched_quotient 3.0× with the
  Q/ν accumulation order kept exactly (bit-identical); size-gated
  parallel slice ops in the polynomial types. No new tests needed
  (elementwise/independent-task only; KATs + thread-invariance cover
  it). fast-check re-verified PASS by coordinator after landing.
- **DAY PUNCHLINE — plain prover, recursion_zk 2^20: ~52 s → ~8 s
  (~6.5×), proofs byte-identical throughout; gap to bb now ~1.8×
  (was ~11×).** Remaining profile: MSMs (parallel already), RNG
  (serial by design), fixed pipeline costs → ch. 23 Phase D is optional
  polish now. Every unit gated: fast-check PASS after each landing;
  fast-tier tests added today: thread-invariance 0.33 s,
  batched-inversion reference 0.05 s, artifact-parse ~0 s, T3
  rerandomization ~1 s. MPC path: L1 −8 rounds landed; ch. 24 notes the
  serial-inversion audit lead for the REP3 local paths.
- **Still open at close: bench v2 run (Mike's go) — now doubly valuable:
  it measures the post-optimisation baseline (R post-L1, times post-C*);
  commits (Mike's word); C2-residual leads (RNG/MSM); ch. 24 L2–L7;
  T2 comms floors (needs bench netstats); 5.1d TS port (fresh session).**

**Session hygiene:** tree has ~30 modified/untracked files, ALL
uncommitted (Mike's word required; list in this entry + git status).
New-session briefs Mike may run in parallel: 5.1d TS port (ch. 20,
monty-hall repo, no collision); L1 worktree (item 6). Both must avoid
heavy builds while the bench runs (check `pgrep -f bench-0_5`).

## Session 15 — 2026-07-25 — regression audit of the optimisation stack: all fast gates green; T2-lite comms fence landed; benchmarking-practice survey in

Mike's asks: was yesterday's work well-tested / write more tests where
useful; run the fast suite (NO long tests); enumerate remaining
optimisation + benchmarking tasks, taking inspiration from public
SNARK/co-SNARK benchmarking; judge commit-worthiness; think about
explorer-site enhancements.

- **Full fast tier re-verified on the landed stack: PASS.**
  `fast-check.sh --all-fast`: plain poseidon KATs incl. thread-count
  invariance (2.1 s), 11 security regressions (2.6 s), REP3+Shamir
  poseidon incl. T3 (15.1 s), and the live bb cross-verify — **VK +
  proof byte-identical to the source-built v5.0.1 oracle** on the fully
  optimised code. Crate-local unit tests (batched-inversion reference,
  artifact-parse) also green.
- **fast-check coverage gap FIXED**: the two crate-local unit tests were
  unreachable via `-p tests` — tier 1 now also runs
  `-p co-noir-common --lib mpc::plain::tests` and
  `-p noir-types tests::parses_program_artifact` (<0.1 s each).
  Re-ran: PASS.
- **T2-lite comms-message fence LANDED** (agent, main tree; coordinator
  re-ran gates independently):
  `poseidon_prove_comms_message_fence_poseidon2sponge` (rep3.rs, fast
  tier, rides the rep3::poseidon filter). Rationale: proof-byte KATs
  pass regardless of round count, so L1's 16→8 win was unfenced. Pins
  exact per-party (sent, recv) totals — pk-gen (116,116)×3 both nets,
  prove (199,199)×3 net0 — determinism confirmed across runs; proof
  bytes cross-checked vs the plain KAT (anti-shortcut). ch. 24 §5
  updated. rep3::poseidon suite 6/6 twice + once by coordinator.
- **Test gaps recorded, not yet closed**: thread-invariance covers only
  poseidon (pure arithmetic) — a slow-tier (#[ignore]) invariance test
  on recursion would exercise C1's lookup/elliptic/aux relation paths;
  ZK path can't be byte-fenced (masking RNG unseedable) — covered by
  verify-accept + tamper tests only; T4 view-scan still open; T2-proper
  (full-matrix floors) still wants bench v2 netstats.
- **Benchmarking-practice survey DONE** (agent, 15 sources, full cited
  report in the agent transcript; ranked backlog distilled to ch. 22
  §5c). Headlines: our metric set already covers the ZKProof cost
  taxonomy incl. rounds (which single-prover benches omit); NOBODY
  publishes a LAN/WAN sweep for co-SNARKs (incl. TACEO) — netem + the
  predict-then-validate model (zk-Bench pattern) would be first;
  Scalable-coZK's netem tiers adopted as our future tier definitions;
  cheap adds: bb/plaindriver verify phases, $-cost + TDP-energy columns,
  gates/sec normalization, cost-accounting disclosure, security-model
  caveat; TACEO:Proof's phone/laptop/MPC-network client-latency table
  is the presentation to emulate for the deployment story.
- **Commit recommendation given to Mike: YES** — all gates green, tree
  consistent; propose a series of small logical commits (JSON-parse fix,
  C1, C2, C1b+C3, L1, tests T3+T2-lite+invariance, phase timers, bench
  v2 suite + dataset infra, docs) so each unit is individually
  revertable. Awaiting Mike's word (hard rule).

**Midday burst (Mike's go: "do the commits… run the benchmarks in full… no need to wait for my input"):**
- **COMMITTED — the whole 2-day optimisation + bench stack, 8 logical
  commits on mc/update-co-noir** (Mike's explicit word, this burst):
  `4830a90a` build (ark feature pins + debug symbols, LTO measured out),
  `b466fb4b` mpc-net msg counters, `521f3672` noir-types parse fix,
  `ae631122` prover perf C1–C3+L1, `83a8bde9` co-noir CLI
  instrumentation (size-variant circuit SOURCES rode along here —
  compiled artifacts stay gitignored), `fb7c3f8b` tests + fast-check
  wiring, `0a005290` bench v2 suite + dataset home, + the docs commit
  after this entry. fast-check --all-fast PASS on the committed tree.
- **Bench suite finished per the §5c survey before launch** (Mike:
  "if you've built all the measurements you want"): NEW timed verify
  cells — bb verify per zk-mode (verifier-time baseline, ~19 ms
  poseidon) and plaindriver `verify_bb` (bb cross-verifies our zk
  proof; rc=0 IS the verifier-side parity invariant, in-dataset).
  Launcher quiet-gate physically removed (was still in the script;
  the 07-24 12:05 decision is now code). Smoke: poseidon 40 rows,
  0 failures, aggregator + RESULTS.md handle the new phases.
  Deliberately NOT added pre-run: busy-vs-blocked network-wait split
  (invasive mpc-net change — queued as v2.1 with Shamir + netem);
  $-cost/energy/gates-per-sec (pure post-processing, no rerun needed).

### BENCH v2 FULL RUN — LAUNCHED 2026-07-25 (WHERE EVERYTHING LIVES)

Run dir: **`bench-results/2026-07-25/`** (in-repo). Contents when done:
`manifest.json` (provenance; co_snarks_commit = the docs commit below),
`results.csv` (every timed cell: circuit,protocol,zk,rep,phase,seconds,
rc,max_rss_kb,cpu_pct,host_load1m — rc=124 = 600 s timeout, failures
kept), `netstats/*.json` (per MPC phase × party bytes + msg counts → R),
`mem/*.time` (per-party wall/RSS/CPU% — party skew), `features/*`
(circuit-info/bbgates/nargo-info/artifact-sizes per circuit),
`RESULTS.md` (human-readable — the entry point for that run's data), `site-anchors.json`
(explorer bake), `launcher.log` (live progress + per-circuit ETA;
`BENCH_DONE rc=… out=…` sentinel line when finished), `*_r*.log`
(per-cell command logs). Runner: `scripts/bench-0_5-launcher.sh`
detached via setsid, its own pid in `bench-results/2026-07-25/launcher.pid`;
stdout/err → launcher.log. Matrix: 12 circuits × {bb, plaindriver, REP3}
× {zk, nonzk} × ≤3 reps, ~2.5–3.5 h estimate (post-optimisation, may be
less). After ingest: `python3 scripts/bench-ingest.py` →
`bench-results/bench.sqlite` (gitignored, derived).

On BENCH_DONE the standing runbook applies (session-14 NEXT STEPS,
minus the dead quiet-gate step): 1) RESULTS.md + launcher.log sanity
(rc≠0? timeout-pruned? medians vs v1 for the 3 base circuits — bb/REP3
should reproduce v1 within noise; plaindriver + REP3-local-work now
FASTER than v1 = the optimisation delta, expected); 2) headline
questions: R vs size (is prove-R ≈ 10·log n + const?), features vs
REP3÷bb ratio (lookup_gates/table_rows as predictor), NEW: verify_bb
rc=0 everywhere (parity invariant), verifier times; 3) commit the run
dir (results are data, committable per the dataset rules); 4) bake
site-anchors into the explorer (same artifact URL, ch. 22 V6/V7);
5) T2-proper floors from the netstats medians; 6) ch. 24 H2–H4
discrimination from the sha sweep. Post-run leads: serial-inversion
audit of REP3 local paths, L1-followup −1 round, C2 residuals.

**BENCH v2 RAN CLEAN 2026-07-25 11:15–12:20 UTC (65 min, rc=0) →
`bench-results/2026-07-25/` (committed).** Host load 15–25 throughout
(a genuinely quiet window, luck); manifest stamps commit 89666ce5,
clean tree. 314 rows; only failures = designed timeout pruning
(sha256_2e16 REP3 prove > 600 s → sha ≥2e17 REP3 skipped, rows kept
honest). Aggregates: RESULTS.md + site-anchors.json in the run dir;
bench.sqlite rebuilt from all runs (v1 + v2). Findings written to
ch. 24 §3a + bench-results/README.md; headlines:
- **Lookup gates, NOT table rows, drive MPC cost** (bb_sha256_compression
  vs sha256_2e16: same dyadic/tables/rows, 15× lookup gates → >4.3×
  REP3 prove; 473× vs >1,140× vs bb).
- **REP3 prove is locally serial: ~260% CPU of 1600% budget** (bb:
  ~1,450%) — L4 + REP3 serial-inversion audit = top levers. Party skew
  nil. Peak RSS 20 GB/party at 2^20 (~13× bb).
- Poseidon REP3÷bb: 3.1× (2^11) → ~13× plateau (2^17–2^20).
- **L1's −8 rounds confirmed on the wire** (prove R 319→311/393→385).
- **R-proxy caveat**: prove msg counts scale ~linearly (~37 KB/msg) —
  application batching emits many frames per logical round; upper bound
  only at scale. Witext of hash-chain circuits is genuinely round-deep
  (270k rounds at 2e20, 39 B/msg) — circuit DEPTH sets WAN witext
  feasibility. Backlog: logical-round counter.
- verify_bb rc=0 all 12 circuits (verifier parity measured per-run);
  verify ≈ 20 ms size-independent everywhere.
Next per runbook: bake site-anchors into the explorer (same URL), then
T2-proper floors from these netstats, ch. 24 L4/L2, sha 2e17 under the
cap. v1-sanity: bb + REP3 reproduce v1 within noise (sha 140.5 s vs
~158 s incl. local-work speedups); plaindriver faster as expected
(witness-fed + C-series).

- **Explorer BAKED + republished (same URL)** with the v2 dataset:
  12 circuits, family-split sweep lines (poseidon solid / sha dashed —
  never joined across families), REP3 sha timeout as a censored ▲
  "≥600 s" floor (never a point; ladder shows a dashed ghost bar),
  R-slider default 385 = measured (caveat in assumptions), peak-RSS
  tile, verify_bb 12/12 in the correctness banner, 18-row assumptions
  table, all provenance strings → 2026-07-25/89666ce5,
  bb_sha256_compression label corrected 2^15→dyadic 2^16. Source HTML
  in session scratchpad; artifact
  https://claude.ai/code/artifact/90d4bf98-8b70-4f9e-814b-5d07b20daefa
  (redeploy: pass this url to the Artifact tool from any session).
  Runbook items 1–4 done; remaining next-session leads: T2-proper
  floors from v2 netstats, ch. 24 L4/L2 + REP3 serial-inversion audit,
  logical-round counter, sha 2e17 REP3 under the cap after a lever.

## Session 16 — 2026-07-25 (afternoon/evening) — bench-v2 methodology fixes; the sha-overhead attribution saga (wrong→wrong→RESOLVED: per-Yao-call tax in the builder's sha gadget); T2-proper fences landed; ZK blinding fence + optimisation research in flight

Picked up the session-15 queue (T2-proper, L4/L2, serial-inversion
audit). Mike challenged the bench-v2 methodology mid-session — every
challenge was right, and the resulting dig ended somewhere nobody
expected. Full technical record in ch. 24 §3a/§4 (updated in place);
this entry is the narrative + state.

### The attribution saga (read this before trusting any older sha claim)

1. **v2's recorded finding** ("lookup GATES drive MPC cost", §3a) was a
   NATURAL experiment (bb_sha256_compression vs sha256_2e16) and Mike
   correctly called it confounded: the pair also differs 6.8× in
   arithmetic gates. It was also doubly weakened: the REP3 "prove" cell
   conflated pk-gen+prove, and the sha256_2e16 cell was CENSORED
   (600 s timeout, rc=124) — a lower bound, not a measurement.
2. **Retro-split fixed the conflation without rerunning**: both phases
   are logged per party → `scripts/bench-retro-phase-split.py` →
   `bench-results/2026-07-25/phase-split.csv` (108 party-rows; both
   uncommitted). Results: REP3 prove-PROPER scales with dyadic size,
   nearly content-independent (recursion_zk vs poseidon_2e20: same 2^20,
   3.3× different arithmetic gates → pk-gen within 8%, prove within 5%
   — arithmetic-gate driver REFUTED with in-data controlled comparison);
   ALL of sha's excess is pk-gen (136.7 s vs ~0.45 s size-baseline at
   2^16; prove is 3.5 s, BELOW the size-scaled poseidon line).
3. **First mechanism attribution (mine, code-read): WRONG.** Blamed the
   serial per-gate OHV pipeline in `construct_lookup_read_counts`;
   rate+traffic arithmetic "cross-checked" — by CONFOUND (every
   per-sha-content mechanism predicts the same 15×). Instrumented
   profile: that function is 8.0 s = 5.8% of pk-gen. Lesson recorded in
   ch. 24: code-reading finds A mechanism; only measurement ranks it.
4. **Profiler's first attribution: ALSO WRONG** (Yao sha256_from_bristol
   re-solve in the builder) — refuted by the witext cell running the
   same opcode in 0.10–0.21 s.
5. **RESOLVED by the second call-counted profile (94.6% of pk-gen
   accounted):** `create_circuit` never re-runs the ACVM solver
   (0 calls). The ~130 s is the BUILDER's sha gate-construction gadget
   (`co-builder/src/types/sha_compression.rs::sha256_block`) deriving
   every sparse-form round intermediate via plookup reads with shared
   keys → **369 separate SMALL Yao garbled-circuit sub-protocols**
   (`yao::get_sparse_normalization_values_many` 176 × 575 ms = 101.3 s
   = 73% of pk-gen alone; `get_sparse_table_with_rotation_values_many`
   193 × 147 ms = 28.4 s). Same gadget code under the plain driver:
   0.106 s → **~1,240× tax = per-invocation FIXED overhead** (fresh
   garbling setup, joint input sharing, circuit transmission + SHA3
   consistency check, output reconstruction), round-trip-bound; all 3
   parties flat ~60% CPU (REP3-Yao is genuinely 3-party — asymmetry
   hypothesis refuted); `get_from_public_luts_internal` 0 calls (ruled
   out). Ceiling proof: witext does the WHOLE compression as ONE
   buffered Yao circuit in ~0.1 s. Fix directions (all
   transcript-preserving; gate layout/wire values are deterministic):
   batch within/across rounds, amortize per-call fixed costs, or
   one-shot Yao with intermediate wires as outputs; alternative
   non-Yao module (a2b+OHV/LUT path ≈ 2 ms/op measured, or GMW-style
   boolean batching) also viable — Mike's "swap the module" question
   answered YES in principle. sha256_2e16 prediction: 15 compression
   calls ≈ 1,950 s pk-gen (uncapped confirmation run still queued).
   ch. 24 §4: new lever L0 (top), L2 demoted to real-but-minor.
6. **Explorer corrected + extended (same URL)**: dated correction
   banner (no silent rewrite), 3 stale "lookup gates" strings fixed,
   NEW Raw-data section (4 datasets: timed cells w/ honest timeout
   flags, recovered phase split, per-phase comms, circuit features;
   summary tables + verbatim CSV blocks). Mike also asked for
   per-ROUND traffic accounting + distance-tier transfer-time estimates
   → spec'd in ch. 24 §3a (logical-round counter + per-round byte
   histogram + Σ max(RTT, bytes/bw) tier model, netem-validated in v3).

### Audit + fences (session-15 queue items, DONE)

- **Full REP3 batching/serial-op audit** (ch. 24 §4 updated): L2b
  serial post-open `y.inverse()` loops (co-noir-common rep3.rs:226/244,
  shamir.rs, mpc-core inv_vec — ~4.2M serial inversions per 2^20 prove,
  coordinator code-verified); L2c driver mul_many routed to serial
  mul_vec while parallel local_mul_vec exists (~13.6M serial muls +
  ChaCha draws at 2^20); L1-followup −1 round in
  array_prod_inner_mul_many (independence code-verified; blast-radius
  CORRECTION: co-acvm is_zero does NOT share it, sole caller is
  co_oink_prover.rs:517); L4 residue = permutation-lagrange TODO
  (plain_proving_key.rs:297). Prove-side profile (poseidon_2e17):
  oink 34% / sumcheck 58% / pcs 6%; sumcheck's relation batch is
  STRUCTURALLY single-threaded (net/state confined to caller thread) —
  the real L4 redesign; poseidon s^5 = 3 inherent mul_many rounds ×
  relation × sumcheck round (L7 territory); gp/array_prod 1.6 s at
  ~101% CPU (L2b/L2c target). Sequencing: L2b → L2c → L1-followup →
  L0 (after research) → L2 → L4 residue.
- **T2-proper comms fences LANDED (uncommitted)**: exact per-party
  (sent,recv) pins for blackbox_and (lookup path) + add3u64
  (delta-range path) + poseidon ZK (counts proved exactly
  deterministic: prove (273,273)×3 vs nonzk (199,199)×3);
  `#[ignore]` band test on bb_sha256_compression ([0.5×,2×]);
  committed floor table rep3_comms_floor_table.json from v2 netstats
  (nulls explicit for censored cells); wired into fast-check tier 3
  (+0.12 s); red-validated; --all-fast PASS. ANOMALY documented in the
  table's provenance: in-process LocalNetwork measures ~100× fewer
  frames than the cross-process TCP bench on the big circuit
  (byte-identical proofs; small circuits unaffected) — methodology gap,
  root cause not isolated.

### In flight at session end (3 background agents)

- **Seedable ZK blinding fence** (Mike's explicit ask): injected
  masking-value stream at the enumerated ZK draw sites (oink
  mask_polynomial rows{1,2,3}, gemini masking poly, libra scalars,
  SSIPA masking term), REP3 promotes to trivial shares; test asserts
  plaindriver-ZK ≡ REP3-ZK ≡ all-3-parties bytes, anti-vacuity +
  red-validation; default path bit-identical (byte-KATs gate it).
  bb-side note: bb HAS a deterministic debug engine but enabling it for
  proving requires uncommenting a line in engine.cpp (source edit) →
  excluded (no-touch-bb); ZK-vs-bb stays covered by bidirectional
  verification.
- **Web research**: TACEO blog/talks/papers + upstream GitHub activity
  + academic co-SNARK optimisation literature; deliverable = ranked
  transcript-preserving tricks + explicit transcript-ALTERING rejects.
- **Local research**: co-circom-vs-co-noir technique diff + upstream
  drift catalogue (git fetch permitted, read-only), specifically
  whether upstream already attacked yao.rs get_sparse_* /
  sha_compression.rs.

### Queued next (in order)

1. Agents return → verify their work independently (this session's
   lesson applies to agent claims too), L2b → L2c → L1-followup as
   small KAT-gated units.
2. L0 design from research + profiler evidence; then sha256_2e16
   UNCAPPED pk-gen run (registered prediction ~1,950 s ± 20%).
3. Controlled gate-sweep circuits (vary lookup gates at fixed
   arithmetic & tables, and vice versa) — the designed experiment that
   replaces the confounded natural one.
4. Bench v2.1: pk-gen/prove as separate cells + separate netstats
   phases (bb vkgen was split at design time, co-noir wasn't — design
   miss, now fixed retroactively via log parsing); logical-round
   counter + per-round byte histogram + tier model; Shamir via
   translate-witness; busy-vs-blocked wait split.
5. Re-run bench after each landed lever; explorer re-bake per run.

NOTE for future sessions: NOTHING from today is committed (Mike's
hard rule; includes the fences, phase-split script/CSV, docs edits,
ZK fence when it lands). When Mike gives the word, the commit split
should follow ch. 24 §4's unit boundaries.

### Session 16 late addendum — all three agents landed, everything verified

- **Seedable ZK blinding fence LANDED (uncommitted) + coordinator-verified**:
  new `co-noir-common/src/zk_masking.rs` (`SeededZkBlinding`, per-site
  ChaCha12 streams keyed by site label; doc-marked test-only —
  destroys ZK in production), explicit
  `prove_with_seeded_zk_blinding` entry points (CLI cannot reach them;
  default `prove` passes None, unseeded path bit-identical — the
  exact-count ZK comms fences and non-ZK byte-KATs prove it).
  Complete draw-site enumeration (oink 8 mask_polynomial sites +
  Gemini poly; libra constant/univariates/concat scalars; SSIPA
  masking term; recursion path passes None). Test
  `zk_blinding_seeded_plaindriver_rep3_byte_parity_poseidon2sponge`
  (~1.1 s, fast tier): plaindriver-ZK ≡ all 3 REP3 parties' ZK bytes +
  determinism + anti-vacuity (different seed → different bytes;
  seeded ≠ unseeded) + verifies. Red-validated at the exact funnel
  (REP3 promote_to_trivial_share +1 → fails at the parity assert).
  Finding: plain and MPC provers correspond 1:1 site-for-site in draw
  order (plain file's function ordering is misleading but call order
  matches). Coordinator re-ran: test PASS, fast-check --all-fast PASS
  incl. bb cross-verify (VK+proof byte-identical to v5.0.1 oracle)
  with ALL of today's uncommitted work in tree. bb-side ZK byte-parity
  remains excluded (bb's debug RNG needs an engine.cpp source edit —
  no-touch-bb).
- **Both research reports in and distilled to ch. 24 §6a (web) / §6b
  (local)**. Headlines: the batched GC kernels for the sha hotspot
  ALREADY EXIST in-tree (get_sparse_*_many, yao.rs:1401/:1452) — the
  369-call pathology is purely co-noir's call layer, and upstream
  hasn't fixed it either (8 post-merge-base commits, none touching
  hotspots) → L0a/b/c specced in §4; NEW lever L0d half-share MSM for
  immediately-opened commitments (co-groth16 precedent, ~half the
  commitment MSM CPU, all circuits); TACEO's own published measurement
  validates batching ("10 or 100 witness extensions in batched form ≈
  no overhead"); documented transcript-altering REJECTS recorded
  (logUp swap, packed-sharing GKR, truncation tricks, etc.);
  per-round-bytes + latency-tier benchmarking would be first-of-kind
  (nobody publishes it, incl. TACEO).
- **Implementation begun on the lever queue** (L2b first: batch
  inversion of post-open values in REP3/Shamir drivers + mpc-core
  inv_vec + mul_open_vec parallel local pass). Still UNCOMMITTED
  throughout, per the hard rule.

### Session 16 lever ledger (all uncommitted, each gated + coordinator-verified)

- **L2b LANDED**: batch inversion of post-open values (6 sites: REP3+
  Shamir drivers inv_many_in_place{,_leaking_zeros}, mpc-core rep3+
  shamir inv_vec) + mul_open_vec parallel local pass. Zero-handling
  proved bit-identical (r·0 = zero share). Referee: poseidon_2e17 REP3
  proofs BYTE-IDENTICAL before/after (md5, 3 parties × 2 reps); comms
  fences unchanged; fast-check PASS. Measured: 10.5 s → 9.37 s prove
  at 2^17 (~11%). Patch: scratchpad l2b/l2b.patch.
- **L2c LANDED**: REP3 + Shamir driver mul_many → local_mul_vec +
  reshare/degree_reduce (parallel pre-squeezed local multiply; message
  counts unchanged by construction, fences prove it). 8.8 → 8.5 s at
  2^17 (~3.4%); proof md5 identical. Patch: l2c-l1f/l2c.patch.
- **L1-followup LANDED**: array_prod_inner_mul_many (+ unused
  array_prod_mul for schedule consistency) two independent mul_many
  merged → one → −1 comms round per grand product. FENCES TRIPPED AS
  DESIGNED and consciously re-pinned (per-party prove counts, all
  −1: poseidon nonzk 199→198, zk 273→272, blackbox_and 199→198,
  add3u64 249→248; pk-gen unchanged; floor-table band test unaffected,
  JSON provenance text now historical — left untouched). Proof md5
  still identical to pre-L2c. Full noir test suite 115/115; fast-check
  PASS. Patch: l2c-l1f/l1-followup.patch.
- Cumulative poseidon 2^17 REP3 prove today: ~10.5 s → ~8.2-8.5 s
  (~20%). Explorer R-anchor (385) is now stale by −1 (384) — re-bake
  rides the next bench rerun (PLAN 6.4).
- NEXT: L0c (merge the 2 GC input rounds in
  decompose_circuit_compose_blueprint — mpc-core yao.rs TODOs at
  :944/:965/:993; −1 RTT × every GC invocation; lookup-circuit pk-gen
  fence counts will legitimately change → re-pin) launched; then
  L0a/L0b sha-gadget _many batching + second-channel concurrency, L0d
  half-share MSM (specs ch. 24 §4).

### Session 16 CLOSE-OUT — oracle re-verified, next steps (read this first next session)

**Oracle provenance RE-VERIFIED on Mike's ask (2026-07-25 late):**
`~/.bb-target-src-v5.0.1/bb` PROVENANCE.txt says built from public-mirror
tag v5.0.1 = tag object b97ff8c3e88f... → commit 72666f8d1d6
"chore(release): v5.0.1 (#24737)"; live `git rev-parse` in ~/ap-next
confirms both hashes MATCH today. versions.env pins this binary as the
default oracle and fast-check reads versions.env (ch. 19 fix). Note the
comparison is NOT a stale KAT: fast-check's cross-verify REGENERATES a
bb proof with this binary every run and byte-diffs it (ran green ≥5×
today on the fully-optimised tree). Committed byte-KATs carry their own
per-dir PROVENANCE (items 2.1/2.10, ch. 19). The ch. 19 §1 tag-name
trap (same tag name, divergent commits, private vs public) is why this
check matters — re-verify hashes, not tag names, whenever in doubt.

**IN FLIGHT AT SESSION END: lever L0c agent** (merge 2 GC input rounds
in mpc-core yao.rs blueprint macro; brief includes: stop-if-dependent,
poseidon fences as canary (must NOT move), blackbox_and pk-gen fence
re-pin expected, bb_sha256_compression pk-gen timing before/after,
patch → scratchpad l0c/). If it landed after this entry: verify per the
session-16 pattern (skim diff, rerun fast-check --all-fast yourself,
check fence re-pin table) before queueing the next lever.

**NEXT STEPS, in order (specs all in ch. 24):**
1. Verify L0c landing (above).
2. **T4 view-scan + BYTE-level fence pins** (Mike's security asks,
   §4a/§5): record all frames at one party during a real 3-party
   prove, assert known witness plaintexts never appear; add exact byte
   pins beside the msg-count pins (catches leak-by-fatter-frames).
   Waits on L0c only because both edit tests/rep3.rs.
3. **L0a/L0b — the sha headline** (~130 s pk-gen): same-table `_many`
   batching at co-acvm rep3.rs:1738/:1809 call sites + choose∥majority
   on the second net channel. §4 L0 entry has the full design incl.
   what CANNOT batch (a/e dependency chain, differing base_bits).
4. **L0d — half-share MSM** for immediately-opened commitments
   (co-groth16 pattern; verify the "all commitments opened immediately"
   audit claim at implementation).
5. Small: permutation-lagrange rayon TODO (pk-gen); shplemini
   allocation hygiene (also attacks 20 GB RSS); old-L2 OHV batching.
6. **Re-run bench v2 on the optimised tree** (PLAN 6.4): quantifies
   L2b+L2c+L1f+L0*; then re-bake explorer anchors (same URL, R now
   384 not 385), refresh T2-proper floor table from new netstats.
7. **Uncapped sha256_2e16 REP3 pk-gen run** — registered prediction
   ~1,950 s ± 20% (15 × ~130 s post-correction; if L0a/b/c land first,
   re-derive the prediction from the new per-call cost — state it
   BEFORE running).
8. Controlled gate-sweep circuits (designed experiment, §3a open
   items); bench v2.1 (separate pk-gen/prove cells + netstats phases,
   logical-round counter + per-round byte histogram + distance-tier
   model §3a, Shamir cells, busy-vs-blocked); netem v3.
9. Larger backlog: cross-relation sumcheck stage-batching (L),
   blocking-TCP transport port (M, breaking config), streaming garbler
   for batched sha kernels, GC delta-reuse (engine-level, no
   precedent).

**Standing rules for all of the above**: one lever per gated unit;
§4a security checklist answered in writing per lever (no new knowledge
at any node; Network trait is the only cross-party channel); fences
re-pinned consciously with old→new recorded; fast-check --all-fast +
bb cross-verify green before a unit counts as landed; NOTHING commits
without Mike's explicit word (patches per unit live in the session
scratchpad; ch. 24 §4 unit boundaries define the commit split).

## Session 17 — 2026-07-26 overnight (autonomous; Mike asleep) — L0c verified; lever queue continues

Recovery: session 16 hit the token limit with the L0c agent in flight.
Forensics: the agent HAD finished the code + fence re-pins + before/after
referee runs (patch + proofs + logs in session-16 scratchpad `l0c/`,
21:11–21:12), but was cut off before the final gate + checklist. Mike had
separately committed L2b+L2c + session-16 docs at 21:13 (049d3435,
c621fdde, 78dfcad1). Still uncommitted: L1-followup, seeded-ZK fence,
T2-proper fences + floor table, L0c.

- **L0c VERIFIED (task 1 of the close-out queue)**: tree diff ≡ saved
  l0c.patch (only its annotation block differs); blackbox_and proofs
  byte-identical before/after (md5 ×3 parties ×2 runs); poseidon fence
  canary unchanged; blackbox_and/add3u64 pk-gen fences re-pinned with
  old→new recorded in-code; **fast-check --all-fast PASS on the full
  uncommitted tree** (13 fast-tier tests, bb v5.0.1 cross-verify VK+proof
  byte-identical, recursion VK KATs green). §4a checklist written
  retroactively (ch. 24 §4a) — the agent died before writing it.
  blackbox_and pk-gen 81.8 → 75.0 ms (3 GC invocations; win scales with
  GC-call count).
- **Mike's overnight directives (before bed)**: run the whole queue; after
  the optimisations, re-run the bench suite — extending its measurements
  first where insightful (pk-gen/prove cell split etc.); research chapter
  on private-shared-state offerings + business-viable Aztec use cases
  (ch. 25, agent-drafted — see below); if the queue runs dry, pick other
  PLAN work but NOT the TS orchestration port.
- **T4 view-scan + byte-level fence pins DONE (uncommitted)** — the two
  security asks from the session-16 queue, spec ch. 24 §5 (details + honest
  limits recorded there): all-parties/both-nets frame recording over a full
  witext+pk-gen+prove run, scanned at every byte offset for every
  high-entropy private witness value in canonical AND Montgomery encodings
  — CLEAN; anti-vacuity via planted-value detection + KAT cross-check.
  Byte pins beside all msg-count pins: exact everywhere except GC-bearing
  pk-gen phases (±8-byte band; Yao GC serialization drifts ±1 byte
  run-to-run — measured, documented in-code). Determinism of ZK prove
  byte totals confirmed across runs. New test in the fast MPC tier
  (~3 s, tier now 14 tests / ~12.7 s); fast-check --all-fast PASS ×2.
  Also fixed a pre-existing clippy needless_question_mark in
  co-noir/src/lib.rs:210 (from 83a8bde9; fast-check has no clippy step so
  it had slipped through). Patches: session-17 scratchpad t4/.
- **Ch. 25 WRITTEN (uncommitted)** — private-shared-state landscape +
  business-viable Aztec use cases (Mike's overnight ask; agent-researched,
  ~1,040 lines, claims tagged [V]/[S]/[opinion], grounded in our own bench
  numbers — spot-verified). Top-3 bets: sealed-bid auctions, Aztec dark
  pool, private credit-data consortium. Notable finds: TACEO×Aztec
  announced a formal PSS partnership 2025-09-25; TACEO Network launched
  2026-03; Penumbra shut down ~2025-09. README indexed.
- **L0a+L0b implemented, REFUTED by measurement, REVERTED** (full story
  ch. 24 §4 L0 entry; patch + prediction + all timing logs + agent's
  own post-mortem: session-17 scratchpad l0ab/). Byte-correct on every
  referee but pk-gen went 139.4 → 142.4 s (L0a-only isolation: 146.1 s
  — the batching plumbing itself is the regression; the L0b join
  clawed back ~3 s). **Mechanism correction that outlives the revert:
  per-GC cost is size-linear garbling compute, NOT fixed setup — each
  sparse-normalization call garbles a 254-bit field↔binary conversion
  circuit, so batching K costs K×; nothing to amortise at loopback.**
  New lever L0e opened (keep intermediates in binary/LUT domain across
  the gadget — the only path to witext's 0.1 s ceiling); L0a/b-shaped
  work re-classified as a WAN-tier lever (still −1 RTT × calls there).
  Post-revert gate re-run green. Bench-methodology note from the agent,
  owned honestly: its rep1-after was contaminated by its own concurrent
  clippy build; conclusion rests on reps 2–3 + isolation rep.
- **L0d LANDED (uncommitted, coordinator-implemented)** — half-share MSM
  for the 11 immediately-opened commitments (co-groth16 pattern): REP3
  now MSMs one summand (ONE Pippenger, not two) and opens via 3-way
  broadcast; plain/Shamir ride the default trait impl unchanged. Fence
  moves predicted exactly before measurement (+6 nonzk/+10 zk prove
  msgs; pk-gen untouched); non-ZK proofs KAT-byte-identical; --all-fast
  green; poseidon 2^17 ZK prove 7.94/8.28 s vs ~8.2–8.5 s baseline
  (within prediction band; bench rerun = definitive). Full entry +
  §4a checklist: ch. 24 §4/§4a. Patch: session-17 scratchpad l0d/.
- **Small levers + bench v2.1 instrumentation (uncommitted)**:
  permutation-lagrange rayon TODO done (L4 residue, local-only, KAT-gated,
  ch. 24 §4); launcher auto-runs phase-split.csv per run; CLI gained
  CO_NOIR_NET_STATS_JSON_PKGEN (mid-run netstats snapshot after pk-gen)
  wired into the bench's REP3 cells — per-phase comms now measured, not
  reconstructed (smoke-tested live). Patches: scratchpad small-levers/.
- **BENCH v2.1 FULL RUN LAUNCHED 2026-07-26 01:12 UTC** →
  `bench-results/2026-07-26/` (12 circuits × {bb, plaindriver, REP3} ×
  {zk, nonzk}, same matrix as v2). ⚠ Host load1m at launch: 45.8
  (HOST-wide; noisier window than v2's 15–25 — read absolute numbers
  with the per-row load stamps, lean on medians + same-window ratios).
  Tree state measured: v2 baseline + L2b + L2c + L1f + L0c + L0d +
  perm-lagrange rayon (L0a/L0b implemented-then-reverted, not in tree).
  On BENCH_DONE: RESULTS.md sanity → v2-comparison findings (expect:
  REP3 prove faster by ~L2b+L2c+L1f+L0d margins; sha pk-gen ~unchanged
  — L0c's −1 RTT × 369 calls is loopback-small; phase-split.csv +
  pkgen netstats now native) → commit stays PENDING Mike's word →
  explorer re-bake (same URL) with the new anchors.
- **BENCH v2.1 RAN CLEAN 01:12–02:12 UTC (60 min, rc=0, 314 rows,
  verify_bb 12/12).** Full findings appended to bench-results/README.md;
  headlines: **REP3 prove-proper −20…−30% at every size** (poseidon 2^20
  zk 90.2→66.2 s; recursion_zk 85.2→67.1 s; REP3÷bb at 2^20 zk
  11.4×→8.8×); sha pk-gen −0.4% (unchanged, as predicted post-L0a/b);
  both expectations from the lever ledger CONFIRMED on the full matrix.
  Bonus analytical win from the new per-phase netstats: **v2's R-proxy
  caveat is RESOLVED** — prove-proper recv_msgs IS true round depth
  (204 at 2^17 nonzk, byte-equal to the in-process fence pin; 336 at
  2^20 zk ≈ 10·log n + const), and ALL the size-linear frame growth was
  pk-gen's ~253 B frames; the in-process-vs-TCP anomaly is now
  LOCALIZED to pk-gen (open, smaller haystack). Run dir UNCOMMITTED
  with everything else, pending Mike's word.
- **Explorer RE-BAKED + republished (same URL)** with the v2.1 anchors
  (~110 values), a dated "Update 2026-07-26" banner (levers/−27%;
  sha root cause RESOLVED, L0e surviving; R-caveat RESOLVED), honest
  dirty-tree provenance (049d3435 + uncommitted session-17 levers),
  R-slider re-seeded 385→384 with the validated round-depth note, and
  assumptions-table refresh (whole-step ~10.4× / prove-proper ~8.8× at
  2^20 zk; v2's ~13× kept as dated history; CPU-260% row explicitly
  dated pre-levers — not re-profiled). 07-25 correction banner + all
  historical CSV blocks kept verbatim (dated, never rewritten).
  Source: session-17 scratchpad site/explorer-v4.html.
- **Uncapped sha256_2e16 REP3 run DONE (02:20–02:54)**: pk-gen
  **2,039.6 s** vs the registered ~2,040 s ± 20% prediction — a 0.02%
  hit; prove-proper 3.6 s; 3-party proofs byte-identical (non-ZK; the
  stored plaindriver proof is ZK — size 14,656 vs 13,120 — so no
  byte-compare there, by mode not by defect). The per-compression-call
  model (15 × ~136 s) is CONFIRMED; recorded in ch. 24 §3a.

### Session 17 CLOSE-OUT (read this first next session)

Everything below remains **UNCOMMITTED** (Mike's hard rule; commit split
should follow ch. 24 §4 unit boundaries + this session's scratchpad
patches: t4/, l0d/, small-levers/, plus session-16's l2b/, l2c-l1f/,
l0c/ and the l0ab/ record of the REVERTED unit). Tree gated green
throughout: fast-check --all-fast + live bb v5.0.1 cross-verify, all
fences re-pinned consciously, view scan clean.

**Landed this session**: L0c verified; T4 view-scan + byte pins; L0d
half-share MSM; perm-lagrange rayon; bench v2.1 instrumentation
(native phase-split + per-phase netstats); bench v2.1 full run
(REP3 prove −20…−30%, ratio to bb at 2^20 zk now ~8.8×); explorer V9
re-bake (same URL); ch. 25 (private shared state); uncapped sha
confirmation (2,039.6 s vs 2,040 predicted). L0a/L0b: implemented,
refuted, reverted — the mechanism correction (size-linear GC compute)
and new lever L0e are the surviving value.

**NEXT STEPS, in order (specs in ch. 24)**:
1. Mike reviews + gives commit word (suggested split: T4+byte-pins /
   L0c / L0d / perm-lagrange / bench-v2.1 instrumentation / bench run
   dir + docs / ch. 25).
2. L0e design (the one remaining sha lever: keep sparse-form
   intermediates in the binary/LUT domain across the gadget; or the
   MAESTRO LUT path). Effort L — needs a design pass before code.
3. Controlled gate-sweep circuits (§3a open item (b)) — the designed
   experiment; the natural-experiment slope is now confirmed but not
   isolated.
4. L2 (construct_lookup_read_counts batching, 1a→1b→1c), L0b-only
   candidate (WAN-tier), shplemini allocation hygiene (20 GB RSS),
   old-L2 OHV batching.
5. Floor-table refresh from v2.1 netstats (provenance text is now
   doubly historical — L1f and L0d moved prove counts); logical-round
   counter + per-round byte histogram + distance-tier model (§3a);
   netem v3; Shamir cells via translate-witness.
6. In-process-vs-TCP frame anomaly: now localized to pk-gen (~253 B
   frames, 116 in-process vs 11k–90k TCP) — root-cause when touching
   mpc-net next.

## Session 18 — 2026-07-26 — commit split executed (Mike's word); next lever round launched

**Mike's word received**: commit the uncommitted work, split per ch. 24 §4
unit boundaries; keep going with optimisations; extend bench granularity;
identify non-optimisation work (always: proofs must not deviate from bb).

**Commit split EXECUTED — 11 commits on mc/update-co-noir (local only)**:
`9c03757a` L1-followup · `2b08d1c9` seeded-ZK plumbing · `dfa4a510` L0c ·
`9e5935ee` L0d · `471e0b62` perm-lagrange rayon · `09f2f45b` T2-proper +
T4 + byte pins + floor table (+ the seeded-ZK byte-parity test) ·
`f4011baf` clippy/fmt tidy · `74158193` bench v2.1 instrumentation ·
`a085f424` bench v2.1 run data + findings · `cb8509d7` ch. 25 ·
`b5f3c5b0` session-17 docs.

Reconstruction notes (for the audit trail): several files interleaved
multiple units (tests/rep3.rs; co-noir-common lib.rs; oink/zk_data/ssipa
mixed seeded-ZK + L0d). Intermediate states were rebuilt from the session
scratchpad patches + a classifier over difflib opcodes (seeded regions kept,
L0d call-site swaps reverted; the one genuinely mixed region — oink's Gemini
masking block — handled explicitly). Fence pins carry their historical
values through the sequence (199→198 at L1f, 198→204 at L0d, full pins at
the tests commit). The working yao.rs differs from the saved l0c.patch only
by a later rustfmt reflow (verified; L0a/b revert left no residue).

**Verification (all green)**: reconstructed original tree vs new HEAD =
EMPTY diff (byte-identical, incl. untracked-file additions); intermediate
compile checks at C1/C2/C3/C4 in a throwaway worktree all pass;
fast-check --all-fast PASS on the final tree (bb v5.0.1 cross-verify VK +
proof byte-identical; recursion VK KATs green). Verification worktree
removed.

### Session 18 (cont.) — optimisation round 2 in flight; anomaly RESOLVED; L0e design verified

- **L0e design pass DONE + coordinator-spot-verified** (scratchpad
  l0e-design/L0E-DESIGN.md): sha gadget's ~369 lookup-read values are
  public-weight linear maps of ~42k carry-free bits (proof: normalization
  table sizes 16/28/16) → design (a) = ONE ~130–200k-AND GC per compression
  (vs ~126M across today's calls), binary outputs + one batched bit-inject,
  ~4 rounds; values served to the UNTOUCHED builder via a driver FIFO cache
  with parity-safe fallback. §4a answered in writing. REGISTERED
  PREDICTIONS: pk-gen 136.7 → 9.5 s ± 2; sha256_2e16 2,039.6 → ~140 s ± 30.
  All spot-checked citations accurate. **U1 (pure GC + cleartext-trace KAT +
  carry-freeness assertions + C3 linearity re-proof + real AND count) agent
  IN FLIGHT.**
- **pk-gen frame "anomaly" RESOLVED — it was a circuit confound, not a
  measurement gap** (agent report coordinator-verified against
  ultra_builder.rs:4214/:340 and the committed v2.1 netstats):
  both net backends count identically; a real TCP run of the small KAT
  circuit reproduces the in-process fence pins byte-for-byte. pk-gen msgs
  = big_quad_constraints + 2 (exact at both sizes tested). The REAL
  finding: one mul_many round PER big-quad constraint → **new lever L8**
  (batch across constraints, O(#constraints)→O(1) rounds; ~30–45 min of
  pure WAN latency at 2^20 today). ch. 24 §3a resolution + §4 L8 entry
  written. sha's floor-table anomaly entry (lookup/Yao path) stays open.
- **Bench-granularity agent IN FLIGHT** (logical-round counter, per-round
  byte histogram, tier model, busy-vs-blocked, Shamir cells).
- All session-18 round-2 work UNCOMMITTED pending Mike's word (commit
  split earlier this session was Mike-authorized and is committed).

### Session 18 (cont. 2) — bench-granularity landed (agent + coordinator fix); tier model now brackets WAN cost

- **Bench-granularity agent LANDED (uncommitted, coordinator-reviewed)**:
  (1) logical-round counter + per-round recv-byte histogram +
  busy-vs-blocked split in mpc-net (observation-only via try_recv;
  all T2 fences byte-identical, fast-check --all-fast PASS, agent-run);
  (2) scripts/bench-tier-model.py → tiers.csv (wired into the launcher);
  (3) Shamir cells for the poseidon family via translate-witness —
  smoke: SHAMIR proof BYTE-IDENTICAL to the plaindriver KAT;
  (4) per-cell sub-phase timers captured to phase-timings/*.json;
  (5) bench-results/README.md v2.2 section. Patch: session-18 scratchpad
  bench-granularity/.
- **Coordinator correction to the tier model (same day)**: the
  blocking-round histogram measures loopback PIPELINING, not dependency
  depth (2^17 prove: 204 recv_msgs vs ~74 blocking rounds,
  non-monotonic in size — agent's own honest finding). tiers.csv now
  carries est_pipelined_seconds (optimistic anchor) AND
  est_dependency_{lo,hi}_seconds computed from recv_msgs (the
  v2.1-validated round-depth proxy): lo = max(msgs·RTT, bytes/bw),
  hi = msgs·RTT + bytes/bw. Validated on the agent's smoke netstats:
  2^17 pk-gen WAN dep-bracket ≈ 445 s pure round latency — the L8
  lever quantified; prove-proper WAN [32, 40] s, bandwidth-bound.
- Still in flight: L0e U1 agent (sparse-trace GC + cleartext KAT).
  Remaining bench-granularity follow-ups listed in README v2.2
  (round-counter size sweep, SQLite/explorer wiring, netem v3, Shamir
  non-poseidon, sent-side histogram).

### Session 18 (cont. 3) — L0e U1 LANDED + coordinator-verified; U2 + L8 launched

- **L0e U1 LANDED (uncommitted, coordinator-verified)**: pure sparse-trace
  GC circuit (mpc-core yao/circuits.rs:3549, 42,016 output bits) +
  cleartext referee against the REAL plain plookup machinery +
  real-garbling equivalence. Bit-equality 22 inputs; carry-freeness
  EXHAUSTIVE; C3 linearity PROVEN coefficient-by-coefficient; measured
  AND count 92,941 (fence-pinned; design predicted 130–200k) ⇒ ~84 ms +
  ~2.8 MB per compression at the kernel level. Coordinator re-ran
  fast-check --all-fast on the full combined tree (U1 + bench-granularity
  + tier-model fix): PASS, bb cross-verify byte-identical. BONUS: latent
  half_adder_const carry bug found (harmless today; ticketed ch. 15 §5.1;
  do NOT fix inside L0e units). Patch: scratchpad l0e-u1/. ch. 24 L0e
  entry updated.
- **IN FLIGHT: U2 agent** (binary-output blueprint kernel + 3-party
  value-equality referee vs the 369 singular kernels; mpc-core only) and
  **L8 agent** (batch pk-gen big-quad mul_many across constraints;
  co-builder + fence re-pins; before-proofs first, registered timing
  prediction, §4a in writing). File-disjoint by brief.

### Session 18 (cont. 4) — U2 + L8 agents died at the usage limit; both units recovered, finished, and verified by the coordinator

Both agents were killed mid-flight by the session limit (the session-16
pattern). Forensics + close-out done inline:

- **L8 LANDED (uncommitted, coordinator-completed)**: the agent had
  implemented the two-pass batching (ultra_builder.rs, +89/−29), re-pinned
  the pk-gen fences to its pre-registered predictions, written the seeded
  share-identity unit test, and saved before-evidence — then died before
  the after-measurement. Coordinator: no debug leftovers in the diff;
  fences PASS live at exactly the predicted pins ((116,116)→(3,3) msgs,
  −904 B/direction; blackbox_and/add3u64 UNCHANGED — they have 0 big-quad
  constraints, correcting the launch brief's expectation);
  l8_batched_mul_vec_share_identity PASS (share-LEVEL identity);
  proof+VK md5 sets IDENTICAL before/after (same witness shares);
  poseidon_2e17 pk-gen 722.9–741.0 ms → **290.0–322.9 ms** (registered
  band 250–550 ms; ~2.4× loopback; WAN: 11,127 rounds → 3);
  fast-check --all-fast PASS incl. bb cross-verify. §4a written
  retroactively (in l8/REPORT.md). Patch: scratchpad l8/l8.patch.
- **L0e U2 LANDED (uncommitted, coordinator-completed)**: kernel + read
  recombination + full 3-party referee were in-tree (the agent died
  before its report/patch). Coordinator: referee PASS (130 s; every
  derived read tuple value-equal to the 369 singular kernels AND U1's
  cleartext trace); RED-VALIDATED (flipped ChOutput weight → FAIL at the
  equality assert, reverted); marked #[ignore] per slow-test convention
  (run explicitly at L0e unit gates + milestones); all existing fences
  untouched; fast-check --all-fast PASS. Patch + coordinator report:
  scratchpad l0e-u2/. Owed from U2 (rides U3): kernel wall-time/comms
  measurement, written RNG-discipline argument.
- Coordinator judgement: with the tree gated green end-to-end and both
  units matching their pre-registered predictions, L0e proceeds to U3
  (driver FIFO cache — the byte-KAT-refereed unit where the ~130 s sha
  pk-gen win materializes).

### Session 18 (cont. 5) — L0e U3 LANDED: sha pk-gen 145.4 → 6.95 s, bytes identical; bench v2.2 launched

- **U3 (driver FIFO cache) LANDED (uncommitted, coordinator re-gated)**:
  bb_sha256_compression REP3 pk-gen **145.4 → 6.95 s (20.4×)** with
  proof+VK md5 IDENTICAL before/after (all parties, 2 sharing seeds) and
  byte-equal to plain + live bb v5.0.1; **sha256_2e16 pk-gen 2,039.6 →
  123.9 s** (design band 140±30) — the bench's timeout-pruned sha cells
  are now feasible. Registered predictions beaten. Fallback red-tested;
  U2 debts (kernel timing ~84–88 ms/compression, comms ≈ design shape;
  RNG-discipline argument) delivered. NO fence re-pin needed — and the
  agent predicted why in writing: the in-process sha KAT proves on a
  PUBLIC witness, which ALSO closes the floor-table's last
  in-process-vs-TCP anomaly (public-vs-shared witness, not
  measurement). Coordinator re-ran fast-check --all-fast: PASS.
  Patch + evidence: scratchpad l0e-u3/. ch. 24 L0e entry updated.
- **Bench v2.2 full run LAUNCHED** on the optimised tree (L8 + L0e U1–U3
  + all committed levers) with the new granularity instrumentation
  (round counter, tiers.csv, phase-timings, Shamir poseidon cells).
  Expectations registered in ch. 24/bench README terms: sha REP3 cells
  no longer prune at 2^16 (~124 s pk-gen); poseidon pk-gen ~2.4× faster
  (L8); prove-proper unchanged vs v2.1; new artifacts present and sane.
- **Bench v2.2 launch correction**: the first launch NEARLY CLOBBERED the
  committed v2.1 dir (launcher defaults to bench-results/<date>/ — same
  day). Killed in the build phase, the two touched files restored from
  HEAD (verified clean), launcher gained a same-day rerun guard (suffix
  -HHMM when results.csv already exists), relaunched →
  `bench-results/2026-07-26-1520/`. Host load1m ~18 at launch (calmer
  than v2.1's 45.8). sha cells no longer expected to prune.

### Session 18 (cont. 6) — bench v2.2 RAN CLEAN; L8 + L0e scored on the full matrix

`bench-results/2026-07-26-1520/`, 15:20–17:49 UTC, rc=0, 418 rows,
verify_bb 12/12, load ~18 (cleanest window yet). Full findings in
bench-results/README.md. Headlines: **sha compression REP3 pk-gen
136.19 → 9.03 s cross-process (design band 9.5±2 ✓); sha 2^16–2^18
cells now measurable (126/265/541 s — the sweep was timeout-pruned
before); poseidon pk-gen 2.4–2.7× (L8 ✓); prove-proper canary held;
first Shamir cells in the dataset; tiers.csv/phase-timings/rounds all
produced on a full run.** Whole-step sha ZK ratio vs bb: ~473× → ~47×.
Known gap: phase-split parser skips SHAMIR logs (queued). Next:
explorer re-bake (same URL) with v2.2 anchors, then the L2 lever (the
last sha pk-gen term).

### Session 18 (cont. 7) — explorer V10 published (same URL); L2-1a in flight

- **Explorer re-baked + republished (same URL)** with the v2.2 anchors:
  agent-baked (programmatic field-by-field anchor diff = exact match;
  all historical dated blocks byte-identical), coordinator-reviewed.
  Two coordinator fixes before publish: (i) banner §5 re-framed — the
  new blocking-rounds counter measures loopback PIPELINING, not
  dependency depth; it does NOT reopen the msgs≈round-depth result
  (which was validated byte-for-byte against fence pins) — tiers.csv
  reports both quantities as a bracket; (ii) added the directly-verified
  L8 collapse fact (poseidon 2^17 pk-gen = exactly 3 msgs per party per
  direction in the v2.2 netstats, was 11,127). New banner records
  L8+L0e scored, sha sweep unlocked, whole-step poseidon 2^20 zk ratio
  re-derived 10.4× → 9.8× (prove-proper ~8.8× flat), first Shamir
  cells (Shamir÷REP3 ≈ 2.55–2.7× on poseidon prove). Source:
  session-18 scratchpad site/explorer-v5.html.
- **IN FLIGHT: L2 unit 1a agent** (batch construct_lookup_read_counts —
  the dominant remaining sha pk-gen term; L0a plumbing-cost lesson +
  registered fence predictions in the brief).

### Session 18 (cont. 8) — L2-1a landed (WAN-structural win; wall-flat at loopback, honestly scored); milestone full sweep launched

- **L2-1a LANDED (uncommitted, coordinator re-verified: fences + all-fast
  green)**: batched read-counts path (details + honest prediction miss
  recorded in ch. 24 §4 L2 — the in-process wall win moved to 1b;
  1a delivers −25% sha msgs, −90 MB GC bytes, ~5,800 serial rounds =
  the WAN term). Msg predictions 12/12 exact; proof/VK md5 identical;
  §4a recorded. Patch: scratchpad l2-1a/.
- Session-18 uncommitted pile is now 8 verified units (L8, L0e U1–U3,
  bench-granularity+tier-bracket+launcher-guard, bench v2.2 data,
  L2-1a, docs+explorer V10). MILESTONE: fast-check --full launched as
  the whole-pile gate ahead of Mike's review/commit word.
- Phase-split parser SHAMIR gap FIXED (both protocols matched; summary
  grouped by protocol; v2.2 phase-split.csv regenerated, 228 rows).
  First Shamir prove-proper figures recorded in the bench README.

## Session 19 — 2026-07-26 — full-gate PASS; session-18 pile committed; UH bug-hunt; bench v3 (netem) launched

Mike's word this session: run the aborted milestone gate, commit the pile,
launch bench v3 (netem tiers) — all via cheap Sonnet agents (mechanical work) —
and separately **check our UH implementation for bugs**. Commit permission was
given for the pile only; the session-19 doc edits below are left UNCOMMITTED
(hard rule: no commits without an explicit ask).

- **Milestone gate PASSED.** The session-18 `fast-check --full` that had
  aborted (empty stdin at its confirmation prompt) was re-run to completion:
  **rc=0, 33 circuits across 4 shards, full noir suite + sharded
  compare.sh/compare_mpc.sh incl. slow set.** The 8-unit pile is validated
  end-to-end.
- **Session-18 pile COMMITTED — 8 commits on mc/update-co-noir (local only),
  one per ch. 24 §4 unit:** `46dc448c` L8 (big-quad mul_many batching) ·
  `f52a194b` L0e U1 (sparse-trace GC) · `66be5920` L0e U2 (kernel +
  recombination) · `86063a1a` L0e U3 (driver FIFO cache) · `1bf3af72`
  bench-granularity (round histogram + tier model) · `36cb6c60` bench v2.2 run
  data · `b3d750bf` L2-1a (construct_lookup_read_counts batching) · `53a7ec5e`
  docs. Verified byte-identical to the pre-split working tree (empty
  `git diff <anchor b6d4ad52> HEAD`); `cargo check --workspace` clean; nothing
  pushed. (Split notes: `l2-1a-files.patch` was a full HEAD-dump not an
  isolated patch — L2-1a staged from the residual working diff after units 1–6,
  spot-checked against its NOTES; the launcher same-day-guard + tier-model
  dependency-bracket hunks were folded into unit 6 by narrative match.)
- **UH bug-hunt DONE — see `project-docs/26-uh-implementation-bug-findings.md`
  (durable copy; canonical scratchpad original at session
  `9488f3f3-…/scratchpad/uh-bug-findings.md`).** Three parallel reviewers
  (soundness / MPC-leakage / correctness), two headline items
  coordinator-verified against bb source:
  - **F1 (real soundness gap, coordinator-confirmed):** the native Rust
    verifier `decider_verifier.rs:138` pairing-checks only the Shplemini/PCS
    points; it never reconstructs + aggregates the public-input pairing-point
    accumulator that bb's `ultra_verifier.cpp:223-240` folds in with a random
    separator. Non-recursive circuits use the infinity default so the two agree
    (why every KAT/cross-verify passes); the gap bites only when a **recursive**
    circuit carries a real accumulator **and co-noir's own verifier is the final
    arbiter** — a malicious inner accumulator would be silently accepted.
    Prover output is unaffected (bb/aztec-nr/on-chain still verify correctly).
    Severity medium/high. → **motivates new PLAN item 4.4** (standing test:
    co-snark-generated proofs → bb verifier; + the malicious-accumulator
    negative). Fix owed as a small dedicated unit with a regression test.
  - **DoS/panic cluster (pre-existing, verified F2/F3):** keccak proof/PI parse
    panics on non-32-aligned length (`noir-types/src/lib.rs:192`); unchecked
    `num_public_inputs` from VK bytes drives `Vec::with_capacity`
    (`oink_verifier.rs:55`); JSON path unwraps + keccak u128 truncation. Same
    class as the Phase-0 off-curve panic — crash, not false-accept.
  - **Lever pile CLEAN:** the MPC/leakage reviewer found no correctness or
    leakage bug in L2b/L2c/L1f/L0c/L0d/L8/L0e — half-share MSM reconstructs only
    the public commitment (type-prevented from re-entering share arithmetic),
    seeded-ZK blinding confirmed unreachable from production, batch
    inversion/reshare/degree-reduction preserve share invariants. One
    cross-corroborated one-line hardening (both MPC + correctness reviewers): move
    the L0e sha stale-cache clear above the `!is_shared` early return in
    `co-acvm/src/mpc/rep3.rs precompute_sha256_block` (non-triggerable today).
- **PLAN 4.4 ADDED** (Mike's ask): standing test that co-snark-generated UH
  proofs verify in the bb UH verifier. Scoped against what already exists
  (`compare_mpc.sh` `run_proof_verification` does the 4-way MPC-proof→bb-verify
  for poseidon+keccak × ZK/non-ZK, but only in the slow `--full` gate) — the
  delta is a first-class always-visible test with guaranteed ZK + recursion +
  Shamir coverage and the negative (tampered proof → bb reject).
- **Bench v3 (netem tiers) LAUNCHED** (Sonnet agent). Focused REP3 cells
  (poseidon_2e17/2e20, bb_sha256_compression) under `lo` shaped to match
  `bench-tier-model.py`'s tiers exactly (loopback control / LAN 1 Gbps 2 ms /
  WAN 100 Mbps 40 ms; delay=RTT/2 on loopback, cleanup trap mandatory).
  Purpose: validate the tier-model PREDICTIONS (est_pipelined + [dep_lo,dep_hi]
  bracket) against real measured WAN/LAN cost — first-of-kind numbers.
  Results recorded IN-REPO under `bench-results/2026-07-26-v3-netem/` with a
  README (predicted-vs-measured table + error analysis) per Mike's ask.
- **NEXT (queued):** on bench-v3 landing, fold results into the bench README +
  consider explorer re-bake; the F1 fix + PLAN 4.4 standing test are the top
  correctness follow-ups; then the pivot decision (Phase 5.0 PXE secret sharer
  vs 5.1d TS orchestration). Session-19 doc edits (PLAN 4.4, ch. 26, README
  index, this entry) remain UNCOMMITTED pending Mike's word.
