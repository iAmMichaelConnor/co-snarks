# Project: co-SNARKs for latest UltraHonk — documentation index

> ⛔ **CONFIDENTIALITY (binding):** this project's code and docs must never be
> committed/pushed to any remote — no public repos, no PRs to Taceo, no
> external services. Content here derives from the private
> `aztec-packages-private` repo. All work stays local. See PLAN.md.

This directory is the durable record of the project described in `../PLAN.md`
(enabling co-SNARKs of the latest UltraHonk proving system with Noir).
It is written for a reader with **no prior context** — neither about co-SNARKs
nor about any prior conversation — and doubles as the hand-off document for
future working sessions (human or AI).

## How to use this directory

- Read `../PLAN.md` first (the mission statement + the appended actionable plan).
- `PROGRESS.md` is the session-by-session log: what was done, what was decided,
  what is in flight. **Every working session must append to it.**
- Numbered chapters are the reference material. They are maintained documents:
  when facts change (e.g. a new barretenberg version lands), update them.

## Chapters

| File | Contents | Status |
|---|---|---|
| `01-cosnarks-primer.md` | What co-SNARKs are; MPC fundamentals (REP3, Shamir); how a Honk-style prover is MPC-ified. Educational, self-contained. | drafted (2026-07-08) |
| `02-cosnarks-repo-map.md` | Architecture of Taceo's `co-snarks` repo: the co-noir proving stack + all wrapper tooling. | complete (2026-07-08) |
| `03-bb-diff-analysis.md` | What changed in barretenberg UltraHonk between `v5.0.0-nightly.20260324` (co-noir's compatibility pin) and current HEAD, decomposed at the public/private fork boundary. | complete (2026-07-08) |
| `04-monty-hall-and-aztec.md` | How `monty-hall-aztec` orchestrates co-noir; the verified v5-next in-contract verification recipe (§5); critique of the hackathon design (§6). | complete (2026-07-08) |
| `05-approach-assessment.md` | Approach 1 (co-snarkify bb C++) vs approach 2 (update Rust co-noir) vs alternatives; recommendation + rationale + Mike's decisions. | complete (2026-07-08) |
| `06-blackbox-support-matrix.md` | All 14 ACIR blackboxes × co-noir support (witext/brillig/builder), difficulty to add missing ones, plain-language constrained-vs-unconstrained explainer, guidance for circuit authors. | complete (2026-07-08) |
| `07-ultrahonk-primer.md` | UltraHonk from a Plonk baseline (sumcheck, logup, Shplemini, ZK flavors, proof format) + stage-by-stage MPC mapping. | complete (2026-07-08) |
| `08-data-flow-diagrams.md` | Diagrams: participants/channels, share splitting & distribution, MPC witness extension, Fiat–Shamir round pattern, REP3 mult, Aztec PSS end-to-end, who-learns-what. | complete (2026-07-08) |
| `09-pxe-secret-sharer.md` | Getting all secret types (notes, privacy keys, signing keys, authwits, nonces, tagging secrets) out of the client into co-noir REP3 shares: candidate paths ranked, layered recommendation, consent model, open questions. | evolving; Q2–Q3 open (2026-07-08) |
| `10-pxe-wallet-architecture.md` | Teach-from-scratch mental model of the v5-next client stack (node / PXE / wallet / account / entrypoint); the two databases; where every secret lives; layer/store/tx-flow diagrams. | complete (2026-07-08) |
| `11-phase2-sync-workplan.md` | Deep, file-by-file plan to update co-noir to v5-next — now annotated **AS BUILT** per work item (commits, divergences from plan, retrospective + 2.9 postscript: what the sync missed in the recursion verifier and the lessons). Starts with the PLAN.md-vs-ch.11 division of labor + work-item numbering map. | complete + AS BUILT; items 2.1–2.7 done, 2.9/2.10 postscript (2026-07-09) |
| `12-sync-runbook-and-prompts.md` | Repeatable procedure + copy-paste agent prompts for any future version sync; safety invariants; gotcha checklist (incl. oracle provenance); unsupported-feature guardrails; drift detection. | complete (2026-07-08) |
| `13-parity-and-soundness-tests.md` | Test plan for byte/verifier parity with bb + soundness (negative tests incl. §3a mandatory security regressions) + completeness + MPC-consistency + differential fuzz; what to build in each phase. | complete (2026-07-08) |
| `14-phase0-command-log.md` | Chronological Phase 0 **and Phase 2** command record (§§12–23): every command (incl. failures + root causes), what it achieved, environment requirements, doc-improvement notes. §§21–23 = the overnight backlog run, VK byte-KATs, and the PLAN-2.9 recursion-parity investigation/fix. | live (2026-07-09; through PLAN 2.9/2.10) |
| `15-improvement-backlog.md` | Post-Phase-2 backlog: VERIFY items, extra test ideas beyond ch. 13, Rust refactor/perf ideas (MPC mul batching, allocation hot spots), anti-drift machinery. Statuses maintained in place (✅ done / open); many §1–§2 and §4 items landed 2026-07-08/09. | live (2026-07-09) |
| `16-phase5-monty-hall-modernization.md` | PLAN 5.1 workplan: modernize monty-hall-aztec to the synced co-noir + v5-next aztec-nr. As-is inventory (call sites, defects), old→new API delta tables (co-noir Rust §3 + aztec-nr contract §5.0), work items A0–A5 / B1–B4 / 5.1c–d with gates; Q1/Q2/Q4 answered. | live (2026-07-13); A0–A4 DONE, A5 open |
| `18-aztec-note-compat-and-local-network.md` | Implementation spec for bit-identical Aztec notes/nullifiers from external (MPC) circuits: all DOM_SEP formulas verified file:line, design facts (inner-hash-only, no-delivery notes are legal, nhk_app is a plain formula), A5a design, local-network/TXE runbook incl. the verify_proof-is-a-no-op-in-TXE caveat. | new (2026-07-13) |
| `17-monty-hall-quality-backlog.md` | Quality review of monty-hall-aztec (Rust + Noir vs current aztec-nr idioms + HackMD design context): confirmed-bug fixes of 2026-07-13 (incl. the choose_door game-logic bug), open test/security/style backlog, contract findings feeding 5.1b, execution order. | live (2026-07-13) |
| `19-v5.0.1-resync-gap-analysis.md` | The v5.0.1 resync: tag-provenance finding (private/public nightly tags of the same name are DIFFERENT commits; co-noir's true baseline already equalled v5.0.1 → zero porting), full Stage-4 validation matrix at the new oracle, pin flip. Supersedes ch. 03 as the *current* baseline analysis. | complete (2026-07-20) |
| `20-phase5-1d-ts-orchestration-workplan.md` | PLAN 5.1d workplan: port the monty-hall orchestrator (HTTP fan-out + byte-identity cross-check + proof verification) to TypeScript; frozen API contract, bb.js-verify spike, LE/BE field-codec gotcha, work items T0–T6 with gates, acceptance = existing e2e suites unchanged. | new (2026-07-23); T0–T6 open |
| `21-pre-ts-tidying-plan.md` | One-session tidying pass of both branches before 5.1d: monty-hall M1–M7 (README/version-label truth, ch. 17 status pass, debris decisions, lint), co-snarks C1–C6 (TODO triage, sync-debris sweep, doc-truth banners, the deferred SSIPA A(1)=0 test, sweep sharding), cross-repo X1–X3. Tidies the tree, not the git log. | new (2026-07-23); all open |

## Key facts established so far (updated 2026-07-08, after Phase 2 code-complete)

**Project state:**
- **Phase 0 DONE** (pipeline validated at the old pin: 603/603 tests, 29/29
  bb-cross-verified circuits, sound under tampering — ch. 14 §§1–11).
  **Phase 1 DONE** (decisions). **Phase 2 CODE-COMPLETE**: items 2.1–2.6 all
  landed on branch `mc/update-co-noir` (commits `4e7abb95` pin bump,
  `e70252e1` KATs, `1a13fcdc` relations/entity reorders, `571c1305`
  trace-offset + ZK, `5ac55600` builder residue). **Only 2.7 (green-up)
  remains**: full examples recompile + compare_mpc.sh vs both oracles +
  ch. 13 §3a security regressions. Status tracker: PLAN.md; AS-BUILT
  detail: ch. 11; chronology: ch. 14 §§12–19.
- Milestone already achieved: **plain KAT byte-equality vs true-target bb**
  (both circuits × both hashers), ZK bidirectional bb cross-verify, VK
  byte-identical, proof sizes 410 (non-ZK) / 458 (ZK) / VK 115 fields —
  lengths identical to the old pin (the sync changed byte content/order
  only).
- ⚠ **Oracle correction (ch. 14 §17.1)**: THE target parity oracle is
  **`~/.bb-target-src/bb`** (built from source at `v5.0.0-nightly.20260708`,
  PROVENANCE.txt alongside). The prebuilt `~/.bb-target/bb` (5.0.0-rc.2) is
  **deprecated** — its release binary predates the entity reorder and emits
  old-order VKs; any doc text saying "rc.2 ≡ v5-next" is stale. Old-pin
  regression oracle stays `~/.bb/bb`.
- Item 2.6 found **two extra proof-breaking bb changes** the diff analysis
  had not flagged as such: lookup `table_index` now starts at 1
  (`0a7d0af035`) and SHA-256 CH-L2 tables became 10-bit + a w[0] range
  constraint (`bbbde54094`/`5d43e115a2` — soundness fixes). Lesson: KAT
  circuits under-cover builder changes; per-feature parity circuits needed
  (ch. 11 §4 AS BUILT, ch. 15).

**Background facts (from session 1, still true):**
- `~/co-snarks` is a checkout of TaceoLabs/co-snarks upstream `main`,
  last commit 2026-07-06 — the repo is **actively maintained**, not abandoned.
- The Rust UltraHonk rewrite (`co-noir/ultrahonk`, `co-noir/co-ultrahonk`)
  was pinned to **barretenberg `v5.0.0-nightly.20260324`** / nargo beta.20
  (~3.5 months behind, **not** the >1 year initially feared); our branch has
  now moved it to the target (`v5.0.0-nightly.20260708` ≡ `origin/v5-next`,
  nargo beta.22).
- `~/aztec-packages-private` HEAD is in the `v6.0.0-nightly` series; the two
  v6-only UH-breaking commits are NOT in v5-next, so Phase 3 (v6 port)
  stays a contingency (ch. 03).
- Taceo's version syncs (per their public history) happen in periodic bursts,
  roughly every 1–2 months.
- Decisions (Mike, 2026-07-08; full list in PLAN.md): target `origin/v5-next`
  (≡ public v5 tip — verified); **no-push confidentiality rule**; no Taceo
  contact for now; ZK flavor default (HONK_ZK=6); 3-party semi-honest REP3 OK;
  implementation independence from bb's C++ structure (decision 6a);
  key output = co-snarks generated from ALL client secret types (ch. 09–10).
- Repo pointers: `~/aztec-packages-private` (reference, incl. v5-next +
  private v6 line), `~/ap-next` = public aztec-packages `v5-next` where PXE
  development actively continues, `~/monty-hall-aztec` (stale demo).
- Env: rustc 1.90 (repo override), nargo 1.0.0-beta.22, oracles
  `~/.bb/bb` (old pin) + `~/.bb-target-src/bb` (target, source-built).
