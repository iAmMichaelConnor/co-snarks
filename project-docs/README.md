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
| `11-phase2-sync-workplan.md` | Deep, file-by-file plan to update co-noir to v5-next: the four proof-format changes, builder/DSL gate changes, KAT regen, green-up order, effort/risk. | complete (2026-07-08) |
| `12-sync-runbook-and-prompts.md` | Repeatable procedure + copy-paste agent prompts for any future version sync; safety invariants; gotcha checklist; unsupported-feature guardrails; drift detection. | complete (2026-07-08) |
| `13-parity-and-soundness-tests.md` | Test plan for byte/verifier parity with bb + soundness (negative tests) + completeness + MPC-consistency + differential fuzz; what to build in each phase. | complete (2026-07-08) |
| `14-phase0-command-log.md` | Chronological Phase 0 command record: every command (incl. failures + root causes), what it achieved, environment requirements, doc-improvement notes for co-noir/bb READMEs. | live (2026-07-08) |

## Key facts established so far (2026-07-08)

- `~/co-snarks` is a checkout of TaceoLabs/co-snarks upstream `main`,
  last commit 2026-07-06 — the repo is **actively maintained**, not abandoned.
- The Rust UltraHonk rewrite (`co-noir/ultrahonk`, `co-noir/co-ultrahonk`) claims
  proof/vk compatibility with **barretenberg `v5.0.0-nightly.20260324`**
  (per `co-noir/co-noir/Readme.md`) and nargo `v1.0.0-beta.20`.
  So the staleness gap is ~3.5 months, **not** the >1 year initially feared.
- `~/aztec-packages-private` HEAD (2026-07-07) is in the `v6.0.0-nightly` series —
  a major version bump happened after the pin. UH-relevant dirs changed by
  ~265 files / ~36k insertions since the pin (raw churn incl. tests; see ch. 03
  for what actually breaks proof compatibility).
- The `v5.0.0-nightly.20260324` tag exists in `aztec-packages-private` itself,
  so precise `git diff` archaeology is possible locally.
- Taceo's version syncs (per their public history) happen in periodic bursts,
  roughly every 1–2 months.
- Decisions (Mike, 2026-07-08; full list in PLAN.md): target `origin/v5-next`
  (≡ public v5 tip — verified); **no-push confidentiality rule**; no Taceo
  contact for now; ZK flavor default (HONK_ZK=6); 3-party semi-honest REP3 OK;
  key output = co-snarks generated from ALL client secret types (ch. 09–10).
- Repo pointers: `~/aztec-packages-private` (reference, incl. v5-next +
  private v6 line), `~/ap-next` = public aztec-packages `v5-next` where PXE
  development actively continues, `~/monty-hall-aztec` (stale demo).
