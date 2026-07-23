# Chapter 21 — Pre-5.1d tidying plan (both branches)

*Created 2026-07-23 (session 13), on Mike's ask: "before we get to the ts
stuff, should we do some passes of tidying the co-snark and monty-hall work
that we've done on our branches?" Answer: yes — one focused tidying session,
then 5.1d (ch. 20) starts in a fresh session against clean, committed,
fully-green branches. Checkboxes are live status.*

## 0. Scope and non-goals

**Goal:** both branches (`co-snarks:mc/update-co-noir`,
`monty-hall-aztec:mc/modernize`) left in a state a new reader (or the fresh
5.1d session) can trust: no stale comments/READMEs contradicting the code,
no leftover investigation debris, statuses in the backlogs true, everything
committed, all gates green.

**Non-goal — history rewriting.** Neither branch is ever pushed or PR'd
(confidentiality rule), so there is no audience for a squashed/rebased
history; the commit trail is our audit log and PROGRESS.md cross-references
its hashes. Decision: keep history as-is; tidy the *tree*, not the *log*.

## 1. monty-hall-aztec (`mc/modernize`)

- [x] **M1 — README accuracy pass.** ✅ 2026-07-23 (agent). The README's pins paragraph is now
      WRONG: it still says the circuits'/contract's deps are "path-deps
      into a local aztec-packages checkout verified to match that tag" —
      superseded 2026-07-23 by git+tag release deps. Rewrite that
      paragraph; sweep the rest of the README against the as-built repo
      (scripts list, env knobs incl. the new per-suite identity overrides,
      trust-model section still accurate).
- [x] **M2 — stale version-label sweep.** ✅ 2026-07-23 (2 Cargo.toml comments + aztec_note.nr header; versions.env history lines deliberately kept). grep the repo (excluding
      upstream-issues/, which is historical record) for
      `v5.0.0-nightly.20260708` and stale "synced to" comments — e.g.
      `mpc/*/Cargo.toml` comments say "synced to bb v5.0.0-nightly.20260708";
      the truthful label is now v5.0.1 (ch. 19). Fix labels; do NOT touch
      upstream-issues history.
- [ ] **M3 — ch. 17 (quality backlog) status pass.** Walk every open item
      in co-snarks ch. 17 against the as-built code and mark what the
      session-9 rework already closed (several contract F-items, hash-claim
      staleness, TLS) vs genuinely open (to_address_point sqrt panic =
      upstream #8970; LocalNetwork test-tier ideas; pss_utils test gaps if
      any remain). Output: ch. 17 statuses true, a short "still open" list.
- [x] **M4 — investigation-debris decision pass.** ✅ 2026-07-23 (4 repro drivers → upstream-issues/repro-tools/ + README there; verify_probe left in place — NB it is NOT actually a contract-workspace member). Deliberate keep/move
      decisions, recorded in place: `contract/verify_probe` (diagnostic
      contract), `e2e/probe_driver.mjs` + `official_example_driver.mjs` +
      `run_official.sh` (bug-repro drivers), `clientivc-recursive-verify-repro/`
      (fixture + logs), driver.mjs `ROUND1_DIR`/`STOP_AFTER_ROUND1` probe
      hooks. Default recommendation: KEEP all, but move the three
      bug-repro drivers under `upstream-issues/repro-tools/` so the
      top-level e2e/ dir only contains the live demo driver; leave the
      probe hooks (documented discriminators).
- [x] **M5 — lint/format gate.** ✅ 2026-07-23 (cargo fmt fallout in 5 files, whitespace-only; clippy 0; nargo fmt in 4 packages; gates re-run green after). `cargo fmt --check` + `clippy -D warnings`
      across mpc/; `noirfmt` (or `nargo fmt`) across noir_logic/ + contract/;
      fix fallout. (Rust was clippy-clean at session 9 — verify it stayed so.)
- [x] **M6 — gitignore/artifact hygiene.** ✅ 2026-07-23. OPEN DECISION for Mike: tracked dead dev-certs at noir_logic/network/data/*.der (unreferenced; recommend delete next commit). Verify `e2e/vks/`,
      `contract/target/`, `noir_logic/*/target/` gitignore status is
      intentional; confirm no key material or fixture blobs are tracked
      that shouldn't be. (`mpc/mpc-node/data/circuits/*.json` ARE tracked
      on purpose — refreshed 2026-07-23; note this in README.)
- [ ] **M7 — commit the tidy + re-run the fast gates** (check.sh, TXE,
      mpc cargo; e2e suites only if M-items touched them).

## 2. co-snarks (`mc/update-co-noir`)

- [x] **C1 — TODO triage.** ✅ 2026-07-23 (ch. 15 §5: 162/163 upstream, 1 ours — stale TODO(phase2-2.6), now deleted/replaced with the as-verified note). ch. 15 header notes ~72 `TACEO TODO`s in
      co-noir/. Separate: (a) Taceo's own upstream TODOs (leave — not ours,
      minimizes diff vs their repo), (b) TODOs *we* introduced during the
      sync (resolve or convert into ch. 15 items with owners). Output: a
      short table in ch. 15.
- [x] **C2 — sync-debris sweep.** ✅ 2026-07-23: CLEAN — no 2.9 instrumentation leaked; all allows/tracing upstream. Only note: examples test_vectors/ranges/ is a dead UPSTREAM fixture (pre-dates fork; leave). Look for leftovers from the Phase-2/2.9
      differential-debugging sessions: instrumentation/dump code paths,
      commented-out blocks, scratch test vectors not referenced by any
      test, stale `#[allow]`s. (The 2.9 per-row trace instrumentation was
      agent-side, but verify none leaked into the tree.)
- [x] **C3 — doc-truth sweep.** ✅ 2026-07-23 (4 banners: ch. 02, ch. 04 ×2, ch. 05; ch. 03/11/14 deliberately unbannered — inherently dated records that self-correct). ch. 04 §5 and
      ch. 02/05 were written pre-resolution; grep chapters 01–14 for
      claims superseded by ch. 19/PLAN-5.1-RESOLUTION (e.g. "real-proving
      blocked", "v5.0.0-nightly.20260708 is the pin") and banner them the
      way ch. 18 §6 was done on 2026-07-23. PROGRESS.md is append-only —
      never edit old entries.
- [x] **C4 — SSIPA A(1)=0 test.** ✅ 2026-07-23: zk_proof_ssipa_evaluation_tamper_rejected (red-mutation validated; found SSIPA evals bound twice independently — defense-in-depth). PLAN 2.7 + ch. 13 §3a#8 updated. From ch. 15: the SSIPA A(1)=0
      boundary-claim consistency test (§3a#8, the one deliberately-deferred
      security regression — decide: implement now (~half day, closes the
      last Phase-2 follow-up) or explicitly re-defer with rationale.
      Recommendation: implement; it is the only "known missing" negative.
- [x] **C5 — acceptance-sweep parallelization** ✅ 2026-07-23: CIRCUIT_FILTER/CONFIG_DIR/scoped-cleanup in compare*.sh + scripts/acceptance-parallel.sh; validated full-matrix PASS in 1003 s (~2.2× vs serial, more coverage); fast-check --full now routes through it. (ch. 15 §4.9a, new):
      `CIRCUIT_FILTER`/`OUT_DIR` knobs for `compare.sh`/`compare_mpc.sh` so
      the D-tier can shard. Optional in the tidy session; do it if C4 goes
      fast.
- [ ] **C6 — lint/format gate + commit**, then `fast-check.sh --all-fast`
      + (once, at the end) the full acceptance gate.

## 3. Cross-repo

- [ ] **X1 — commit everything now-pending** (this session's uncommitted:
      script isolation knobs, run.sh kill-scoping, docs reconciliation,
      ch. 20/21, PROGRESS/ch. 14 updates) — needs Mike's word per the
      no-commits rule.
- [ ] **X2 — PROGRESS + ch. 14 entries** for the tidy session itself
      (standing convention; Mike re-affirmed 2026-07-23).
- [ ] **X3 — memory hygiene**: after tidy, update [[cosnark-uh-project]]
      status paragraph; the bisection memory is already final.

## 4. Suggested execution

One session, in this order: M1–M2 (fast, high reader-value) → C3 (same
nature) → M3 → C1–C2 → C4 → M4–M6 → C5 (if time) → M7/C6/X1–X3 gates +
commits. Estimated: one focused session; C4 is the only item with real
engineering content. Then 5.1d starts fresh (ch. 20), per the
fresh-session decision.
