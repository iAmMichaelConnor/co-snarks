You're in the Taceo co-snarks repo. My main goal is to ensure cosnarks (aka co-snarks) are possible with Noir and the very latest UltraHonk proving system. You have access to the latest implementations of Noir and Ultrahonk via `~/aztec-packages-private/` on this machine. Note: UltraHonk (aka UH) lives in the `barretenberg/` dir of `~/aztec-packages-private/` and Noir lives in the `noir/` dir.

> Note: UltraHonk is a different proving system from Chonk; both proving systems live in Barretenberg, and might even share common codepaths. We don't care about a co-snark implementation of Chonk for our project because it would be too complex and slow to prove a co-snark of Chonk.

We (Aztec) asked the Taceo team to implement a co-snark version of UH. Barretenberg (including UH) is written in C++, but the Taceo team prefer Rust, so I believe they re-wrote UltraHonk in Rust within this `co-snarks` repo within the `co-noir/` dir. But they did this over a year ago, so I suspect their Rust version of the UH proving system (in `~/co-snarks/co-noir/`) is very outdated relative to the latest UH proving system at `~/aztec-packages-private/barretenberg/`.

I want you to assess what the best approach would be to enable co-snarks of the very latest UH proving system. The reference implementation for the very latest system is at `~/aztec-packages-private/barretenberg/`, but it doesn't include any code relating to "co-snarkification". The outdated implementation is at `~/co-snarks/co-noir/` which _does_ include code relating to co-snarkification. So I see two potential options (although you might want to suggest more options):
1. Add code to barretenberg (likely in the C++ language?) which enables co-snarkification of the barretenberg implementation of UH. This approach would understand everything about `~/co-snarks/co-noir/` and try to re-implement the co-snark-related concepts in `~/aztec-packages-private/barretenberg/`.
2. Update the Rust implementation of UH (in `~/co-snarks/co-noir/`) to "exactly match" the latest C++ version of UH. This approach would need to understand how exactly the C++ version of UH has changed since the Rust version was written, and update the Rust version to match the C++ version. By "exactly match", I mean a proof generated with one version (C++ or Rust) should be verifiable by a verifier of the other version (Rust or C++, respectively), without any discrepancies. The implementation details of the Rust implementation can vary considerable vs the C++ version if you like, as long as it's sound and complete.

I'm not familiar with how co-snarks work, nor the content of the `~/co-snarks/` repo, so please also educate me. Don't assume I know anything. Always explain things to me in detail, and ALWAYS read the code and README.md and CLAUDE.md and SKILLS.md and AGENTS.md (and other such, similarly named md files) of the `~/aztec-packages-private` and `~/co-snarks` repos, rather than guessing. 
As you embark on making coding changes, you MUST:
- Record what the plan is.
- Update the plan if your plans change.
- Maintain a very detailed doc about this project, including: your aims; design choices; rationale; tradeoff decisions; implementation details; diagrams for the flow of information between participants, and for steps participants must do, their high-level calculation actions, and the sharing of data between them; commands for building, running, testing, etc.. And ensure this doc doesn't assume the reader was privy to any of our chats; it must be written as though the reader is someone new to the subject of cosnarks and/or a future AI session which doesn't have any context. We can talk more about the diagrams. 

Criteria for assessing approach 1 vs approach 2 vs other approaches that you think would be better:
- A "working" implementation would satisfy this definition of "done":
    - A co-snark over simple Noir circuits can be generated (perhaps without certain blackbox functions implemented, although I'd like the assessment to consider how difficult it would be to get blackbox functions working).
    - The generated co-snark can verify correctly against the latest UH verifier. Multiple inputs should be tested (for valid and invalid proofs) to ensure soundness and completeness.
    - There is lots of rust tooling within `~/co-snarks` and within `~/monty-hall-aztec` which "wraps" the co-snarks. I.e. this "wrapper" code treats co-snark MPC proving as a "black box" but enables spinning-up and orchestration of the MPC network, enables shared secrets to be generated and shared, enables sharding of a user's witness data, enables the shards of co-snark proofs to be recombined into a single co-snark, enables encryption of data between users and MPC and between MPC nodes. You know what I mean? Research that thoroughly. A "working" implementation should include this tooling. Rather than rebuilding all that tooling and wrapper code, I imagine we'd make edits to the existing `~/co-snarks/` code, even if "approach 1" above is taken -- of implementing the co-snarkification in barretenberg. I'm open to alternative suggestions, though. E.g. if approach 1 is taken, re-implementing the rust "wrapper" tooling entirely in typescript/C++. (Typescript would be good to help integrate this into the PXE for enabling a user to create secret-shares of their private data in Aztec for UH co-snark proofs). I'd be happy with the existing Rust wrappers whilst we get the actual UH proving system co-snarkified, and then consider typescript versions of the tooling later. Please can one of your early tasks be to outline and explain all of the wrapper tooling that exists in `~/co-snarks` beyond the UH proving system itself, that we will need?
    - Understand `~/monty-hall-aztec` and how UH aztec proofs can be generated and verified within Aztec private smart contract functions. A general pattern for generating co-snarkified UH proofs (using an Aztec user's secret data, secret note data, secret keys, etc from their PXE) is the ultimate ultimate goal of all of this.
- How fast can a working implementation with the latest UH proving system be "working"?
- We want to minimise future ongoing maintenance burden or code duplication. The barretenberg version of the UH proving system has been audited extensively, so my preference would be approach 1 above. But it depends on how significant the modifications to barretenberg would be? We want to do minimal changes to the existing C++ code so as not to invalidate audits, but we'd be happy to add new files if most of the extra co-snarkification work can be done in new files without many changes to the C++? The Aztec team would probably find it easier to maintain a C++ version of UH. Please could one early task be for you to outline the extra functionality and code (beyond the C++ UH implementation) that co-snarkification will require?
- Thorough tests which can be run and pass. Many such tests might already exist in the reference co-snarks/ repo.

I want you to explain everything to me in detail, and I want those explanations to be recorded (in the aforementioned doc that I want you to maintain). I want access to that doc too.

We should extend append to this PLAN.md doc (but not modify any of my text above) an actual plan.

---

# THE PLAN (appended by Claude; Mike's text above is immutable)

*Created 2026-07-08 (session 1). Maintained: update statuses here as phases
progress; per-session detail goes in `project-docs/PROGRESS.md`.*

## ⛔ CONFIDENTIALITY RULE (Mike, 2026-07-08 — binding on every session)

**Never commit or push any of this project's code or docs to any remote,
especially not to any public repo, and especially not as a PR to Taceo's
repo.** The target includes content derived from the private
`aztec-packages-private` repo. All work stays in the local working copies.
Local commits: only if Mike explicitly asks. No `git push`, no `gh pr create`,
no pasting project code into external services. When in doubt, don't.

## Decisions made by Mike (2026-07-08)

1. **Target = `origin/v5-next` of aztec-packages-private.** (Verified: its
   barretenberg tree is identical to public tag `v5.0.0-nightly.20260708`,
   and the two v6-only breaking commits are NOT in it → the sync gap is the
   four public consensus changes + builder changes; the v6 port phase becomes
   a contingency, not a phase.)
2. **No Taceo engagement for now** (maybe later). All work in-house, local.
3. **ZK-flavor requirement — RESOLVED (2026-07-08)**: Taceo implements both
   ZK and non-ZK flavors; Aztec's in-contract path supports BOTH
   (proof_type HONK=0 non-ZK, HONK_ZK=6 ZK; poseidon2 transcript mandatory;
   proof 410/458 fields, VK 115 fields on v5-next — full recipe in
   project-docs ch. 04 §5). Default to **ZK** for co-snarks (the proof can
   otherwise leak witness data to whoever handles it); non-ZK acceptable for
   pure self-delegation.
4. **Blackbox priority**: document the full support matrix + difficulty
   (project-docs ch. 06); build-out only as needed by target circuits.
5. **3-party honest-majority semi-honest REP3 is acceptable for now.**
6a. **(2026-07-08, session 2) Implementation-independence principle.** The
   co-noir Rust may be structured however is best practice (following
   Taceo's existing conventions) — do NOT copy bb's C++ layout blindly.
   The two implementations should stay as independent as possible so they
   can be *differentially fuzzed* against each other later (ch. 13 §6);
   the only mandatory coupling is behavioral: proof/VK byte parity and
   mutual verifier acceptance at the KAT boundary.
6. **(2026-07-08, later) Key project output: co-snarks from PXE secrets.**
   The user's notes / secret keys / private state live in their PXE, which
   today has no way to export them for secret-sharing. We must design the
   lightest-weight extraction path (PXE maintainers are not amenable to
   PRs/reviews), with user consent, feeding a new "PXE secret sharer" module
   that produces co-noir-compatible REP3 shares. Reference PXE: private
   repo's `v5-next`, but NOTE active development continues on the PUBLIC
   repo's `v5-next`, checked out at `~/ap-next` (verified: public
   aztec-packages, branch v5-next, current 2026-07-08). Exploration and
   recommendation: project-docs ch. 09; work items in phase 5 below.

## Where all project knowledge lives

- **`project-docs/`** — the detailed, self-contained project doc requested
  above. Index: `project-docs/README.md`. Chapters: 01 co-SNARK/MPC primer,
  02 co-snarks repo map + wrapper-tooling catalogue, 03 bb version-diff
  analysis, 04 monty-hall/Aztec integration, 05 approach assessment,
  06 blackbox support matrix, 07 UltraHonk primer, 08 data-flow diagrams,
  09 PXE secret sharer, 10 PXE/wallet architecture, 11 Phase-2 sync workplan
  (status lives HERE in PLAN.md; ch. 11 is the file-by-file HOW, annotated
  AS BUILT), 12 sync runbook + agent prompts, 13 parity/soundness test plan,
  14 Phase 0+2 command log, 15 improvement backlog, 16 Phase-5.1 monty-hall
  workplan, 17 monty-hall quality backlog, 18 note-compat + local-network
  spec, 19 v5.0.1 resync gap analysis (supersedes 03 as current baseline),
  20 Phase-5.1d TS orchestration workplan.
- **`project-docs/PROGRESS.md`** — append-only session log. Every session
  starts by reading PLAN.md + README.md + PROGRESS.md, and ends by appending.

## Findings that reframe the mission (details & evidence in project-docs)

1. Taceo's Rust UltraHonk is NOT ~1 year stale: it is pinned to bb
   `v5.0.0-nightly.20260324` (~3.5 months behind) and Taceo re-syncs every
   1–2 months, with byte-level proof-compatibility tests against bb KATs.
2. "Latest UH" splits in two: public aztec-packages is still v5-nightly;
   the private repo's v6 line adds exactly **two** UH-proof-breaking commits
   (full-width Fiat–Shamir challenges `a69ffdf8a1`; ROM-via-logup
   `d3e42f9d3a`) that Taceo cannot see.
3. There is no "proof shard recombination": MPC parties each emit an
   identical, standard proof. The real tooling gap is user→MPC share
   submission/encryption + orchestration (monty-hall-aztec is the unfinished
   reference pattern for exactly that).
4. **Recommendation: approach 2** (update Rust co-noir), decomposed as
   public-sync + tiny private-port, with the bb C++ left untouched. Approach 1
   (C++ co-snarkification of bb) is rejected: it means rebuilding Taceo's MPC
   stack from scratch anyway — see `project-docs/05-approach-assessment.md` §1.

## Phases

### Phase 0 — validate the pipeline at the current pin  [~DONE 2026-07-08; ch. 14]
Goal: a co-snark generated and verified end-to-end this week; baseline metrics.
- [x] 0.1 Build co-snarks workspace (needs rustc 1.90 — ch. 14 §2); test suite
      `cargo test -p tests --release`: FINAL 603 passed / 0 failed (ch. 14 §4).
- [x] 0.2 3-party local demo: proof verified; all 3 parties' proofs
      byte-identical; ~752 ms/party proving (poseidon) (ch. 14 §5).
- [x] 0.3 Cross-verify vs real bb at the pin (prebuilt release binary, not
      source build): compare_mpc.sh — FINAL 29/29 circuits, 0 errors
      (poseidon2+keccak × ZK+non-ZK, 4-way proof×VK verify) (ch. 14 §6.1).
- [x] 0.4 Soundness spot-checks: 7 tamper cases × both verifiers — no false
      accepts. Two divergences found → fix in Phase 2: (i) co-noir accepts
      trailing proof bytes (bb rejects); (ii) panic (not clean reject) on
      off-curve points in proof/VK (ch. 14 §7).
- [~] 0.5 Benchmark: wall-clock + comms, REP3 vs Shamir, ZK vs non-ZK, vs
      single-prover bb. **v1 RAN CLEAN overnight 2026-07-23** (wall-clock
      only; PROGRESS session 14): REP3÷bb = 6.0× poseidon / 439.6× sha256 /
      29.8× recursion_zk → cost tracks gate COMPOSITION, not size; explorer
      recalibrated (ch. 22 V7). **v2 prepared 2026-07-24** (Mike's asks, all
      tracked in ch. 22 §5a): results in-repo (`bench-results/<date>/`);
      comms bytes+msgs per phase (R = sequential-rounds proxy — "is R
      constant?" gets measured); circuit-feature capture (`co-noir
      circuit-info`: block composition, lookup/table rows, witness zeros);
      size sweeps poseidon 2^11→2^20 + sha256 2^15→2^20 (ascending,
      600 s/cell timeout prune — Mike's 10-min rule, 2 reps ≥2^18); FAIR
      baselines (bb vkgen split out; plaindriver witness-fed); Shamir cells
      deferred to v2.1 (= REP3-split + translate-witness; split-input is
      REP3-only). Instrumentation ALL LANDED + committed 2026-07-25
      (mpc-net msg counters, CO_NOIR_NET_STATS_JSON, circuit-info, size
      variants, per-cell RSS/CPU%/load stamps, artifact sizes, verify
      cells incl. the verify_bb parity invariant, SQLite ingest, dataset
      README). Quiet-gate REMOVED (host loadavg is mainframe-wide —
      2026-07-24 12:05 decision): run when convenient, stamp load per
      row. **v2 FULL RUN LAUNCHED 2026-07-25** (post-optimisation
      baseline: R post-L1, times post-C1–C3) → `bench-results/2026-07-25/`.
      THEN: bake v2 anchors into the explorer (same URL); v2.1 = Shamir
      via translate-witness; v3 = netem latency tiers (adopt
      Local 10Gbps/0.1ms, LAN 1Gbps/2ms, WAN from the literature —
      ch. 22 §5c).

### Phase 1 — decisions  [DONE 2026-07-08]
- [x] 1.1 Mike answered the 5 open questions — see "Decisions made by Mike"
      above. Taceo engagement deferred (1.2 dropped for now).
- [x] 1.3 Resolve the ZK-flavor question → both supported in-contract;
      ZK is our default. See Decisions item 3 / project-docs ch. 04 §5.

### Phase 2 — sync co-noir to the v5-next target  (~2–4 wks, LOCAL ONLY)  [STARTED 2026-07-08]

**⚠ SUPERSEDED 2026-07-20 (Phase 2b below): the pin moved on from
`v5.0.0-nightly.20260708` to `v5.0.1`.** The working-set block immediately
below is preserved as the historical record of how the *original* Phase 2
sync was pinned — do not treat it as current. Also note (ch. 19 §1): the
`~/.bb-target-src/bb` oracle this block names was actually built from
private-repo commit `289aaec1e027`, not the public mirror's same-named
`v5.0.0-nightly.20260708` tag (a divergent commit) — re-verify tag/commit
identity yourself before relying on any tag name in this block.

**Pinned working set (re-verify at each session start, repos move daily):**
- **Work branch**: `mc/update-co-noir` in `~/co-snarks` (branched off local
  `main` @ `36da0ea8`; origin pushurl DISABLED as no-push rail; local
  commits only, incremental, working-code gate — see ch. 14 §12).
- **bb reference**: `~/aztec-packages-private`, target = `origin/v5-next`;
  effective target tag = `v5.0.0-nightly.20260708` (bb tree verified
  identical to v5-next 2026-07-08, twice). Diff range for all work items:
  `v5.0.0-nightly.20260324..v5.0.0-nightly.20260708` (both tags exist in
  aztec-packages-private).
- **Noir tooling target**: `v1.0.0-beta.22` (= v5-next noir submodule
  commit `c57152f912…`, exactly the upstream release tag; deps stay on
  github.com/noir-lang/noir, vendoring fallback =
  aztec-packages-private/noir/noir-repo).
- **Oracle binaries**: `~/.bb/bb` = 5.0.0-nightly.20260324 (old pin);
  `~/.bb-target-src/bb` = **source-built at v5.0.0-nightly.20260708** — THE
  target oracle (see PROVENANCE.txt next to it; ch. 14 §17.1).
  ⚠ `~/.bb-target/bb` (prebuilt 5.0.0-rc.2) is DEPRECATED as oracle: the
  rc.2 *binary* predates the entity reorder and emits OLD-order VKs (found
  2026-07-08; the earlier "rc.2 ≡ v5-next UH" claim compared source trees,
  not the shipped binary). nargo = beta.22.
- Public mirror for tags/releases: `~/ap-next` (public repo, v5-next).
Work items map 1:1 to the breaking changes in `project-docs/03-bb-diff-analysis.md` §2:
- [x] 2.1 Regenerate/collect fresh bb KATs at the new pin — DONE 2026-07-08
      (4 proof KATs, both circuits × both hashers, non-ZK), but with the
      **source-built** `~/.bb-target-src/bb`, NOT a prebuilt binary: the
      rc.2 prebuilt predates the entity reorder (ch. 14 §17.1). Byte-identity
      independently re-verified. ZK has no byte-KAT (randomized) — covered by
      live bb cross-verify instead.
- [x] 2.2 Permutation relation 2→3 subrelations (+alpha bookkeeping) —
      step ③, commit 1a13fcdc (ch. 14 §16.1).
- [x] 2.3 Trace-offset rework: masking rows at top, content offset 5,
      lagrange_first at row 4 — step ④, commit 571c1305 (ch. 14 §17.2).
- [x] 2.4 ZK rework: masking randomness in witness rows {1,2,3}, new
      row-disabling factor, padding_indicator_array dropped, honest
      virtual-round univariates, SSIPA 5th opening claim A(1)=0, Shamir
      randomness accounting re-derived — step ④, commit 571c1305.
- [x] 2.5 Relation tuple reorder (alpha assignment) — step ③, 1a13fcdc.
- [x] 2.5a **Entity/get_all reorder:** sumcheck-evaluation transmit order +
      VK commitment serialization + recursion mirror — step ③, 1a13fcdc.
- [x] 2.6 Builder/gate-level residue — DONE 2026-07-08, commit 5ac55600
      (ch. 14 §19). ROM/RAM sorted-index pinning (soundness); lookup
      table_index from 1; SHA 10-bit CH-L2 tables + w[0] range constraint;
      uint multitable slot count; recursion size assert + compile-time
      410/458/115 invariants. EC gate parity confirmed empirically.
      Byte-identical vs source-built target bb: ram, rom_shared,
      embedded_curve_add, bb_sha256_compression, blackbox_and/xor,
      get_bytes. NOT ported: secp256k1/r1 table changes (ECDSA
      unimplemented).
- [x] 2.7 Green-up — DONE 2026-07-08 (session 3). Full sweep vs source-built
      oracle ~/.bb-target-src/bb: **all 31 non-recursion circuits PASS** plain
      + REP3 + cargo (603/603); recursion/recursion_zk fixed (stale vectors +
      K count, ch.14 §20) and now self-verify (note: the "bb cross-verify"
      here was same-key only; the true cross-key parity break it hid was
      found and RESOLVED as item 2.9); ≥4-party
      Shamir PASS (validates randomness accounting); ZK bidirectional
      cross-verify PASS; VK byte-identical; 410/458/115 invariants (now
      compile-time asserts). ch.13 §3a security regressions: #9 ROM/RAM +
      #10 trailing/off-curve DONE; verifier hardening landed. Iteration tool =
      `fast-check.sh` (NEVER circom). **Remaining follow-ups (not blocking):**
      ~~SSIPA A(1)=0 boundary-claim consistency test (§3a#8, deferred)~~ —
      **CLOSED 2026-07-23** (ch. 21 C4): `zk_proof_ssipa_evaluation_tamper_rejected`
      landed with red-mutation validation; bonus finding: co-noir binds the
      SSIPA evals TWICE independently (Shplemini/KZG + consistency identity)
      — defense-in-depth vs bb's single check. Non-canonical (≥modulus)
      encoding was RESOLVED as deliberate match-bb behavior (ch.15 §1.3).
- ~~2.8 Upstream PR(s)~~ — dropped per confidentiality rule; work stays local.
- [x] 2.9 **Recursion VK/proof parity break — RESOLVED 2026-07-09**
      (found by the overnight backlog run; full record ch. 14 §23, ch. 15
      §1.9). Seven root causes fixed via differential gate instrumentation
      (per-phase counts → per-row selector/wire dumps) against source-built
      bb: mask_points ∞-asserts (SECURITY: ROM-table guard), bigfield
      top-limb range width 68→50 (SECURITY: tighter less-than bound),
      compute_naf top-entry fix_witness (SECURITY: was unconstrained),
      ZK row-disabling per-subrelation, gate-separator operand order,
      self_reduce quotient-max off-by-one, SmallSubgroupIPA claim-batching
      emission order. RESULT: recursion + recursion_zk VK byte-identical
      to bb; bidirectional cross-verify PASS in both zk modes; 0/703,658
      trace rows differ. Anti-regression: always-on ~5 s
      `recursion{,_zk}_vk_kat` suite tests + compare.sh VK byte-diff for
      every circuit. Bonus fix: the suite's own recursion vectors were
      still stale (K=3 + beta.20 inner proof; only examples were fixed in
      2.7) — refreshed. Proof BYTES are legitimately prover-specific for
      recursion (random masking offset generator): VK identity + mutual
      verification is the parity criterion.
- [x] 2.10 VK byte-KATs — DONE 2026-07-09 (backlog §2.3/§4.3). bb VK bytes
      (source-built oracle) committed for add3u64+poseidon × both hashers
      with per-dir PROVENANCE.txt; plain_test asserts VK byte-parity in
      both zk modes; flipped-byte tripwire validated. Recursion VK KATs
      were deferred to 2.9 and landed with its fix (always-on ~5 s
      `recursion{,_zk}_vk_kat` tests).

### Phase 2b — resync to bb v5.0.1  [DONE 2026-07-20; ch. 19]
- [x] Full write-up: `project-docs/19-v5.0.1-resync-gap-analysis.md`.
      Headline: the C++ source for every UltraHonk-critical directory is
      **byte-identical** between co-noir's true current baseline and
      `v5.0.1` — Stage 3 (porting) is empty by construction. This traces to
      a tag-provenance surprise: the existing oracle (`~/.bb-target-src/bb`,
      `PROVENANCE.txt`) was actually built from private-repo commit
      `289aaec1e027`, which shares the nightly *tag name*
      `v5.0.0-nightly.20260708` with a different, divergent commit in the
      public mirror — verified 4 independent ways in ch. 19 §1.2 (byte-
      identical from-source rebuild of `289aaec1e027`; empty tree-diff
      `289aaec1e027..v5.0.1` for every UltraHonk dir; identical Noir/ACIR
      submodule pin; co-noir's own commit messages already describing
      v5.0.1-era content). Stage 4 (validation) was still run in full and is
      green: bb-vs-bb 100% byte parity, `compare.sh`/`compare_mpc.sh`
      (incl. slow set + recursion) 0 errors vs the new oracle. Pin flipped:
      `versions.env` → `BARRETENBERG_VERSION=5.0.1`,
      `BARRETENBERG_BINARY_DEFAULT=~/.bb-target-src-v5.0.1/bb`. New oracle at
      `~/.bb-target-src-v5.0.1/bb`; old oracle/pin left on disk, not deleted.
      Two incidental pre-existing script bugs found + fixed (ch. 19 §4):
      `compare_mpc.sh`'s hardcoded `TEST_SLOWER_CIRCUITS=0` silently
      overriding the caller's env var, and `fast-check.sh` hardcoding its own
      (now-stale) copy of the oracle path instead of reading `versions.env`.
      Held uncommitted through 2026-07-20 (Mike's confidentiality
      correction); **committed 2026-07-23 on Mike's explicit ask**, after a
      full code-level re-verification of every claim (PROGRESS session 13).

### Phase 3 — CONTINGENCY ONLY: port the two v6-line commits
*Out of scope while the target is v5-next (verified: neither commit is in
v5-next). Reactivate only if the target moves to the v6 line:*
full-width FS challenges (`a69ffdf8a1` = #500) in `co-noir-common/src/transcript.rs`;
**[NOTE session 10: `a69ffdf8a1` (#500) is ALSO the leading fix for the
in-contract UH-verify real-proving bug (Phase 5.1 status) — it bundles
translator op=0 + shift-size + full-width FS + VK regen. That bb-side fix
lands via the AZTEC toolchain pin, not this co-noir transcript port; the two
are independent consumers of the same commit.]**
**[UPDATE 2026-07-23: the 5.1 real-proving bug turned out to be a toolchain
vintage-mismatch confound, resolved at a consistent v5.0.1 pin (5.1 status
block) — so #500/v6 is NOT needed for monty-hall and this contingency stays
dormant unless the co-noir target itself ever moves to the v6 line.]**
ROM-via-logup (`d3e42f9d3a`): memory relation 6→8 subrelations,
`rom_logup_gamma` challenge in oink, builder ROM gate changes.

### Phase 4 — maintenance machinery (anti-drift)
**⚠ HOLD (Mike, 2026-07-08): discuss with Mike BEFORE making any changes to
barretenberg or aztec-packages CI (items 4.1/4.2). Anti-drift work inside the
local co-snarks tree (4.3, ch. 15 §4 items) may proceed.**
- [ ] 4.1 CI job (aztec-packages-private) running co-noir KATs against bb
      nightly → UH-breaking changes detected on merge.
- [ ] 4.2 Identify the ~6 proof-format-defining bb dirs; add co-snark-impact
      note to bb PR review guidance.
- [ ] 4.3 **Grow the co-noir differential-fuzz / negative-test set as
      anti-drift** (decision 6a payoff). Add negative tests pinning the
      per-module invariants of the EC-builder area (`cycle_group` ⇄
      ultra_circuit_builder); the same protocol invariants bb enforces
      transfer directly. Soundness lens (guides where to spend review effort):
      the prover carries completeness and privacy, while soundness lives in
      the verifier and the circuit builder — so negative tests belong there.

### Phase 6 — performance (opened 2026-07-24 on Mike's asks; nothing here
### relaxes the invariants: non-ZK proof bytes stay identical to bb, secret
### sharing stays sound — NO shortcuts on MPC properties)
- [x] 6.1 **Plaindriver/single-prover optimisation** — DONE to the point
      of diminishing returns (2026-07-24, committed 2026-07-25): ~6.5×
      on recursion_zk 2^20 (~52 s → ~8 s), gap to bb now ~1.8× (was
      ~11×), proofs byte-identical throughout. Landed: JSON-parse fix
      (~80×), C1 sumcheck rayon (~8.2× phase), C2 oink batch-inversion
      + rayon (4.9× phase), C1b+C3 decider residuals, phase timers
      (CO_NOIR_PHASE_TIMINGS=1). B1/B2/B3 refuted by measurement
      (features were already on; LTO within noise). Full ledger ch. 23
      §C. Phase D = optional polish, reopen only on profile evidence.
- [~] 6.2 **MPC-path (co-snarkification) optimisation** — ch. 24 written
      + first lever LANDED: L1 grand-product round batching 16 → 8 comms
      rounds (committed 2026-07-25). First measured R (poseidon 2^11):
      prove 319 nonzk / 393 zk.
      **[UPDATE 2026-07-25 session 16: the sha-overhead question is
      RESOLVED — it's pk-gen, specifically ~369 small per-call-overhead
      Yao sub-protocols in the builder's sha gadget (~1,240× vs plain;
      ch. 24 §3a, lever L0). The v2 "lookup gates drive cost" finding is
      RETRACTED as a confound; REP3 prove-proper is size-driven and
      content-independent (retro phase-split, phase-split.csv). Full
      REP3 batching/serial-op audit DONE → levers L2b (post-open serial
      inversions), L2c (mul_many→local_mul_vec), L1-followup (−1 round),
      L0 (sha gadget), L2 (demoted), L4 residue — sequencing + evidence
      in ch. 24 §4. Optimisation research (TACEO/upstream/academic) +
      seedable-ZK-blinding fence in flight. UNCOMMITTED work pending
      Mike's word.]**
- [~] 6.3 **Property-preservation tests** — T3 share re-randomization
      DONE; T2-lite comms-message fence DONE 2026-07-25 (exact per-party
      msg counts pinned for rep3 poseidon, fast tier); thread-invariance
      + batched-inversion reference tests landed alongside.
      **[UPDATE 2026-07-25 session 16: T2-PROPER LANDED (uncommitted) —
      exact-pin fences for blackbox_and + add3u64 + poseidon-ZK (ZK
      counts proved deterministic), #[ignore] band test on
      bb_sha256_compression, floor table from v2 netstats, fast-check
      wired (+0.12 s), red-validated. In-process-vs-TCP frame-count
      anomaly (~100× on big circuits) documented in the floor table.
      Seedable ZK blinding byte-fence (plaindriver ≡ REP3, Mike's ask)
      in flight. Remaining: T4 view scan, slow-tier thread-invariance
      on recursion. Specs in ch. 24 §5.]**
      **[UPDATE 2026-07-26 session 17: seedable-ZK-blinding fence landed
      (session-16 late, verified); T4 VIEW SCAN + BYTE-LEVEL FENCE PINS
      DONE (uncommitted) — all-parties/both-nets frame recording across
      witext+pk-gen+prove, scanned for every high-entropy private
      witness value in canonical AND Montgomery encodings, CLEAN;
      byte pins added beside all msg-count pins (exact, except GC-
      bearing pk-gen phases: ±8-byte band — Yao GC serialization
      drifts ±1 byte run-to-run, measured). Details ch. 24 §5.
      Remaining: slow-tier thread-invariance on recursion.]**
- [x] 6.4 Bench v2 run: LAUNCHED 2026-07-25 after 6.1+L1 landed — the
      run measures the post-optimisation baseline. Rerun-per-lever
      (formerly the rest of 6.4) continues as levers land.
      **[v2.1 rerun LAUNCHED 2026-07-26 01:12 on the optimised tree
      (L2b/L2c/L1f/L0c/L0d/perm-lagrange; L0a+L0b refuted+reverted,
      ch. 24 §4), with the v2.1 measurement fixes: native
      phase-split.csv + per-phase netstats (pkgen snapshot env).
      High-load window (45.8) — noise caveat in PROGRESS s17.]**

### Phase 5 — Aztec integration (successor project; scope after Phase 2)
- [ ] 5.0 **PXE secret sharer** (key output per decision 6): choose the
      extraction path from ch. 09's ranked options (external API /
      utility-function oracle export / in-process PXE-as-library / direct DB
      read / upstream API), design the consent flow, and build the module
      that turns PXE notes/keys into co-noir REP3 input shares (encrypted
      per MPC node). Design doc + recommendation: project-docs ch. 09.
      **Scope (Mike, 2026-07-08): ALL secret types must be shareable** —
      privacy keys, signing/spending keys, authwits, note preimages, nonces,
      tagging secrets — in a tidy unified way. Note some (signing keys,
      authwits) live OUTSIDE the PXE in the wallet/account layer; the client
      architecture mental-model + secret→location map is project-docs ch. 10.
- [ ] 5.1 Modernize the monty-hall-aztec pattern to current aztec-nr/bb
      (constants: proof size 410/458, VK 115, vk-hash; capsule flow;
      HONK_ZK=6 — see ch. 04 §5). Let's start with updating it in its current rust language, but then after that's all working, let's make a typescript implementation of all the orchestration logic, because that'll be preferred by people.
      **[STARTED 2026-07-13 — Phase 5 begins here (Mike). Rust
      modernization first; TS orchestration after it works. Workplan:
      project-docs ch. 16.]**
      **[STATUS 2026-07-13 late (session 9): Rust phase COMPLETE — all
      four game rounds: circuits (Aztec-native notes, note_nonce
      convention), contract (raw kernel primitives, ChoiceNote, TXE
      10/10 incl. full game), MPC node/orchestrator (A5c: share
      persistence, per-round proofs; 3-party full-game cargo test ~8 s;
      e2e.sh all rounds bb-verified + tamper negative). First TS
      artifact exists: e2e/ local-network driver (aztec.js, pinned) —
      full game on `aztec start --local-network` with real MPC proofs
      as capsules; real-proving mode + tamper negative still pending
      (verify_proof_with_type is a no-op under simulated proving).
      Upstream aztec-nr defect found + written up (third-party note
      delivery; monty-hall repo upstream-issues/). Record: PROGRESS
      session 9, ch. 14 §26, ch. 16 banner, ch. 17 §6.7–6.9.]**
      **[STATUS 2026-07-17 (session 10): the real-proving blocker is a REAL
      bb bug, NOT our work — confirmed session 9 with Aztec's own tutorial
      example failing identically at the v5.0.0-nightly.20260708 pin. Built the
      in-process C++ reproduction (`ChonkHonkRecursionTests` in bb, branch
      `mc/fix-clientivc-recursive-verify`, commit 91e7212adb): a UH recursive
      verifier in a Mega app, accumulated+proven+verified via Chonk, + a
      corrupt-proof negative control. Both PASS on `next` → the bug is fixed
      upstream. Leading (unconfirmed-by-bisect) fix: `a69ffdf8a1` (#500) — the
      SAME v6-line commit Phase 3 already flags (full-width FS + translator op=0
      + shift-size + VK regen); it is the only PIN..next commit touching the
      failing translator subsystem. Resolution for real-proving: bump the AZTEC
      toolchain pin to a v6/next release, or cherry-pick #500 into bb. This is
      an aztec-client/bb pin concern, SEPARATE from co-noir's v5-next sync
      target. Record: PROGRESS session 10.]**
      **[RETRACTION 2026-07-17 (session 11): the bisect overturned the above.
      #500 is NOT the fix (its parent a1f07c9fda passes), and — more importantly
      — the C++ test does NOT reproduce the bug: it PASSES at the v5 pin
      v5.0.0-nightly.20260708 where the bug is validated via e2e. So "fixed on
      next" is UNPROVEN and the #500/full-width-FS attribution is withdrawn. The
      ONLY hard fact remains the e2e validation at the v5 pin (session 9). Need a
      faithful reproduction first (DSL create_honk_recursion_constraints path, or
      real e2e on a next client) before any fix/branch claim. Record: PROGRESS
      session 11.]**
      **[RESOLUTION 2026-07-20/23 — the real-proving blocker is GONE and moving
      off v5 is NOT needed. Final sequence: (i) session 11 cont2/3 re-confirmed
      the frozen captured stack fails on v5 and a real-kernel run passes on
      v6/next, with a real-stack bisect pinning that fix to #500 full-width FS —
      that remains true as an upstream fact about the FROZEN FIXTURE. (ii) But
      2026-07-20's corrected-methodology rerun could not reproduce the bug via
      FRESH real proving at ANY v5 version — 34/34 GOOD at the previously
      "confirmed-bad" pin — and traced monty-hall's own 3/3 e2e failures to a
      contract/toolchain vintage mismatch: the contract had been silently
      compiled against the drifting ~/ap-next mirror and run against an older
      network. (iii) At a consistently-pinned v5.0.1 toolchain, the FULL real
      game passes 3/3 incl. the tamper-reject negative → the ch.04 §5
      soundness gate is PASSED and 5.1's Rust phase is genuinely COMPLETE.
      (iv) 2026-07-23: all Noir deps re-pinned to immutable public release-tag
      git deps (kills the drift-hazard class for good); artifacts proven
      byte-equivalent; gates re-run green. Whether the source-level bb defect
      (127-bit-truncated batch-merge hash binding, unchanged in v5.0.1) is
      reachable by any fresh real app remains an open UPSTREAM question
      documented in monty-hall upstream-issues/ — it does not block us.
      Remaining for 5.1: one real-proving e2e re-run post-re-pin (in flight,
      session 13), then 5.1d = the TS orchestration port (workplan: ch. 20).]**
- [ ] 5.2 Design+build the user→MPC share submission channel (envelope
      encryption per node; TypeScript tooling; TACEO:Proof is the
      commercial reference shape, ch. 02 §5.4), but if that's not open source, we should look at the ~/monty-hall-aztec repo for inspiration.
- [ ] 5.3 (If needed per 1.1) blackbox build-out: ECDSA k1/r1, keccak —
      each in co-builder AND co-acvm.

## Session conventions (for future Claude sessions)

1. Read PLAN.md, `project-docs/README.md`, `project-docs/PROGRESS.md` first.
2. Verify pins before relying on them — both repos move daily.
3. Never modify Mike's text above the `---`; update checkboxes/statuses here;
   append session entries to PROGRESS.md; keep chapters current when facts change.
4. Definition of done for any sync work = byte-equality KATs + two-way
   cross-verification with bb + negative tests. Negatives must cover the
   **soundness surface** (verifiers + co-builder — ch. 13 §9), including the
   mandatory security regressions (ch. 13 §3a: SSIPA A(1)=0 boundary claim,
   ROM/RAM index-chain pinning, trailing-data/off-curve handling).

## Reference resources (read-only; verify before relying)

- `~/aztec-packages-private` — bb + Noir reference (target `origin/v5-next`).
- `~/ap-next` — public aztec-packages v5-next (PXE dev; tag/release mirror).
- `~/monty-hall-aztec` — stale in-contract UH demo (ch. 04).

