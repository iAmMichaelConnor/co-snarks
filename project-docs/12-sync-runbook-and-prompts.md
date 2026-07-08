# Chapter 12 — Reusable sync runbook + agent prompts

*A repeatable procedure — and copy-paste agent prompts — for keeping co-noir
byte-compatible with a chosen Barretenberg/Noir target, safely and
comprehensively, every time (not just the phase-2 catch-up). Designed so a
future agent (or human) can run a sync end-to-end without re-deriving the
context in ch. 02/03/07/11. Scope here is **version synchronization**; it
deliberately does not cover anything else.*

## 0. When to run this
- A new target bb/Noir version is chosen (scheduled, or because Aztec bumped).
- The drift-detector (ch. 11 phase 4 / §5 below) reports a proof-format change.
- Before relying on co-noir for a new deployment (re-confirm parity).

## 1. Invariants the sync must never violate (the safety rules)
1. **co-noir must remain byte-identical to the target bb** for non-ZK proofs
   and VKs, and verifier-compatible for ZK. This is THE definition of done —
   not "tests pass", but "bytes match a real `bb` at the target version".
2. **Never invent a fix or improvement.** Match the target exactly, even if a
   line looks wrong. Divergence = broken compatibility. (Anything that looks
   like a genuine defect is out of scope for a *sync* — record it separately,
   don't "fix" it mid-sync.)
3. **Plain `ultrahonk` first, then mirror into `co-ultrahonk`.** The plain
   KAT byte-equality test is the tightest oracle; get it green before MPC.
4. **The reference `bb` binary is the source of truth**, not memory or docs —
   and it must be **provenance-verified** (§3 first gotcha): prefer a bb
   **built from source at the exact target tag**; if using a prebuilt
   (`bbup -v <target>` or a release tarball), first byte-compare its
   `write_vk` output against a source build. A prebuilt rc binary burned us
   once (ch. 14 §17.1).
5. **No pushing anywhere** (project confidentiality rule, PLAN.md).
6. **Nothing is done until the full test matrix (ch. 13) is green**, including
   negative tests and 4-way cross-verification against real `bb`.

## 2. The procedure (checklist)

**A. Scope the diff.**
1. Identify current pin (co-noir `co-noir/co-noir/Readme.md`) and target tag.
2. In the aztec-packages checkout, diff the UH-relevant dirs between the two:
   `git diff <pin>..<target> -- barretenberg/cpp/src/barretenberg/{ultra_honk,honk,flavor,relations,sumcheck,commitment_schemes,transcript,constants.hpp,plonk_honk_shared,dsl}`.
3. Classify each change as PROOF/VK/CHALLENGE-format-breaking vs internal-only
   (perf/refactor/Chonk-Mega-AVM). Only the former need porting. Use ch. 03's
   method and taxonomy; produce a change list like ch. 03 §2.

**B. Pin bump.** Bump Noir tooling tags in root `Cargo.toml` to the target's
Noir version; get the workspace compiling (opcode-struct changes surface here
— see ch. 11 §1/§4).

**C. Port, in mirror-chain order** (ch. 11 §0): `ultrahonk` → `co-ultrahonk`
→ `co-builder` (+ `honk_verifier`) → `co-noir-common` (constants/transcript/
keys) → `co-acvm`/`co-brillig` (only if witext/opcode semantics changed).
For each breaking change, apply ch. 11-style edits.

**D. Update the derived constants** (`co-noir-common/src/constants.rs`) and add
compile-time assertions on proof/VK lengths & entity counts.

**E. Regenerate KATs & vectors** (ch. 11 §5): `compile.sh` for circuits/
witnesses; real `bb` for the committed proof/VK KATs; bump the 5 version-pin
locations.

**F. Green-up in order** (ch. 11 §6) and run the full matrix (ch. 13).

**G. Record**: append a PROGRESS.md entry (what changed, new pin, any
gotchas); update ch. 03 to the new baseline; update `co-noir/co-noir/Readme.md`.

## 3. Gotchas checklist (the "often forgotten" list)
Tick every one on every sync:
- [ ] **Oracle provenance** (bit us 2026-07-08, ch. 14 §17.1): before trusting
      ANY prebuilt bb binary as the parity oracle, byte-compare its
      `write_vk` output for one circuit against a bb **built from source at
      the exact target tag** (`git archive <tag> barretenberg/cpp`; cmake
      preset default, `-DAVM=OFF`, target `bb`, ~90 s). rc/nightly release
      binaries can predate proof-breaking commits that are already in the tag.
- [ ] **Alpha count**: any subrelation add/remove changes the alpha vector
      length and sumcheck batching — grep all `NUM_SUBRELATIONS`/alpha sites.
- [ ] **Relation order**: reordering relations silently changes alpha→
      subrelation assignment (no compile error).
- [ ] **Shamir randomness accounting** (`co_ultra_prover.rs` ~159–201): update
      whenever subrelation counts, rounds, or the ZK path change — it fails at
      *runtime*, not compile time.
- [ ] **Both transcript hashers**: poseidon2 AND keccak paths
      (`transcript.rs`, `keccak_hash.rs`) — `split_challenge`, point
      encoding, label strings, padding (`USE_PADDING` differs per hasher).
- [ ] **ZK and non-ZK** variants of every change (masking, SSIPA, proof
      lengths); ZK is byte-nondeterministic so it needs the `bb verify`
      cross-check, not KAT equality.
- [ ] **VK bytes**: trace-layout changes regenerate *every* VK — regenerate
      VK KATs, not just proof KATs.
- [ ] **`padding_indicator_array`** and similar helpers added/removed in bb.
- [ ] **ACIR opcode struct shapes** (e.g. EC `is_infinite`) when the Noir pin
      moves — the builder + acvm read against these.
- [ ] **The co- mirror**: every `ultrahonk` edit has a `co-ultrahonk` twin;
      the plain and MPC provers must produce identical bytes for one witness.
- [ ] **Recursion path** (`co-builder/src/honk_verifier/`): in-circuit
      verifier + any hard-coded expected proof size.
- [ ] **Recursion TEST VECTORS go stale on a proof-format change** (bit us
      2026-07-08, ch. 14 §20 — cost hours). The `recursion`/`recursion_zk`
      examples embed a bb-generated INNER proof/VK in their `Prover.toml`; a
      format change makes that inner proof no longer verify in-circuit, which
      surfaces as a builder `assert_equal` **panic at circuit-build time**
      (`ultra_builder.rs:223`), NOT a clean diff — easy to misread as a
      verifier-code bug. It is almost always a stale vector. Regen procedure =
      §7 below. Also re-check `recursion*/src/main.nr`'s
      `public_inputs: pub [Field; K]`: K must equal the INNER circuit's real
      public-input count — the pairing-point object (`PUBLIC_INPUTS_SIZE`)
      lives inside the `proof` array, NOT in `public_inputs`, so K must not
      include it (a wrong K silently shifts the transcript read cursor). K can
      change across a sync if the pairing-point accounting changes (it went
      16→8 in the v5-next sync).
- [ ] **Gitignored compiled artifacts don't travel with git.** After editing
      any `*/src/main.nr` or `Prover.toml` (or merging/checkout that changes
      them), the derived `target/<name>.json` (compiled circuit) and
      `target/<name>.gz` (executed witness) are **gitignored** and go stale —
      rerun `nargo compile && nargo execute` in that circuit dir (≈0.6 s).
      A merge that brings a `main.nr`/`Prover.toml` change but leaves an old
      `target/` build produces the same misleading build-time panic.
- [ ] **The 5 version-pin locations** (ch. 02 §6): Readme, compare.sh,
      compare_mpc.sh, two compile.sh.

## 4. Unsupported-feature guardrails (don't get surprised)
co-noir does **not** implement (ch. 06): ECDSA (k1/r1), keccak/keccakf1600,
BigInt, Schnorr blackboxes; Brillig blackboxes beyond ToRadix; Shamir has no
binary layer (bit-ops REP3-only); no ClientIVC/Mega/Chonk/ECCVM/Translator/AVM
flavors. During a sync:
- A bb change to any of those is **out of scope** — note it, don't port it,
  don't let it block the sync.
- If a *newly added test-vector circuit* uses an unsupported blackbox, it will
  hit a `todo!`/panic — that's expected; keep such circuits out of the KAT set
  until the feature is implemented (a separate workstream), and `log` the
  exclusion so coverage isn't silently overstated.

## 4a. Updating the recursion test vectors (ONLY when needed — keep it off the inner loop)

**When to do this (not more often):**
- After a **proof-format-affecting sync** (the inner proof in `Prover.toml`
  becomes stale — it's a real bb proof of the inner circuit, and its bytes
  must round-trip through the *current* relation/transcript logic).
- When the **inner circuit** (`inner_for_recursion/src/main.nr`) changes.
- When `PUBLIC_INPUTS_SIZE` / pairing-point accounting changes (re-check the
  `public_inputs: pub [Field; K]` count in `recursion*/src/main.nr`).
- **NOT per iteration.** Recursion is deliberately OUT of the fast inner loop
  (`fast-check.sh` never touches it; the recursion cargo tests are
  `#[ignore]`d; recursion only runs in `compare.sh`'s `TEST_SLOWER_CIRCUITS`
  set / the `--full` gate). Regenerating on every edit would wreck iteration
  speed for no benefit — the non-recursion `plain::poseidon` KAT already
  guards the shared proof format.

**How to regenerate (verified 2026-07-08, ch. 14 §20)** — from the
`inner_for_recursion` dir, with the TARGET bb (`~/.bb-target-src/bb`):
```
# non-ZK inner proof (for `recursion`); ZK: swap -t noir-recursive-no-zk -> noir-recursive
bb write_vk -b target/inner_for_recursion.json -o OUT -t noir-recursive-no-zk
bb prove    -b target/inner_for_recursion.json -w target/inner_for_recursion.gz \
            -k OUT/vk -t noir-recursive-no-zk --output_format json -o OUT
bb write_vk -b target/inner_for_recursion.json -o OUT_JSON -t noir-recursive-no-zk --output_format json
# OUT/proof.json = 410 (non-ZK) / 458 (ZK) hex fields; OUT_JSON/vk.json = 115 hex fields + "hash"
```
Then convert hex→decimal and write into `recursion*/Prover.toml` as `proof`,
`verification_key`, `vk_hash` (all decimal strings, matching the file's
existing convention) and `public_inputs = ["<inner pub input>"]` (K = the
inner circuit's real public-input count, e.g. `["3"]` for `x*2+y==9`, y=3 —
K=1, NOT including pairing points). Finally recompile+execute the OUTER
circuits (`nargo compile && nargo execute` in each `recursion*` dir) and
confirm with `plaindriver … --circuit target/recursion.json …` (self-verify)
+ a `~/.bb-target-src/bb` cross-verify. Diagnostic tip: if it panics at
`ultra_builder.rs:223` (`assert_equal`), suspect stale vector / wrong K
FIRST — not the `.rs` verifier port.

## 5. Drift detection (so a sync is never a surprise)
Stand up a local job (phase 4) that, on a schedule or on bb-nightly, runs the
existing co-noir KATs and the `compare.sh` cross-check against a freshly
`bbup`-installed nightly `bb`. A red result = the proof format moved; open a
sync. Maintain a short watchlist of the ~6 proof-format-defining bb dirs
(ultra_honk, honk/relations, sumcheck, commitment_schemes, transcript,
constants.hpp, dsl gate constants) so a human reviewer of a bb bump can eyeball
whether co-noir is affected.

## 6. Reusable agent prompts

Paste these to a coding agent. They encode the file scope, safety rules, and
gotchas so the agent can't wander. `<PIN>`/`<TARGET>` are version tags.

### Prompt A — scope the diff (read-only)
> You are working in the aztec-packages checkout. Diff the UltraHonk proving
> system between `<PIN>` and `<TARGET>` and produce a change list classified
> as PROOF/VK/CHALLENGE-format-breaking vs internal-only. Dirs:
> `barretenberg/cpp/src/barretenberg/{ultra_honk,honk,flavor,relations,
> sumcheck,commitment_schemes,transcript,constants.hpp,plonk_honk_shared,
> dsl}`. For each breaking change give: commit hash, one-para description,
> which of {proof length, VK bytes, challenge derivation, relation set/order,
> gate layout} it affects, and the affected files. EXCLUDE Chonk/ClientIVC/
> Mega/ECCVM/Translator/AVM — those are not in co-noir's scope. Do NOT edit
> anything. Output a table like project-docs/03-bb-diff-analysis.md §2.

### Prompt B — port one breaking change (write)
> Context: co-noir (Rust) must stay BYTE-IDENTICAL to bb `<TARGET>` for
> non-ZK proofs/VKs and verifier-compatible for ZK. Read project-docs
> ch. 02, 07, 11 first. Port EXACTLY this bb change into co-noir: <paste one
> change from Prompt A>. Rules: (1) match bb exactly — invent nothing, "fix"
> nothing; (2) apply it in `ultrahonk/` first, then mirror into the twin
> files under `co-ultrahonk/`, then `co-builder`/`co-noir-common` as needed;
> (3) update alpha counts, the Shamir randomness accounting in
> `co_ultra_prover.rs`, and both poseidon2+keccac transcript paths if the
> change touches subrelations/challenges; (4) update derived constants in
> `co-noir-common/src/constants.rs`. List every file you changed and why.
> Do not regenerate KATs yet. Do not push.

### Prompt C — regenerate KATs & vectors (write, needs `bb`/`nargo`)
> Reference binaries are installed (`bb` at `<TARGET>` — provenance-verified
> per §3's first gotcha, source-built if in any doubt; matching nargo via
> noirup). Regenerate co-noir's test vectors and KATs for the new
> pin: run `test_vectors/noir/compile.sh` and the examples `compile.sh`;
> regenerate the committed bb proof KATs (`add3u64`, `poseidon`, both
> `--oracle_hash poseidon2` and `keccak`, `--disable_zk`) and all committed
> VK KATs using the reference `bb`; bump the 5 version-pin locations (Readme,
> compare.sh, compare_mpc.sh, two compile.sh). Report exactly which files
> changed. Do not push.

### Prompt D — verify parity (the gate; read + run)
> Run the full parity matrix (project-docs ch. 13) and report pass/fail per
> cell, honestly (no silent skips): plain non-ZK poseidon2 & keccac KAT
> byte-equality; REP3 & Shamir MPC KAT byte-equality vs the plain proof;
> ZK verifier round-trip; 4-way cross-verification (our/their proof ×
> our/their VK) via `compare.sh`/`compare_mpc.sh` against real `bb`
> `<TARGET>`; and the negative tests (tampered share/witness/proof/public
> input must be REJECTED). If any cell is red, stop and report the exact
> byte/field divergence — do not paper over it. Do not push.

### Prompt E — completeness critic (read)
> Audit the sync just performed against project-docs ch. 12 §3 (gotchas) and
> §4 (unsupported-feature guardrails). For each gotcha, state whether it was
> handled and cite the file/line. Flag anything in the Prompt-A change list
> that was not ported and confirm it is genuinely out of scope (internal-only
> or an excluded flavor), not forgotten. List any test-vector circuit that
> uses an unsupported blackbox and was (correctly) excluded from KATs.

## 7. Why this is a runbook, not automation
The diff-scoping (Prompt A) and the port (Prompt B) are the parts that need
judgment — deciding format-breaking vs internal, and translating C++ template
machinery into the Rust structure. Everything downstream (pin bump, KAT
regen, the parity matrix, the gotcha audit) is mechanical and scriptable, and
the parity matrix is a hard, byte-level gate that makes a wrong port
impossible to miss. Run the judgment steps with a capable agent + human
review; let the mechanical steps run to completion and trust the gate.
