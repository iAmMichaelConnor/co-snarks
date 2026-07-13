# Chapter 17 — monty-hall-aztec quality backlog (reviews of 2026-07-13)

*Sources: two exhaustive read-only reviews (Rust workspace; Noir code vs
current aztec-nr idioms in `~/ap-next` v5-next) + Mike's design write-up
(hackmd.io/@mike-connor/ByZ6tymhyl). Statuses maintained in place.
Tags: effort S/M/L × impact H/M/L. The hackathon origin showed: the worst
finds were in the *original* code, not the modernization.*

## 0. Design context from the HackMD write-up (feeds A5/5.1b/5.0)

- The pattern's core trick: a co-Noir program that adheres to Aztec's
  `PrivateCircuitPublicInputs` layout (read requests / nullifiers / note
  hashes) "is effectively an Aztec smart contract function". The OS
  (orchestrator) executes the contract side and must NEVER see preimages —
  only commitments/nullifiers (this is why PrivateShared* exist).
- MPC-held nullifier secret key = the network's identity; could extend to
  a full MPC-held Aztec address (not implemented).
- Wish-list overlapping our plan: PXE `add_note_hash()` endpoint (→ add to
  ch. 09 scope); PXE secret-sharing (= PLAN 5.0); ZK recursive verifier
  (SOLVED on v5-next: HONK_ZK=6); UH kernel circuits (long-term);
  `SharedMutable` rename (upstream naming note only).
- Known-acknowledged hacks: secure data sharing hand-waved; MPC identity
  is a bare keypair.

## 1. Confirmed bugs — FIXED 2026-07-13 (commit pending on mc/modernize)

1. ✅ **F0 `GameState::choose_door` broken for winning==chosen ∈ {1,2}**
   [S×H — live soundness/liveness bug in the original code]. Noir
   evaluates both branch blocks eagerly: (a) winning==chosen==1 → the
   "equal" branch opened the WINNING (= chosen) door ~half the time;
   (b) winning==chosen==2 → the discarded `3-w-d` underflowed u8 →
   circuit PANICS (game unprovable). All 6 original tests used seed 123
   (winning door 0) and could not see it. FIXED: branch restructured
   (both blocks total + panic-free for all inputs; comment explains the
   eager-evaluation rule); tests: exhaustive (winning,chosen) sweep +
   coin-flip coverage + 3 state-machine negatives (11 tests green).
2. ✅ **Orchestrator returned HTTP 200 on proof-verification failure**
   [S×H]. Now: `ApiErrors::VerificationFailed` → 502; error taxonomy
   rewritten (NodesDiverged names the diverging field — also fixes the
   copy-pasted "seed_commitment differ!" message); all handler
   unwrap/expect removed; VK parsed once at startup; e2e.sh now asserts
   the real signal.
3. ✅ **Side-effecting GETs** [S×H] → POST (+ TraceLayer request logging).
4. ✅ **No session guard on nodes** [M×H]: fixed mesh port meant a second
   concurrent MPC session → EADDRINUSE via an accidental client-side
   queue. Now an explicit per-node `session_lock` (Mutex) + a
   `run_mpc_session` helper (dedupes both handlers, maps failures to
   distinct gRPC statuses; `init_game` without prior randomness →
   FAILED_PRECONDITION; `reveal_door` → UNIMPLEMENTED not `todo!()`).
5. ✅ **Non-transactional TRUNCATE+INSERT** [S×M] → singleton-row atomic
   upserts (migration `20260713140000`); DB deserialization now fallible
   (TryFrom) instead of `.expect` panics.
6. ✅ **Dead `CryptoDevice`** [S×M]: deleted (with the `--key-phrase`
   config + crypto deps); its hidden side effect is now an explicit
   `install_rustls_provider()` (needed by sqlx). NOTE: 5.2's envelope
   encryption will be designed fresh; the crypto_box sketch lives in git
   history (`main`).
7. ✅ Cleanups: orchestrator startup validates `mpc_nodes.len()==3` +
   loads VK/CRS with context errors; node validates circuit ABI param
   names at startup (fail-fast, replaces silent convention); network
   config parsed once (was per-RPC + unwrap); phase-timing log bug fixed
   (delta-vs-cumulative) + `{:.3}`s format; orphaned
   `monty-hall-orchestration/data/` (stale VK/keys, unreferenced)
   deleted; compose postgres image pinned 16-alpine; start_nodes.sh
   header + `set -euo pipefail`; clippy 0 warnings; both gates re-run
   PASS (check.sh + e2e.sh).

## 2. Open — Rust workspace (priority order)

1. **In-process 3-party integration test** [M×H — the big lever]:
   genericize `sample_root_rand`/`init_game`/`commit` over `N: Network`,
   dev-dep `mpc_net` with feature `local`, then a `LocalNetwork`-based
   3-thread test asserting byte-identical proofs + `UltraHonk::verify`
   true + flipped-byte false — the co-snarks `rep3.rs` tests are the
   model. Gives sub-second `cargo test` coverage of what e2e.sh needs
   docker+bb for. (Blocker: `local` feature not in the dep graph yet.)
2. **Unit tests** [S×H]: `extract_public_returns` (happy/shared/out-of-
   range, driving witness index from a real artifact's `return_values`);
   `data_store` serialization round-trips + corrupted-buffer → Err;
   orchestrator handler negatives (mocked divergent responses → 502).
3. **Transport security — DECIDED (Mike 2026-07-13): wire it properly (TLS mesh + gRPC security)** [M×H]: party TOMLs carry key/cert paths that
   mpc-net's `NetworkConfigFile` silently IGNORES (wrong TOML shape → 
   `tls: None`) and the code hardcodes `TcpNetwork` anyway; gRPC plane
   has no TLS/auth either. Decide: wire `TlsNetwork` + tonic mTLS, or
   delete the pretense (certs/keys) and document "plaintext, localhost
   demo only". Upstream note: mpc-net could `deny_unknown_fields`.
4. **CI** [M×H]: nothing runs cargo check/clippy/tests/gates on commit
   (local-only repo → a git hook or a local script convention).
5. Smaller: node-connect retry/backoff at orchestrator startup [S×M];
   committed dev TLS keys under `noir_logic/network/data` — regenerate
   or README-mark as loopback-only [S×L]; MSRV claim vs 1.90 toolchain
   [S×L]; `mpc/README.md` (architecture, port table 8000-2/10000-2/
   8080-2/3000, run paths) [S×H for onboarding].

## 3. Open — Noir (priority order)

1. **pss_utils test coverage** [S/M×H]: `private_state.nr` has ZERO
   tests (verify/verify_and_nullify/compute_nullifier — the soundness
   core): happy paths + tampered commitment/meta + wrong sk/pk
   negatives + KATs pinning commit/nullifier outputs (they're
   chain-visible values; a silent hash change must turn a test red).
   `prng.nr` zero tests (determinism, wrap at position 3, KAT).
   `ae.nr`: add wrong-key, direct tag-tamper, single-slot tamper
   negatives + KATs. `dh.nr`: KAT + non-square-address negative.
2. **F1 `to_address_point` panics for ~half of addresses** [M×H]:
   `sqrt().unwrap()` (upstream TODO aztec-packages #8970). Affects
   `verify_and_nullify`'s pk-binding path. Options: negate-y retry
   (address points are constructed to have square y², so real inputs
   may be fine — VERIFY the caller contract's guarantee) or propagate
   Option.
3. **F2 — DECIDED (Mike 2026-07-13): option (b), full DOM_SEP rework** [M×H]:
   GENERATOR_INDEX__{NOTE_HASH=1,NOTE_NULLIFIER=53} no longer exist on
   v5-next — replaced by `DOM_SEP__NOTE_HASH=116501019` /
   `DOM_SEP__NOTE_NULLIFIER=50789342` + `poseidon2_hash_with_separator`
   with a different preimage shape. Decide: true bit-compat (redo the
   scheme, feeds 5.1b's TACEONote whose hash is the raw commitment) or
   fix the comment to "structurally inspired". KATs first either way.
4. **F3 player-input commitments not tied to on-chain notes** [L×H —
   the known TODO from the demo's last commit]: nothing constrains the
   MPC circuits' `door`/`switch` inputs to equal the user's on-chain
   `UintNote` commitment (whose real hash is a 2-stage domain-separated
   construction now). This is exactly the A5/5.1b integration seam —
   fold into ch. 16 A5 design.
5. Style batch [S×M]: copy `noirfmt.toml` from ap-next + `nargo fmt`;
   `///` docs on all pub items (aztec-nr AGENTS.md structure);
   normalize `// Safety:` and replace the contract's 12
   "This is normal Aztec practice?" placeholders with real
   justifications; `compiler_version` pin in taceo_commit;
   `commit_field_array`+`absorb` are DEAD CODE (delete or test+use);
   fold `monty_hall_test`/`dh_test` bins into lib `#[test]`s (keep
   `taceo_commit` — operational circuit); F4: document (+negative-test)
   the `from_field_unsafe` repurposing in verify_and_nullify; F6 PRNG
   always advances comment (DONE in the F0 fix comment).

## 4. Open — contract (fold into ch. 16 5.1b when it starts)

- **F7 `TACEONote::unpack` second bug** [S×H]: beyond the known
  pack-duplicate-`.x`, unpack reads `packed[1]` (y) as the commitment —
  never `packed[3]`. Round-trip through PXE storage silently corrupts
  the note. Port fix: `#[derive(Packable)]` makes the class impossible.
- **F8 `game_phase` is write-only** [M×H]: no function ever reads or
  asserts it — the phase machine enforces nothing; call order is
  unconstrained (beyond per-note single-init). Port: assert phase (or
  drive the machine from the private state note).
- **F9 no access control** [L×H]: anyone can init (first-caller claims
  the game), choose/switch (first-caller claims the slot), open/finish
  (maybe intentional — proof is the gate — but must become an explicit
  design decision). Port: Map-per-player storage + stored operator
  address where identity matters.
- **F10** (= ch. 16 §5.0 delta table; the review independently
  confirmed it, adding: `compute_nullifier_unconstrained -> Option<Field>`
  is the DESIGNED way to express TACEONote's "no individual party can
  nullify" — replaces the `assert(false)` hack; and
  `SinglePrivateMutable` now has an upstream non-leaky initialization
  nullifier scheme our fork should inherit).
- **F11** [M×M]: consider `PartialUintNote` (partial notes) for
  `opened_door`/`win` delivery — first-class primitive for "value not
  known until later" — instead of the claim-function pattern.

## 5. Suggested execution order

1. §2.1+§2.2 (Rust tests incl. LocalNetwork harness) — locks in 5.1a.
2. §3.1 (pss_utils tests+KATs) + §3.2/§3.3 decisions — locks the crypto
   primitives before A5 builds on them.
3. ch. 16 A5 (open_door round) with §3.4/F3 as part of its design.
4. 5.1b contract port with §4 folded in.
5. §2.3 transport security + §2.5/§3.5 hygiene batches — before anything
   leaves localhost.
