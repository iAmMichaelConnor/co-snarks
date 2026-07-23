# Chapter 20 — Phase 5.1d: TypeScript orchestration port (workplan)

*Created 2026-07-23 (session 13), grounded in a direct read of the as-built
Rust orchestrator (`monty-hall-aztec/mpc/monty-hall-orchestration/`, 371
lines across 6 files) and the existing TS driver (`e2e/driver.mjs`). Status
markers here are updated as work lands; per-session detail goes in
PROGRESS.md as usual.*

## 0. What 5.1d is (and is not)

PLAN 5.1 (Mike): after the Rust modernization works — it now does, real
proving included — *"make a typescript implementation of all the
orchestration logic, because that'll be preferred by people."*

The monty-hall MPC stack has three layers, and only the middle one ports:

| Layer | Language today | 5.1d action |
|---|---|---|
| **MPC nodes** (`mpc/mpc-node`): gRPC servers that run the actual co-noir REP3 witness extension + ZK UltraHonk proving, persist share state in Postgres | Rust | **Stays Rust, untouched.** It embeds co-noir; a TS node would need co-noir compiled to WASM — that is Phase 5.0/5.2 territory (browser-side share *splitting*), not orchestration. |
| **Orchestrator** (`mpc/monty-hall-orchestration`): HTTP JSON API for the game driver; fans each round out to the 3 nodes over gRPC (mTLS), cross-checks the three responses are byte-identical, verifies the single shared proof against the round's bb-format VK, returns hex proof + publics | Rust (axum/tonic) | **Ports to TypeScript** — this is "the orchestration logic". |
| **Game driver** (`e2e/driver.mjs`): deploys the contract, calls the orchestrator per round, stages proof capsules, mines note nonces from tx effects, plays the player moves, asserts the outcome | Already TS/JS (aztec.js) | Stays; must keep working **unchanged** (the API contract is frozen, §2). |

Why people will prefer TS orchestration: the driver, wallet, PXE, and all
of aztec.js are TS; an integrator adopting the PSS pattern then needs Rust
only for the (black-box, containerized) MPC nodes.

## 1. As-is inventory (what must be reproduced exactly)

From the code, not from memory — file references are to
`mpc/monty-hall-orchestration/src/`:

1. **HTTP surface** (`routes.rs`, `routes/user.rs`): four POST endpoints
   `/api/{sample_rand,init_game,open_door,finish_game}`. JSON bodies with
   0x-prefixed big-endian hex field elements (matching aztec.js `Fr`
   printing, so the driver passes chain data through verbatim); `door` is
   a JSON number, `switch` a JSON bool. Response `{ proof: "0x…" (458×32
   bytes), public_inputs: ["0x…", …] (ACIR order) }`.
2. **Fan-out**: each round builds one protobuf request
   (`mpc/protos/monty_hall.proto`, 4 rpcs, all returning `ProofResponse`)
   and sends it to all 3 nodes concurrently (`tokio::join!`); per-node
   serialization exists client-side but correctness relies on the NODE's
   own session lock (comment in `mpc_node.rs:50` — preserve that stance).
3. **Byte-identity cross-check** (`require_all_equal`): proof bytes and
   public-input bytes must be identical across all 3 nodes; any divergence
   → error naming the diverging field. This is the semi-honest-model
   integrity tripwire — do not weaken it.
4. **Proof verification**: the agreed proof is verified in-process with
   co-noir's Rust verifier (`UltraHonk::verify`, `ZeroKnowledge::Yes`,
   poseidon2 transcript) against a per-round **bb-format VK** loaded and
   parsed at startup (fail at boot on a corrupt VK, not on first request —
   `main.rs:30`). Verification failure → error, never a 200.
5. **Error taxonomy** (`error.rs`): 400 bad request (unparseable hex /
   >32-byte field), **502** nodes-diverged (naming the field), **502**
   verification-failed, 500 internal. The 502-on-verify-failure semantics
   were a deliberate session-6 fix (the original demo logged and returned
   200) — a parity test must pin them.
6. **Config** (`config.rs`): env/flag pairs `SMPC_BIND_ADDR`,
   `SMPC_MPC_NODES` (comma list, exactly 3), `SMPC_{COMMIT,INIT,OPEN_DOOR,
   FINISH}_CIRCUIT_VK`, `SMPC_VERIFIER_CRS`, and all-or-nothing
   `SMPC_GRPC_TLS_{CA,CERT,KEY}` for mutual TLS towards the nodes
   (plaintext + warning if unset — dev only). Keep the same env names so
   `e2e.sh`/`run.sh` drive either implementation.
7. **Ops niceties**: request tracing (axum `TraceLayer`), permissive CORS,
   per-round info logs. Mirror with standard Node middleware.

## 2. Frozen contract

The **HTTP JSON API (§1.1) and error taxonomy (§1.5) are the compatibility
contract**: `e2e/driver.mjs` and `mpc/e2e.sh`'s assertions must pass
against the TS orchestrator with zero driver changes. That makes the
existing e2e suites the acceptance gate for free (§5).

## 3. Design decisions (proposed; confirm-or-adjust with Mike where marked)

1. **Verification backend = `@aztec/bb.js` (WASM), CLI fallback.** The TS
   orchestrator must verify a ZK UltraHonk proof (458 fields, poseidon2
   transcript) against a bb-format VK. bb.js at 5.0.1 ships the UltraHonk
   verifier as WASM (it is what the PXE itself uses). **T1 is a spike** to
   pin the exact entry point and prove it accepts/rejects correctly (honest
   + tampered) against artifacts from the existing e2e fixtures. Known-good
   fallback if the WASM surface fights us: spawn the pinned `bb` binary
   (`bb verify --scheme ultra_honk --zk` — exactly what `check.sh`/`e2e.sh`
   already do), keeping bb.js as a follow-up. Either way the VERDICT
   semantics (§1.4/§1.5) are identical.
   - Note the third verifier lens we get for free: Rust co-noir verifier
     (old orchestrator) vs bb.js/bb (new) — the acceptance run (§5) becomes
     a small differential test of the two verifier stacks.
2. **gRPC stack = `@grpc/grpc-js` + `@grpc/proto-loader`**, loading
   `mpc/protos/monty_hall.proto` at runtime (no codegen step to drift).
   mTLS via `credentials.createSsl(ca, key, cert)` with the same PEM
   material `scripts/gen_dev_certs.sh` already produces.
3. **⚠ THE field-encoding gotcha (write the unit test first):** on the
   gRPC wire, field elements are **ark-serialize uncompressed bn254 Fr =
   32 bytes LITTLE-endian** (`field_bytes` in `user.rs` — the nodes
   `deserialize_uncompressed`). The HTTP JSON side is **big-endian** hex.
   The Rust orchestrator converts by parsing to `Fr` and re-serializing;
   the TS port must byte-reverse (and range-check < r, mirroring
   `from_be_bytes_mod_order` semantics + the >32-byte 400). Get this wrong
   and every request fails deep inside witness extension with a confusing
   error. Unit-test with vectors captured from the Rust implementation.
4. **Language/runtime**: TypeScript proper (tsc, ESM), Node ≥ 22, plain
   `node:http` or a minimal framework — recommend **no framework** (four
   POST routes do not justify one) or `express` if middleware parity
   (CORS/tracing) is annoying by hand. [Mike may have a preference.]
5. **Location**: new top-level `orchestrator-ts/` in monty-hall-aztec
   (sibling of `mpc/`, `e2e/`), its own `package.json` pinned to
   `@aztec/bb.js@5.0.1` etc. — same released-npm-pin policy as `e2e/`.
6. **What is deliberately NOT ported**: VK *writing* (stays a bb CLI step
   in the scripts), CRS handling (bb.js embeds/fetches its own; the
   `SMPC_VERIFIER_CRS` flag becomes accepted-and-ignored or optional —
   decide in T1), and the nodes' gRPC *server* side.

## 4. Work items

- [ ] **T0 — scaffold + parity fixtures.** `orchestrator-ts/` skeleton;
      capture wire fixtures from the Rust implementation (per-round JSON
      request/response pairs + the LE gRPC bytes for a few fields) into
      `orchestrator-ts/test/fixtures/`, generated by a documented one-shot
      script against the running Rust stack. Gate: fixtures committed +
      loadable.
- [ ] **T1 — bb.js verify spike.** Prove `@aztec/bb.js@5.0.1` (WASM)
      verifies the round-1 fixture proof (bb-format VK bytes, 458-field ZK
      proof, poseidon2) and REJECTS a tampered byte. Decide CRS flag
      handling. Gate: a standalone `node spike.mjs` printing
      accept/reject correctly both ways. If blocked >½ day: switch to the
      bb-CLI fallback and file bb.js findings in ch. 15.
- [ ] **T2 — gRPC client + field codec.** proto-loader client, mTLS
      wiring, BE↔LE codec with the T0 vectors. Gate: unit tests green,
      incl. >32-byte reject and non-canonical (≥ r) handling matching
      Rust's `from_be_bytes_mod_order`.
- [ ] **T3 — the four endpoints + cross-check + verify + error taxonomy.**
      Gate: unit tests with a mocked node trio — identical responses →
      200 + correct JSON shape; one diverging node → 502 naming the field;
      tampered proof → 502 verification-failed; bad hex → 400.
- [ ] **T4 — script integration.** `mpc/e2e.sh` (and `e2e/run.sh`) gain
      `ORCHESTRATOR_IMPL={rust|ts}` (default rust until T5 passes twice).
      Gate: `ORCHESTRATOR_IMPL=ts mpc/e2e.sh` full-game PASS (byte-identity,
      per-round bb cross-verification, tamper negative, seed chaining).
- [ ] **T5 — acceptance.** `e2e/run.sh` full on-chain game with the TS
      orchestrator, simulated AND `EXPECT_REAL_PROOFS=1`. Gate: PASS +
      the tamper negative, twice. Then flip the default to `ts`? [Mike
      decides — the Rust orchestrator stays in-tree either way as the
      reference implementation and differential-test peer.]
- [ ] **T6 — docs.** README table + ch. 16 cross-refs updated; this
      chapter's checkboxes closed; PROGRESS entry.

Estimated effort: T0–T3 ≈ 1 session; T4–T6 ≈ 1 session, dominated by e2e
wall-clock.

## 5. Acceptance criteria (definition of done for 5.1d)

1. `e2e/driver.mjs` unchanged, `mpc/e2e.sh` + `e2e/run.sh` (both proving
   modes) PASS with `ORCHESTRATOR_IMPL=ts`.
2. Tamper and divergence negatives return the SAME status codes and
   equivalent messages as the Rust implementation (parity test T3).
3. No weakening of the security posture: byte-identity check intact,
   verify-before-return intact, mTLS supported, VKs parsed at startup.
4. Everything pinned to released npm 5.0.1 packages (no path/live deps —
   the ch. 19 / pinned-recompile lesson).

## 6. Risks / open questions

- **bb.js verify surface** at 5.0.1 for *standalone* UH-ZK proofs is the
  main unknown (T1 exists to burn it down early; CLI fallback bounded).
- **Non-canonical field inputs**: Rust uses `from_be_bytes_mod_order`
  (reduces, never rejects). Mirror exactly — do not "improve" to rejection
  here; the co-noir-side canonical-encoding question is tracked separately
  (ch. 15 §1.3) and the orchestrator should not diverge from its Rust
  reference behavior.
- **Long-lived gRPC channels**: grpc-js reconnect semantics differ from
  tonic's; T4's e2e (nodes restarted between runs) will surface any
  staleness — handle with per-request deadline + transparent retry-once on
  UNAVAILABLE, nothing fancier.
