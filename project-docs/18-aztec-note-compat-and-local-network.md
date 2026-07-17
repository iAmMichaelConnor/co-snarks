# Chapter 18 — Aztec-native note compatibility (DOM_SEP formulas) + local-network/TXE runbook

*Created 2026-07-13 from two deep-dives into `~/ap-next` v5-next @
`a455b9a943e` (≡ our tag for these surfaces). This is the implementation
spec for ch. 16 A5a (bit-identical notes/nullifiers, Mike's option (b))
and the runbook for the full-game local-network e2e. All file:line cites
are into `~/ap-next` unless noted.*

## 1. The one primitive

Everything is `poseidon2_hash_with_separator(inputs, sep)` =
`Poseidon2::hash([sep as Field, ...inputs])` (variable-length std
poseidon2; separator PREPENDED as a decimal Field) —
`noir-protocol-circuits/crates/types/src/hash.nr:216-222`.
**Decision: pss_utils depends on the real `types` crate**
(`protocol_types = { git = aztec-packages, tag = v5.0.0-nightly.20260708,
directory = "noir-projects/noir-protocol-circuits/crates/types" }`,
package name `types`) and uses its constants + hash functions verbatim —
no reimplementation, no drift.

## 2. Formula reference (copy-paste; DOM_SEP values verified)

```
# Canonical #[note] note hash (macros/notes.nr:75-94 → note/utils.nr:16-20).
# App-level ("inner") hash — THE value an external circuit must reproduce:
note_hash = P2( 116501019  /*DOM_SEP__NOTE_HASH*/,
                storage_slot, pack(note)..., owner.to_field(), randomness )

# UintNote (uint-note/src/uint_note.nr:40-56,145-150,246-249) — for
# binding player inputs (F3):
commitment = P2( 568912195 /*DOM_SEP__PARTIAL_NOTE_COMMITMENT*/, owner, randomness )
note_hash  = P2( 116501019, storage_slot, commitment, value.to_field() )

# Kernel does siloing/uniquification AUTOMATICALLY for every pushed hash
# (reset_output_composer.nr:34-59; hash.nr:54-119) — external circuits
# reproduce it only when nullifying a SETTLED note:
siloed        = P2( 3361878420 /*SILOED_NOTE_HASH*/, contract_address, note_hash )
note_nonce    = P2( 1721808740 /*NOTE_HASH_NONCE*/, first_nullifier_in_tx, note_index_in_tx )
unique_siloed = P2( 226850429  /*UNIQUE_NOTE_HASH*/, note_nonce, siloed )

# Canonical nullifier (note/utils.nr:30-37); nhfn depends on note state:
#   settled → unique_siloed; pending-same-phase → raw note_hash;
#   pending-prev-phase → compute in-circuit (utils.nr:84-103)
nullifier = P2( 50789342 /*NOTE_NULLIFIER*/, note_hash_for_nullification, nhk_app )
siloed_nullifier = P2( 57496191 /*SILOED_NULLIFIER*/, contract_address, nullifier )  # kernel-applied

# Key derivation (hash.nr:160-169) — PLAIN PUBLIC FORMULA, no oracle/kernel
# needed if you hold sk_m (the MPC network does):
nhk_app    = P2( 242137788  /*NHK_M*/, sk_m.hi, sk_m.lo, contract_address )
npk_m_hash = P2( 3452068255 /*SINGLE_PUBLIC_KEY_HASH*/, pk_m.x, pk_m.y ), pk_m = sk_m·G (Grumpkin)

# Single* state-var initialization nullifier (single_private_mutable.nr:104-126):
init_nullifier = P2( 1653084894 /*INITIALIZATION_NULLIFIER*/, storage_slot, nhk_app(contract) )
```

## 3. Facts that shape the design

1. **Only the inner note hash matters** — kernels silo+uniquify every
   pushed hash unconditionally; a TACEONote returning the same inner
   value as a canonical note is indistinguishable downstream.
2. **"Nobody-knows-the-preimage" notes are legal**: `create_note` pushes
   the note hash BEFORE returning the `NoteMessage` (lifecycle.nr:40-75);
   `#[must_use]` is a warning, not an error — sink the message, deliver
   nothing, and the note exists on-chain but is undiscoverable. No
   `MessageDelivery` variant is needed (the 3 variants all deliver
   something). Nullifiers never have delivery obligations at all.
3. **`randomness` is an unconstrained oracle witness** in native notes
   (oracle/random.nr) — the MPC supplying its own shared randomness is
   exactly equivalent.
4. **The MPC can compute `nhk_app` directly** (plain formula) from its
   collectively-held master nullifier secret key `sk_m` (Grumpkin scalar,
   hi/lo limbs). The kernel's key-validation machinery only runs if a
   contract calls `request_nhk_app` — ours won't; the co-Noir circuit
   computes the final nullifier and the contract pushes it via
   `push_nullifier_for_note_hash`. `npk_m_hash` is the MPC network's
   public identity the contract stores/asserts.
5. **A custom note's `compute_nullifier` is free-form** — the designed
   escape hatch for our pattern; `compute_nullifier_unconstrained`
   returning `Option::none()` is the intended way to say "no local keys".
6. Note discovery: a note message plaintext = `[owner, storage_slot,
   randomness, ...pack(note)]`, AES to recipient. PSS notes forgo it by
   design; player-owned notes (doors) use normal delivery.

## 4. A5a design (pss_utils rework)

- `pss_utils::aztec_note` module: thin wrappers over `types::hash` +
  `types::constants` for every §2 formula (each a 1-liner + doc comment
  citing the aztec-nr source it mirrors); KAT tests pin outputs; TXE
  differential test later (contract-side native note hash == MPC-side).
- `PrivateState` reworked: meta = `{contract_address, storage_slot,
  owner, randomness}`; `commit` = canonical note_hash; `verify_and_
  nullify(sk_m, note_status_inputs)` = canonical nullifier over the
  correct `note_hash_for_nullification` (settled notes: needs
  `note_nonce` + `contract_address` as circuit inputs); pk binding via
  `npk_m_hash` (public input) instead of the old ad-hoc `pk == sk·G`.
- Game circuits: metas/keys become explicit inputs (public where the
  contract checks them); node gRPC requests carry the deployment context
  (contract address, slots, owner) — protos gain these fields.

## 5. Local-network / TXE runbook (from the 2026-07-13 deep-dive)

- **No sandbox at this pin.** Install: `VERSION=5.0.0-nightly.20260708
  bash -i <(curl -sL https://install.aztec.network)` → `aztec start
  --local-network` (installed wrapper auto-starts anvil; the raw
  `node dest/bin/index.js` entrypoint does NOT — set `ETHEREUM_HOSTS`).
  Node RPC :8080; NO standalone PXE service (PXE is in-process in
  aztec.js `EmbeddedWallet`). Docker alternative: `aztecprotocol/aztec:
  5.0.0-nightly.20260708` (no v prefix; verify published before relying).
- **TS driving** (the only full-featured path): `createAztecNodeClient` →
  `EmbeddedWallet.create(node)`; ONE wallet holds many accounts, actor
  chosen per-call via `{from}`. Template: `yarn-project/end-to-end/src/
  composed/e2e_local_network_example.test.ts`. All `@aztec/*` npm deps
  pinned to the exact string `5.0.0-nightly.20260708`.
- **Capsules are aztec.js-only**: `new Capsule(contractAddress, slot,
  Fr[])` attached via `.send({ capsules: [...] })` / `.with({capsules})`.
  `aztec-wallet` CLI CANNOT set capsules → the game driver must be TS.
- **TXE**: run via `aztec test` (starts `aztec start --txe` on :8081 and
  runs `nargo test --oracle-resolver http://127.0.0.1:8081`); the `aztec`
  CLI version must exactly match the `aztec` Nargo dep tag (runtime
  version check). Capsules set inside tests via `aztec::oracle::capsules::
  store` directly. Test API: `TestEnvironment::new()`, `create_light_
  account`/`create_contract_account` (latter for authwits), `deploy`,
  `call_private`/`call_public`/`execute_utility` with `from` = actor.
- **⚠ THE BIG CAVEAT: `verify_proof_with_type` is a NO-OP during
  execution/witness-gen** (`acvm/src/pwg/blackbox/mod.rs:152-153` —
  RecursiveAggregation is backend-only). TXE tests therefore CANNOT
  reject a forged proof — they test flow, state, access control only.
  Worse, the local network defaults to `realProofs: false` (automine
  sequencer, local-network.ts:126-136) and PXE proving may be simulated.
  **The full-game e2e MUST run with real client-side proving enabled**
  (investigate the realProofs/proving toggle at e2e build time — the
  recursive_verification tutorial is the reference) or the in-circuit
  verification of MPC proofs is never actually exercised. Negative e2e
  test (tampered proof → tx rejected) is the definitive check.

## 6. TXE + local-network: validated 2026-07-13 (toolchain proven)

**Toolchain**: `@aztec/aztec@5.0.0-nightly.20260708` installed via npm
(no docker needed for CLI); `aztec --version` prints the pin. `nargo`
beta.22, `nc`, `anvil` (Foundry) all present. `aztec compile` builds the
contract (MegaHonk VKs for all functions); `aztec test` runs TXE.

**TXE (`aztec test`) — DONE, 6/6 green** (`contract/montyhall_test`).
Contract restructured into a workspace (`montyhall` + `montyhall_test`) —
`aztec test` requires it. Tests validate everything that runs BEFORE a
note read: deploy, round-1 capsule proof verification, VK-hash-pin
rejection, operator/player access control on every round. Hard limits
of TXE, both confirmed empirically:
1. `verify_proof_with_type` is a NO-OP in the TXE ACVM → proof validity
   is NOT testable here (a forged proof passes). Only the local network
   with real proving tests it.
2. **PSS note discovery doesn't work in TXE (or plainly anywhere via the
   normal path)** — this is the crux finding. A `TACEONote` carries only
   a public commitment; it has no preimage the recipient can use to
   recompute/discover it through ordinary PXE message delivery. Every
   attempt to `deliver()`/`deliver_to()` it and then `get_note()` in a
   later tx fails "Failed to get a note". **This is exactly the gap
   Taceo's HackMD flagged as requiring an `add_note_hash()` PXE
   endpoint** (ch. 17 §0 / the write-up): the operator KNOWS the note
   hash (it's a public input) but the PXE has no way to be told "a note
   with this hash exists at this slot" through delivery. The operator's
   PXE note store must be populated out-of-band.

   Gotchas discovered getting TXE green: `contract` is a reserved Noir
   keyword (can't be a variable name); capsule oracles must run inside
   `env.private_context(_at)`; capsule store/load want a nominal type
   (`ProofData` struct), not bare `[Field; N]` (array-`Serialize` T
   inference is flaky in-file); `init_game` can't be `#[initializer]`
   because it consumes a capsule staged at the deployed address.

**Local network — VALIDATED (starts; e2e driver is the remaining build).**
`aztec start --local-network` (wrapper auto-starts anvil on :8545) brings
up the node on :8080 + admin :8880, deploys protocol contracts, funds
test accounts, deploys BananaCoin/FPC/SponsoredFPC. Confirmed running at
the pin. No sandbox flag (`--local-network`, not `--sandbox`).

### The e2e build (concrete plan, now de-risked)
A TypeScript driver (aztec.js, pinned `@aztec/*@5.0.0-nightly.20260708`;
aztec-kit's `setupLocalNetwork` fixture + `Capsule` usage in
`embedded-wallet.ts` are the reference patterns) that:
1. `createAztecNodeClient(:8080)` → `EmbeddedWallet.create`; create
   operator + player accounts.
2. `aztec codegen` the contract → TS class; deploy it.
3. For each round: generate the REAL co-SNARK proof via the `mpc/`
   pipeline (3-node run, or plaindriver for a single-prover proof at
   first), get its bb VK, build a `ProofData` and attach it as a
   `Capsule` (`.send({ capsules: [...] })`) to the round's call.
4. **Solve PSS note discovery**: the operator's PXE must learn the
   game_state note hash. Options: (a) the `add_note_hash`-style manual
   injection Taceo wanted — investigate if aztec.js exposes a way to add
   a note to the PXE store directly; (b) store the (hash-only) note as a
   capsule the contract reads instead of via note discovery — i.e.
   redesign PrivateSharedMutable to keep its current note in a capsule
   the operator restages each round, sidestepping discovery entirely.
   (b) is likely the cleaner answer and worth prototyping first.

**UPDATE (2026-07-13):** the discovery question is resolved differently —
see ch. 17 §6. PSS notes are NOT delivered/discovered at all; inclusion is
proved by a hash-only kernel read request (`assert_note_exists`, option c),
not by note discovery. The §6 primitives replace the deliver/get_note path.

**UPDATE 2 (2026-07-13, session 9 — this section's plan is largely
DONE-in-TXE):** the primitives landed and hash-only settled reads were
verified to work in TXE (resolved via `node.findLeavesIndexes` on the
note-hash tree, no note store involved — code path:
`contract_function_simulator.ts::verifyReadRequests`). The FULL game now
runs in TXE (10/10 tests, incl. tamper-adjacent negatives; ch. 17 §6.7).
Step 4 below is therefore VOID — no discovery workaround is needed. The
remaining e2e (real proving) simplifies to: TS driver fetches each
round's tx effects from the node (first nullifier + note-hash leaves,
the same data the TXE tests read via `get_last_tx_effects`) and passes
leaves/tx-positions as function args. The definitive tamper-reject gate
(step 5) still requires the local network with real proofs.
5. Assertions: the honest-proof rounds succeed; a TAMPERED proof round
   is REJECTED by the contract (the definitive in-circuit-verification
   soundness gate TXE cannot provide).

This is a multi-step build in its own right; the toolchain, contract,
circuits, and MPC prover are all proven, so it is now purely
integration work. The note-discovery decision (step 4) is the one real
design fork and should be settled with Mike (it also feeds PLAN 5.0's
PXE-secret-sharer, which faces the mirror-image problem).

**BUILT + PASS (2026-07-13 night, session 9): `e2e/run.sh` +
`e2e/driver.mjs`** (repo monty-hall-aztec). The ENTIRE game ran on
`aztec start --local-network` with REAL MPC co-SNARK proofs staged as
operator-scoped Capsules: initializerless deploy; per-round orchestrator
fetch (JSON HTTP); nonces/leaves mined from `node.getTxEffect` +
`computeNoteHashNonce`; MPC-derived unique note hashes cross-checked
against the chain's tx effects every round; real ChoiceNote delivery +
tagged-log discovery for the player notes; final phase/opened_door/win
asserted on-chain. Simulated-proving mode only — the tamper
negative is coded but gated on `EXPECT_REAL_PROOFS=1`
(PROVER_REAL_PROOFS on the network + `proverEnabled` in the wallet's
PXE).

**⚠ REAL-PROVING MODE FAILS AT THIS TAG — and NOT because of co-noir
(probed 2026-07-13 night).** With `EXPECT_REAL_PROOFS=1`: the plain
deploy tx PROVES AND MINES fine (ClientIVC pipeline works), but the
first tx containing `verify_proof_with_type(..., HONK_ZK)` — init_game —
dies in the PXE prover with bb.js `BBApiException: Failed to verify the
generated proof!` (the prover's own self-check after Chonk proof
generation). Discriminating probe: substituting a **bb-generated** ZK
proof of the same circuit (driver env `ROUND1_DIR` + `STOP_AFTER_ROUND1`,
probe artifacts preserved in the session scratchpad `bbround1/`) fails
IDENTICALLY → our MPC proofs are exonerated; the in-circuit
UH-verification path itself breaks under real client proving. Checked:
vk_hash convention is NOT the issue (bb's vk.json `hash` ==
TS `poseidon2Hash(vk_fields)` == the contract's pin, verified equal).
Notable: NO app contract in the whole ap-next tree calls
`verify_proof_with_type` (only protocol/mock kernels use verify_proof,
in UH→UH recursion) — "verify a UH proof inside a Chonk-proven app
function" appears UNTESTED upstream at this tag; we are probably the
first to run it for real. DIAGNOSED (2026-07-13 night, session 9 cont.) — it is a
barretenberg-side defect in an untested path, NOT ours; full
maintainer-ready report + deterministic repro in the monty-hall repo
`upstream-issues/clientivc-recursive-verify-fails-in-app.md`
(+ `clientivc-recursive-verify-repro/`). Findings:
- The failing check is `ChonkVerifier: verification failed at batched
  translator+joint reduction` (chonk_verifier.cpp:89, Step 5 Translator
  Oink + Joint sumcheck + Joint PCS; `reduction_succeeded==false`, not
  the pairing). Same binary proves and self-verifies, so the PROVER
  emits a Goblin translator/joint sub-proof that fails its own verifier.
- Discriminated with a minimal 2-function probe contract
  (`contract/verify_probe`): deploy (no verify) PROVES; an app calling
  `verify_proof_with_type` FAILS for BOTH HONK=0/410 and HONK_ZK=6/458,
  and FAILS with bb-generated inner proofs too. So not the ZK flavor,
  not co-noir, not vk_hash (bb vk.json hash == poseidon2(vk) == the
  pin, verified equal). Sole common factor: a Mega app circuit
  containing the UH recursive verifier (~700 Goblin ECC ops → ECCVM +
  Translator).
- Recursive UH verification IS exercised upstream, but never in the
  failing configuration. In BOTH trees every verify_proof caller is
  either standalone Ultra→Ultra recursion proven directly with bb
  (barretenberg/noir/bb_proof_verification + docs/examples/.../recursive),
  a protocol/rollup/mock kernel (Ultra builder), or on-chain L1 Solidity
  (integration_proof_verification.test.ts). ZERO `#[aztec]` contract
  functions call verify_proof in either tree. So "UH verifier in a Mega
  app accumulated by ClientIVC" is the unexercised path.
- POSITIVE CONTROL: the repro circuit (only gate = verify_proof_with_type)
  proves + self-verifies fine as a standalone ULTRA proof
  (`bb prove --scheme ultra_honk`); the identical constraint fails ONLY
  under Mega/ClientIVC. Localizes the defect to the Goblin/ECCVM/
  Translator path, not the recursion verifier. (Corrects an earlier
  overstatement that there were no verify_proof callers at all — there
  are, just no #[aztec] contract ones.)
- Repro is file-based: the real 6-circuit folding stack captured from
  the failing PXE run (dumped via serializePrivateExecutionSteps) +
  `bb prove --scheme chonk --ivc_inputs_path …` on the matching 0703
  bb.js binary. Capture technique (bb-prover dump hook, bb.js native
  logger) documented in the report.
CONSEQUENCE: the definitive tamper-reject soundness gate stays blocked
until the bb team fixes this; everything up to real client proving is
green (TXE 10/10, MPC full game, local-network e2e in simulated mode).
Also: ch. 04 §5's in-contract recipe was verified at the
artifact/constant level and in TXE, but never end-to-end under real
ClientIVC proving — that gap is what this surfaced. Driver gotchas recorded in ch. 14
§26 (foundation subpath exports; @aztec/accounts lazy JSON import needs
a load-hook shim; send() waits by default — no `.wait()`).
