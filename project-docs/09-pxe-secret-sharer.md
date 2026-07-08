# Chapter 9 — The PXE Secret Sharer: getting user secrets out of the PXE and into REP3 shares

*Written 2026-07-08. Reference: `~/ap-next` = public aztec-packages,
branch `v5-next` @ `a455b9a943e` (where PXE development actively continues;
the private repo's v5-next mirrors it). Key claims spot-verified in code.
Goal (PLAN.md decision 6): generate a co-snark from a user's PXE secrets —
notes, secret keys, private state — with user consent, changing as little
PXE code as possible (the PXE team is not amenable to PRs/reviews).*

## 0. Two facts that reshape the problem

1. **The PXE is no longer a remote service.** On v5-next there is no
   JSON-RPC PXE, no `createPXEClient`, no schema layer. `createPXE(node,
   config)` returns a plain TS object that wallets hold as a field
   (`yarn-project/wallets/src/embedded/embedded_wallet.ts:105-112`,
   `cli-wallet/src/utils/wallet.ts:62`). Anything running in the wallet's
   process can call PXE methods directly — there is no RPC gate to strip
   "dangerous" methods. A "secret sharer module" is therefore naturally an
   **in-process TS library loaded by the wallet**, not a network peer.
2. **A sanctioned bulk key-export API already exists.**
   `pxe.getAccountSecretKeys(account)` (`pxe/src/pxe.ts:772`) returns the
   account's four master privacy secret keys — nullifier-hiding, incoming
   viewing, outgoing viewing, tagging (`AccountPrivacySecretKeys`,
   `key-store/src/account_privacy_keys.ts`). It was added deliberately
   (commit `7920a596829`) for **account migration between PXEs**, with a
   docstring warning that apps should never see them. It is *not* exposed on
   the aztec.js `Wallet` interface — only on the raw PXE object. So "export
   keys with consent" doesn't need a new API; it needs a consent flow around
   an existing one.

Also load-bearing:

- **Notes are stored as full plaintext preimages** — `NoteDao`
  (`stdlib/src/note/note_dao.ts`) holds the note fields, **randomness**,
  nonce, storage slot, contract address, owner, note hash, siloed nullifier.
  Storage backend: one `pxe_data` KV store (LMDB on servers — *unencrypted at
  rest*; IndexedDB/OPFS in browsers; an encrypted sqlite-opfs option exists).
- **There is no note-query API on the PXE object at all** (verified: zero
  `getNotes` methods in `pxe.ts`). Note access happens only inside Noir
  execution via oracles, or by reading the store directly.
- **Spending/signing keys are not in the PXE, full stop** (removed by commit
  `5cd500e043e`). If a target circuit needs signature-generation keys, they
  live at the wallet/account layer, and the sharer must source them there.
- The Noir oracle layer **app-silos everything**: a contract function (incl.
  `unconstrained`/utility ones) can read only *its own contract's* notes, and
  can obtain only *app-siloed* keys (`skApp`), never master keys
  (`utility_execution_oracle.ts:216-225,426-461`). Deliberate and good — it
  bounds what path C below can ever do.

## 1. What the sharer must produce (the co-noir side of the contract)

From ch. 02: co-noir's REP3 input sharing (`split_input_rep3`) takes the
target circuit's ABI-typed inputs (a `Prover.toml`-shaped map), splits each
private field element into a replicated 3-sharing, and emits three
`Rep3SharedInput` maps (bincode-serialized `.shared` blobs, or in-memory
structs when used as a library). Public inputs are replicated verbatim into
all three. So the sharer pipeline is:

```
PXE secrets ──(extract, §2)──▶ circuit-input map (ABI-typed Fr values)
            ──(split)────────▶ 3 × Rep3 share maps
            ──(encrypt)──────▶ 3 ciphertexts, one per MPC node pubkey
            ──(submit)───────▶ MPC network (phase 5.2 channel)
```

For the *split* step the sharer (TypeScript) has three implementation
options: (a) reimplement REP3 splitting + bincode serialization in TS —
simple math (sample two uniform field elements; shares are the pairs) but a
serialization-compatibility liability; (b) **compile the relevant co-noir
crates (`co-noir-types` / split functions) to WASM** via wasm-bindgen and
call them from TS — one source of truth for share format, works in browser
wallets too; (c) sidecar: shell out to the `co-noir split-input` binary —
fine for CLI/server wallets, dead in browsers. **Recommendation: (b)**, with
(c) as the quick interim for CLI-based phase-5 demos.

## 2. Candidate extraction paths, ranked

### Path A — in-process raw-PXE calls  ← RECOMMENDED for keys
Hold the `PXE` object (wallets store it as a field; our sharer is loaded by
the wallet) and call **`getAccountSecretKeys(account)`** for the privacy
keys, plus `executeUtility` where convenient. Zero PXE changes. Rides the
*most stable* code in the tree (`key-store`: 9 commits since April, and the
export API was *just deliberately added* — it will not quietly vanish).
Consent: the sharer itself prompts the user (this API bypasses the
scopes/capability system entirely, so consent is ours to implement — §4).

### Path B — read the `pxe_data` store directly ("stores-as-library")  ← RECOMMENDED for notes
Open the same KV store and instantiate the PXE's own store classes over it —
`new NoteStore(store)`, `new KeyStore(store)`, etc. This is **exactly what
the TXE (Aztec's testing environment) already does in-tree**
(`txe/src/txe_session.ts:318` instantiates `new KeyStore(store)` directly),
so the pattern is precedented, and using *their* store classes (rather than
raw LMDB parsing) tracks schema changes at the TS-API level. It is the
**only path that reads notes across all contracts** (the note-oracle path is
own-contract-only), returning full preimages including the randomness that
co-snark circuits will need to open commitments. Zero PXE changes. Costs:
moderate churn exposure (`pxe/src/storage`: 38 commits since April; schema
version bumps), LMDB single-writer locking (coordinate with the running PXE:
run in the same process reusing the same store handle — natural, since we're
in the wallet process anyway — or while PXE is stopped), and it wholly
bypasses the scopes system, so consent again is ours to enforce.

### Path C — pure-API "exporter utility contract" via `wallet.executeUtility`
A Noir contract the user installs whose `unconstrained` (utility) functions
read state via oracles and *return* it (`executeUtility` hands the raw
`Fr[]` return to the TS caller — verified). Best consent story: it flows
through the wallet's existing **scopes + capability-manifest** machinery,
i.e. the only path with an in-tree "user grants access" model. But it is
**structurally incomplete** — own-contract notes only, app-siloed keys only,
never master keys — and it leans on the *hottest* code in the tree (oracle
layer: 91 commits since April, with breaking oracle-signature refactors
mid-flight). Verdict: not the backbone; useful as the consent-friendly
option for app-specific flows where the co-snark circuit belongs to the same
contract as the notes (which, note, is exactly the PSS pattern's shape).

### Path D — upstream API ("if the PXE team were amenable")
The surprising finding: **half of this PR already happened** — key export
exists (`getAccountSecretKeys`). The remaining gap is small and sharply
definable: (1) a read-only **note-export/query method** on PXE (returning
`NoteDao`s for given scopes — ~30 lines wrapping `NoteStore.getNotes`
without the contract-address restriction), and (2) optionally surfacing both
on the `Wallet` interface behind a new **capability type** so third-party
wallets get a standard consent gate. That's a far lighter ask than "add a
secret-sharing subsystem" — worth keeping in the back pocket even given the
review-averse team, because it's the kind of PR that mostly deletes risk
from *their* perspective (a supported read API beats users poking LMDB).

### Path E (rejected) — parse the LMDB/IndexedDB files without PXE classes
Maximum robustness-to-nothing: raw binary parsing of an unversioned-for-us
format, breaks on every schema change, duplicated per backend. Only relevant
for forensics/recovery, not a product path.

## 3. Recommendation

**Hybrid A + B, packaged as one wallet-side TS module ("PXE Secret
Sharer"), with C as the consent-clean variant for same-contract flows:**

1. Module is instantiated *by the wallet* with the `PXE` object and (same
   process) its KV store handle.
2. On a sharing request `(account, circuit, input-descriptor)`:
   - present the **consent prompt** (§4) enumerating exactly which notes and
     which keys will be shared and to which 3 nodes;
   - keys via `pxe.getAccountSecretKeys` (Path A);
   - notes via the store classes (Path B), filtered to the requested
     contract/storage-slots;
   - assemble the ABI-typed input map → REP3-split via WASM-compiled
     co-noir-types (§1) → encrypt per node → hand to the submission channel
     (phase 5.2).
3. Secrets are held in memory only for the split; zeroized after; nothing
   written to disk unencrypted.
4. Version-pin the `@aztec/pxe`, `@aztec/key-store`, `@aztec/kv-store`
   packages and treat PXE schema-version bumps as an explicit compatibility
   gate (the store carries `PXE_DATA_SCHEMA_VERSION` — check it, refuse on
   mismatch rather than misread).

Why not C-first despite its better consent fit: it caps completeness (no
master keys, no cross-contract notes) *and* sits on the fastest-churning
internal surface. We take C's *consent model* (capability-manifest-shaped
grants) and implement it in our own module around A+B instead.

## 4. Consent model (sketch — to refine with Mike)

The scopes/capability system doesn't govern paths A/B, so the sharer imposes
its own gate, deliberately shaped like the in-tree capability manifest so a
future Path-D upstreaming is a rename, not a redesign:

- A **sharing manifest** per request: `{ account, contractAddress(es),
  storage slots / note selectors, key types requested (e.g. nhk only),
  target circuit hash, MPC node identities (pubkeys), expiry }`.
- Explicit user approval per manifest (wallet UI/CLI prompt); approvals
  logged; no blanket grants in v1.
- Principle of least secrecy: request only the note fields/keys the circuit
  ABI actually consumes (e.g. many PSS circuits need `nhk_app`-derived
  values, not the raw master key — derive app-siloed keys *in the sharer*
  where possible, mirroring `computeAppSecretKey`, and share the derived
  value instead of the master).

## 5. Risks & open questions

- **Churn**: PXE overall is hot (189 commits since April). Paths A/B pin to
  its two calmest corners, but this project must re-verify on every Aztec
  version bump (add to phase-4 drift checks).
- **The signing-key ceiling — Q1 ANSWERED (Mike, 2026-07-08): share EVERYTHING.**
  Target scope is now *all* secret types in a tidy unified way — privacy keys,
  **signing/spending keys, authwitnesses, note nonces**, note preimages,
  tagging secrets. Consequence: the sharer cannot be PXE-only, because
  signing keys and authwits live in the **wallet/account layer, not the PXE**
  (the PXE deliberately dropped signing/fallback keys, commit `5cd500e043e`).
  The full client-architecture map and the secret→location table that this
  design depends on is **ch. 10**; the sharer design in this chapter will be
  revised to a layered extractor (PXE stores for notes/privacy-keys +
  wallet/account keystore for signing keys + tx-build hooks for authwits/
  nonces) once ch. 10 lands.
- **Deployment target**: server wallet (LMDB, CLI) vs browser wallet
  (IndexedDB/OPFS, WASM-only) changes Path B's plumbing and the split-step
  implementation. **Q2: what's the v1 deployment — CLI/server-side wallet
  (easiest), or browser wallet?**
- **Whose wallet**: if we control the wallet (e.g. a dev/demo wallet or
  cli-wallet fork), loading the sharer in-process is trivial; if targeting
  third-party wallets eventually, Path D's capability-gated Wallet-interface
  surface becomes the real answer. **Q3: is a self-controlled wallet
  acceptable for v1?**
- **At-rest exposure pre-exists us**: PXE data is unencrypted on disk
  (server LMDB); the sharer doesn't worsen this but shouldn't be blamed for
  it either — worth noting for whoever reviews the design.
- **Aztec-side consent optics**: paths A/B are, bluntly, "the wallet process
  reads its own database" — legitimate (it's the user's own data, user-
  approved), but we should socialize the design so it isn't mistaken for an
  exfiltration pattern. The manifest log (§4) is the traceability answer.
