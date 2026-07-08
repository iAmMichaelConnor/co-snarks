# Chapter 10 — The Aztec client architecture, from scratch (PXE, wallet, account, node)

*Audience: you know cryptography and Aztec's proving side, but the client
stack (wallet/PXE/account/node) is unfamiliar — to the point that "what even
is a wallet?" is unclear. This chapter builds the mental model from zero.
Verified 2026-07-08 against `~/ap-next` = public aztec-packages `v5-next`
@ `a455b9a943e`; paths are under `yarn-project/`. This is the foundation for
the secret-sharer design (ch. 09), which needs to know where every secret
lives.*

## 0. The one-sentence model

> A **wallet** is a plain in-process TypeScript object that bundles together
> **(a)** an embedded **PXE** (a private-execution engine with its own
> database of your notes and *privacy* keys), **(b)** a *second, separate*
> **wallet database** holding your accounts list and *signing* keys, and
> **(c)** per-account **AccountContract** objects that hold the signing key
> and actually produce signatures. The wallet talks to a **remote Aztec
> node** over JSON-RPC.

The single most important correction to the intuition most people start
with: **there is no "PXE server" anymore, and the PXE is not where your
signing key lives.** Both were true in older Aztec; neither is true on
v5-next. Let's unpack why, piece by piece.

## 1. The pieces, and which is what kind of thing

"Wallet" feels fuzzy because it isn't one thing — it's a *composition* of
several things, some libraries, one a remote process, one an on-chain
contract. Here they are, sorted by "what kind of thing is this":

**Libraries running on the user's device (all in one process):**

- **aztec.js** — the SDK a dApp imports. Gives you `Contract`,
  `ContractFunctionInteraction`, `AccountManager`, the `Wallet` type, authwit
  helpers. (`aztec.js/src/**`)
- **Wallet** — an *interface* (`type Wallet`, `aztec.js/src/wallet/wallet.ts`)
  the dApp programs against: `sendTx`, `simulateTx`, `createAuthWit`,
  `getAccounts`, etc. Concrete implementations are `EmbeddedWallet` and
  `CLIWallet`, both extending `BaseWallet`
  (`wallet-sdk/src/base-wallet/base_wallet.ts`).
- **PXE** ("Private eXecution Environment") — the engine that simulates your
  private function calls, runs the client-side proving, and owns a database
  of your private state + privacy keys. Created by `createPXE(node, config)`
  (`pxe/src/entrypoints/server/utils.ts`). **It is a library object the
  wallet holds as a field**, not a server.
- **AccountContract object** — the *client-side* object that knows an account
  contract's artifact and **holds its signing key**; it produces the
  `AuthWitnessProvider` that signs. (`accounts/src/schnorr/…`, `…/ecdsa/…`)
- **Entrypoint** — encodes your app calls into the account contract's
  `entrypoint(...)` ABI and inserts the signature.
  (`entrypoints/src/account_entrypoint.ts`)

**A remote process, reached over JSON-RPC:**

- **Aztec node** — the shared network component. Syncs L2 state, serves
  membership witnesses and fee estimates, and accepts your finished
  transaction (`sendTx`). It never sees your secrets — only the proof + public
  data. Your wallet holds a client stub via `createAztecNodeClient(url)`.

**An on-chain contract:**

- **Account contract (deployed)** — a Noir contract on L2 whose `entrypoint`
  and `verify_private_authwit` run *in-circuit* to check your signature. This
  is the on-chain counterpart of the client-side "AccountContract object";
  don't conflate the two.

### Why "no PXE server" matters
On older Aztec, the PXE was often a separate daemon your wallet reached over
JSON-RPC (`createPXEClient`, a `PXESchema`). On v5-next **those symbols no
longer exist** (verified: `grep` finds zero matches). The PXE is always
embedded in the wallet's process. The *only* RPC-shaped boundary left inside
the client is **dApp ↔ wallet** for browser-extension/iframe wallets (a
`postMessage` bridge validated against `WalletSchema`,
`wallet-sdk/src/{extension,iframe}/…`) — there, the real wallet (with PXE +
keys) lives in the extension background and the dApp holds only a proxy.

Consequence for us (ch. 09): a secret-sharer is naturally **code loaded into
the wallet's process**, calling PXE and wallet objects directly — not a
network client of a PXE service (there is none).

## 2. What an "account" actually is (three faces — don't conflate)

This is where most of the confusion lives. An Aztec account is *three
distinct things* that share an identity:

1. **The account's keys.** A per-account root `secretKey: Fr` deterministically
   derives, via `deriveKeys` (`stdlib/src/keys/derivation.ts:119`), a family
   of **master keys**: nullifier-hiding `nhk_m`, incoming-viewing `ivsk_m`,
   outgoing-viewing `ovsk_m`, tagging `tsk_m` (the four **privacy keys**),
   plus newer master message-signing `mssk_m` and fallback `fbsk_m`.
   **Separately** there is the account contract's **signing (spending) key**
   — a Schnorr or ECDSA key. Since a recent refactor the signing key is
   **independent** of the privacy keys (the CLI actually goes the other way:
   pick a random signing key, then derive the privacy `secretKey` from it via
   a one-way hash, so the privacy side can never recover the signing key).
2. **The account contract on-chain.** A deployed Noir contract (Schnorr,
   ECDSA, etc.) whose address commits to the master *public* keys. Its
   in-circuit `entrypoint` verifies signatures against a public key it stores.
3. **The account's representation in the PXE.** `pxe.registerAccount(keys,
   partialAddress)` stores the account's *privacy* keys in the KeyStore and
   its address in the AddressStore. The PXE can now *decrypt this account's
   notes* — but it **cannot sign for the account** (it doesn't have the
   signing key).

So "an account" = a key family + an on-chain contract + a PXE registration.
The wallet is what stitches them together for you.

### Where signing actually happens
When you send a transaction, the wallet loads the **signing key from its own
database** and constructs an `AccountContract` object (e.g.
`SchnorrBaseAccountContract`, holding `signingPrivateKey: GrumpkinScalar`,
verified at `accounts/src/schnorr/account_contract.ts:17`). That object's
`AuthWitnessProvider.createAuthWit(messageHash)` runs
`Schnorr.constructSignature(messageHash, signingPrivateKey)` — **the signature
is produced here, in the wallet layer, and the signing key is never given to
the PXE.** (The design comment at `base_wallet.ts:366` is explicit: "PXE never
receives the account seed… only the four privacy secret keys and the
message-signing/fallback *public* keys.")

An **authwitness (authwit)** is that signature (plus its message hash),
authorizing either the whole transaction (per-tx) or a specific action
(app-level approval). It is created at signing time and attached to the
transaction request; it is **transient by default** (not persisted), though
the CLI wallet optionally saves app-level authwits under an `authwits:` alias.

The **SSH-ECDSA account variant** is the proof that this seam is clean: there
the signing key is *not in the process at all* — it lives in the OS `ssh-agent`
and `createAuthWit` delegates to the agent over a socket. That is exactly the
shape an MPC threshold-signer would take (ch. 09 §6).

## 3. The two databases (this is the part that was invisible)

There are **two physically separate key-value databases** on a user's device.
Each is one backing store with many named sub-stores inside it.

### DB #1 — `pxe_data` (owned by the PXE)
Opened by `createPXE`. Backend: **LMDB** on node/CLI (unencrypted on disk),
**SQLite-OPFS** in the browser (optional ChaCha20 encryption, *off by
default*). Schema version 12 (`pxe/src/storage/metadata.ts`), bound to the
rollup address. Its 12 sub-stores (`pxe/src/storage/open_pxe_stores.ts`):

- **KeyStore** (`key-store/src/key_store.ts`) — the four **privacy master
  secret keys** (`nhk_m`, `ivsk_m`, `ovsk_m`, `tsk_m`) per account, stored
  *plaintext and independently* (there's no persisted root secret and no
  derivation tree in here — the wallet derives them and hands them in).
  Master message-signing/fallback **secrets are deliberately withheld** (only
  their public keys are kept).
- **NoteStore** — note **preimages, randomness, and nonces** (the `NoteDao`).
- **AddressStore** — complete addresses + master *public* keys.
- **TaggingSecretSourcesStore / Sender- / RecipientTaggingStore** — tagging
  secrets (some derived from `tsk_m`, some independently registered
  handshake points).
- **CapsuleStore, FactStore** — contract-local opaque scratch data.
- **ContractStore, PrivateEventStore, AnchorBlockStore, L2TipsKVStore** —
  artifacts, decrypted events, chain sync.

### DB #2 — WalletDB (owned by the wallet, *not* the PXE)
A **separate** store the wallet opens itself (CLI: `~/.aztec/wallet`;
embedded: `wallet_data_<rollup>`). Backend LMDB/OPFS, plaintext. Holds:

- **accounts** map: per account the root `secretKey` (`…:sk`), the
  **signing/spending key** (`…:signing`), salt, type, public signing key.
  ← *This is where the signing key lives — a different database from the PXE.*
- **aliases**: human names for accounts/contracts/artifacts, and (CLI)
  `secrets:` and `authwits:` namespaces.
- **bridgedFeeJuice**: fee-juice claim secrets (CLI).

**The key realization:** your secrets are split across two custodians. Notes
and privacy keys are in the PXE's DB; the signing key, root secret, and
persisted authwits/secrets are in the wallet's *own* DB. A secret-sharer that
only hooked the PXE (the assumption in an earlier draft of ch. 09) would miss
signing keys and authwits entirely.

## 4. How a transaction flows (and where each secret is touched)

```
dApp: wallet.sendTx(payload, { from })
  │
  ├─ fee/gas prep ...................... asks NODE for min fees, gas limits
  │
  ├─ load account for `from`
  │     └─ read {secretKey, signingKey} from  WalletDB (DB#2)   ◀── SIGNING KEY touched
  │        build SchnorrAccountContract(signingKey)
  │
  ├─ entrypoint builds the call, computes messageHash
  │     └─ AuthWitnessProvider.createAuthWit(messageHash)       ◀── SIGN happens (wallet layer)
  │           = Schnorr.constructSignature(...)  [SSH: via agent socket]
  │        authwit attached to the tx request (transient)
  │
  ├─ pxe.simulateTx(request)
  │     └─ oracles read NoteStore (preimages/nonces), KeyStore  ◀── PRIVACY KEYS, NOTES,
  │        (app-siloed skApp), tagging stores, capsules, facts      TAGGING touched (DB#1)
  │
  ├─ pxe.proveTx(...)  → client-side kernel proof
  │
  └─ node.sendTx(tx) ──── JSON-RPC ───▶ NODE (verifies proof, mempool)
```

Secret-touch summary: **signing key → the signing step (wallet)**; **privacy
keys + note preimages/nonces + tagging secrets → simulation (PXE)**; **authwit
→ transient in the tx request**. Three different homes.

## 5. The layer-cake diagram

```
                   USER DEVICE (one process)                        NETWORK
┌──────────────────────────────────────────────────────────┐   ┌────────────┐
│ dApp + aztec.js   (Contract, interactions, authwit utils)  │   │            │
│      │  wallet.sendTx / simulateTx / createAuthWit         │   │            │
│      ▼                                                      │   │            │
│  Wallet  =  BaseWallet ⇒ EmbeddedWallet / CLIWallet         │   │  AZTEC     │
│      owns three things:                                     │   │  NODE      │
│      ├── PXE (embedded)  ───────────────────────────────────┼──▶│  (remote,  │
│      │     simulate + prove;  DB#1 pxe_data:                │   │  JSON-RPC) │
│      │       KeyStore=PRIVACY keys, NoteStore, tagging,     │   │  sendTx,   │
│      │       capsules, facts, addresses …                   │   │  fees,     │
│      ├── WalletDB (DB#2, SEPARATE):                          │   │  witnesses │
│      │       accounts, root secretKey, SIGNING KEY, authwits│   │            │
│      └── AccountContract objects:                           │   └─────┬──────┘
│            hold signingPrivateKey; createAuthWit = SIGN      │         │ tx+proof
│            (SSH variant: key stays in ssh-agent)            │         ▼
└──────────────────────────────────────────────────────────┘   ┌────────────┐
   [browser-extension wallets only: dApp↔wallet postMessage     │ Account    │
    bridge (WalletSchema) — the one RPC-shaped seam left]        │ contract   │
                                                                 │ ON-CHAIN   │
                                                                 │ (verifies  │
                                                                 │  signature)│
                                                                 └────────────┘
```

## 6. Every secret → where it lives (the table the sharer needs)

| Secret | Custodian | Store (DB) | Note |
|---|---|---|---|
| Account root `secretKey` | Wallet | WalletDB `accounts:…:sk` (DB#2) | the privacy-side root |
| `nhk_m`, `ivsk_m`, `ovsk_m`, `tsk_m` (privacy masters) | PXE | KeyStore (DB#1), plaintext, independent entries | derived by wallet, handed to PXE |
| App-siloed keys (`skApp`) | PXE (computed) | not stored — derived on demand | from master + contract addr |
| **Signing / spending key** | Wallet / AccountContract | **WalletDB `accounts:…:signing` (DB#2)** | ★ NOT in PXE; SSH variant keeps it in ssh-agent |
| Master message-signing `mssk_m` / fallback `fbsk_m` (secrets) | nowhere persisted | — | derivable by wallet from root; only public parts stored; mid-refactor |
| **Authwitnesses** | Wallet (transient) | tx request; optional CLI `authwits:` alias (DB#2) | produced from signing key |
| Note preimages, randomness, **nonces** | PXE | NoteStore (DB#1) | private data |
| Directional tagging secrets | PXE | Sender/RecipientTaggingStore (DB#1) | derived from `tsk_m` |
| Handshake shared-secret points | PXE | TaggingSecretSourcesStore (DB#1) | independently registered |
| Capsules / facts | PXE | Capsule/FactStore (DB#1) | opaque contract blobs |
| Fee-juice claim secrets | Wallet (CLI) | WalletDB `bridgedFeeJuice` (DB#2) | user-supplied |

## 7. What this means for the secret-sharer (updates ch. 09)

To share **all** secret types (your instruction), the sharer must touch
**three seams, in two databases and one in-memory layer**:

1. **PXE KeyStore** (DB#1) — privacy master secrets. Either read them out
   (`getMasterSecretKey` / the account-migration `getAccountSecretKeys`) or,
   for a full solution, replace the KeyStore's key map with *shares* and turn
   its derivations into MPC evaluations.
2. **PXE tagging/note/capsule stores** (DB#1) — note preimages/nonces,
   tagging secrets, handshake points: read via the store classes (Path B of
   ch. 09).
3. **Wallet layer** (DB#2 + AccountContract) — the signing key and authwits.
   The clean interception point is `getAuthWitnessProvider(address)` on the
   `AccountContract` (`aztec.js/src/account/account_contract.ts:53`): swap the
   local signer for an **MPC threshold signer**, exactly as the SSH-agent
   variant swaps it for a remote agent. The raw signing key then need never
   sit in WalletDB in the clear.

So the sharer is a **layered extractor/replacer**, not a PXE add-on. Two
sub-designs fall out:
- **"Export then share"** (simpler, v1): read every secret from both DBs +
  in-memory account objects, with consent, and REP3-split them as circuit
  inputs. Good for delegated proving where the MPC network is trusted to
  hold shares transiently.
- **"Never-in-clear"** (harder, later): the KeyStore holds only key-shares and
  the AuthWitnessProvider is an MPC signer, so no single machine ever has a
  whole key. This is the real end-state for signing keys (you don't want a
  spending key sitting in one process), and it mirrors how the SSH variant
  already externalizes signing.

## 8. Stability (what's safe to build on)

Commit counts since 2026-04-01 on v5-next: **pxe 189** (epicenter — three
concurrent refactors: "keys out of PXE", FactStore/notes, tagging/handshake),
key-store 9 (low volume but nearly every commit is breaking), wallets 30,
wallet-sdk 25, cli-wallet 25, aztec.js/wallet 21, **accounts 6**,
aztec.js/account 3, **entrypoints 2**.

Guidance: the **accounts / entrypoints / aztec.js-account** layers (where
signing lives, and where an MPC signer would interpose) are **stable** — safe
to build against `getAuthWitnessProvider`. The **PXE KeyStore and
tagging/note stores** are **actively churning** — pin to a commit and expect
the `key_store.ts` layout and tagging shapes to shift; re-verify on every
Aztec bump (fold into the phase-4 drift checks). The "keys out of PXE"
refactor (commits `#23510 → #24348 → #24416 → #24439 → #24451`) is the reason
signing keys are now cleanly separated — good for us, but it means anything
you read about PXE holding signing keys pre-July-2026 is stale.

### Flags / to re-confirm at build time
- Browser OPFS encryption-at-rest is **off by default** — a deployment must
  opt in (`openEncryptedEmbeddedStores`).
- `mssk_m`/`fbsk_m` are defined and derivable but **not yet wired as active
  signing keys** in the default account contracts (mid-refactor) — treat as
  in-flight; today's signer is the independent Schnorr/ECDSA `signing` key.
- LMDB (node/CLI) is plaintext at rest — the sharer doesn't worsen this, but
  note it for whoever reviews the design.
