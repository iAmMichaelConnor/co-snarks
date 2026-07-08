# Chapter 2 — Map of the `co-snarks` repo (proving stack + wrapper tooling)

*Facts verified 2026-07-08 against TaceoLabs/co-snarks `main` @ `36da0ea8`
(2026-07-06). All paths repo-relative. Read chapter 01 first for concepts.*

## 0. Headline facts

- **The repo is actively maintained by Taceo.** It is NOT a year-stale snapshot.
  Sync commits with upstream land every ~1–2 months, each a breaking (`!`) change,
  e.g. `7d992613 chore!: sync with latest Noir (1.0.0-beta.20) and Barretenberg
  (5.0.0-nightly.20260324) (#543)`.
- **Current compatibility pin: bb `v5.0.0-nightly.20260324` + nargo `v1.0.0-beta.20`**
  (`co-noir/co-noir/Readme.md:3,30`; Noir crates pinned to that tag in root
  `Cargo.toml:35-39`).
- **Compatibility with bb is enforced by tests**: proofs produced by the Rust
  provers are byte-compared against stored Barretenberg proof KATs
  (`tests/tests/noir/proof_tests/plain.rs:59`, `rep3.rs:109,191`), for both
  Poseidon2 and Keccak transcripts, ZK and non-ZK (ZK proofs are randomized, so
  those only round-trip through the verifier).
- Scope is **UltraHonk only**: ClientIVC/Mega ("Chonk"-adjacent) flavors were
  deliberately removed (commit `8ac77190`).

## 1. Crate layout (what depends on what)

```
mpc-net        transport: Network trait, TCP/TLS/QUIC party mesh, config TOML
mpc-core       MPC math: REP3, REP3-over-rings, Shamir, Yao/garbled circuits,
               A2B/B2A conversions, poseidon2 & merkle gadgets, LUTs
   ▲
   │
co-noir/…      the Noir/UltraHonk stack:
   noir-types         HonkProof etc.
   co-noir-types      Rep3Type/ShamirType, split/merge of witnesses & inputs
   co-noir-common     transcript (Poseidon2Sponge / Keccak256), CRS parser,
                      VK types, shared polynomials, THE DRIVER TRAIT (see §3),
                      driver impls (plain / rep3 / shamir)
   ultrahonk          plain Rust UltraHonk prover+verifier (bb rewrite)
   co-ultrahonk       the MPC UltraHonk prover (mirrors ultrahonk's structure)
   co-builder         ACIR → UltraCircuitBuilder → proving key (bb's builder in Rust)
                      + in-circuit recursive Honk verifier (honk_verifier/)
   co-acvm            MPC witness extension (ACVM opcodes on shares)
   co-brillig         MPC Brillig VM (unconstrained functions on shares)
   co-noir            CLI binary + orchestration-facing library API
co-circom/…    the parallel Circom stack (Groth16/Plonk) — shares mpc-core/mpc-net
tests/         end-to-end proof tests + bb KAT comparisons
test_vectors/  ~34 compiled Noir circuits + witnesses + bb KAT proofs
```

## 2. The prover pipeline (Rust names ↔ bb names)

`ultrahonk` and `co-ultrahonk` mirror bb's UltraHonk prover stage-for-stage:

1. **Oink** (`ultrahonk/src/oink/oink_prover.rs`, `co-ultrahonk/src/co_oink/`):
   commit to wires, compute lookup log-derivative inverses, public-input delta,
   grand product `z_perm`, draw relation-separator alphas. Flavors = 2 hashers
   (Poseidon2Sponge, Keccak256) × ZK on/off — matching bb's
   `Ultra{,ZK,Keccak,KeccakZK}Flavor`. Poseidon2 flavor pads proofs to
   `CONST_PROOF_SIZE_LOG_N = 25`; Keccak doesn't.
2. **Sumcheck** (`decider/sumcheck/`, `co_decider/co_sumcheck/`): 9 subrelations —
   ultra_arithmetic, permutation, logderiv_lookup, delta_range, elliptic,
   memory, non_native_field, poseidon2_external, poseidon2_internal
   (`ultrahonk/src/decider/relations/mod.rs`). ZK adds Libra masking /
   SmallSubgroupIPA (`small_subgroup_ipa.rs`).
3. **PCS**: Gemini fold → Shplonk batch → KZG opening ("Shplemini",
   `decider/shplemini/`, `co_decider/co_shplemini/`).
4. Proof/VK serialization matches bb byte layouts
   (`co-noir-common/src/keys/verification_key.rs` — note keccak VK layout
   differs from poseidon2 VK layout; `constants.rs` holds proof-length constants).

### How the MPC version differs structurally (`co-ultrahonk`)

- All polynomial **commitments are MSMs over public CRS bases with shared
  scalars** → each party computes locally, producing a *point share*; the
  parties then `open_point(_many)` and feed the public commitment into the
  transcript. Fiat–Shamir hashing itself is public (as ch. 01 predicts).
- **Sumcheck round univariates** use `local_mul` + `reshare` per round
  (degree reduction instead of opening; `co_sumcheck/co_sumcheck_round.rs`).
- Log-derivative lookup inverses need genuine MPC inversion (`inv_many`).
- Shamir proving requires **pre-counted correlated randomness** — the prover
  computes exactly how many Beaver-style pairs the whole proof will consume
  (`co_ultra_prover.rs:159-201`). This accounting must be updated whenever the
  proving flow changes: a known maintenance hotspot.

## 3. The two "seams" everything plugs into

These traits are the swap points if the underlying prover is replaced/upgraded —
the wrapper tooling only touches these:

1. **`NoirUltraHonkProver<P: CurveGroup>`** (`co-noir-common/src/mpc/mod.rs:17`)
   — ~60 methods (add/mul/mul_many/open/inv_many/msm_public_points/fft/…)
   implemented by `PlainUltraHonkDriver`, `Rep3UltraHonkDriver`,
   `ShamirUltraHonkDriver`. The whole prover is generic over this.
2. **`NoirWitnessExtensionProtocol<F>`** (`co-acvm/src/mpc.rs:21`) — the same
   idea for witness extension (ACVM), with `BrilligDriver` for unconstrained code.

## 4. Blackbox-function coverage (the practical gap list)

| Capability | Witness extension (co-acvm/co-brillig) | Circuit building (co-builder) |
|---|---|---|
| AssertZero / arithmetic, MemoryInit/Op (ROM/RAM), BrilligCall | ✅ | ✅ |
| RANGE, AND, XOR | ✅ | ✅ (plookup) |
| Poseidon2 | ✅ | ✅ |
| SHA-256 compression | ✅ | ✅ |
| Blake2s / Blake3 | ✅ | ✅ |
| AES-128 encrypt | ✅ | ✅ |
| MSM / EmbeddedCurveAdd (Grumpkin) | ✅ | ✅ |
| Honk RecursiveAggregation | ✅ (no-op in witext) | ✅ (`honk_verifier/`) |
| **ECDSA secp256k1 / secp256r1** | ❌ `todo!` | ❌ (empty stubs, `ultra_builder.rs:~4222`) |
| **Keccak / keccakf1600** | ❌ `todo!` | ❌ (commented out, `acir_format.rs:99-100`) |
| BigInt ops, Schnorr | ❌ | ❌ |
| Brillig blackboxes | ToRadix only (`co-brillig/src/blackbox.rs`) | n/a |

Relevance for Aztec: private-function circuits lean heavily on Poseidon2 +
embedded-curve ops (✅), but anything touching ECDSA account signatures or
Keccak would hit the gaps. Also note: if a single user owns the whole witness,
witness extension can be done in the clear (`split-witness` mode) and only the
prover runs under MPC — then only the co-builder column matters.

## 5. Wrapper tooling catalogue (the PLAN.md "early task")

### 5.1 `mpc-core` — the MPC math library
REP3 (3-party replicated, semi-honest, n=3/t=1), REP3-over-rings (with `Bit`,
LUTs, one-hot vectors, sort), Shamir (any n, `2t+1 ≤ n`; DN07-style
preprocessing via Vandermonde double-sharings), Yao garbled circuits (bundled
Bristol AES-128/SHA-256 circuits, used for A2B-style conversions), Poseidon2 &
Merkle gadgets with REP3/Shamir accelerators, REP3→Shamir bridge
(`protocols/bridges/`). Sharing/reconstruction entry points:
`rep3::share_field_elements`, `rep3::combine_field_element`,
`shamir::share_field_element`, etc.

### 5.2 `mpc-net` — the party mesh
`Network` trait (`send/recv/flush`, sync). Backends behind features: `tcp`
(what co-noir uses), `tls` (rustls, server-auth-only against pinned party
certs), `quic`, `local` (in-process, great for tests). Config: TOML
`NetworkConfigFile` — party list (`id`, `dns_name`), `my_id`, `bind_addr`,
optional TLS key/certs (DER), timeouts, `max_frame_length`. Deterministic
connection setup: lower id dials, higher id accepts. Framed messages with
background reader/writer threads. Cert generation: `mpc-net/examples/gen_cert.rs`
(rcgen self-signed). REP3 runs over *two* parallel networks (`join` helpers).

### 5.3 `co-noir` CLI + library — the orchestration surface
Subcommands (clap, `co-noir/co-noir/src/bin/co-noir.rs`; config = TOML file <
`CONOIR_*` env < flags):

| Local (no MPC) | MPC (networked) |
|---|---|
| `split-witness` (REP3/Shamir), `split-input` (REP3), `split-proving-key`, `merge-input-shares`, `create-vk`, `verify`, `download-crs`, `circuit-info` | `generate-witness` (REP3 only), `translate-witness` / `translate-proving-key` (REP3→Shamir), `build-proving-key`, `generate-proof`, `build-and-generate-proof` |

Library API (`co-noir/co-noir/src/lib.rs`) exposes the same operations for
embedding (this is what monty-hall-aztec calls): `split_input_rep3`,
`split_witness_rep3/shamir`, `merge_input_shares`, `generate_witness_rep3`,
`generate_proving_key_rep3/shamir`, `translate_*`, `generate_vk[_barretenberg]`,
`parse_barretenberg_vk`, `download_g1_crs`. The prove call itself is invoked
directly as `Rep3CoUltraHonk::<_,H>::prove(net, pk, crs, has_zk, &vk)` /
`ShamirCoUltraHonk::…` and verification as `UltraHonk::<_,H>::verify`.

File formats: `.shared` share files are **bincode** of the share types, named
`<base>.<party>.shared`; proofs and VKs are raw **Barretenberg-compatible byte
buffers** (optional `--fields-as-json`); CRS is bb's flat `.dat` format
(bundled small ones in `co-noir-common/src/crs/`; `download-crs` curls a byte
range of Aztec's ignition S3 `g1.dat`).

Examples/demos: `co-noir/co-noir/examples/` — 3-party localhost scripts
(`run_full_poseidon.sh` etc.), party TOMLs with TLS certs in `examples/data/`,
a two-user input-merge demo, and `compare_mpc.sh` diffing outputs against a
real bb binary.

### 5.4 What the repo does NOT provide (gaps an Aztec deployment must fill)
- No long-running node/daemon, job queue, or session management — every CLI
  invocation is one-shot; parties must start in lockstep.
- **No user→MPC share submission channel**: shares are written to local files;
  no envelope encryption of shares, no submission API, no PKI beyond
  self-signed pinned certs (TLS is server-auth-only; party identity is asserted
  by handshake bytes). (monty-hall-aztec starts building this layer — see ch. 04.)

  **Why this "essential" piece is missing (investigated 2026-07-08):** it
  isn't missing from Taceo's *product* — it's missing from their *open
  source*. Taceo operates a hosted service, **TACEO:Proof** (production since
  July 2025, on the "TACEO Network"), which is exactly this layer: the
  client compiles the witness locally, secret-shares it, **encrypts each
  share under the designated node's public key**, and submits via their API;
  jobs can be scheduled REP3 or Shamir. That commercial orchestration layer
  is not in this repo — the open-source co-snarks is the cryptographic core
  + CLI. Consequence for us: the share-submission/encryption channel is
  buildable (monty-hall's `crypto_box` sketch shows the intended shape) but
  is genuinely our work in phase 5 — or a reason to talk to Taceo later.
  Sources: docs.taceo.io (TACEO:Proof overview/quick-start-co-noir),
  core.taceo.io/articles/taceo-proof-prod.
- No proof collection/aggregation service (each party outputs an identical
  proof; "recombination" is trivial byte-equality, since opens happen inside
  the protocol).
- No metrics/health/retry infrastructure; failure mid-pipeline leaves orphan
  files. CLI is bn254-only; REP3 fixed at n=3/t=1; witness-gen is REP3-only.

## 6. How Taceo performs a bb/Noir sync (investigated 2026-07-08)

**There is no diff-porting automation — the code port is manual.** Someone
reads the bb C++ diff between nightlies and hand-mirrors it into
`ultrahonk` → `co-ultrahonk` → `co-builder/honk_verifier` (the in-circuit
recursive verifier), bumps the Noir git-tag pins, and regenerates test
vectors. What *is* scripted:

- `test_vectors/noir/compile.sh` (+ twin in `examples/`) — pins
  `NARGO_VERSION`, auto-installs via `noirup`, recompiles all ~34 circuits
  and refreshes witness/bytecode KATs.
- `co-noir/co-noir/examples/compare.sh` / `compare_mpc.sh` — **the real
  parity harness**: pins `BARRETENBERG_VERSION` (installed via `bbup`), then
  for 33 circuits × {poseidon2,keccak} × {zk,non-zk} runs both stacks and
  byte-diffs proofs (non-zk) plus a 4-way cross-verify matrix
  (our/their proof × our/their VK with `bb verify`). CI-ready output, but
  **no GitHub workflow actually invokes it** — CI only runs `cargo test`
  against two committed bb proof KATs (add3u64, poseidon; hand-generated
  with `bb prove --scheme ultra_honk --oracle_hash … --disable_zk`).

Anatomy of past syncs: a routine nightly hop was a same-day, ~90-file commit
(`cd1fb5b2`); the big beta.17→beta.20 + bb 3→5 jump (`7d992613`, PR #543) was
241 files, ±7k lines, **49 commits over 16 days**, done by an external
contributor and reviewed by two Taceo engineers. Version pins live in 5
places: root `Cargo.toml` (Noir tags), `compare.sh`, `compare_mpc.sh`, two
`compile.sh` — plus Readmes.

**Reusable for our (local, no-push) sync**: the compare.sh oracle pattern and
compile.sh KAT regeneration, verbatim — our target (v5-next ≡ public
`v5.0.0-nightly.20260708`) has a public bb release, so `bbup` can install the
reference binary without touching anything private. **Not reusable**: there's
no porting tool to borrow; the relation/transcript/builder mirroring is
skilled manual work, which is exactly what PLAN.md phase 2 budgets for.

## 7. Build / run / test commands

```bash
# Build everything (repo root)
cargo build --release

# Run the end-to-end proof tests incl. bb KAT byte-equality
cargo test -p tests --release

# Full 3-party local demo (split → witness-gen → prove → verify)
cd co-noir/co-noir/examples && ./run_full_poseidon.sh

# Compare Rust vs a real bb binary (needs bb v5.0.0-nightly.20260324 built)
cd co-noir/co-noir/examples && ./compare_mpc.sh
```
