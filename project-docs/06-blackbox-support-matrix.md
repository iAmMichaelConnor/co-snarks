# Chapter 6 — Blackbox & stdlib function support in co-noir, with difficulty estimates

*Verified 2026-07-08 against co-snarks main @ `36da0ea8` (pins Noir
v1.0.0-beta.20). Read ch. 01 §2.3 (garbled circuits / binary sharing) first —
it explains WHY bit-oriented functions are the hard ones.*

## 0. How Noir functions map to what co-noir must support

Noir stdlib calls compile to one of two things:

1. **Ordinary ACIR** (field arithmetic + memory ops + Brillig): works under
   co-noir automatically — no per-function support needed.
2. **ACIR blackbox function calls** — 14 opcodes the backend must implement
   natively. Each needs support in up to three co-noir places:
   - **co-acvm** (MPC witness extension — computing the output values from
     shared inputs),
   - **co-brillig** (only if called inside `unconstrained` code),
   - **co-builder** (laying down the constraint gates; the gate *layout* is
     public, but the builder must call MPC driver ops wherever it materializes
     intermediate witness values from shared ones).

Illustration: there is **no Pedersen blackbox** — `std::hash::pedersen_hash`
lowers through `std::embedded_curve_ops` onto the MultiScalarMul /
EmbeddedCurveAdd blackboxes (both supported) plus field arithmetic, so
Pedersen works and has passing test vectors (`test_vectors/noir/pedersen_*`).
Conversely `keccak256` lowers onto the Keccakf1600 blackbox — unsupported, so
it fails. The blackbox matrix below is therefore the exact support frontier.

## 1. The matrix (all 14 ACIR blackboxes, Noir beta.20)

Legend: ✅ supported · ⚠️ partial · ❌ unsupported (`todo!`/panic).
"witext" = witness extension (co-acvm). Dispatch:
`co-acvm/src/solver/blackbox_solver.rs:430-524` (fallthrough `todo!` at :523);
brillig: `co-brillig/src/blackbox.rs` (only ToRadix; others `todo!`);
builder: `co-builder/src/acir_format.rs:645-871` → `ultra_builder.rs`.

| Blackbox | witext REP3 | witext Shamir | co-brillig | co-builder (REP3) |
|---|---|---|---|---|
| RANGE | ✅ | ✅ | ❌ | ✅ (plookup) |
| AND / XOR | ✅ | ⚠️ public inputs only | ❌ | ✅ |
| Poseidon2Permutation | ✅ | ✅ | ❌ | ✅ |
| Sha256Compression | ✅ | ❌ | ❌ | ✅ |
| Blake2s / Blake3 | ✅ | ❌ | ❌ | ✅ |
| AES128Encrypt | ✅ | ❌ | ❌ | ✅ |
| MultiScalarMul | ✅ | ❌ | ❌ | ✅ |
| EmbeddedCurveAdd | ✅ | ❌ | ❌ | ✅ |
| RecursiveAggregation | ✅ (no-op in witext) | ✅ (no-op) | ❌ | ⚠️ Honk/HonkZK only; other proof types panic |
| **EcdsaSecp256k1** | ❌ | ❌ | ❌ | ❌ |
| **EcdsaSecp256r1** | ❌ | ❌ | ❌ | ❌ |
| **Keccakf1600** | ❌ | ❌ | ❌ | ❌ |

Non-blackbox opcodes (AssertZero, MemoryInit/Op = ROM/RAM, BrilligCall, Call)
are all ✅.

### The "unconstrained functions" caveat, explained from scratch

Noir programs contain two kinds of code, and they take **different execution
paths** through co-noir:

- **Constrained code** (normal Noir) compiles to **ACIR**: a list of
  constraints that end up as gates in the proof. To *generate the witness*,
  the ACVM executes these opcodes — in co-noir, that's **co-acvm**, and its
  blackbox support is the "witext" column above.
- **Unconstrained code** (functions marked `unconstrained`, and hidden helpers
  the compiler inserts, e.g. for division or sorting) compiles to a different
  bytecode called **Brillig**. It is *executed but never proven* — it's used
  to cheaply compute "hint" values which constrained code then verifies.
  Classic example: to prove `y = 1/x`, unconstrained code computes `y` by
  actually dividing, and the circuit only constrains `x·y == 1`.

Because unconstrained code still *runs on secret-shared values* during MPC
witness generation, co-noir needs a second MPC interpreter for it —
**co-brillig** — with its own, separate blackbox dispatcher. And that
dispatcher currently implements only one operation (`ToRadix`, i.e.
decomposing a field element into digits/bytes).

**The consequence, concretely:** `poseidon2` works fine in normal Noir code
(co-acvm supports it), but if a circuit calls `poseidon2` *inside an
`unconstrained` function*, MPC witness generation crashes — same function,
different execution path, different support table. The circuit author sees a
`todo!` panic from `co-brillig/src/blackbox.rs:21`.

Two mitigating notes: (1) this only bites during MPC *witness extension*; if
the witness is computed in the clear (single-owner flow via `split-witness`)
and only proving is done under MPC, Brillig never runs on shares at all.
(2) Noir's stdlib rarely puts blackboxes inside unconstrained helpers, so in
practice this is mostly a hazard for hand-written `unconstrained` code. When
checking a target circuit for co-noir compatibility, inspect its unconstrained
functions for blackbox calls specifically.

**Why the Shamir column is so red:** Shamir sharing has no binary/Yao layer
(`decompose_arithmetic` is "not feasible for Shamir",
`co-acvm/src/mpc/shamir.rs`) — so only field-native blackboxes work. This is
by design; the intended flow is REP3 for witness extension, with optional
translation to Shamir for the proving stage only. Practically: **REP3 is the
protocol that matters for blackbox coverage.**

## 2. Difficulty to add the missing pieces (REP3)

| Item | Difficulty | Rationale |
|---|---|---|
| **Keccakf1600, witext** | **Medium** | Pure bit-permutation (XOR/AND/rotations over 25×64-bit lanes). The binary-sharing/Yao machinery it needs already exists (`mpc-core/src/protocols/rep3/yao/` — this is exactly how SHA-256/AES are done). Missing ingredient: a keccak-f Bristol circuit (only `aes_128.txt` and `sha256.txt` are bundled) or a hand-built gadget from binary ops. Directly analogous to completed work. |
| **Keccakf1600, builder** | **Medium** | bb has a lookup-table keccak gadget; co-builder even has the placeholder slot (`acir_format.rs:99`). Effort ≈ the already-done sha256_compression port (gate layout + driver calls for sparse-form normalization). |
| **ECDSA k1/r1, witext** | **Hard** | Non-native field arithmetic (secp256 base + scalar fields emulated in BN254 limbs) + foreign-curve scalar mul + modular inversion, all under MPC. Building blocks exist in rep3 (`mul_mod`, `inverse`, limb helpers, NAF machinery — used by the recursive verifier), but assembling full ECDSA-verify is large and error-prone. r1 slightly worse (no endomorphism shortcuts). |
| **ECDSA k1/r1, builder** | **Hard** | Port bb's bigfield/biggroup ECDSA gadget; volume-heavy rather than conceptually novel — every non-native mul/inverse/EC op needs a driver call. |
| **AND/XOR on shared values, Shamir** | **Hard (architectural)** | Would mean building an entire binary layer for Shamir. Not worth it — use REP3 (+ translate-to-Shamir) instead. |
| **co-brillig blackboxes beyond ToRadix** | Easy→Hard, **low priority** | Driver ops mostly exist (Poseidon2/bitwise easy; hashes medium by reusing witext code; ECDSA hard). Only needed if a target circuit calls blackboxes *inside* unconstrained fns. |
| **RecursiveAggregation of non-Honk proof types** | Hard, out of scope | Would require porting other in-circuit verifiers (AVM/Chonk etc.). Honk/HonkZK — the ones we need — already work. |

## 3. Practical guidance for circuit authors (Aztec context)

- **Cheap under MPC**: Poseidon2 (hashing, commitments, nullifiers), Pedersen,
  embedded-curve ops (ECDH, address derivation), field arithmetic, ROM/RAM,
  ranges — i.e. the primitives typical Aztec private-function logic uses.
- **Works but expensive** (bit-native, via binary sharing/garbled circuits):
  SHA-256, Blake2s/3, AES-128.
- **Currently impossible**: keccak256/Keccakf1600 (medium to add), ECDSA
  signature verification (hard to add), any blackbox inside unconstrained code
  except ToRadix.
- One upgrade caveat: Noir beta.22 changed the EmbeddedCurveAdd/MultiScalarMul
  opcode shapes (infinity flags removed — matching the bb-side ACIR serde
  change noted in ch. 03 §2). Bumping co-noir's Noir pin past beta.20 must
  update `co-acvm/src/solver/blackbox_solver.rs` and
  `co-builder/src/acir_format.rs` accordingly — this is part of PLAN.md
  phase 2.6.
