# Chapter 1 — A primer on co-SNARKs (collaborative SNARKs)

*Audience: mathematically fluent, comfortable with cryptography up to
Plonk-era SNARKs, no MPC background assumed. This chapter covers the MPC side
and the general principles of running a SNARK prover under MPC. Chapter 07
covers UltraHonk itself (what changed since Plonk) and maps each prover stage
to its MPC realization. Chapter 08 has the data-flow diagrams. Repo-specific
claims are cross-referenced to chapter 02.*

## 1. The problem co-SNARKs solve

A normal SNARK prover must see the **entire witness in the clear**. That's
fine when the prover *is* the data owner (an Aztec user proving from their own
PXE). It breaks down when:

1. **The witness combines private data from multiple parties** — e.g. proving
   a joint statement about two users' balances without revealing either.
2. **The data owner can't or shouldn't prove** — a phone delegates an
   expensive proof to servers without trusting any single server; or (the
   "private shared state" pattern, ch. 04) the state being proven about must
   be hidden *from every individual party including the user*.

A **co-SNARK** runs the *prover algorithm itself* as a **secure multi-party
computation (MPC)**: N servers each hold only a *secret share* of the witness,
jointly execute the prover, and output a **perfectly ordinary proof** —
byte-identical in format to a single-prover proof, verifiable by the
unmodified verifier, which cannot tell MPC was involved. The security claim:
as long as no more than t of the N parties collude, the protocol transcript
reveals nothing about the witness beyond what the proof itself reveals.

The idea is due to Ozdemir & Boneh, *"Experimenting with Collaborative
zk-SNARKs: Zero-Knowledge Proofs for Distributed Secrets"* (USENIX Security
2022, [eprint 2021/1530](https://eprint.iacr.org/2021/1530)), which built MPC
versions of Groth16/Plonk/Marlin and formalized the security notion
(*t-zero-knowledge*: corrupt parties' views are simulatable from public data
+ the proof). Taceo's own [Collaborative SNARKs
Primer](https://docs.taceo.io/docs/primer/collabSNARKs-primer/) motivates it
with the canonical two-party example: Alice (secret `a`) and Bob (secret `b`)
want a proof about hash(a,b) — a trusted third party "would learn both of
their secrets", so instead each secret-shares their input to a small network
that computes and proves *on the shares*.

## 2. Linear secret sharing, properly

Everything happens over the same field 𝔽 the SNARK uses (BN254's scalar field
𝔽ᵣ for UltraHonk). Fix the corruption threshold t and party count N.

### 2.1 Additive sharing (the building block)

⟨x⟩ = (x₁, …, x_N) with x = Σxᵢ, all but one summand uniformly random. Any
N−1 shares are uniform and independent of x; all N reconstruct it. Additions
and scalar multiplications are share-local. Multiplication of two additively
shared values is *not* local: x·y = Σᵢⱼ xᵢyⱼ contains cross terms xᵢyⱼ that no
single party can compute. Everything else in MPC is machinery for handling
those cross terms.

### 2.2 REP3 — replicated 3-party sharing (the workhorse here)

N = 3, t = 1, **semi-honest** (parties follow the protocol but may try to
infer secrets from their view; this is the model Taceo's stack targets —
accepted for now per Mike's decision, PLAN.md).

Write x = x₀ + x₁ + x₂. Party i holds the *pair* (xᵢ, xᵢ₋₁) (indices mod 3) —
each additive share is held by exactly two parties. Any single party's view
(two of three summands) is uniform, so privacy holds against one corruption.

**Why replication makes multiplication cheap.** With y shared the same way,
party i can locally compute

  zᵢ = xᵢ·yᵢ + xᵢ·yᵢ₋₁ + xᵢ₋₁·yᵢ

Summing over i: Σzᵢ = Σᵢⱼ xᵢyⱼ = x·y — every one of the 9 cross terms appears
exactly once. So the parties obtain an *additive* (non-replicated) sharing of
the product with **zero communication**. Two housekeeping steps remain:

1. **Re-randomization**: zᵢ as computed is correlated with the inputs; each
   party adds its share αᵢ of a fresh secret sharing of zero (Σαᵢ = 0). These
   "zero shares" cost nothing online: at setup each pair of parties exchanges
   a PRF seed, and αᵢ = PRF(seedᵢ, ctr) − PRF(seedᵢ₋₁, ctr). This is REP3's
   entire "correlated randomness" — no preprocessing phase needed.
2. **Resharing**: to restore the replicated format (each summand held twice),
   party i sends its re-randomized zᵢ to party i+1. **One field element per
   party per multiplication, one round** — and any number of independent
   multiplications batch into the same round.

This is why REP3 is the default protocol in co-snarks: multiplication is a
single cheap round, there's no preprocessing, and the witness-extension VM
(ch. 02 §4) only supports REP3.

### 2.3 Shamir sharing (for generality beyond 3 parties)

x is the constant term of a random degree-t polynomial f; party i holds
f(i). Any t+1 shares interpolate f (reconstruct x); any t shares are
uniform. Linear operations are share-local (interpolation is linear).

Multiplying share-wise gives points on f·g — a degree-2t polynomial whose
constant term is xy. Two consequences: you need 2t+1 ≥ ⌈…⌉ parties to even
hold enough points (honest majority again), and the sharing has the wrong
degree. The classic fix (Damgård–Nielsen '07 style, which is what `mpc-core`
implements) uses **double sharings**: preprocessing produces pairs
(⟨r⟩_t, ⟨r⟩_2t) — the *same* random r shared at both degrees, generated
efficiently by having each party contribute a random value and multiplying by
a Vandermonde matrix to extract N−t independent outputs per batch. Online,
for each multiplication: parties locally compute dᵢ = f(i)·g(i) + r^{2t}_i,
open the degree-2t value d = xy + r (opening reveals nothing — r masks the
product), then set their new share to d − ⟨r⟩_t. One opening per
multiplication; batchable. This is the "correlated randomness accounting"
that co-ultrahonk must precompute for Shamir proving (ch. 02 §2) — the prover
counts exactly how many multiplications the whole proof will perform.

REP3 → Shamir translation exists (`translate-witness`), so the intended flow
is: witness extension under REP3 (richer gadget support), optionally
translate, prove under either.

### 2.4 The cost model (this drives every design decision)

| Operation on shared values | Cost |
|---|---|
| Addition, subtraction, multiplication by *public* constants | Free (local) |
| Any 𝔽-linear map — including **polynomial commitment MSMs**, FFTs/IFFTs, evaluating a shared polynomial at a *public* point | Free (local on shares) |
| Multiplication of two shared values | 1 round, 1–2 field elements per party; batchable |
| Inversion of a shared value | ~2 rounds via mask-and-open (below) |
| Opening (reconstructing) a value | 1 round; the value becomes public forever |
| Bit-decomposition, comparisons, range ops, bitwise ops | Expensive — requires the binary world (§3) |

Two cost-model facts deserve emphasis:

- **Commitments are free.** A KZG/IPA-style commitment commit(p) = Σₖ pₖ·[τᵏ]₁
  is 𝔽-linear in the coefficients. Party i MSMs its own share vector against
  the public CRS and obtains an elliptic-curve-point *share* of the
  commitment: commit(p) = Σᵢ commit(pᵢ) (for additive/replicated shares;
  interpolation-in-the-exponent for Shamir). The single most expensive step
  of a Honk prover — witness commitment MSMs — parallelizes perfectly with
  zero communication. Point shares live in the curve group; `mpc-core` has
  `pointshare` modules implementing the same sharing algebra over G₁.
- **Latency, not bandwidth, dominates.** A million independent
  multiplications in one round cost barely more than one. Protocol design is
  about *round structure*: batch everything, never sequentialize
  multiplications that could share a round. (E.g. `mul_many`, `open_many`,
  `inv_many` throughout the driver trait, ch. 02 §3.)

**Deferring the reshare through linear postprocessing** — the optimization
behind Taceo's ["surprising efficiency" of honest-majority MPC for
coSNARKs](https://core.taceo.io/articles/honest-majority-mpc-for-cosnarks/):
after the *local* half of a multiplication, parties hold additive shares of
the product; since everything downstream may be linear (FFT, MSM, sums),
they can apply those linear maps **directly to the un-reshared additive
shares** and only reshare (or open) at the very end. For Groth16's h-vector
— elementwise products followed by purely linear work — this collapses
communication from circuit-size to **constant** ("3 field elements and 2
multiplications regardless of constraint count"; their words: *"communication
is constant … which is both surprising and amazing"*). Honk's sumcheck is
less extreme (each round's challenge depends on the previous round's opened
values, forcing a round structure), but the same principle shapes the
driver's `local_mul_vec` + `reshare` split (ch. 02 §3, ch. 07 §5).

**The inversion trick** (used for log-derivative lookup inverses, ch. 07):
to compute ⟨x⁻¹⟩ from ⟨x⟩, sample a shared random ⟨r⟩, compute ⟨r·x⟩ (one
multiplication), **open** r·x (uniform, reveals nothing about x), publicly
invert it, and set ⟨x⁻¹⟩ = (r·x)⁻¹ · ⟨r⟩ — a scalar-times-share, free. Two
rounds total, fully batchable.

## 3. The binary world: bit operations and garbled circuits

Arithmetic sharing makes +/× cheap but is hopeless for boolean algorithms:
XOR/AND/shifts/comparisons have no low-degree expression over a 254-bit prime
field. MPC keeps a **second representation** and hops between them:

- **Binary sharing**: share each bit of x XOR-additively
  (x = x⁰ ⊕ x¹ ⊕ x², replicated as in REP3). Now XOR is free and AND is the
  1-round multiplication — the boolean mirror of the arithmetic world.
- **A2B / B2A conversion**: converting an arithmetic share to a binary share
  means securely computing a ripple/parallel-prefix *addition circuit* over
  the shares' bits (the summands x₀,x₁,x₂ must be added *as integers with
  carries*, under sharing). This is the genuinely expensive hop; everything
  bit-native (SHA-256, AES, Keccak-if-implemented, range decompositions)
  pays it on entry and exit.
- **Garbled circuits (Yao)** give *constant-round* boolean computation, vs
  one round per AND-depth for share-based binary MPC. Mechanics: the
  **garbler** assigns every wire two random 128-bit keys (meaning 0/1) and
  encrypts each gate's truth table so that possession of one key per input
  wire decrypts exactly one output key and nothing else; the **evaluator**
  walks the circuit ciphertext-by-ciphertext without learning any wire's
  semantics. Free-XOR and half-gate optimizations make XOR cost nothing and
  AND cost ~2 ciphertexts. In the 3-party honest-majority setting the roles
  are distributed so no single party learns anything.
- **In this repo**: `mpc-core/src/protocols/rep3/yao/` implements
  garbler/evaluator (via the `fancy-garbling` library), parses
  **Bristol-format** circuit descriptions, and bundles AES-128 and SHA-256
  circuits. REP3's A2B conversions are configurable to route through Yao
  (`A2BType` on `Rep3State`); the sorting network used for range-check
  witness generation uses these gadgets too.

Rule of thumb: **field-native work (Poseidon2, Pedersen, embedded-curve ops)
is cheap under MPC; bit-native work is 10–1000× more expensive.** This is why
blackbox coverage (ch. 06) is the practical frontier, and why circuits
destined for co-snarking should prefer Poseidon2 over bit-oriented hashes.

## 4. Running a SNARK prover under MPC: the general principles

A modern (Plonk/Honk-family) prover is an interactive protocol made
non-interactive by Fiat–Shamir: rounds of *commit to polynomials → derive
challenge by hashing the transcript → compute the next polynomials using the
challenge*. Under MPC:

1. **The transcript is public.** Everything that enters the Fiat–Shamir hash
   is, by definition, part of the proof the verifier will see. So the parties
   can **open** each round's outputs (commitments, evaluations) as they are
   produced, hash them *in the clear* — no MPC hashing needed — and continue
   with a public challenge. Opening a value that appears verbatim in the
   final proof leaks exactly nothing beyond the proof itself. This single
   observation removes what would otherwise be the deal-breaker (evaluating
   Poseidon2/Keccak inside MPC every round).
2. **Public challenges keep everything linear-ish.** Once a challenge γ is
   public, "multiply the shared polynomial by γ and add" is free. The only
   *secret×secret* multiplications left are those intrinsic to the proving
   math: products of witness polynomials inside relation evaluation
   (sumcheck), grand-product/log-derivative accumulators, and inverses.
   Chapter 07 §5 walks stage-by-stage through where these occur in UltraHonk.
3. **Commitments are opened before hashing** — the parties hold point-shares
   of each commitment (free MSM, §2.4), broadcast the shares, reconstruct the
   public curve point, and feed it to the transcript. One round per prover
   round, batched across all commitments of that round.
4. **Prover randomness must be jointly sampled.** ZK blinding/masking values
   must be uniform *and unknown to every individual party* — otherwise the
   party that chose them could de-blind. REP3 gets these from the correlated
   PRF seeds (each masking share is a PRF output, so the mask is the sum of
   values no single party fully knows); Shamir from the preprocessing
   double-sharings.
5. **Determinism.** With shares fixed and challenges derived by Fiat–Shamir,
   every honest party computes the *same* proof bytes. There is no "proof
   shard recombination" step: the proof is assembled from values that were
   opened during the protocol, so each party can emit the complete proof, and
   an orchestrator can cross-check the three copies byte-for-byte (this is
   exactly what monty-hall-aztec does, ch. 04). ZK flavors are still
   deterministic *given* the correlated randomness — the masks are shared
   pseudorandomness, not per-party coin flips — which is why byte-equality
   across parties holds there too.

### 4.1 What must run under MPC, end to end

1. **Witness extension**: Noir's ACVM executes ACIR opcode-by-opcode to fill
   in every intermediate wire value from the inputs. If inputs are shared,
   this execution runs on shares (co-acvm/co-brillig). Arithmetic opcodes are
   the easy case; blackbox functions are ch. 06's matrix. Control flow needs
   care: ACIR is already flattened (no data-dependent branches), but
   `unconstrained` Brillig code *does* have data-dependent behavior, handled
   with oblivious techniques (cmux trees, one-hot LUT reads — `mpc-core`'s
   `rep3_ring` gadgets) or by accepting leakage-free early termination only
   where provably safe.
2. **Proving-key construction**: selector polynomials, permutation σ, lookup
   tables are all *public* (they define the circuit); only the witness
   columns are shared. co-builder (ch. 02) mirrors bb's UltraCircuitBuilder
   but with wire values as shares — the gate *layout* decisions must never
   depend on secret values (bb's builder sometimes branches on witness
   values as an optimization; the MPC port must take the data-independent
   path).
3. **The prover** itself (ch. 07 §5 for the stage-by-stage mapping).

Everything else — compilation, VK generation, CRS, verification — is public,
single-party, and identical to the non-MPC stack.

### 4.2 Alternative: single-owner delegation ("split-witness" mode)

If one user owns the whole witness, they can run plain `nargo execute`
locally, then secret-share the *finished* witness vector (`split-witness`)
— skipping MPC witness extension entirely, so blackbox support (ch. 06)
becomes irrelevant and only the prover runs under MPC. This is the "proof
delegation" deployment: the user's device does the cheap part (witness ≈
circuit execution), the network does the expensive part (the prover), and no
node sees the witness. Taceo's hosted **TACEO:Proof** product is exactly this
flow (shares encrypted per-node, submitted via API) — see ch. 02 §5.4 on
what's in the open-source repo vs their commercial layer.

## 5. What a non-ZK proof leaks, and why ZK matters more here

Standard UltraHonk (non-ZK flavor) is *sound* but makes no zero-knowledge
claim: witness commitments are binding but unblinded, and sumcheck reveals
evaluations of witness polynomials at the random challenge point. For a
single prover who owns the witness this is usually acceptable (the proof
often stays inside a local recursion stack). For co-SNARKs the calculus
changes: the *entire point* is that nobody — sometimes including the user —
learns the witness, and the proof is the one artifact everyone sees. If the
proof itself leaks witness information, the MPC's privacy guarantee is
undermined by its own output. Hence the **ZK flavors** (masked witness
commitments, Libra-masked sumcheck, SmallSubgroupIPA — ch. 07 §4) are the
safe default for co-SNARK deployments, and both are implemented in co-noir
(`ZeroKnowledge::Yes`). Whether Aztec's in-contract verifier accepts non-ZK,
ZK, or both is tracked in PROGRESS.md (investigation in flight).

The formal statement of co-SNARK security (Ozdemir–Boneh and follow-ups):
the MPC realizes the prover functionality t-privately — corrupt parties'
views are simulatable given only the public inputs and the proof. Composing
with a ZK proof system yields: the adversary learns nothing about honest
parties' witness contributions, full stop. With a *non*-ZK proof system you
still get "nothing beyond what the proof reveals" — which is a weaker,
circuit-dependent guarantee.

## 6. Performance intuition

- The heavy prover steps (MSMs, FFTs) are share-local → each node does
  roughly the same computation as a single prover, in parallel.
- Communication is dominated by sumcheck's per-round multiplications and the
  witness-extension phase; both batch well. On LAN-grade links between the 3
  nodes, expect small-constant-factor (~2–10×) wall-clock overhead vs a
  single prover for arithmetic-heavy circuits; latency-bound degradation on
  WAN; and much larger factors for bit-heavy circuits (A2B conversions).
- Taceo's published expectations (their [honest-majority MPC
  post](https://core.taceo.io/articles/honest-majority-mpc-for-cosnarks/)):
  REP3 CPU cost "usually is twice that of a non-MPC prover due to computing
  on two additive shares"; 3-party Shamir approaches non-MPC performance
  (each party holds ONE share and all CPU-heavy ops are linear);
  communication overhead negligible for Groth16-shaped provers. Honk's
  round-heavy sumcheck will do somewhat worse than the Groth16 constant-
  communication result — **do not quote numbers for co-UltraHonk until we
  measure** (PLAN.md phase 0.5).

## 7. Sources & further reading

Prominent public explainers this primer draws on and agrees with (all
re-verified 2026-07-08; our repo-specific claims come from code, ch. 02):

- **Ozdemir & Boneh**, *Experimenting with Collaborative zk-SNARKs* —
  [eprint 2021/1530](https://eprint.iacr.org/2021/1530). The founding paper:
  MPC Groth16/Plonk/Marlin, the t-zero-knowledge definition.
- **Taceo, [Collaborative SNARKs Primer](https://docs.taceo.io/docs/primer/collabSNARKs-primer/)** —
  gentle intro; the Alice & Bob Poseidon example; "shares of a secret-shared
  value are safe to send around".
- **Taceo, [The Surprising Efficiency of Honest-Majority MPC for coSNARKs](https://core.taceo.io/articles/honest-majority-mpc-for-cosnarks/)** —
  the technical heart of why this is practical: local-mul + linear
  postprocessing before resharing; constant communication for Groth16;
  REP3 ≈ 2× CPU, 3-party Shamir ≈ 1×; seed-based randomness without
  communication.
- **Taceo, [Private Shared State](https://core.taceo.io/articles/private-shared-state/)** and
  **[Hashing it out: coSNARKs at TACEO](https://core.taceo.io/articles/hashing-it-out/)** —
  the PSS pattern (ch. 04's subject) and the product framing: "coSNARKs allow
  multiple parties to jointly compute and generate a proof, without requiring
  any one party to know the entire witness."
- **Taceo, [TACEO:Proof docs](https://docs.taceo.io/)** — the hosted
  delegation flow (encrypt-share-per-node, REP3/Shamir job scheduling);
  see ch. 02 §5.4 for why that layer isn't in the open-source repo.
- **[TaceoLabs/co-snarks](https://github.com/TaceoLabs/co-snarks)** — the
  code this project builds on (ch. 02).

Where this primer goes beyond those sources: the REP3 multiplication
derivation (§2.2), DN07 double-sharing detail (§2.3), the mask-and-open
inversion pattern (§2.4), garbled-circuit mechanics (§3), the Fiat–Shamir
"open-then-hash-publicly" principle and prover-randomness/determinism
analysis (§4), and the ZK-leakage discussion (§5) — assembled from the
literature and verified against the co-noir implementation.

## 8. Glossary

| Term | Meaning |
|---|---|
| co-SNARK | A SNARK whose prover ran under MPC; the proof is standard. |
| Party / node | One of the N (=3) servers jointly proving. |
| REP3 | Replicated 3-party sharing: party i holds (xᵢ, xᵢ₋₁) of x = x₀+x₁+x₂. Honest-majority, 1 corruption, no preprocessing. |
| Shamir | Threshold sharing via polynomial evaluation; needs DN07 double-sharing preprocessing for multiplication. |
| Semi-honest | Adversary follows the protocol, tries to infer from its view. (Contrast *malicious*: may deviate arbitrarily — not covered by this stack for UH.) |
| Opening | Broadcasting shares to reconstruct a value publicly. |
| Correlated randomness | Pre-agreed random values with a joint structure (zero-sharings, double-sharings, PRF seeds) consumed by the online protocol. |
| A2B / B2A | Conversion between arithmetic and binary (bitwise) sharings. |
| Garbled circuit | Encrypted boolean circuit enabling constant-round secure evaluation (Yao; free-XOR/half-gates). |
| Bristol format | Standard textual format for boolean circuit descriptions. |
| Witness extension | Executing the circuit (ACVM/Brillig) to derive all wire values from inputs. |
| Mask-and-open | Pattern: multiply secret by shared random mask, open the product, finish in public (e.g. batched inversion). |
| Point share | Secret share of an elliptic-curve point (shares live in G₁). |
| CRS/SRS | Public powers-of-τ for KZG; `.dat` files here. |
| Transcript hasher | Poseidon2 (cheap in-circuit for recursion) or Keccak (cheap on EVM) — determines the Fiat–Shamir hash and hence the flavor. |
