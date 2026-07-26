# Chapter 25 — Private shared state: the landscape, and what to build on Aztec

*Research date-stamp: **2026-07-26**. Web research performed via search + primary-source
fetches on that date; company/funding/traction facts are a snapshot and will rot.
Register: crypto/MPC at full depth (ch. 01 assumed); business and market reasoning
spelled out in plain language, no product familiarity assumed. Every externally
sourced claim carries an inline URL. Claims are tagged:*

- ***[V]** — verified against a primary source (page fetched and read);*
- ***[S]** — seen only in search-result snippets / secondary aggregators (weaker);*
- ***[opinion]** — my inference or judgement, not a sourced fact.*

*Local performance numbers come from our own bench runs
(`bench-results/bench.sqlite`, run `2026-07-25`, loopback, per-party medians) and
chs. 22/24 — those are measured facts about THIS repo's code, not estimates.*

---

## 1. What "private shared state" means, precisely

### 1.1 The three regimes

Blockchain state today comes in two flavors, and there is a third that almost
nobody ships:

| Regime | Who can read it | Who can write it | Example |
|---|---|---|---|
| **Public shared state** | everyone | anyone (per contract rules) | Ethereum/Uniswap pool balances |
| **Private personal state** | its owner only | its owner (proves transitions in ZK) | Aztec notes today: the PXE holds the plaintext, proves privately, publishes commitments |
| **Private SHARED state** | **nobody** — no single party, *including the users it concerns* | a defined quorum, via a privacy-preserving computation that also emits a public proof of correctness | monty-hall's `TACEONote` (ch. 04): the MPC network holds the door assignment as REP3 shares; not even the player's PXE knows it |

The precise property: **state such that no single machine ever holds the
plaintext, yet a designated group can (a) apply agreed state-transition
functions to it and (b) convince the public — via an ordinary SNARK — that the
transition was correct.** Three separable capabilities are being demanded at
once:

1. **Custody without knowledge** — the state exists only as shares/ciphertexts.
2. **Computation without disclosure** — transitions run without reconstructing it.
3. **Public verifiability** — outsiders (an L1/L2 contract) can check the
   transition without trusting the custodians for *integrity*, only for
   *privacy* (this split is the key design point: in a co-SNARK, collusion
   breaks secrecy but never soundness — the proof still only verifies if the
   transition was correct; ch. 01 §1).

Why per-user privacy (Aztec's native model) can't fake it: a Noir private
function proves over witnesses *the prover knows*. Any app whose core logic is
a function of **several parties' secrets simultaneously** (an auction over all
bids, a match over both order books, a score over many lenders' records) needs
someone to see all of them — and "someone" is exactly what private shared
state eliminates. The discriminator question for every use case in §4 is:
*does the state-transition function take more than one party's secret as
input, or need to be hidden from its own beneficiary?* If no, ordinary Aztec
notes suffice and PSS is over-engineering.

### 1.2 The mechanism taxonomy

Five known ways to build the property, with honest maturity readings
(**[opinion]** except where sourced):

**MPC / co-SNARKs (this repo).** State lives as linear secret shares across
N servers; transitions run as MPC; a collaborative SNARK
([Ozdemir–Boneh 2021](https://eprint.iacr.org/2021/1530)) makes the output
publicly verifiable with an *unmodified* verifier. Strengths: exact
field-native computation (no ciphertext blowup), integrity independent of the
privacy assumption, byte-identical proofs (ch. 01 §1). Weaknesses: an
honest-majority *non-collusion* assumption (n-of-3, t=1, semi-honest in this
repo), and communication-round latency (§5). Maturity: **production** — TACEO
has run World ID's uniqueness checks on it at ~15M-user scale (§2), and this
repo proves real UltraHonk circuits today. The most mature *general* PSS
mechanism as of 2026 **[opinion]**.

**TEEs (Intel SGX/TDX, AMD SEV).** Plaintext state inside enclave memory;
"privacy" = hardware attestation. Cheapest and lowest-latency by far — and the
track record is disqualifying for high-value adversarial settings: Secret
Network's consensus seed was exposed by the 2022 xAPIC/AEPIC leak (potentially
retroactively decrypting the whole chain's history,
[corroborated across security research](https://aepicleak.com/)), and the 2025
"TEE.fail" DDR5 bus attack (sub-$1,000 hardware, affects SGX *and* TDX *and*
SEV-SNP) forced Secret into permissioned-validator mode
([Secret Labs response](https://scrt.network/blog/secret-labs-response-to-tee-fail-ddr5-vulnerability) [V]).
Secret's own 2026 roadmap now includes "SGX decoupling" [S]. Use TEEs as a
*defense-in-depth layer* or for low-stakes latency-critical apps, not as the
sole custodian of valuable secrets **[opinion]**.

**FHE.** Compute directly on ciphertexts (TFHE-family for the EVM projects).
Elegant single-server story, but two catches: (a) computational overhead
commonly cited in the 10³–10⁶× range depending on operation mix (unverified
folklore figure, but Zama's GPU/ASIC roadmap is itself evidence the overhead
is hardware-scale); (b) **someone must hold the decryption key** — every deployed fhEVM
design (Zama, Inco Atlas) puts the key under a *threshold-MPC committee*
([Zama's 13 MPC node operators](https://www.zama.org/post/zama-protocol-testnet-update-mpc-partners-better-performance-audits-and-new-features) [V]),
so FHE-for-shared-state inherits the same non-collusion assumption as MPC —
it moves *where* the computation happens, not *who you trust* **[opinion]**.
Maturity: Zama mainnet on Ethereum since 2025-12-30 [S]; real but young, and
economically unproven for heavy state transitions.

**Threshold encryption (without general compute).** Encrypt to a committee
key; decrypt only when a condition fires (end of a voting period, end of a
batch). No computation on hidden state — just *timed disclosure*. Much cheaper
than MPC/FHE and already deployed: Shutter×Snapshot shielded DAO voting
([live since 2022](https://blog.shutter.network/shutter-brings-shielded-voting-to-snapshot/) [V]),
Penumbra's batch swaps (§3). Covers exactly the use cases where "hidden until
T, then public" suffices — sealed bids being the canonical one — but cannot
keep state private *across* transitions. A serious, cheaper competitor for the
auction use cases in §4 **[opinion]**.

**Witness encryption / iO.** "Decryptable by whoever has a witness to R(x)."
Would eliminate the committee entirely. Status: general-purpose WE remains
impractical; 2025 work builds *special-purpose* WE from SNARK verification
equations with real benchmarks
([CRYPTO 2025 framework](https://eprint.iacr.org/2025/1364);
[NIST STPPA presentation](https://csrc.nist.gov/Presentations/2025/stppa7-witness-encryption)),
but nothing supports rich stateful applications. Watch, don't build on
**[opinion]**.

**Where co-SNARKs sit [opinion]:** the only mechanism that simultaneously
gives exact computation, public verifiability with unmodified verifiers, and
production maturity — at the price of a small-committee trust assumption and
round-latency. Everything in §4 is scoped to that envelope.

---

## 2. TACEO's product offerings (researched 2026-07-26)

TACEO (TU Graz spin-out, Graz, Austria, founded 2022; ~20–22 people [S];
**$5.5M seed announced 2025-07-31**, led by Archetype with a16z CSX,
cyber•Fund, a_capital, Polymorphic Capital —
[core.taceo.io/articles/seed](https://core.taceo.io/articles/seed/) [V]) has
moved in four years from "open-source co-SNARK library" to a small product
*portfolio* around one thesis they brand exactly as our subject: **"Private
Shared State"** — tagline *"Collaborate Privately, Prove Publicly"*
([taceo.io](https://taceo.io/) [V];
[their PSS manifesto](https://core.taceo.io/articles/pss-taceo-network/) [V]
frames it as Szabo's 1999 "God Protocols" made real, citing the failed
Google–Mastercard ad-measurement deal and the Boston Wage Gap Study as the
canonical blocked-collaboration precedents).

### 2.1 The open-source layer: co-snarks (what this repo is)

The cryptographic core — co-circom (Groth16/Plonk) and co-noir (UltraHonk),
REP3 + 3-party Shamir, semi-honest honest-majority — is Apache/MIT
open source. Ch. 02 §5.4 already established what it deliberately lacks:
job orchestration, share-submission channels, node operations. That gap *is*
the commercial product:

### 2.2 TACEO:Proof — the hosted proof-delegation market

Production since **2025-07-23** ("the first production-grade private proof
market", after a beta from ~2025-04-30 that generated 1M+ proofs;
[core.taceo.io/articles/taceo-proof-prod](https://core.taceo.io/articles/taceo-proof-prod/) [V]).
Architecture ([docs.taceo.io TACEO:Proof overview](https://docs.taceo.io/docs/taceo-proof/overview/) [V]):

- A **Cryptographic Coordination Layer (CCL)** schedules jobs ("blueprints" +
  short-lived vouchers); clients secret-share the witness locally and submit
  **encrypted shares** — the layer we identified in ch. 02 §5.4 as missing
  from the open source.
- **Node providers** run dockerized "coSNARK Engines" peering over QUIC;
  **3 distinct operators are randomly selected per job** from a pool.
- Protocols: REP3 and 3-party Shamir, both semi-honest honest-majority; REP3
  is the only one with in-network witness extension (matches our repo's
  constraint, ch. 02 §4); their docs note REP3 compresses uploads ~3× vs
  Shamir ([best-practices doc](https://docs.taceo.io/docs/taceo-proof/dev/bestpractice/) [V]).
- Proof systems: Groth16/Circom was the original path; a **co-noir/UltraHonk
  quick-start is now live** (verified via `bb verify --scheme ultra_honk --zk`;
  [quick-start-co-noir](https://docs.taceo.io/docs/taceo-proof/dev/quick-start-co-noir/) [V]) —
  i.e. the exact stack this repo works on is now a hosted TACEO product path.
- Published performance (delegation vs local phone proving): sha256 2^16 —
  0.67 s network vs 1.69 s phone; rsa 2^18 — 1.83 s vs 6.0 s
  ([production-launch article](https://core.taceo.io/articles/taceo-proof-prod/) [V]).
  Note these are *small Groth16-class* jobs — consistent with our own finding
  that small-circuit REP3 proving is sub-second (poseidon 2^11: 0.40 s) while
  2^20 UltraHonk is ~100 s (§4.0).

**Pricing: NOT publicly discoverable.** No pricing page, tier list, or
per-proof cost exists anywhere findable; the business model is
enterprise/B2B "privacy infrastructure beneath customer apps" per CEO Lukas
Helminger ([Biometric Update interview, 2026-06](https://www.biometricupdate.com/202606/taceo-ceo-sees-market-for-distributed-biometrics-processing-coming-together) [V]).
One search summary asserted subscription tiers but no source page states it —
treat as unverified.

### 2.3 The TACEO Network + service portfolio (2026)

Public launch **2026-03-19**
([core.taceo.io/articles/taceo-network](https://core.taceo.io/articles/taceo-network/) [V];
[TNW coverage](https://thenextweb.com/news/taceo-network-launch-private-computation-world-id) [V]).
Named node operators: **Nethermind, P2P.org, InfStones, Stakecraft, Moonli,
H2O Nodes, ZKPassport, CTU Prague, TU Graz** [V] — note the pattern: staking
firms + universities, i.e. institutions whose *reputation* is the collateral
(directly relevant to §5.3). Services layered on the network
([pss-taceo-services](https://core.taceo.io/articles/pss-taceo-services/) [V]):

- **TACEO:OPRF** — oblivious-PRF nullifiers / private recognition.
  **Production**, powering World ID and zkPassport.
- **TACEO:OMap** — a private hashmap/ORAM for *persistent* encrypted shared
  state (onboarding phase). This is the "state" half of PSS — the piece
  co-snarks-the-library never had.
- **TACEO:Match** — private set intersection / identity matching
  (integration phase).
- **Merces** — confidential ERC-20-style transfers via MPC + coSNARKs,
  claiming >300 tx/s including proving
  ([eprint 2026/850](https://eprint.iacr.org/2026/850) [V]) — authored by
  Escudero/Walch/Rechberger et al.; TACEO's answer to confidential payments.
- **Confidential x402** — amount-hiding extension of the x402 agent-payments
  protocol (Poseidon2 commitments + 3-way shares;
  [protocol reference](https://docs.taceo.io/docs/finance-solutions/x402/protocol-reference/) [V]).

### 2.4 Customers and what they reveal

- **World / World ID**: TACEO's MPC stack is the production backbone of
  World's iris-uniqueness checking at **~14–18M verified users**
  ([TACEO Network article](https://core.taceo.io/articles/taceo-network/) [V];
  [Biometric Update](https://www.biometricupdate.com/202508/startup-behind-worlds-biometric-matching-software-raises-5-5m-in-seed-funding) [V]).
  World gave TACEO a community grant in 2024, pre-seed. This is, as far as I
  can find, **the largest production MPC-on-secret-shared-data deployment in
  existence** — and its shape is instructive: the shared state is a *biometric
  uniqueness set* that must be hidden from everyone including its operator,
  queried millions of times. Recurring infrastructure revenue, not per-proof
  retail.
- **zkPassport**: uses TACEO:OPRF in production *and* runs a network node [V].
- **Aztec**: formal partnership announced **2025-09-25** to bring Private
  Shared State to Ethereum via co-noir
  ([core.taceo.io/articles/taceo-aztec-pss-ethereum](https://core.taceo.io/articles/taceo-aztec-pss-ethereum/) [V];
  [crypto.news](https://crypto.news/taceo-and-aztec-to-bring-private-shared-state-to-ethereum/) [V]),
  plus an earlier Aztec Labs grant for Noir-ecosystem work [S]. So the
  strategic bet this chapter analyses — PSS-on-Aztec — is not hypothetical;
  it is an announced joint direction of both companies.
- Devcon7 (2024-11): NFC social-graph demo with Cursive/PSE — 15,266 Groth16
  co-proofs over 4 days, peak 40 proofs/min
  ([devcon-demo](https://core.taceo.io/articles/devcon-demo/) [V]) — evidence
  the delegation pipeline handles consumer-app burst load at small circuit
  sizes.
- Research direction to watch: their
  [multiparty zkTLS notary post](https://core.taceo.io/articles/mpc-zktls/) [V]
  (SPDZ-based, dishonest-majority malicious) and the CRYPTO 2025 result that
  honest-majority semi-honest MPC yields malicious-secure co-SNARKs
  essentially for free for several schemes
  ([eprint 2025/1026](https://eprint.iacr.org/2025/1026) [V]) — the latter
  matters for us: it suggests the semi-honest REP3 stack we run may be closer
  to malicious security than its label implies (soundness was already free;
  this is about privacy against active adversaries). Not yet reflected in
  the co-snarks code.

**Business-model reading [opinion]:** TACEO is not selling proofs retail;
it is selling *managed private-computation infrastructure* with two revenue
shapes — (1) World-style bespoke enterprise deployments (identity/biometrics,
where they have the flagship), and (2) the network/services platform where
node operators are partners and TACEO takes the coordination layer. Nothing
public indicates per-proof pricing or self-serve revenue. For an Aztec-app
deployer, the takeaway is that TACEO's commercial focus is the
*infrastructure layer* — the application layer on top (everything in §4) is
open territory.

---

## 3. The rest of the landscape (researched 2026-07-26)

Ordered by mechanism. The point of this section is not a directory — it is to
read **demand signals**: who is paying for private shared state today, with
what mechanism, and what the traction (or lack of it) tells us about §4.

### 3.1 MPC networks

**Arcium** (ex-Elusiv, Solana) — "confidential supercomputer": MPC "MXEs"
(Multi-party eXecution Environments) with per-app choice of node cluster and
computation. **Mainnet Alpha 2026-02-02**
([The Block](https://www.theblock.co/post/387564) [V]). Own funding is modest
(~$9–14M total across seed + strategic [S];
[$5.5M strategic 2025-05 led by Greenfield](https://www.theblock.co/post/387564) [V]);
$ARX TGE 2026-06-22 [S]. The revealing datum: its first app, **Umbra**
(shielded swaps/transfers), raised **~$155M in ICO commitments via MetaDAO
(2025-10)** [V, The Block] — an order of magnitude more than the
infrastructure itself. Its early ecosystem is dark pools, sealed-bid auction
markets, private trading (Dark Pool, Melee, Vanish, Bench, Crafts [S]).
**Signal: speculative capital believes the *application* layer (private
trading) is where the value is, and the app mix on an MPC chain converges on
exactly the §4 short-list [opinion].**

**Nillion** — "blind computation" via a blend of MPC/HE/TEE modules (nilDB,
nilVM, nilAI). ~$50M raised (incl.
[$25M Series A 2024-10 led by Hack VC](https://www.crunchbase.com/organization/nillion) [S]);
"Alpha Mainnet" 2025-03-24
([own announcement](https://nillion.com/news/nillion-alpha-mainnet-is-live) [V] —
notably free of any usage metrics). NIL market cap had fallen to ~$18M by
2026-07 [S], and in 2026 Nillion announced a pivot from its own Cosmos chain
to an **Ethereum L2**
([own post](https://nillion.com/news/the-next-frontier-for-nillion-ethereum) [V]).
**Signal: a generalized "private compute network" without a flagship
application has struggled to find demand; TACEO's contrasting approach
(one marquee customer — World — then generalize) worked better [opinion].**

**Partisia Blockchain** — L1 with MPC as a native primitive, from the
Danish/Aarhus MPC lineage (the team's pedigree traces to real-world MPC
auctions for spectrum/electricity — the 2008 Danish sugar-beet auction line;
the "Danish veterans" framing is plausible but was not re-verified this
session [S]). Traction signal: a partnership with **Tora (LSEG group)**,
which handles >$3B/day of institutional trading, to build MPC software [S] —
production status unconfirmed. Funding figures unreconciled ($20M–$54M across
aggregators [S]); token trades sub-cent; no material TVL found. **Signal:
even 20 years of MPC pedigree doesn't bootstrap a horizontal MPC chain;
distribution beats mechanism [opinion].**

**Renegade** (renegade.fi) — the single most important comparable for §4:
a live, non-custodial **on-chain dark pool** where orders match at the
Binance midpoint and *neither pre- nor post-trade order data is revealed* —
counterparty relayers run **pairwise 2-party MPC** to find crosses, then
produce a **collaborative SNARK** ("VALID MATCH MPC") so neither side ever
sees the other's book; i.e. a production deployment of the exact
Ozdemir–Boneh line this repo implements (their own
[`mpc-bulletproof`](https://github.com/renegade-fi/mpc-bulletproof) library [S]).
Mainnet on Arbitrum **2024-09-03** (built on Stylus to reuse their Rust
crypto stack; settlement ~$0.30;
[Arbitrum case study](https://blog.arbitrum.io/renegade-stylus-case-study/) [V]),
now also on Base ([renegade.fi](https://renegade.fi/) [V]). Funding: $3.4M
seed led by Dragonfly, angels incl. Balaji Srinivasan, Tarun Chitra
([jamesbachini.com writeup](https://jamesbachini.com/renegade/) [V]);
aggregators claim $21.3M total [S]. **Fee model: 2 bps in-protocol + ~2 bps
relayer fee [S].** Volume: ~$336M all-time / claims of "$100M daily order
flow" are search-snippet-only, no independent dashboard found — treat as
unverified [S]. **Signals: (1) co-SNARK dark pools are shippable and audited
(zkSecurity); (2) the take-rate is bps-of-volume; (3) after ~2 years the
verifiable traction is modest — a dark pool without a distribution edge
still fights the liquidity cold-start [opinion].**

### 3.2 FHE

**Zama** — TFHE libraries + fhEVM co-processors + the Zama Protocol.
The best-funded player in the whole space: **>$150M raised, >$1B valuation
(first "FHE unicorn", Series B 2025-06-25 led by Pantera)**
([tech.eu](https://tech.eu/2025/06/25/zama-hits-unicorn-status-with-57m-series-b-for-encryption-tech/) [V]).
Testnet metrics (2025-11): 1.2M+ encrypted txs, 19k confidential contracts,
120k wallets; threshold key held by **13 MPC operators** incl. Ledger,
Fireblocks, OpenZeppelin, Figment
([own update](https://www.zama.org/post/zama-protocol-testnet-update-mpc-partners-better-performance-audits-and-new-features) [V]).
Ethereum **mainnet 2025-12-30**, first confidential-stablecoin (cUSDT)
transfer [S]. Business model worth studying: **dual licensing** (BSD
non-commercial + paid commercial/patent license), with "$50M+ signed contract
value within six months of commercialization" claimed in 2024 [S].
**Signals: (1) serious institutional money believes confidential *payments/
stablecoins* on public rails is a product; (2) even the FHE flagship rests on
an MPC committee for decryption — the trust assumption converges with ours;
(3) infra-layer licensing can produce real revenue pre-mainnet [opinion].**

**Fhenix** — pivoted from "FHE L2" to CoFHE, an FHE co-processor callable
from any EVM chain; $22M raised
([Series A 2024-06 led by Hack VC](https://www.theblock.co/post/300880/fhenix-raises-15-million-series-a-hack-vc) [S]);
still testnet-only as of mid-2026 (one conflicting "live on Base" snippet,
unresolved [S]); self-reported 128 apps / 56k encrypted txs
([fhenix.io/ecosystem](https://www.fhenix.io/ecosystem) [V]). ~3 years from
seed without mainnet. **Signal: FHE-chain economics are hard below
Zama-scale funding [opinion].**

**Inco** — Lightning (TEE-based, live on Ethereum/Base) now, Atlas (FHE+MPC)
later; ~$10M total incl.
[$5M strategic 2025-04 led by a16z CSX + Coinbase Ventures](https://www.inco.org/blog/inco-raises-5m-to-accelerate-development-of-confidentiality-layer-for-blockchains) [V].
No public usage numbers. Notable: even the "FHE company" ships **TEEs first**
for latency reasons. **Signal: latency pressure is real enough that vendors
compromise on trust model to meet it — the §5 latency ceiling is
commercially binding [opinion].**

### 3.3 TEE chains (the cautionary tail)

**Secret Network** — the longest-running private-contract chain (Enigma
mainnet 2020-02; SGX). Battle scars: the 2022 xAPIC/AEPIC leak exposed the
network's master decryption seed (retroactive-decryption risk for the whole
chain history; well corroborated across
[aepicleak.com](https://aepicleak.com/) and security press [S]); the 2025
**TEE.fail** DDR5-bus attack (<$1,000 hardware, breaks SGX/TDX/SEV-SNP)
forced permissioned-validator mode
([Secret Labs response](https://scrt.network/blog/secret-labs-response-to-tee-fail-ddr5-vulnerability) [V]);
a $4.67M IBC bridge exploit 2026-06
([The Block](https://www.theblock.co/post/405459) [V]); TVL in the low
single-digit $M [S]; and a 2026 proposal to abandon Cosmos for Arbitrum with
"SGX decoupling" on the roadmap [V/S]. **Signal: six years of TEE-chain
operation ended in permissioned mode and a partial retreat from the
mechanism. For adversarial, high-value shared state, hardware roots of trust
keep failing — this is the strongest argument that the MPC/co-SNARK cost is
worth paying [opinion].**

**Oasis Sapphire** — confidential EVM in SGX, mainnet since ~2023, ~$45M
raised in 2018 ([a16z-led pre-sale](https://www.ccn.com/oasis-labs-45-million/) [S]);
TVL reported around $0.3M [S] despite 3+ years live. **Signal: "confidential
EVM" as a horizontal platform, without a killer app, has near-zero organic
pull. Mechanism maturity does not create demand; applications do
[opinion].**

**Flashbots SUAVE → BuilderNet** — Flashbots raised **$60M at >$1B
valuation (2023, Paradigm)** for SUAVE, a decentralized private-mempool/
block-building chain [S, well corroborated]. SUAVE never shipped as a chain;
the shipped descendant is **BuilderNet** (2024-11), TEE-based decentralized
block building
([buildernet.org](https://buildernet.org/blog/introducing-buildernet) [S]).
**Signal: a unicorn valuation was paid for the *thesis* that private shared
orderflow is core Ethereum infrastructure — and even Flashbots retreated to
TEEs to hit block-time latency. co-SNARKs can't play at 12 s block cadence;
they can play at auction/batch cadence [opinion].**

### 3.4 Threshold crypto, ZK L1s, and the adjacent proven businesses

**Penumbra** — the cautionary tale. Cosmos shielded L1 with a private DEX:
sealed **batch swaps** where the batch totals are decrypted by a validator
**threshold committee** each block — architecturally the closest existing
thing to "private shared state via threshold decryption." Superb
engineering; shielded TVL only **~$3.8M** [S], and **Penumbra Labs wound
down ~2025-09** (the project's own X account, 2026-01: "Penumbra Labs shut
down over four months ago. No foundation runway." [S]). **Signal: the purest
warning in the whole landscape — mechanism-first, distribution-later fails
even with world-class cryptography. Any §4 proposal must name its first
hundred users [opinion].**

**Aleo** — private L1 (per-user ZK state, not shared state), **$298M
raised** at $1.45B (a16z/SoftBank/Samsung [S]), mainnet 2024-09-18; ~30 live
apps of 350+ built, private-contract TVL ~$12.4M, Q1-2025 fee revenue down
84% QoQ ([Messari State of Aleo](https://messari.io/report/state-of-aleo-q2-2025) [S]).
**Signal: even *personal* private state as a horizontal chain has not found
product-market fit yet; the demand is app-shaped, not chain-shaped
[opinion].**

**Lit Protocol** — threshold key network (PKPs, threshold signing/
decryption). Naga mainnet DKG 2025-12-17 with **7 node operators**,
migrating ~$500M in managed assets / 2M accounts [S]; only ~$15–18M
disclosed funding [S]; usage-based fee model in LITKEY. **Signal: threshold
*key custody as a service* has real usage at small budgets — it's the
adjacent business, not the same business (keys, not computed state)
[opinion].**

**MPC custody (the adjacent proven category).** **Fireblocks**: $8B
valuation (Jan 2022), ~$100M ARR by 2022, reported $124M revenue 2024 /
$152M 2025 [S via [Sacra profile](https://sacra.com/c/fireblocks/) [V] +
aggregators]. **Zengo**: 1.5M+ consumer users, $19.99/mo subscription [S].
**Coinbase** open-sourced its institutional MPC library 2025-03 [S].
These firms prove enterprises pay nine figures/year for MPC when it protects
*keys*. The unproven step — and the whole opportunity of this chapter — is
MPC that custodies *application state and computes on it*. Fireblocks is the
existence proof that the operational model (run MPC nodes commercially, sell
trust) supports a real company **[opinion]**.

**Fairblock** — threshold identity-based encryption for "encrypt until
condition" (sealed bids, confidential swaps), $2.5–7.5M raised [S,
unreconciled], pitching sealed-bid auctions on Arbitrum
([Arbitrum blog](https://blog.arbitrum.io/how-fairblock-is-unlocking-confidential-payments-and-auctions-on-arbitrum/) [S]);
no production usage found. Direct future competitor for §4's auction thesis,
with a cheaper mechanism that only does *timed reveal* (it cannot compute a
winner without decrypting all bids — a co-SNARK can reveal *only the
winner*) **[opinion]**.

### 3.5 The two strongest non-crypto demand proofs

**BWWC / Boston University wage-gap study** — verified end-to-end
([thebwwc.org/mpc](https://thebwwc.org/mpc) [V];
[BU coverage](https://www.bu.edu/hic/2023/12/19/boston-womens-workforce-council-finds-30-percent-decline-gender-wage-gap) [V]):
Boston-area employers submit encrypted payroll data; BU's Hariri Institute
runs MPC so the Council only ever sees aggregates; biennial production runs
since ~2016; the Dec-2023 report measured the gender wage gap falling 30¢ →
21¢ per dollar. **The longest-running, plainly successful real-world private
shared state deployment anywhere** — and note what it isn't: not a
blockchain, not real-time, not high-frequency. Annual-cadence aggregate
statistics over consortium data is MPC's proven home turf.

**Duality Technologies** — enterprise privacy-preserving data collaboration
(HE-based): $49M raised incl. $30M Series B (LG, Intel Capital;
[SecurityWeek](https://www.securityweek.com/secure-data-collaboration-firm-duality-technologies-raises-30-million/) [S]),
customers incl. Scotiabank inter-bank financial-crime data sharing and
national-security deployments [S]. **Signal: regulated institutions already
pay for cross-institution computation on data they won't share — the §4
credit-consortium thesis has a funded, revenue-generating off-chain
analogue [opinion].**

And the sharpest *counter*-signal: **Pave**, the market leader in
compensation-data pooling ($46M Series B at $400M post-money,
[BusinessWire](https://www.businesswire.com/news/home/20210810005300/en/Pave-Secures-Series-B-Valued-at-%24400M-and-Releases-Free-Real-Time-Compensation-Benchmarking) [V];
900+ customers [S]) uses **no cryptography at all** for the pooled payroll
data — SOC 2, contracts, and trust in a neutral SaaS vendor were enough to
build the business [S]. **Lesson: "this could use MPC" ≠ "customers need
MPC." PSS wins only where a trusted intermediary is unacceptable,
non-existent, or is itself the product being disintermediated [opinion].**

### 3.6 Summary table

| Project | Mechanism | Status (mid-2026) | Money in | Verifiable traction | One-line lesson |
|---|---|---|---|---|---|
| TACEO | MPC + co-SNARK | Network live 2026-03 | $5.5M seed | World ID @ ~15M users | Flagship customer first, platform second |
| Renegade | 2PC + co-SNARK | Mainnet 2024-09 | $3.4M+ | volume claims unverified | co-SNARK dark pools shippable; liquidity is the hard part |
| Arcium | MPC (MXEs) | Mainnet alpha 2026-02 | ~$10M (+Umbra ICO $155M) | early | App layer (private trading) attracts the capital |
| Zama | FHE + MPC-threshold | Ethereum mainnet 2025-12 | >$150M @ >$1B | 1.2M testnet txs | Confidential payments thesis is heavily funded |
| Nillion | MPC/HE/TEE blend | alpha, pivoting to ETH L2 | ~$50M | thin | Horizontal "blind compute" lacks pull |
| Secret | TEE (SGX) | permissioned after TEE.fail | — | TVL ~$1–7M | TEEs keep breaking |
| Oasis Sapphire | TEE | mainnet 3+ yrs | ~$48M | TVL ~$0.3M | Confidential EVM ≠ demand |
| Penumbra | threshold decryption | chain lives, company dead | — | TVL ~$4M | Mechanism-first fails |
| Aleo | ZK (personal state) | mainnet 2024-09 | $298M | TVL ~$12M | Even personal privacy is app-shaped |
| Fireblocks | MPC (custody) | — | ~$1B raised, $8B val | ~$150M rev/yr | MPC *operations* businesses are real |
| BWWC/BU | MPC (consortium stats) | running since 2016 | grant-scale | policy-grade output | MPC's proven home: batch consortium aggregates |
| Aztec | ZK L2 (+PSS via co-SNARK, this work) | Ignition mainnet 2025-11 (consensus); Alpha V5 exec layer 2026-07 | >$119M | first apps (Nyx, Dark Forest Aztec) [S] | The venue this chapter builds for |

*(Aztec status per [The Block on the $61M CCA token sale](https://www.theblock.co/post/381618/aztec-network-raises-over-60-million-in-eth-with-community-first-token-sale-testing-new-auction-model) [S],
[road-to-mainnet](https://aztec.network/blog/road-to-mainnet) [V], and search-level
reporting of the 2026-07-21 Alpha V5 governance activation [S]. Mike will know
the internal truth better than the press does.)*

---

## 4. What to build on Aztec — use cases and business viability

This section assumes the exact capability this repo provides: **3-party REP3
semi-honest co-proving of arbitrary Noir circuits**, byte-compatible with bb
UltraHonk, verified in-circuit on Aztec via `verify_proof_with_type` (the
monty-hall pattern, ch. 04), with the PXE secret-sharer of ch. 09 as the
user→MPC on-ramp.

### 4.0 The performance envelope (our measured numbers, not vendor claims)

From the v2 bench run (2026-07-25, loopback, per-party medians,
`bench-results/bench.sqlite` + README):

| Circuit (dyadic size) | witext | prove (zk) | REP3÷bb (zk, e2e) |
|---|---|---|---|
| poseidon 2^11 | 0.13 s | 0.46 s | 3.1× |
| poseidon 2^17 | 1.5 s | 12.1 s | ~13× |
| poseidon 2^18 | 3.1 s | 24.3 s | ~13× |
| poseidon 2^19 | 6.2 s | 48.8 s | ~13× |
| poseidon 2^20 | 15.0 s | 101 s | ~13× |
| sha256-compression (2^16) | 0.12 s | 140.6 s | 473× |
| recursion_zk (2^20) | 0.12 s | 94.8 s | ~30× |

Plus the WAN structure (ch. 24): the **prove** phase is round-shallow
(~311–385 logical rounds for poseidon-class; at 50 ms RTT that adds
~15–20 s), but **witness extension of sequentially-deep circuits is
round-deep** — poseidon hash-chains measure witext R ≈ 33k (2^17) → 270k
(2^20), a ~10-hour WAN floor at 140 ms one-way. Memory: ~20 GB/party at
2^20. Verification: ~20 ms, indistinguishable from bb.

Design rules this imposes on every use case below **[opinion, from measured
facts]**:

1. **Batch/event cadence, not per-interaction cadence** — anything needing a
   fresh 2^17+ proof inside a few seconds is out. Sub-second is available
   only at 2^11–2^13-class circuits.
2. **Poseidon-native circuits only** — bit-twiddling hashers (sha/keccak)
   inside the MPC circuit cost 1–3 orders of magnitude; keep them outside
   the shared-state transition.
3. **Shallow witness dependency chains** — the state-transition circuit
   should be wide (many independent items: bids, orders, records), not deep
   (long sequential hash chains). Happily, "process N parties' secret
   inputs" is naturally wide.
4. **Co-locate or regionally cluster the 3 MPC nodes** — WAN geography is a
   real cost; "3 nodes in 3 clouds in one metro" is a defensible privacy
   posture at 10× less latency than 3 continents (§5.3).

### 4.1 Ranking criteria (stated up front, so the ranking is checkable)

1. **Revenue quality** — take-rate on recurring flow > per-event fees >
   SaaS > grants. A viable business needs the fee to attach to value that
   *recurs*.
2. **PSS-necessity** — the §1.1 discriminator. If a trusted intermediary or
   plain Aztec notes can deliver 90% of the product, they will, cheaper
   (the Pave lesson, §3.5).
3. **Latency fit** — does the natural cadence of the app tolerate
   tens-of-seconds-to-minutes state transitions?
4. **Circuit fit** — poseidon-class arithmetic (comparisons, sorting,
   commitments) vs sha-heavy.
5. **Cold-start severity** — two-sided liquidity marketplaces are brutal
   (Renegade, Penumbra); event-driven or consortium apps less so.
6. **Regulatory exposure** — securities/gambling/credit rules can kill the
   deployer regardless of cryptography.
7. **Operator-trust story** — can you name 3 node operators whose
   non-collusion a counterparty with $10M at stake would accept, and who
   gets paid what to run them (§5.3)?
8. **Moat** — code is forkable; *liquidity, data consortia, and regulatory
   licenses* are not.

### 4.2 The catalogue

Each entry: what it is → why it *needs* PSS → why blockchain/Aztec → the
deployer's business → honest viability. All viability judgments are
**[opinion]** grounded in the §2–3 signals.

#### U1. Sealed-bid auction house (one-shot, high-value events)

**What.** A venue for genuinely sealed bids: token launches / IDOs, NFT and
RWA sales, liquidation auctions for lending protocols, validator/orderflow
rights, treasury buybacks. Bidders secret-share bids to the MPC committee
(via the ch. 09 channel); at close, one co-SNARK proves "the winner and
clearing price are correct w.r.t. all committed bids" — **revealing only the
winner and price, never the losing bids**, before or after.

**Why PSS.** The auction function takes *every bidder's secret* as input —
per-user privacy can hide a bid *before* close but someone must compute over
all of them at close. Commit-reveal leaks all bids afterwards (bid-shading
and strategy leakage return); threshold-decrypt (Fairblock/Shutter) reveals
all bids to everyone at close. Only compute-under-MPC reveals *nothing but
the outcome*. This is the textbook second-price-auction honesty problem: a
Vickrey auction is strategy-proof only if losing bids stay secret —
otherwise the auctioneer/observers exploit them next round.

**Why Aztec.** Settlement and custody: bids escrowed in Aztec private
notes; the winning transfer settles atomically against the proof;
losing bidders' *participation* is also hidden (an Aztec-private deposit),
which no L1 sealed-bid design achieves. And credibility: the deployer
provably *cannot* peek (they'd have to corrupt 2 of 3 named operators),
whereas every off-chain auction house asks you to trust it.

**Business.** Fee = 0.5–2% of clearing value (auction houses charge far
more: Christie's buyer's premium ~20%+; crypto launchpads 2–5%). Recurs
per event; no persistent liquidity needed — each auction brings its own
demand (criterion 5, the marketplace cold-start, largely dissolves). The
deployer curates events, runs the
orchestrator, pays the 3 node operators from fees.

**Viability: strong.** Demand evidence: Aztec's own token sale used a novel
Uniswap-v4 continuous clearing auction and raised ~$61M from 16.7k
participants [S, The Block §3.6] — sophisticated auction mechanisms already
attract 8-figure events, and that one was fully public (bid strategies were
visible on-chain). MEV data shows private orderflow — 12% of transactions —
carries **54.6% of block value**
([builder-market study](https://www.emergentmind.com/topics/mev-builders) [S]):
order *information* is the most valuable commodity on-chain. Liquidation
auctions alone recur daily across DeFi. Latency fit is perfect: an auction
closes on a schedule; 30–120 s of proving is invisible. Circuit fit is
perfect: sort/compare N bids + Poseidon commitments, wide not deep — a
1k-bid Vickrey circuit is plausibly 2^15–2^17 (**needs a prototype**, cf.
ch. 24 methodology). Competition: Fairblock (weaker mechanism — reveals all
bids), Arcium ecosystem's "Crafts" [S]. Regulatory: moderate (depends what's
auctioned; RWA auctions drag in securities law).

#### U2. Aztec dark pool / periodic crossing network

**What.** Renegade's mechanism, rebuilt on Aztec with 3-party co-SNARKs:
traders deposit into private notes, submit secret-shared orders; every T
seconds/minutes the MPC crosses the book at an external midpoint (oracle
price) and proves the crossing correct; only net settlements surface.
Pre-trade *and* post-trade privacy; no order-book leakage, no MEV.

**Why PSS.** Matching is a function of *both sides'* secret orders. A
private-notes-only DEX (per-user privacy) still needs a matcher who sees
orders — that matcher is today's centralized dark pool operator, i.e. the
thing being disintermediated. Renegade proved the mechanism [§3.1]; note
their 2-party pairwise design leaks "a match happened between us" to the
counterparty relayer — a 3-party neutral-committee design (ours) can hide
even match occurrence from traders **[opinion]**.

**Why Aztec.** The deposits, the settlement, and the *identity privacy* all
live natively in Aztec's shielded model — a dark pool on a transparent
chain (Renegade on Arbitrum) still leaks deposit/withdrawal linkage at the
edges. Aztec is the only venue where the pool's *perimeter* is also private.

**Business.** bps on matched volume (Renegade: 2+2 bps). $1B/month matched
at 4 bps = $400k/month. The demand pool is objectively enormous: crypto OTC
volumes grew **109% YoY in 2025** with 40% of institutions preferring
off-exchange execution ([Finery Markets](https://finerymarkets.com/blog/crypto-otc-report-2025-results-trends) [S]);
in US equities, off-exchange execution crossed **50% of volume for the
first time in Dec 2024** (~14–18% in ATS dark pools proper) [S, §3-agent
research with year-caveats noted]; dark liquidity is the *end state* of
mature markets, not a niche.

**Viability: strong thesis, hard execution.** The two honest problems:
(1) **liquidity cold-start** — Renegade, with the first-mover story and
Dragonfly backing, still shows only unverified ~$336M lifetime volume [S];
Penumbra died of this [§3.4]. A deployer needs anchor market-makers
committed *before* launch (the Renegade "relayer" model — MMs run
infrastructure — is one answer; an RFQ-style quote obligation is another).
(2) **Latency**: a 1–5 min batch cross at 2^17–2^18 (12–24 s prove) is
comfortable; continuous limit-order matching is not (§5.1). Batch crossing
also *concentrates* liquidity (CoW-style uniform clearing price
[docs.cow.fi](https://docs.cow.fi/cow-protocol/concepts/introduction/fair-combinatorial-auction) [S])
— the constraint is arguably a feature for block-size trades. Regulatory:
significant and rising with success (operating a matching venue).

#### U3. Private credit-data consortium + undercollateralised lending

**What.** N lenders (on-chain protocols, CeFi desks, eventually banks) pool
borrower repayment/default histories as secret-shared records held by the
MPC committee — a **credit bureau nobody owns**. Products: (a) co-SNARK
credit scores usable in Aztec lending contracts ("score ≥ θ" proven, score
hidden); (b) duplicate-borrower / aggregate-exposure checks across lenders
("this borrower has open loans elsewhere" without any lender revealing its
book).

**Why PSS.** The score is a function over *many lenders' confidential
books*; each lender's loan tape is competitively sensitive (it IS their
alpha) and legally encumbered. A trusted aggregator is exactly the thing
lenders don't want to feed (it becomes a competitor/honeypot — the reason
on-chain lending has no bureau today). BWWC proves consortium-MPC-statistics
works in production [§3.5, V]; Duality proves banks pay for it [§3.5].

**Why Aztec.** The *output* must be consumable by on-chain lending logic:
an undercollateralised loan contract needs the score attestation verified
in-circuit at draw time — that's `verify_proof_with_type` inside a private
function, with the borrower's identity kept private (Aztec) and the score
computed over data nobody holds (co-SNARK). 3Jane's Paradigm-led $5.2M seed
and ~$50M launch caps
([cmointern](https://www.cmointern.com/2025/06/3jane-protocol-raises-52m-led-by.html) [S])
show investor + borrower appetite for on-chain unsecured credit — but 3Jane
scores from *the borrower's own* zkTLS-attested data; it has no
cross-lender view. Cross-lender data is precisely what makes TradFi bureaus
(Experian/Equifax/TransUnion — a combined ~$15B+/yr revenue oligopoly)
valuable **[opinion; bureau revenue figure is common knowledge, not
re-verified this session]**.

**Business.** Per-query fees (bureaus charge per pull) + per-loan bps.
**The moat is the consortium itself** — data network effects compound and
are unforkable (criterion 8's best case). Cold-start is the classic
consortium chicken-and-egg: needs ~5 anchor lenders; DAO-adjacent CeFi
desks burned by 2022 contagion (which was an *information* failure —
nobody could see aggregate exposure) are the wedge.

**Viability: the best long-term moat on this list, the slowest to close.**
Sales cycle is quarters-to-years; regulatory surface (FCRA-like regimes if
consumer data ever enters) is real; latency is irrelevant (scores refresh
daily/hourly — batch MPC's home turf, cf. BWWC). This is a company, not a
weekend protocol.

#### U4. Hidden-information games with real stakes — poker first

**What.** Texas hold'em where the MPC committee *is* the dealer: the deck
is a secret-shared permutation; hole cards are dealt as private notes to
each player's PXE; each street's reveal + showdown is a co-SNARK-proven
state transition. No house to trust for shuffle fairness; pots settle in
Aztec notes.

**Why PSS.** The deck is the canonical shared secret: state that must be
hidden from *every* player yet updated per action. Mental-poker protocols
exist (zkHoldem/zkShuffle on Manta et al.,
[zkholdem.xyz](https://zkholdem.xyz/) [S]) but player-run shuffles degrade
UX and break on dropout; an MPC dealer committee is operationally clean and
matches the monty-hall pattern exactly (ch. 04 — monty-hall *is* a toy
hidden-information game; this is its grown-up sibling).

**Why Aztec.** Stakes custody in private notes (players' bankrolls and bet
sizes hidden — a real product feature: table image and bankroll stalking
are known leaks in online poker), plus credibly-neutral settlement.

**Business.** Rake, the most proven willingness-to-pay in consumer
software: online poker is a **$3–6B/yr market growing to ~$11B by 2030**
([ResearchAndMarkets](https://www.businesswire.com/news/home/20250602812357/en/Online-Poker-Global-Strategic-Business-Report-2025-Market-to-Reach-%2411.4-Billion-by-2030---Emergence-of-Cross-Platform-Play-and-Global-Tournaments-Spurs-Adoption---ResearchAndMarkets.com) [S]).
Crypto poker sites already thrive offshore with *zero* fairness guarantees;
"provably fair, house-can't-see-your-cards" is a genuine differentiator.

**Viability: big market, perfect circuit fit, terrible regulatory
position.** Per-action circuits are small (deal/reveal ≈ permutation checks
+ Poseidon, 2^11–2^13-class → **sub-second REP3 proving measured at 2^11,
plausibly low-single-second through 2^13** — poker's 5–15 s action cadence
fits; the actual deal/reveal circuit still needs prototyping). The killers: (1) gambling licensing —
the deployer needs offshore structure, which conflicts with recruiting
reputable MPC operators (§5.3); (2) **MPC does not solve player collusion**
(two colluding *players* sharing hole cards out-of-band — the actual #1
integrity problem in online poker) and anonymity makes collusion-detection
*harder*; be honest that PSS fixes the house-trust problem, not the
player-trust problem. A licensed operator adopting this as
infrastructure — rather than a crypto team going direct — is the realistic
path **[opinion]**.

#### U5. Private uniqueness / eligibility attestation (the World ID pattern, generalized)

**What.** A shared hidden *set* (registered biometrics, KYC'd identities,
sanctioned addresses, prior claimants) held as secret shares; the product
is membership/non-membership/uniqueness proofs against it: airdrop
sybil-resistance, one-account-per-human for apps, "not on the sanctions
list" attestations for private DeFi pools, KYC-dedup across institutions.

**Why PSS.** The set itself is the honeypot (biometric templates, KYC
files, watchlists) — no single operator may hold it, yet every query
computes over *all* of it. This is TACEO's actual production business:
World ID uniqueness at ~15M users [§2.4, V] — **the one PSS use case with
proven, at-scale, paying deployment**, and Helminger's cited comp (Prove
serving 9 of the top-10 US banks) shows the identity-infrastructure market
pays real money
([Biometric Update](https://www.biometricupdate.com/202606/taceo-ceo-sees-market-for-distributed-biometrics-processing-coming-together) [V]).

**Why Aztec.** Aztec private functions can *consume* the attestation
without deanonymizing the user — "prove to this private pool that I'm
unique/eligible" composes with private balances in a way no transparent
chain offers. Compliance-gated private DeFi (institutions need "provably
clean counterparties" before touching shielded pools) is plausibly *the*
unlock for institutional Aztec usage **[opinion]**.

**Business.** Per-verification fees / infrastructure contracts
(TACEO-style B2B). Viability: proven demand, but **TACEO themselves own
this lane** — they have the flagship customer, the OPRF service, and the
Aztec partnership. An app deployer's play is the *Aztec-side integration*
(compliance-gated pools, private airdrop tooling), not competing on the
MPC infrastructure **[opinion]**.

#### U6. Auditable-but-private reserves & solvency

**What.** A stablecoin issuer / exchange / RWA fund proves "assets ≥
liabilities" where *liabilities* are summed over a hidden user-balance set
and *assets* over accounts the issuer won't enumerate publicly (front-running
its portfolio) — with per-institution inputs supplied by multiple parties
(custodians, banks) as shares. Continuous, machine-checkable solvency
without disclosure.

**Why PSS / why Aztec.** Sum-over-many-parties'-secrets is PSS by
definition when custodians won't show each other their books. Chainlink
PoR's regulator pilots (Bermuda Monetary Authority,
[CoinDesk](https://www.coindesk.com/policy/2025/11/05/chainlink-apex-group-test-onchain-stablecoin-compliance-with-bermuda-regulator) [S])
show the attestation market is forming — but PoR publishes *plaintext
reserves*; the private version (prove the inequality, hide the composition)
is the version institutions actually want **[opinion]**. Circuit fit:
summation + range checks = poseidon-class, batch cadence (hourly) — ideal.
Viability: **good product, likely a feature not a company** — the buyer
(issuer) captures the value, so it's sold as B2B tooling/service; recurring
but small-N customers. Moderate ranking.

#### U7. Private DAO governance / voting

Demand is *proven* — Snapshot×Shutter shielded voting live since 2022
([Shutter blog](https://blog.shutter.network/shutter-brings-shielded-voting-to-snapshot/) [V]),
MACI used in Gitcoin GG24's privacy round (Oct–Nov 2025,
[gitcoin.co case study](https://gitcoin.co/case-studies/gg24-first-funding-round-of-gitcoin-3-0) [S]) —
and co-SNARK voting is strictly stronger (individual votes *never* decrypt;
tally proven; collusion-resistance à la MACI without MACI's trusted
coordinator — the MPC committee *is* a decentralized coordinator).
**But willingness-to-pay is ~zero**: both incumbents are free public goods;
DAOs treat voting as cost center. Build it as an ecosystem credibility
play / grant-funded public good, not a business **[opinion]**.

#### U8. Dark-forest-style games & autonomous worlds

Hidden world-state (fog of war) that no player *or server* can see is
artistically exactly PSS, and Aztec already has a "Dark Forest Aztec" app
in its Alpha V5 first wave [S, §3.6]; the original Dark Forest sustains an
active modding community but zero revenue
([blog.zkga.me](https://blog.zkga.me/df-22-summer-break) [V-adjacent]).
ZK-only Dark Forest hides *your* state from others; MPC adds
*nobody-knows* state (neutral NPCs, hidden treasure, sealed map regions) —
a genuine design-space expansion. Viability as a business: poor
(crypto-native games monetize erratically); value as **ecosystem showcase
and stress-test: high** — it exercises exactly the monty-hall machinery at
scale **[opinion]**.

#### U9. The rest, briefly

- **Private RFQ networks** — quotes as shared secrets, best-quote-wins
  proven without losers' quotes leaking (quote-fading data is MM alpha).
  Hashflow's $11B cumulative RFQ volume [S,
  [Bitget summary](https://www.bitget.com/academy/what-is-hashflow-hft-price-analysis)]
  proves the venue model; private quotes are an increment, not a category —
  fold into U2's product surface **[opinion]**.
- **Salary/comp benchmarking consortium** — BWWC proves feasibility;
  Pave proves the market pays; Pave *also* proves they'll accept a SaaS
  vendor without cryptography [§3.5]. And there is no on-chain settlement
  leg → no reason for Aztec. Off-chain MPC consultancy work, not an Aztec
  app **[opinion]**.
- **Healthcare/genomic data markets** — the graveyard: LunaDNA shut down
  2024 ([GenomeWeb](https://www.genomeweb.com/informatics/blockchain-genomics-firm-lunadna-shut-down) [S]);
  Nebula Genomics discontinued its DTC service 2025-02 [S]. Consumer
  data-marketplace economics failed *before* privacy tech entered the
  picture. Institutional consortium analytics (Duality's lane) is real but
  is enterprise sales with no chain leg. Avoid **[opinion]**.
- **Threshold custody + policy engines** — Fireblocks/Lit own it; it's
  keys-not-state; don't compete on an adjacent's home turf **[opinion]**.

### 4.3 The ranking — what I'd bet on

**[opinion, all of it]** Scoring the catalogue against §4.1:

| Rank | Use case | Why it wins | What kills it |
|---|---|---|---|
| **1** | **U1 sealed-bid auctions** | Event cadence = perfect latency fit; per-event fees on 7–8-figure clearing values; no liquidity cold-start; poseidon-class circuits; auctions are *provably* better sealed (mechanism-design argument sells itself) | If threshold-reveal (Fairblock-style, all-bids-public-at-close) turns out "good enough" for most events, the premium for reveal-nothing shrinks |
| **2** | **U2 dark pool / batch crossing** | Largest addressable fee pool (bps × institutional volume; OTC +109% YoY; >50% of US equity is already off-exchange); Renegade validates mechanism AND leaves room (its 2-party design leaks match-occurrence; Aztec adds perimeter privacy) | Liquidity cold-start (the Penumbra failure mode); needs anchor MMs pre-committed; regulatory weight grows with success |
| **3** | **U3 credit consortium** | The only unforkable moat on the list (data network effects); recurring per-query revenue; BWWC+Duality prove the pattern off-chain; 3Jane proves on-chain demand; latency-insensitive | Slowest cold-start (consortium sales); regulatory surface; needs a BD-heavy team, not just cryptographers |
| **4** | **U4 poker (via licensed operator)** | Proven rake economics in a $3–6B market; per-action circuits measured sub-second (the rare *interactive* app inside the envelope); monty-hall already prototyped the machinery | Gambling law vs reputable-operator paradox; MPC doesn't fix player collusion — dishonest to claim otherwise |
| **5** | **U5 eligibility attestation on Aztec** | The only category with proven at-scale PSS revenue (World ID); unlocks institutional/private-DeFi compliance on Aztec | TACEO owns the infra lane; deployer must find the app-layer angle |

The portfolio logic: U1 is the **wedge** (shippable by a small team, revenue
per event from day one, every auction is a marketing event for the
mechanism); U2 is the **prize** the wedge grows into (an auction house that
runs recurring batch crossings *is* a dark pool); U3 is the **decade moat**;
U4/U5 are opportunistic. If forced to pick one: **U1, then let it become
U2** — sealed-bid liquidation auctions for Aztec-native lending protocols
are the most concrete first customer, they recur, and nobody has to be
convinced privacy matters when they're being front-run today.

What I would *not* bet on, despite their popularity in privacy-tech
pitches: horizontal "confidential compute" platforms (§3's graveyard —
Nillion, Oasis, Secret, Aleo all show mechanism-first fails), voting (no
WTP), consumer data markets (demand-side failure predates the privacy
tech), and anything requiring sub-second shared-state updates (§5.1).

---

## 5. What co-SNARK private shared state cannot do well

Honesty section — the constraints that survive all optimism, each with the
measurement or structural reason.

### 5.1 Latency and cadence

The envelope (§4.0) is: sub-second at 2^11–2^13, tens of seconds at
2^17–2^19, ~2 min at 2^20 — *per state transition, at loopback*. On WAN,
prove adds R×RTT (R ≈ 311–385 logical rounds → +15–20 s at 50 ms RTT) and
deep witness-extension is far worse (270k sequential rounds at 2^20 for
hash-chain circuits ≈ 10 h at 140 ms one-way — ch. 24; circuit *depth*,
not size, sets WAN feasibility). Ruled out: CLOB matching at exchange
speed, per-block DeFi composability, real-time multiplayer state, anything
a market-maker must requote inside a second. The Inco datum (§3.2) — an
FHE company shipping TEEs to hit latency — shows this ceiling is
commercially binding across all cryptographic mechanisms, not just ours.

### 5.2 Throughput and state contention

Private shared state is a *serialized* resource: transitions over the same
state must be sequenced through the committee (monty-hall's per-game
lockstep, ch. 04). There is no sharding story in this repo; concurrency =
partition the state (per-auction, per-table, per-pool instances) or batch
many users' inputs into one wide circuit (the auction/crossing shapes do
this naturally — another reason they rank high). Also: sha/keccak-heavy
transitions are 473×–>1,140× bb (measured, §4.0) — bit-oriented hashing
inside the shared-state circuit is effectively forbidden; and at 2^20 each
operator needs ~20 GB RAM *per concurrent job* (measured), which prices
the hardware floor.

### 5.3 The n-of-3 assumption is a business problem, not just a crypto one

Everything rests on "no 2 of the 3 named operators collude, and none is
compromised." Structural facts to state plainly:

- **Collusion breaks privacy silently and retroactively.** Two colluding
  operators reconstruct every secret ever shared with that committee; no
  on-chain evidence is produced; there is no slashing condition you can
  write because the offense is unobservable. (Soundness survives — proofs
  can't be forged — but the product *is* the privacy.)
- **Semi-honest is weaker than it sounds and stronger than it sounds.**
  Weaker: an actively malicious operator may deviate to extract
  information beyond its view. Stronger: for honest-majority co-SNARKs,
  recent results show semi-honest protocols already yield malicious
  security for several schemes essentially free
  ([eprint 2025/1026](https://eprint.iacr.org/2025/1026) [V]) — but this
  is not yet engineered/claimed for this codebase; do not sell active
  security we haven't implemented.
- **Who runs the nodes is the product decision.** The trust story must be
  legible to a counterparty risking real money: distinct legal entities,
  distinct jurisdictions, distinct clouds, reputations worth more than the
  secrets (TACEO's roster — Nethermind, P2P.org, universities — is the
  template [§2.3]; Zama's 13-operator committee of Ledger/Fireblocks/
  OpenZeppelin likewise [§3.2]). Note the tension with §5.1: jurisdictional
  diversity costs RTT. A defensible middle: 3 organizations, 3 clouds,
  one metro region **[opinion]**.
- **Operator economics must close.** Three professional operators × HA
  infrastructure × 20 GB-class jobs is real opex the deployer's fee model
  must cover from day one — unlike a smart contract, PSS has a payroll.
  This is why use cases with per-event fees attached to high-value flow
  (U1–U3) rank above ones with diffuse value (voting, games).
- **Liveness is 3-of-3.** REP3 has no robustness: one operator down halts
  every state transition (no proof, no state advance). SLAs, hot spares
  with re-sharing ceremonies, and exit procedures (what happens to shares
  when an operator quits — re-share to a successor, ch. 09's consent model)
  are unsolved *operational* design work in this repo (ch. 02 §5.4).
- **The user must still trust the share-distribution channel.** The PXE
  secret-sharer (ch. 09) is the root of the whole trust chain — a
  compromised client that mis-shares (or shares to fake nodes) defeats
  everything downstream. Envelope encryption to pinned operator keys
  (monty-hall's `crypto_box` sketch) is necessary but the key-directory
  governance behind it is a real institution someone must run.

### 5.4 What this adds up to

co-SNARK PSS is a **batch-cadence, high-value-per-transition, committee-
custodied** technology. It is the wrong tool for high-frequency, low-value,
trust-nobody-ever settings — and precisely the right tool where today a
*single trusted intermediary* computes over multiple parties' secrets and
everyone resents it: auctioneers, dark-pool operators, credit bureaus,
dealers, registries. The businesses in §4.3 are all, at bottom, the same
trade: replace one trusted middleman with three semi-trusted operators plus
a proof — and charge most of what the middleman used to.

---

## 6. Sources

Research performed 2026-07-26 via web search + primary-source fetches
(three parallel research passes: TACEO; MPC/FHE/TEE platforms; markets &
adjacents). Verification tags as defined in the header. Key sources:

**TACEO:**
- https://taceo.io/ · https://docs.taceo.io/docs/taceo-proof/overview/ ·
  https://docs.taceo.io/docs/taceo-proof/dev/quick-start-co-noir/ ·
  https://docs.taceo.io/docs/taceo-proof/dev/bestpractice/
- https://core.taceo.io/articles/taceo-proof-prod/ ·
  /articles/taceo-network/ · /articles/pss-taceo-network/ ·
  /articles/pss-taceo-services/ · /articles/seed/ ·
  /articles/taceo-aztec-pss-ethereum/ · /articles/devcon-demo/ ·
  /articles/mpc-zktls/ · /articles/honest-majority-mpc-for-cosnarks/
- https://www.biometricupdate.com/202606/taceo-ceo-sees-market-for-distributed-biometrics-processing-coming-together
- https://www.biometricupdate.com/202508/startup-behind-worlds-biometric-matching-software-raises-5-5m-in-seed-funding
- https://eprint.iacr.org/2026/850 (Merces) · https://eprint.iacr.org/2025/1026
  (malicious security of co-SNARKs) · https://eprint.iacr.org/2021/1530
  (Ozdemir–Boneh) · https://github.com/TaceoLabs

**Platforms:**
- Zama: https://www.zama.org/post/zama-protocol-testnet-update-mpc-partners-better-performance-audits-and-new-features ·
  https://tech.eu/2025/06/25/zama-hits-unicorn-status-with-57m-series-b-for-encryption-tech/
- Arcium/Umbra: https://www.theblock.co/post/387564
- Nillion: https://nillion.com/news/nillion-alpha-mainnet-is-live ·
  https://nillion.com/news/the-next-frontier-for-nillion-ethereum
- Secret: https://scrt.network/blog/secret-labs-response-to-tee-fail-ddr5-vulnerability ·
  https://aepicleak.com/ · https://www.theblock.co/post/405459
- Inco: https://www.inco.org/blog/inco-raises-5m-to-accelerate-development-of-confidentiality-layer-for-blockchains
- Fhenix: https://www.fhenix.io/ecosystem
- Renegade: https://renegade.fi/ · https://blog.arbitrum.io/renegade-stylus-case-study/ ·
  https://jamesbachini.com/renegade/ · https://github.com/renegade-fi/mpc-bulletproof
- Penumbra: https://x.com/penumbrazone/status/2012287805670539501 (shutdown post, [S])
- Aleo: https://messari.io/report/state-of-aleo-q2-2025
- Aztec: https://aztec.network/blog/road-to-mainnet ·
  https://www.theblock.co/post/381618/aztec-network-raises-over-60-million-in-eth-with-community-first-token-sale-testing-new-auction-model
- Lit/Fireblocks/Zengo: https://messari.io/report/lit-protocol-vincent-launch-litkey-tge-and-naga-mainnet ·
  https://sacra.com/c/fireblocks/
- Flashbots/Fairblock: https://buildernet.org/blog/introducing-buildernet ·
  https://blog.arbitrum.io/how-fairblock-is-unlocking-confidential-payments-and-auctions-on-arbitrum/
- Partisia: https://medium.com/partisia-blockchain/enabling-secure-multiparty-computation-a-life-journey-2f11ef74f7d5

**Demand signals:**
- BWWC MPC wage study: https://thebwwc.org/mpc ·
  https://www.bu.edu/hic/2023/12/19/boston-womens-workforce-council-finds-30-percent-decline-gender-wage-gap
- Duality: https://www.securityweek.com/secure-data-collaboration-firm-duality-technologies-raises-30-million/
- Pave: https://www.businesswire.com/news/home/20210810005300/en/Pave-Secures-Series-B-Valued-at-%24400M-and-Releases-Free-Real-Time-Compensation-Benchmarking
- Crypto OTC: https://finerymarkets.com/blog/crypto-otc-report-2025-results-trends
- Dark pools: https://www.rblt.com/market-structure-reports/let-there-be-light-us-edition-47
  (edition-year caveat noted in §3-research)
- MEV/orderflow: https://www.emergentmind.com/topics/mev-builders
- CoW batch auctions: https://docs.cow.fi/cow-protocol/concepts/introduction/fair-combinatorial-auction
- 3Jane: https://www.cmointern.com/2025/06/3jane-protocol-raises-52m-led-by.html ·
  https://www.3jane.xyz/pdf/whitepaper.pdf
- Online poker market: https://www.businesswire.com/news/home/20250602812357/en/Online-Poker-Global-Strategic-Business-Report-2025-Market-to-Reach-%2411.4-Billion-by-2030---Emergence-of-Cross-Platform-Play-and-Global-Tournaments-Spurs-Adoption---ResearchAndMarkets.com ·
  https://zkholdem.xyz/
- Voting: https://blog.shutter.network/shutter-brings-shielded-voting-to-snapshot/ ·
  https://gitcoin.co/case-studies/gg24-first-funding-round-of-gitcoin-3-0
- Genomic-market failures: https://www.genomeweb.com/informatics/blockchain-genomics-firm-lunadna-shut-down ·
  https://genomereviews.com/articles/20260328-nebula-shutdown
- Hashflow RFQ: https://www.bitget.com/academy/what-is-hashflow-hft-price-analysis
- Proof of reserves: https://www.coindesk.com/policy/2025/11/05/chainlink-apex-group-test-onchain-stablecoin-compliance-with-bermuda-regulator
- Dark Forest: https://blog.zkga.me/df-22-summer-break
- Witness encryption state of the art: https://eprint.iacr.org/2025/1364 ·
  https://csrc.nist.gov/Presentations/2025/stppa7-witness-encryption

**Local (measured):** `bench-results/bench.sqlite` + `bench-results/README.md`
(v2 run 2026-07-25), project-docs chs. 01, 02 §5.4, 04, 09, 22, 24.


