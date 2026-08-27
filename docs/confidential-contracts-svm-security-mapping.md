# Confidential Contracts / FHEVM Security Patterns Mapped to Solana SVM

**Independent research document. Not a production security specification.**

This mapping was produced by the authors of this repository. It is an
architectural comparison of official OpenZeppelin Confidential Contracts
and Zama FHEVM documentation against the Solana/SVM coordinator
implemented in this tree.

- OpenZeppelin did not review this mapping.
- OpenZeppelin did not endorse this project.
- Zama did not review this mapping.
- Zama did not endorse this project.
- This project is not audited.
- This is not a production security specification.
- This repository does not run FHEVM on Solana.
- This repository does not port OpenZeppelin Confidential Contracts to
  Solana.
- This repository does not implement Token-2022 settlement or real-value
  transfer.

Every claim about OpenZeppelin Confidential Contracts or Zama FHEVM
below is drawn from official documentation or official source
repositories. Every claim about this prototype is drawn from the
on-chain program, protocol crate, worker, and client as implemented
today. Intended behavior that is not enforced is labeled as such.

---

## 1. Scope

### Purpose of Phase 3

Phase 3 answers a narrow question: which security *assumptions* from
OpenZeppelin Confidential Contracts and Zama FHEVM can inform an
SVM-native confidential-policy coordinator, which require a different
mechanism, and which do not apply.

This phase studies which security principles can inform an SVM-native
design; it is not a source-level port of the EVM implementation.

### Why EVM / FHEVM assumptions cannot be copied into SVM

FHEVM host contracts execute *symbolic* FHE operations: they manipulate
32-byte ciphertext handles, consult a dedicated ACL contract, and emit
events that off-chain coprocessors execute with TFHE-rs. Encrypted
inputs carry Zero-Knowledge Proofs of Knowledge (ZKPoKs). Public
decryption is an asynchronous Gateway/KMS flow that later returns
signed cleartexts to a contract function. OpenZeppelin Confidential
Contracts are Solidity libraries that assume that host environment
(Zama `euint64` / `ebool` handles, `FHE.fromExternal`,
`FHE.allow` / `FHE.allowTransient`, `FHE.checkSignatures`).

SVM does not provide that environment. A Solana program is stateless
executable code. Mutable state lives in separately addressed accounts
that must be declared up front. A transaction is atomic only for the
instructions it contains. There is no EVM-style storage slot, no
`msg.sender`-as-sole-authorization-context, and no in-transaction FHE
handle algebra. Solana still supports multi-instruction transactions,
CPI, and atomic composition of those instructions. What this
architecture cannot do is synchronously finish external/off-chain
TFHE evaluation inside the same Solana transaction.
Ciphertexts in this prototype are too large to store on-chain
(measured `FheUint64` payloads are hundreds of kilobytes; the Solana
account data limit is 10 MiB, but packing TFHE blobs into accounts is
not the architecture). The coordinator therefore stores SHA-256
commitments and coordinates an explicit request lifecycle.

Naming coincidence is not semantic equivalence. An ERC-7984
"operator" is a time-limited transfer delegate. This repository's
"FHE operator" is the Ed25519 identity that attests an off-chain TFHE
result. Those are different roles.

### What this phase does

- Documents the trust model and threat model of the current prototype.
- Maps official Confidential Contracts / FHEVM patterns onto SVM
  mechanisms that actually exist in this repository.
- Classifies each pattern as A (directly applicable), B (applicable
  with SVM-specific adaptation), C (not directly applicable), or D
  (out of scope for this prototype).
- Records residual trust that remains after Phases 1 and 2.

### What this phase does not implement

This phase does not change programs, crates, account layouts,
instruction layouts, PDA derivations, digest formats, Relayer
transport, Token-2022 integration, or cryptographic implementation.
It does not add multi-operator quorum, verifiable FHE, threshold KMS,
durable ciphertext storage, settlement, or monitoring.

```text
FHEVM / Confidential Contracts          This prototype
------------------------------          ----------------
Solidity + FHEVMExecutor + ACL          Anchor coordinator (no tfhe)
euint64 / ebool handles                 SHA-256 ciphertext refs
FHE.fromExternal + ZKPoK                hash + local blob metadata
coprocessor majority + Gateway          single TFHE-rs worker
FHE.allow / allowTransient              PDA owner / signer checks
requestDecryption / checkSignatures     submit → Pending → finalize
ERC-7984 confidential token             mint identity binding only
OpenZeppelin Relayer (optional)         OpenZeppelin Relayer v1.5.0
                                        (finalize transport only)
```

---

## 2. Current Prototype Security Model

The following describes the repository as implemented. It is not a
desired end state.

### 2.1 Actors

| Actor | Role in this tree |
| --- | --- |
| Owner / requester | Signs `create_account`, `submit`, and `cancel`. Encrypts `FheUint64` inputs with the client key. Holds the client decryption key used to decrypt the finalized `FheBool`. |
| Config authority | Signs `initialize_config`, `set_paused`, `rotate_operator`, and `set_key_version`. Distinct from the FHE operator unless an operator reuses that keypair (the protocol does not require them to be the same). |
| FHE operator | Off-chain TFHE-rs worker identity. Loads the evaluation/server key, evaluates the fixed circuit, stores the result blob, and Ed25519-signs `encode_result`. Does not sign or pay the Solana transaction. |
| OpenZeppelin Relayer | Optional Phase 2 finalize transport (v1.5.0). Builds, signs, and fee-pays the Solana transaction from an instruction array. Never receives the FHE operator private key. Direct JSON-RPC remains the default path. |
| Solana validator / runtime | Enforces account ownership, PDA seeds, transaction atomicity, the native Ed25519 precompile, and the coordinator's state transitions. |
| Client / decryption-key holder | Retains `ClientKey`. Compromising this key decrypts every blob encrypted under it. |
| Ciphertext storage | Local content-addressed directory. Blobs are named by SHA-256 of the wrapped bytes. This is not a durable decentralized store. |
| Program upgrade authority | The Devnet deployment is upgradeable under the research deployer. This is a loader-v3 authority, not Config.authority. |

### 2.2 Assets

| Asset | Where it lives | What the coordinator sees |
| --- | --- | --- |
| Encrypted balance | Local blob; `ConfidentialAccount.balance_ref` and `Request.balance_hash` store SHA-256 | 32-byte hash only |
| Encrypted requested amount | Local blob; `Request.amount_hash` | 32-byte hash only |
| Encrypted limit | Local blob; `ConfidentialAccount.limit_ref` and `Request.limit_hash` | 32-byte hash only |
| Encrypted policy result (`FheBool`) | Local blob after worker evaluation; `Request.result_hash` after finalize | 32-byte hash only; plaintext `allowed` is never on-chain |
| Client decryption key | Local file (`keys/client.bin`). Worker evaluation paths do not load it. | Not on-chain |
| Server / evaluation key | Local file (`keys/server.bin`). `params_hash` is SHA-256 of the safe-serialized `CompressedServerKey`. | `Config.params_hash` / `Request.params_hash` |
| Operator signing key | Local Ed25519 keypair. Worker signs; finalizer/Relayer consume the signature bytes. | `Config.operator` public key |
| Relayer transaction key | Relayer signer. Pays fees. Distinct from `Config.operator`. | Finalize `payer` is any signer |
| Request state | Request PDA | Full lifecycle, digests, hashes, versions |
| Config state | Config PDA | Authority, operator, epochs, pause, params commitment |
| ConfidentialAccount state | Account PDA | Owner, refs, nonce, pending lock, `state_version` |
| Mint identity | `Config.mint` / PDA seeds | Synthetic pubkey. Not a Token-2022 mint. |

`ConfidentialAccount` does **not** store the policy result. A
`Finalized` Request stores `result_hash` and `result_digest` only.

### 2.3 Trust Assumptions

| Assumption | Status |
| --- | --- |
| FHE operator correctness | **TRUSTED** |
| FHE operator liveness | **TRUSTED** |
| Operator result authenticity | **CRYPTOGRAPHICALLY AUTHENTICATED VIA ED25519** over `encode_result` |
| Correctness of FHE execution | **NOT PROVEN** |
| Relayer | **NOT TRUSTED FOR FHE RESULT CORRECTNESS** |
| Relayer availability | **OPERATIONAL DEPENDENCY WHEN RELAYER TRANSPORT IS USED** |
| Solana state transition | **ENFORCED BY THE PROGRAM / RUNTIME** |
| Ciphertext availability | **LOCAL / NOT DURABLE** |
| Ciphertext well-formedness on-chain | **NOT VERIFIED** |
| Plaintext range / semantic binding of a hash | **NOT VERIFIED** |
| Proof of knowledge of plaintext | **NOT IMPLEMENTED** |
| Proof of correct TFHE evaluation | **NOT IMPLEMENTED** |
| Config authority honesty | **TRUSTED FOR PAUSE, OPERATOR ROTATION, KEY-VERSION WRITES** |
| Program upgrade authority | **TRUSTED; CAN REPLACE PROGRAM BYTECODE** |
| Client-key custody | **TRUSTED; COMPROMISE DECRYPTS ALL BLOBS UNDER THAT KEY** |
| Evaluation-key confidentiality for privacy of *computation capability* | **SERVER KEY IS INTENDED TO BE PUBLIC FOR EVALUATION**; it does not decrypt |
| Token-2022 / value movement | **NOT PRESENT** |

An Ed25519 signature proves which operator attested to a result; it does
not prove that the operator executed the intended TFHE circuit correctly.

---

## 3. Threat Model

Mitigations listed as "on-chain" are enforced by
`programs/confidential-coordinator`. Mitigations listed as "client" are
enforced only by `crates/client` when that path is used. An adversary
who submits raw transactions bypasses client checks.

### Unauthorized request submission

| | |
| --- | --- |
| **Threat** | A non-owner creates a Request for someone else's ConfidentialAccount. |
| **Current mitigation** | `Submit` requires `owner` as signer; PDA seeds are `["account", mint, owner]`; `has_one = owner`. Program tests reject a stranger submit. |
| **Residual risk** | Owner key compromise. |
| **Potential future improvement** | Hardware / KMS custody for owner keys; session keys with scoped rights. |

### Request replay

| | |
| --- | --- |
| **Threat** | Re-submit or re-finalize the same request. |
| **Current mitigation** | Request PDA is `["request", account, nonce_le]`. Nonce increments on submit and is never decremented on lock release. `init` fails if the PDA already exists. Finalize requires `STATUS_PENDING` and matching `pending_request`. Duplicate finalize is rejected (`invalid status`). |
| **Residual risk** | None for the same nonce/PDA once created. A new nonce is a new request. |
| **Potential future improvement** | None required for this specific replay class. |

### Stale request replay

| | |
| --- | --- |
| **Threat** | Finalize a request after the account's `state_version` or nonce has moved, or after Config versions changed. |
| **Current mitigation** | Finalize requires `account.state_version == request.state_version`, `account.request_nonce == request.request_nonce`, `request.operator_epoch == config.operator_epoch`, `request.key_version == config.key_version`, and `clock.slot < expiry_slot`. `request_digest` is recomputed from current Config/Request fields and must match the stored digest. |
| **Residual risk** | A still-pending, unexpired request with unchanged versions can be finalized by any payer who holds a valid operator signature. |
| **Potential future improvement** | Optional finalize authorization (owner or designated finalizer set). |

### Cross-account request substitution

| | |
| --- | --- |
| **Threat** | Point finalize at account A while the signed result is for account B. |
| **Current mitigation** | PDA seeds bind Request to `account` + nonce. `require_pending_lock` checks `request.confidential_account == account` and `account.pending_request == request`. `encode_result` includes `confidential_account` and `request_pda`. A substituted PDA in the signed message fails the Ed25519 message compare (`invalid result`). Tested. |
| **Residual risk** | None for this substitution class if the program is unchanged. |
| **Potential future improvement** | — |

### Cross-mint substitution

| | |
| --- | --- |
| **Threat** | Submit or finalize using a Config/mint other than the account's mint. |
| **Current mitigation** | Config PDA is `["config", mint]`. Account PDA includes mint. Submit and finalize compare `account.mint` / `request.mint` to `config.mint`. Tests reject a foreign Config. |
| **Residual risk** | The mint is an unchecked identity pubkey, not a Token-2022 mint. Binding is namespace isolation, not asset custody. |
| **Potential future improvement** | Phase 4 Token-2022 mint validation, if that phase is designed. |

### Ciphertext hash substitution

| | |
| --- | --- |
| **Threat** | Change `amount_hash` / `balance_hash` / `limit_hash` in the signed result relative to the on-chain Request. |
| **Current mitigation** | Hashes are copied onto the Request at submit. Finalize rebuilds `RequestBinding` from the Request account. A modified hash changes `request_digest` and fails the stored-digest check or the Ed25519 message compare. Tested (`substituted_ciphertext_hash_rejected`). |
| **Residual risk** | On-chain hashes do not prove the off-chain blob is a well-formed `FheUint64` of a particular plaintext. |
| **Potential future improvement** | Input ZKPoK or other binding proofs (FHEVM-style `FHE.fromExternal` is not available on SVM). |

### Result substitution

| | |
| --- | --- |
| **Threat** | Finalize with a `result_hash` other than the one the operator signed. |
| **Current mitigation** | `encode_result` includes `result_hash`. The Ed25519 instruction message must equal the coordinator's `encode_result`. Flipping the finalize argument fails (`invalid result`). Tested. |
| **Residual risk** | The signed hash may name a blob the operator produced incorrectly. Authenticity ≠ correctness. |
| **Potential future improvement** | Verifiable computation or multi-operator attestation. |

### Result replay across requests

| | |
| --- | --- |
| **Threat** | Reuse a valid operator signature from request N on request M. |
| **Current mitigation** | Result bytes include the full request binding and `request_digest` (domain `SOLFHE-CTL-RES-V1`). Different nonce, PDA, hashes, versions, or expiry change the message. |
| **Residual risk** | None for cross-request reuse of the same signature bytes against this encoder. |
| **Potential future improvement** | — |

### Stale operator signature

| | |
| --- | --- |
| **Threat** | Use a signature produced for a request after operator rotation or after expiry. |
| **Current mitigation** | Finalize requires current `Config.operator` as the Ed25519 pubkey *and* `request.operator_epoch == config.operator_epoch`. Rotation increments `operator_epoch`, so a pending request cannot finalize after rotation even if the new operator re-signs the old binding (epoch in the stored Request is stale relative to Config). Expiry rejects `clock.slot >= expiry_slot`. |
| **Residual risk** | Before rotation and before expiry, the old signature remains valid for that Pending request. |
| **Potential future improvement** | Explicit "invalidate pending" admin instruction; shorter lifetimes. |

### Operator rotation

| | |
| --- | --- |
| **Threat** | Authority replaces `Config.operator` while a Request is Pending. |
| **Current mitigation** | `rotate_operator` increments `operator_epoch`. Finalize fails with `InvalidOperatorEpoch`. Owner can still `cancel` (not paused-gated). Anyone can `expire` after `expiry_slot`. Tested (`wrong_operator_epoch_rejected`). |
| **Residual risk** | Pending work is stranded until cancel or expire. There is no "rebind pending request to new operator" path. Cancel is not blocked by `paused`. |
| **Potential future improvement** | Documented rotation procedure; optional cancel-on-rotate; migrate-or-expire batch. |

### Key-version mismatch

| | |
| --- | --- |
| **Threat** | Finalize or submit under a different evaluation-key generation than the account/request. |
| **Current mitigation** | Submit requires `account.key_version == config.key_version`. Finalize requires `request.key_version == config.key_version`. Worker `unwrap_blob` rejects mismatched `key_version` in the blob header. Tested for finalize after `set_key_version`. |
| **Residual risk** | `set_key_version` writes only `Config.key_version`. It does not update `ConfidentialAccount.key_version`, does not update `params_hash`, and does not migrate blobs. After a Config bump, existing accounts cannot submit until some out-of-band account recreation (there is no `set_account_key_version` instruction). Pending requests fail finalize (fail-closed). |
| **Potential future improvement** | Atomic params_hash + key_version rotation; account migration instruction; ciphertext re-encryption protocol. |

### Result signed for wrong Config

| | |
| --- | --- |
| **Threat** | Operator signs a result bound to Config A; attacker finalizes against Config B. |
| **Current mitigation** | Binding includes `config`, `mint`, `domain_id`, `program_id`. Finalize uses the passed Config account (PDA-seeded by `config.mint`) and rebuilds the binding from that Config + Request. Digest mismatch or message mismatch rejects. |
| **Residual risk** | None for this substitution class. |
| **Potential future improvement** | — |

### Result signed for wrong Request

| | |
| --- | --- |
| **Threat** | Signature for Request PDA X used to finalize Request PDA Y. |
| **Current mitigation** | Binding includes `request_pda` and `request_digest`. Tested (`wrong_request_rejected`). |
| **Residual risk** | None for this substitution class. |
| **Potential future improvement** | — |

### Malicious Relayer

| | |
| --- | --- |
| **Threat** | Relayer refuses delivery, delays, submits a valid pair, or tries to alter instructions / result. |
| **Current mitigation** | Relayer is not `Config.operator`. Finalize checks the Ed25519 instruction's pubkey against `Config.operator` and the message against `encode_result`. Client `require_ed25519_immediately_before_finalize` refuses a payload that inserts an instruction between Ed25519 and finalize. Post-submit, the client re-fetches the Request PDA and checks status, hashes, `pending_request`, and `state_version`. Direct JSON-RPC remains available. |
| **Residual risk** | Liveness and ordering if Relayer is the chosen transport. The coordinator requires native Ed25519 verification immediately before finalize and fails closed if that adjacency is violated. The successful Devnet Relayer validation preserved that adjacency. The current Relayer API/docs do not establish this as a future compatibility guarantee, so Relayer transaction-building behavior remains an integration assumption that should be regression-tested across upgrades. Relayer can expire a request after `expiry_slot` (any payer). Relayer learns public hashes, PDAs, and that a finalize was attempted — not plaintexts. |
| **Potential future improvement** | Multiple independent delivery paths; Relayer policy allowlists already documented for the two program IDs. |

### Reordered instructions

| | |
| --- | --- |
| **Threat** | Place finalize before Ed25519, or insert an instruction between them. |
| **Current mitigation** | Coordinator loads `current_index - 1` from the instructions sysvar and requires that instruction to be the Ed25519 program. `current == 0` fails. Client-side adjacency check matches. |
| **Residual risk** | Extra instructions *before* the pair are allowed on-chain. The Ed25519 precompile can theoretically pull pubkey/message/signature from *other* instructions; this coordinator requires those offsets to refer to the Ed25519 instruction itself (`index_is_self`). |
| **Potential future improvement** | Optionally require the pair to be the only non-budget instructions. |

### Missing Ed25519 instruction

| | |
| --- | --- |
| **Threat** | Call finalize with no preceding Ed25519 verify. |
| **Current mitigation** | `current > 0` and previous program id must be `Ed25519SigVerify111111111111111111111111111`. |
| **Residual risk** | None for a lone finalize. |
| **Potential future improvement** | — |

### Incorrect Ed25519 public key

| | |
| --- | --- |
| **Threat** | Ed25519 instruction verifies a signature under a key other than `Config.operator`. |
| **Current mitigation** | Coordinator compares the pubkey bytes inside the Ed25519 instruction to `config.operator` (`InvalidOperator`). Native precompile success is not sufficient. Tested (`wrong_operator_rejected`). Client also compares `result.json` operator to Config. |
| **Residual risk** | None for this class. |
| **Potential future improvement** | — |

### Finalization by arbitrary payer

| | |
| --- | --- |
| **Threat** | Anyone who obtains a valid operator signature submits finalize. |
| **Current mitigation** | By design: `Finalize.payer` is any signer. This enables Relayer fee payment and worker/finalizer separation. Authorization of the *result* is the operator signature, not the payer. |
| **Residual risk** | A leaked `result.json` (signature + hashes) can be submitted by any funded payer before cancel/expiry. That is equivalent to completing an otherwise valid finalize. |
| **Potential future improvement** | Allowlist of finalizers; owner-gated finalize if fee abstraction is not required. |

### Finalized-but-denied confusion

| | |
| --- | --- |
| **Threat** | Interpreting `status = Finalized` as `allowed == true`. |
| **Current mitigation** | The program never decrypts or stores `allowed`. It stores `result_hash` / `result_digest` of an `FheBool` ciphertext. `RESULT_TYPE_FHE_BOOL` is checked; the bit is not. |
| **Residual risk** | Downstream readers (humans, later settlement code) may misuse the status enum. No settlement code exists today. |
| **Potential future improvement** | Keep settlement authorization as a separate, explicit predicate over a decrypted or MPC-opened bit — not over `STATUS_FINALIZED`. |

### Duplicate finalization

| | |
| --- | --- |
| **Threat** | Finalize twice to overwrite `result_hash`. |
| **Current mitigation** | First finalize sets `STATUS_FINALIZED` and clears `pending_request`. Second finalize fails `require_pending_lock` (`InvalidStatus`). Tested. The `AlreadyFinalized` error variant exists but is unused; rejection is `InvalidStatus`. |
| **Residual risk** | None for overwrite. |
| **Potential future improvement** | Unused error code cleanup (documentation only; not required for security). |

### Stale client state

| | |
| --- | --- |
| **Threat** | Finalize from a stale `request.json` that does not match the chain. |
| **Current mitigation** | Client reconstructs `RequestBinding` from on-chain Config + Request, verifies PDA derivations and stored `request_digest`, and refuses if `request.json` differs. Worker/CLI `evaluate` still reads local `request.json` unless the Devnet submit path rewrote it from chain. |
| **Residual risk** | A worker pointed at a stale `request.json` can sign a result that will not finalize (fail-closed) or, if the file was substituted to match a *different* live request, will sign that other request. The worker does not itself fetch the Request PDA. |
| **Potential future improvement** | Worker-side RPC reconstruction (the Devnet client already does this before finalize). |

### Concurrent request handling

| | |
| --- | --- |
| **Threat** | Two in-flight policy checks on one ConfidentialAccount. |
| **Current mitigation** | Submit requires `!account.has_pending()`. Account is writable on submit/finalize/cancel/expire, so the runtime serializes conflicting transactions. Tested (`second_active_request_rejected`). |
| **Residual risk** | Cross-account concurrency is allowed (different PDAs). No global rate limit. |
| **Potential future improvement** | Explicit queue if multi-outstanding requests are ever required. |

### Cancelled request finalization

| | |
| --- | --- |
| **Threat** | Finalize after cancel. |
| **Current mitigation** | Cancel sets `STATUS_CANCELLED` and clears the lock. Finalize requires `STATUS_PENDING` and `pending_request == request`. Tested. |
| **Residual risk** | Race: cancel and finalize in-flight. Runtime account locks make one succeed; the loser fails. |
| **Potential future improvement** | — |

### Expired request finalization

| | |
| --- | --- |
| **Threat** | Finalize after `expiry_slot`. |
| **Current mitigation** | Finalize requires `clock.slot < expiry_slot` even if status is still Pending. `expire` then marks `STATUS_EXPIRED` and releases the lock. Tested. |
| **Residual risk** | Slot timing is consensus-clock, not wall clock. A request can sit Pending after expiry until someone calls `expire`. |
| **Potential future improvement** | Crank / monitor to expire promptly (Phase 6). |

### Paused protocol behavior

| | |
| --- | --- |
| **Threat** | Activity continues after pause, or pause is used to trap Pending requests. |
| **Current mitigation** | `create_account`, `submit`, and `finalize` check `config.paused`. `cancel` and `expire` do **not**. Authority can still `rotate_operator` / `set_key_version` while paused. Client finalize also refuses a paused Config. |
| **Residual risk** | Pause is not a global halt. Pending requests can be cancelled by the owner or expired by anyone after expiry. They cannot be finalized while paused. After unpause, a still-Pending, unexpired request with matching epochs can finalize. There is no on-chain pause event subscription in this repo. |
| **Potential future improvement** | Pause policy documentation; optional pause-blocks-cancel; Monitor alerts (Phase 6). |

### Ciphertext disappearance

| | |
| --- | --- |
| **Threat** | Blob files are deleted. |
| **Current mitigation** | Worker `get` fails if the file is missing. On-chain hashes remain. Owner cannot decrypt. |
| **Residual risk** | Availability is entirely local. Lost blobs cannot be reconstructed from hashes. |
| **Potential future improvement** | Durable replicated store; backup/restore of `.data/` (operational, not consensus). |

### Malicious ciphertext store

| | |
| --- | --- |
| **Threat** | Store operator returns a different blob for a hash, or serves extra blobs. |
| **Current mitigation** | `BlobStore::get` recomputes SHA-256 and requires equality with the requested hash. A wrong blob is `HashMismatch`. Extra files are ignored. On-chain does not read the store. |
| **Residual risk** | Withholding (availability). Serving the *correct* hash of an incorrectly encrypted plaintext (integrity of plaintext semantics is not proven). |
| **Potential future improvement** | Independent replicas; input proofs. |

### Compromised operator

| | |
| --- | --- |
| **Threat** | Operator signs an incorrect `FheBool` (wrong circuit, swapped inputs, random bits). |
| **Current mitigation** | None for correctness. Binding prevents signing a result for the *wrong request*. Owner who decrypts may detect a surprising bit; the coordinator will still accept it. |
| **Residual risk** | Full integrity failure of the policy bit. This is the central remaining trust assumption. |
| **Potential future improvement** | Phase 7: quorum attestation, verifiable computation, threshold FHE. A quorum is not trustless. |

### Compromised Relayer

| | |
| --- | --- |
| **Threat** | Relayer API key and Solana signer stolen. |
| **Current mitigation** | Relayer cannot produce a valid operator signature. It can pay finalize for a leaked `result.json`, refuse service, or call `expire` after expiry. Official Relayer docs require deploying behind a private backend, not on the public internet. |
| **Residual risk** | Fee theft, liveness, and griefing via expire-after-timeout. |
| **Potential future improvement** | Relayer signer isolation; rotate Relayer independently of FHE operator. |

### Compromised client decryption key

| | |
| --- | --- |
| **Threat** | Attacker decrypts historical and future blobs under that key. |
| **Current mitigation** | Local file permissions only. Not a KMS. Worker evaluation does not load the client key. |
| **Residual risk** | Total confidentiality failure for that key's ciphertexts. Participation metadata was already public. |
| **Potential future improvement** | KMS / threshold client keys; per-request ephemeral encryption where the architecture allows. |

### Compromised evaluation / server key

| | |
| --- | --- |
| **Threat** | Attacker obtains `CompressedServerKey`. |
| **Current mitigation** | TFHE-rs documents the server key as the key that enables computation and is not the decryption key. Evaluation capability is intended to be public to the computing party. `params_hash` binds which evaluation key the request committed to. |
| **Residual risk** | Anyone with the server key and the blobs can re-evaluate the circuit (they still cannot decrypt). A *substituted* server key is rejected by `require_server_key_commitment` in the worker. |
| **Potential future improvement** | Treat server-key distribution as an operational control, not a confidentiality control. |

### Program upgrade risk

| | |
| --- | --- |
| **Threat** | Upgrade authority replaces coordinator bytecode and weakens checks. |
| **Current mitigation** | None in-protocol. README records the Devnet program as upgradeable under the research deployer. Solana loader-v3 allows Upgrade while an upgrade authority is set. |
| **Residual risk** | Full protocol rewrite, including skipping Ed25519 or writing arbitrary Request status. |
| **Potential future improvement** | Multisig / governance upgrade authority; `set-upgrade-authority --final` when the research phase ends; verifiable builds. |

### Config authority compromise

| | |
| --- | --- |
| **Threat** | Attacker pauses, rotates operator to themselves, or bumps `key_version`. |
| **Current mitigation** | `AdminConfig` requires `has_one = authority`. Rotation increments `operator_epoch` (pending finalizes fail). `key_version` bump strands pending finalizes and new submits on existing accounts. |
| **Residual risk** | Attacker-controlled operator can attest false results for *new* requests after rotation (once accounts can submit again — today they cannot until account `key_version` matches, which has no update instruction). Pause censors finalize. |
| **Potential future improvement** | Multisig authority; timelocks; split pause vs rotate roles. |

---

## 4. Security Pattern Mapping

Mapping class:

- **A** — DIRECTLY APPLICABLE
- **B** — APPLICABLE WITH SVM-SPECIFIC ADAPTATION
- **C** — NOT DIRECTLY APPLICABLE
- **D** — OUT OF SCOPE FOR THIS PROTOTYPE

| Pattern / Concern | EVM / FHEVM / Confidential Contracts model | Current SVM mechanism | Mapping class | Security difference | Current status | Future work |
| --- | --- | --- | --- | --- | --- | --- |
| Encrypted integer inputs | Zama `euint64` / `externalEuint64` handles; values encrypted under the network FHE public key | Off-chain TFHE-rs `FheUint64` blobs; on-chain SHA-256 of a versioned wrapper | B | Handle is a symbolic pointer into coprocessor storage; hash is a content commitment to a local file | Implemented (hash + local blob) | Durable store; input proofs |
| Encrypted Boolean outputs | `ebool` handle from FHE ops (`select`, comparisons) | Off-chain `FheBool`; `Request.result_hash` after finalize | B | Same handle-vs-hash distinction; result is not written to ConfidentialAccount | Implemented | Do not treat hash as `allowed` |
| Ciphertext handles | `H = keccak256(fheOperation, input1, …)` from FHEVMExecutor; ACL-checked | SHA-256(wrapped_blob); zero-hash rejected | C | FHEVM handle encodes *operation identity*; SHA-256 encodes *bytes*. No on-chain ACL for the hash | Implemented as integrity ref only | Do not pretend hashes are FHEVM handles |
| Handle validity / binding | Symbolic executor checks types and ACL; `FHE.fromExternal` + ZKPoK binds input to contract and sender | Binding is request digest fields (program, config, mint, account, PDA, hashes, versions) | B | SVM binds the *hash* to accounts; it does not validate the ciphertext | Partial (hash binding only) | ZKPoK or equivalent |
| Encrypted-value ACL | `FHE.allow` / `allowThis` / `allowTransient` / `isSenderAllowed`; persistent ACL contract + EIP-1153 transient | PDA owner, signer checks, Config.authority | C | PDAs address accounts; they do not grant compute/decrypt rights on a ciphertext | Owner-scoped accounts only | Explicit ciphertext capability model if ever needed |
| ERC-7984 token operator | Time-limited `setOperator` for `confidentialTransferFrom`; operators cannot decrypt balances | Not implemented. Name collision with FHE operator | C / D | Different role entirely | Absent | Phase 4+ if settlement is designed |
| HandleAccessManager | OZ helper: grant persistent/transient allowance after `_validateHandleAllowance` | No handle allowance instruction | C | No FHEVM ACL to grant into | Absent | D unless an SVM ACL is designed |
| Execution-context binding | Encryption bound to `(contract, user)` in input proof; handles used in one EVM tx | `RequestBinding`: protocol, domain, program, config, mint, account, request PDA, hashes, `params_hash`, `state_version`, nonce, `key_version`, `operator_epoch`, expiry | B | SVM binding is an explicit digest, not an FHEVM ZKPoK | Implemented | Keep domain separators stable |
| Asynchronous computation | Coprocessors execute after symbolic on-chain ops; decryption via Gateway/KMS | Submit → Pending → off-chain worker → signed result → finalize | B | Similar split of heavy FHE vs chain, different orchestration (no Gateway, no majority) | Implemented | Quorum / verifiable compute |
| Public decryption callback | `FHE.requestDecryption` + callback, or `makePubliclyDecryptable` + off-chain `publicDecrypt` + `FHE.checkSignatures` | Owner decrypts locally; coordinator never sees plaintext | C | This prototype does not decrypt on-chain and does not verify KMS signatures | Owner-local decrypt | Do not add EVM callbacks |
| Input ZKPoK | Official FHEVM: proof that user knows plaintext and input is bound to contract/user; `FHE.fromExternal` | NOT IMPLEMENTED | C | Coordinator accepts any non-zero hash | Absent | Research if an SVM-verifiable proof is feasible |
| FHE evaluation correctness | FHEVM coprocessors: majority-honest, commitments, optional fraud/slashing (protocol docs) | Single operator signature | C | This repo has no coprocessor set, stake, or fraud proof | Single-operator trust | Phase 7 |
| Result authentication | KMS / coprocessor signatures over handles/cleartexts (`checkSignatures`) | Ed25519 over `encode_result` by `Config.operator` | B | Authenticity of *attestation*, not of TFHE | Implemented | Do not conflate with KMS proofs |
| Relayer / delivery | OZ Relayer: sign/pay/broadcast; FHEVM also has a Zama Relayer for KMS decrypt — different product | OZ Relayer v1.5.0 Solana instruction-array submit; fee_payment_strategy=relayer | B | Delivery ≠ computation. Zama "Relayer" in FHEVM decrypt docs is not this Relayer | Phase 2 validated | Keep keys separate |
| Instruction introspection | EVM `ecrecover` inside one call; no sibling-instruction sysvar | Instructions sysvar; Ed25519 precompile immediately before finalize; offsets must be self | B | SVM-specific adjacency; precompile can otherwise read other ixs | Implemented | — |
| Replay / nonces | EVM account nonce; ERC-7984 has no transfer nonce; FHEVM input proofs resist input replay | Account `request_nonce`, Request PDA, status machine, domain-separated digests | B | Closest SVM mechanism is PDA+nonce+status, not an EVM nonce | Implemented | — |
| Key / params versioning | FHEVM Gateway administers key management/rotation (protocol docs) | `key_version`, `params_hash`, `operator_epoch`; incomplete rotation lifecycle | B | Versions exist; no params_hash update; no account key migration | Partial | Rotation protocol |
| Confidential business state | Contract storage holds `euint64` balances; coprocessor holds ciphertexts under handles | SVM holds refs; blobs are off-chain | C | Availability/integrity split is fundamental | Implemented as refs | Durable store |
| Finalization semantics | ERC-7984 transfer updates encrypted balances; decrypt finalize reveals amount for swaps | `STATUS_FINALIZED` commits an attested result hash | B | Finalized ≠ allowed; no balance update | Implemented | Settlement must not use status alone |
| ERC-7984 callbacks | Same-tx `onConfidentialTransferReceived`; refund if `ebool` false | No token receiver hook; no encrypted result in the submit transaction | C | Solana CPI and multi-instruction composition exist, but off-chain TFHE evaluation cannot finish inside the submit transaction | Absent | D for this prototype |
| Events / logs | FHEVM ACL events drive coprocessors; ERC-7984 `ConfidentialTransfer` | No protocol events; clients poll accounts | C | SVM programs may emit logs; this coordinator does not define an event ABI | Absent | Phase 6 Monitor on account diffs |
| Upgradeability | EVM proxies / OZ upgrade patterns; FHEVM host contracts | BPF loader-v3 ProgramData upgrade authority | C | Different trust surface (replace all bytecode vs storage-preserving proxy) | Upgradeable on Devnet | Governance / immutability |
| Gas / account locking | EVM sequential; transient storage EIP-1153 | Declared account locks; parallel runtime | B | Concurrent txs on the same ConfidentialAccount serialize | Used implicitly | — |
| Pause / emergency | IERC7984Rwa `pause`; Relayer `paused` | `Config.paused` on create/submit/finalize | B | Cancel/expire still work; Relayer pause is a separate client gate | Implemented | Monitor pause |
| Monitoring | OpenZeppelin Monitor watches EVM/Stellar/Solana (official Monitor docs) | Not integrated | D | Planned Phase 6; does not change FHE trust | Planned | Phase 6 |

### 4.1 Encrypted value representation

Official FHEVM symbolic execution treats a handle as a 32-byte
pointer, typically `keccak256(fheOperation, inputs…)`, generated by
`FHEVMExecutor`. Coprocessors store the real ciphertext under that
handle and consult ACL before compute or decrypt.

OpenZeppelin Confidential Contracts store ERC-7984 balances and
transfer amounts as those handles (`euint64`). ERC-7984 (draft)
abstracts this further as `bytes32` pointers whose resolution is
implementation-specific.

This prototype stores a SHA-256 of a local wrapper
(`CTL1` ‖ kind ‖ key_version ‖ params_hash ‖ TFHE-rs safe-serialized
payload). That hash is an integrity reference, not a capability and
not a symbolic FHE opcode digest.

Consequences:

- On-chain state cannot fetch or type-check the blob.
- Anyone who can read the file and the client key can decrypt; anyone
  who can read the file and the server key can recompute.
- Garbage-collecting a file does not change SVM state; the hash
  remains, the plaintext is lost.

**Class: B** for "commit to an encrypted value"; **C** for FHEVM
handle semantics.

### 4.2 Authorization / ACL

Official FHEVM ACL ([Access Control List](https://docs.zama.org/protocol/solidity-guides/smart-contract/acl)):

- `FHE.allow(ciphertext, address)` — persistent permission, stored in
  a dedicated ACL contract.
- `FHE.allowTransient` — current-transaction only (EIP-1153).
- `FHE.allowThis` — `allow` for `address(this)`.
- `FHE.makePubliclyDecryptable` — global decrypt permission.
- `FHE.isAllowed` / `FHE.isSenderAllowed` — checks before consuming a
  handle (documented as necessary to reduce inference attacks).
- Delegation helpers for user decryption.

OpenZeppelin `HandleAccessManager` is a thin wrapper that grants
persistent or transient allowance after an internal validator.

**Can an EVM-style encrypted-value ACL be directly reproduced using
PDAs?** No. A PDA is a deterministic account address derived from
seeds and a program id. It answers "which account holds this
struct?" and "which program may sign as this address?" It does not
implement a per-ciphertext map from handle → {addresses that may
compute or decrypt}. SVM has no FHEVMExecutor, no ACL contract, and
no handle that the runtime understands.

**What authorization this prototype actually provides:**

- Owner must sign `create_account`, `submit`, and `cancel`.
- Config authority must sign admin instructions.
- FHE operator must have signed `encode_result` (verified via
  precompile + coordinator checks).
- Expire and finalize payers are unrestricted.
- PDA seeds bind mint/owner/account/nonce so accounts cannot be
  swapped silently.

**What authorization is absent:**

- Per-ciphertext compute/decrypt ACL.
- Proof that the submitter knows the plaintext of a hash.
- Restriction on who may read the local blob directory.
- ERC-7984-style transfer operators.

**Class: C** for FHEVM ACL; **B** for "bind actions to Solana
signers and PDAs."

### 4.3 Execution context binding

FHEVM encrypted inputs are bound to a contract address and user
address inside the ZKPoK (`createEncryptedInput(contract, user)` /
`encrypt_and_prove_for`). Handles produced on-chain are bound by
ACL and by the symbolic opcode hash.

This repository binds via `RequestBinding` / `ResultBinding`
(domain-separated encodings in `crates/protocol`):

- protocol version, domain id, program id
- config, mint, confidential account, request PDA
- operation, three input hashes, `params_hash`
- `state_version`, `request_nonce`, `key_version`, `operator_epoch`
- `expiry_slot`
- result path also binds `request_digest`, `result_hash`,
  `result_type`, `circuit_id`

What the code demonstrates:

- **Result reuse across requests:** rejected (digest includes nonce,
  PDA, hashes).
- **Result reuse across accounts:** rejected (`confidential_account`
  + PDA seeds).
- **Stale result acceptance:** rejected when state_version, nonce,
  key_version, operator_epoch, or expiry no longer match, or when
  the recomputed request digest differs.

**Class: B.**

### 4.4 Asynchronous / deferred execution

Official FHEVM public decryption is a three-step process
(`makePubliclyDecryptable` → off-chain `publicDecrypt` →
`FHE.checkSignatures`) or an older `requestDecryption(callback)`
pattern. Computation itself is already asynchronous: the host chain
records symbolic ops; coprocessors execute later.

This prototype's path is:

```text
submit (owner, atomic)
    → Request status = Pending, pending_request set
off-chain TFHE-rs worker (not consensus)
    → result blob + Ed25519 signature
finalize (any payer, atomic with Ed25519 ix)
    → Finalized, lock released, state_version++
```

External/off-chain TFHE evaluation cannot synchronously complete
inside the same Solana transaction in this architecture. That is not
a claim that Solana lacks multi-instruction transactions, CPI, or
transaction-level composition; those exist and this coordinator uses
them (for example `[Ed25519, finalize]` in one transaction). The FHE
work itself is performed outside the transaction, so the protocol
uses:

```text
submit transaction
    → authoritative Pending state
    → external TFHE evaluation
    → independent finalize transaction
```

Between submit and finalize, Config may be paused or rotated; the
account lock prevents a second Pending request; expiry bounds
liveness. Worker-internal progress is not on-chain (no Processing
status). Transaction atomicity applies *within* submit and *within*
`[Ed25519, finalize]`, not across the off-chain gap.

**Class: B** for async off-chain FHE; **C** for Solidity callbacks.

### 4.5 Proof / input validation

Official FHEVM inputs are accompanied by ZKPoKs. `FHE.fromExternal`
validates the ciphertext and proof and converts an external handle
into an `euint64` / `ebool`. Coprocessors also verify those proofs
at the Gateway.

This prototype:

| Check | Status |
| --- | --- |
| Ciphertext well-formedness (on-chain) | **NOT IMPLEMENTED** |
| Ciphertext well-formedness (worker `safe_deserialize`) | Worker-only; not consensus |
| Plaintext range correctness | **NOT IMPLEMENTED** |
| Ciphertext ownership | **NOT IMPLEMENTED** |
| Proof of knowledge | **NOT IMPLEMENTED** |
| Proof that ciphertext corresponds to a claimed semantic value | **NOT IMPLEMENTED** |
| Proof of correct FHE evaluation | **NOT IMPLEMENTED** |

On-chain `require_ct_hash` only rejects the zero hash. Blob magic /
kind / key_version / params_hash checks run in the worker when
loading files.

**Class: C** (FHEVM proofs); worker deserialize is an operational
sanity check, not a security proof.

### 4.6 Result authentication

FHEVM's documented trust story for *decryption* is KMS signatures
checked by `FHE.checkSignatures`. Coprocessor *computation* is
described as majority-honest with published ciphertext commitments
and slashing (Zama Protocol coprocessor docs). This repository
implements neither KMS proofs nor coprocessor consensus.

This prototype: one Ed25519 attestation over canonical result bytes.

**Authenticity:** the configured operator signed this exact binding.

**Correctness:** not proven.

An Ed25519 signature proves which operator attested to a result; it does
not prove that the operator executed the intended TFHE circuit correctly.

**Class: B** for "authenticate an off-chain result"; **C** for FHEVM
KMS / majority coprocessor guarantees.

### 4.7 Relayer / transaction delivery

[OpenZeppelin Relayer v1.5.x](https://docs.openzeppelin.com/relayer/1.5.x/)
is a backend service that signs and submits transactions to EVM,
Solana, and Stellar. It is not a confidential-compute coprocessor.
Official Solana docs: with `fee_payment_strategy: "relayer"`, clients
may POST an instruction array; the Relayer builds the transaction,
adds compute-budget and priority-fee instructions, signs, and
submits.

This is a different component from the "Zama Relayer" that FHEVM
docs mention for KMS `publicDecrypt`.

Role split in this repository:

| Role | Job |
| --- | --- |
| FHE operator | Computation + result signature |
| Relayer | Transaction construction / signing / fee payment / delivery |
| Coordinator | State-transition enforcement |

What the program prevents: accepting a Relayer-signed *result*;
accepting a mutated result hash; accepting finalize without a
matching operator Ed25519 message; accepting finalize if versions
diverged.

The coordinator requires native Ed25519 verification immediately
before finalize and fails closed if that adjacency is violated. The
successful Devnet Relayer validation preserved that adjacency. The
current Relayer API/docs describe adding compute-budget and
priority-fee instructions when building from an instruction array;
they do not establish a future compatibility guarantee that extras
will never be inserted between Ed25519 and finalize. Relayer
transaction-building behavior is therefore an integration assumption
that should be regression-tested across Relayer upgrades.

What remains a liveness dependency: Relayer uptime, fee balance, and
policy (`allowed_programs` must include the Ed25519 program and the
coordinator).

**Class: B.**

### 4.8 Instruction introspection

Solana programs inspect *top-level* instructions via
`Sysvar1nstructions1111111111111111111111111`. CPI inner
instructions are not visible. The Ed25519 precompile verifies
signatures as native code and, per official docs, may load
pubkey/message/signature from *any* instruction in the transaction.

This implementation therefore:

1. Requires the immediately previous top-level instruction to be the
   Ed25519 program.
2. Requires signature, pubkey, and message indexes to refer to that
   instruction (`ed_index` or `u16::MAX`).
3. Requires pubkey == `Config.operator` and message ==
   `encode_result`.

That is not equivalent to `ecrecover` in a Solidity function. It is
an SVM-specific defense against precompile offset tricks and
instruction reordering.

**Class: B.**

### 4.9 Replay protection

EVM transaction nonces, EIP-712 domain separators, and FHEVM input
proofs are different tools. This prototype's replay domain is:

- Request PDA uniqueness (account + little-endian nonce)
- Monotonic `request_nonce` (never reused after lock release)
- Status machine (Pending is the only finalizable state)
- Domain separators `SOLFHE-CTL-REQ-V1` / `SOLFHE-CTL-RES-V1`
- Digest fields listed in §4.3
- `pending_request` lock

These are **not** "the Solana equivalent of an EVM nonce." They are
the closest SVM-native mechanisms; the security boundary differs
because Solana has no per-account EVM nonce for arbitrary program
calls, and because Request accounts persist after terminal states.

**Class: B.**

### 4.10 Key management / rotation

TFHE-rs: `ClientKey` must remain private; `ServerKey` is sent to the
evaluator (`generate_keys` docs).

This prototype:

| Knob | Behavior | Gap |
| --- | --- | --- |
| `params_hash` | Set at `initialize_config` only | No update instruction |
| `key_version` | `set_key_version` updates Config only | Accounts keep the version from `create_account`; submit then fails |
| `operator_epoch` | Incremented on `rotate_operator` | Pending requests fail finalize (fail-closed); no rebind |
| Blob header | Worker checks version + params_hash | Cannot migrate old blobs in-protocol |
| Client key | Local file | No rotation / re-encrypt path |

Outstanding Pending requests during rotation fail closed. Decryption
continuity for old blobs requires retaining the old client key
forever.

**Class: B** (version fields exist); lifecycle is incomplete.

### 4.11 Confidential state

**A.** FHEVM / Confidential Contracts: encrypted business state
(`euint64` balances) is a first-class contract value. Coprocessors
keep ciphertext bytes under handles; ACL and Gateway coordinate
availability for decrypt/bridge. Protocol docs mention public
storage (e.g. S3) for ciphertext availability.

**B.** This prototype: SVM stores commitments. Ciphertexts are local
files.

| Concern | Consequence here |
| --- | --- |
| Availability | Lost files ⇒ stuck decrypt / stuck worker; hashes remain |
| Integrity | Hash mismatch detected on read; semantic integrity not proven |
| Garbage collection | Manual; no on-chain GC |
| Synchronization | Client must keep store and Request hashes aligned |
| Disaster recovery | Restore `.data/` from backup; chain cannot help |
| Censorship | Store operator can withhold blobs; chain cannot force reveal |
| Durability | Not provided |

**Class: C** for "encrypted state in the confidential execution
environment."

### 4.12 Finalization semantics

`STATUS_FINALIZED` means:

the authenticated encrypted result was accepted and committed
according to protocol rules.

It does **not** mean `allowed == true`. It does not reveal the
Boolean. It does not authorize Token-2022 movement. The
ConfidentialAccount is not updated with the policy bit.

A later settlement phase must define a separate authorization
predicate. Phase 5 in the README already states this; this mapping
reaffirms it as a security invariant of interpretation, not of
storage.

**Class: B** (commit attested output); misuse is an application bug.

---

## 5. What Does Not Translate Directly to SVM

### 5.1 EVM contract storage versus the Solana account model

**Why direct translation fails.** An FHEVM host contract stores
`euint64` fields in contract storage and treats handles as values.
Solana stores state in separately owned accounts with explicit lock
lists. There is no unified contract storage trie.

**SVM-native design must** put each authoritative object (Config,
ConfidentialAccount, Request) in a PDA with checked seeds, and treat
ciphertexts as external objects referenced by commitment.

### 5.2 Synchronous FHE completion inside one transaction

**Why direct translation fails.** Even FHEVM computation is
asynchronous under the hood, but Solidity can still *return* a new
handle in the same transaction and, for ERC-7984, invoke
`onConfidentialTransferReceived` before the transaction ends.
External/off-chain TFHE evaluation cannot synchronously complete
inside the same Solana transaction in this architecture. Solana
still supports multi-instruction transactions, CPI, and
transaction-level composition; those are not the missing piece. The
missing piece is completing the TFHE circuit before the submit
transaction ends.

**SVM-native design must** therefore use:

```text
submit transaction
    → authoritative Pending state
    → external TFHE evaluation
    → independent finalize transaction
```

Pending is first-class consensus state. The gap is bounded with
expiry and a single-flight lock.

### 5.3 Encrypted-value ACL semantics

**Why direct translation fails.** `FHE.allow` / `allowTransient` are
permissions on handles enforced by an ACL contract and replicated to
coprocessors. PDAs and `has_one = owner` are permissions on
*accounts*.

**SVM-native design must** authorize signers for lifecycle
instructions and, if ciphertext sharing is ever required, invent an
explicit capability scheme. Do not call a PDA an ACL.

### 5.4 Callback and receiver semantics

**Why direct translation fails.** ERC-7984 `AndCall` and FHEVM
decryption callbacks assume a later function in the *same* or a
*subsequent EVM* transaction invoked as a contract call with
`msg.sender` = token or oracle. Solana has CPI and multi-instruction
transactions, but those compose work that is already in the
transaction. External/off-chain TFHE evaluation cannot synchronously
complete inside the submit transaction in this architecture, so a
receiver hook cannot observe the encrypted policy result there.

**SVM-native design must** use an independent finalize transaction
after external TFHE evaluation, and must not rely on receiver hooks
to interpret encrypted results in the submit transaction.

### 5.5 Ciphertext handle lifetime

**Why direct translation fails.** FHEVM handles are deterministically
derived from operations and live in coprocessor/DA storage with ACL
lifetime rules. A SHA-256 file name lives as long as the disk does.

**SVM-native design must** treat availability as an operational
property and integrity as a hash check, separately.

### 5.6 Transaction-sender assumptions

**Why direct translation fails.** FHEVM input proofs and
`isSenderAllowed` assume a single `msg.sender`. A Solana transaction
has a fee payer plus zero or more other signers. Finalize's payer is
intentionally *not* the operator and need not be the owner.

**SVM-native design must** name each required signer in account
metas and must not treat "transaction signer" as "FHE principal."

### 5.7 Upgradeability models

**Why direct translation fails.** EVM upgradeability is usually a
proxy pointing at new logic while storage slots persist. Solana
loader-v3 replaces ProgramData bytecode in place; account layouts
remain the program's problem. A malicious upgrade can ignore every
invariant in this document.

**SVM-native design must** treat upgrade authority as a top-tier
trust assumption, distinct from Config.authority.

### 5.8 Event-driven coprocessor consensus

**Why direct translation fails.** Zama coprocessors listen to host
events, replicate ACL, and reach majority agreement via the Gateway.
This repository has one worker that reads a JSON file.

**SVM-native design must** not claim coprocessor security properties
until a multi-operator protocol exists (Phase 7 research).

---

## 6. Proposed SVM-Native Confidential-Contract Security Principles

These are architecture principles derived from the mapping. They are
not claims that unimplemented controls exist.

1. **Bind every external encrypted artifact to authoritative SVM
   state.** A ciphertext hash is usable only as it appears on a
   program-owned PDA, inside a domain-separated digest.

2. **Treat external computation as asynchronous and adversarial until
   authenticated and validated.** Off-chain TFHE output has no
   consensus status until finalize succeeds.

3. **Separate computation identity from transaction-delivery
   identity.** `Config.operator` attests results. Relayer or RPC
   payer only pays fees.

4. **Bind results to request-specific state and a replay domain.**
   Include program, config, account, request PDA, nonce, versions,
   hashes, and expiry in the signed message.

5. **Make lifecycle state authoritative on-chain.** Pending /
   Finalized / Cancelled / Expired live on the Request PDA. Worker
   memory is not a status.

6. **Never interpret Finalized as plaintext policy approval.**
   Finalized means an attested encrypted result was committed.

7. **Treat ciphertext availability separately from ciphertext
   integrity.** A hash detects substitution; it does not store the
   bytes.

8. **Make key and version transitions explicit.**
   `key_version`, `params_hash`, and `operator_epoch` must change
   through defined instructions; stale pending work should fail
   closed.

9. **Fail closed on stale or ambiguous finalization.** Prefer
   rejecting finalize after rotation, pause, expiry, or digest
   mismatch over "best effort" acceptance.

10. **Keep trust assumptions visible.** Operator correctness, client-key
    custody, upgrade authority, and local blob availability remain
    trusted until a later phase removes them.

---

## 7. Gap Analysis

| Capability | Current prototype | Desired security property | Gap | Candidate future phase |
| --- | --- | --- | --- | --- |
| FHE computation correctness | Single trusted operator | Attested result matches the circuit on the committed inputs | No correctness proof | Phase 7 |
| Multi-operator trust | One `Config.operator` | No single evaluator can unilaterally set the bit | No quorum | Phase 7 |
| Verifiable computation | Ed25519 authenticity only | Third party can check evaluation | Not present | Phase 7 |
| Threshold operation | Single client key, single operator key | Compromise of one share is insufficient | Not present | Phase 7 |
| Ciphertext durability | Local directory | Survive disk loss / single-host failure | No replication | Phase 7 / ops |
| Ciphertext access control | Filesystem permissions | Explicit who may fetch/evaluate/decrypt | No ACL | Research; not PDA-equivalent |
| Key rotation | `set_key_version` + `rotate_operator` | Safe migration of accounts, params, and blobs | No `params_hash` update; no account version migrate; pending stranded | Later protocol work |
| Disaster recovery | Manual `.data/` copy | Documented restore of keys + blobs + chain pointers | Operational only | Ops |
| Token-2022 binding | Synthetic mint pubkey | Bind policy to real mint / confidential balances | UncheckedAccount mint | Phase 4 |
| Settlement | None | Move value only if policy allows | Not designed | Phase 5 (after Phase 4) |
| Monitoring | None | Observe pause, rotate, finalize, anomalies | Not integrated | Phase 6 |
| Pause / emergency governance | Single authority `set_paused` | Accountable emergency control | Single key; cancel/expire still live | Governance design |
| Program upgrades | Loader-v3 research authority | Constrained or revoked upgrade | Full bytecode replacement possible | Production governance |
| Confidential state synchronization | Manual hash ↔ file | Store and chain cannot diverge silently | Client discipline + worker hash check | Durable store + sync protocol |

---

## 8. Security Invariants

The following are true of the current program and protocol crates.
Each is backed by an on-chain check (and, where noted, a test).

1. **At most one active Pending request per ConfidentialAccount.**
   `submit` requires `!account.has_pending()`. Test:
   `second_active_request_rejected`.

2. **Request nonce matches account sequencing.** Submit computes
   `nonce = request_nonce + 1` and requires `nonce == expected_nonce`.
   The Request PDA seeds include `expected_nonce.to_le_bytes()`.
   Test: `wrong_nonce_rejected`.

3. **Nonce is not reused after lock release.** `release_account_lock`
   clears `pending_request` and increments `state_version` but does
   not decrement `request_nonce`. Comment in program source states
   this as intentional.

4. **A Finalized Request cannot be finalized again.**
   `require_pending_lock` requires `STATUS_PENDING`. Test:
   `duplicate_finalization_rejected`.

5. **A Cancelled Request cannot be finalized.** Same lock check.
   Test: `cancelled_finalize_rejected`.

6. **An Expired Request cannot be finalized.** Finalize requires
   `clock.slot < expiry_slot`; after `expire`, status is not Pending.
   Test: `expired_finalize_rejected`.

7. **The accepted worker identity is `Config.operator`.** Ed25519
   pubkey bytes must equal `config.operator`. The Relayer payer is
   not consulted. Test: `wrong_operator_rejected`.

8. **The Relayer does not replace operator identity.**
   `finalize_ixs_with_signature` never loads the operator secret.
   Coordinator compares to `Config.operator` only.

9. **The signed result is bound to the on-chain request digest.**
   Finalize rebuilds `RequestBinding`, requires
   `request_digest(binding) == request.request_digest`, and verifies
   Ed25519 over `encode_result`. Tests: `wrong_result_digest_rejected`,
   `substituted_ciphertext_hash_rejected`, `wrong_request_rejected`.

10. **`result_hash` and `result_digest` are committed on the Request
    at successful finalize.** Program writes both before releasing
    the lock.

11. **Successful finalize clears `pending_request`.**
    `release_account_lock`.

12. **Successful finalize, cancel, and expire increment
    `state_version`.** Same helper.

13. **Native Ed25519 verification must immediately precede finalize.**
    `ed25519::verify_operator_message`. Pubkey, signature, and
    message must reside in that Ed25519 instruction.

14. **Zero ciphertext hashes are rejected.** `require_ct_hash` on
    create, submit, and finalize result. Test:
    `zero_ciphertext_ref_rejected`.

15. **Pause blocks create_account, submit, and finalize.** It does
    not block cancel or expire (verified by reading those
    handlers — they have no `paused` check).

16. **Owner is the only submitter and canceller.** Expire and
    finalize accept any payer.

17. **PDA derivations are as specified:**
    `["config", mint]`, `["account", mint, owner]`,
    `["request", account, nonce_le]`.

18. **Domain separation:** request encodings use `SOLFHE-CTL-REQ-V1`;
    result encodings use `SOLFHE-CTL-RES-V1`. Protocol tests assert
    they differ.

19. **Worker evaluation does not load the client decryption key.**
    `load_server_material` / worker CLI / `cmd_evaluate` load only
    the compressed server key and operator keypair.

20. **The mint field is identity binding, not Token-2022 validation.**
    `InitializeConfig.mint` is `UncheckedAccount`.

### 8.1 Desired but Not Yet Enforced Invariants

These are *not* true today. They must not be cited as current
guarantees.

- The operator-evaluated `FheBool` equals the honest evaluation of
  `(balance >= amount) && (amount <= limit)` on the intended
  plaintexts.
- More than one independent operator must agree before finalize.
- Ciphertext bytes remain available for the life of the Request.
- Only authorized parties may fetch a blob (beyond local FS).
- `params_hash` and account `key_version` stay consistent across a
  completed rotation procedure.
- A `Finalized` result is interpreted as a Token-2022 transfer
  authorization. (Must remain false.)
- The program bytecode cannot change.
- Input hashes correspond to well-formed TFHE ciphertexts of
  claimed values.
- Config.authority is a decentralized governance body.

---

## 9. Attack Scenarios

### Scenario A — malicious Relayer modifies transaction

| | |
| --- | --- |
| **Attacker capability** | Controls Relayer signer and the HTTP API that accepts instruction arrays. |
| **Attempt** | Drop or reorder the Ed25519 instruction; replace `result_hash`; insert an instruction between Ed25519 and finalize; sign finalize as Relayer. |
| **Current defense** | Coordinator requires native Ed25519 verification immediately before finalize, with `Config.operator` and exact `encode_result`, and fails closed if adjacency is violated. Mutated hash fails the message compare. Client refuses non-adjacent specs. Relayer cannot forge the operator signature. The successful Devnet Relayer validation preserved that adjacency. The current Relayer API/docs do not establish this as a future compatibility guarantee; Relayer transaction-building remains an integration assumption that should be regression-tested across upgrades. |
| **Residual risk** | Censorship, delay, expire-after-timeout, fee drain. |
| **Future mitigation** | Dual transport; Relayer allowlists; Monitor on unexpected expire. |

### Scenario B — stale worker result replay

| | |
| --- | --- |
| **Attacker capability** | Holds `result.json` from an old request. |
| **Attempt** | Submit that signature against a new Request or a completed one. |
| **Current defense** | Message includes request-specific fields and digest. Completed requests are not Pending. New nonce ⇒ new PDA and digest. |
| **Residual risk** | Same Pending request can still be finalized by any payer until cancel/expiry. |
| **Future mitigation** | Shorter expiry; finalizer allowlist. |

### Scenario C — operator signs result for another Request

| | |
| --- | --- |
| **Attacker capability** | Honest or malicious operator produces a signature for Request X. |
| **Attempt** | Finalize Request Y with that signature. |
| **Current defense** | PDA, digest, and message binding. Tested. |
| **Residual risk** | None for cross-request reuse. |
| **Future mitigation** | — |

### Scenario D — attacker replaces ciphertext blob

| | |
| --- | --- |
| **Attacker capability** | Write access to the blob directory. |
| **Attempt** | Overwrite the file named by an on-chain hash. |
| **Current defense** | `BlobStore::get` rejects hash mismatch. A replacement that *matches* the hash is the same bytes. A new file with a new hash is irrelevant unless submit/finalize also change (owner-signed / operator-signed). |
| **Residual risk** | Deletion (availability). Owner who encrypts the wrong plaintext still gets a "valid" hash. |
| **Future mitigation** | Replicated store; input proofs. |

### Scenario E — compromised FHE operator returns incorrect encrypted result

| | |
| --- | --- |
| **Attacker capability** | Operator key and evaluation key. |
| **Attempt** | Encrypt `false` instead of `true` (or the reverse) and sign the correct binding. |
| **Current defense** | None for correctness. The coordinator will finalize. The owner may notice after local decrypt. |
| **Residual risk** | Integrity of `allowed` is entirely operator trust. |
| **Future mitigation** | Phase 7 verifiable or threshold evaluation. |

### Scenario F — ciphertext store loses blobs

| | |
| --- | --- |
| **Attacker capability** | Accidental loss or store deletion. |
| **Attempt** | Worker cannot load inputs; owner cannot decrypt. |
| **Current defense** | None beyond local backups. Chain still shows hashes and status. |
| **Residual risk** | Permanent loss of confidentiality *use* (data gone). Public metadata remains. |
| **Future mitigation** | Durable availability layer. |

### Scenario G — operator rotation while Request is Pending

| | |
| --- | --- |
| **Attacker capability** | Config authority calls `rotate_operator`. |
| **Attempt** | Old operator signature finalize; or new operator signs the old Request binding. |
| **Current defense** | `request.operator_epoch != config.operator_epoch` ⇒ `InvalidOperatorEpoch`. New operator's signature still fails that check because the Request's stored epoch is old. Owner can cancel; anyone can expire later. |
| **Residual risk** | Request stuck until cancel/expire. If authority is the attacker, they can also pause and rotate to themselves for *future* requests (account `key_version` still blocks submit unless it already matches). |
| **Future mitigation** | Rotation runbook; optional force-expire; split admin roles. |

---

## 10. OpenZeppelin Integration Boundary

This phase studies which security principles can inform an SVM-native
design; it is not a source-level port of the EVM implementation.

### OpenZeppelin Relayer

**IMPLEMENTED + DEVNET VALIDATED** (Phase 2)

Used only as Solana transaction delivery and fee payment
(`fee_payment_strategy = relayer`, instruction-array POST). Official
product: [OpenZeppelin Relayer v1.5.x](https://docs.openzeppelin.com/relayer/1.5.x/).
OpenZeppelin did not review or endorse this integration.

### OpenZeppelin Confidential Contracts

**SECURITY / ARCHITECTURAL REFERENCE**

Official library for Solidity confidential tokens and related
primitives on Zama fhEVM
([docs](https://docs.openzeppelin.com/confidential-contracts)).
OpenZeppelin states the library is provided as-is, is not formally
audited, is not in the Immunefi bounty, and has no backward-compatibility
guarantee. This repository does not vendor that source and does not
run those contracts on Solana.

ERC-7984 is a **draft** ERC for confidential fungible tokens via
`bytes32` pointers. It is a token interface, not an SVM program.

### OpenZeppelin Monitor

**PLANNED** (Phase 6)

Official Monitor is a separate service that can watch Solana among
other networks ([docs](https://docs.openzeppelin.com/monitor/1.3.x)).
It is not integrated. Monitoring would observe public account
fields; it would not verify FHE correctness.

---

## 11. Zama Integration Boundary

### TFHE-rs

**ACTUAL DEPENDENCY / ACTUAL COMPUTATION ENGINE**

Host crates use TFHE-rs 1.7.0 (`FheUint64`, `FheBool`,
`generate_keys`, `safe_serialize` / `safe_deserialize`). The
on-chain coordinator crate does not depend on `tfhe`. Official key
split: client key stays private; server key is given to the evaluator.

### FHEVM

**SECURITY / ARCHITECTURAL REFERENCE**

FHEVM is Zama's protocol for encrypted smart contracts on EVM-compatible
hosts: symbolic handles, ACL, coprocessors, Gateway, KMS. Official
docs describe coprocessors as majority-honest, staked, and
publicly committable. This repository does not run FHEVM, the
Gateway, or the KMS.

TFHE-rs is used directly for computation. FHEVM concepts are studied
to understand confidential-contract security patterns.

---

## 12. Phase 3 Conclusions

**Map well (A / tight B):** domain-separated request/result binding;
single-flight request lifecycle; fail-closed version/epoch/expiry
checks; separation of FHE operator vs fee payer; treating finalize
as commitment of an encrypted handle rather than a plaintext
decision; using a native signature precompile to authenticate an
off-chain message.

**Require SVM-specific adaptation (B):** submit → Pending → external
TFHE → independent finalize, because off-chain TFHE cannot finish
inside the submit transaction; PDA + signer constraints instead of
`msg.sender` + Solidity ACL; instruction-sysvar adjacency instead of
in-function `ecrecover`; SHA-256 content refs instead of FHEVM
handles; Relayer as a Solana fee payer rather than an FHE
coprocessor.

**Do not translate (C):** FHEVM per-handle ACL; ZKPoK
`fromExternal`; coprocessor majority / Gateway / KMS
`checkSignatures`; ERC-7984 encrypted balances and submit-time
receiver hooks that observe an already-computed FHE result; EVM
storage and event-driven execution; treating PDAs as ciphertext
capabilities.

**Intentionally deferred:** FHE correctness, multi-operator trust,
durable ciphertext availability, Token-2022 settlement, Monitor,
production upgrade governance. Phase 3 documents these gaps; it does
not close them.

The residual trust that remains in this repository is unchanged by
this document: one FHE operator for correctness and liveness;
Ed25519 for authenticity only; local blob availability; Config
authority and program upgrade authority.

---

## References

Primary sources consulted. Community tutorials were not used as the
basis for security claims.

### OpenZeppelin

- [Confidential Contracts (library overview and security notice)](https://docs.openzeppelin.com/confidential-contracts)
- [ERC-7984 usage in Confidential Contracts](https://docs.openzeppelin.com/confidential-contracts/token)
- [Confidential Contracts API — Token](https://docs.openzeppelin.com/confidential-contracts/api/token)
- [Confidential Contracts API — Utils (`HandleAccessManager`, `FHESafeMath`)](https://docs.openzeppelin.com/confidential-contracts/api/utils)
- [Confidential Contracts API — Interfaces](https://docs.openzeppelin.com/confidential-contracts/api/interfaces)
- [OpenZeppelin Relayer v1.5.x](https://docs.openzeppelin.com/relayer/1.5.x/)
- [OpenZeppelin Relayer v1.5.x — Solana integration](https://docs.openzeppelin.com/relayer/1.5.x/solana)
- [OpenZeppelin Relayer v1.5.x — API](https://docs.openzeppelin.com/relayer/1.5.x/api)
- [OpenZeppelin Monitor v1.3.x](https://docs.openzeppelin.com/monitor/1.3.x)
- [OpenZeppelin/openzeppelin-relayer (source)](https://github.com/OpenZeppelin/openzeppelin-relayer)
- [OpenZeppelin/openzeppelin-confidential-contracts (source)](https://github.com/OpenZeppelin/openzeppelin-confidential-contracts)

### Ethereum (ERC-7984 draft, Official EIP)

- [ERC-7984: Confidential Fungible Token (Draft)](https://eips.ethereum.org/EIPS/eip-7984)

### Zama

- [FHEVM Access Control List](https://docs.zama.org/protocol/solidity-guides/smart-contract/acl)
- [FHEVM Encrypted inputs](https://docs.zama.org/protocol/solidity-guides/smart-contract/inputs)
- [FHEVM Public decryption](https://docs.zama.org/protocol/solidity-guides/smart-contract/oracle)
- [Zama Protocol — Coprocessor](https://docs.zama.org/protocol/protocol/overview/coprocessor)
- [Zama Protocol — Gateway](https://docs.zama.org/protocol/protocol/overview/gateway)
- [FHEVM symbolic execution (handles)](https://docs.zama.org/protocol/solidity-guides/v0.10/coprocessor/docs/fundamentals/fhevm/symbolic_execution.md)
- [TFHE-rs documentation](https://docs.zama.org/tfhe-rs)
- [TFHE-rs configuration and key generation](https://docs.zama.org/tfhe-rs/fhe-computation/compute/configure-and-generate-keys)
- [zama-ai/tfhe-rs](https://github.com/zama-ai/tfhe-rs)
- [zama-ai/fhevm](https://github.com/zama-ai/fhevm)

### Solana

- [Accounts](https://solana.com/docs/core/accounts)
- [Transactions (atomicity)](https://solana.com/docs/core/transactions)
- [Instructions](https://solana.com/docs/core/instructions)
- [Instruction introspection](https://solana.com/docs/core/instructions/instruction-introspection)
- [Program Derived Addresses](https://solana.com/docs/core/pda)
- [Precompiled programs (Ed25519)](https://solana.com/docs/core/programs/precompiles)
- [Program deployment and loader-v3 upgrades](https://solana.com/docs/core/programs/program-deployment)
- [Agave Ed25519 precompile source](https://github.com/anza-xyz/agave/blob/v3.1.8/precompiles/src/ed25519.rs)

### This repository (implementation sources for §2–§3, §8 invariants)

- `programs/confidential-coordinator/src/lib.rs`
- `programs/confidential-coordinator/src/state.rs`
- `programs/confidential-coordinator/src/ed25519.rs`
- `crates/protocol/src/lib.rs`
- `crates/fhe-worker/src/lib.rs`
- `crates/client/src/devnet/finalize.rs`
- `crates/client/src/devnet/decode.rs`
- `crates/client/src/relayer/types.rs`
- `tests/integration/tests/program.rs`
