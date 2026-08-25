//! Fetch and independently verify on-chain coordinator state.
//!
//! `submit`, `fetch-request`, and `finalize` must never trust a locally
//! cached `request.json` blindly: the canonical request binding is always
//! reconstructed from the authoritative on-chain `Request` + `Config`
//! accounts, after checking account ownership, the Anchor discriminator,
//! the PDA derivations that tie config/account/request together, and the
//! stored request digest.

use std::str::FromStr;

use anchor_lang::AccountDeserialize;
use confidential_coordinator::state::{ConfidentialAccount, Config, Request};
use confidential_protocol as protocol;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use solana_address::Address;

use crate::devnet::rpc::RpcClient;
use crate::{request_pda, LabError, PROGRAM_ID};

pub fn parse_address(value: &str) -> Result<Address, LabError> {
    Address::from_str(value).map_err(|e| LabError(format!("invalid address '{value}': {e}")))
}

/// Require coordinator program ownership, then Anchor-deserialize (which
/// separately validates the 8-byte account discriminator).
pub fn decode_owned_account<T: AccountDeserialize>(
    address: &Address,
    owner: &str,
    data: &[u8],
    label: &str,
) -> Result<T, LabError> {
    let owner_address = Address::from_str(owner).map_err(|e| {
        LabError(format!(
            "{label} account {address} has invalid owner '{owner}': {e}"
        ))
    })?;
    if owner_address != PROGRAM_ID {
        return Err(LabError(format!(
            "{label} account {address} is owned by {owner_address} (expected coordinator program {PROGRAM_ID}); refusing to trust it"
        )));
    }
    let mut slice = data;
    T::try_deserialize(&mut slice).map_err(|e| {
        LabError(format!(
            "{label} account {address}: failed Anchor discriminator/deserialize check: {e}"
        ))
    })
}

/// Fetch an account and require it to be owned by the coordinator program
/// before attempting to Anchor-deserialize it.
fn fetch_and_decode<T: AccountDeserialize>(
    rpc: &RpcClient,
    address: &Address,
    label: &str,
) -> Result<T, LabError> {
    let account = rpc
        .get_account_info(&address.to_string())?
        .ok_or_else(|| LabError(format!("{label} account {address} does not exist")))?;
    decode_owned_account(address, &account.owner, &account.data, label)
}

pub fn account_exists(rpc: &RpcClient, address: &Address) -> Result<bool, LabError> {
    Ok(rpc.get_account_info(&address.to_string())?.is_some())
}

pub fn fetch_config(rpc: &RpcClient, address: &Address) -> Result<Config, LabError> {
    fetch_and_decode(rpc, address, "config")
}

pub fn fetch_account(rpc: &RpcClient, address: &Address) -> Result<ConfidentialAccount, LabError> {
    fetch_and_decode(rpc, address, "confidential account")
}

pub fn fetch_request_raw(rpc: &RpcClient, address: &Address) -> Result<Request, LabError> {
    fetch_and_decode(rpc, address, "request")
}

/// Everything needed to trust a request: the decoded on-chain accounts, the
/// reconstructed canonical binding, and confirmation that the on-chain
/// `request_digest` matches a fresh recomputation.
pub struct VerifiedRequest {
    pub config_address: Address,
    pub config: Config,
    pub account_address: Address,
    pub account: ConfidentialAccount,
    pub request_address: Address,
    pub request: Request,
    pub binding: protocol::RequestBinding,
}

/// Reconstruct the canonical `RequestBinding` the coordinator itself uses
/// (`protocol_version` / `domain_id` live on Config, not Request).
pub fn reconstruct_request_binding(
    config: &Config,
    config_address: Address,
    request: &Request,
    account_address: Address,
    request_address: Address,
) -> protocol::RequestBinding {
    protocol::RequestBinding {
        protocol_version: config.protocol_version,
        domain_id: config.domain_id,
        program_id: PROGRAM_ID.to_bytes(),
        config: config_address.to_bytes(),
        mint: request.mint.to_bytes(),
        confidential_account: account_address.to_bytes(),
        request_pda: request_address.to_bytes(),
        operation: request.operation,
        balance_hash: request.balance_hash,
        amount_hash: request.amount_hash,
        limit_hash: request.limit_hash,
        params_hash: request.params_hash,
        state_version: request.state_version,
        request_nonce: request.request_nonce,
        key_version: request.key_version,
        operator_epoch: request.operator_epoch,
        expiry_slot: request.expiry_slot,
    }
}

/// Relationship, PDA, and digest checks that do not require RPC. Pending-lock
/// fields are only required while the request is still `STATUS_PENDING`, so
/// historical Finalized/Cancelled/Expired requests remain readable after the
/// account lock advances.
pub fn verify_request_accounts(
    request_address: Address,
    request: &Request,
    config_address: Address,
    config: &Config,
    account_address: Address,
    account: &ConfidentialAccount,
) -> Result<protocol::RequestBinding, LabError> {
    require_eq_address(
        request.config,
        config_address,
        "request.config does not match provided config address",
    )?;
    require_eq_address(
        request.mint,
        config.mint,
        "request.mint does not match config.mint",
    )?;
    require_eq_address(
        request.confidential_account,
        account_address,
        "request.confidential_account does not match provided account address",
    )?;
    require_eq_address(
        account.config,
        config_address,
        "confidential account.config does not match config address",
    )?;
    require_eq_address(
        account.mint,
        config.mint,
        "confidential account.mint does not match config.mint",
    )?;
    if request.requester != account.owner {
        return Err(LabError(format!(
            "request.requester {} does not match confidential account.owner {}",
            request.requester, account.owner
        )));
    }
    if request.operation != config.operation {
        return Err(LabError(format!(
            "request.operation {} does not match config.operation {}",
            request.operation, config.operation
        )));
    }
    if request.params_hash != config.params_hash {
        return Err(LabError(
            "request.params_hash does not match config.params_hash".to_string(),
        ));
    }

    require_eq_address(
        config_address,
        derive_config(&request.mint),
        "request.config is not the config PDA derived from request.mint",
    )?;
    require_eq_address(
        account_address,
        derive_account(&request.mint, &account.owner),
        "request.confidential_account is not the account PDA derived from mint+owner",
    )?;
    require_eq_address(
        request_address,
        derive_request(&account_address, request.request_nonce),
        "request address is not the request PDA derived from account+nonce",
    )?;

    if request.status == protocol::STATUS_PENDING {
        require_eq_address(
            account.pending_request,
            request_address,
            "pending confidential account.pending_request does not equal this request",
        )?;
        if account.request_nonce != request.request_nonce {
            return Err(LabError(format!(
                "pending account.request_nonce {} does not equal request.request_nonce {}",
                account.request_nonce, request.request_nonce
            )));
        }
        if account.state_version != request.state_version {
            return Err(LabError(format!(
                "pending account.state_version {} does not equal request.state_version {}",
                account.state_version, request.state_version
            )));
        }
    }

    let binding = reconstruct_request_binding(
        config,
        config_address,
        request,
        account_address,
        request_address,
    );
    let recomputed = protocol::request_digest(&binding);
    if recomputed != request.request_digest {
        return Err(LabError(format!(
            "recomputed request_digest {} does not match on-chain stored digest {} for request {request_address}; refusing to trust reconstructed binding",
            hex::encode(recomputed),
            hex::encode(request.request_digest)
        )));
    }

    Ok(binding)
}

/// Fetch the `Request` PDA, its `Config` (domain_id/protocol_version live
/// there, not on `Request`), and its `ConfidentialAccount`; verify that the
/// PDA derivations for all three match the seeds the program itself would
/// use, and that the recomputed `request_digest` equals the value stored
/// on-chain at submit time.
pub fn fetch_and_verify_request(
    rpc: &RpcClient,
    request_address: Address,
) -> Result<VerifiedRequest, LabError> {
    let request = fetch_request_raw(rpc, &request_address)?;

    let config_address = request.config;
    let config = fetch_config(rpc, &config_address)?;

    let account_address = request.confidential_account;
    let account = fetch_account(rpc, &account_address)?;

    let binding = verify_request_accounts(
        request_address,
        &request,
        config_address,
        &config,
        account_address,
        &account,
    )?;

    Ok(VerifiedRequest {
        config_address,
        config,
        account_address,
        account,
        request_address,
        request,
        binding,
    })
}

pub fn derive_config(mint: &Address) -> Address {
    Address::find_program_address(&[protocol::SEED_CONFIG, mint.as_ref()], &PROGRAM_ID).0
}

pub fn derive_account(mint: &Address, owner: &Address) -> Address {
    Address::find_program_address(
        &[protocol::SEED_ACCOUNT, mint.as_ref(), owner.as_ref()],
        &PROGRAM_ID,
    )
    .0
}

pub fn derive_request(account: &Address, nonce: u64) -> Address {
    request_pda(account, nonce)
}

fn require_eq_address(actual: Address, expected: Address, message: &str) -> Result<(), LabError> {
    if actual != expected {
        return Err(LabError(format!(
            "{message} (found {actual}, expected {expected})"
        )));
    }
    Ok(())
}

pub fn status_label(status: u8) -> &'static str {
    match status {
        protocol::STATUS_PENDING => "pending",
        protocol::STATUS_FINALIZED => "finalized",
        protocol::STATUS_CANCELLED => "cancelled",
        protocol::STATUS_EXPIRED => "expired",
        _ => "unknown",
    }
}

pub fn verify_ed25519(
    pubkey_bytes: &[u8; 32],
    message: &[u8],
    signature_bytes: &[u8; 64],
) -> Result<(), LabError> {
    let verifying_key = VerifyingKey::from_bytes(pubkey_bytes)
        .map_err(|e| LabError(format!("invalid operator public key bytes: {e}")))?;
    let signature = Signature::from_bytes(signature_bytes);
    verifying_key.verify(message, &signature).map_err(|_| {
        LabError(
            "ed25519 signature in result.json does not verify against the canonical \
             encode_result message; refusing to finalize"
                .to_string(),
        )
    })
}

/// Parsed `result.json` fields used by finalize. Does not load any private key.
#[derive(Clone, Copy, Debug)]
pub struct ParsedResultFile {
    pub result_hash: [u8; 32],
    pub request_digest: [u8; 32],
    pub result_digest: [u8; 32],
    pub signature: [u8; 64],
    pub operator: [u8; 32],
    pub result_type: u8,
    pub circuit_id: u16,
}

pub fn parse_result_file(file: &fhe_worker::ResultFile) -> Result<ParsedResultFile, LabError> {
    Ok(ParsedResultFile {
        result_hash: parse_hex32_field(&file.result_hash, "result_hash")?,
        request_digest: parse_hex32_field(&file.request_digest, "request_digest")?,
        result_digest: parse_hex32_field(&file.result_digest, "result_digest")?,
        signature: parse_hex64_field(&file.signature, "signature")?,
        operator: parse_hex32_field(&file.operator, "operator")?,
        result_type: file.result_type,
        circuit_id: file.circuit_id,
    })
}

fn parse_hex32_field(value: &str, name: &str) -> Result<[u8; 32], LabError> {
    fhe_worker::parse_hex32(value)
        .map_err(|_| LabError(format!("invalid {name} hex in result.json")))
}

fn parse_hex64_field(value: &str, name: &str) -> Result<[u8; 64], LabError> {
    hex::decode(value)
        .map_err(|_| LabError(format!("invalid {name} hex in result.json")))?
        .try_into()
        .map_err(|_| LabError(format!("{name} in result.json is not 64 bytes")))
}

/// Build the `ResultBinding` that finalize will broadcast, using the
/// authoritative on-chain request binding (never `request.json`).
pub fn result_binding_from_authoritative(
    authoritative: &protocol::RequestBinding,
    parsed: &ParsedResultFile,
) -> protocol::ResultBinding {
    protocol::ResultBinding {
        request: *authoritative,
        request_digest: protocol::request_digest(authoritative),
        result_hash: parsed.result_hash,
        result_type: parsed.result_type,
        circuit_id: parsed.circuit_id,
    }
}

/// Local finalize gates that do not require a second RPC round-trip.
/// `request.json` is compared when present (worker cache) but is never the
/// binding used to construct the signed result message.
pub fn validate_finalize_consistency(
    verified: &VerifiedRequest,
    cached_request: Option<&protocol::RequestBinding>,
    parsed: &ParsedResultFile,
) -> Result<protocol::ResultBinding, LabError> {
    if let Some(cached) = cached_request {
        if verified.binding != *cached {
            return Err(LabError(
                "authoritative on-chain RequestBinding does not equal request.json; \
                 refusing to finalize from a stale or substituted worker cache"
                    .to_string(),
            ));
        }
    }
    if verified.request.status != protocol::STATUS_PENDING {
        return Err(LabError(format!(
            "request {} is {} (expected pending); refusing to finalize",
            verified.request_address,
            status_label(verified.request.status)
        )));
    }
    if verified.request.request_digest != parsed.request_digest {
        return Err(LabError(
            "on-chain request_digest does not equal result.json.request_digest; refusing to finalize"
                .to_string(),
        ));
    }
    if parsed.operator != verified.config.operator.to_bytes() {
        return Err(LabError(format!(
            "result.json operator {} does not match current Config.operator {}; refusing to finalize",
            hex::encode(parsed.operator),
            verified.config.operator
        )));
    }
    if parsed.result_type != protocol::RESULT_TYPE_FHE_BOOL {
        return Err(LabError(format!(
            "unexpected result_type {} in result.json (expected {})",
            parsed.result_type,
            protocol::RESULT_TYPE_FHE_BOOL
        )));
    }
    if parsed.circuit_id != verified.config.circuit_id {
        return Err(LabError(format!(
            "result.json circuit_id {} does not match Config.circuit_id {}",
            parsed.circuit_id, verified.config.circuit_id
        )));
    }

    let binding = result_binding_from_authoritative(&verified.binding, parsed);
    let recomputed_result_digest = protocol::result_digest(&binding);
    if recomputed_result_digest != parsed.result_digest {
        return Err(LabError(
            "result.json result_digest does not recompute correctly; refusing to finalize"
                .to_string(),
        ));
    }
    let message = protocol::encode_result(&binding);
    verify_ed25519(&parsed.operator, &message, &parsed.signature)?;
    Ok(binding)
}
