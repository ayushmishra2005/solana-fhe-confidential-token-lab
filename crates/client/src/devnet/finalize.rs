//! Transport-neutral finalize preparation and post-finalize verification.
//!
//! Direct JSON-RPC and OpenZeppelin Relayer both consume `PreparedFinalize`.
//! Security checks live here once; transports only deliver the resulting
//! `[ed25519, finalize]` instruction pair.

use std::path::Path;

use confidential_protocol as protocol;
use solana_address::Address;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_signer::Signer;

use crate::devnet::args::{flag, has_flag, require_flag};
use crate::devnet::decode::{
    fetch_and_verify_request, parse_address, parse_result_file, status_label,
    validate_finalize_consistency, ParsedResultFile, VerifiedRequest,
};
use crate::devnet::rpc::RpcClient;
use crate::devnet::state::DevnetState;
use crate::relayer::{
    instructions_to_specs, load_api_key_from_env, require_ed25519_immediately_before_finalize,
    require_ed25519_immediately_before_finalize_specs, OpenZeppelinRelayerClient, PollSettings,
    RelayerSubmitResult,
};
use crate::{data_paths, finalize_ixs_with_signature, read_request_file, LabError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinalizeTransport {
    Direct,
    OpenZeppelin {
        relayer_url: String,
        relayer_id: String,
    },
}

pub struct PreparedFinalize {
    pub request_address: Address,
    pub config_address: Address,
    pub account_address: Address,
    pub prior_state_version: u64,
    pub parsed: ParsedResultFile,
    pub binding: protocol::ResultBinding,
    pub result_hash: [u8; 32],
    pub result_digest: [u8; 32],
}

pub struct FinalizeOutcome {
    pub request_address: Address,
    pub result_hash: [u8; 32],
    pub result_digest: [u8; 32],
    pub solana_signature: Option<String>,
    pub relayer_transaction_id: Option<String>,
}

impl FinalizeTransport {
    pub fn from_args(args: &[String]) -> Result<Self, LabError> {
        if has_flag(args, "--api-key") || args.iter().any(|arg| arg.starts_with("--api-key=")) {
            return Err(LabError(
                "--api-key is not supported; set OPENZEPPELIN_RELAYER_API_KEY in the environment"
                    .to_string(),
            ));
        }
        match flag(args, "--transport").unwrap_or("direct") {
            "direct" => Ok(Self::Direct),
            "openzeppelin" => Ok(Self::OpenZeppelin {
                relayer_url: require_flag(args, "--relayer-url")?,
                relayer_id: require_flag(args, "--relayer-id")?,
            }),
            other => Err(LabError(format!(
                "unknown --transport {other}; expected direct or openzeppelin"
            ))),
        }
    }
}

pub fn resolve_request_address(
    args: &[String],
    state: &DevnetState,
    cached_request: Option<&protocol::RequestBinding>,
) -> Result<Address, LabError> {
    if let Some(value) = flag(args, "--request") {
        return parse_address(value);
    }
    if let Some(cached) = cached_request {
        return Ok(Address::new_from_array(cached.request_pda));
    }
    parse_address(state.latest_request.as_deref().ok_or_else(|| {
        LabError(
            "no --request, no request.json, and no cached latest_request in \
             devnet-state.json"
                .to_string(),
        )
    })?)
}

pub fn load_parsed_result(data_dir: &Path) -> Result<ParsedResultFile, LabError> {
    let paths = data_paths(data_dir);
    let result_file: fhe_worker::ResultFile =
        serde_json::from_slice(&std::fs::read(&paths.result).map_err(|e| {
            LabError(format!(
                "failed to read {}: {e} (run `evaluate` first)",
                paths.result.display()
            ))
        })?)
        .map_err(|e| LabError(e.to_string()))?;
    parse_result_file(&result_file)
}

pub fn load_cached_request(data_dir: &Path) -> Result<Option<protocol::RequestBinding>, LabError> {
    let paths = data_paths(data_dir);
    if paths.request.exists() {
        Ok(Some(read_request_file(&paths.request)?))
    } else {
        Ok(None)
    }
}

/// Shared security path used by every finalize transport.
pub fn prepare_finalize(
    rpc: &RpcClient,
    request_address: Address,
    cached_request: Option<&protocol::RequestBinding>,
    parsed: &ParsedResultFile,
) -> Result<PreparedFinalize, LabError> {
    let verified = fetch_and_verify_request(rpc, request_address)?;
    let binding = validate_finalize_consistency(&verified, cached_request, parsed)?;
    if verified.config.paused {
        return Err(LabError(format!(
            "config {} is paused; refusing to finalize",
            verified.config_address
        )));
    }
    Ok(PreparedFinalize {
        request_address: verified.request_address,
        config_address: verified.config_address,
        account_address: verified.account_address,
        prior_state_version: verified.account.state_version,
        parsed: *parsed,
        binding,
        result_hash: parsed.result_hash,
        result_digest: protocol::result_digest(&binding),
    })
}

impl PreparedFinalize {
    pub fn instructions_for_payer(&self, payer: Address) -> Result<[Instruction; 2], LabError> {
        let ixs = finalize_ixs_with_signature(
            payer,
            self.config_address,
            self.account_address,
            self.request_address,
            self.parsed.operator,
            self.parsed.signature,
            &self.binding,
        );
        require_ed25519_immediately_before_finalize(&ixs)?;
        Ok(ixs)
    }
}

/// Authoritative Request PDA checks after any successful transport delivery.
pub fn verify_authoritative_finalized(
    post: &VerifiedRequest,
    prepared: &PreparedFinalize,
) -> Result<(), LabError> {
    if post.request.status != protocol::STATUS_FINALIZED {
        return Err(LabError(format!(
            "request {} did not reach Finalized status after confirmation \
             (status: {})",
            prepared.request_address,
            status_label(post.request.status)
        )));
    }
    if post.request.result_hash != prepared.result_hash {
        return Err(LabError(
            "on-chain result_hash does not match result.json after finalize".to_string(),
        ));
    }
    if post.request.result_digest != prepared.result_digest {
        return Err(LabError(
            "on-chain result_digest does not match the recomputed digest after finalize"
                .to_string(),
        ));
    }
    if post.account.pending_request != Address::default() {
        return Err(LabError(format!(
            "confidential account {} still has pending_request {} after finalize",
            post.account_address, post.account.pending_request
        )));
    }
    let expected_version = prepared
        .prior_state_version
        .checked_add(1)
        .ok_or_else(|| LabError("state_version overflow after finalize".to_string()))?;
    if post.account.state_version != expected_version {
        return Err(LabError(format!(
            "confidential account {} state_version {} did not advance from {} to {expected_version}",
            post.account_address, post.account.state_version, prepared.prior_state_version
        )));
    }
    Ok(())
}

pub fn refetch_and_verify_finalized(
    rpc: &RpcClient,
    prepared: &PreparedFinalize,
) -> Result<VerifiedRequest, LabError> {
    let post = fetch_and_verify_request(rpc, prepared.request_address)?;
    verify_authoritative_finalized(&post, prepared)?;
    Ok(post)
}

pub fn deliver_direct(
    rpc: &RpcClient,
    prepared: &PreparedFinalize,
    payer: &Keypair,
    send: impl FnOnce(&RpcClient, &Keypair, &[Instruction]) -> Result<String, LabError>,
) -> Result<FinalizeOutcome, LabError> {
    let [verify_ix, finalize_ix] = prepared.instructions_for_payer(payer.pubkey())?;
    let signature = send(rpc, payer, &[verify_ix, finalize_ix])?;
    refetch_and_verify_finalized(rpc, prepared)?;
    Ok(FinalizeOutcome {
        request_address: prepared.request_address,
        result_hash: prepared.result_hash,
        result_digest: prepared.result_digest,
        solana_signature: Some(signature),
        relayer_transaction_id: None,
    })
}

pub fn deliver_openzeppelin(
    rpc: &RpcClient,
    prepared: &PreparedFinalize,
    relayer_url: &str,
    relayer_id: &str,
    poll: &PollSettings,
) -> Result<FinalizeOutcome, LabError> {
    let api_key = load_api_key_from_env()?;
    let client = OpenZeppelinRelayerClient::new(relayer_url, relayer_id, api_key)?;
    let relayer = client.validate_configured_relayer()?;
    let ixs = prepared.instructions_for_payer(relayer.address)?;
    let specs = instructions_to_specs(&ixs);
    // Submitted pair only; Relayer v1.5.0 does not insert between these ixs.
    require_ed25519_immediately_before_finalize_specs(&specs)?;
    let RelayerSubmitResult {
        transaction_id,
        solana_signature,
        ..
    } = client.submit_instructions_and_wait(&specs, poll)?;
    // Relayer success is not authoritative; re-read the Request PDA.
    refetch_and_verify_finalized(rpc, prepared)?;
    Ok(FinalizeOutcome {
        request_address: prepared.request_address,
        result_hash: prepared.result_hash,
        result_digest: prepared.result_digest,
        solana_signature,
        relayer_transaction_id: Some(transaction_id),
    })
}

pub fn print_openzeppelin_success(outcome: &FinalizeOutcome) {
    println!("OpenZeppelin Relayer transaction/job ID:");
    println!(
        "{}",
        outcome
            .relayer_transaction_id
            .as_deref()
            .unwrap_or("(not reported)")
    );
    println!();
    println!("Solana transaction signature:");
    println!(
        "{}",
        outcome
            .solana_signature
            .as_deref()
            .unwrap_or("(not reported)")
    );
    println!();
    println!("Request PDA:");
    println!("{}", outcome.request_address);
    println!();
    println!("status:");
    println!("Finalized");
    println!();
    println!("result_hash:");
    println!("{}", hex::encode(outcome.result_hash));
    println!();
    println!("result_digest:");
    println!("{}", hex::encode(outcome.result_digest));
}

/// Test helper: confirm a serialized finalize pair still encodes the worker
/// operator inside the Ed25519 instruction, not the Relayer payer.
pub fn ed25519_instruction_contains_operator(verify_ix: &Instruction, operator: &[u8; 32]) -> bool {
    verify_ix.program_id.to_string() == crate::relayer::ED25519_PROGRAM_ID_STR
        && verify_ix.data.windows(32).any(|window| window == operator)
}
