use std::path::{Path, PathBuf};
use std::str::FromStr;

use confidential_coordinator::state::{ConfidentialAccount, Config};
use confidential_protocol as protocol;
use solana_address::Address;
use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;

use crate::devnet::args::{flag, flag_hex32, flag_or, flag_u64_or};
use crate::devnet::decode::{
    account_exists, derive_account, derive_config, derive_request, fetch_account,
    fetch_and_verify_request, fetch_config, parse_address, status_label,
};
use crate::devnet::finalize::{
    deliver_direct, deliver_openzeppelin, load_cached_request, load_parsed_result,
    prepare_finalize, print_openzeppelin_success, resolve_request_address, FinalizeTransport,
};
use crate::devnet::rpc::RpcClient;
use crate::devnet::state::{
    default_keypair_path, expand_tilde, read_keypair_file, DevnetState,
    DEFAULT_MAX_REQUEST_LIFETIME_SLOTS,
};
use crate::relayer::PollSettings;
use crate::{
    create_account_ix, data_paths, initialize_ix, read_operator, submit_ix, write_request_file,
    LabError, ParamsFile, PROGRAM_ID,
};

fn signer_path(args: &[String], flag_name: &str, cached: Option<&str>) -> PathBuf {
    if let Some(value) = flag(args, flag_name) {
        return expand_tilde(value);
    }
    if let Some(cached) = cached {
        return expand_tilde(cached);
    }
    default_keypair_path()
}

fn send_ixs(rpc: &RpcClient, signer: &Keypair, ixs: &[Instruction]) -> Result<String, LabError> {
    let blockhash_str = rpc.get_latest_blockhash()?;
    let blockhash = Hash::from_str(&blockhash_str)
        .map_err(|e| LabError(format!("invalid blockhash '{blockhash_str}': {e}")))?;
    let message = Message::new(ixs, Some(&signer.pubkey()));
    let tx = Transaction::new(&[signer], message, blockhash);
    rpc.send_and_confirm(&tx)
}

fn optional_address_flag(args: &[String], name: &str) -> Result<Option<Address>, LabError> {
    flag(args, name).map(parse_address).transpose()
}

/// `devnet initialize`: create the `Config` PDA for a (possibly freshly
/// generated) synthetic Phase-1 mint identity. Never touches Token-2022.
pub fn cmd_initialize(data_dir: &Path, args: &[String]) -> Result<(), LabError> {
    let mut state = DevnetState::load(data_dir)?;
    let rpc_url = flag_or(args, "--rpc-url", &state.rpc_url());
    let rpc = RpcClient::new(rpc_url.clone())?;

    let authority_path = signer_path(args, "--authority", state.authority_keypair_path.as_deref());
    let authority = read_keypair_file(&authority_path)?;

    let mint = match optional_address_flag(args, "--mint")? {
        Some(mint) => mint,
        None => {
            let generated = Keypair::new().pubkey();
            println!(
                "generated synthetic Phase-1 mint identity (NOT a Token-2022 mint, no on-chain \
                 mint account): {generated}"
            );
            generated
        }
    };

    let config = derive_config(&mint);
    if account_exists(&rpc, &config)? {
        return Err(LabError(format!(
            "config {config} already exists for mint {mint}; run `devnet inspect --config {config}` \
             instead of re-initializing"
        )));
    }

    let paths = data_paths(data_dir);
    let params: ParamsFile =
        serde_json::from_slice(&std::fs::read(&paths.params).map_err(|e| {
            LabError(format!(
                "failed to read {}: {e} (run `setup` first)",
                paths.params.display()
            ))
        })?)
        .map_err(|e| LabError(e.to_string()))?;
    let params_hash = fhe_worker::parse_hex32(&params.params_hash)
        .map_err(|_| LabError("invalid params_hash in params.json".to_string()))?;
    let operator = read_operator(&paths.operator)?;
    let operator_pubkey = operator.pubkey();

    let max_request_lifetime_slots = flag_u64_or(
        args,
        "--max-request-lifetime-slots",
        DEFAULT_MAX_REQUEST_LIFETIME_SLOTS,
    )?;

    let ix = initialize_ix(
        authority.pubkey(),
        mint,
        config,
        operator_pubkey,
        params_hash,
        max_request_lifetime_slots,
    );
    let signature = send_ixs(&rpc, &authority, &[ix])?;
    println!("initialize_config confirmed: {signature}");
    println!("config: {config}");

    state.rpc_url = Some(rpc_url);
    state.program_id = Some(PROGRAM_ID.to_string());
    state.mint = Some(mint.to_string());
    state.config = Some(config.to_string());
    state.authority = Some(authority.pubkey().to_string());
    state.operator = Some(operator_pubkey.to_string());
    state.params_hash = Some(params.params_hash.clone());
    state.key_version = Some(params.key_version);
    state.max_request_lifetime_slots = Some(max_request_lifetime_slots);
    state.authority_keypair_path = Some(authority_path.display().to_string());
    state.save(data_dir)?;
    Ok(())
}

/// `devnet create-account`: create the owner's `ConfidentialAccount` PDA
/// under the mint identity/config recorded by `initialize`.
pub fn cmd_create_account(data_dir: &Path, args: &[String]) -> Result<(), LabError> {
    let mut state = DevnetState::load(data_dir)?;
    let rpc_url = flag_or(args, "--rpc-url", &state.rpc_url());
    let rpc = RpcClient::new(rpc_url.clone())?;

    let mint = parse_address(state.mint.as_deref().ok_or_else(|| {
        LabError("no mint recorded in devnet-state.json; run `devnet initialize` first".to_string())
    })?)?;
    let config = parse_address(state.config.as_deref().ok_or_else(|| {
        LabError(
            "no config recorded in devnet-state.json; run `devnet initialize` first".to_string(),
        )
    })?)?;

    let owner_path = signer_path(args, "--owner", state.owner_keypair_path.as_deref());
    let owner = read_keypair_file(&owner_path)?;

    let account = derive_account(&mint, &owner.pubkey());
    if account_exists(&rpc, &account)? {
        return Err(LabError(format!(
            "confidential account {account} already exists for owner {}; run \
             `devnet inspect --account {account}` instead of re-creating it",
            owner.pubkey()
        )));
    }

    let balance_hash = flag_hex32(args, "--balance-hash")?;
    let limit_hash = flag_hex32(args, "--limit-hash")?;

    let ix = create_account_ix(owner.pubkey(), config, account, balance_hash, limit_hash);
    let signature = send_ixs(&rpc, &owner, &[ix])?;
    println!("create_account confirmed: {signature}");
    println!("account: {account}");

    state.rpc_url = Some(rpc_url);
    state.owner = Some(owner.pubkey().to_string());
    state.account = Some(account.to_string());
    state.owner_keypair_path = Some(owner_path.display().to_string());
    state.save(data_dir)?;
    Ok(())
}

/// `devnet submit`: fetch authoritative on-chain `Config`/`ConfidentialAccount`
/// state, submit the next request, then fetch+verify the resulting `Request`
/// PDA and write `request.json` for `evaluate`.
pub fn cmd_submit(data_dir: &Path, args: &[String]) -> Result<(), LabError> {
    let mut state = DevnetState::load(data_dir)?;
    let rpc_url = flag_or(args, "--rpc-url", &state.rpc_url());
    let rpc = RpcClient::new(rpc_url.clone())?;

    let owner_path = signer_path(args, "--owner", state.owner_keypair_path.as_deref());
    let owner = read_keypair_file(&owner_path)?;

    let config_address = parse_address(state.config.as_deref().ok_or_else(|| {
        LabError(
            "no config recorded in devnet-state.json; run `devnet initialize` first".to_string(),
        )
    })?)?;
    let account_address = parse_address(state.account.as_deref().ok_or_else(|| {
        LabError(
            "no confidential account recorded in devnet-state.json; run `devnet create-account` first"
                .to_string(),
        )
    })?)?;

    let config: Config = fetch_config(&rpc, &config_address)?;
    let account: ConfidentialAccount = fetch_account(&rpc, &account_address)?;

    if config.paused {
        return Err(LabError(format!(
            "config {config_address} is paused; cannot submit"
        )));
    }
    if account.config != config_address {
        return Err(LabError(format!(
            "confidential account {account_address}.config does not match {config_address}"
        )));
    }
    if account.mint != config.mint {
        return Err(LabError(format!(
            "confidential account {account_address}.mint does not match config.mint"
        )));
    }
    if account.owner != owner.pubkey() {
        return Err(LabError(format!(
            "confidential account {account_address} is owned by {}, not the provided --owner {}",
            account.owner,
            owner.pubkey()
        )));
    }
    if account.key_version != config.key_version {
        return Err(LabError(format!(
            "confidential account key_version {} does not match config key_version {}",
            account.key_version, config.key_version
        )));
    }
    if account.pending_request != Address::default() {
        return Err(LabError(format!(
            "confidential account {account_address} already has a pending request {}; \
             finalize, cancel, or wait for expiry before submitting again",
            account.pending_request
        )));
    }

    let amount_hash = flag_hex32(args, "--amount-hash")?;
    let expected_state_version = account.state_version;
    let expected_nonce = account
        .request_nonce
        .checked_add(1)
        .ok_or_else(|| LabError("request nonce overflow".to_string()))?;
    let request_address = derive_request(&account_address, expected_nonce);

    let ix = submit_ix(
        owner.pubkey(),
        config_address,
        account_address,
        request_address,
        amount_hash,
        expected_state_version,
        expected_nonce,
    );
    let signature = send_ixs(&rpc, &owner, &[ix])?;
    println!("submit confirmed: {signature}");
    println!("request: {request_address} (nonce {expected_nonce})");

    let verified = fetch_and_verify_request(&rpc, request_address)?;
    let paths = data_paths(data_dir);
    write_request_file(&paths.request, &verified.binding)?;
    println!("wrote {}", paths.request.display());

    state.rpc_url = Some(rpc_url);
    state.owner = Some(owner.pubkey().to_string());
    state.owner_keypair_path = Some(owner_path.display().to_string());
    state.latest_request = Some(request_address.to_string());
    state.latest_request_nonce = Some(expected_nonce);
    state.save(data_dir)?;
    Ok(())
}

/// `devnet fetch-request`: standalone/repeatable fetch+verify+reconstruct,
/// e.g. to hand `request.json` to a worker running on another machine.
pub fn cmd_fetch_request(data_dir: &Path, args: &[String]) -> Result<(), LabError> {
    let state = DevnetState::load(data_dir)?;
    let rpc_url = flag_or(args, "--rpc-url", &state.rpc_url());
    let rpc = RpcClient::new(rpc_url)?;

    let request_address = match optional_address_flag(args, "--request")? {
        Some(address) => address,
        None => parse_address(state.latest_request.as_deref().ok_or_else(|| {
            LabError(
                "no --request given and no cached latest_request in devnet-state.json".to_string(),
            )
        })?)?,
    };

    let verified = fetch_and_verify_request(&rpc, request_address)?;
    let paths = data_paths(data_dir);
    write_request_file(&paths.request, &verified.binding)?;
    println!(
        "verified request {request_address} (status: {}); wrote {}",
        status_label(verified.request.status),
        paths.request.display()
    );
    Ok(())
}

/// `devnet finalize`: consume the worker's existing `result.json` signature
/// as-is (never re-signs, never loads the operator's private key). The
/// signed `ResultBinding` is built from a freshly fetched on-chain Request,
/// not from `request.json` (worker cache only).
///
/// `--transport direct` (default) submits over JSON-RPC. `--transport
/// openzeppelin` delivers the same prepared instructions through OpenZeppelin
/// Relayer. Both paths share `prepare_finalize` and post-finalize PDA checks.
pub fn cmd_finalize(data_dir: &Path, args: &[String]) -> Result<(), LabError> {
    let mut state = DevnetState::load(data_dir)?;
    let transport = FinalizeTransport::from_args(args)?;
    let rpc_url = flag_or(args, "--rpc-url", &state.rpc_url());
    let rpc = RpcClient::new(rpc_url.clone())?;

    let parsed = load_parsed_result(data_dir)?;
    let cached_request = load_cached_request(data_dir)?;
    let request_address = resolve_request_address(args, &state, cached_request.as_ref())?;
    let prepared = prepare_finalize(&rpc, request_address, cached_request.as_ref(), &parsed)?;

    match transport {
        FinalizeTransport::Direct => {
            let payer_path = signer_path(args, "--payer", state.payer_keypair_path.as_deref());
            let payer = read_keypair_file(&payer_path)?;
            let outcome = deliver_direct(&rpc, &prepared, &payer, send_ixs)?;
            let signature = outcome
                .solana_signature
                .as_deref()
                .unwrap_or("(not reported)");
            println!("finalize confirmed: {signature}");
            println!("verified on-chain: status=finalized, result_hash and result_digest match");
            state.rpc_url = Some(rpc_url);
            state.payer_keypair_path = Some(payer_path.display().to_string());
            state.save(data_dir)?;
        }
        FinalizeTransport::OpenZeppelin {
            relayer_url,
            relayer_id,
        } => {
            let outcome = deliver_openzeppelin(
                &rpc,
                &prepared,
                &relayer_url,
                &relayer_id,
                &PollSettings::default(),
            )?;
            print_openzeppelin_success(&outcome);
            state.rpc_url = Some(rpc_url);
            state.latest_relayer_transaction_id = outcome.relayer_transaction_id;
            state.latest_solana_signature = outcome.solana_signature;
            state.save(data_dir)?;
        }
    }
    Ok(())
}

/// `devnet inspect`: fetch and pretty-print decoded on-chain state.
pub fn cmd_inspect(data_dir: &Path, args: &[String]) -> Result<(), LabError> {
    let state = DevnetState::load(data_dir)?;
    let rpc_url = flag_or(args, "--rpc-url", &state.rpc_url());
    let rpc = RpcClient::new(rpc_url)?;

    let config_address = match optional_address_flag(args, "--config")? {
        Some(address) => Some(address),
        None => state.config.as_deref().map(parse_address).transpose()?,
    };
    if let Some(config_address) = config_address {
        match fetch_config(&rpc, &config_address) {
            Ok(config) => {
                println!("config {config_address}:");
                println!("  authority: {}", config.authority);
                println!(
                    "  mint (synthetic Phase-1 identity, not Token-2022): {}",
                    config.mint
                );
                println!(
                    "  operator: {} (epoch {})",
                    config.operator, config.operator_epoch
                );
                println!("  key_version: {}", config.key_version);
                println!("  params_hash: {}", hex::encode(config.params_hash));
                println!(
                    "  max_request_lifetime_slots: {}",
                    config.max_request_lifetime_slots
                );
                println!("  paused: {}", config.paused);
            }
            Err(err) => println!("config {config_address}: {err}"),
        }
    } else {
        println!("no config address known; pass --config or run `devnet initialize`");
    }

    let account_address = match optional_address_flag(args, "--account")? {
        Some(address) => Some(address),
        None => state.account.as_deref().map(parse_address).transpose()?,
    };
    if let Some(account_address) = account_address {
        match fetch_account(&rpc, &account_address) {
            Ok(account) => {
                println!("confidential account {account_address}:");
                println!("  owner: {}", account.owner);
                println!("  balance_ref: {}", hex::encode(account.balance_ref));
                println!("  limit_ref: {}", hex::encode(account.limit_ref));
                println!("  state_version: {}", account.state_version);
                println!("  request_nonce: {}", account.request_nonce);
                println!("  pending_request: {}", account.pending_request);
                println!("  key_version: {}", account.key_version);
            }
            Err(err) => println!("confidential account {account_address}: {err}"),
        }
    } else {
        println!(
            "no confidential account address known; pass --account or run `devnet create-account`"
        );
    }

    let request_address = match optional_address_flag(args, "--request")? {
        Some(address) => Some(address),
        None => state
            .latest_request
            .as_deref()
            .map(parse_address)
            .transpose()?,
    };
    if let Some(request_address) = request_address {
        match fetch_and_verify_request(&rpc, request_address) {
            Ok(verified) => {
                let request = &verified.request;
                println!("request {request_address}:");
                println!("  status: {}", status_label(request.status));
                println!("  requester: {}", request.requester);
                println!("  nonce: {}", request.request_nonce);
                println!(
                    "  created_slot: {}, expiry_slot: {}",
                    request.created_slot, request.expiry_slot
                );
                println!("  result_hash: {}", hex::encode(request.result_hash));
                println!("  result_digest: {}", hex::encode(request.result_digest));
                if let Ok(slot) = rpc.get_slot() {
                    let stale =
                        slot >= request.expiry_slot && request.status == protocol::STATUS_PENDING;
                    println!(
                        "  current_slot: {slot}{}",
                        if stale {
                            " (past expiry; pending request is stale)"
                        } else {
                            ""
                        }
                    );
                }
            }
            Err(err) => println!("request {request_address}: {err}"),
        }
    } else {
        println!("no request address known; pass --request or run `devnet submit`/`fetch-request`");
    }

    Ok(())
}
