use std::path::PathBuf;

use anchor_lang::AccountSerialize;
use confidential_coordinator::state::{ConfidentialAccount, Config, Request};
use confidential_protocol as protocol;
use serde_json::json;
use solana_address::Address;
use solana_keypair::Keypair;
use solana_signer::Signer;

use crate::devnet::decode::{
    decode_owned_account, derive_account, derive_config, derive_request, parse_result_file,
    reconstruct_request_binding, result_binding_from_authoritative, validate_finalize_consistency,
    verify_ed25519, verify_request_accounts, ParsedResultFile, VerifiedRequest,
};
use crate::devnet::rpc::rpc_error_to_lab_error;
use crate::devnet::state::{
    default_keypair_path_with_home, expand_tilde_with_home, state_path, DevnetState,
    DEFAULT_DEVNET_RPC_URL,
};
use crate::PROGRAM_ID;

const BALANCE: [u8; 32] = [0xb1; 32];
const AMOUNT: [u8; 32] = [0xa1; 32];
const LIMIT: [u8; 32] = [0xc1; 32];
const PARAMS: [u8; 32] = [0xaa; 32];
const RESULT: [u8; 32] = [0xd1; 32];

struct Fixture {
    operator: Keypair,
    config_address: Address,
    account_address: Address,
    request_address: Address,
    config: Config,
    account: ConfidentialAccount,
    request: Request,
}

impl Fixture {
    fn pending() -> Self {
        let authority = Keypair::new();
        let owner = Keypair::new();
        let operator = Keypair::new();
        let mint = Keypair::new().pubkey();
        let config_address = derive_config(&mint);
        let account_address = derive_account(&mint, &owner.pubkey());
        let nonce = 1u64;
        let request_address = derive_request(&account_address, nonce);

        let config = Config {
            authority: authority.pubkey(),
            mint,
            domain_id: protocol::local_domain_id(),
            operator: operator.pubkey(),
            operator_epoch: 1,
            key_version: 1,
            params_hash: PARAMS,
            operation: protocol::OPERATION_POLICY_CHECK,
            circuit_id: protocol::CIRCUIT_POLICY_V1,
            protocol_version: protocol::PROTOCOL_VERSION,
            max_request_lifetime_slots: 10_000,
            paused: false,
            bump: 255,
        };
        let account = ConfidentialAccount {
            config: config_address,
            mint,
            owner: owner.pubkey(),
            balance_ref: BALANCE,
            limit_ref: LIMIT,
            state_version: 0,
            request_nonce: nonce,
            pending_request: request_address,
            key_version: 1,
            bump: 255,
        };
        let request = Request {
            requester: owner.pubkey(),
            config: config_address,
            mint,
            confidential_account: account_address,
            operation: protocol::OPERATION_POLICY_CHECK,
            balance_hash: BALANCE,
            amount_hash: AMOUNT,
            limit_hash: LIMIT,
            params_hash: PARAMS,
            state_version: 0,
            request_nonce: nonce,
            key_version: 1,
            operator_epoch: 1,
            created_slot: 10,
            expiry_slot: 10_010,
            status: protocol::STATUS_PENDING,
            request_digest: [0u8; 32],
            result_hash: [0u8; 32],
            result_digest: [0u8; 32],
            bump: 255,
        };
        let mut fixture = Self {
            operator,
            config_address,
            account_address,
            request_address,
            config,
            account,
            request,
        };
        fixture.seal_digest();
        fixture
    }

    fn binding(&self) -> protocol::RequestBinding {
        reconstruct_request_binding(
            &self.config,
            self.config_address,
            &self.request,
            self.account_address,
            self.request_address,
        )
    }

    fn seal_digest(&mut self) {
        self.request.request_digest = protocol::request_digest(&self.binding());
    }

    fn into_verified(self) -> VerifiedRequest {
        let binding = self.binding();
        VerifiedRequest {
            config_address: self.config_address,
            config: self.config,
            account_address: self.account_address,
            account: self.account,
            request_address: self.request_address,
            request: self.request,
            binding,
        }
    }
}

fn signed_result(fixture: &Fixture) -> (protocol::ResultBinding, ParsedResultFile) {
    let request = fixture.binding();
    let binding = protocol::ResultBinding {
        request_digest: protocol::request_digest(&request),
        request,
        result_hash: RESULT,
        result_type: protocol::RESULT_TYPE_FHE_BOOL,
        circuit_id: protocol::CIRCUIT_POLICY_V1,
    };
    let message = protocol::encode_result(&binding);
    let signature = fixture.operator.sign_message(&message);
    let signature_bytes: [u8; 64] = signature.as_ref().try_into().expect("ed25519 signature");
    let file = fhe_worker::ResultFile {
        result_hash: hex::encode(RESULT),
        result_type: protocol::RESULT_TYPE_FHE_BOOL,
        circuit_id: protocol::CIRCUIT_POLICY_V1,
        request_digest: hex::encode(binding.request_digest),
        result_digest: hex::encode(protocol::result_digest(&binding)),
        signature: hex::encode(signature_bytes),
        operator: hex::encode(fixture.operator.pubkey().to_bytes()),
    };
    (binding, parse_result_file(&file).expect("parse result"))
}

#[test]
fn default_rpc_url_is_literal_devnet_endpoint() {
    assert_eq!(DEFAULT_DEVNET_RPC_URL, "https://api.devnet.solana.com");
}

#[test]
fn devnet_state_roundtrip_has_no_private_key_bytes() {
    let dir = std::env::temp_dir().join(format!(
        "ctl-devnet-state-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let state = DevnetState {
        rpc_url: Some(DEFAULT_DEVNET_RPC_URL.to_string()),
        program_id: Some(PROGRAM_ID.to_string()),
        mint: Some("Mint111111111111111111111111111111111111111".to_string()),
        config: Some("Cfg1111111111111111111111111111111111111111".to_string()),
        account: Some("Acc1111111111111111111111111111111111111111".to_string()),
        owner: Some("Own1111111111111111111111111111111111111111".to_string()),
        authority: Some("Auth111111111111111111111111111111111111111".to_string()),
        operator: Some("Oper111111111111111111111111111111111111111".to_string()),
        params_hash: Some(hex::encode([0xab; 32])),
        key_version: Some(1),
        max_request_lifetime_slots: Some(10_000),
        latest_request: Some("Req1111111111111111111111111111111111111111".to_string()),
        latest_request_nonce: Some(1),
        payer_keypair_path: Some("~/.config/solana/id.json".to_string()),
        authority_keypair_path: Some("/tmp/authority.json".to_string()),
        owner_keypair_path: Some("/tmp/owner.json".to_string()),
    };
    state.save(&dir).unwrap();
    let loaded = DevnetState::load(&dir).unwrap();
    assert_eq!(loaded.rpc_url, state.rpc_url);
    assert_eq!(loaded.latest_request_nonce, Some(1));
    assert_eq!(
        loaded.payer_keypair_path.as_deref(),
        Some("~/.config/solana/id.json")
    );

    let raw = std::fs::read_to_string(state_path(&dir)).unwrap();
    let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let object = value.as_object().expect("object");
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    let mut expected = [
        "rpc_url",
        "program_id",
        "mint",
        "config",
        "account",
        "owner",
        "authority",
        "operator",
        "params_hash",
        "key_version",
        "max_request_lifetime_slots",
        "latest_request",
        "latest_request_nonce",
        "payer_keypair_path",
        "authority_keypair_path",
        "owner_keypair_path",
    ];
    expected.sort_unstable();
    assert_eq!(keys, expected);
    for key in &keys {
        let lower = key.to_ascii_lowercase();
        assert!(
            !lower.contains("secret") && !lower.contains("private") && !lower.ends_with("_bytes"),
            "unexpected secret-like field {key}"
        );
    }
    for path_field in [
        "payer_keypair_path",
        "authority_keypair_path",
        "owner_keypair_path",
    ] {
        assert!(
            object[path_field].is_string(),
            "{path_field} must be a path string, not key bytes"
        );
        assert!(
            !object[path_field].is_array(),
            "{path_field} must not store a JSON byte array"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn tilde_and_default_keypair_paths() {
    assert_eq!(
        expand_tilde_with_home("~/keys/id.json", Some("/Users/me")),
        PathBuf::from("/Users/me/keys/id.json")
    );
    assert_eq!(
        expand_tilde_with_home("/abs/id.json", Some("/Users/me")),
        PathBuf::from("/abs/id.json")
    );
    assert_eq!(
        expand_tilde_with_home("rel/id.json", Some("/Users/me")),
        PathBuf::from("rel/id.json")
    );
    assert_eq!(
        expand_tilde_with_home("~/id.json", None),
        PathBuf::from("~/id.json")
    );
    assert_eq!(
        default_keypair_path_with_home(Some("/Users/me")),
        PathBuf::from("/Users/me/.config/solana/id.json")
    );
    assert_eq!(
        default_keypair_path_with_home(None),
        PathBuf::from(".config/solana/id.json")
    );
}

#[test]
fn pda_helpers_are_deterministic_and_reuse_request_pda() {
    let mint = Address::new_unique();
    let owner = Address::new_unique();
    assert_eq!(derive_config(&mint), derive_config(&mint));
    assert_ne!(derive_config(&mint), derive_config(&owner));
    let account = derive_account(&mint, &owner);
    assert_eq!(account, derive_account(&mint, &owner));
    assert_ne!(account, derive_account(&owner, &mint));
    assert_eq!(derive_request(&account, 7), crate::request_pda(&account, 7));
    assert_ne!(derive_request(&account, 7), derive_request(&account, 8));
}

#[test]
fn request_binding_reconstruction_and_digest_mismatch() {
    let mut fixture = Fixture::pending();
    let binding = verify_request_accounts(
        fixture.request_address,
        &fixture.request,
        fixture.config_address,
        &fixture.config,
        fixture.account_address,
        &fixture.account,
    )
    .expect("valid fixture");
    assert_eq!(binding, fixture.binding());
    assert_eq!(binding.request_pda, fixture.request_address.to_bytes());

    fixture.request.request_digest[0] ^= 1;
    let err = verify_request_accounts(
        fixture.request_address,
        &fixture.request,
        fixture.config_address,
        &fixture.config,
        fixture.account_address,
        &fixture.account,
    )
    .expect_err("digest mismatch");
    assert!(
        err.to_string().contains("recomputed request_digest"),
        "{err}"
    );
}

#[test]
fn historical_finalized_request_survives_account_lock_release() {
    let mut fixture = Fixture::pending();
    fixture.request.status = protocol::STATUS_FINALIZED;
    fixture.account.pending_request = Address::default();
    fixture.account.state_version = fixture.request.state_version + 1;
    verify_request_accounts(
        fixture.request_address,
        &fixture.request,
        fixture.config_address,
        &fixture.config,
        fixture.account_address,
        &fixture.account,
    )
    .expect("historical finalized request must remain readable");
}

#[test]
fn pending_request_rejects_stale_account_lock() {
    let mut fixture = Fixture::pending();
    fixture.account.pending_request = Address::default();
    let err = verify_request_accounts(
        fixture.request_address,
        &fixture.request,
        fixture.config_address,
        &fixture.config,
        fixture.account_address,
        &fixture.account,
    )
    .expect_err("pending lock mismatch");
    assert!(err.to_string().contains("pending_request"), "{err}");
}

#[test]
fn requester_must_match_account_owner() {
    let mut fixture = Fixture::pending();
    fixture.request.requester = Keypair::new().pubkey();
    fixture.seal_digest();
    let err = verify_request_accounts(
        fixture.request_address,
        &fixture.request,
        fixture.config_address,
        &fixture.config,
        fixture.account_address,
        &fixture.account,
    )
    .expect_err("requester mismatch");
    assert!(err.to_string().contains("request.requester"), "{err}");
}

#[test]
fn decode_rejects_wrong_owner_and_malformed_discriminator() {
    let fixture = Fixture::pending();
    let mut data = Vec::new();
    fixture.config.try_serialize(&mut data).unwrap();

    decode_owned_account::<Config>(
        &fixture.config_address,
        &PROGRAM_ID.to_string(),
        &data,
        "config",
    )
    .expect("valid coordinator-owned config");

    let stranger = Keypair::new().pubkey().to_string();
    match decode_owned_account::<Config>(&fixture.config_address, &stranger, &data, "config") {
        Ok(_) => panic!("wrong owner must be rejected"),
        Err(owner_err) => assert!(owner_err.to_string().contains("owned by"), "{owner_err}"),
    }

    data[0] ^= 0xff;
    match decode_owned_account::<Config>(
        &fixture.config_address,
        &PROGRAM_ID.to_string(),
        &data,
        "config",
    ) {
        Ok(_) => panic!("bad discriminator must be rejected"),
        Err(disc_err) => assert!(
            disc_err
                .to_string()
                .contains("Anchor discriminator/deserialize"),
            "{disc_err}"
        ),
    }
}

#[test]
fn finalize_accepts_valid_worker_signature_against_authoritative_binding() {
    let fixture = Fixture::pending();
    let (expected, parsed) = signed_result(&fixture);
    let cached = fixture.binding();
    let verified = fixture.into_verified();
    let binding = validate_finalize_consistency(&verified, Some(&cached), &parsed).unwrap();
    assert_eq!(binding, expected);
    assert_eq!(
        result_binding_from_authoritative(&verified.binding, &parsed).request,
        verified.binding
    );
}

#[test]
fn finalize_rejects_stale_request_cache_and_non_pending_status() {
    let fixture = Fixture::pending();
    let (_expected, parsed) = signed_result(&fixture);
    let mut cached = fixture.binding();
    cached.request_nonce = cached.request_nonce.wrapping_add(1);
    let err = validate_finalize_consistency(&fixture.into_verified(), Some(&cached), &parsed)
        .expect_err("stale cache");
    assert!(err.to_string().contains("request.json"), "{err}");

    let mut finalized = Fixture::pending();
    let parsed = signed_result(&finalized).1;
    finalized.request.status = protocol::STATUS_FINALIZED;
    let err = validate_finalize_consistency(&finalized.into_verified(), None, &parsed)
        .expect_err("not pending");
    assert!(err.to_string().contains("expected pending"), "{err}");
}

#[test]
fn finalize_rejects_modified_message_signature_or_operator() {
    let fixture = Fixture::pending();
    let cached = fixture.binding();

    let mut bad_hash = signed_result(&fixture).1;
    bad_hash.result_hash[0] ^= 1;
    let err = validate_finalize_consistency(&fixture.into_verified(), Some(&cached), &bad_hash)
        .expect_err("modified result hash");
    assert!(
        err.to_string().contains("result_digest") || err.to_string().contains("ed25519"),
        "{err}"
    );

    let fixture = Fixture::pending();
    let cached = fixture.binding();
    let mut bad_sig = signed_result(&fixture).1;
    bad_sig.signature[0] ^= 1;
    let err = validate_finalize_consistency(&fixture.into_verified(), Some(&cached), &bad_sig)
        .expect_err("modified signature");
    assert!(err.to_string().contains("ed25519"), "{err}");

    let fixture = Fixture::pending();
    let cached = fixture.binding();
    let mut bad_op = signed_result(&fixture).1;
    bad_op.operator = Keypair::new().pubkey().to_bytes();
    let err = validate_finalize_consistency(&fixture.into_verified(), Some(&cached), &bad_op)
        .expect_err("modified operator");
    assert!(err.to_string().contains("operator"), "{err}");
}

#[test]
fn local_ed25519_rejects_modified_message() {
    let fixture = Fixture::pending();
    let (binding, parsed) = signed_result(&fixture);
    let message = protocol::encode_result(&binding);
    verify_ed25519(&parsed.operator, &message, &parsed.signature).unwrap();

    let mut tweaked = binding;
    tweaked.result_hash[0] ^= 1;
    let err = verify_ed25519(
        &parsed.operator,
        &protocol::encode_result(&tweaked),
        &parsed.signature,
    )
    .expect_err("modified message");
    assert!(err.to_string().contains("ed25519"), "{err}");
}

#[test]
fn rpc_error_parsing_surfaces_simulation_logs() {
    let error = json!({
        "code": -32002,
        "message": "Transaction simulation failed: Error processing Instruction 0",
        "data": {
            "err": { "InstructionError": [0, { "Custom": 17 }] },
            "logs": [
                "Program 2xNTgr7PmWSQRqGcMuCVhdTQLRP8bexVHGJ2CjxiJM6X invoke [1]",
                "Program log: AnchorError thrown in programs/confidential-coordinator/src/lib.rs:321. Error Code: InvalidStatus."
            ]
        }
    });
    let err = rpc_error_to_lab_error("sendTransaction", &error);
    let message = err.to_string();
    assert!(
        message.contains("sendTransaction failed (code -32002)"),
        "{message}"
    );
    assert!(message.contains("program logs:"), "{message}");
    assert!(message.contains("InvalidStatus"), "{message}");
}

#[test]
fn rpc_error_without_logs_still_includes_code_and_message() {
    let error = json!({
        "code": -32602,
        "message": "Invalid params"
    });
    let err = rpc_error_to_lab_error("getAccountInfo", &error);
    assert_eq!(
        err.to_string(),
        "getAccountInfo failed (code -32602): Invalid params"
    );
}
