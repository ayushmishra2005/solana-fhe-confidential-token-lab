//! Request/response types and instruction serialization for OpenZeppelin
//! Relayer v1.5.x (stable docs: https://docs.openzeppelin.com/relayer/1.5.x/).
//!
//! Field names match the official Relayer models:
//! `SolanaInstructionSpec`, `SolanaAccountMeta`, `RelayerResponse`,
//! `SolanaTransactionResponse`, and `TransactionStatus`.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use solana_address::Address;
use solana_instruction::Instruction;

use crate::devnet::decode::parse_address;
use crate::{LabError, PROGRAM_ID};

/// Native Ed25519 precompile, as required by the coordinator verifier.
pub const ED25519_PROGRAM_ID_STR: &str = "Ed25519SigVerify111111111111111111111111111";

/// Official built-in Solana Devnet network name from Relayer
/// `config/networks/solana.json` (`"network": "devnet"`).
pub const RELAYER_NETWORK_DEVNET: &str = "devnet";
/// Documented custom/example Solana Devnet network identifier from the
/// Relayer Solana integration guide.
pub const RELAYER_NETWORK_SOLANA_DEVNET: &str = "solana-devnet";

/// OpenZeppelin Relayer `SolanaInstructionSpec` (v1.5.0).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolanaInstructionSpec {
    /// Program ID (base58-encoded pubkey).
    pub program_id: String,
    /// Account metadata for the instruction.
    pub accounts: Vec<SolanaAccountMeta>,
    /// Instruction data (base64-encoded).
    pub data: String,
}

/// OpenZeppelin Relayer `SolanaAccountMeta` (v1.5.0).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolanaAccountMeta {
    /// Account public key (base58-encoded).
    pub pubkey: String,
    pub is_signer: bool,
    pub is_writable: bool,
}

/// `GET /api/v1/relayers/{id}` `data` object (`RelayerResponse`).
#[derive(Debug, Clone, Deserialize)]
pub struct RelayerInfo {
    pub id: String,
    #[serde(default)]
    pub name: String,
    pub network: String,
    pub network_type: String,
    pub paused: bool,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub system_disabled: Option<bool>,
    #[serde(default)]
    pub policies: Option<serde_json::Value>,
}

/// Relayer that has passed the Solana/Devnet/usable-payer gates.
#[derive(Debug, Clone)]
pub struct ValidatedRelayer {
    pub id: String,
    pub network: String,
    pub address: Address,
}

/// Shared transaction fields from send/get transaction responses.
/// Solana responses use `signature`; other fields are ignored.
#[derive(Debug, Clone, Deserialize)]
pub struct RelayerTransaction {
    pub id: String,
    pub status: String,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub status_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayerJobState {
    InProgress,
    Succeeded,
    Failed,
}

/// Official `TransactionStatus` variants (`rename_all = "lowercase"`).
/// Relayer maps Solana processed/confirmed → `mined` and Solana finalized →
/// `confirmed`. Only Relayer `confirmed` is treated as poll success so we do
/// not return before a sufficiently confirmed Solana state. Comparison is
/// case-insensitive; unknown statuses stay in-progress.
pub fn classify_relayer_status(status: &str) -> RelayerJobState {
    match status.trim().to_ascii_lowercase().as_str() {
        "confirmed" => RelayerJobState::Succeeded,
        "failed" | "expired" | "canceled" => RelayerJobState::Failed,
        _ => RelayerJobState::InProgress,
    }
}

pub fn is_solana_devnet_network(network: &str) -> bool {
    let normalized = network.trim().to_ascii_lowercase();
    normalized == RELAYER_NETWORK_DEVNET || normalized == RELAYER_NETWORK_SOLANA_DEVNET
}

pub fn validate_solana_devnet_relayer(info: &RelayerInfo) -> Result<ValidatedRelayer, LabError> {
    if info.network_type != "solana" {
        return Err(LabError(format!(
            "OpenZeppelin Relayer '{}' has network_type '{}'; finalize requires network_type=solana",
            info.id, info.network_type
        )));
    }
    if !is_solana_devnet_network(&info.network) {
        return Err(LabError(format!(
            "OpenZeppelin Relayer '{}' is configured for network '{}'; finalize requires Solana Devnet (official network name '{}')",
            info.id, info.network, RELAYER_NETWORK_DEVNET
        )));
    }
    if info.paused {
        return Err(LabError(format!(
            "OpenZeppelin Relayer '{}' is paused",
            info.id
        )));
    }
    if info.system_disabled == Some(true) {
        return Err(LabError(format!(
            "OpenZeppelin Relayer '{}' is system_disabled",
            info.id
        )));
    }

    let address_str = info
        .address
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            LabError(format!(
                "OpenZeppelin Relayer '{}' did not return a Solana address",
                info.id
            ))
        })?;
    let address = parse_address(address_str).map_err(|_| {
        LabError(format!(
            "OpenZeppelin Relayer '{}' returned an invalid Solana address '{address_str}'",
            info.id
        ))
    })?;
    if address == Address::default() {
        return Err(LabError(format!(
            "OpenZeppelin Relayer '{}' returned the default/zero Solana address",
            info.id
        )));
    }

    // Instruction-array submit is only accepted when the Relayer pays fees.
    // Official default is `user`, which requires a pre-built transaction.
    let strategy = info
        .policies
        .as_ref()
        .and_then(|policies| policies.get("fee_payment_strategy"))
        .and_then(|value| value.as_str());
    match strategy {
        Some("relayer") => {}
        Some("user") => {
            return Err(LabError(format!(
                "OpenZeppelin Relayer '{}' has fee_payment_strategy=user; instruction-array finalize requires fee_payment_strategy=relayer",
                info.id
            )));
        }
        Some(other) => {
            return Err(LabError(format!(
                "OpenZeppelin Relayer '{}' has unsupported fee_payment_strategy '{other}'",
                info.id
            )));
        }
        None => {
            return Err(LabError(format!(
                "OpenZeppelin Relayer '{}' does not expose fee_payment_strategy=relayer (official default is user, which cannot accept instruction arrays)",
                info.id
            )));
        }
    }

    Ok(ValidatedRelayer {
        id: info.id.clone(),
        network: info.network.clone(),
        address,
    })
}

pub fn instruction_to_spec(ix: &Instruction) -> SolanaInstructionSpec {
    SolanaInstructionSpec {
        program_id: ix.program_id.to_string(),
        accounts: ix
            .accounts
            .iter()
            .map(|account| SolanaAccountMeta {
                pubkey: account.pubkey.to_string(),
                is_signer: account.is_signer,
                is_writable: account.is_writable,
            })
            .collect(),
        data: BASE64.encode(&ix.data),
    }
}

pub fn instructions_to_specs(ixs: &[Instruction]) -> Vec<SolanaInstructionSpec> {
    ixs.iter().map(instruction_to_spec).collect()
}

pub fn require_ed25519_immediately_before_finalize(ixs: &[Instruction]) -> Result<(), LabError> {
    let program_ids: Vec<String> = ixs.iter().map(|ix| ix.program_id.to_string()).collect();
    require_ed25519_immediately_before_finalize_ids(&program_ids)
}

pub fn require_ed25519_immediately_before_finalize_specs(
    specs: &[SolanaInstructionSpec],
) -> Result<(), LabError> {
    let program_ids: Vec<String> = specs.iter().map(|spec| spec.program_id.clone()).collect();
    require_ed25519_immediately_before_finalize_ids(&program_ids)
}

fn require_ed25519_immediately_before_finalize_ids(program_ids: &[String]) -> Result<(), LabError> {
    let coordinator = PROGRAM_ID.to_string();
    let finalize_positions: Vec<usize> = program_ids
        .iter()
        .enumerate()
        .filter(|(_, id)| *id == &coordinator)
        .map(|(idx, _)| idx)
        .collect();
    if finalize_positions.len() != 1 {
        return Err(LabError(format!(
            "expected exactly one coordinator finalize instruction, found {}",
            finalize_positions.len()
        )));
    }
    let finalize_idx = finalize_positions[0];
    if finalize_idx == 0 || program_ids[finalize_idx - 1] != ED25519_PROGRAM_ID_STR {
        return Err(LabError(
            "native Ed25519 instruction must immediately precede coordinator finalize; \
             refusing a payload that inserts another instruction between them"
                .to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devnet::decode::parse_address;
    use serde_json::json;

    fn solana_devnet_info() -> RelayerInfo {
        RelayerInfo {
            id: "solana-devnet".to_string(),
            name: "Solana Devnet".to_string(),
            network: "devnet".to_string(),
            network_type: "solana".to_string(),
            paused: false,
            address: Some("4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7AijMQwWNAsrD".to_string()),
            system_disabled: Some(false),
            policies: Some(json!({ "fee_payment_strategy": "relayer", "min_balance": 0 })),
        }
    }

    #[test]
    fn parses_valid_relayer_info_and_accepts_solana_devnet() {
        let raw = json!({
            "id": "solana-devnet",
            "name": "Solana Devnet",
            "network": "devnet",
            "network_type": "solana",
            "paused": false,
            "address": "4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7AijMQwWNAsrD",
            "system_disabled": false,
            "signer_id": "local-signer",
            "policies": { "fee_payment_strategy": "relayer" }
        });
        let info: RelayerInfo = serde_json::from_value(raw).unwrap();
        let validated = validate_solana_devnet_relayer(&info).unwrap();
        assert_eq!(validated.id, "solana-devnet");
        assert_eq!(validated.network, "devnet");
        assert_eq!(
            validated.address.to_string(),
            "4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7AijMQwWNAsrD"
        );
    }

    #[test]
    fn rejects_wrong_network() {
        let mut info = solana_devnet_info();
        info.network = "mainnet-beta".to_string();
        let err = validate_solana_devnet_relayer(&info).unwrap_err();
        assert!(err.to_string().contains("mainnet-beta"), "{err}");
        assert!(err.to_string().contains("Devnet"), "{err}");
    }

    #[test]
    fn rejects_non_solana_relayer() {
        let mut info = solana_devnet_info();
        info.network_type = "evm".to_string();
        info.network = "sepolia".to_string();
        let err = validate_solana_devnet_relayer(&info).unwrap_err();
        assert!(err.to_string().contains("network_type"), "{err}");
        assert!(err.to_string().contains("evm"), "{err}");
    }

    #[test]
    fn rejects_paused_or_system_disabled_relayer() {
        let mut paused = solana_devnet_info();
        paused.paused = true;
        let err = validate_solana_devnet_relayer(&paused).unwrap_err();
        assert!(err.to_string().contains("paused"), "{err}");

        let mut disabled = solana_devnet_info();
        disabled.system_disabled = Some(true);
        let err = validate_solana_devnet_relayer(&disabled).unwrap_err();
        assert!(err.to_string().contains("system_disabled"), "{err}");
    }

    #[test]
    fn rejects_invalid_or_missing_solana_payer_address() {
        let mut missing = solana_devnet_info();
        missing.address = None;
        let err = validate_solana_devnet_relayer(&missing).unwrap_err();
        assert!(
            err.to_string().contains("did not return a Solana address"),
            "{err}"
        );

        let mut invalid = solana_devnet_info();
        invalid.address = Some("not-a-pubkey".to_string());
        let err = validate_solana_devnet_relayer(&invalid).unwrap_err();
        assert!(err.to_string().contains("invalid Solana address"), "{err}");

        let mut zero = solana_devnet_info();
        zero.address = Some(Address::default().to_string());
        let err = validate_solana_devnet_relayer(&zero).unwrap_err();
        assert!(err.to_string().contains("default/zero"), "{err}");
    }

    #[test]
    fn rejects_user_fee_strategy_and_missing_relayer_strategy() {
        let mut user = solana_devnet_info();
        user.policies = Some(json!({ "fee_payment_strategy": "user" }));
        let err = validate_solana_devnet_relayer(&user).unwrap_err();
        assert!(
            err.to_string().contains("fee_payment_strategy=user"),
            "{err}"
        );

        let mut missing = solana_devnet_info();
        missing.policies = None;
        let err = validate_solana_devnet_relayer(&missing).unwrap_err();
        assert!(
            err.to_string().contains("fee_payment_strategy=relayer"),
            "{err}"
        );
    }

    #[test]
    fn classifies_official_transaction_statuses() {
        assert_eq!(
            classify_relayer_status("pending"),
            RelayerJobState::InProgress
        );
        assert_eq!(classify_relayer_status("sent"), RelayerJobState::InProgress);
        assert_eq!(
            classify_relayer_status("submitted"),
            RelayerJobState::InProgress
        );
        assert_eq!(
            classify_relayer_status("mined"),
            RelayerJobState::InProgress
        );
        assert_eq!(
            classify_relayer_status("confirmed"),
            RelayerJobState::Succeeded
        );
        assert_eq!(classify_relayer_status("failed"), RelayerJobState::Failed);
        assert_eq!(classify_relayer_status("expired"), RelayerJobState::Failed);
        assert_eq!(classify_relayer_status("canceled"), RelayerJobState::Failed);
        assert_eq!(
            classify_relayer_status("unknown-status"),
            RelayerJobState::InProgress
        );
    }

    #[test]
    fn classifies_relayer_status_case_insensitively() {
        assert_eq!(
            classify_relayer_status("Confirmed"),
            RelayerJobState::Succeeded
        );
        assert_eq!(
            classify_relayer_status("CONFIRMED"),
            RelayerJobState::Succeeded
        );
        assert_eq!(
            classify_relayer_status("MINED"),
            RelayerJobState::InProgress
        );
        assert_eq!(classify_relayer_status("Failed"), RelayerJobState::Failed);
        assert_eq!(classify_relayer_status("EXPIRED"), RelayerJobState::Failed);
        assert_eq!(classify_relayer_status("Canceled"), RelayerJobState::Failed);
    }

    #[test]
    fn instruction_serialization_preserves_program_accounts_flags_and_data() {
        let program = PROGRAM_ID;
        let signer = parse_address("4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7AijMQwWNAsrD").unwrap();
        let other = Address::default();
        let data = vec![0x11, 0x22, 0x33, 0xaa];
        let ix = Instruction {
            program_id: program,
            accounts: vec![
                solana_instruction::AccountMeta::new(signer, true),
                solana_instruction::AccountMeta::new_readonly(other, false),
            ],
            data: data.clone(),
        };
        let spec = instruction_to_spec(&ix);
        assert_eq!(spec.program_id, program.to_string());
        assert_eq!(spec.accounts.len(), 2);
        assert_eq!(spec.accounts[0].pubkey, signer.to_string());
        assert!(spec.accounts[0].is_signer);
        assert!(spec.accounts[0].is_writable);
        assert_eq!(spec.accounts[1].pubkey, other.to_string());
        assert!(!spec.accounts[1].is_signer);
        assert!(!spec.accounts[1].is_writable);
        assert_eq!(BASE64.decode(&spec.data).unwrap(), data);
    }

    #[test]
    fn rejects_instruction_inserted_between_ed25519_and_finalize() {
        let ed = ED25519_PROGRAM_ID_STR.to_string();
        let finalize = PROGRAM_ID.to_string();
        let budget = "ComputeBudget111111111111111111111111111111".to_string();
        require_ed25519_immediately_before_finalize_ids(&[ed.clone(), finalize.clone()]).unwrap();
        require_ed25519_immediately_before_finalize_ids(&[
            budget.clone(),
            ed.clone(),
            finalize.clone(),
        ])
        .unwrap();
        let err = require_ed25519_immediately_before_finalize_ids(&[
            ed.clone(),
            budget.clone(),
            finalize.clone(),
        ])
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("immediately precede coordinator finalize"),
            "{err}"
        );
        let missing =
            require_ed25519_immediately_before_finalize_ids(std::slice::from_ref(&finalize))
                .unwrap_err();
        assert!(
            missing
                .to_string()
                .contains("immediately precede coordinator finalize"),
            "{missing}"
        );
        let reversed =
            require_ed25519_immediately_before_finalize_ids(&[finalize, ed]).unwrap_err();
        assert!(
            reversed
                .to_string()
                .contains("immediately precede coordinator finalize"),
            "{reversed}"
        );
    }
}
