//! Persistent Devnet context.
//!
//! `devnet-state.json` is a convenience cache of *public* information only:
//! addresses, the RPC URL, hashes, and (optionally) keypair *file paths*.
//! It must never contain private key bytes. Signers are always re-read from
//! disk at the point of use.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use solana_keypair::Keypair;

use crate::LabError;

pub const DEFAULT_DEVNET_RPC_URL: &str = "https://api.devnet.solana.com";
/// Devnet research default. Deliberately larger than the 1_000-slot LiteSVM
/// demo value: a manual initialize -> create-account -> submit -> evaluate ->
/// finalize round trip against a real cluster can take several minutes.
pub const DEFAULT_MAX_REQUEST_LIFETIME_SLOTS: u64 = 10_000;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DevnetState {
    pub rpc_url: Option<String>,
    pub program_id: Option<String>,
    /// Synthetic Phase-1 mint identity (not a Token-2022 mint).
    pub mint: Option<String>,
    pub config: Option<String>,
    pub account: Option<String>,
    pub owner: Option<String>,
    pub authority: Option<String>,
    pub operator: Option<String>,
    pub params_hash: Option<String>,
    pub key_version: Option<u32>,
    pub max_request_lifetime_slots: Option<u64>,
    pub latest_request: Option<String>,
    pub latest_request_nonce: Option<u64>,
    // File paths only. Never keypair bytes.
    pub payer_keypair_path: Option<String>,
    pub authority_keypair_path: Option<String>,
    pub owner_keypair_path: Option<String>,
}

impl DevnetState {
    pub fn load(data_dir: &Path) -> Result<Self, LabError> {
        let path = state_path(data_dir);
        if !path.exists() {
            return Ok(Self::default());
        }
        let bytes = fs::read(&path)?;
        serde_json::from_slice(&bytes).map_err(|e| LabError(e.to_string()))
    }

    pub fn save(&self, data_dir: &Path) -> Result<(), LabError> {
        fs::create_dir_all(data_dir)?;
        let path = state_path(data_dir);
        let bytes = serde_json::to_vec_pretty(self).map_err(|e| LabError(e.to_string()))?;
        fs::write(path, bytes)?;
        Ok(())
    }

    pub fn rpc_url(&self) -> String {
        self.rpc_url
            .clone()
            .unwrap_or_else(|| DEFAULT_DEVNET_RPC_URL.to_string())
    }
}

pub fn state_path(data_dir: &Path) -> PathBuf {
    data_dir.join("devnet-state.json")
}

/// Expand a leading `~/` using `$HOME`. Does not attempt full shell tilde
/// expansion (e.g. `~user`); sufficient for this CLI's own flags.
pub fn expand_tilde(path: &str) -> PathBuf {
    expand_tilde_with_home(path, std::env::var("HOME").ok().as_deref())
}

pub fn expand_tilde_with_home(path: &str, home: Option<&str>) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = home {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(path)
}

/// Default Solana CLI keypair location, used as the default for
/// `--payer`/`--authority`/`--owner` in this Phase 1.1 manual workflow.
pub fn default_keypair_path() -> PathBuf {
    default_keypair_path_with_home(std::env::var("HOME").ok().as_deref())
}

pub fn default_keypair_path_with_home(home: Option<&str>) -> PathBuf {
    match home {
        Some(home) => PathBuf::from(home).join(".config/solana/id.json"),
        None => PathBuf::from(".config/solana/id.json"),
    }
}

/// Read a Solana CLI-format keypair file (a JSON array of 64 secret-key
/// bytes), as produced by `solana-keygen new`.
pub fn read_keypair_file(path: &Path) -> Result<Keypair, LabError> {
    let bytes = fs::read(path).map_err(|e| {
        LabError(format!(
            "failed to read keypair file {}: {e}",
            path.display()
        ))
    })?;
    let json: Vec<u8> = serde_json::from_slice(&bytes).map_err(|e| {
        LabError(format!(
            "failed to parse keypair file {} as a JSON byte array: {e}",
            path.display()
        ))
    })?;
    Keypair::try_from(json.as_slice())
        .map_err(|e| LabError(format!("invalid keypair bytes in {}: {e}", path.display())))
}
