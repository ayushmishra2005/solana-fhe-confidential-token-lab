//! Minimal OpenZeppelin Relayer REST client for Phase 2 finalize transport.
//!
//! This is not a general-purpose Relayer SDK. It implements only the
//! documented v1.5.x endpoints this lab needs:
//! `GET /api/v1/relayers/{id}`, `POST .../transactions`, and
//! `GET .../transactions/{id}`.

pub mod openzeppelin;
pub mod types;

pub use openzeppelin::{
    load_api_key, load_api_key_from_env, OpenZeppelinRelayerClient, PollSettings,
    RelayerSubmitResult, API_KEY_ENV,
};
pub use types::{
    instruction_to_spec, instructions_to_specs, require_ed25519_immediately_before_finalize,
    require_ed25519_immediately_before_finalize_specs, validate_solana_devnet_relayer, RelayerInfo,
    RelayerTransaction, SolanaAccountMeta, SolanaInstructionSpec, ValidatedRelayer,
    ED25519_PROGRAM_ID_STR,
};
