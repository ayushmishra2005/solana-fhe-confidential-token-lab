use anchor_lang::prelude::*;

#[error_code]
pub enum CoordinatorError {
    #[msg("unauthorized")]
    Unauthorized,
    #[msg("paused")]
    Paused,
    #[msg("invalid PDA")]
    InvalidPda,
    #[msg("config mismatch")]
    ConfigMismatch,
    #[msg("mint mismatch")]
    MintMismatch,
    #[msg("account mismatch")]
    AccountMismatch,
    #[msg("request mismatch")]
    RequestMismatch,
    #[msg("invalid status")]
    InvalidStatus,
    #[msg("invalid nonce")]
    InvalidNonce,
    #[msg("invalid state version")]
    InvalidStateVersion,
    #[msg("invalid operation")]
    InvalidOperation,
    #[msg("invalid ciphertext reference")]
    InvalidCiphertextRef,
    #[msg("invalid key version")]
    InvalidKeyVersion,
    #[msg("invalid operator")]
    InvalidOperator,
    #[msg("invalid operator epoch")]
    InvalidOperatorEpoch,
    #[msg("request expired")]
    Expired,
    #[msg("request not expired")]
    NotExpired,
    #[msg("already finalized")]
    AlreadyFinalized,
    #[msg("active request exists")]
    ActiveRequest,
    #[msg("no pending request")]
    NoPendingRequest,
    #[msg("invalid result")]
    InvalidResult,
    #[msg("invalid signature")]
    InvalidSignature,
    #[msg("overflow")]
    Overflow,
}
