use anchor_lang::prelude::*;

#[account]
#[derive(InitSpace)]
pub struct Config {
    pub authority: Pubkey,
    pub mint: Pubkey,
    pub domain_id: [u8; 32],
    pub operator: Pubkey,
    pub operator_epoch: u64,
    pub key_version: u32,
    pub params_hash: [u8; 32],
    pub operation: u16,
    pub circuit_id: u16,
    pub protocol_version: u16,
    pub max_request_lifetime_slots: u64,
    pub paused: bool,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct ConfidentialAccount {
    pub config: Pubkey,
    pub mint: Pubkey,
    pub owner: Pubkey,
    pub balance_ref: [u8; 32],
    pub limit_ref: [u8; 32],
    pub state_version: u64,
    pub request_nonce: u64,
    pub pending_request: Pubkey,
    pub key_version: u32,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct Request {
    pub requester: Pubkey,
    pub config: Pubkey,
    pub mint: Pubkey,
    pub confidential_account: Pubkey,
    pub operation: u16,
    pub balance_hash: [u8; 32],
    pub amount_hash: [u8; 32],
    pub limit_hash: [u8; 32],
    pub params_hash: [u8; 32],
    pub state_version: u64,
    pub request_nonce: u64,
    pub key_version: u32,
    pub operator_epoch: u64,
    pub created_slot: u64,
    pub expiry_slot: u64,
    pub status: u8,
    pub request_digest: [u8; 32],
    pub result_hash: [u8; 32],
    pub result_digest: [u8; 32],
    pub bump: u8,
}

impl ConfidentialAccount {
    pub fn has_pending(&self) -> bool {
        self.pending_request != Pubkey::default()
    }
}
