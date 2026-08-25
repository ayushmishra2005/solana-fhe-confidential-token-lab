use anchor_lang::prelude::*;
use solana_instructions_sysvar::{load_current_index_checked, load_instruction_at_checked};

use crate::error::CoordinatorError;

/// Native ed25519 verify program. Offsets with u16::MAX mean "this instruction".
pub const ED25519_PROGRAM_ID: Pubkey = pubkey!("Ed25519SigVerify111111111111111111111111111");
pub const INSTRUCTIONS_ID: Pubkey = pubkey!("Sysvar1nstructions1111111111111111111111111");

const PUBKEY_SIZE: usize = 32;
const SIGNATURE_SIZE: usize = 64;

/// Bind finalize to a prior ed25519 instruction over `message` by `operator`.
/// Only data inside that ed25519 instruction is accepted.
pub fn verify_operator_message(
    ix_sysvar: &AccountInfo,
    operator: &Pubkey,
    message: &[u8],
) -> Result<()> {
    let current = load_current_index_checked(ix_sysvar)?;
    require!(current > 0, CoordinatorError::InvalidSignature);
    let ed_index = current
        .checked_sub(1)
        .ok_or(CoordinatorError::InvalidSignature)?;
    let ed_ix = load_instruction_at_checked(usize::from(ed_index), ix_sysvar)?;
    require_keys_eq!(
        ed_ix.program_id,
        ED25519_PROGRAM_ID,
        CoordinatorError::InvalidSignature
    );

    let data = ed_ix.data.as_slice();
    require!(data.len() >= 16, CoordinatorError::InvalidSignature);
    require!(data[0] == 1, CoordinatorError::InvalidSignature);

    let sig_off = u16_at(data, 2)?;
    let sig_ix = u16_at(data, 4)?;
    let pk_off = u16_at(data, 6)?;
    let pk_ix = u16_at(data, 8)?;
    let msg_off = u16_at(data, 10)?;
    let msg_sz = u16_at(data, 12)?;
    let msg_ix = u16_at(data, 14)?;

    require!(
        index_is_self(sig_ix, ed_index)
            && index_is_self(pk_ix, ed_index)
            && index_is_self(msg_ix, ed_index),
        CoordinatorError::InvalidSignature
    );

    let pk_off = usize::from(pk_off);
    let sig_off = usize::from(sig_off);
    let msg_off = usize::from(msg_off);
    let msg_sz = usize::from(msg_sz);
    require!(
        pk_off
            .checked_add(PUBKEY_SIZE)
            .ok_or(CoordinatorError::InvalidSignature)?
            <= data.len(),
        CoordinatorError::InvalidSignature
    );
    require!(
        sig_off
            .checked_add(SIGNATURE_SIZE)
            .ok_or(CoordinatorError::InvalidSignature)?
            <= data.len(),
        CoordinatorError::InvalidSignature
    );
    require!(
        msg_off
            .checked_add(msg_sz)
            .ok_or(CoordinatorError::InvalidSignature)?
            <= data.len(),
        CoordinatorError::InvalidSignature
    );
    require!(msg_sz == message.len(), CoordinatorError::InvalidResult);

    let pk = Pubkey::try_from(&data[pk_off..pk_off + PUBKEY_SIZE])
        .map_err(|_| CoordinatorError::InvalidSignature)?;
    require_keys_eq!(pk, *operator, CoordinatorError::InvalidOperator);
    require!(
        &data[msg_off..msg_off + msg_sz] == message,
        CoordinatorError::InvalidResult
    );
    Ok(())
}

fn index_is_self(stored: u16, ed_index: u16) -> bool {
    stored == ed_index || stored == u16::MAX
}

fn u16_at(data: &[u8], offset: usize) -> Result<u16> {
    let slice = data
        .get(offset..offset + 2)
        .ok_or(CoordinatorError::InvalidSignature)?;
    Ok(u16::from_le_bytes(
        slice
            .try_into()
            .map_err(|_| CoordinatorError::InvalidSignature)?,
    ))
}
