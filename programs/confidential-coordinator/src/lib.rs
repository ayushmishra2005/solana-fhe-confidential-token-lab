#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;
use confidential_protocol as protocol;

pub mod ed25519;
pub mod error;
pub mod state;

use error::CoordinatorError;
use state::{ConfidentialAccount, Config, Request};

declare_id!("2xNTgr7PmWSQRqGcMuCVhdTQLRP8bexVHGJ2CjxiJM6X");

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct InitializeConfigArgs {
    pub domain_id: [u8; 32],
    pub operator: Pubkey,
    pub key_version: u32,
    pub params_hash: [u8; 32],
    pub max_request_lifetime_slots: u64,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct CreateAccountArgs {
    pub balance_hash: [u8; 32],
    pub limit_hash: [u8; 32],
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct SubmitArgs {
    pub amount_hash: [u8; 32],
    pub expected_state_version: u64,
    pub expected_nonce: u64,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct FinalizeArgs {
    pub result_hash: [u8; 32],
    pub result_type: u8,
    pub circuit_id: u16,
}

#[program]
pub mod confidential_coordinator {
    use super::*;

    pub fn initialize_config(
        ctx: Context<InitializeConfig>,
        args: InitializeConfigArgs,
    ) -> Result<()> {
        require!(
            args.max_request_lifetime_slots > 0,
            CoordinatorError::InvalidOperation
        );
        require!(
            !protocol::is_zero_hash(&args.params_hash),
            CoordinatorError::InvalidCiphertextRef
        );
        require!(
            args.operator != Pubkey::default(),
            CoordinatorError::InvalidOperator
        );

        let config = &mut ctx.accounts.config;
        config.authority = ctx.accounts.authority.key();
        config.mint = ctx.accounts.mint.key();
        config.domain_id = args.domain_id;
        config.operator = args.operator;
        config.operator_epoch = 1;
        config.key_version = args.key_version;
        config.params_hash = args.params_hash;
        config.operation = protocol::OPERATION_POLICY_CHECK;
        config.circuit_id = protocol::CIRCUIT_POLICY_V1;
        config.protocol_version = protocol::PROTOCOL_VERSION;
        config.max_request_lifetime_slots = args.max_request_lifetime_slots;
        config.paused = false;
        config.bump = ctx.bumps.config;
        Ok(())
    }

    pub fn set_paused(ctx: Context<AdminConfig>, paused: bool) -> Result<()> {
        ctx.accounts.config.paused = paused;
        Ok(())
    }

    pub fn rotate_operator(ctx: Context<AdminConfig>, new_operator: Pubkey) -> Result<()> {
        require!(
            new_operator != Pubkey::default(),
            CoordinatorError::InvalidOperator
        );
        let config = &mut ctx.accounts.config;
        config.operator = new_operator;
        config.operator_epoch = config
            .operator_epoch
            .checked_add(1)
            .ok_or(CoordinatorError::Overflow)?;
        Ok(())
    }

    pub fn set_key_version(ctx: Context<AdminConfig>, key_version: u32) -> Result<()> {
        ctx.accounts.config.key_version = key_version;
        Ok(())
    }

    pub fn create_account(ctx: Context<CreateAccount>, args: CreateAccountArgs) -> Result<()> {
        require_ct_hash(&args.balance_hash)?;
        require_ct_hash(&args.limit_hash)?;
        require!(!ctx.accounts.config.paused, CoordinatorError::Paused);

        let account = &mut ctx.accounts.account;
        account.config = ctx.accounts.config.key();
        account.mint = ctx.accounts.config.mint;
        account.owner = ctx.accounts.owner.key();
        account.balance_ref = args.balance_hash;
        account.limit_ref = args.limit_hash;
        account.state_version = 0;
        account.request_nonce = 0;
        account.pending_request = Pubkey::default();
        account.key_version = ctx.accounts.config.key_version;
        account.bump = ctx.bumps.account;
        Ok(())
    }

    pub fn submit(ctx: Context<Submit>, args: SubmitArgs) -> Result<()> {
        let request_key = ctx.accounts.request.key();
        let account_key = ctx.accounts.account.key();
        let config = &ctx.accounts.config;
        let account = &mut ctx.accounts.account;
        require!(!config.paused, CoordinatorError::Paused);
        require!(!account.has_pending(), CoordinatorError::ActiveRequest);
        require_keys_eq!(
            account.config,
            config.key(),
            CoordinatorError::ConfigMismatch
        );
        require_keys_eq!(account.mint, config.mint, CoordinatorError::MintMismatch);
        require_keys_eq!(
            account.owner,
            ctx.accounts.owner.key(),
            CoordinatorError::Unauthorized
        );
        require!(
            account.key_version == config.key_version,
            CoordinatorError::InvalidKeyVersion
        );
        require!(
            account.state_version == args.expected_state_version,
            CoordinatorError::InvalidStateVersion
        );
        require_ct_hash(&account.balance_ref)?;
        require_ct_hash(&account.limit_ref)?;
        require_ct_hash(&args.amount_hash)?;

        let nonce = account
            .request_nonce
            .checked_add(1)
            .ok_or(CoordinatorError::Overflow)?;
        require!(nonce == args.expected_nonce, CoordinatorError::InvalidNonce);

        let clock = Clock::get()?;
        let expiry_slot = clock
            .slot
            .checked_add(config.max_request_lifetime_slots)
            .ok_or(CoordinatorError::Overflow)?;

        let request = &mut ctx.accounts.request;
        request.requester = ctx.accounts.owner.key();
        request.config = config.key();
        request.mint = config.mint;
        request.confidential_account = account_key;
        request.operation = config.operation;
        request.balance_hash = account.balance_ref;
        request.amount_hash = args.amount_hash;
        request.limit_hash = account.limit_ref;
        request.params_hash = config.params_hash;
        request.state_version = account.state_version;
        request.request_nonce = nonce;
        request.key_version = config.key_version;
        request.operator_epoch = config.operator_epoch;
        request.created_slot = clock.slot;
        request.expiry_slot = expiry_slot;
        request.status = protocol::STATUS_PENDING;
        request.result_hash = [0u8; 32];
        request.result_digest = [0u8; 32];
        request.bump = ctx.bumps.request;
        request.request_digest =
            protocol::request_digest(&request_binding(config, request, request_key));

        account.request_nonce = nonce;
        account.pending_request = request_key;
        Ok(())
    }

    pub fn cancel(ctx: Context<Cancel>) -> Result<()> {
        let clock = Clock::get()?;
        let account_key = ctx.accounts.account.key();
        let request_key = ctx.accounts.request.key();
        let account = &mut ctx.accounts.account;
        let request = &mut ctx.accounts.request;
        require_pending_lock(account, account_key, request, request_key)?;
        require_keys_eq!(
            account.owner,
            ctx.accounts.owner.key(),
            CoordinatorError::Unauthorized
        );
        require!(clock.slot < request.expiry_slot, CoordinatorError::Expired);
        release_lock(account, request, protocol::STATUS_CANCELLED)?;
        Ok(())
    }

    pub fn expire(ctx: Context<Expire>) -> Result<()> {
        let clock = Clock::get()?;
        let account_key = ctx.accounts.account.key();
        let request_key = ctx.accounts.request.key();
        let account = &mut ctx.accounts.account;
        let request = &mut ctx.accounts.request;
        require_pending_lock(account, account_key, request, request_key)?;
        require!(
            clock.slot >= request.expiry_slot,
            CoordinatorError::NotExpired
        );
        release_lock(account, request, protocol::STATUS_EXPIRED)?;
        Ok(())
    }

    pub fn finalize(ctx: Context<Finalize>, args: FinalizeArgs) -> Result<()> {
        let account_key = ctx.accounts.account.key();
        let request_key = ctx.accounts.request.key();
        let config = &ctx.accounts.config;
        let account = &mut ctx.accounts.account;
        let request = &mut ctx.accounts.request;
        require!(!config.paused, CoordinatorError::Paused);
        require_pending_lock(account, account_key, request, request_key)?;
        require_keys_eq!(
            request.config,
            config.key(),
            CoordinatorError::ConfigMismatch
        );
        require_keys_eq!(request.mint, config.mint, CoordinatorError::MintMismatch);
        require_keys_eq!(
            account.config,
            config.key(),
            CoordinatorError::ConfigMismatch
        );
        require_keys_eq!(account.mint, config.mint, CoordinatorError::MintMismatch);
        require!(
            request.operator_epoch == config.operator_epoch,
            CoordinatorError::InvalidOperatorEpoch
        );
        require!(
            request.key_version == config.key_version,
            CoordinatorError::InvalidKeyVersion
        );
        require!(
            account.state_version == request.state_version,
            CoordinatorError::InvalidStateVersion
        );
        require!(
            account.request_nonce == request.request_nonce,
            CoordinatorError::InvalidNonce
        );
        require!(
            request.operation == config.operation,
            CoordinatorError::InvalidOperation
        );
        require!(
            args.circuit_id == config.circuit_id,
            CoordinatorError::InvalidOperation
        );
        require!(
            args.result_type == protocol::RESULT_TYPE_FHE_BOOL,
            CoordinatorError::InvalidResult
        );
        require_ct_hash(&args.result_hash)?;

        let clock = Clock::get()?;
        require!(clock.slot < request.expiry_slot, CoordinatorError::Expired);

        let binding = protocol::ResultBinding {
            request: request_binding(config, request, request_key),
            request_digest: request.request_digest,
            result_hash: args.result_hash,
            result_type: args.result_type,
            circuit_id: args.circuit_id,
        };
        require!(
            protocol::request_digest(&binding.request) == request.request_digest,
            CoordinatorError::RequestMismatch
        );
        let message = protocol::encode_result(&binding);
        ed25519::verify_operator_message(
            &ctx.accounts.instructions.to_account_info(),
            &config.operator,
            &message,
        )?;

        request.status = protocol::STATUS_FINALIZED;
        request.result_hash = args.result_hash;
        request.result_digest = protocol::result_digest(&binding);
        release_account_lock(account)?;
        Ok(())
    }
}

fn require_ct_hash(hash: &[u8; 32]) -> Result<()> {
    require!(
        !protocol::is_zero_hash(hash),
        CoordinatorError::InvalidCiphertextRef
    );
    Ok(())
}

fn require_pending_lock(
    account: &ConfidentialAccount,
    account_key: Pubkey,
    request: &Request,
    request_key: Pubkey,
) -> Result<()> {
    require!(
        request.status == protocol::STATUS_PENDING,
        CoordinatorError::InvalidStatus
    );
    require!(account.has_pending(), CoordinatorError::NoPendingRequest);
    require_keys_eq!(
        account.pending_request,
        request_key,
        CoordinatorError::RequestMismatch
    );
    require_keys_eq!(
        request.confidential_account,
        account_key,
        CoordinatorError::AccountMismatch
    );
    Ok(())
}

fn release_lock(
    account: &mut ConfidentialAccount,
    request: &mut Request,
    status: u8,
) -> Result<()> {
    request.status = status;
    release_account_lock(account)
}

fn release_account_lock(account: &mut ConfidentialAccount) -> Result<()> {
    // Nonce is not reverted. Releasing the lock must not allow nonce reuse.
    account.pending_request = Pubkey::default();
    account.state_version = account
        .state_version
        .checked_add(1)
        .ok_or(CoordinatorError::Overflow)?;
    Ok(())
}

fn request_binding(
    config: &Config,
    request: &Request,
    request_pda: Pubkey,
) -> protocol::RequestBinding {
    protocol::RequestBinding {
        protocol_version: config.protocol_version,
        domain_id: config.domain_id,
        program_id: crate::ID.to_bytes(),
        config: request.config.to_bytes(),
        mint: request.mint.to_bytes(),
        confidential_account: request.confidential_account.to_bytes(),
        request_pda: request_pda.to_bytes(),
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

#[derive(Accounts)]
pub struct InitializeConfig<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    /// CHECK: mint identity is recorded; Token-2022 validation is Phase 2.
    pub mint: UncheckedAccount<'info>,
    #[account(
        init,
        payer = authority,
        space = 8 + Config::INIT_SPACE,
        seeds = [protocol::SEED_CONFIG, mint.key().as_ref()],
        bump
    )]
    pub config: Account<'info, Config>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AdminConfig<'info> {
    pub authority: Signer<'info>,
    #[account(mut, has_one = authority @ CoordinatorError::Unauthorized)]
    pub config: Account<'info, Config>,
}

#[derive(Accounts)]
pub struct CreateAccount<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,
    #[account(
        seeds = [protocol::SEED_CONFIG, config.mint.as_ref()],
        bump = config.bump
    )]
    pub config: Account<'info, Config>,
    #[account(
        init,
        payer = owner,
        space = 8 + ConfidentialAccount::INIT_SPACE,
        seeds = [protocol::SEED_ACCOUNT, config.mint.as_ref(), owner.key().as_ref()],
        bump
    )]
    pub account: Account<'info, ConfidentialAccount>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(args: SubmitArgs)]
pub struct Submit<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,
    #[account(
        seeds = [protocol::SEED_CONFIG, config.mint.as_ref()],
        bump = config.bump
    )]
    pub config: Account<'info, Config>,
    #[account(
        mut,
        seeds = [protocol::SEED_ACCOUNT, config.mint.as_ref(), owner.key().as_ref()],
        bump = account.bump,
        has_one = owner @ CoordinatorError::Unauthorized,
        has_one = config @ CoordinatorError::ConfigMismatch
    )]
    pub account: Account<'info, ConfidentialAccount>,
    #[account(
        init,
        payer = owner,
        space = 8 + Request::INIT_SPACE,
        seeds = [protocol::SEED_REQUEST, account.key().as_ref(), args.expected_nonce.to_le_bytes().as_ref()],
        bump
    )]
    pub request: Account<'info, Request>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Cancel<'info> {
    pub owner: Signer<'info>,
    #[account(
        mut,
        seeds = [protocol::SEED_ACCOUNT, account.mint.as_ref(), owner.key().as_ref()],
        bump = account.bump,
        has_one = owner @ CoordinatorError::Unauthorized
    )]
    pub account: Account<'info, ConfidentialAccount>,
    #[account(
        mut,
        seeds = [protocol::SEED_REQUEST, account.key().as_ref(), request.request_nonce.to_le_bytes().as_ref()],
        bump = request.bump,
        constraint = request.confidential_account == account.key() @ CoordinatorError::AccountMismatch
    )]
    pub request: Account<'info, Request>,
}

#[derive(Accounts)]
pub struct Expire<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        mut,
        seeds = [protocol::SEED_ACCOUNT, account.mint.as_ref(), account.owner.as_ref()],
        bump = account.bump
    )]
    pub account: Account<'info, ConfidentialAccount>,
    #[account(
        mut,
        seeds = [protocol::SEED_REQUEST, account.key().as_ref(), request.request_nonce.to_le_bytes().as_ref()],
        bump = request.bump,
        constraint = request.confidential_account == account.key() @ CoordinatorError::AccountMismatch
    )]
    pub request: Account<'info, Request>,
}

#[derive(Accounts)]
pub struct Finalize<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        seeds = [protocol::SEED_CONFIG, config.mint.as_ref()],
        bump = config.bump
    )]
    pub config: Account<'info, Config>,
    #[account(
        mut,
        seeds = [protocol::SEED_ACCOUNT, config.mint.as_ref(), account.owner.as_ref()],
        bump = account.bump,
        has_one = config @ CoordinatorError::ConfigMismatch
    )]
    pub account: Account<'info, ConfidentialAccount>,
    #[account(
        mut,
        seeds = [protocol::SEED_REQUEST, account.key().as_ref(), request.request_nonce.to_le_bytes().as_ref()],
        bump = request.bump,
        has_one = config @ CoordinatorError::ConfigMismatch,
        constraint = request.confidential_account == account.key() @ CoordinatorError::AccountMismatch
    )]
    pub request: Account<'info, Request>,
    /// CHECK: address constrained to the instructions sysvar.
    #[account(address = ed25519::INSTRUCTIONS_ID)]
    pub instructions: UncheckedAccount<'info>,
}
