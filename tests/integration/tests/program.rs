use anchor_lang::AccountSerialize;
use confidential_coordinator::state::{ConfidentialAccount, Config, Request};
use confidential_lab::{
    boot_svm, cancel_ix, create_account_ix, expire_ix, finalize_ixs, initialize_ix, request_pda,
    rotate_operator_ix, send, set_key_version_ix, set_paused_ix, submit_ix, LocalSvm,
};
use confidential_protocol as protocol;
use solana_account::Account;
use solana_clock::Clock;
use solana_keypair::Keypair;
use solana_signer::Signer;

const LIFETIME: u64 = 100;
const PARAMS: [u8; 32] = [0xab; 32];
const BALANCE: [u8; 32] = [0xb1; 32];
const AMOUNT: [u8; 32] = [0xa1; 32];
const LIMIT: [u8; 32] = [0xc1; 32];
const RESULT: [u8; 32] = [0xd1; 32];

fn env() -> LocalSvm {
    let operator = Keypair::new();
    let mut local = boot_svm(&operator).expect("boot svm");
    send(
        &mut local.svm,
        &local.authority,
        &[initialize_ix(
            local.authority.pubkey(),
            local.mint.pubkey(),
            local.config,
            local.operator.pubkey(),
            PARAMS,
            LIFETIME,
        )],
    )
    .expect("initialize");
    send(
        &mut local.svm,
        &local.owner,
        &[create_account_ix(
            local.owner.pubkey(),
            local.config,
            local.account,
            BALANCE,
            LIMIT,
        )],
    )
    .expect("create account");
    local
}

fn submit_ok(local: &mut LocalSvm, nonce: u64, state_version: u64) -> solana_address::Address {
    let request = request_pda(&local.account, nonce);
    send(
        &mut local.svm,
        &local.owner,
        &[submit_ix(
            local.owner.pubkey(),
            local.config,
            local.account,
            request,
            AMOUNT,
            state_version,
            nonce,
        )],
    )
    .expect("submit");
    request
}

fn result_binding(
    local: &LocalSvm,
    request: solana_address::Address,
    nonce: u64,
) -> protocol::ResultBinding {
    result_binding_for(
        local,
        local.config,
        local.mint.pubkey(),
        local.account,
        request,
        nonce,
    )
}

fn result_binding_for(
    local: &LocalSvm,
    config: solana_address::Address,
    mint: solana_address::Address,
    account: solana_address::Address,
    request: solana_address::Address,
    nonce: u64,
) -> protocol::ResultBinding {
    let onchain: Request = deserialize_account(&local.svm.get_account(&request).unwrap());
    assert_eq!(onchain.request_nonce, nonce);
    let request_binding = protocol::RequestBinding {
        protocol_version: protocol::PROTOCOL_VERSION,
        domain_id: protocol::local_domain_id(),
        program_id: confidential_coordinator::ID.to_bytes(),
        config: config.to_bytes(),
        mint: mint.to_bytes(),
        confidential_account: account.to_bytes(),
        request_pda: request.to_bytes(),
        operation: protocol::OPERATION_POLICY_CHECK,
        balance_hash: onchain.balance_hash,
        amount_hash: onchain.amount_hash,
        limit_hash: onchain.limit_hash,
        params_hash: onchain.params_hash,
        state_version: onchain.state_version,
        request_nonce: onchain.request_nonce,
        key_version: onchain.key_version,
        operator_epoch: onchain.operator_epoch,
        expiry_slot: onchain.expiry_slot,
    };
    protocol::ResultBinding {
        request_digest: protocol::request_digest(&request_binding),
        request: request_binding,
        result_hash: RESULT,
        result_type: protocol::RESULT_TYPE_FHE_BOOL,
        circuit_id: protocol::CIRCUIT_POLICY_V1,
    }
}

fn read_request(local: &LocalSvm, request: &solana_address::Address) -> Request {
    deserialize_account(&local.svm.get_account(request).unwrap())
}

fn read_confidential_account(
    local: &LocalSvm,
    account: &solana_address::Address,
) -> ConfidentialAccount {
    deserialize_account(&local.svm.get_account(account).unwrap())
}

fn read_config(local: &LocalSvm) -> Config {
    deserialize_account(&local.svm.get_account(&local.config).unwrap())
}

fn system_transfer_ix(
    from: solana_address::Address,
    to: solana_address::Address,
    lamports: u64,
) -> solana_instruction::Instruction {
    let mut data = Vec::with_capacity(12);
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());
    solana_instruction::Instruction {
        program_id: solana_address::address!("11111111111111111111111111111111"),
        accounts: vec![
            solana_instruction::AccountMeta::new(from, true),
            solana_instruction::AccountMeta::new(to, false),
        ],
        data,
    }
}

fn expire_blockhash(local: &mut LocalSvm) {
    local.svm.expire_blockhash();
}

fn create_second_account(local: &mut LocalSvm) -> (Keypair, solana_address::Address) {
    let owner2 = Keypair::new();
    local.svm.airdrop(&owner2.pubkey(), 10_000_000_000).unwrap();
    let (account2, _) = solana_address::Address::find_program_address(
        &[
            protocol::SEED_ACCOUNT,
            local.mint.pubkey().as_ref(),
            owner2.pubkey().as_ref(),
        ],
        &confidential_lab::PROGRAM_ID,
    );
    send(
        &mut local.svm,
        &owner2,
        &[create_account_ix(
            owner2.pubkey(),
            local.config,
            account2,
            BALANCE,
            LIMIT,
        )],
    )
    .expect("create second account");
    (owner2, account2)
}

fn finalize_ok(local: &mut LocalSvm, request: solana_address::Address, nonce: u64) {
    let binding = result_binding(local, request, nonce);
    send(
        &mut local.svm,
        &local.owner,
        &finalize_ixs(
            local.owner.pubkey(),
            local.config,
            local.account,
            request,
            &local.operator,
            &binding,
        ),
    )
    .expect("finalize");
}

fn send_fail(
    svm: &mut litesvm::LiteSVM,
    payer: &Keypair,
    ixs: &[solana_instruction::Instruction],
) -> String {
    match send(svm, payer, ixs) {
        Ok(_) => panic!("expected failure"),
        Err(err) => err.0,
    }
}

fn contains_err(hay: &str, needle: &str) {
    assert!(hay.contains(needle), "missing {needle} in {hay}");
}

#[test]
fn initialize_create_submit_finalize() {
    let mut local = env();
    let request = submit_ok(&mut local, 1, 0);
    finalize_ok(&mut local, request, 1);
    let request_acc = local.svm.get_account(&request).unwrap();
    let parsed: Request = deserialize_account(&request_acc);
    assert_eq!(parsed.status, protocol::STATUS_FINALIZED);
    assert_eq!(parsed.result_hash, RESULT);
}

#[test]
fn cancel_request() {
    let mut local = env();
    let request = submit_ok(&mut local, 1, 0);
    send(
        &mut local.svm,
        &local.owner,
        &[cancel_ix(local.owner.pubkey(), local.account, request)],
    )
    .expect("cancel");
    let parsed: Request = deserialize_account(&local.svm.get_account(&request).unwrap());
    assert_eq!(parsed.status, protocol::STATUS_CANCELLED);
}

#[test]
fn expire_request() {
    let mut local = env();
    let request = submit_ok(&mut local, 1, 0);
    let clock = local.svm.get_sysvar::<Clock>();
    local.svm.warp_to_slot(clock.slot + LIFETIME);
    send(
        &mut local.svm,
        &local.owner,
        &[expire_ix(local.owner.pubkey(), local.account, request)],
    )
    .expect("expire");
    let parsed: Request = deserialize_account(&local.svm.get_account(&request).unwrap());
    assert_eq!(parsed.status, protocol::STATUS_EXPIRED);
}

#[test]
fn duplicate_finalization_rejected() {
    let mut local = env();
    let request = submit_ok(&mut local, 1, 0);
    finalize_ok(&mut local, request, 1);
    let binding = result_binding(&local, request, 1);
    let relayer = Keypair::new();
    local.svm.airdrop(&relayer.pubkey(), 1_000_000_000).unwrap();
    let err = send_fail(
        &mut local.svm,
        &relayer,
        &finalize_ixs(
            relayer.pubkey(),
            local.config,
            local.account,
            request,
            &local.operator,
            &binding,
        ),
    );
    contains_err(&err, "invalid status");
}

#[test]
fn cancelled_finalize_rejected() {
    let mut local = env();
    let request = submit_ok(&mut local, 1, 0);
    send(
        &mut local.svm,
        &local.owner,
        &[cancel_ix(local.owner.pubkey(), local.account, request)],
    )
    .unwrap();
    let binding = result_binding(&local, request, 1);
    let err = send_fail(
        &mut local.svm,
        &local.owner,
        &finalize_ixs(
            local.owner.pubkey(),
            local.config,
            local.account,
            request,
            &local.operator,
            &binding,
        ),
    );
    contains_err(&err, "invalid status");
}

#[test]
fn expired_finalize_rejected() {
    let mut local = env();
    let request = submit_ok(&mut local, 1, 0);
    let clock = local.svm.get_sysvar::<Clock>();
    local.svm.warp_to_slot(clock.slot + LIFETIME);
    let binding = result_binding(&local, request, 1);
    let err = send_fail(
        &mut local.svm,
        &local.owner,
        &finalize_ixs(
            local.owner.pubkey(),
            local.config,
            local.account,
            request,
            &local.operator,
            &binding,
        ),
    );
    contains_err(&err, "request expired");
}

#[test]
fn wrong_owner_rejected() {
    let mut local = env();
    let stranger = Keypair::new();
    local
        .svm
        .airdrop(&stranger.pubkey(), 1_000_000_000)
        .unwrap();
    let request = request_pda(&local.account, 1);
    let err = send_fail(
        &mut local.svm,
        &stranger,
        &[submit_ix(
            stranger.pubkey(),
            local.config,
            local.account,
            request,
            AMOUNT,
            0,
            1,
        )],
    );
    assert!(!err.is_empty());
}

#[test]
fn wrong_config_and_mint_rejected() {
    let mut local = env();
    let other_mint = Keypair::new();
    let (other_config, _) = solana_address::Address::find_program_address(
        &[protocol::SEED_CONFIG, other_mint.pubkey().as_ref()],
        &confidential_lab::PROGRAM_ID,
    );
    send(
        &mut local.svm,
        &local.authority,
        &[initialize_ix(
            local.authority.pubkey(),
            other_mint.pubkey(),
            other_config,
            local.operator.pubkey(),
            PARAMS,
            LIFETIME,
        )],
    )
    .unwrap();
    let request = request_pda(&local.account, 1);
    let err = send_fail(
        &mut local.svm,
        &local.owner,
        &[submit_ix(
            local.owner.pubkey(),
            other_config,
            local.account,
            request,
            AMOUNT,
            0,
            1,
        )],
    );
    assert!(!err.is_empty());
}

#[test]
fn wrong_request_rejected() {
    let mut local = env();
    let request = submit_ok(&mut local, 1, 0);
    send(
        &mut local.svm,
        &local.owner,
        &[cancel_ix(local.owner.pubkey(), local.account, request)],
    )
    .unwrap();
    let request2 = submit_ok(&mut local, 2, 1);
    let mut binding = result_binding(&local, request2, 2);
    binding.request.request_pda = request.to_bytes();
    binding.request_digest = protocol::request_digest(&binding.request);
    let err = send_fail(
        &mut local.svm,
        &local.owner,
        &finalize_ixs(
            local.owner.pubkey(),
            local.config,
            local.account,
            request2,
            &local.operator,
            &binding,
        ),
    );
    contains_err(&err, "invalid result");
}

#[test]
fn wrong_nonce_rejected() {
    let mut local = env();
    let request = request_pda(&local.account, 9);
    let err = send_fail(
        &mut local.svm,
        &local.owner,
        &[submit_ix(
            local.owner.pubkey(),
            local.config,
            local.account,
            request,
            AMOUNT,
            0,
            9,
        )],
    );
    contains_err(&err, "invalid nonce");
}

#[test]
fn wrong_state_version_rejected() {
    let mut local = env();
    let request = request_pda(&local.account, 1);
    let err = send_fail(
        &mut local.svm,
        &local.owner,
        &[submit_ix(
            local.owner.pubkey(),
            local.config,
            local.account,
            request,
            AMOUNT,
            4,
            1,
        )],
    );
    contains_err(&err, "invalid state version");
}

#[test]
fn stale_state_version_finalize_rejected() {
    let mut local = env();
    let request = submit_ok(&mut local, 1, 0);
    mutate_account_state_version(&mut local, 99);
    let binding = result_binding(&local, request, 1);
    let err = send_fail(
        &mut local.svm,
        &local.owner,
        &finalize_ixs(
            local.owner.pubkey(),
            local.config,
            local.account,
            request,
            &local.operator,
            &binding,
        ),
    );
    contains_err(&err, "invalid state version");
}

#[test]
fn wrong_operator_rejected() {
    let mut local = env();
    let request = submit_ok(&mut local, 1, 0);
    let binding = result_binding(&local, request, 1);
    let other = Keypair::new();
    let err = send_fail(
        &mut local.svm,
        &local.owner,
        &finalize_ixs(
            local.owner.pubkey(),
            local.config,
            local.account,
            request,
            &other,
            &binding,
        ),
    );
    contains_err(&err, "invalid operator");
}

#[test]
fn wrong_operator_epoch_rejected() {
    let mut local = env();
    let request = submit_ok(&mut local, 1, 0);
    let next = Keypair::new();
    send(
        &mut local.svm,
        &local.authority,
        &[rotate_operator_ix(
            local.authority.pubkey(),
            local.config,
            next.pubkey(),
        )],
    )
    .unwrap();
    let binding = result_binding(&local, request, 1);
    let err = send_fail(
        &mut local.svm,
        &local.owner,
        &finalize_ixs(
            local.owner.pubkey(),
            local.config,
            local.account,
            request,
            &next,
            &binding,
        ),
    );
    contains_err(&err, "invalid operator epoch");
}

#[test]
fn wrong_key_version_rejected() {
    let mut local = env();
    let request = submit_ok(&mut local, 1, 0);
    send(
        &mut local.svm,
        &local.authority,
        &[set_key_version_ix(
            local.authority.pubkey(),
            local.config,
            9,
        )],
    )
    .unwrap();
    let binding = result_binding(&local, request, 1);
    let err = send_fail(
        &mut local.svm,
        &local.owner,
        &finalize_ixs(
            local.owner.pubkey(),
            local.config,
            local.account,
            request,
            &local.operator,
            &binding,
        ),
    );
    contains_err(&err, "invalid key version");
}

#[test]
fn wrong_result_digest_rejected() {
    let mut local = env();
    let request = submit_ok(&mut local, 1, 0);
    let signed = result_binding(&local, request, 1);
    let mut ixs = finalize_ixs(
        local.owner.pubkey(),
        local.config,
        local.account,
        request,
        &local.operator,
        &signed,
    );
    let mut data = ixs[1].data.clone();
    // Flip a byte inside the result_hash argument region after the 8-byte discriminator.
    data[8] ^= 0xff;
    ixs[1].data = data;
    let err = send_fail(&mut local.svm, &local.owner, &ixs);
    contains_err(&err, "invalid result");
}

#[test]
fn substituted_ciphertext_hash_rejected() {
    let mut local = env();
    let request = submit_ok(&mut local, 1, 0);
    let mut binding = result_binding(&local, request, 1);
    binding.request.amount_hash = [0x99; 32];
    binding.request_digest = protocol::request_digest(&binding.request);
    let err = send_fail(
        &mut local.svm,
        &local.owner,
        &finalize_ixs(
            local.owner.pubkey(),
            local.config,
            local.account,
            request,
            &local.operator,
            &binding,
        ),
    );
    contains_err(&err, "invalid result");
}

#[test]
fn second_active_request_rejected() {
    let mut local = env();
    let _ = submit_ok(&mut local, 1, 0);
    let request2 = request_pda(&local.account, 2);
    let err = send_fail(
        &mut local.svm,
        &local.owner,
        &[submit_ix(
            local.owner.pubkey(),
            local.config,
            local.account,
            request2,
            AMOUNT,
            0,
            2,
        )],
    );
    contains_err(&err, "active request exists");
}

#[test]
fn zero_ciphertext_ref_rejected() {
    let operator = Keypair::new();
    let mut local = boot_svm(&operator).unwrap();
    send(
        &mut local.svm,
        &local.authority,
        &[initialize_ix(
            local.authority.pubkey(),
            local.mint.pubkey(),
            local.config,
            local.operator.pubkey(),
            PARAMS,
            LIFETIME,
        )],
    )
    .unwrap();
    let err = send_fail(
        &mut local.svm,
        &local.owner,
        &[create_account_ix(
            local.owner.pubkey(),
            local.config,
            local.account,
            [0u8; 32],
            LIMIT,
        )],
    );
    contains_err(&err, "invalid ciphertext reference");
}

#[test]
fn rejects_cross_request_result_replay() {
    let mut local = env();
    let request_a = submit_ok(&mut local, 1, 0);
    let binding_a = result_binding(&local, request_a, 1);
    send(
        &mut local.svm,
        &local.owner,
        &[cancel_ix(local.owner.pubkey(), local.account, request_a)],
    )
    .unwrap();
    let request_b = submit_ok(&mut local, 2, 1);
    let err = send_fail(
        &mut local.svm,
        &local.owner,
        &finalize_ixs(
            local.owner.pubkey(),
            local.config,
            local.account,
            request_b,
            &local.operator,
            &binding_a,
        ),
    );
    contains_err(&err, "invalid result");
}

#[test]
fn rejects_cross_account_result_substitution() {
    let mut local = env();
    let request_x = submit_ok(&mut local, 1, 0);
    let binding_x = result_binding(&local, request_x, 1);

    let (owner_y, account_y) = create_second_account(&mut local);
    let request_y = request_pda(&account_y, 1);
    send(
        &mut local.svm,
        &owner_y,
        &[submit_ix(
            owner_y.pubkey(),
            local.config,
            account_y,
            request_y,
            AMOUNT,
            0,
            1,
        )],
    )
    .expect("submit Y");

    let err = send_fail(
        &mut local.svm,
        &owner_y,
        &finalize_ixs(
            owner_y.pubkey(),
            local.config,
            account_y,
            request_y,
            &local.operator,
            &binding_x,
        ),
    );
    contains_err(&err, "invalid result");
}

#[test]
fn rejects_cross_config_result_substitution() {
    let mut local = env();
    let request_a = submit_ok(&mut local, 1, 0);
    let binding_a = result_binding(&local, request_a, 1);

    let other_mint = Keypair::new();
    let (other_config, _) = solana_address::Address::find_program_address(
        &[protocol::SEED_CONFIG, other_mint.pubkey().as_ref()],
        &confidential_lab::PROGRAM_ID,
    );
    send(
        &mut local.svm,
        &local.authority,
        &[initialize_ix(
            local.authority.pubkey(),
            other_mint.pubkey(),
            other_config,
            local.operator.pubkey(),
            PARAMS,
            LIFETIME,
        )],
    )
    .unwrap();

    let owner_b = Keypair::new();
    local
        .svm
        .airdrop(&owner_b.pubkey(), 10_000_000_000)
        .unwrap();
    let (account_b, _) = solana_address::Address::find_program_address(
        &[
            protocol::SEED_ACCOUNT,
            other_mint.pubkey().as_ref(),
            owner_b.pubkey().as_ref(),
        ],
        &confidential_lab::PROGRAM_ID,
    );
    send(
        &mut local.svm,
        &owner_b,
        &[create_account_ix(
            owner_b.pubkey(),
            other_config,
            account_b,
            BALANCE,
            LIMIT,
        )],
    )
    .unwrap();
    let request_b = request_pda(&account_b, 1);
    send(
        &mut local.svm,
        &owner_b,
        &[submit_ix(
            owner_b.pubkey(),
            other_config,
            account_b,
            request_b,
            AMOUNT,
            0,
            1,
        )],
    )
    .unwrap();

    let err = send_fail(
        &mut local.svm,
        &owner_b,
        &finalize_ixs(
            owner_b.pubkey(),
            other_config,
            account_b,
            request_b,
            &local.operator,
            &binding_a,
        ),
    );
    contains_err(&err, "invalid result");
}

#[test]
fn rejects_mutated_request_digest_in_signed_message() {
    let mut local = env();
    let request = submit_ok(&mut local, 1, 0);
    let mut binding = result_binding(&local, request, 1);
    binding.request_digest[0] ^= 1;
    let err = send_fail(
        &mut local.svm,
        &local.owner,
        &finalize_ixs(
            local.owner.pubkey(),
            local.config,
            local.account,
            request,
            &local.operator,
            &binding,
        ),
    );
    contains_err(&err, "invalid result");
}

#[test]
fn rejects_wrong_result_type() {
    let mut local = env();
    let request = submit_ok(&mut local, 1, 0);
    let binding = result_binding(&local, request, 1);
    let mut ixs = finalize_ixs(
        local.owner.pubkey(),
        local.config,
        local.account,
        request,
        &local.operator,
        &binding,
    );
    // FinalizeArgs: discriminator (8) + result_hash (32) + result_type (u8)
    ixs[1].data[40] = 9;
    let err = send_fail(&mut local.svm, &local.owner, &ixs);
    contains_err(&err, "invalid result");
}

#[test]
fn rejects_wrong_circuit_id() {
    let mut local = env();
    let request = submit_ok(&mut local, 1, 0);
    let binding = result_binding(&local, request, 1);
    let mut ixs = finalize_ixs(
        local.owner.pubkey(),
        local.config,
        local.account,
        request,
        &local.operator,
        &binding,
    );
    // circuit_id is the u16 immediately after result_type.
    ixs[1].data[41] = 99;
    ixs[1].data[42] = 0;
    let err = send_fail(&mut local.svm, &local.owner, &ixs);
    contains_err(&err, "invalid operation");
}

#[test]
fn rejects_mutated_params_hash_in_signed_domain() {
    let mut local = env();
    let request = submit_ok(&mut local, 1, 0);
    let mut binding = result_binding(&local, request, 1);
    binding.request.params_hash = [0x99; 32];
    binding.request_digest = protocol::request_digest(&binding.request);
    let err = send_fail(
        &mut local.svm,
        &local.owner,
        &finalize_ixs(
            local.owner.pubkey(),
            local.config,
            local.account,
            request,
            &local.operator,
            &binding,
        ),
    );
    contains_err(&err, "invalid result");
}

#[test]
fn rejects_finalize_without_adjacent_ed25519_instruction() {
    let mut local = env();
    let request = submit_ok(&mut local, 1, 0);
    let binding = result_binding(&local, request, 1);
    let ixs = finalize_ixs(
        local.owner.pubkey(),
        local.config,
        local.account,
        request,
        &local.operator,
        &binding,
    );
    let err = send_fail(&mut local.svm, &local.owner, &[ixs[1].clone()]);
    contains_err(&err, "invalid signature");
}

#[test]
fn rejects_wrong_signed_message() {
    let mut local = env();
    let request = submit_ok(&mut local, 1, 0);
    let good = result_binding(&local, request, 1);
    let mut bad = good;
    bad.result_hash = [0xee; 32];
    let [verify_bad, _] = finalize_ixs(
        local.owner.pubkey(),
        local.config,
        local.account,
        request,
        &local.operator,
        &bad,
    );
    let [_, finalize_good] = finalize_ixs(
        local.owner.pubkey(),
        local.config,
        local.account,
        request,
        &local.operator,
        &good,
    );
    let err = send_fail(&mut local.svm, &local.owner, &[verify_bad, finalize_good]);
    contains_err(&err, "invalid result");
}

/// Native Ed25519 data layout: 16-byte header/offsets, then pubkey,
/// signature, and message. Offsets are little-endian u16s at the same
/// positions the coordinator reads (`ed25519.rs`).
fn ed25519_self_regions(data: &[u8]) -> (usize, usize, usize, usize) {
    assert!(data.len() >= 16, "Ed25519 instruction header too short");
    assert_eq!(data[0], 1, "expected exactly one Ed25519 signature");
    let sig_off = u16::from_le_bytes(data[2..4].try_into().unwrap()) as usize;
    let pk_off = u16::from_le_bytes(data[6..8].try_into().unwrap()) as usize;
    let msg_off = u16::from_le_bytes(data[10..12].try_into().unwrap()) as usize;
    let msg_sz = u16::from_le_bytes(data[12..14].try_into().unwrap()) as usize;
    assert!(
        sig_off.checked_add(64).is_some_and(|end| end <= data.len()),
        "signature offset {sig_off} is outside instruction data"
    );
    assert!(
        pk_off.checked_add(32).is_some_and(|end| end <= data.len()),
        "pubkey offset {pk_off} is outside instruction data"
    );
    assert!(
        msg_off
            .checked_add(msg_sz)
            .is_some_and(|end| end <= data.len()),
        "message region {msg_off}+{msg_sz} is outside instruction data"
    );
    (sig_off, pk_off, msg_off, msg_sz)
}

#[test]
fn rejects_corrupted_ed25519_signature() {
    let mut local = env();
    let request = submit_ok(&mut local, 1, 0);
    let binding = result_binding(&local, request, 1);
    let mut ixs = finalize_ixs(
        local.owner.pubkey(),
        local.config,
        local.account,
        request,
        &local.operator,
        &binding,
    );

    let header_before = ixs[0].data[..16].to_vec();
    let (sig_off, pk_off, msg_off, msg_sz) = ed25519_self_regions(&ixs[0].data);
    let pubkey_before = ixs[0].data[pk_off..pk_off + 32].to_vec();
    let message_before = ixs[0].data[msg_off..msg_off + msg_sz].to_vec();
    assert_eq!(
        pubkey_before,
        local.operator.pubkey().to_bytes(),
        "fixture must start with Config.operator in the Ed25519 pubkey region"
    );

    ixs[0].data[sig_off] ^= 0xff;

    assert_eq!(&ixs[0].data[..16], header_before.as_slice());
    assert_eq!(&ixs[0].data[pk_off..pk_off + 32], pubkey_before.as_slice());
    assert_eq!(
        &ixs[0].data[msg_off..msg_off + msg_sz],
        message_before.as_slice()
    );

    let err = send_fail(&mut local.svm, &local.owner, &ixs);
    assert!(
        !err.is_empty(),
        "native Ed25519 verification must reject a corrupted signature"
    );
    assert!(
        !err.contains("invalid result") && !err.contains("invalid operator"),
        "failure must be signature verification, not a message or pubkey mismatch: {err}"
    );
}

#[test]
fn rejects_ed25519_after_finalize() {
    let mut local = env();
    let request = submit_ok(&mut local, 1, 0);
    let binding = result_binding(&local, request, 1);
    let ixs = finalize_ixs(
        local.owner.pubkey(),
        local.config,
        local.account,
        request,
        &local.operator,
        &binding,
    );
    let err = send_fail(
        &mut local.svm,
        &local.owner,
        &[ixs[1].clone(), ixs[0].clone()],
    );
    contains_err(&err, "invalid signature");
}

#[test]
fn rejects_instruction_inserted_between_ed25519_and_finalize() {
    let mut local = env();
    let request = submit_ok(&mut local, 1, 0);
    let binding = result_binding(&local, request, 1);
    let ixs = finalize_ixs(
        local.owner.pubkey(),
        local.config,
        local.account,
        request,
        &local.operator,
        &binding,
    );
    let inserted = system_transfer_ix(local.owner.pubkey(), local.authority.pubkey(), 1);
    let err = send_fail(
        &mut local.svm,
        &local.owner,
        &[ixs[0].clone(), inserted, ixs[1].clone()],
    );
    contains_err(&err, "invalid signature");
}

#[test]
fn accepts_adjacent_ed25519_then_finalize() {
    let mut local = env();
    let before = read_confidential_account(&local, &local.account);
    assert_eq!(before.state_version, 0);
    assert_eq!(before.request_nonce, 0);
    let request = submit_ok(&mut local, 1, 0);
    let after_submit = read_confidential_account(&local, &local.account);
    assert_eq!(after_submit.request_nonce, 1);
    let binding = result_binding(&local, request, 1);
    send(
        &mut local.svm,
        &local.owner,
        &finalize_ixs(
            local.owner.pubkey(),
            local.config,
            local.account,
            request,
            &local.operator,
            &binding,
        ),
    )
    .expect("Ed25519 immediately before finalize must succeed");

    let parsed = read_request(&local, &request);
    let account = read_confidential_account(&local, &local.account);
    assert_eq!(parsed.status, protocol::STATUS_FINALIZED);
    assert_eq!(parsed.result_hash, RESULT);
    assert_eq!(parsed.result_digest, protocol::result_digest(&binding));
    assert_eq!(account.pending_request, solana_address::Address::default());
    assert_eq!(account.state_version, before.state_version + 1);
    assert_eq!(account.request_nonce, after_submit.request_nonce);
    assert_eq!(account.key_version, before.key_version);
}

#[test]
fn relayer_payer_can_finalize_with_operator_attestation() {
    let mut local = env();
    let request = submit_ok(&mut local, 1, 0);
    let binding = result_binding(&local, request, 1);
    let relayer = Keypair::new();
    local.svm.airdrop(&relayer.pubkey(), 1_000_000_000).unwrap();
    assert_ne!(relayer.pubkey(), local.operator.pubkey());
    send(
        &mut local.svm,
        &relayer,
        &finalize_ixs(
            relayer.pubkey(),
            local.config,
            local.account,
            request,
            &local.operator,
            &binding,
        ),
    )
    .expect("payer may differ from Config.operator");
    let parsed = read_request(&local, &request);
    assert_eq!(parsed.status, protocol::STATUS_FINALIZED);
    assert_eq!(parsed.result_hash, RESULT);
}

#[test]
fn relayer_payer_does_not_replace_fhe_operator() {
    let mut local = env();
    let request = submit_ok(&mut local, 1, 0);
    let binding = result_binding(&local, request, 1);
    let relayer = Keypair::new();
    local.svm.airdrop(&relayer.pubkey(), 1_000_000_000).unwrap();
    let err = send_fail(
        &mut local.svm,
        &relayer,
        &finalize_ixs(
            relayer.pubkey(),
            local.config,
            local.account,
            request,
            &relayer,
            &binding,
        ),
    );
    contains_err(&err, "invalid operator");
}

#[test]
fn successful_finalize_state_invariants_and_duplicate_is_stable() {
    let mut local = env();
    let request = submit_ok(&mut local, 1, 0);
    let binding = result_binding(&local, request, 1);
    finalize_ok(&mut local, request, 1);

    let first = read_request(&local, &request);
    let account_after = read_confidential_account(&local, &local.account);
    assert_eq!(first.status, protocol::STATUS_FINALIZED);
    assert_eq!(first.result_hash, RESULT);
    assert_eq!(first.result_digest, protocol::result_digest(&binding));
    assert_eq!(
        account_after.pending_request,
        solana_address::Address::default()
    );
    assert_eq!(account_after.state_version, 1);
    assert_eq!(account_after.request_nonce, 1);

    let relayer = Keypair::new();
    local.svm.airdrop(&relayer.pubkey(), 1_000_000_000).unwrap();
    let err = send_fail(
        &mut local.svm,
        &relayer,
        &finalize_ixs(
            relayer.pubkey(),
            local.config,
            local.account,
            request,
            &local.operator,
            &binding,
        ),
    );
    contains_err(&err, "invalid status");

    let second = read_request(&local, &request);
    let account_again = read_confidential_account(&local, &local.account);
    assert_eq!(second.status, protocol::STATUS_FINALIZED);
    assert_eq!(second.result_hash, first.result_hash);
    assert_eq!(second.result_digest, first.result_digest);
    assert_eq!(account_again.state_version, account_after.state_version);
    assert_eq!(account_again.request_nonce, account_after.request_nonce);
}

#[test]
fn cancel_clears_pending_without_committing_fhe_result() {
    let mut local = env();
    let request = submit_ok(&mut local, 1, 0);
    send(
        &mut local.svm,
        &local.owner,
        &[cancel_ix(local.owner.pubkey(), local.account, request)],
    )
    .unwrap();
    let parsed = read_request(&local, &request);
    let account = read_confidential_account(&local, &local.account);
    assert_eq!(parsed.status, protocol::STATUS_CANCELLED);
    assert_ne!(parsed.status, protocol::STATUS_FINALIZED);
    assert_eq!(parsed.result_hash, [0u8; 32]);
    assert_eq!(parsed.result_digest, [0u8; 32]);
    assert_eq!(account.pending_request, solana_address::Address::default());
    assert_eq!(account.state_version, 1);
    assert_eq!(account.request_nonce, 1);
}

#[test]
fn expire_clears_pending_without_committing_fhe_result() {
    let mut local = env();
    let request = submit_ok(&mut local, 1, 0);
    let clock = local.svm.get_sysvar::<Clock>();
    local.svm.warp_to_slot(clock.slot + LIFETIME);
    send(
        &mut local.svm,
        &local.owner,
        &[expire_ix(local.owner.pubkey(), local.account, request)],
    )
    .unwrap();
    let parsed = read_request(&local, &request);
    let account = read_confidential_account(&local, &local.account);
    assert_eq!(parsed.status, protocol::STATUS_EXPIRED);
    assert_ne!(parsed.status, protocol::STATUS_FINALIZED);
    assert_eq!(parsed.result_hash, [0u8; 32]);
    assert_eq!(parsed.result_digest, [0u8; 32]);
    assert_eq!(account.pending_request, solana_address::Address::default());
    assert_eq!(account.state_version, 1);
    assert_eq!(account.request_nonce, 1);
}

#[test]
fn rejects_cancel_of_finalized_request() {
    let mut local = env();
    let request = submit_ok(&mut local, 1, 0);
    finalize_ok(&mut local, request, 1);
    let err = send_fail(
        &mut local.svm,
        &local.owner,
        &[cancel_ix(local.owner.pubkey(), local.account, request)],
    );
    contains_err(&err, "invalid status");
}

#[test]
fn rejects_expire_of_finalized_request() {
    let mut local = env();
    let request = submit_ok(&mut local, 1, 0);
    finalize_ok(&mut local, request, 1);
    let clock = local.svm.get_sysvar::<Clock>();
    local.svm.warp_to_slot(clock.slot + LIFETIME);
    let err = send_fail(
        &mut local.svm,
        &local.owner,
        &[expire_ix(local.owner.pubkey(), local.account, request)],
    );
    contains_err(&err, "invalid status");
}

#[test]
fn rejects_operator_signature_after_operator_rotation() {
    let mut local = env();
    let request = submit_ok(&mut local, 1, 0);
    let binding = result_binding(&local, request, 1);
    let next = Keypair::new();
    send(
        &mut local.svm,
        &local.authority,
        &[rotate_operator_ix(
            local.authority.pubkey(),
            local.config,
            next.pubkey(),
        )],
    )
    .unwrap();
    let config = read_config(&local);
    assert_eq!(config.operator, next.pubkey());
    assert_eq!(config.operator_epoch, 2);
    let err = send_fail(
        &mut local.svm,
        &local.owner,
        &finalize_ixs(
            local.owner.pubkey(),
            local.config,
            local.account,
            request,
            &local.operator,
            &binding,
        ),
    );
    contains_err(&err, "invalid operator epoch");
}

#[test]
fn submit_rejected_after_config_key_version_change() {
    let mut local = env();
    let account_before = read_confidential_account(&local, &local.account);
    send(
        &mut local.svm,
        &local.authority,
        &[set_key_version_ix(
            local.authority.pubkey(),
            local.config,
            account_before.key_version + 1,
        )],
    )
    .unwrap();
    let config = read_config(&local);
    let account_after = read_confidential_account(&local, &local.account);
    assert_eq!(config.key_version, account_before.key_version + 1);
    assert_eq!(account_after.key_version, account_before.key_version);
    let request = request_pda(&local.account, 1);
    let err = send_fail(
        &mut local.svm,
        &local.owner,
        &[submit_ix(
            local.owner.pubkey(),
            local.config,
            local.account,
            request,
            AMOUNT,
            0,
            1,
        )],
    );
    contains_err(&err, "invalid key version");
}

#[test]
fn pause_blocks_create_submit_and_finalize() {
    let mut local = env();
    send(
        &mut local.svm,
        &local.authority,
        &[set_paused_ix(local.authority.pubkey(), local.config, true)],
    )
    .unwrap();

    let stranger = Keypair::new();
    local
        .svm
        .airdrop(&stranger.pubkey(), 10_000_000_000)
        .unwrap();
    let (account2, _) = solana_address::Address::find_program_address(
        &[
            protocol::SEED_ACCOUNT,
            local.mint.pubkey().as_ref(),
            stranger.pubkey().as_ref(),
        ],
        &confidential_lab::PROGRAM_ID,
    );
    let create_err = send_fail(
        &mut local.svm,
        &stranger,
        &[create_account_ix(
            stranger.pubkey(),
            local.config,
            account2,
            BALANCE,
            LIMIT,
        )],
    );
    contains_err(&create_err, "paused");

    let request = request_pda(&local.account, 1);
    let submit_err = send_fail(
        &mut local.svm,
        &local.owner,
        &[submit_ix(
            local.owner.pubkey(),
            local.config,
            local.account,
            request,
            AMOUNT,
            0,
            1,
        )],
    );
    contains_err(&submit_err, "paused");

    expire_blockhash(&mut local);
    send(
        &mut local.svm,
        &local.authority,
        &[set_paused_ix(local.authority.pubkey(), local.config, false)],
    )
    .unwrap();
    let request = submit_ok(&mut local, 1, 0);
    send(
        &mut local.svm,
        &local.authority,
        &[set_paused_ix(local.authority.pubkey(), local.config, true)],
    )
    .unwrap();
    let binding = result_binding(&local, request, 1);
    let finalize_err = send_fail(
        &mut local.svm,
        &local.owner,
        &finalize_ixs(
            local.owner.pubkey(),
            local.config,
            local.account,
            request,
            &local.operator,
            &binding,
        ),
    );
    contains_err(&finalize_err, "paused");
}

#[test]
fn pause_permits_cancel() {
    let mut local = env();
    let request = submit_ok(&mut local, 1, 0);
    send(
        &mut local.svm,
        &local.authority,
        &[set_paused_ix(local.authority.pubkey(), local.config, true)],
    )
    .unwrap();
    send(
        &mut local.svm,
        &local.owner,
        &[cancel_ix(local.owner.pubkey(), local.account, request)],
    )
    .expect("cancel must remain available while paused");
    assert_eq!(
        read_request(&local, &request).status,
        protocol::STATUS_CANCELLED
    );
}

#[test]
fn pause_permits_expire() {
    let mut local = env();
    let request = submit_ok(&mut local, 1, 0);
    send(
        &mut local.svm,
        &local.authority,
        &[set_paused_ix(local.authority.pubkey(), local.config, true)],
    )
    .unwrap();
    let clock = local.svm.get_sysvar::<Clock>();
    local.svm.warp_to_slot(clock.slot + LIFETIME);
    send(
        &mut local.svm,
        &local.owner,
        &[expire_ix(local.owner.pubkey(), local.account, request)],
    )
    .expect("expire must remain available while paused");
    assert_eq!(
        read_request(&local, &request).status,
        protocol::STATUS_EXPIRED
    );
}

fn deserialize_account<T: anchor_lang::AccountDeserialize>(account: &Account) -> T {
    let mut data = account.data.as_slice();
    T::try_deserialize(&mut data).expect("account decode")
}

fn mutate_account_state_version(local: &mut LocalSvm, version: u64) {
    let mut account = local.svm.get_account(&local.account).unwrap();
    let mut parsed: ConfidentialAccount = deserialize_account(&account);
    parsed.state_version = version;
    let mut buf = Vec::new();
    parsed.try_serialize(&mut buf).unwrap();
    account.data = buf;
    local.svm.set_account(local.account, account).unwrap();
}
