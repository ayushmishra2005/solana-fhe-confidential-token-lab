use anchor_lang::AccountSerialize;
use confidential_coordinator::state::{ConfidentialAccount, Request};
use confidential_lab::{
    boot_svm, cancel_ix, create_account_ix, expire_ix, finalize_ixs, initialize_ix, request_pda,
    rotate_operator_ix, send, set_key_version_ix, submit_ix, LocalSvm,
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
    let onchain: Request = deserialize_account(&local.svm.get_account(&request).unwrap());
    assert_eq!(onchain.request_nonce, nonce);
    let request_binding = protocol::RequestBinding {
        protocol_version: protocol::PROTOCOL_VERSION,
        domain_id: protocol::local_domain_id(),
        program_id: confidential_coordinator::ID.to_bytes(),
        config: local.config.to_bytes(),
        mint: local.mint.pubkey().to_bytes(),
        confidential_account: local.account.to_bytes(),
        request_pda: request.to_bytes(),
        operation: protocol::OPERATION_POLICY_CHECK,
        balance_hash: BALANCE,
        amount_hash: AMOUNT,
        limit_hash: LIMIT,
        params_hash: PARAMS,
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
