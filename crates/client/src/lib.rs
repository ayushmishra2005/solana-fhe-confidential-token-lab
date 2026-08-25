use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anchor_lang::{InstructionData, ToAccountMetas};
use confidential_coordinator::accounts as accs;
use confidential_coordinator::instruction as ixs;
use confidential_coordinator::{CreateAccountArgs, FinalizeArgs, InitializeConfigArgs, SubmitArgs};
use confidential_protocol as protocol;
use fhe_worker::{
    activate_server_key, decrypt_bool, encrypt_u64, evaluate_policy, generate_material, load_bool,
    process_request, store_u64, write_client_key, write_server_key, BlobStore, FheMaterial,
    RequestFile,
};
use litesvm::LiteSVM;
use solana_clock::Clock;
use solana_ed25519_program::new_ed25519_instruction_with_signature;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;

pub const PROGRAM_ID: solana_address::Address =
    solana_address::address!("2xNTgr7PmWSQRqGcMuCVhdTQLRP8bexVHGJ2CjxiJM6X");

#[derive(Debug)]
pub struct LabError(pub String);

impl std::fmt::Display for LabError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for LabError {}

impl From<fhe_worker::WorkerError> for LabError {
    fn from(err: fhe_worker::WorkerError) -> Self {
        Self(err.to_string())
    }
}

impl From<std::io::Error> for LabError {
    fn from(err: std::io::Error) -> Self {
        Self(err.to_string())
    }
}

pub fn program_bytes() -> Result<Vec<u8>, LabError> {
    let mut candidates = vec![
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/deploy/confidential_coordinator.so"),
        PathBuf::from("target/deploy/confidential_coordinator.so"),
        PathBuf::from(
            "programs/confidential-coordinator/target/deploy/confidential_coordinator.so",
        ),
    ];
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join("target/deploy/confidential_coordinator.so"));
    }
    for path in candidates {
        if path.exists() {
            return Ok(fs::read(path)?);
        }
    }
    Err(LabError(
        "missing confidential_coordinator.so; run cargo build-sbf --manifest-path programs/confidential-coordinator/Cargo.toml"
            .into(),
    ))
}

pub fn data_paths(root: &Path) -> DataPaths {
    DataPaths {
        root: root.to_path_buf(),
        keys: root.join("keys"),
        ciphertexts: root.join("ciphertexts"),
        client_key: root.join("keys/client.bin"),
        server_key: root.join("keys/server.bin"),
        operator: root.join("keys/operator.json"),
        params: root.join("keys/params.json"),
        request: root.join("request.json"),
        result: root.join("result.json"),
    }
}

pub struct DataPaths {
    pub root: PathBuf,
    pub keys: PathBuf,
    pub ciphertexts: PathBuf,
    pub client_key: PathBuf,
    pub server_key: PathBuf,
    pub operator: PathBuf,
    pub params: PathBuf,
    pub request: PathBuf,
    pub result: PathBuf,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct ParamsFile {
    pub params_hash: String,
    pub key_version: u32,
}

pub fn setup(root: &Path) -> Result<FheMaterial, LabError> {
    let paths = data_paths(root);
    fs::create_dir_all(&paths.keys)?;
    fs::create_dir_all(&paths.ciphertexts)?;
    let material = generate_material()?;
    write_client_key(&paths.client_key, &material.client_key)?;
    write_server_key(&paths.server_key, &material.compressed_server_key)?;
    let operator = Keypair::new();
    fs::write(
        &paths.operator,
        serde_json::to_vec(&operator.to_bytes().to_vec()).map_err(|e| LabError(e.to_string()))?,
    )?;
    let params = ParamsFile {
        params_hash: hex::encode(material.params_hash),
        key_version: 1,
    };
    fs::write(
        &paths.params,
        serde_json::to_vec_pretty(&params).map_err(|e| LabError(e.to_string()))?,
    )?;
    Ok(material)
}

pub struct EncryptedRefs {
    pub balance_hash: [u8; 32],
    pub amount_hash: [u8; 32],
    pub limit_hash: [u8; 32],
}

pub fn encrypt_inputs(
    root: &Path,
    material: &FheMaterial,
    balance: u64,
    amount: u64,
    limit: u64,
) -> Result<EncryptedRefs, LabError> {
    let paths = data_paths(root);
    let store = BlobStore::new(&paths.ciphertexts)?;
    let key_version = 1;
    let balance_hash = store_u64(
        &store,
        &encrypt_u64(balance, &material.client_key),
        key_version,
        &material.params_hash,
    )?;
    let amount_hash = store_u64(
        &store,
        &encrypt_u64(amount, &material.client_key),
        key_version,
        &material.params_hash,
    )?;
    let limit_hash = store_u64(
        &store,
        &encrypt_u64(limit, &material.client_key),
        key_version,
        &material.params_hash,
    )?;
    Ok(EncryptedRefs {
        balance_hash,
        amount_hash,
        limit_hash,
    })
}

pub fn read_operator(path: &Path) -> Result<Keypair, LabError> {
    let bytes = fs::read(path)?;
    let json: Vec<u8> = serde_json::from_slice(&bytes).map_err(|e| LabError(e.to_string()))?;
    Keypair::try_from(json.as_slice()).map_err(|e| LabError(e.to_string()))
}

pub struct LocalSvm {
    pub svm: LiteSVM,
    pub authority: Keypair,
    pub owner: Keypair,
    pub operator: Keypair,
    pub mint: Keypair,
    pub config: solana_address::Address,
    pub account: solana_address::Address,
}

pub fn boot_svm(operator: &Keypair) -> Result<LocalSvm, LabError> {
    let mut svm = LiteSVM::new();
    svm.add_program(PROGRAM_ID, &program_bytes()?)
        .map_err(|e| LabError(format!("{e:?}")))?;
    let authority = Keypair::new();
    let owner = Keypair::new();
    let mint = Keypair::new();
    svm.airdrop(&authority.pubkey(), 10_000_000_000)
        .map_err(|e| LabError(format!("{e:?}")))?;
    svm.airdrop(&owner.pubkey(), 10_000_000_000)
        .map_err(|e| LabError(format!("{e:?}")))?;
    let (config, _) = solana_address::Address::find_program_address(
        &[protocol::SEED_CONFIG, mint.pubkey().as_ref()],
        &PROGRAM_ID,
    );
    let (account, _) = solana_address::Address::find_program_address(
        &[
            protocol::SEED_ACCOUNT,
            mint.pubkey().as_ref(),
            owner.pubkey().as_ref(),
        ],
        &PROGRAM_ID,
    );
    Ok(LocalSvm {
        svm,
        authority,
        owner,
        operator: clone_keypair(operator),
        mint,
        config,
        account,
    })
}

pub fn request_pda(account: &solana_address::Address, nonce: u64) -> solana_address::Address {
    solana_address::Address::find_program_address(
        &[
            protocol::SEED_REQUEST,
            account.as_ref(),
            &nonce.to_le_bytes(),
        ],
        &PROGRAM_ID,
    )
    .0
}

pub fn send(
    svm: &mut LiteSVM,
    payer: &Keypair,
    ixs: &[Instruction],
) -> Result<litesvm::types::TransactionMetadata, LabError> {
    let blockhash = svm.latest_blockhash();
    let msg = Message::new(ixs, Some(&payer.pubkey()));
    let tx = Transaction::new(&[payer], msg, blockhash);
    svm.send_transaction(tx)
        .map_err(|e| LabError(format!("{e:?}")))
}

pub fn initialize_ix(
    authority: solana_address::Address,
    mint: solana_address::Address,
    config: solana_address::Address,
    operator: solana_address::Address,
    params_hash: [u8; 32],
    max_request_lifetime_slots: u64,
) -> Instruction {
    Instruction {
        program_id: PROGRAM_ID,
        accounts: accs::InitializeConfig {
            authority,
            mint,
            config,
            system_program: anchor_lang::system_program::ID,
        }
        .to_account_metas(None),
        data: ixs::InitializeConfig {
            args: InitializeConfigArgs {
                domain_id: protocol::local_domain_id(),
                operator,
                key_version: 1,
                params_hash,
                max_request_lifetime_slots,
            },
        }
        .data(),
    }
}

pub fn create_account_ix(
    owner: solana_address::Address,
    config: solana_address::Address,
    account: solana_address::Address,
    balance_hash: [u8; 32],
    limit_hash: [u8; 32],
) -> Instruction {
    Instruction {
        program_id: PROGRAM_ID,
        accounts: accs::CreateAccount {
            owner,
            config,
            account,
            system_program: anchor_lang::system_program::ID,
        }
        .to_account_metas(None),
        data: ixs::CreateAccount {
            args: CreateAccountArgs {
                balance_hash,
                limit_hash,
            },
        }
        .data(),
    }
}

pub fn submit_ix(
    owner: solana_address::Address,
    config: solana_address::Address,
    account: solana_address::Address,
    request: solana_address::Address,
    amount_hash: [u8; 32],
    expected_state_version: u64,
    expected_nonce: u64,
) -> Instruction {
    Instruction {
        program_id: PROGRAM_ID,
        accounts: accs::Submit {
            owner,
            config,
            account,
            request,
            system_program: anchor_lang::system_program::ID,
        }
        .to_account_metas(None),
        data: ixs::Submit {
            args: SubmitArgs {
                amount_hash,
                expected_state_version,
                expected_nonce,
            },
        }
        .data(),
    }
}

pub fn cancel_ix(
    owner: solana_address::Address,
    account: solana_address::Address,
    request: solana_address::Address,
) -> Instruction {
    Instruction {
        program_id: PROGRAM_ID,
        accounts: accs::Cancel {
            owner,
            account,
            request,
        }
        .to_account_metas(None),
        data: ixs::Cancel.data(),
    }
}

pub fn expire_ix(
    payer: solana_address::Address,
    account: solana_address::Address,
    request: solana_address::Address,
) -> Instruction {
    Instruction {
        program_id: PROGRAM_ID,
        accounts: accs::Expire {
            payer,
            account,
            request,
        }
        .to_account_metas(None),
        data: ixs::Expire.data(),
    }
}

pub fn rotate_operator_ix(
    authority: solana_address::Address,
    config: solana_address::Address,
    new_operator: solana_address::Address,
) -> Instruction {
    Instruction {
        program_id: PROGRAM_ID,
        accounts: accs::AdminConfig { authority, config }.to_account_metas(None),
        data: ixs::RotateOperator { new_operator }.data(),
    }
}

pub fn set_key_version_ix(
    authority: solana_address::Address,
    config: solana_address::Address,
    key_version: u32,
) -> Instruction {
    Instruction {
        program_id: PROGRAM_ID,
        accounts: accs::AdminConfig { authority, config }.to_account_metas(None),
        data: ixs::SetKeyVersion { key_version }.data(),
    }
}

pub fn set_paused_ix(
    authority: solana_address::Address,
    config: solana_address::Address,
    paused: bool,
) -> Instruction {
    Instruction {
        program_id: PROGRAM_ID,
        accounts: accs::AdminConfig { authority, config }.to_account_metas(None),
        data: ixs::SetPaused { paused }.data(),
    }
}

pub fn finalize_ixs(
    payer: solana_address::Address,
    config: solana_address::Address,
    account: solana_address::Address,
    request: solana_address::Address,
    operator: &Keypair,
    binding: &protocol::ResultBinding,
) -> [Instruction; 2] {
    let message = protocol::encode_result(binding);
    let signature = operator.sign_message(&message);
    let sig: [u8; 64] = signature.as_ref().try_into().expect("ed25519 signature");
    let verify =
        new_ed25519_instruction_with_signature(&message, &sig, &operator.pubkey().to_bytes());
    let finalize = Instruction {
        program_id: PROGRAM_ID,
        accounts: accs::Finalize {
            payer,
            config,
            account,
            request,
            instructions: confidential_coordinator::ed25519::INSTRUCTIONS_ID,
        }
        .to_account_metas(None),
        data: ixs::Finalize {
            args: FinalizeArgs {
                result_hash: binding.result_hash,
                result_type: binding.result_type,
                circuit_id: binding.circuit_id,
            },
        }
        .data(),
    };
    [verify, finalize]
}

pub struct DemoReport {
    pub allowed: bool,
    pub result_hash: [u8; 32],
    pub submit_cu: u64,
    pub finalize_cu: u64,
}

pub fn run_demo(
    root: &Path,
    balance: u64,
    amount: u64,
    limit: u64,
) -> Result<DemoReport, LabError> {
    let paths = data_paths(root);
    let material = setup(root)?;
    let EncryptedRefs {
        balance_hash,
        amount_hash,
        limit_hash,
    } = encrypt_inputs(root, &material, balance, amount, limit)?;
    let operator = read_operator(&paths.operator)?;
    let mut local = boot_svm(&operator)?;

    send(
        &mut local.svm,
        &local.authority,
        &[initialize_ix(
            local.authority.pubkey(),
            local.mint.pubkey(),
            local.config,
            local.operator.pubkey(),
            material.params_hash,
            1_000,
        )],
    )?;
    send(
        &mut local.svm,
        &local.owner,
        &[create_account_ix(
            local.owner.pubkey(),
            local.config,
            local.account,
            balance_hash,
            limit_hash,
        )],
    )?;
    let nonce = 1;
    let request = request_pda(&local.account, nonce);
    let submit_meta = send(
        &mut local.svm,
        &local.owner,
        &[submit_ix(
            local.owner.pubkey(),
            local.config,
            local.account,
            request,
            amount_hash,
            0,
            nonce,
        )],
    )?;

    let clock = local.svm.get_sysvar::<Clock>();
    let binding = protocol::RequestBinding {
        protocol_version: protocol::PROTOCOL_VERSION,
        domain_id: protocol::local_domain_id(),
        program_id: confidential_coordinator::ID.to_bytes(),
        config: local.config.to_bytes(),
        mint: local.mint.pubkey().to_bytes(),
        confidential_account: local.account.to_bytes(),
        request_pda: request.to_bytes(),
        operation: protocol::OPERATION_POLICY_CHECK,
        balance_hash,
        amount_hash,
        limit_hash,
        params_hash: material.params_hash,
        state_version: 0,
        request_nonce: nonce,
        key_version: 1,
        operator_epoch: 1,
        expiry_slot: clock.slot + 1_000,
    };
    fs::write(
        &paths.request,
        serde_json::to_vec_pretty(&fhe_worker::request_to_file(&binding))
            .map_err(|e| LabError(e.to_string()))?,
    )?;
    let store = BlobStore::new(&paths.ciphertexts)?;
    let (result, signature) =
        process_request(&store, &binding, &material.compressed_server_key, &operator)?;
    let result_file = fhe_worker::ResultFile {
        result_hash: hex::encode(result.result_hash),
        result_type: result.result_type,
        circuit_id: result.circuit_id,
        request_digest: hex::encode(result.request_digest),
        result_digest: hex::encode(protocol::result_digest(&result)),
        signature: hex::encode(signature),
        operator: hex::encode(operator.pubkey().to_bytes()),
    };
    fs::write(
        &paths.result,
        serde_json::to_vec_pretty(&result_file).map_err(|e| LabError(e.to_string()))?,
    )?;

    let finalize_meta = send(
        &mut local.svm,
        &local.owner,
        &finalize_ixs(
            local.owner.pubkey(),
            local.config,
            local.account,
            request,
            &operator,
            &result,
        ),
    )?;
    let allowed = decrypt_bool(
        &load_bool(&store, &result.result_hash, 1, &material.params_hash)?,
        &material.client_key,
    );
    Ok(DemoReport {
        allowed,
        result_hash: result.result_hash,
        submit_cu: submit_meta.compute_units_consumed,
        finalize_cu: finalize_meta.compute_units_consumed,
    })
}

pub struct MeasureReport {
    pub hardware: String,
    pub client_key_bytes: usize,
    pub compressed_server_key_bytes: usize,
    pub server_key_bytes: usize,
    pub u64_ciphertext_bytes: usize,
    pub bool_ciphertext_bytes: usize,
    pub keygen_ms: u128,
    pub encrypt_three_ms: u128,
    pub policy_ms: u128,
}

pub fn measure() -> Result<MeasureReport, LabError> {
    let started = Instant::now();
    let material = generate_material()?;
    let keygen_ms = started.elapsed().as_millis();
    activate_server_key(&material.server_key);
    let enc_started = Instant::now();
    let balance = encrypt_u64(100, &material.client_key);
    let amount = encrypt_u64(25, &material.client_key);
    let limit = encrypt_u64(50, &material.client_key);
    let encrypt_three_ms = enc_started.elapsed().as_millis();
    let policy_started = Instant::now();
    let allowed = evaluate_policy(&balance, &amount, &limit);
    let policy_ms = policy_started.elapsed().as_millis();

    let client_key_path = std::env::temp_dir().join("ctl-measure-client.bin");
    let server_key_path = std::env::temp_dir().join("ctl-measure-server.bin");
    write_client_key(&client_key_path, &material.client_key)?;
    write_server_key(&server_key_path, &material.compressed_server_key)?;
    let client_key_bytes = std::fs::read(&client_key_path)?.len();
    let compressed_server_key_bytes = std::fs::read(&server_key_path)?.len();
    let _ = std::fs::remove_file(client_key_path);
    let _ = std::fs::remove_file(server_key_path);
    let server_key_bytes = fhe_worker::serialized_server_key_len(&material.server_key)?;
    let u64_ciphertext_bytes = fhe_worker::serialize_u64(&balance)?.len();
    let bool_ciphertext_bytes = fhe_worker::serialize_bool(&allowed)?.len();
    Ok(MeasureReport {
        hardware: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        client_key_bytes,
        compressed_server_key_bytes,
        server_key_bytes,
        u64_ciphertext_bytes,
        bool_ciphertext_bytes,
        keygen_ms,
        encrypt_three_ms,
        policy_ms,
    })
}

fn clone_keypair(keypair: &Keypair) -> Keypair {
    Keypair::try_from(&keypair.to_bytes()[..]).expect("keypair clone")
}

pub fn write_request_file(path: &Path, binding: &protocol::RequestBinding) -> Result<(), LabError> {
    fs::write(
        path,
        serde_json::to_vec_pretty(&fhe_worker::request_to_file(binding))
            .map_err(|e| LabError(e.to_string()))?,
    )?;
    Ok(())
}

pub fn read_request_file(path: &Path) -> Result<protocol::RequestBinding, LabError> {
    let file: RequestFile =
        serde_json::from_slice(&fs::read(path)?).map_err(|e| LabError(e.to_string()))?;
    fhe_worker::request_from_file(&file).map_err(Into::into)
}
