//! Off-chain TFHE evaluation. Never decrypts policy operands or the result.

use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use confidential_protocol as protocol;
use solana_keypair::Keypair;
use solana_signer::Signer;
use tfhe::prelude::*;
use tfhe::safe_serialization::{safe_deserialize, safe_serialize};
use tfhe::{
    generate_keys, set_server_key, ClientKey, CompressedServerKey, ConfigBuilder, FheBool,
    FheUint64, ServerKey,
};

pub const CLIENT_KEY_LIMIT: u64 = 1 << 26;
pub const SERVER_KEY_LIMIT: u64 = 1 << 30;
pub const CIPHERTEXT_LIMIT: u64 = 1 << 22;
pub const BOOL_LIMIT: u64 = 1 << 20;

#[derive(Debug)]
pub enum WorkerError {
    Io(String),
    HashMismatch,
    Blob(protocol::BlobError),
    Deserialize,
    Serialize,
    Params,
    Unsupported,
    StorePath,
}

impl std::fmt::Display for WorkerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(msg) => write!(f, "io: {msg}"),
            Self::HashMismatch => write!(f, "ciphertext hash mismatch"),
            Self::Blob(err) => write!(f, "blob: {err:?}"),
            Self::Deserialize => write!(f, "ciphertext deserialize failed"),
            Self::Serialize => write!(f, "ciphertext serialize failed"),
            Self::Params => write!(f, "parameter mismatch"),
            Self::Unsupported => write!(f, "unsupported operation"),
            Self::StorePath => write!(f, "refusing untrusted store path"),
        }
    }
}

impl std::error::Error for WorkerError {}

impl From<std::io::Error> for WorkerError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err.to_string())
    }
}

#[derive(Clone)]
pub struct FheMaterial {
    pub client_key: ClientKey,
    pub server_key: ServerKey,
    pub compressed_server_key: CompressedServerKey,
    pub params_hash: [u8; 32],
}

pub fn generate_material() -> Result<FheMaterial, WorkerError> {
    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);
    let compressed_server_key = CompressedServerKey::new(&client_key);
    // Commit to the exact evaluation key. Config is not safe-serializable in 1.7.0.
    let params_hash = hash_compressed_server_key(&compressed_server_key)?;
    Ok(FheMaterial {
        client_key,
        server_key,
        compressed_server_key,
        params_hash,
    })
}

pub fn hash_compressed_server_key(key: &CompressedServerKey) -> Result<[u8; 32], WorkerError> {
    let mut buf = Vec::new();
    safe_serialize(key, &mut buf, SERVER_KEY_LIMIT).map_err(|_| WorkerError::Serialize)?;
    Ok(protocol::sha256(&buf))
}

/// Reject an evaluation key that is not the exact committed CompressedServerKey.
pub fn require_server_key_commitment(
    key: &CompressedServerKey,
    expected: &[u8; 32],
) -> Result<(), WorkerError> {
    let actual = hash_compressed_server_key(key)?;
    if actual != *expected {
        return Err(WorkerError::Params);
    }
    Ok(())
}

pub fn activate_server_key(server_key: &ServerKey) {
    set_server_key(server_key.clone());
}

pub fn encrypt_u64(value: u64, client_key: &ClientKey) -> FheUint64 {
    FheUint64::encrypt(value, client_key)
}

pub fn decrypt_u64(ct: &FheUint64, client_key: &ClientKey) -> u64 {
    ct.decrypt(client_key)
}

pub fn decrypt_bool(ct: &FheBool, client_key: &ClientKey) -> bool {
    ct.decrypt(client_key)
}

/// Encrypted predicate: (balance >= amount) && (amount <= limit).
pub fn evaluate_policy(balance: &FheUint64, amount: &FheUint64, limit: &FheUint64) -> FheBool {
    let balance_ok = balance.ge(amount);
    let limit_ok = amount.le(limit);
    balance_ok & limit_ok
}

pub fn serialize_u64(ct: &FheUint64) -> Result<Vec<u8>, WorkerError> {
    let mut buf = Vec::new();
    safe_serialize(ct, &mut buf, CIPHERTEXT_LIMIT).map_err(|_| WorkerError::Serialize)?;
    Ok(buf)
}

pub fn serialize_bool(ct: &FheBool) -> Result<Vec<u8>, WorkerError> {
    let mut buf = Vec::new();
    safe_serialize(ct, &mut buf, BOOL_LIMIT).map_err(|_| WorkerError::Serialize)?;
    Ok(buf)
}

pub fn deserialize_u64(bytes: &[u8]) -> Result<FheUint64, WorkerError> {
    safe_deserialize(&mut Cursor::new(bytes), CIPHERTEXT_LIMIT)
        .map_err(|_| WorkerError::Deserialize)
}

pub fn deserialize_bool(bytes: &[u8]) -> Result<FheBool, WorkerError> {
    safe_deserialize(&mut Cursor::new(bytes), BOOL_LIMIT).map_err(|_| WorkerError::Deserialize)
}

pub struct BlobStore {
    root: PathBuf,
}

impl BlobStore {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, WorkerError> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    pub fn put(&self, bytes: &[u8]) -> Result<[u8; 32], WorkerError> {
        let hash = protocol::sha256(bytes);
        let path = self.path_for(&hash)?;
        if !path.exists() {
            let tmp = path.with_extension("tmp");
            fs::write(&tmp, bytes)?;
            fs::rename(tmp, path)?;
        }
        Ok(hash)
    }

    pub fn get(&self, expected: &[u8; 32]) -> Result<Vec<u8>, WorkerError> {
        let path = self.path_for(expected)?;
        let bytes = fs::read(path)?;
        if protocol::sha256(&bytes) != *expected {
            return Err(WorkerError::HashMismatch);
        }
        Ok(bytes)
    }

    fn path_for(&self, hash: &[u8; 32]) -> Result<PathBuf, WorkerError> {
        let name = hex::encode(hash);
        if name.len() != 64 || !name.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(WorkerError::StorePath);
        }
        Ok(self.root.join(name))
    }
}

pub fn store_u64(
    store: &BlobStore,
    ct: &FheUint64,
    key_version: u32,
    params_hash: &[u8; 32],
) -> Result<[u8; 32], WorkerError> {
    let payload = serialize_u64(ct)?;
    let blob = protocol::wrap_blob(protocol::CT_KIND_U64, key_version, params_hash, &payload);
    store.put(&blob)
}

pub fn store_bool(
    store: &BlobStore,
    ct: &FheBool,
    key_version: u32,
    params_hash: &[u8; 32],
) -> Result<[u8; 32], WorkerError> {
    let payload = serialize_bool(ct)?;
    let blob = protocol::wrap_blob(protocol::CT_KIND_BOOL, key_version, params_hash, &payload);
    store.put(&blob)
}

pub fn load_u64(
    store: &BlobStore,
    hash: &[u8; 32],
    key_version: u32,
    params_hash: &[u8; 32],
) -> Result<FheUint64, WorkerError> {
    let blob = store.get(hash)?;
    let payload = protocol::unwrap_blob(&blob, protocol::CT_KIND_U64, key_version, params_hash)
        .map_err(WorkerError::Blob)?;
    deserialize_u64(payload)
}

pub fn load_bool(
    store: &BlobStore,
    hash: &[u8; 32],
    key_version: u32,
    params_hash: &[u8; 32],
) -> Result<FheBool, WorkerError> {
    let blob = store.get(hash)?;
    let payload = protocol::unwrap_blob(&blob, protocol::CT_KIND_BOOL, key_version, params_hash)
        .map_err(WorkerError::Blob)?;
    deserialize_bool(payload)
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RequestFile {
    pub protocol_version: u16,
    pub domain_id: String,
    pub program_id: String,
    pub config: String,
    pub mint: String,
    pub confidential_account: String,
    pub request_pda: String,
    pub operation: u16,
    pub balance_hash: String,
    pub amount_hash: String,
    pub limit_hash: String,
    pub params_hash: String,
    pub state_version: u64,
    pub request_nonce: u64,
    pub key_version: u32,
    pub operator_epoch: u64,
    pub expiry_slot: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ResultFile {
    pub result_hash: String,
    pub result_type: u8,
    pub circuit_id: u16,
    pub request_digest: String,
    pub result_digest: String,
    pub signature: String,
    pub operator: String,
}

pub fn process_request(
    store: &BlobStore,
    request: &protocol::RequestBinding,
    compressed_server_key: &CompressedServerKey,
    operator: &Keypair,
) -> Result<(protocol::ResultBinding, [u8; 64]), WorkerError> {
    if request.operation != protocol::OPERATION_POLICY_CHECK {
        return Err(WorkerError::Unsupported);
    }
    if request.protocol_version != protocol::PROTOCOL_VERSION {
        return Err(WorkerError::Unsupported);
    }
    require_server_key_commitment(compressed_server_key, &request.params_hash)?;
    activate_server_key(&compressed_server_key.decompress());
    let balance = load_u64(
        store,
        &request.balance_hash,
        request.key_version,
        &request.params_hash,
    )?;
    let amount = load_u64(
        store,
        &request.amount_hash,
        request.key_version,
        &request.params_hash,
    )?;
    let limit = load_u64(
        store,
        &request.limit_hash,
        request.key_version,
        &request.params_hash,
    )?;
    let allowed = evaluate_policy(&balance, &amount, &limit);
    let result_hash = store_bool(store, &allowed, request.key_version, &request.params_hash)?;
    let binding = protocol::ResultBinding {
        request: *request,
        request_digest: protocol::request_digest(request),
        result_hash,
        result_type: protocol::RESULT_TYPE_FHE_BOOL,
        circuit_id: protocol::CIRCUIT_POLICY_V1,
    };
    let message = protocol::encode_result(&binding);
    let signature = operator.sign_message(&message);
    let sig_bytes: [u8; 64] = signature
        .as_ref()
        .try_into()
        .map_err(|_| WorkerError::Serialize)?;
    Ok((binding, sig_bytes))
}

pub fn write_client_key(path: &Path, key: &ClientKey) -> Result<(), WorkerError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut buf = Vec::new();
    safe_serialize(key, &mut buf, CLIENT_KEY_LIMIT).map_err(|_| WorkerError::Serialize)?;
    fs::write(path, buf)?;
    Ok(())
}

pub fn read_client_key(path: &Path) -> Result<ClientKey, WorkerError> {
    let bytes = fs::read(path)?;
    safe_deserialize(&mut Cursor::new(bytes), CLIENT_KEY_LIMIT)
        .map_err(|_| WorkerError::Deserialize)
}

pub fn serialized_server_key_len(key: &ServerKey) -> Result<usize, WorkerError> {
    let mut buf = Vec::new();
    safe_serialize(key, &mut buf, SERVER_KEY_LIMIT).map_err(|_| WorkerError::Serialize)?;
    Ok(buf.len())
}

pub fn write_server_key(path: &Path, key: &CompressedServerKey) -> Result<(), WorkerError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut buf = Vec::new();
    safe_serialize(key, &mut buf, SERVER_KEY_LIMIT).map_err(|_| WorkerError::Serialize)?;
    fs::write(path, buf)?;
    Ok(())
}

pub fn read_compressed_server_key(path: &Path) -> Result<CompressedServerKey, WorkerError> {
    let bytes = fs::read(path)?;
    safe_deserialize(&mut Cursor::new(bytes), SERVER_KEY_LIMIT)
        .map_err(|_| WorkerError::Deserialize)
}

pub fn read_server_key(path: &Path) -> Result<ServerKey, WorkerError> {
    Ok(read_compressed_server_key(path)?.decompress())
}

pub fn load_material(
    client_key_path: &Path,
    server_key_path: &Path,
    params_hash: [u8; 32],
) -> Result<FheMaterial, WorkerError> {
    let client_key = read_client_key(client_key_path)?;
    let compressed_server_key = read_compressed_server_key(server_key_path)?;
    require_server_key_commitment(&compressed_server_key, &params_hash)?;
    Ok(FheMaterial {
        server_key: compressed_server_key.decompress(),
        client_key,
        compressed_server_key,
        params_hash,
    })
}

/// Evaluation-only material: the compressed server (evaluation) key and its
/// commitment. Deliberately excludes the client decryption key so a worker
/// role can evaluate circuits without ever being able to decrypt operands or
/// results.
pub struct ServerMaterial {
    pub compressed_server_key: CompressedServerKey,
    pub params_hash: [u8; 32],
}

pub fn load_server_material(
    server_key_path: &Path,
    params_hash: [u8; 32],
) -> Result<ServerMaterial, WorkerError> {
    let compressed_server_key = read_compressed_server_key(server_key_path)?;
    require_server_key_commitment(&compressed_server_key, &params_hash)?;
    Ok(ServerMaterial {
        compressed_server_key,
        params_hash,
    })
}

pub fn parse_hex32(value: &str) -> Result<[u8; 32], WorkerError> {
    let bytes = hex::decode(value).map_err(|_| WorkerError::Deserialize)?;
    bytes.try_into().map_err(|_| WorkerError::Deserialize)
}

pub fn request_from_file(file: &RequestFile) -> Result<protocol::RequestBinding, WorkerError> {
    Ok(protocol::RequestBinding {
        protocol_version: file.protocol_version,
        domain_id: parse_hex32(&file.domain_id)?,
        program_id: parse_hex32(&file.program_id)?,
        config: parse_hex32(&file.config)?,
        mint: parse_hex32(&file.mint)?,
        confidential_account: parse_hex32(&file.confidential_account)?,
        request_pda: parse_hex32(&file.request_pda)?,
        operation: file.operation,
        balance_hash: parse_hex32(&file.balance_hash)?,
        amount_hash: parse_hex32(&file.amount_hash)?,
        limit_hash: parse_hex32(&file.limit_hash)?,
        params_hash: parse_hex32(&file.params_hash)?,
        state_version: file.state_version,
        request_nonce: file.request_nonce,
        key_version: file.key_version,
        operator_epoch: file.operator_epoch,
        expiry_slot: file.expiry_slot,
    })
}

pub fn request_to_file(binding: &protocol::RequestBinding) -> RequestFile {
    RequestFile {
        protocol_version: binding.protocol_version,
        domain_id: hex::encode(binding.domain_id),
        program_id: hex::encode(binding.program_id),
        config: hex::encode(binding.config),
        mint: hex::encode(binding.mint),
        confidential_account: hex::encode(binding.confidential_account),
        request_pda: hex::encode(binding.request_pda),
        operation: binding.operation,
        balance_hash: hex::encode(binding.balance_hash),
        amount_hash: hex::encode(binding.amount_hash),
        limit_hash: hex::encode(binding.limit_hash),
        params_hash: hex::encode(binding.params_hash),
        state_version: binding.state_version,
        request_nonce: binding.request_nonce,
        key_version: binding.key_version,
        operator_epoch: binding.operator_epoch,
        expiry_slot: binding.expiry_slot,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    fn material() -> &'static FheMaterial {
        static MATERIAL: OnceLock<FheMaterial> = OnceLock::new();
        MATERIAL.get_or_init(|| generate_material().expect("keygen"))
    }

    fn with_server<T>(f: impl FnOnce(&FheMaterial) -> T) -> T {
        let material = material();
        activate_server_key(&material.server_key);
        f(material)
    }

    fn expect_policy(balance: u64, amount: u64, limit: u64, expected: bool) {
        with_server(|m| {
            let enc_balance = encrypt_u64(balance, &m.client_key);
            let enc_amount = encrypt_u64(amount, &m.client_key);
            let enc_limit = encrypt_u64(limit, &m.client_key);
            let allowed = evaluate_policy(&enc_balance, &enc_amount, &enc_limit);
            assert_eq!(decrypt_bool(&allowed, &m.client_key), expected);
        });
    }

    #[test]
    fn policy_allowed() {
        expect_policy(100, 25, 50, true);
    }

    #[test]
    fn policy_insufficient_balance() {
        expect_policy(20, 25, 50, false);
    }

    #[test]
    fn policy_over_limit() {
        expect_policy(100, 60, 50, false);
    }

    #[test]
    fn policy_equality_boundaries() {
        expect_policy(25, 25, 25, true);
        expect_policy(24, 25, 25, false);
        expect_policy(25, 25, 24, false);
    }

    #[test]
    fn policy_zero_boundaries() {
        expect_policy(0, 0, 0, true);
        expect_policy(0, 1, 1, false);
        expect_policy(1, 0, 0, true);
    }

    #[test]
    fn safe_serialization_roundtrip() {
        with_server(|m| {
            let ct = encrypt_u64(42, &m.client_key);
            let bytes = serialize_u64(&ct).unwrap();
            let back = deserialize_u64(&bytes).unwrap();
            assert_eq!(decrypt_u64(&back, &m.client_key), 42);
            let flag = evaluate_policy(
                &ct,
                &encrypt_u64(1, &m.client_key),
                &encrypt_u64(100, &m.client_key),
            );
            let flag_bytes = serialize_bool(&flag).unwrap();
            let flag_back = deserialize_bool(&flag_bytes).unwrap();
            assert!(decrypt_bool(&flag_back, &m.client_key));
        });
    }

    #[test]
    fn modified_ciphertext_is_rejected() {
        with_server(|m| {
            let dir = tempfile::tempdir().unwrap();
            let store = BlobStore::new(dir.path()).unwrap();
            let hash =
                store_u64(&store, &encrypt_u64(9, &m.client_key), 1, &m.params_hash).unwrap();
            let path = dir.path().join(hex::encode(hash));
            let mut bytes = fs::read(&path).unwrap();
            let last = bytes.len() - 1;
            bytes[last] ^= 0xff;
            fs::write(&path, bytes).unwrap();
            match load_u64(&store, &hash, 1, &m.params_hash) {
                Err(err) => assert!(matches!(err, WorkerError::HashMismatch)),
                Ok(_) => panic!("expected hash mismatch"),
            }
        });
    }

    #[test]
    fn invalid_payload_is_rejected() {
        let garbage =
            protocol::wrap_blob(protocol::CT_KIND_U64, 1, &[7u8; 32], b"not-a-ciphertext");
        assert!(deserialize_u64(
            protocol::unwrap_blob(&garbage, protocol::CT_KIND_U64, 1, &[7u8; 32]).unwrap()
        )
        .is_err());
    }

    #[test]
    fn wrong_params_metadata_is_rejected() {
        with_server(|m| {
            let dir = tempfile::tempdir().unwrap();
            let store = BlobStore::new(dir.path()).unwrap();
            let hash =
                store_u64(&store, &encrypt_u64(3, &m.client_key), 1, &m.params_hash).unwrap();
            match load_u64(&store, &hash, 1, &[0u8; 32]) {
                Err(err) => assert!(matches!(
                    err,
                    WorkerError::Blob(protocol::BlobError::Params)
                )),
                Ok(_) => panic!("expected params mismatch"),
            }
            match load_u64(&store, &hash, 2, &m.params_hash) {
                Err(err) => assert!(matches!(
                    err,
                    WorkerError::Blob(protocol::BlobError::KeyVersion)
                )),
                Ok(_) => panic!("expected key version mismatch"),
            }
        });
    }

    #[test]
    fn server_key_commitment_matches() {
        let m = material();
        require_server_key_commitment(&m.compressed_server_key, &m.params_hash).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let client = dir.path().join("client.bin");
        let server = dir.path().join("server.bin");
        write_client_key(&client, &m.client_key).unwrap();
        write_server_key(&server, &m.compressed_server_key).unwrap();
        let loaded = load_material(&client, &server, m.params_hash).unwrap();
        assert_eq!(loaded.params_hash, m.params_hash);
    }

    #[test]
    fn server_key_commitment_rejects_wrong_hash() {
        let m = material();
        assert!(matches!(
            require_server_key_commitment(&m.compressed_server_key, &[0u8; 32]),
            Err(WorkerError::Params)
        ));
        let dir = tempfile::tempdir().unwrap();
        let client = dir.path().join("client.bin");
        let server = dir.path().join("server.bin");
        write_client_key(&client, &m.client_key).unwrap();
        write_server_key(&server, &m.compressed_server_key).unwrap();
        assert!(matches!(
            load_material(&client, &server, [0u8; 32]),
            Err(WorkerError::Params)
        ));
    }

    #[test]
    fn process_request_rejects_foreign_server_key() {
        with_server(|m| {
            let other = generate_material().expect("foreign keygen");
            assert_ne!(other.params_hash, m.params_hash);
            let dir = tempfile::tempdir().unwrap();
            let store = BlobStore::new(dir.path()).unwrap();
            let before: Vec<_> = fs::read_dir(dir.path())
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect();
            let request = protocol::RequestBinding {
                protocol_version: protocol::PROTOCOL_VERSION,
                domain_id: protocol::local_domain_id(),
                program_id: [1u8; 32],
                config: [2u8; 32],
                mint: [3u8; 32],
                confidential_account: [4u8; 32],
                request_pda: [5u8; 32],
                operation: protocol::OPERATION_POLICY_CHECK,
                balance_hash: [6u8; 32],
                amount_hash: [7u8; 32],
                limit_hash: [8u8; 32],
                params_hash: m.params_hash,
                state_version: 0,
                request_nonce: 1,
                key_version: 1,
                operator_epoch: 1,
                expiry_slot: 10,
            };
            let err = process_request(
                &store,
                &request,
                &other.compressed_server_key,
                &Keypair::new(),
            )
            .unwrap_err();
            assert!(matches!(err, WorkerError::Params));
            let after: Vec<_> = fs::read_dir(dir.path())
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect();
            assert_eq!(before, after);
        });
    }
}
