//! Phase 1 request/result encodings.
//!
//! Digests and operator signatures are computed over these exact bytes.
//! Do not hash via a generic serializer.

use sha2::{Digest, Sha256};

pub const PROTOCOL_VERSION: u16 = 1;
pub const OPERATION_POLICY_CHECK: u16 = 1;
pub const CIRCUIT_POLICY_V1: u16 = 1;
pub const RESULT_TYPE_FHE_BOOL: u8 = 1;

pub const STATUS_PENDING: u8 = 0;
pub const STATUS_FINALIZED: u8 = 1;
pub const STATUS_CANCELLED: u8 = 2;
pub const STATUS_EXPIRED: u8 = 3;

pub const CT_KIND_U64: u8 = 1;
pub const CT_KIND_BOOL: u8 = 2;

pub const SEED_CONFIG: &[u8] = b"config";
pub const SEED_ACCOUNT: &[u8] = b"account";
pub const SEED_REQUEST: &[u8] = b"request";

/// Domain separator for request digests. Changing this invalidates all prior requests.
pub const DOMAIN_REQUEST: &[u8] = b"SOLFHE-CTL-REQ-V1";
/// Domain separator for result signatures. Changing this invalidates all prior results.
pub const DOMAIN_RESULT: &[u8] = b"SOLFHE-CTL-RES-V1";

pub const BLOB_MAGIC: &[u8; 4] = b"CTL1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestBinding {
    pub protocol_version: u16,
    pub domain_id: [u8; 32],
    pub program_id: [u8; 32],
    pub config: [u8; 32],
    pub mint: [u8; 32],
    pub confidential_account: [u8; 32],
    pub request_pda: [u8; 32],
    pub operation: u16,
    pub balance_hash: [u8; 32],
    pub amount_hash: [u8; 32],
    pub limit_hash: [u8; 32],
    pub params_hash: [u8; 32],
    pub state_version: u64,
    pub request_nonce: u64,
    pub key_version: u32,
    pub operator_epoch: u64,
    pub expiry_slot: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResultBinding {
    pub request: RequestBinding,
    pub request_digest: [u8; 32],
    pub result_hash: [u8; 32],
    pub result_type: u8,
    pub circuit_id: u16,
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn is_zero_hash(hash: &[u8; 32]) -> bool {
    *hash == [0u8; 32]
}

pub fn encode_request(binding: &RequestBinding) -> Vec<u8> {
    let mut buf = Vec::with_capacity(DOMAIN_REQUEST.len() + 400);
    buf.extend_from_slice(DOMAIN_REQUEST);
    put_u16(&mut buf, binding.protocol_version);
    buf.extend_from_slice(&binding.domain_id);
    buf.extend_from_slice(&binding.program_id);
    buf.extend_from_slice(&binding.config);
    buf.extend_from_slice(&binding.mint);
    buf.extend_from_slice(&binding.confidential_account);
    buf.extend_from_slice(&binding.request_pda);
    put_u16(&mut buf, binding.operation);
    buf.extend_from_slice(&binding.balance_hash);
    buf.extend_from_slice(&binding.amount_hash);
    buf.extend_from_slice(&binding.limit_hash);
    buf.extend_from_slice(&binding.params_hash);
    put_u64(&mut buf, binding.state_version);
    put_u64(&mut buf, binding.request_nonce);
    put_u32(&mut buf, binding.key_version);
    put_u64(&mut buf, binding.operator_epoch);
    put_u64(&mut buf, binding.expiry_slot);
    buf
}

pub fn request_digest(binding: &RequestBinding) -> [u8; 32] {
    sha256(&encode_request(binding))
}

pub fn encode_result(binding: &ResultBinding) -> Vec<u8> {
    let mut buf = encode_request(&binding.request);
    // Replace the request domain prefix with the result domain without reallocating the body.
    debug_assert!(buf.starts_with(DOMAIN_REQUEST));
    buf.splice(0..DOMAIN_REQUEST.len(), DOMAIN_RESULT.iter().copied());
    buf.extend_from_slice(&binding.request_digest);
    buf.extend_from_slice(&binding.result_hash);
    buf.push(binding.result_type);
    put_u16(&mut buf, binding.circuit_id);
    buf
}

pub fn result_digest(binding: &ResultBinding) -> [u8; 32] {
    sha256(&encode_result(binding))
}

pub fn local_domain_id() -> [u8; 32] {
    sha256(b"solana-fhe-confidential-token-lab/local/v1")
}

pub fn wrap_blob(kind: u8, key_version: u32, params_hash: &[u8; 32], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 1 + 4 + 32 + payload.len());
    out.extend_from_slice(BLOB_MAGIC);
    out.push(kind);
    put_u32(&mut out, key_version);
    out.extend_from_slice(params_hash);
    out.extend_from_slice(payload);
    out
}

pub fn unwrap_blob<'a>(
    bytes: &'a [u8],
    expected_kind: u8,
    expected_key_version: u32,
    expected_params_hash: &[u8; 32],
) -> Result<&'a [u8], BlobError> {
    if bytes.len() < 4 + 1 + 4 + 32 {
        return Err(BlobError::Truncated);
    }
    if &bytes[0..4] != BLOB_MAGIC {
        return Err(BlobError::Magic);
    }
    if bytes[4] != expected_kind {
        return Err(BlobError::Kind);
    }
    let key_version = u32::from_le_bytes(bytes[5..9].try_into().unwrap());
    if key_version != expected_key_version {
        return Err(BlobError::KeyVersion);
    }
    let params = &bytes[9..41];
    if params != expected_params_hash {
        return Err(BlobError::Params);
    }
    Ok(&bytes[41..])
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlobError {
    Truncated,
    Magic,
    Kind,
    KeyVersion,
    Params,
}

fn put_u16(buf: &mut Vec<u8>, value: u16) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn put_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request() -> RequestBinding {
        RequestBinding {
            protocol_version: PROTOCOL_VERSION,
            domain_id: [0x11; 32],
            program_id: [0x22; 32],
            config: [0x33; 32],
            mint: [0x44; 32],
            confidential_account: [0x55; 32],
            request_pda: [0x66; 32],
            operation: OPERATION_POLICY_CHECK,
            balance_hash: [0x77; 32],
            amount_hash: [0x88; 32],
            limit_hash: [0x99; 32],
            params_hash: [0xaa; 32],
            state_version: 7,
            request_nonce: 9,
            key_version: 3,
            operator_epoch: 4,
            expiry_slot: 99,
        }
    }

    fn sample_result() -> ResultBinding {
        let request = sample_request();
        ResultBinding {
            request_digest: request_digest(&request),
            request,
            result_hash: [0xbb; 32],
            result_type: RESULT_TYPE_FHE_BOOL,
            circuit_id: CIRCUIT_POLICY_V1,
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn request_encoding_is_deterministic() {
        let a = encode_request(&sample_request());
        let b = encode_request(&sample_request());
        assert_eq!(a, b);
        assert!(a.starts_with(DOMAIN_REQUEST));
    }

    #[test]
    fn result_encoding_is_deterministic() {
        let a = encode_result(&sample_result());
        let b = encode_result(&sample_result());
        assert_eq!(a, b);
        assert!(a.starts_with(DOMAIN_RESULT));
        assert!(!a.starts_with(DOMAIN_REQUEST));
    }

    #[test]
    fn request_and_result_domains_differ() {
        assert_ne!(DOMAIN_REQUEST, DOMAIN_RESULT);
        let request = sample_request();
        let result = sample_result();
        assert_ne!(encode_request(&request), encode_result(&result));
        assert_ne!(request_digest(&request), result_digest(&result));
    }

    #[test]
    fn changing_each_request_field_changes_digest() {
        let base = request_digest(&sample_request());
        let mut cases = Vec::new();

        let mut b = sample_request();
        b.protocol_version = 2;
        cases.push(b);
        let mut b = sample_request();
        b.domain_id[0] ^= 1;
        cases.push(b);
        let mut b = sample_request();
        b.program_id[0] ^= 1;
        cases.push(b);
        let mut b = sample_request();
        b.config[0] ^= 1;
        cases.push(b);
        let mut b = sample_request();
        b.mint[0] ^= 1;
        cases.push(b);
        let mut b = sample_request();
        b.confidential_account[0] ^= 1;
        cases.push(b);
        let mut b = sample_request();
        b.request_pda[0] ^= 1;
        cases.push(b);
        let mut b = sample_request();
        b.operation = 2;
        cases.push(b);
        let mut b = sample_request();
        b.balance_hash[0] ^= 1;
        cases.push(b);
        let mut b = sample_request();
        b.amount_hash[0] ^= 1;
        cases.push(b);
        let mut b = sample_request();
        b.limit_hash[0] ^= 1;
        cases.push(b);
        let mut b = sample_request();
        b.params_hash[0] ^= 1;
        cases.push(b);
        let mut b = sample_request();
        b.state_version += 1;
        cases.push(b);
        let mut b = sample_request();
        b.request_nonce += 1;
        cases.push(b);
        let mut b = sample_request();
        b.key_version += 1;
        cases.push(b);
        let mut b = sample_request();
        b.operator_epoch += 1;
        cases.push(b);
        let mut b = sample_request();
        b.expiry_slot += 1;
        cases.push(b);

        let mut seen = std::collections::HashSet::from([base]);
        for case in cases {
            let digest = request_digest(&case);
            assert_ne!(digest, base);
            assert!(seen.insert(digest));
        }
    }

    #[test]
    fn changing_each_result_field_changes_digest() {
        let base = result_digest(&sample_result());
        let mut r = sample_result();
        r.result_hash[0] ^= 1;
        assert_ne!(result_digest(&r), base);
        let mut r = sample_result();
        r.result_type = 2;
        assert_ne!(result_digest(&r), base);
        let mut r = sample_result();
        r.circuit_id = 2;
        assert_ne!(result_digest(&r), base);
        let mut r = sample_result();
        r.request_digest[0] ^= 1;
        assert_ne!(result_digest(&r), base);
        let mut r = sample_result();
        r.request.request_nonce += 1;
        assert_ne!(result_digest(&r), base);
    }

    #[test]
    fn golden_request_vector() {
        // Frozen against the canonical encoder. If this fails, the wire format changed.
        assert_eq!(
            hex(&request_digest(&sample_request())),
            "ecbf88cb0e6aab58fe92780c678dd22db2fd8f056316ae2f42cd3c80344ec130"
        );
    }

    #[test]
    fn golden_result_vector() {
        assert_eq!(
            hex(&result_digest(&sample_result())),
            "c4bc420b3ccde1fdd091a64a026201cac3f6e98c00fa9707e0e3185cd5cd4bad"
        );
    }

    #[test]
    fn blob_roundtrip_and_rejects() {
        let params = [0xcc; 32];
        let blob = wrap_blob(CT_KIND_U64, 1, &params, b"payload");
        assert_eq!(
            unwrap_blob(&blob, CT_KIND_U64, 1, &params).unwrap(),
            b"payload"
        );
        assert_eq!(
            unwrap_blob(&blob, CT_KIND_BOOL, 1, &params),
            Err(BlobError::Kind)
        );
        assert_eq!(
            unwrap_blob(&blob, CT_KIND_U64, 2, &params),
            Err(BlobError::KeyVersion)
        );
        let other = [0xdd; 32];
        assert_eq!(
            unwrap_blob(&blob, CT_KIND_U64, 1, &other),
            Err(BlobError::Params)
        );
        assert_eq!(
            unwrap_blob(&blob[..10], CT_KIND_U64, 1, &params),
            Err(BlobError::Truncated)
        );
    }

    #[test]
    fn local_domain_id_is_stable() {
        assert_eq!(
            hex(&local_domain_id()),
            "121d1d03df887c82fa68d5ba57f2d4bbc65356af5a6a88b2bc94f7626246eff7"
        );
    }
}
