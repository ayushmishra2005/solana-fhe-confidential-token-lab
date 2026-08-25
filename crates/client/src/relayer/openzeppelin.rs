//! Blocking REST client for the documented OpenZeppelin Relayer v1.5.x API.
//!
//! Authentication uses `Authorization: Bearer <token>` (official API). The
//! token is read from `OPENZEPPELIN_RELAYER_API_KEY` by the CLI and is never
//! accepted as a command-line flag, stored in `devnet-state.json`, or logged.

use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{json, Value};

use crate::relayer::types::{
    classify_relayer_status, validate_solana_devnet_relayer, RelayerInfo, RelayerJobState,
    RelayerTransaction, SolanaInstructionSpec, ValidatedRelayer,
};
use crate::LabError;

/// Client-side environment variable. The Relayer *server* uses `API_KEY`.
pub const API_KEY_ENV: &str = "OPENZEPPELIN_RELAYER_API_KEY";

pub struct OpenZeppelinRelayerClient {
    base_url: String,
    relayer_id: String,
    api_key: String,
    http: reqwest::blocking::Client,
}

/// Covers Relayer v1.5.0 pending/sent windows (~3 minutes). Direct RPC stays at 90s.
pub const DEFAULT_RELAYER_POLL_TIMEOUT_SECS: u64 = 240;

pub struct PollSettings {
    pub timeout: Duration,
    pub interval: Duration,
}

impl Default for PollSettings {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(DEFAULT_RELAYER_POLL_TIMEOUT_SECS),
            interval: Duration::from_secs(1),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RelayerSubmitResult {
    pub transaction_id: String,
    pub status: String,
    pub solana_signature: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ApiEnvelope<T> {
    #[serde(default)]
    success: Option<bool>,
    data: Option<T>,
    error: Option<String>,
    message: Option<String>,
}

pub fn load_api_key(value: Option<&str>) -> Result<String, LabError> {
    match value.map(str::trim).filter(|key| !key.is_empty()) {
        Some(key) => Ok(key.to_string()),
        None => Err(LabError(format!(
            "missing {API_KEY_ENV}; set this environment variable to authenticate to \
             OpenZeppelin Relayer (do not pass the secret as a CLI flag)"
        ))),
    }
}

pub fn load_api_key_from_env() -> Result<String, LabError> {
    load_api_key(std::env::var(API_KEY_ENV).ok().as_deref())
}

impl OpenZeppelinRelayerClient {
    pub fn new(
        relayer_url: impl Into<String>,
        relayer_id: impl Into<String>,
        api_key: impl Into<String>,
    ) -> Result<Self, LabError> {
        let base_url = relayer_url.into().trim().trim_end_matches('/').to_string();
        if base_url.is_empty() {
            return Err(LabError("missing --relayer-url".to_string()));
        }
        let relayer_id = relayer_id.into();
        if relayer_id.trim().is_empty() {
            return Err(LabError("missing --relayer-id".to_string()));
        }
        let http = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| LabError(format!("failed to build Relayer HTTP client: {e}")))?;
        Ok(Self {
            base_url,
            relayer_id,
            api_key: api_key.into(),
            http,
        })
    }

    fn relayer_path(&self, suffix: &str) -> String {
        format!(
            "{}/api/v1/relayers/{}{suffix}",
            self.base_url, self.relayer_id
        )
    }

    fn send(
        &self,
        method: reqwest::Method,
        url: &str,
        body: Option<&Value>,
    ) -> Result<(reqwest::StatusCode, String), LabError> {
        let mut request = self
            .http
            .request(method, url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json");
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request
            .send()
            .map_err(|e| LabError(format!("OpenZeppelin Relayer request to {url} failed: {e}")))?;
        let status = response.status();
        let text = response.text().map_err(|e| {
            LabError(format!(
                "failed to read OpenZeppelin Relayer response body: {e}"
            ))
        })?;
        Ok((status, text))
    }

    fn decode_envelope<T: for<'de> Deserialize<'de>>(
        &self,
        operation: &str,
        status: reqwest::StatusCode,
        text: &str,
    ) -> Result<T, LabError> {
        if status.as_u16() == 401 {
            return Err(LabError(format!(
                "OpenZeppelin Relayer rejected authentication for {operation} (HTTP 401)"
            )));
        }
        let envelope: ApiEnvelope<T> = serde_json::from_str(text).map_err(|e| {
            LabError(format!(
                "OpenZeppelin Relayer {operation} returned non-JSON (HTTP {status}): {e}; body: {text}"
            ))
        })?;
        let success = envelope.success.unwrap_or(status.is_success());
        if !status.is_success() || !success {
            let detail = envelope
                .error
                .or(envelope.message)
                .unwrap_or_else(|| text.to_string());
            return Err(LabError(format!(
                "OpenZeppelin Relayer {operation} failed (HTTP {status}): {detail}"
            )));
        }
        envelope.data.ok_or_else(|| {
            LabError(format!(
                "OpenZeppelin Relayer {operation} returned no data: {text}"
            ))
        })
    }

    pub fn fetch_relayer(&self) -> Result<RelayerInfo, LabError> {
        let url = self.relayer_path("");
        let (status, text) = self.send(reqwest::Method::GET, &url, None)?;
        self.decode_envelope("GET /relayers/{id}", status, &text)
    }

    pub fn validate_configured_relayer(&self) -> Result<ValidatedRelayer, LabError> {
        let info = self.fetch_relayer()?;
        validate_solana_devnet_relayer(&info)
    }

    pub fn submit_instructions(
        &self,
        instructions: &[SolanaInstructionSpec],
    ) -> Result<RelayerTransaction, LabError> {
        let url = self.relayer_path("/transactions");
        let body = json!({ "instructions": instructions });
        let (status, text) = self.send(reqwest::Method::POST, &url, Some(&body))?;
        self.decode_envelope("POST /relayers/{id}/transactions", status, &text)
    }

    pub fn get_transaction(&self, transaction_id: &str) -> Result<RelayerTransaction, LabError> {
        let url = self.relayer_path(&format!("/transactions/{transaction_id}"));
        let (status, text) = self.send(reqwest::Method::GET, &url, None)?;
        self.decode_envelope("GET /relayers/{id}/transactions/{id}", status, &text)
    }

    pub fn wait_for_terminal(
        &self,
        transaction_id: &str,
        poll: &PollSettings,
    ) -> Result<RelayerTransaction, LabError> {
        let deadline = Instant::now() + poll.timeout;
        loop {
            let tx = self.get_transaction(transaction_id)?;
            let last_status = tx.status.clone();
            match classify_relayer_status(&tx.status) {
                RelayerJobState::Succeeded => return Ok(tx),
                RelayerJobState::Failed => {
                    let reason = tx
                        .status_reason
                        .as_deref()
                        .filter(|reason| !reason.is_empty())
                        .unwrap_or("no status_reason from Relayer");
                    return Err(LabError(format!(
                        "OpenZeppelin Relayer transaction {transaction_id} failed \
                         (status: {}): {reason}",
                        tx.status
                    )));
                }
                RelayerJobState::InProgress => {}
            }
            if Instant::now() >= deadline {
                return Err(LabError(format!(
                    "timed out waiting for OpenZeppelin Relayer transaction {transaction_id} \
                     to reach Relayer confirmed (last status: {last_status}); inspect the \
                     Request PDA and Relayer job before attempting another finalize"
                )));
            }
            std::thread::sleep(poll.interval);
        }
    }

    pub fn submit_instructions_and_wait(
        &self,
        instructions: &[SolanaInstructionSpec],
        poll: &PollSettings,
    ) -> Result<RelayerSubmitResult, LabError> {
        let submitted = self.submit_instructions(instructions)?;
        let terminal = match classify_relayer_status(&submitted.status) {
            RelayerJobState::Succeeded => submitted,
            RelayerJobState::Failed => {
                let reason = submitted
                    .status_reason
                    .as_deref()
                    .unwrap_or("no status_reason from Relayer");
                return Err(LabError(format!(
                    "OpenZeppelin Relayer transaction {} failed (status: {}): {reason}",
                    submitted.id, submitted.status
                )));
            }
            RelayerJobState::InProgress => self.wait_for_terminal(&submitted.id, poll)?,
        };
        Ok(RelayerSubmitResult {
            transaction_id: terminal.id,
            status: terminal.status,
            solana_signature: terminal.signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relayer::types::{SolanaAccountMeta, SolanaInstructionSpec};
    use serde_json::json;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;

    struct MockRequest {
        method: String,
        path: String,
        authorization: Option<String>,
        body: String,
    }

    fn spawn_mock<F>(handler: F) -> String
    where
        F: Fn(&MockRequest) -> (u16, String) + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handler = Arc::new(handler);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let Ok(req) = read_http_request(&mut stream) else {
                    continue;
                };
                let (status, body) = handler(&req);
                let reason = match status {
                    200 => "OK",
                    400 => "Bad Request",
                    401 => "Unauthorized",
                    404 => "Not Found",
                    _ => "Error",
                };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        format!("http://{addr}")
    }

    fn read_http_request(stream: &mut impl Read) -> Result<MockRequest, ()> {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 1024];
        loop {
            let n = stream.read(&mut tmp).map_err(|_| ())?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if let Some(header_end) = find_header_end(&buf) {
                let header_text = std::str::from_utf8(&buf[..header_end]).map_err(|_| ())?;
                let mut lines = header_text.split("\r\n");
                let request_line = lines.next().ok_or(())?;
                let mut parts = request_line.split_whitespace();
                let method = parts.next().ok_or(())?.to_string();
                let path = parts.next().ok_or(())?.to_string();
                let mut authorization = None;
                let mut content_length = 0usize;
                for line in lines {
                    let Some((name, value)) = line.split_once(':') else {
                        continue;
                    };
                    if name.eq_ignore_ascii_case("authorization") {
                        authorization = Some(value.trim().to_string());
                    }
                    if name.eq_ignore_ascii_case("content-length") {
                        content_length = value.trim().parse().unwrap_or(0);
                    }
                }
                let mut body = buf[header_end..].to_vec();
                while body.len() < content_length {
                    let n = stream.read(&mut tmp).map_err(|_| ())?;
                    if n == 0 {
                        break;
                    }
                    body.extend_from_slice(&tmp[..n]);
                }
                body.truncate(content_length);
                return Ok(MockRequest {
                    method,
                    path,
                    authorization,
                    body: String::from_utf8(body).unwrap_or_default(),
                });
            }
            if buf.len() > 64 * 1024 {
                return Err(());
            }
        }
        Err(())
    }

    fn find_header_end(buf: &[u8]) -> Option<usize> {
        buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
    }

    fn ok_envelope(data: Value) -> String {
        json!({ "success": true, "data": data, "error": null }).to_string()
    }

    fn relayer_data() -> Value {
        json!({
            "id": "solana-devnet",
            "name": "Solana Devnet",
            "network": "devnet",
            "network_type": "solana",
            "paused": false,
            "address": "4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7AijMQwWNAsrD",
            "system_disabled": false,
            "signer_id": "local-signer",
            "policies": { "fee_payment_strategy": "relayer" }
        })
    }

    fn sample_ix() -> SolanaInstructionSpec {
        SolanaInstructionSpec {
            program_id: "11111111111111111111111111111111".to_string(),
            accounts: vec![SolanaAccountMeta {
                pubkey: "4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7AijMQwWNAsrD".to_string(),
                is_signer: true,
                is_writable: true,
            }],
            data: "AQID".to_string(),
        }
    }

    fn short_poll() -> PollSettings {
        PollSettings {
            timeout: Duration::from_secs(2),
            interval: Duration::from_millis(10),
        }
    }

    fn submit_until_polled_status(status: &str, reason: &str) -> LabError {
        let job_id = format!("job-{status}");
        let polled_status = status.to_string();
        let polled_reason = reason.to_string();
        let url = spawn_mock(move |req| {
            if req.method == "POST" {
                return (
                    200,
                    ok_envelope(json!({
                        "id": job_id,
                        "status": "pending",
                        "created_at": "2026-01-01T00:00:00Z",
                        "transaction": ""
                    })),
                );
            }
            (
                200,
                ok_envelope(json!({
                    "id": job_id,
                    "status": polled_status,
                    "status_reason": polled_reason,
                    "created_at": "2026-01-01T00:00:00Z",
                    "transaction": ""
                })),
            )
        });
        let client = OpenZeppelinRelayerClient::new(&url, "solana-devnet", "token").unwrap();
        client
            .submit_instructions_and_wait(&[sample_ix()], &short_poll())
            .unwrap_err()
    }

    #[test]
    fn missing_authentication_fails_clearly() {
        let err = load_api_key(None).unwrap_err();
        assert!(err.to_string().contains(API_KEY_ENV), "{err}");
        assert!(err.to_string().contains("environment"), "{err}");
        assert!(!err.to_string().contains("Bearer"), "{err}");

        let err = load_api_key(Some("")).unwrap_err();
        assert!(err.to_string().contains(API_KEY_ENV), "{err}");
    }

    #[test]
    fn fetch_relayer_sends_bearer_auth_and_parses_info() {
        let url = spawn_mock(|req| {
            assert_eq!(req.method, "GET");
            assert_eq!(req.path, "/api/v1/relayers/solana-devnet");
            assert_eq!(
                req.authorization.as_deref(),
                Some("Bearer test-relayer-token")
            );
            (200, ok_envelope(relayer_data()))
        });
        let client =
            OpenZeppelinRelayerClient::new(&url, "solana-devnet", "test-relayer-token").unwrap();
        let info = client.fetch_relayer().unwrap();
        assert_eq!(info.network_type, "solana");
        assert_eq!(info.network, "devnet");
        client.validate_configured_relayer().unwrap();
    }

    #[test]
    fn unauthorized_response_does_not_echo_api_key() {
        let url = spawn_mock(|_req| {
            (
                401,
                json!({"success": false, "data": null, "message": "Unauthorized"}).to_string(),
            )
        });
        let client =
            OpenZeppelinRelayerClient::new(&url, "solana-devnet", "super-secret-api-key").unwrap();
        let err = client.fetch_relayer().unwrap_err();
        assert!(err.to_string().contains("HTTP 401"), "{err}");
        assert!(!err.to_string().contains("super-secret-api-key"), "{err}");
    }

    #[test]
    fn default_relayer_poll_timeout_covers_relayer_windows() {
        let poll = PollSettings::default();
        assert_eq!(
            poll.timeout,
            Duration::from_secs(DEFAULT_RELAYER_POLL_TIMEOUT_SECS)
        );
        assert!(poll.timeout >= Duration::from_secs(180));
        assert_eq!(DEFAULT_RELAYER_POLL_TIMEOUT_SECS, 240);
    }

    #[test]
    fn failed_relayer_status_returns_useful_error() {
        let err = submit_until_polled_status("failed", "simulation failed: custom program error");
        assert!(err.to_string().contains("job-failed"), "{err}");
        assert!(err.to_string().contains("failed"), "{err}");
        assert!(err.to_string().contains("simulation failed"), "{err}");
    }

    #[test]
    fn expired_relayer_status_returns_useful_error() {
        let err = submit_until_polled_status("expired", "blockhash expired");
        assert!(err.to_string().contains("job-expired"), "{err}");
        assert!(err.to_string().contains("expired"), "{err}");
        assert!(err.to_string().contains("blockhash expired"), "{err}");
        assert!(!err.to_string().contains("timed out"), "{err}");
    }

    #[test]
    fn canceled_relayer_status_returns_useful_error() {
        let err = submit_until_polled_status("canceled", "canceled by operator");
        assert!(err.to_string().contains("job-canceled"), "{err}");
        assert!(err.to_string().contains("canceled"), "{err}");
        assert!(err.to_string().contains("canceled by operator"), "{err}");
        assert!(!err.to_string().contains("timed out"), "{err}");
    }

    #[test]
    fn mined_is_not_terminal_success() {
        let err = submit_until_polled_status("mined", "");
        assert!(err.to_string().contains("timed out"), "{err}");
        assert!(err.to_string().contains("job-mined"), "{err}");
        assert!(err.to_string().contains("mined"), "{err}");
        assert!(err.to_string().contains("inspect the Request PDA"), "{err}");
        assert!(
            !err.to_string().contains("transaction job-mined failed"),
            "{err}"
        );
    }

    #[test]
    fn polling_timeout_returns_useful_error() {
        let url = spawn_mock(|req| {
            let body = if req.method == "POST" {
                json!({
                    "id": "job-slow",
                    "status": "pending",
                    "created_at": "2026-01-01T00:00:00Z",
                    "transaction": ""
                })
            } else {
                json!({
                    "id": "job-slow",
                    "status": "submitted",
                    "created_at": "2026-01-01T00:00:00Z",
                    "transaction": ""
                })
            };
            (200, ok_envelope(body))
        });
        let client = OpenZeppelinRelayerClient::new(&url, "solana-devnet", "token").unwrap();
        let err = client
            .submit_instructions_and_wait(
                &[sample_ix()],
                &PollSettings {
                    timeout: Duration::from_millis(40),
                    interval: Duration::from_millis(10),
                },
            )
            .unwrap_err();
        assert!(err.to_string().contains("timed out"), "{err}");
        assert!(err.to_string().contains("job-slow"), "{err}");
        assert!(err.to_string().contains("submitted"), "{err}");
        assert!(err.to_string().contains("inspect the Request PDA"), "{err}");
        assert!(!err.to_string().contains("failed (status"), "{err}");
    }

    #[test]
    fn confirmed_status_is_accepted_case_insensitively() {
        let url = spawn_mock(|req| {
            if req.method == "POST" {
                return (
                    200,
                    ok_envelope(json!({
                        "id": "job-ok-case",
                        "status": "pending",
                        "created_at": "2026-01-01T00:00:00Z",
                        "transaction": ""
                    })),
                );
            }
            (
                200,
                ok_envelope(json!({
                    "id": "job-ok-case",
                    "status": "CONFIRMED",
                    "signature": "5Vt1xY8uWJcQhW8nYqK1pL3sR4tU6vA7bC9dE2fG8hJ",
                    "created_at": "2026-01-01T00:00:00Z",
                    "transaction": "dHh4"
                })),
            )
        });
        let client = OpenZeppelinRelayerClient::new(&url, "solana-devnet", "token").unwrap();
        let result = client
            .submit_instructions_and_wait(&[sample_ix()], &short_poll())
            .unwrap();
        assert_eq!(result.transaction_id, "job-ok-case");
        assert_eq!(result.status, "CONFIRMED");
        assert!(result.solana_signature.is_some());
    }

    #[test]
    fn submit_and_poll_returns_job_id_and_solana_signature() {
        let polls = Arc::new(AtomicUsize::new(0));
        let polls_clone = polls.clone();
        let url = spawn_mock(move |req| {
            if req.method == "POST" {
                assert!(req.path.ends_with("/transactions"));
                let body: Value = serde_json::from_str(&req.body).unwrap();
                assert!(body
                    .get("instructions")
                    .and_then(|v| v.as_array())
                    .is_some());
                return (
                    200,
                    ok_envelope(json!({
                        "id": "job-ok",
                        "status": "pending",
                        "created_at": "2026-01-01T00:00:00Z",
                        "transaction": ""
                    })),
                );
            }
            let n = polls_clone.fetch_add(1, Ordering::SeqCst);
            let status = if n == 0 { "submitted" } else { "confirmed" };
            let signature = if n == 0 {
                Value::Null
            } else {
                Value::String("5Vt1xY8uWJcQhW8nYqK1pL3sR4tU6vA7bC9dE2fG8hJ".to_string())
            };
            (
                200,
                ok_envelope(json!({
                    "id": "job-ok",
                    "status": status,
                    "signature": signature,
                    "created_at": "2026-01-01T00:00:00Z",
                    "transaction": "dHh4"
                })),
            )
        });
        let client = OpenZeppelinRelayerClient::new(&url, "solana-devnet", "token").unwrap();
        let result = client
            .submit_instructions_and_wait(
                &[sample_ix()],
                &PollSettings {
                    timeout: Duration::from_secs(2),
                    interval: Duration::from_millis(10),
                },
            )
            .unwrap();
        assert_eq!(result.transaction_id, "job-ok");
        assert_eq!(result.status, "confirmed");
        assert!(result.solana_signature.is_some());
    }

    #[test]
    fn server_error_detail_is_surfaced() {
        let url = spawn_mock(|_req| {
            (
                400,
                json!({
                    "success": false,
                    "data": null,
                    "message": "Instruction 0: Only the relayer address can be marked as a signer"
                })
                .to_string(),
            )
        });
        let client = OpenZeppelinRelayerClient::new(&url, "solana-devnet", "token").unwrap();
        let err = client.submit_instructions(&[sample_ix()]).unwrap_err();
        assert!(err.to_string().contains("HTTP 400"), "{err}");
        assert!(
            err.to_string().contains("Only the relayer address"),
            "{err}"
        );
    }
}
