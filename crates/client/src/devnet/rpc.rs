//! A deliberately minimal blocking Solana JSON-RPC client.
//!
//! This intentionally does not use `solana-rpc-client`: that crate pulls in
//! a second, newer generation of the Solana SDK that conflicts with the
//! versions LiteSVM pins elsewhere in this workspace. Only the handful of
//! JSON-RPC methods this CLI actually needs are implemented:
//! `getLatestBlockhash`, `getAccountInfo`, `sendTransaction`,
//! `getSignatureStatuses`, and `getSlot`. This is not a general RPC
//! framework.

use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde::Deserialize;
use serde_json::{json, Value};
use solana_transaction::Transaction;

use crate::LabError;

pub struct RpcClient {
    url: String,
    http: reqwest::blocking::Client,
}

pub struct FetchedAccount {
    pub data: Vec<u8>,
    pub owner: String,
    pub lamports: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SignatureStatus {
    pub slot: u64,
    pub err: Option<Value>,
    #[serde(rename = "confirmationStatus")]
    pub confirmation_status: Option<String>,
}

impl RpcClient {
    pub fn new(url: impl Into<String>) -> Result<Self, LabError> {
        let http = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| LabError(format!("failed to build HTTP client: {e}")))?;
        Ok(Self {
            url: url.into(),
            http,
        })
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, LabError> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let response = self
            .http
            .post(&self.url)
            .json(&body)
            .send()
            .map_err(|e| LabError(format!("RPC request to {} failed: {e}", self.url)))?;
        let status = response.status();
        let text = response
            .text()
            .map_err(|e| LabError(format!("failed to read RPC response body: {e}")))?;
        let value: Value = serde_json::from_str(&text).map_err(|e| {
            LabError(format!(
                "RPC response was not valid JSON (http status {status}): {e}; body: {text}"
            ))
        })?;
        if let Some(error) = value.get("error") {
            return Err(rpc_error_to_lab_error(method, error));
        }
        value
            .get("result")
            .cloned()
            .ok_or_else(|| LabError(format!("RPC method {method} returned no result: {text}")))
    }

    /// Returns the base58 blockhash.
    pub fn get_latest_blockhash(&self) -> Result<String, LabError> {
        let result = self.call("getLatestBlockhash", json!([{ "commitment": "confirmed" }]))?;
        result
            .get("value")
            .and_then(|v| v.get("blockhash"))
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| LabError("getLatestBlockhash: missing blockhash".to_string()))
    }

    pub fn get_slot(&self) -> Result<u64, LabError> {
        let result = self.call("getSlot", json!([{ "commitment": "confirmed" }]))?;
        result
            .as_u64()
            .ok_or_else(|| LabError("getSlot: non-numeric result".to_string()))
    }

    /// Fetches account info, base64-decoded. Returns `Ok(None)` if the
    /// account does not exist (rather than treating that as an error), so
    /// callers can implement clear "already exists" / "not found" checks.
    pub fn get_account_info(&self, address: &str) -> Result<Option<FetchedAccount>, LabError> {
        let result = self.call(
            "getAccountInfo",
            json!([address, { "encoding": "base64", "commitment": "confirmed" }]),
        )?;
        let value = result.get("value").cloned().unwrap_or(Value::Null);
        if value.is_null() {
            return Ok(None);
        }
        let data_field = value
            .get("data")
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .and_then(|v| v.as_str())
            .ok_or_else(|| LabError(format!("getAccountInfo({address}): malformed data field")))?;
        let data = BASE64
            .decode(data_field)
            .map_err(|e| LabError(format!("getAccountInfo({address}): invalid base64: {e}")))?;
        let owner = value
            .get("owner")
            .and_then(|v| v.as_str())
            .ok_or_else(|| LabError(format!("getAccountInfo({address}): missing owner")))?
            .to_string();
        let lamports = value
            .get("lamports")
            .and_then(|v| v.as_u64())
            .unwrap_or_default();
        Ok(Some(FetchedAccount {
            data,
            owner,
            lamports,
        }))
    }

    /// Submits a signed legacy transaction with preflight enabled. On a
    /// simulation failure, surfaces the program logs (if any) from the RPC
    /// error response rather than just the bare error message.
    pub fn send_transaction(&self, tx: &Transaction) -> Result<String, LabError> {
        let bytes = bincode::serialize(tx)
            .map_err(|e| LabError(format!("failed to serialize transaction: {e}")))?;
        let encoded = BASE64.encode(bytes);
        let result = self.call(
            "sendTransaction",
            json!([
                encoded,
                {
                    "encoding": "base64",
                    "skipPreflight": false,
                    "preflightCommitment": "confirmed",
                }
            ]),
        )?;
        result
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| LabError(format!("sendTransaction: unexpected result: {result}")))
    }

    pub fn get_signature_statuses(
        &self,
        signatures: &[String],
    ) -> Result<Vec<Option<SignatureStatus>>, LabError> {
        let result = self.call(
            "getSignatureStatuses",
            json!([signatures, { "searchTransactionHistory": true }]),
        )?;
        let values = result
            .get("value")
            .and_then(|v| v.as_array())
            .cloned()
            .ok_or_else(|| LabError("getSignatureStatuses: missing value array".to_string()))?;
        values
            .into_iter()
            .map(|v| {
                if v.is_null() {
                    Ok(None)
                } else {
                    serde_json::from_value(v)
                        .map(Some)
                        .map_err(|e| LabError(format!("getSignatureStatuses: {e}")))
                }
            })
            .collect()
    }

    /// Sends a transaction and polls for confirmation, returning the
    /// signature once it reaches at least `confirmed`. Times out after
    /// roughly 90 seconds, which comfortably covers a devnet blockhash's
    /// validity window.
    pub fn send_and_confirm(&self, tx: &Transaction) -> Result<String, LabError> {
        let signature = self.send_transaction(tx)?;
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            let statuses = self.get_signature_statuses(std::slice::from_ref(&signature))?;
            if let Some(Some(status)) = statuses.into_iter().next() {
                if let Some(err) = status.err {
                    return Err(LabError(format!(
                        "transaction {signature} landed but failed on-chain: {err}"
                    )));
                }
                let confirmed = matches!(
                    status.confirmation_status.as_deref(),
                    Some("confirmed") | Some("finalized")
                );
                if confirmed {
                    return Ok(signature);
                }
            }
            if Instant::now() >= deadline {
                return Err(LabError(format!(
                    "timed out waiting for confirmation of {signature}"
                )));
            }
            std::thread::sleep(Duration::from_millis(1_000));
        }
    }
}

pub(crate) fn rpc_error_to_lab_error(method: &str, error: &Value) -> LabError {
    let message = error
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown RPC error");
    let code = error.get("code").and_then(|v| v.as_i64());
    let logs = error
        .get("data")
        .and_then(|d| d.get("logs"))
        .and_then(|l| l.as_array())
        .map(|entries| {
            entries
                .iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join("\n  ")
        });
    match (code, logs) {
        (Some(code), Some(logs)) if !logs.is_empty() => LabError(format!(
            "{method} failed (code {code}): {message}\nprogram logs:\n  {logs}"
        )),
        (Some(code), _) => LabError(format!("{method} failed (code {code}): {message}")),
        (None, Some(logs)) if !logs.is_empty() => LabError(format!(
            "{method} failed: {message}\nprogram logs:\n  {logs}"
        )),
        (None, _) => LabError(format!("{method} failed: {message}")),
    }
}
