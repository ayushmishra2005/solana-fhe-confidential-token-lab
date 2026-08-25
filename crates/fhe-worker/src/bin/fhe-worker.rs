use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use fhe_worker::{
    parse_hex32, process_request, read_compressed_server_key, request_from_file, BlobStore,
    RequestFile, ResultFile,
};
use solana_keypair::Keypair;
use solana_signer::Signer;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        eprintln!(
            "usage: fhe-worker evaluate --request <file> --store <dir> --server-key <file> --operator <file> --out <file>"
        );
        return ExitCode::from(2);
    }
    let cmd = args.remove(0);
    match cmd.as_str() {
        "evaluate" => {
            if let Err(err) = evaluate(&args) {
                eprintln!("error: {err}");
                return ExitCode::from(1);
            }
        }
        other => {
            eprintln!("unknown command: {other}");
            return ExitCode::from(2);
        }
    }
    ExitCode::SUCCESS
}

fn evaluate(args: &[String]) -> Result<(), String> {
    let request_path = flag(args, "--request")?;
    let store_path = flag(args, "--store")?;
    let server_key_path = flag(args, "--server-key")?;
    let operator_path = flag(args, "--operator")?;
    let out_path = flag(args, "--out")?;

    let request_file: RequestFile =
        serde_json::from_slice(&fs::read(request_path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let request = request_from_file(&request_file).map_err(|e| e.to_string())?;
    let store = BlobStore::new(PathBuf::from(store_path)).map_err(|e| e.to_string())?;
    let compressed_server_key =
        read_compressed_server_key(PathBuf::from(server_key_path).as_path())
            .map_err(|e| e.to_string())?;
    let operator = read_operator(operator_path)?;
    let (binding, signature) = process_request(&store, &request, &compressed_server_key, &operator)
        .map_err(|e| e.to_string())?;
    let result = ResultFile {
        result_hash: hex::encode(binding.result_hash),
        result_type: binding.result_type,
        circuit_id: binding.circuit_id,
        request_digest: hex::encode(binding.request_digest),
        result_digest: hex::encode(confidential_protocol::result_digest(&binding)),
        signature: hex::encode(signature),
        operator: hex::encode(operator.pubkey().to_bytes()),
    };
    if let Some(parent) = PathBuf::from(out_path).parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(
        out_path,
        serde_json::to_vec_pretty(&result).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    println!("result_hash: {}", result.result_hash);
    let _ = parse_hex32(&result.result_hash);
    Ok(())
}

fn flag<'a>(args: &'a [String], name: &str) -> Result<&'a str, String> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].as_str())
        .ok_or_else(|| format!("missing {name}"))
}

fn read_operator(path: &str) -> Result<Keypair, String> {
    let bytes = fs::read(path).map_err(|e| e.to_string())?;
    if let Ok(json) = serde_json::from_slice::<Vec<u8>>(&bytes) {
        return Keypair::try_from(json.as_slice()).map_err(|e| e.to_string());
    }
    Keypair::try_from(bytes.as_slice()).map_err(|e| e.to_string())
}
