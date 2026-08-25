use std::path::{Path, PathBuf};
use std::process::ExitCode;

use confidential_lab::{
    data_paths, encrypt_inputs, measure, read_operator, run_demo, setup, LabError, ParamsFile,
};
use fhe_worker::{
    decrypt_bool, load_bool, load_material, load_server_material, parse_hex32, process_request,
    request_from_file, BlobStore,
};
use solana_signer::Signer;

fn main() -> ExitCode {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut data_dir = PathBuf::from(".data");
    if let Some(pos) = args.iter().position(|a| a == "--data-dir") {
        if pos + 1 >= args.len() {
            eprintln!("missing --data-dir value");
            return ExitCode::from(2);
        }
        data_dir = PathBuf::from(args[pos + 1].clone());
        args.drain(pos..=pos + 1);
    }
    if args.is_empty() {
        usage();
        return ExitCode::from(2);
    }
    let cmd = args.remove(0);
    let result = match cmd.as_str() {
        "setup" => cmd_setup(&data_dir),
        "encrypt" => cmd_encrypt(&data_dir, &args),
        "evaluate" => cmd_evaluate(&data_dir),
        "decrypt" => cmd_decrypt(&data_dir),
        "demo" => cmd_demo(&data_dir, &args),
        "measure" => cmd_measure(),
        "devnet" => cmd_devnet(&data_dir, &args),
        other => {
            eprintln!("unknown command: {other}");
            usage();
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(1)
        }
    }
}

fn usage() {
    eprintln!(
        "usage: confidential-lab [--data-dir .data] <setup|encrypt|evaluate|decrypt|demo|measure|devnet>"
    );
    eprintln!(
        "       confidential-lab [--data-dir .data] devnet <initialize|create-account|submit|fetch-request|finalize|inspect>"
    );
}

fn cmd_devnet(data_dir: &Path, args: &[String]) -> Result<(), LabError> {
    if args.is_empty() {
        eprintln!(
            "usage: confidential-lab devnet <initialize|create-account|submit|fetch-request|finalize|inspect>"
        );
        return Err(LabError("missing devnet subcommand".to_string()));
    }
    let sub = args[0].as_str();
    let rest = &args[1..];
    use confidential_lab::devnet::commands;
    match sub {
        "initialize" => commands::cmd_initialize(data_dir, rest),
        "create-account" => commands::cmd_create_account(data_dir, rest),
        "submit" => commands::cmd_submit(data_dir, rest),
        "fetch-request" => commands::cmd_fetch_request(data_dir, rest),
        "finalize" => commands::cmd_finalize(data_dir, rest),
        "inspect" => commands::cmd_inspect(data_dir, rest),
        other => {
            eprintln!(
                "unknown devnet subcommand: {other}; expected one of initialize|create-account|submit|fetch-request|finalize|inspect"
            );
            Err(LabError(format!("unknown devnet subcommand: {other}")))
        }
    }
}

fn cmd_setup(data_dir: &Path) -> Result<(), LabError> {
    setup(data_dir)?;
    println!("setup: wrote keys under {}", data_dir.display());
    Ok(())
}

fn cmd_encrypt(data_dir: &Path, args: &[String]) -> Result<(), LabError> {
    let balance = parse_u64_flag(args, "--balance")?;
    let amount = parse_u64_flag(args, "--amount")?;
    let limit = parse_u64_flag(args, "--limit")?;
    let paths = data_paths(data_dir);
    let params: ParamsFile = serde_json::from_slice(&std::fs::read(&paths.params)?)
        .map_err(|e| LabError(e.to_string()))?;
    let material = load_material(
        &paths.client_key,
        &paths.server_key,
        parse_hex32(&params.params_hash)?,
    )?;
    let refs = encrypt_inputs(data_dir, &material, balance, amount, limit)?;
    let balance_hash = refs.balance_hash;
    let amount_hash = refs.amount_hash;
    let limit_hash = refs.limit_hash;
    println!("balance_hash: {}", hex::encode(balance_hash));
    println!("amount_hash: {}", hex::encode(amount_hash));
    println!("limit_hash: {}", hex::encode(limit_hash));
    Ok(())
}

fn cmd_evaluate(data_dir: &Path) -> Result<(), LabError> {
    let paths = data_paths(data_dir);
    let request_file: fhe_worker::RequestFile =
        serde_json::from_slice(&std::fs::read(&paths.request)?)
            .map_err(|e| LabError(e.to_string()))?;
    let request = request_from_file(&request_file)?;
    let store = BlobStore::new(&paths.ciphertexts)?;
    let params: ParamsFile = serde_json::from_slice(&std::fs::read(&paths.params)?)
        .map_err(|e| LabError(e.to_string()))?;
    // Evaluation only ever needs the evaluation (server) key; the client
    // decryption key is never loaded here so a worker role cannot decrypt.
    let material = load_server_material(&paths.server_key, parse_hex32(&params.params_hash)?)?;
    let operator = read_operator(&paths.operator)?;
    let (binding, signature) =
        process_request(&store, &request, &material.compressed_server_key, &operator)?;
    let out = fhe_worker::ResultFile {
        result_hash: hex::encode(binding.result_hash),
        result_type: binding.result_type,
        circuit_id: binding.circuit_id,
        request_digest: hex::encode(binding.request_digest),
        result_digest: hex::encode(confidential_protocol::result_digest(&binding)),
        signature: hex::encode(signature),
        operator: hex::encode(operator.pubkey().to_bytes()),
    };
    std::fs::write(
        &paths.result,
        serde_json::to_vec_pretty(&out).map_err(|e| LabError(e.to_string()))?,
    )?;
    println!("result_hash: {}", out.result_hash);
    Ok(())
}

fn cmd_decrypt(data_dir: &Path) -> Result<(), LabError> {
    let paths = data_paths(data_dir);
    let result_file: fhe_worker::ResultFile =
        serde_json::from_slice(&std::fs::read(&paths.result)?)
            .map_err(|e| LabError(e.to_string()))?;
    let result_hash = parse_hex32(&result_file.result_hash)?;
    let params: ParamsFile = serde_json::from_slice(&std::fs::read(&paths.params)?)
        .map_err(|e| LabError(e.to_string()))?;
    let params_hash = parse_hex32(&params.params_hash)?;
    let store = BlobStore::new(&paths.ciphertexts)?;
    let material = load_material(&paths.client_key, &paths.server_key, params_hash)?;
    let ct = load_bool(&store, &result_hash, params.key_version, &params_hash)?;
    let allowed = decrypt_bool(&ct, &material.client_key);
    println!("result: {allowed}");
    Ok(())
}

fn cmd_demo(data_dir: &Path, args: &[String]) -> Result<(), LabError> {
    let balance = parse_u64_flag(args, "--balance").unwrap_or(100);
    let amount = parse_u64_flag(args, "--amount").unwrap_or(25);
    let limit = parse_u64_flag(args, "--limit").unwrap_or(50);
    let report = run_demo(data_dir, balance, amount, limit)?;
    println!("submit_cu: {}", report.submit_cu);
    println!("finalize_cu: {}", report.finalize_cu);
    println!("result_hash: {}", hex::encode(report.result_hash));
    println!("result: {}", report.allowed);
    Ok(())
}

fn cmd_measure() -> Result<(), LabError> {
    let report = measure()?;
    println!("hardware: {}", report.hardware);
    println!("keygen_ms: {}", report.keygen_ms);
    println!("encrypt_three_ms: {}", report.encrypt_three_ms);
    println!("policy_ms: {}", report.policy_ms);
    println!("client_key_bytes: {}", report.client_key_bytes);
    println!(
        "compressed_server_key_bytes: {}",
        report.compressed_server_key_bytes
    );
    println!("server_key_bytes: {}", report.server_key_bytes);
    println!("u64_ciphertext_bytes: {}", report.u64_ciphertext_bytes);
    println!("bool_ciphertext_bytes: {}", report.bool_ciphertext_bytes);
    Ok(())
}

fn parse_u64_flag(args: &[String], name: &str) -> Result<u64, LabError> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .ok_or_else(|| LabError(format!("missing {name}")))?[1]
        .parse()
        .map_err(|_| LabError(format!("invalid {name}")))
}
