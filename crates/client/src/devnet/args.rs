//! Manual `--flag value` parsing, in the same minimal style as the rest of
//! this CLI (see `parse_u64_flag` in `main.rs`). No argument-parsing crate.

use crate::LabError;

pub fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].as_str())
}

pub fn require_flag(args: &[String], name: &str) -> Result<String, LabError> {
    flag(args, name)
        .map(str::to_string)
        .ok_or_else(|| LabError(format!("missing required flag {name}")))
}

pub fn flag_or(args: &[String], name: &str, default: &str) -> String {
    flag(args, name).unwrap_or(default).to_string()
}

pub fn flag_u64_or(args: &[String], name: &str, default: u64) -> Result<u64, LabError> {
    match flag(args, name) {
        Some(value) => value
            .parse()
            .map_err(|_| LabError(format!("invalid {name}: {value}"))),
        None => Ok(default),
    }
}

pub fn flag_hex32(args: &[String], name: &str) -> Result<[u8; 32], LabError> {
    let value = require_flag(args, name)?;
    fhe_worker::parse_hex32(&value)
        .map_err(|_| LabError(format!("invalid {name}: not 32 bytes of hex")))
}
