//! Phase 1.1: drive the deployed coordinator program over real Solana
//! Devnet RPC. Transport/RPC only -- no changes to the on-chain program,
//! account layouts, or the `confidential-protocol` digest scheme.

pub mod args;
pub mod commands;
pub mod decode;
pub mod rpc;
pub mod state;

#[cfg(test)]
mod tests;
