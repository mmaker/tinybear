#![forbid(unsafe_code)]

/// Basic AES implementation.
pub mod aes;
/// AES keyschedule and cipher constraints.
mod constrain;
/// Interface functions publicly exposed.
mod exports;
/// Linear algebra toolkit.
mod linalg;
/// Core lookup sub-protocol.
mod lookup;
/// Pedersen commitment.
pub mod pedersen;
/// Prover module.
mod prover;
/// Helper module for the prover and verifier.
mod registry;
/// Core sigma protocols sub-protocols.
mod sigma;
/// Core sumcheck sub-protocol.
mod sumcheck;
/// Unit-tests.
#[cfg(test)]
mod tests;
/// Generic models used in the proof.
#[allow(non_snake_case)]
mod traits;
/// Fast MSM for u8 scalar elements.
mod u8msm;
/// Verifier module.
mod verifier;



pub use exports::*;
