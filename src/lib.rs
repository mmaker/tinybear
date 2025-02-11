#![forbid(unsafe_code)]

pub mod witness;

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
/// Core sigma protocols sub-protocols.
pub mod sigma;
/// Core sumcheck sub-protocol.
pub mod sumcheck;
/// Unit-tests.
#[cfg(test)]
mod tests;
/// Generic models used in the proof.
#[allow(non_snake_case)]
mod traits;
/// Fast MSM for u8 scalar elements.
mod umsm;
/// Verifier module.
mod verifier;

pub use exports::*;
