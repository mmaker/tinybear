#![forbid(unsafe_code)]

pub mod aes;

/// Helper module for the prover and verifier.
mod helper;
mod common;

pub mod prover;
pub mod verifier;

pub mod pedersen;
mod u8msm;

mod linalg;
mod lookup;
mod sigma;
mod sumcheck;
