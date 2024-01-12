use ark_ec::CurveGroup;
use ark_serialize::CanonicalSerialize;
use transcript::IOPTranscript;
use rand::{CryptoRng, RngCore};

use crate::{pedersen::CommitmentKey, sigma::{SigmaProof, self}};

#[allow(non_snake_case)]
pub trait LinProof<G: CurveGroup>: CanonicalSerialize  + Default{
    fn new(csrng: &mut (impl CryptoRng + RngCore), transcript: &mut IOPTranscript<G::ScalarField>, ck: &CommitmentKey<G>, x_vec: &[G::ScalarField], X_opening: &G::ScalarField, Y_opening: &G::ScalarField, a_vec: &[G::ScalarField]) -> Self;

    fn verify(&self, transcript: &mut IOPTranscript<G::ScalarField>, ck: &CommitmentKey<G>, a_vec: &[G::ScalarField], X: &G, Y: &G) -> Result<(), ()>;
}

#[allow(non_snake_case)]
impl<G: CurveGroup> LinProof<G> for SigmaProof<G> {
    fn new(csrng: &mut (impl CryptoRng + RngCore), transcript: &mut IOPTranscript<G::ScalarField>, ck: &CommitmentKey<G>, x_vec: &[G::ScalarField], X_opening: &G::ScalarField, Y_opening: &G::ScalarField, a_vec: &[G::ScalarField]) -> Self {
        sigma::lin_prove(csrng, transcript, ck, x_vec, &X_opening, &Y_opening, a_vec)
    }

    fn verify(&self, transcript: &mut IOPTranscript<G::ScalarField>, ck: &CommitmentKey<G>, a_vec: &[G::ScalarField], X: &G, Y: &G) -> Result<(), ()> {
        sigma::lin_verify(transcript, ck, a_vec, X, Y, self)
    }

}