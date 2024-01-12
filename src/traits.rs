use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_serialize::CanonicalSerialize;
use rand::{CryptoRng, RngCore};
use transcript::IOPTranscript;

use crate::pedersen::CommitmentKey;
use crate::sigma::SigmaProof;

pub type ProofResult = Result<(), ()>;

pub trait LinProof<G: CurveGroup>: CanonicalSerialize + Default {
    /// Prove that <x, a> = y, where x and y are private
    /// phi is blinder of vec_x
    /// psi is blinder of y
    fn new(
        csrng: &mut (impl CryptoRng + RngCore),
        transcript: &mut IOPTranscript<G::ScalarField>,
        ck: &CommitmentKey<G>,
        x_vec: &[G::ScalarField],
        X_opening: &G::ScalarField,
        Y_opening: &G::ScalarField,
        a_vec: &[G::ScalarField],
    ) -> Self;

    /// Verify a proof that given commitment X, its opening x has: <x, a> = y
    fn verify(
        &self,
        transcript: &mut IOPTranscript<G::ScalarField>,
        ck: &CommitmentKey<G>,
        a_vec: &[G::ScalarField],
        X: &G,
        Y: &G,
    ) -> Result<(), ()>;
}

pub trait Instance<G: CurveGroup> {
    fn full_witness_com(&self, w_com: &G) -> G;

    fn trace_to_needles_map(
        &self,
        src: &[G::ScalarField],
        r: [G::ScalarField; 4],
    ) -> (Vec<G::ScalarField>, G::ScalarField);
}

pub trait Witness<F: Field> {
    fn witness_vec(&self) -> &[u8];
    /// Compute needles and frequencies
    /// Return (needles, frequencies, frequencies_u8)
    fn compute_needles_and_frequencies(&self, r: [F; 4]) -> (Vec<F>, Vec<F>, Vec<u8>);
    fn trace_to_needles_map(&self, src: &[F], r: [F; 4]) -> (Vec<F>, F);
    /// The full witness, aka vector z in the scheme,
    /// is the concatenation of the public and private information.
    fn full_witness(&self) -> Vec<F>;
    /// The full witness opening is the opening of
    fn full_witness_opening(&self) -> F;
}

#[derive(Default, CanonicalSerialize)]
pub struct TinybearProof<G, LP>
where
    G: CurveGroup,
    LP: crate::traits::LinProof<G>,
{
    // prover sends w
    pub W: G,
    // sends commitments
    pub M: G, // com(m)
    pub Q: G, // com(q)
    // claimed evaluation of <m, h> = <q, 1>
    pub Y: G, // com(y)

    // runs sumcheck and sends commitments to folded elements
    pub ipa_sumcheck: Vec<[G; 2]>,
    pub ipa_Q_fold: G,
    pub ipa_F_twist_fold: G,
    pub mul_proof: SigmaProof<G>,

    // runs sumcheck and sends commitments to folded secret elements
    pub lin_sumcheck: Vec<[G; 2]>,
    pub lin_M_fold: G,
    pub lin_Q_fold: G,
    // lin_Z_fold computed from the reduced claim
    pub lin_proof: LP,
}
