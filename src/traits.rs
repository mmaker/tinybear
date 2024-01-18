use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_serialize::CanonicalSerialize;
use nimue::plugins::arkworks::ArkGroupIOPattern;

use nimue::plugins::arkworks::ArkGroupArthur;
use nimue::plugins::arkworks::ArkGroupMerlin;
use nimue::{ProofResult, DuplexHash};

use crate::pedersen::CommitmentKey;
use crate::registry;
use crate::sigma::SigmaProof;

pub trait TinybearIO: SumcheckIO + MulProofIO + LinProofIO + Sized {
    fn tinybear_statement(self) -> Self;
    fn tinybear_io(self, needles_len: usize, witness_len: usize) -> Self;

    fn aes128_io(self) -> Self {
        let reg = registry::AES128REG;
        self.tinybear_io(reg.needles_len, reg.witness_len)
    }

    fn aes256_io(self) -> Self {
        let reg = registry::AES256REG;
        self.tinybear_io(reg.needles_len, reg.witness_len)
    }

    fn aes128ks_io(self) -> Self {
        let reg = registry::AES128KSREG;
        self.tinybear_io(reg.needles_len, reg.witness_len)
    }
}

pub trait SumcheckIO {
    fn sumcheck_io(self, len: usize) -> Self;
}

pub trait LinProofIO {
    fn linproof_io(self, len: usize) -> Self;
}

pub trait MulProofIO {
    fn mulproof_io(self) -> Self;
}

pub trait LinProof<G: CurveGroup>: CanonicalSerialize + Default {
    /// Prove that <x, a> = y, where x and y are private
    /// phi is blinder of vec_x
    /// psi is blinder of y
    fn new<'a>(
        arthur: &'a mut ArkGroupArthur<G>,
        ck: &CommitmentKey<G>,
        x_vec: &[G::ScalarField],
        X_opening: &G::ScalarField,
        Y_opening: &G::ScalarField,
        a_vec: &[G::ScalarField],
    ) -> ProofResult<&'a [u8]>;

    /// Verify a proof that given commitment X, its opening x has: <x, a> = y
    fn verify(
        merlin: &mut ArkGroupMerlin<G>,
        ck: &CommitmentKey<G>,
        a_vec: &[G::ScalarField],
        X: &G,
        Y: &G,
    ) -> ProofResult<()>;
}

pub trait Instance<G: CurveGroup> {
    fn needles_len(&self) -> usize;
    fn witness_len(&self) -> usize;

    fn full_witness_com(&self, w_com: &G) -> G;

    fn trace_to_needles_map(
        &self,
        src: &[G::ScalarField],
        r: [G::ScalarField; 4],
    ) -> (Vec<G::ScalarField>, G::ScalarField);
}

pub trait Witness<F: Field> {
    fn witness_vec(&self) -> &[u8];

    fn needles_len(&self) -> usize;
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

impl<G: CurveGroup, H: DuplexHash<u8>> TinybearIO for ArkGroupIOPattern<G, H, u8> {
    fn tinybear_statement(self) -> Self {
        todo!()
    }

    fn tinybear_io(self, needles_len: usize, witness_len: usize) -> Self {
        self.add_points(1, "witness")
            .challenge_scalars(1, "batch lookup (c_lup_batch)")
            .add_points(1, "lookup frequences (M)")
            .challenge_scalars(1, "lookup (c_lup)")
            .add_points(2, "inverse needles and claimed IP (Q, Y)")
            .challenge_scalars(1, "IPA twist (c_ipa_twist)")
            .sumcheck_io(needles_len)
            .add_points(2, "ipa_Q_fold, ipa_F_twist_fold")
            .mulproof_io()
            .challenge_scalars(1, "c_q")
            .challenge_scalars(1, "c_lin_batch")
            .sumcheck_io(witness_len * 2)
            .add_points(2, "lin_M_fold, lin_Q_fold")
            .challenge_scalars(1, "c_batch_eval")
            .linproof_io(witness_len * 2)
    }
}
#[derive(Default, CanonicalSerialize)]
pub struct TinybearProof<G, LP>
where
    G: CurveGroup,
    LP: LinProof<G>,
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
