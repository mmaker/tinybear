use ark_ec::CurveGroup;
use ark_ff::{Zero};

use transcript::IOPTranscript;

use crate::linalg::tensor;

use crate::prover::ProofTranscript;

use super::{sumcheck};

pub struct InvalidProof;
type ProofResult = Result<(), InvalidProof>;

#[allow(unused)] // XXX during dev
pub fn verify<G>(
    transcript: &mut IOPTranscript<G::ScalarField>,
    ck: &[G::Affine],
    k: [u8; 16],
    proof: &ProofTranscript<G>,
) -> ProofResult
where
    G: CurveGroup,
{
    transcript.append_serializable_element(b"witness", &[proof.witness_com]).unwrap();
    let lookup_challenge = transcript.get_and_append_challenge(b"lookup_challenge").unwrap();
    let r_mcolpre = transcript.get_and_append_challenge(b"r_mcolpre").unwrap();
    let r_sbox = transcript.get_and_append_challenge(b"r_sbox").unwrap();
    let r_xor = transcript.get_and_append_challenge(b"r_xor").unwrap();
    let r2_xor = transcript.get_and_append_challenge(b"r2_xor").unwrap();

    transcript
        .append_serializable_element(b"nhf", &[
            proof.inverse_needles_com,
            proof.inverse_haystack_com,
            proof.freqs_com,
        ])
        .unwrap();

    let mut batch_challenge = [G::ScalarField::zero(); 2];
    batch_challenge[0] = transcript.get_and_append_challenge(b"bc0").unwrap();
    batch_challenge[1] = transcript.get_and_append_challenge(b"bc1").unwrap();
    let sumcheck_batch_challenge = transcript.get_and_append_challenge(b"sbc").unwrap();

    let sumcheck_claim =
        proof.sumcheck_claim_haystack + sumcheck_batch_challenge * proof.sumcheck_claim_needles;
    let e = &proof.evaluations;
    let evaluation_haystack = G::ScalarField::zero();
    let evaluation_needles = G::ScalarField::zero();
    let needles_sumcheck_got = e.inverse_needles * evaluation_needles;
    let haystack_sumcheck_got = e.inverse_haystack * (evaluation_haystack + e.freqs);

    let (sumcheck_challenges, haystack_reduced) =
        sumcheck::reduce(transcript, &proof.sumcheck, proof.sumcheck_claim_haystack);


    let k_gg = proof.evaluations.sigma_proof.0;
    let s = &proof.evaluations.sigma_proof.1;
    transcript.append_serializable_element(b"k_gg", &[k_gg]).unwrap();
    let c = transcript.get_and_append_challenge(b"c0").unwrap();
    let s_gg = G::msm_unchecked(&ck, &s);

    // check the sigma protocol is valid
    let morphism = tensor(&sumcheck_challenges);
    // let morphism_witness = challenge_for_witness(&morphism, r_sbox, r_mcolpre, r_xor, r2_xor);

    Err(InvalidProof)
}
