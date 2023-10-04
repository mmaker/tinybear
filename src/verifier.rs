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
    // Step 2: Lookup verifier challenges
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

    // Step 4: Verifier challenges for inner product batching
    let c_0 = transcript.get_and_append_challenge(b"bc0").unwrap(); // c_0
    let c_1 = transcript.get_and_append_challenge(b"bc1").unwrap(); // c_1
    let beta = transcript.get_and_append_challenge(b"sbc").unwrap();

    // Step 5: Sumcheck

    // t + \beta * c_1
    let sumcheck_claim =
        proof.sumcheck_claim_haystack + beta * proof.sumcheck_claim_needles;
    // XXX
    let evaluation_haystack = G::ScalarField::zero();
    let evaluation_needles = G::ScalarField::zero();
    // <f, tensor> XXX
    let needles_sumcheck_got = proof.evaluations.inverse_needles * evaluation_needles;
    // <t, tensor> * (XXX + <m, tensor>)
    let haystack_sumcheck_got = proof.evaluations.inverse_haystack * (evaluation_haystack + proof.evaluations.freqs);

    // proof.sumcheck_claim_haystack is result?
    let (sumcheck_challenges, tensorcheck_claim) =
        sumcheck::reduce(transcript, &proof.sumcheck, proof.sumcheck_claim_haystack);

    // Step 6: Linear evaluations

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
