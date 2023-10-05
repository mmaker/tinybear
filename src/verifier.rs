use ark_ec::CurveGroup;
use ark_ff::{Zero};

use transcript::IOPTranscript;

use crate::linalg;
use crate::linalg::{tensor};

use crate:: pedersen;
use crate::prover::{prove, Proof};

use super::{sumcheck};

pub struct InvalidProof;
type ProofResult = Result<(), InvalidProof>;

#[allow(unused)] // XXX during dev
pub fn verify<G>(
    transcript: &mut IOPTranscript<G::ScalarField>,
    ck: &[G::Affine],
    k: [u8; 16],
    proof: &Proof<G>,
) -> ProofResult
where
    G: CurveGroup,
{
    // Step 2: Lookup verifier challenges
    transcript.append_serializable_element(b"witness_com", &[proof.witness_com]).unwrap();

    let r_mcolpre = transcript.get_and_append_challenge(b"r_mcolpre").unwrap();
    let r_sbox = transcript.get_and_append_challenge(b"r_sbox").unwrap();
    let r_xor = transcript.get_and_append_challenge(b"r_xor").unwrap();
    let r2_xor = transcript.get_and_append_challenge(b"r2_xor").unwrap();

    transcript.append_serializable_element(b"m", &[proof.freqs_com,]).unwrap();

    let alpha = transcript.get_and_append_challenge(b"alpha").unwrap();

    transcript.append_serializable_element(b"g", &[proof.inverse_needles_com]).unwrap();
    transcript.append_serializable_element(b"gamma", &[proof.gamma]).unwrap();

    // Step 5: Sumcheck
    let (sumcheck_challenges, tensorcheck_claim) =
        sumcheck::reduce(transcript, &proof.sumcheck_messages, proof.sumcheck_claim_f_g);

    // Step 6: Linear evaluations
    let c_0 = transcript.get_and_append_challenge(b"bc0").unwrap();
    let evaluation_point = linalg::tensor(&sumcheck_challenges);

    // First sigma
    // let k_gg = proof.sigmas.sigma_proof.0;
    // let s = &proof.sigmas.sigma_proof.1;
    // transcript.append_serializable_element(b"k_gg", &[k_gg]).unwrap();

    // let mut vec_delta = [G::ScalarField::zero(); 3];
    // vec_delta[0] = transcript.get_and_append_challenge(b"delta0").unwrap();
    // vec_delta[1] = transcript.get_and_append_challenge(b"delta1").unwrap();
    // vec_delta[2] = transcript.get_and_append_challenge(b"delta2").unwrap();

    // // Second sigma
    // let k_gg_2 = proof.sigmas.sigma_proof_needles.0;
    // transcript.append_serializable_element(b"k_gg2", &[k_gg_2]).unwrap();
    // let chal = transcript.get_and_append_challenge(b"chal").unwrap();

    // println!("v chal: {}", chal);

    // check the sigma protocol is valid
    let morphism = tensor(&sumcheck_challenges);
    // let morphism_witness = challenge_for_witness(&morphism, r_sbox, r_mcolpre, r_xor, r2_xor);

    Err(InvalidProof)
}


#[test]
fn test_end_to_end() {
    type G = ark_curve25519::EdwardsProjective;

    let mut transcript_p = IOPTranscript::<ark_curve25519::Fr>::new(b"aes");
    transcript_p.append_message(b"init", b"init").unwrap();

    let mut transcript_v = IOPTranscript::<ark_curve25519::Fr>::new(b"aes");
    transcript_v.append_message(b"init", b"init").unwrap();


    let message = [
        0x4A, 0x8F, 0x6D, 0xE2, 0x12, 0x7B, 0xC9, 0x34, 0xA5, 0x58, 0x91, 0xFD, 0x23, 0x69, 0x0C,
        0xE7,
    ];
    let key = [
        0xE7u8, 0x4A, 0x8F, 0x6D, 0xE2, 0x12, 0x7B, 0xC9, 0x34, 0xA5, 0x58, 0x91, 0xFD, 0x23, 0x69,
        0x0C,
    ];
    let ck = pedersen::setup::<G>(&mut rand::thread_rng(), 2084);

    let proof = prove::<G>(&mut transcript_p, &ck, message, &key);

    let _ = verify::<G>(&mut transcript_v, &ck, key, &proof);
}

