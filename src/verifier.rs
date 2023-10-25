#![allow(non_snake_case)]
use ark_ec::CurveGroup;

use transcript::IOPTranscript;

use crate::{aes, helper, linalg, lookup, sigma, sumcheck};

use crate::helper::AesEMStatement;
use crate::pedersen::CommitmentKey;
use crate::prover::TinybearProof;

type ProofResult = Result<(), ()>;

fn statement_generation(key: [u8; 16], ctx: [u8; 16]) -> AesEMStatement {
    let round_keys = aes::keyschedule(&key);
    // XXX. Needed only for AES-EM
    // let output = aes::xor(ctx, round_keys[10]);
    let output = ctx;

    AesEMStatement { round_keys, output }
}

pub fn verify<G>(
    transcript: &mut IOPTranscript<G::ScalarField>,
    ck: &CommitmentKey<G>,
    k: [u8; 16],
    ctx: [u8; 16],
    msg_com: &G,
    proof: &TinybearProof<G>,
) -> ProofResult
where
    G: CurveGroup,
{
    let statement = statement_generation(k, ctx);
    transcript
        .append_serializable_element(b"witness_com", &[proof.witness_com])
        .unwrap();

    let r_rj2 = transcript.get_and_append_challenge(b"r_rj2").unwrap();
    let r_sbox = transcript.get_and_append_challenge(b"r_sbox").unwrap();
    let r_xor = transcript.get_and_append_challenge(b"r_xor").unwrap();
    let r2_xor = transcript.get_and_append_challenge(b"r2_xor").unwrap();

    transcript
        .append_serializable_element(b"m", &[proof.freqs_com])
        .unwrap();

    let c = transcript.get_and_append_challenge(b"c").unwrap();

    transcript
        .append_serializable_element(b"Q", &[proof.inverse_needles_com])
        .unwrap();
    transcript
        .append_serializable_element(b"Y", &[proof.Y])
        .unwrap();

    // Compute h and t
    let (_haystack, inverse_haystack) = lookup::compute_haystack(r_xor, r2_xor, r_sbox, r_rj2, c);

    // Sumcheck
    let (sumcheck_challenges, tensorcheck_claim) =
        sumcheck::reduce(transcript, &proof.sumcheck_messages, proof.sumcheck_claim_s);

    // Verify sumcheck claim
    assert_eq!(
        proof.sumcheck_claim_s,
        G::ScalarField::from(proof.needles_len as i32) - c * proof.y
    );

    // Verify sumcheck tensorcheck claim (random evaluation)
    // using yet unverified y_1 and y_2
    // assert_eq!(tensorcheck_claim, proof.sigmas.y_1 * proof.sigmas.y_2);

    // Linear evaluations
    // time to verify that g, m and y are correctly provided by the prover

    // // Verify first sigma: <m, h> = y
    sigma::lineval_verifier(
        transcript,
        &ck,
        &inverse_haystack,
        &proof.freqs_com,
        &proof.Y,
        &proof.sigmas.proof_m_h,
    )?;

    // Verify merged scalar product: <g, tensor + z> = y_1 + z * y

    let tensor_evaluation_point = linalg::tensor(&sumcheck_challenges);

    let z = transcript.get_and_append_challenge(b"bc").unwrap();
    let vec_tensor_z: Vec<G::ScalarField> =
        tensor_evaluation_point.iter().map(|t| *t + z).collect();
    let Y_1_z_Y = proof.sigmas.Y_1 + proof.Y.mul(z);
    sigma::lineval_verifier(
        transcript,
        &ck,
        &vec_tensor_z,
        &proof.inverse_needles_com,
        &Y_1_z_Y,
        &proof.sigmas.proof_q_1_tensor,
    )?;

    // Verify fourth sigma: <h, tensor> = y
    let sumcheck_tensor_challenges = linalg::tensor(&sumcheck_challenges);
    let (v, constant_term) = helper::trace_to_needles_map(
        &statement,
        &sumcheck_tensor_challenges,
        r_sbox,
        r_rj2,
        r_xor,
        r2_xor,
    );
    let X = proof.witness_com + msg_com;
    let Y = proof.sigmas.Y_2 - ck.G * constant_term;
    sigma::lineval_verifier(transcript, &ck, &v, &X, &Y, &proof.sigmas.proof_f_tensor)?;

    Ok(())
}

#[test]
fn test_aes128_proof_correctness() {
    use crate::{pedersen, u8msm};
    use crate::prover::prove;

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

    let msg = message.iter().map(|x| [x & 0xf, x>>4]).flatten().collect::<Vec<_>>();
    // XXX. George: we need to make this more ergonomic;
    // it shoud be possible to concatenate the commitment keys.
    let msg_com = u8msm::u8msm(&ck.vec_G[helper::OFFSETS.message*2..], &msg);
    let ctx = aes::aes128(message, key);
    let proof = prove::<G>(&mut transcript_p, &ck, message, &key);
    let result = verify::<G>(&mut transcript_v, &ck, key, ctx, &msg_com, &proof);
    assert!(result.is_ok());
}
