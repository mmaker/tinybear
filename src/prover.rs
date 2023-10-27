#![allow(non_snake_case)]

/// See Figure 8 in the paper to learn how this protocol works
use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_serialize::CanonicalSerialize;

use transcript::IOPTranscript;

use super::{aes, helper, linalg, lookup, pedersen, sigma, sumcheck};
use crate::linalg::tensor;
use crate::pedersen::CommitmentKey;
use crate::sigma::SigmaProof;
use crate::sumcheck::Claim;

// A summary of the evaluations and proofs required in the protocol.
#[derive(Default, CanonicalSerialize)]
pub struct LinearEvaluationProofs<G: CurveGroup> {
    // com(y_1)
    pub Y_1: G,
    // com(y_2)
    pub Y_2: G,
    // Proof for <m, h> = y
    pub proof_m_h: SigmaProof<G>,
    // Proof and partial result for merged scalar product: <g, tensor + c> = y_1 + c * y
    pub proof_q_1_tensor: SigmaProof<G>,
    // Proof and result for <f, tensor> = <w, A tensor> =  y_2
    pub proof_f_tensor: SigmaProof<G>,
    // Proof that Y = y1 * y2 (??)
    pub proof_y: SigmaProof<G>,
}

#[derive(Default, CanonicalSerialize)]
pub struct TinybearProof<G: CurveGroup> {
    // first message: witness commitment, frequencies commitment.
    pub witness_com: G,
    pub freqs_com: G, // com(m)
    // second message: inverse needles commitment, claimed evaluation.
    pub inverse_needles_com: G, // com(g)
    pub Y: G,                   // com(y)
    // sumcheck arguments: prove inner products.
    // also satisfies: <q,f> = s = tensor_evaluation - c * y
    pub sumcheck_messages: Vec<[G; 2]>,
    // claimed final evaluations.
    pub folded_w_com: G,
    pub folded_q_com: G,
    pub folded_m_com: G,
    // proof for final evaluations.
    pub sigma: SigmaProof<G>,
}

fn get_r2j_witness(witness: &aes::Witness) -> Vec<(u8, u8)> {
    let xs = witness.s_box.iter().copied();
    let ys = witness.m_col[0].iter().copied();
    xs.zip(ys).collect()
}

// sbox needles to lookup in table x -> SBOX[x]
fn get_s_box_witness(witness: &aes::Witness) -> Vec<(u8, u8)> {
    let s_box = witness._s_row.iter().zip(&witness.s_box);
    // let k_sch_s_box = witness._k_rot.iter().zip(&witness.k_sch_s_box);
    s_box.map(|(&x, &y)| (x, y)).collect()
}

// xor needles to lookup in table (x, y, z = x ^ y)
fn get_xor_witness(witness: &aes::Witness) -> Vec<(u8, u8, u8)> {
    let mut witness_xor = Vec::new();
    // m_col_xor
    for i in 0..4 {
        let xs = witness.m_col[i].iter().copied();
        let ys = witness._aux_m_col[i].iter().copied();
        let zs = witness.m_col[i + 1].iter().copied();
        let new_witness = xs.zip(ys).zip(zs).map(|((x, y), z)| (x, y, z));
        witness_xor.extend(new_witness)
    }
    // round key xor
    {
        let xs = witness.m_col[4].iter().copied();
        let zs = witness.start.iter().skip(16).copied();
        let ys = witness._keys.iter().flatten().skip(16).copied();
        // ys are the round keys
        let new_witness = xs.zip(ys).zip(zs).map(|((x, y), z)| (x, y, z));
        witness_xor.extend(new_witness)
    }
    // last round
    {
        let xs = witness.s_box.iter().skip(9 * 16).copied();
        let ys = witness._keys.iter().flatten().skip(10 * 16).copied();
        let zs = witness.output.iter().copied();
        let new_witness = xs.zip(ys).zip(zs).map(|((x, y), z)| (x, y, z));
        witness_xor.extend(new_witness);
    }
    // first round xor
    {
        let xs = witness.message.iter().copied();
        // let ys = witness._keys.iter().take(16).flatten().copied();
        let zs = witness.start.iter().take(16).copied();
        // ys is the 0th round key
        let new_witness = xs.zip(zs).map(|(x, z)| (x, x ^ z, z));
        witness_xor.extend(new_witness);
    }

    // k_sch_xor
    // for i in 0..witness.k_sch[0].len() {
    //     let (x, z) = (witness.k_sch_s_box[i], witness.k_sch[0][i]);
    //     let y = x ^ z; // this is the round constant
    //     witness_xor.push((x, y, z))
    // }
    // for x in 0..4 {
    //     for i in 4..witness.k_sch[x + 1].len() {
    //         let (x, y, z) = (
    //             witness.k_sch[x][i],
    //             witness.k_sch[x + 1][i - 4],
    //             witness.k_sch[x + 1][i],
    //         );
    //         assert_eq!(z, x ^ y);
    //         witness_xor.push((x, y, z))
    //     }
    // }
    // final_round_xor
    // {
    //     let xs = witness.s_box.iter().copied();
    //     let zs = witness.output.iter().copied();
    //     let new_witness = xs.zip(zs).map(|(x, z)| (x, x ^ z, z));
    //     witness_xor.extend(new_witness)
    // }
    witness_xor
}

/// Compute needles and frequencies
/// Return (needles, frequencies, frequencies_u8)
pub fn compute_needles_and_frequencies<F: Field>(
    witness: &aes::Witness,
    r_xor: F,
    r2_xor: F,
    r_sbox: F,
    r_rj2: F,
) -> (Vec<F>, Vec<F>, Vec<u8>) {
    // Generate the witness.
    // witness_s_box = [(a, sbox(a)), (b, sbox(b)), ...]
    let witness_s_box = get_s_box_witness(witness);
    // witness_r2j = [(a, r2j(a)), (b, r2j(b)), ...]
    let witness_r2j = get_r2j_witness(witness);
    // witness_xor = [(a, b, xor(a, b)), (c, d, xor(c, d)), ...] for 4-bits
    let witness_xor = get_xor_witness(witness);

    // Needles: these are the elements that want to be found in the haystack.
    // s_box_needles = [x_1 + r * sbox[x_1], x_2 + r * sbox[x_2], ...]
    let s_box_needles = lookup::compute_u8_needles(&witness_s_box, r_sbox);
    // r2j_needles = [x_1 + r2 * r2j[x_1], x_2 + r2 * r2j[x_2], ...]
    let r2j_needles = lookup::compute_u8_needles(&witness_r2j, r_rj2);
    // xor_needles = [x_1 + r * x_2 + r2 * xor[x_1 || x_2] , ...]
    let xor_needles = lookup::compute_u16_needles(&witness_xor, [r_xor, r2_xor]);
    // concatenate all needles
    let needles = [s_box_needles, r2j_needles, xor_needles].concat();

    // Frequencies: these count how many times each element will appear in the haystack.
    // To do so, we build the frequency vectors.
    // Frequencies are organized in this way
    // | 4-bit xor | sbox | r2j |
    // |  256      | 256  | 256 |
    // First, group witness by lookup table.
    let mut frequencies_u8 = vec![0u8; 256 * 3];
    lookup::count_u16_frequencies(&mut frequencies_u8[0..256], &witness_xor);
    lookup::count_u8_frequencies(&mut frequencies_u8[256..512], &witness_s_box);
    lookup::count_u8_frequencies(&mut frequencies_u8[512..768], &witness_r2j);

    let frequencies = frequencies_u8
        .iter()
        .map(|x| F::from(*x))
        .collect::<Vec<_>>();
    assert_eq!(needles.len(), helper::NEEDLES_LEN);
    (needles, frequencies, frequencies_u8)
}

pub fn prove<G>(
    transcript: &mut IOPTranscript<G::ScalarField>,
    ck: &CommitmentKey<G>,
    message: [u8; 16],
    key: &[u8; 16],
) -> TinybearProof<G>
where
    G: CurveGroup,
{
    let rng = &mut rand::rngs::OsRng;

    let mut proof = TinybearProof::<G>::default();
    // witness generation
    // TIME: 7e-3ms
    let witness = aes::aes128_trace(message, *key);

    // commit to trace of the program.
    // TIME: ~3-4ms [outdated]
    let witness_vector = helper::vectorize_witness(&witness);
    let (W, W_opening) = pedersen::commit_hiding_u8(rng, &ck, &witness_vector);
    // Send W
    proof.witness_com = W;
    transcript
        .append_serializable_element(b"witness_com", &[proof.witness_com])
        .unwrap();

    // Lookup
    // Get challenges for the lookup protocol.
    // one for sbox + mxcolhelp, sbox, two for xor
    let r_rj2 = transcript.get_and_append_challenge(b"r_rj2").unwrap();
    let r_sbox = transcript.get_and_append_challenge(b"r_sbox").unwrap();
    let r_xor = transcript.get_and_append_challenge(b"r_xor").unwrap();
    let r2_xor = transcript.get_and_append_challenge(b"r2_xor").unwrap();
    // Compute needles and frequencies
    let (needles, frequencies, frequencies_u8) =
        compute_needles_and_frequencies(&witness, r_xor, r2_xor, r_sbox, r_rj2);
    // Commit to m (using mu as the blinder) and send it over
    let (freqs_com, mu) = pedersen::commit_hiding_u8(rng, ck, &frequencies_u8);

    // Send M
    proof.freqs_com = freqs_com;
    transcript
        .append_serializable_element(b"m", &[proof.freqs_com])
        .unwrap();

    // Get the lookup challenge c and compute q and y
    let c = transcript.get_and_append_challenge(b"c").unwrap();
    // Compute vector inverse_needles[i] = 1 / (needles[i] + a) = q
    let mut inverse_needles = needles.iter().map(|k| c + k).collect::<Vec<_>>();
    ark_ff::batch_inversion(&mut inverse_needles);

    // Q = Com(q)
    let (inverse_needles_com, theta) = pedersen::commit_hiding(rng, &ck, &inverse_needles);
    // y = <g,1>
    let y = inverse_needles.iter().sum();
    let (Y, psi) = pedersen::commit_hiding(rng, &ck, &[y]);

    // Send (Q,Y)
    proof.inverse_needles_com = inverse_needles_com;
    proof.Y = Y;

    transcript
        .append_serializable_element(b"Q", &[proof.inverse_needles_com])
        .unwrap();
    transcript
        .append_serializable_element(b"Y", &[proof.Y])
        .unwrap();

    // Finally compute h and t
    let (haystack, inverse_haystack) = lookup::compute_haystack(r_xor, r2_xor, r_sbox, r_rj2, c);

    //////////////////////////////// Sanity checks ////////////////////////////////////////
    // Sanity check: check that the witness is indeed valid
    // sum_i q_i  = sum_i f_i
    assert_eq!(inverse_haystack.len(), frequencies_u8.len());
    assert!(needles.iter().all(|x| haystack.contains(x)));
    assert_eq!(
        inverse_haystack
            .iter()
            .zip(&frequencies_u8)
            .map(|(&a, &b)| a * G::ScalarField::from(b))
            .sum::<G::ScalarField>(),
        inverse_needles.iter().sum::<G::ScalarField>()
    );
    // check other linear evaluation scalar products
    // <m, h> == y
    assert_eq!(linalg::inner_product(&frequencies, &inverse_haystack), y);
    // <g, 1> == y
    assert_eq!(inverse_needles.iter().sum::<G::ScalarField>(), y);

    ////////////////////////////// Sumcheck  //////////////////////////////
    // claims to be computed:
    // 1. <m, h> = y
    // 2. <q, 1> = y
    //    <q, twist . (A * w + c)>  = geom_series_twist + y
    // 3. <m, G> = M
    //    <q, G> = Q
    //    <w', G'> = W
    //   all shrinked into one
    // where
    //  w' = twist . (A * w)
    //  G' =  (A * twist)^{-1} . G

    // get verifier challenges
    let twist = transcript.get_and_append_challenge(b"twist").unwrap();
    let lin_batch_chal = transcript
        .get_and_append_challenge(b"lin batch chal")
        .unwrap();
    let lin_batch_chal2 = lin_batch_chal.square();
    let batch_chal = transcript
        .get_and_append_challenge(b"sumcheck batch chal")
        .unwrap();

    // <m, h> = y
    let claim_1 = Claim::Field(frequencies.to_vec(), inverse_haystack.to_vec());

    // <m, G> = M; <q, G> = Q; <w, G> = W
    let claim_2_lhs = frequencies
        .iter()
        .zip(&witness_vector)
        .zip(&inverse_needles)
        .map(|((a, b), c)| *a + lin_batch_chal * G::ScalarField::from(*b) + lin_batch_chal2 * c)
        .collect::<Vec<_>>();
    let claim_2 = Claim::Group(claim_2_lhs, ck.vec_G.iter().map(|x| G::from(*x)).collect());

    // <q, twist . (A * w + c)>  = geom_series_twist + y
    let twists = linalg::powers(twist, helper::NEEDLES_LEN);
    let (mut mapped, _constant_term) =
        helper::trace_to_needles_map(&witness.output, &twists, r_sbox, r_rj2, r_xor, r2_xor);
    mapped.iter_mut().for_each(|x| *x += c);
    let claim_3 = Claim::Field(inverse_needles.to_vec(), mapped);

    let claims = [claim_1, claim_2, claim_3];
    let batch_challenges = linalg::powers(batch_chal, 3).try_into().unwrap();
    let (reduced_claims, sumcheck_challenges, sumcheck_messages, sumcheck_openings) =
        sumcheck::batch_sumcheck(rng, transcript, ck, claims, batch_challenges);
    proof.sumcheck_messages = sumcheck_messages;

    let [Claim::Field(folded_m, folded_h), Claim::Group(folded_commitments, folded_generators), Claim::Field(folded_q, folded_linear_w)] =
        reduced_claims
    else {
        unreachable!()
    };

    let (folded_q_com, folded_q_opening) = pedersen::commit_hiding(rng, &ck, &folded_q);
    let (folded_m_com, folded_m_opening) = pedersen::commit_hiding(rng, &ck, &folded_m);
    let (folded_w_com, folded_w_opening) = pedersen::commit_hiding(rng, &ck, &folded_linear_w);

    // send at the end:
    // com(folded_w)
    // com(folded_q)
    // com(folded_m)
    // verifier computes:
    // folded_h
    // folded_1
    // folded_G
    // folded_twist_G
    // prover must also prove folded_q * folded_w'
    proof.folded_m_com = folded_m_com;
    proof.folded_q_com = folded_q_com;
    proof.folded_w_com = folded_w_com;

    ////////////////////////////// Sigma protocols //////////////////////////////
    // proof.tensors =

    proof
}

#[test]
fn test_prove() {
    type G = ark_curve25519::EdwardsProjective;

    let mut transcript = IOPTranscript::<ark_curve25519::Fr>::new(b"aes");
    transcript.append_message(b"init", b"init").unwrap();

    let message = [
        0x4A, 0x8F, 0x6D, 0xE2, 0x12, 0x7B, 0xC9, 0x34, 0xA5, 0x58, 0x91, 0xFD, 0x23, 0x69, 0x0C,
        0xE7,
    ];
    let key = [
        0xE7u8, 0x4A, 0x8F, 0x6D, 0xE2, 0x12, 0x7B, 0xC9, 0x34, 0xA5, 0x58, 0x91, 0xFD, 0x23, 0x69,
        0x0C,
    ];
    let ck = pedersen::setup::<G>(&mut rand::thread_rng(), 2084);

    let proof = prove::<G>(&mut transcript, &ck, message, &key);
    println!("size: {}", proof.compressed_size());
}
