/// Here's roughly how the protocol works.
///
/// Prover:
///  com(witness): G
/// Verifier:
///  r, r_sbox, r_xor, r2_xor, lookup_challenge: [F; 5]
/// Prover:
///  com(inverse_needles): G
///  com(inverse_haystack): G
///  com(freqs): G
/// Verifier:
///  batch_sumcheck_challenges: F
/// Prover:
///  sumcheck_claims: [F; 2]
/// Prover and Verifier:
///  sumcheck
/// Prover:
///  linear_evaluations: [F; 4]
///  linear_evaluations_proofs
use ark_ec::CurveGroup;
use ark_ff::{Field, UniformRand, Zero};
use ark_serialize::CanonicalSerialize;

use crate::linalg::tensor;

use super::{aes, linalg, lookup, pedersen, sumcheck};

const WITNESS_LEN: usize = 1760;

#[derive(Default)]
struct AesWitnessRegions {
    start: usize,
    s_box: usize,
    // final_s_box: usize,
    m_col_xor: [usize; 5],
}

// The witness is structured as follows:
// .start is the state at each intermediate round, so
//   pos = 0
//   len = 16 * 9 = 144
// .s_box is the state after the sbox, so
//   pos = 16 * 9 = 144
//   len = 16 * 9 = 144
// .m_col_xor[i] is the state after the m_col_xor[i], so
//   pos = .start.len +
const OFFSETS: AesWitnessRegions = {
    let start = 0;
    let s_box = start + 2 * (16 * 9 + 16);
    // let final_s_box = s_box + 2 * 16;
    // thank Rust for const for loops
    let m_col_offset = s_box + 2 * (16 * 9);
    let m_col_len = 2 * (16 * 9);
    let m_col_xor = [
        m_col_offset + m_col_len * 0,
        m_col_offset + m_col_len * 1,
        m_col_offset + m_col_len * 2,
        m_col_offset + m_col_len * 3,
        m_col_offset + m_col_len * 4,
    ];

    AesWitnessRegions {
        start,
        s_box,
        // final_s_box,
        m_col_xor,
    }
};

// A summary of the evaluations and proofs required in the protocol.
#[derive(Default, CanonicalSerialize)]
pub struct AesProofEvaluations<G: CurveGroup> {
    // inverse_needles(sumcheck_challenges)
    inverse_needles: G::ScalarField,
    // inverse_haystack(sumcheck_challenges)
    inverse_haystack: G::ScalarField,
    /// freqs(twist)
    freqs: G::ScalarField,
    // needles(sumcheck_challenges)
    needles: G::ScalarField,

    // proofs
    proof: (G, Vec<G::ScalarField>),
    proof_needles: (G, Vec<G::ScalarField>),
}

#[derive(Default, CanonicalSerialize)]
pub struct ProofTranscript<G: CurveGroup> {
    witness: G,
    // we actually know the len of the items below, it's LOOKUP_CHUNKS
    freqs_com: G,
    inverse_needles_com: G,
    inverse_haystack_com: G,

    // we actually know the len of this thing,
    // it's going to be 12 for aes128 with 4-bit xor
    // it's going to be 17 for 8-bit table xor
    sumcheck: Vec<[G::ScalarField; 2]>,
    sumcheck_claim_haystack: G::ScalarField,
    sumcheck_claim_needles: G::ScalarField,

    evaluations: AesProofEvaluations<G>,
}

fn witness_vector(witness: &aes::Witness) -> Vec<u8> {
    let mut w = Vec::new();

    assert_eq!(OFFSETS.start, w.len());
    w.extend(witness.start.iter().map(|x| [x & 0xf, x >> 4]).flatten());

    assert_eq!(OFFSETS.s_box, w.len());
    w.extend(witness.s_box.iter().map(|x| [x & 0xf, x >> 4]).flatten());

    // assert_eq!(OFFSETS.final_s_box, w.len());
    // w.extend(
    //     witness
    //         .final_s_box
    //         .iter()
    //         .map(|x| [x & 0xf, x >> 4])
    //         .flatten(),
    // );

    for i in 0..5 {
        assert_eq!(OFFSETS.m_col_xor[i], w.len());
        w.extend(
            witness.m_col_xor[i]
                .iter()
                .map(|x| [x & 0xf, x >> 4])
                .flatten(),
        );
    }

    // w.extend(
    //     witness
    //         .final_s_box
    //         .iter()
    //         .map(|x| [x & 0xf, x >> 4])
    //         .flatten(),
    // );

    w
}

fn get_m_col_pre_witness(witness: &aes::Witness) -> Vec<(u8, u8)> {
    let xs = witness.s_box.iter().copied();
    let ys = witness.m_col_xor[0].iter().copied();
    xs.zip(ys).collect()
}

// sbox needles to lookup in table x -> SBOX[x]
fn get_s_box_witness(witness: &aes::Witness) -> Vec<(u8, u8)> {
    let s_box = witness._s_row.iter().zip(&witness.s_box);
    // let k_sch_s_box = witness._k_rot.iter().zip(&witness.k_sch_s_box);
    // let final_s_box = witness._final_s_row.iter().zip(&witness.final_s_box);
    // s_box.chain(final_s_box).map(|(&x, &y)| (x, y)).collect()
    s_box.map(|(&x, &y)| (x, y)).collect()
}

// xor needles to lookup in table (x, y, z = x ^ y)
fn get_xor_witness(witness: &aes::Witness) -> Vec<(u8, u8, u8)> {
    let mut witness_xor = Vec::new();
    // m_col_xor
    for i in 0..4 {
        let xs = witness.m_col_xor[i].iter().copied();
        let ys = witness._aux_m_col_xor[i].iter().copied();
        let zs = witness.m_col_xor[i + 1].iter().copied();
        let new_witness = xs.zip(ys).zip(zs).map(|((x, y), z)| (x, y, z));
        witness_xor.extend(new_witness)
    }
    // addroundkey_xor
    {
        let xs = witness.m_col_xor[4].iter().copied();
        let zs = witness.start.iter().copied();
        // ys are the round keys
        let new_witness = xs.zip(zs).map(|(x, z)| (x, x ^ z, z));
        witness_xor.extend(new_witness)
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
    {
        let xs = witness.final_s_box.iter().copied();
        let zs = witness.output.iter().copied();
        let new_witness = xs.zip(zs).map(|(x, z)| (x, x ^ z, z));
        witness_xor.extend(new_witness)
    }
    witness_xor
}

fn challenge_for_witness<F: Field>(vector: &[F], r_sbox: F, r: F, r_xor: F, r2_xor: F) -> Vec<F> {
    // the final matrix that maps witness -> needles
    // has dimensions: needles.len() x witness.len()
    // where
    // needles.len() = 1472
    //   s_box_needles.len() (9 * 16) +
    //   m_col_pre.len() (9 * 16) +
    //   xor_needles.len() (16 * 9 * 5 * 2)
    // witness.len() =
    //   start.len() (9 * 16 * 2)
    //   s_box.len() (9 * 16 * 2)
    //   m_col_pre.len() (9 * 16 * 5 * 2)
    const WITNESS_LEN: usize = 2016 + 144;

    let mut current_row = vec![F::zero(); WITNESS_LEN];
    let identity = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let s_row = aes::shiftrows(identity);
    let mut aux_m_col = [identity; 4];
    aes::rotate_right_inplace(&mut aux_m_col[0], 1);
    aes::rotate_right_inplace(&mut aux_m_col[1], 2);
    aes::rotate_right_inplace(&mut aux_m_col[2], 3);
    aes::rotate_right_inplace(&mut aux_m_col[3], 3);

    let mut offset = 0;
    // sbox
    for round in 0..9 {
        for i in 0..16 {
            let s_row_pos = 16 * round + s_row[i] as usize;
            let s_box_pos = 16 * round + i;
            //
            let c_lo = vector[round * 16 + i];
            let c_hi = c_lo.double().double().double().double();
            current_row[s_row_pos * 2] += c_lo;
            current_row[s_row_pos * 2 + 1] += c_hi;
            current_row[OFFSETS.s_box + s_box_pos * 2] += r_sbox * c_lo;
            current_row[OFFSETS.s_box + s_box_pos * 2 + 1] += r_sbox * c_hi;
        }
    }

    offset += 16 * 9;
    // add mxcolpre
    for round in 0..9 {
        for i in 0..16 {
            let pos = 16 * round + i;
            //
            let c_lo = vector[offset + pos];
            let c_hi = c_lo.double().double().double().double();
            current_row[OFFSETS.s_box + pos * 2] += c_lo;
            current_row[OFFSETS.s_box + pos * 2 + 1] += c_hi;
            current_row[OFFSETS.m_col_xor[0] + pos * 2] += r * c_lo;
            current_row[OFFSETS.m_col_xor[0] + pos * 2 + 1] += r * c_hi;
        }
    }

    offset += 16 * 9;
    for k in 0..4 {
        for round in 0..9 {
            for i in 0..16 {
                let pos = 16 * round + i;
                let ys_pos = 16 * round + aux_m_col[k][i];
                let ys_offset = if k < 3 {
                    OFFSETS.s_box
                } else {
                    OFFSETS.m_col_xor[0]
                };
                let c_even = vector[offset + 16 * 9 * 2 * k + pos * 2];
                let c_odd = vector[offset + 16 * 9 * 2 * k + pos * 2 + 1];
                current_row[OFFSETS.m_col_xor[k] + pos * 2] += c_even;
                current_row[ys_offset + ys_pos * 2] += r_xor * c_even;
                current_row[OFFSETS.m_col_xor[k + 1] + pos * 2] += r2_xor * c_even;

                current_row[OFFSETS.m_col_xor[k] + pos * 2 + 1] += c_odd;
                current_row[ys_offset + ys_pos * 2 + 1] += r_xor * c_odd;
                current_row[OFFSETS.m_col_xor[k + 1] + pos * 2 + 1] += r2_xor * c_odd;
            }
        }
    }

    offset += 16 * 9 * 4 * 2;
    // add mxcolpre
    for round in 0..9 {
        for i in 0..16 {
            let pos = 16 * round + i;
            let c_even = vector[offset + pos * 2];
            let c_odd = vector[offset + pos * 2 + 1];
            current_row[OFFSETS.m_col_xor[4] + pos * 2] += c_even;
            // current_row[ys_offset + ys_pos * 2] += r_xor * c_even;
            current_row[OFFSETS.start + pos * 2] += r2_xor * c_even;

            current_row[OFFSETS.m_col_xor[4] + pos * 2 + 1] += c_odd;
            // current_row[ys_offset + ys_pos * 2 + 1] += r_xor * c_odd;
            current_row[OFFSETS.start + pos * 2 + 1] += r2_xor * c_odd;
        }
    }
    current_row
}

pub fn prove<G>(
//    transcript: &mut Transcript,
    ck: &[G::Affine],
    message: [u8; 16],
    key: &[u8; 16],
) -> ProofTranscript<G>
where
    G: CurveGroup,
{
    let rng = &mut rand::rngs::OsRng;

    let mut proof = ProofTranscript::<G>::default();
    // witness generation
    // TIME: 7e-3ms
    let witness = aes::aes128_trace(message, *key);
    // commit to trace of the program.
    // TIME: ~3-4ms [outdated]
    let witness_vector = witness_vector(&witness);
    proof.witness = pedersen::commit_u8(&ck, &witness_vector);
    // transcript.absorb_serializable(&[proof.witness]).unwrap();

    // Lookup protocol
    // we're going to play with it using log derivatives.
    // we want to show that all the needles are in the haystack
    // Generate the witness.
    let witness_s_box = get_s_box_witness(&witness);
    let witness_m_col_pre = get_m_col_pre_witness(&witness);
    let witness_xor = get_xor_witness(&witness);
    // Get challenges for the lookup protocol.
    // one for sbox + mxcolhelp, sbox, two for xor
    // let lookup_challenge = transcript.squeeze_pfelt::<G::ScalarField>().unwrap();
    let lookup_challenge = G::ScalarField::from(0); // squeeze
    // let r_mcolpre = transcript.squeeze_pfelt().unwrap();
    let r_mcolpre = G::ScalarField::from(0); // squeeze
    // let r_sbox = transcript.squeeze_pfelt().unwrap();
    let r_sbox = G::ScalarField::from(0); // squeeze
    // XXXXXXXXX
    // let r_xor = transcript.squeeze_pfelt::<G::ScalarField>().unwrap();
    let r_xor = G::ScalarField::from(0); // squeeze
    // let r2_xor = transcript.squeeze_pfelt().unwrap();
    let r2_xor = G::ScalarField::from(0); // squeeze

    // Needles: these are the elements that want to be found in the haystack.
    // Note: sbox+mixcol is a single table x -> MXCOLHELP[SBOX[x]]
    let s_box_needles = lookup::u8_needles(&witness_s_box, r_sbox);
    let m_col_pre_needles = lookup::u8_needles(&witness_m_col_pre, r_mcolpre);
    let xor_needles = lookup::u16_needles(&witness_xor, [r_xor, r2_xor]);

    let needles = [s_box_needles, m_col_pre_needles, xor_needles].concat();

    // Frequencies: these count how many times each element will appear in the haystack.
    // To do so, we build the frequency vectors.
    // Frequencies are organized in this way
    // | 4-bit xor | sbox | m_col_pre |
    // |  256      | 256  | 256       |
    // First, group witness by lookup table.
    let mut u8freqs = vec![0u8; 256 * 3];
    lookup::u16_frequencies(&mut u8freqs[0..256], &witness_xor);
    lookup::u8_frequencies(&mut u8freqs[256..512], &witness_s_box);
    lookup::u8_frequencies(&mut u8freqs[512..768], &witness_m_col_pre);
    let freqs = u8freqs
        .iter()
        .map(|x| G::ScalarField::from(*x))
        .collect::<Vec<_>>();

    let mut inverse_needles = needles
        .iter()
        .map(|k| lookup_challenge + k)
        .collect::<Vec<_>>();
    ark_ff::batch_inversion(&mut inverse_needles);

    let haystack_xor = (0u8..=255)
        .map(|i| {
            let x = i & 0xf;
            let y = i >> 4;
            let z = x ^ y;
            G::ScalarField::from(x)
                + r_xor * G::ScalarField::from(y)
                + r2_xor * G::ScalarField::from(z)
        })
        .collect::<Vec<_>>();
    let haystack_s_box = (0u8..=255)
        .map(|i| {
            let x = i;
            let y = aes::SBOX[x as usize];
            G::ScalarField::from(x) + r_sbox * G::ScalarField::from(y)
        })
        .collect::<Vec<_>>();
    let haystack_m_col_pre = (0u8..=255)
        .map(|i| {
            let x = i;
            let y = aes::M_COL_HELP[x as usize];
            G::ScalarField::from(x) + r_mcolpre * G::ScalarField::from(y)
        })
        .collect::<Vec<_>>();

    let haystack = [haystack_xor, haystack_s_box, haystack_m_col_pre].concat();

    let mut inverse_haystack = haystack
        .iter()
        .map(|x| lookup_challenge + x)
        .collect::<Vec<_>>();
    ark_ff::batch_inversion(&mut inverse_haystack);

    // check that the witness is indeed valid
    // sum_i g_i  = sum_i f_i
    assert_eq!(inverse_haystack.len(), u8freqs.len());
    for x in &needles {
        assert!(haystack.contains(x))
    }
    assert_eq!(
        inverse_haystack
            .iter()
            .zip(&u8freqs)
            .map(|(&a, &b)| a * G::ScalarField::from(b))
            .sum::<G::ScalarField>(),
        inverse_needles.iter().sum::<G::ScalarField>()
    );

    // TIME: 1ms
    // We commit to inverse_needles and inverse_haystack.
    // Normally, this would be:
    proof.inverse_needles_com = pedersen::commit(&ck, &inverse_needles);
    proof.inverse_haystack_com = pedersen::commit(&ck, &inverse_haystack);
    proof.freqs_com = pedersen::commit_u8(ck, &u8freqs);
    // transcript
    //     .absorb_serializable(&[
    //         proof.inverse_needles_com,
    //         proof.inverse_haystack_com,
    //         proof.freqs_com,
    //     ])
    //     .unwrap();

    let mut batch_challenge = [G::ScalarField::zero(); 2];
    // batch_challenge[0] = transcript.squeeze_pfelt().unwrap();
    batch_challenge[0] = G::ScalarField::zero(); // squeeze
    // batch_challenge[1] = transcript.squeeze_pfelt().unwrap();
    batch_challenge[1] = G::ScalarField::zero();
    // let sumcheck_batch_challenge = transcript.squeeze_pfelt().unwrap();
    let sumcheck_batch_challenge = G::ScalarField::zero();

    let sumcheck_needles_rhs = {
        let shift = lookup_challenge + batch_challenge[0];
        needles.iter().map(|x| shift + x).collect::<Vec<_>>()
    };

    let mut sumcheck_haystack_rhs = vec![G::ScalarField::zero(); 256 * 3];
    for (i, (f, h)) in freqs.iter().zip(&haystack).enumerate() {
        let value = batch_challenge[0] * f + batch_challenge[1] * h + lookup_challenge;
        sumcheck_haystack_rhs[i] = value
    }

    let sumcheck_data = sumcheck::batch_sumcheck(
//        transcript,
        [&inverse_haystack, &inverse_needles],
        [&sumcheck_haystack_rhs, &sumcheck_needles_rhs],
        sumcheck_batch_challenge,
    );
    let sumcheck_challenges = sumcheck_data.0;
    proof.sumcheck = sumcheck_data.1;

    proof.sumcheck_claim_haystack =
        linalg::inner_product(&inverse_haystack, &sumcheck_haystack_rhs);
    proof.sumcheck_claim_needles = linalg::inner_product(&inverse_needles, &sumcheck_needles_rhs);

    let evaluation_challenge = linalg::tensor(&sumcheck_challenges);
    proof.evaluations.inverse_haystack =
        linalg::inner_product(&inverse_haystack, &evaluation_challenge);
    proof.evaluations.inverse_needles =
        linalg::inner_product(&inverse_needles, &evaluation_challenge);
    proof.evaluations.freqs = linalg::inner_product_u8(&u8freqs, &evaluation_challenge);

    // let's go with the sigma protocol now
    let k_len = usize::max(needles.len(), haystack.len());
    let mut k = (0..k_len)
        .map(|_| G::ScalarField::rand(rng))
        .collect::<Vec<_>>();
    // put this thing back in the kernel
    k[0] = -linalg::inner_product(&k[1..], &evaluation_challenge[1..]);
    let k_gg = G::msm_unchecked(&ck, &k);
    //    transcript.absorb_serializable(&[k_gg]).unwrap();
    let mut chal = [G::ScalarField::rand(rng); 3];
    // chal[0] = transcript.squeeze_pfelt().unwrap();
    // chal[1] = transcript.squeeze_pfelt().unwrap();
    // chal[2] = transcript.squeeze_pfelt().unwrap();
    chal[0] = G::ScalarField::zero(); // squeeze
    chal[1] = G::ScalarField::zero();
    chal[2] = G::ScalarField::zero();

    let s = linalg::linear_combination(&[&k, &freqs, &inverse_haystack, &inverse_needles], &chal);
    proof.evaluations.proof = (k_gg, s);

    let mut k = (0..witness_vector.len())
//        .map(|_| G::ScalarField::rand(transcript.rng()))
        .map(|_| G::ScalarField::zero()) // squeeze
        .collect::<Vec<_>>();
    let morphism = challenge_for_witness(&evaluation_challenge, r_sbox, r_mcolpre, r_xor, r2_xor);
    k[0] = -linalg::inner_product(&k[1..], &morphism);
    let k_gg = G::msm_unchecked(&ck, &k);
    // transcript.absorb_serializable(&[k_gg]).unwrap();
    // let chal = transcript.squeeze_pfelt().unwrap();
    let chal = G::ScalarField::zero(); // squeeze
    let witness_vector_ff = witness_vector
        .iter()
        .map(|&x| G::ScalarField::from(x))
        .collect::<Vec<_>>();
    let s = linalg::linear_combination(&[&k, &witness_vector_ff], &[chal]);
    proof.evaluations.proof_needles = (k_gg, s);

    println!("{}", witness_vector_ff.len());
    proof

    // let chal = [G::ScalarField::rand(rng); 1];
    // for i in 1440 + 144..evaluation_challenge.len() {
    //     evaluation_challenge[i] = G::ScalarField::zero();
    // }
    // // evaluation_challenge[144*2+1z] = G::ScalarField::from(1);
    // let expected = linalg::inner_product(&needles, &evaluation_challenge);

    // let morphed_evaluation_challenge =
    //     challenge_for_witness(&evaluation_challenge, r_sbox, r_mcolpre, r_xor, r2_xor);
    // let got = linalg::inner_product(&witness_vector_ff, &morphed_evaluation_challenge);

    // assert_eq!(got, expected, "left: {}, right: {}", got, expected);
    // // let s = misc::linear_combination(&[&k1, &witness_vector_ff], &chal);

    // // proof.sigmas = (K, s);
    // proof
}

pub struct InvalidProof;
type ProofResult = Result<(), InvalidProof>;

pub fn verify<G>(
//    transcript: &mut Transcript,
    ck: &[G::Affine],
    k: [u8; 16],
    proof: &ProofTranscript<G>,
) -> ProofResult
where
    G: CurveGroup,
{
    // transcript.absorb_serializable(&[proof.witness]).unwrap();
    // let lookup_challenge = transcript.squeeze_pfelt::<G::ScalarField>().unwrap();
    let lookup_challenge = G::ScalarField::from(0); // squeeze
    // let r_mcolpre = transcript.squeeze_pfelt::<G::ScalarField>().unwrap();
    let r_mcolpre = G::ScalarField::from(0); // squeeze
    // let r_sbox = transcript.squeeze_pfelt::<G::ScalarField>().unwrap();
    let r_sbox = G::ScalarField::from(0); // squeeze
    // XXXXXXXXX
    // let r_xor = transcript.squeeze_pfelt::<G::ScalarField>().unwrap();
    let r_xor = G::ScalarField::from(0); // squeeze
    // let r2_xor = transcript.squeeze_pfelt::<G::ScalarField>().unwrap();
    let r2_xor = G::ScalarField::from(0); // squeeze

    // transcript
    //     .absorb_serializable(&[
    //         proof.inverse_needles_com,
    //         proof.inverse_haystack_com,
    //         proof.freqs_com,
    //     ])
    //     .unwrap();

    let mut batch_challenge = [G::ScalarField::zero(); 2];
    // batch_challenge[0] = transcript.squeeze_pfelt().unwrap();
    batch_challenge[0] = G::ScalarField::zero(); // squeeze
    // batch_challenge[1] = transcript.squeeze_pfelt().unwrap();
    batch_challenge[1] = G::ScalarField::zero(); // squeeze
    // let sumcheck_batch_challenge = transcript.squeeze_pfelt::<G::ScalarField>().unwrap();
    let sumcheck_batch_challenge = G::ScalarField::zero(); // squeeze

    let sumcheck_claim =
        proof.sumcheck_claim_haystack + sumcheck_batch_challenge * proof.sumcheck_claim_needles;
    let e = &proof.evaluations;
    let evaluation_haystack = G::ScalarField::zero();
    let evaluation_needles = G::ScalarField::zero();
    let needles_sumcheck_got = e.inverse_needles * evaluation_needles;
    let haystack_sumcheck_got = e.inverse_haystack * (evaluation_haystack + e.freqs);

    let (sumcheck_challenges, haystack_reduced) =
        sumcheck::reduce(&proof.sumcheck, proof.sumcheck_claim_haystack);

    let k_gg = proof.evaluations.proof.0;
    let s = &proof.evaluations.proof.1;
    // transcript.absorb_serializable(&[k_gg]).unwrap();
    // let c = transcript.squeeze_pfelt::<G::ScalarField>().unwrap();
    let c = G::ScalarField::zero(); // squeeze
    let s_gg = G::msm_unchecked(&ck, &s);

    // check the sigma protocol is valid
    let morphism = tensor(&sumcheck_challenges);
    let morphism_witness = challenge_for_witness(&morphism, r_sbox, r_mcolpre, r_xor, r2_xor);

    Err(InvalidProof)
}

#[test]
fn test_prove() {
    type G = ark_curve25519::EdwardsProjective;

    // let mut transcript = Transcript::from(&iopattern);

    let message = [
        0x4A, 0x8F, 0x6D, 0xE2, 0x12, 0x7B, 0xC9, 0x34, 0xA5, 0x58, 0x91, 0xFD, 0x23, 0x69, 0x0C,
        0xE7,
    ];
    let key = [
        0xE7u8, 0x4A, 0x8F, 0x6D, 0xE2, 0x12, 0x7B, 0xC9, 0x34, 0xA5, 0x58, 0x91, 0xFD, 0x23, 0x69,
        0x0C,
    ];
    let ck = pedersen::setup::<G>(&mut rand::thread_rng(), 2084);

    let proof = prove::<G>(&ck, message, &key);
    println!("size: {}", proof.compressed_size());
    println!("size: {}", proof.evaluations.compressed_size());
}
