//! See Figure 8 in the paper to learn how this protocol works
#![allow(non_snake_case)]

// use std::slice::range;

use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField};

use nimue::plugins::ark::*;
use nimue::ProofResult;

use super::{linalg, lookup, pedersen, sigma, sumcheck};
use crate::pedersen::CommitmentKey;
use crate::traits::{LinProof, Witness};

pub fn aes_prove<'a, G: CurveGroup, LP: LinProof<G>, const R: usize>(
    merlin: &'a mut Merlin,
    ck: &CommitmentKey<G>,
    witness: &impl Witness<G::ScalarField>,
) -> ProofResult<&'a [u8]>
where
    G::ScalarField: PrimeField,
{
    // Commit to the AES trace.
    // TIME: ~3-4ms [outdated]
    let w_vec = witness.witness_vec();
    let (W, W_opening) = pedersen::commit_hiding_u8(merlin.rng(), ck, w_vec);
    // Send W
    merlin.add_points(&[W]).unwrap();

    // Lookup
    // Get challenges for the lookup protocol.
    // one for sbox + mxcolhelp, sbox, two for xor
    let [c_lup_batch] = merlin.challenge_scalars().unwrap();
    let [_, c_xor, c_xor2, c_sbox, c_rj2]: [G::ScalarField; 5] =
        linalg::powers(c_lup_batch, 5).try_into().unwrap();

    // Compute needles and frequencies
    let (f_vec, m_vec, m_u64) =
        witness.compute_needles_and_frequencies([c_xor, c_xor2, c_sbox, c_rj2]);
    debug_assert_eq!(f_vec.len(), witness.needles_len());
    // Commit to m (using mu as the blinder) and send it over
    let (M, M_opening) = pedersen::commit_hiding_u64(merlin.rng(), ck, m_u64.as_slice());
    // Send M
    merlin.add_points(&[M]).unwrap();

    // Get the lookup challenge c and compute q and y
    let [c_lup] = merlin.challenge_scalars().unwrap();
    // Compute vector inverse_needles[i] = 1 / (needles[i] + a) = q
    let mut q_vec = linalg::add_constant(&f_vec, c_lup);
    ark_ff::batch_inversion(&mut q_vec);
    // Q = Com(q)
    let (Q, Q_opening) = pedersen::commit_hiding(merlin.rng(), ck, &q_vec);
    // y = <g,1>
    let y = q_vec.iter().sum();
    let (Y, Y_opening) = pedersen::commit_hiding(merlin.rng(), ck, &[y]);
    // Finally compute h and t
    let (t_vec, h_vec) = lookup::compute_haystack([c_xor, c_xor2, c_sbox, c_rj2], c_lup);
    // there are as many frequencies as elements in the haystack
    debug_assert_eq!(h_vec.len(), m_u64.len());
    // all needles are in the haystack
    debug_assert!(f_vec.iter().all(|x| t_vec.contains(x)));
    // Send (Q,Y)
    merlin.add_points(&[Q, Y]).unwrap();

    // Sumcheck for inner product
    // reduce <f . twist_vec ,q> = Y into:
    // 1.  <f, twist_vec . ipa_tensor> = F_fold
    // 2.  <q, ipa_tensor> = Q_fold
    let [c_ipa_twist] = merlin.challenge_scalars().unwrap();
    let c_ipa_twist_vec = linalg::powers(c_ipa_twist, f_vec.len());
    let f_twist_vec = {
        let tmp = linalg::add_constant(&f_vec, c_lup);
        linalg::hadamard(&tmp, &c_ipa_twist_vec)
    };
    // check that the inner-product relation is indeed correct.
    debug_assert_eq!(
        linalg::inner_product(&f_twist_vec, &q_vec),
        c_ipa_twist_vec.iter().sum::<G::ScalarField>()
    );
    let (cs_ipa, ipa_sumcheck_openings, (f_twist_fold, ipa_q_fold)) =
        sumcheck::sumcheck(merlin, ck, &f_twist_vec, &q_vec);
    // Commit to the final folded claims
    let (ipa_F_twist_fold, ipa_F_twist_fold_opening) =
        pedersen::commit_hiding(merlin.rng(), ck, &[f_twist_fold]);
    let (ipa_Q_fold, ipa_Q_fold_opening) = pedersen::commit_hiding(merlin.rng(), ck, &[ipa_q_fold]);
    merlin.add_points(&[ipa_Q_fold, ipa_F_twist_fold]).unwrap();

    // Prove that the folded sumcheck claims are consistent
    let ipa_sumcheck_opening =
        sumcheck::reduce_with_challenges(&ipa_sumcheck_openings, &cs_ipa, G::ScalarField::from(0));
    sigma::mul_prove(
        merlin,
        ck,
        f_twist_fold,
        ipa_Q_fold,
        ipa_F_twist_fold_opening,
        ipa_Q_fold_opening,
        ipa_sumcheck_opening,
    )
    .unwrap();

    // Sumcheck for linear evaluation
    let cs_ipa_vec = linalg::tensor(&cs_ipa);
    let ipa_twist_cs_vec = linalg::hadamard(&cs_ipa_vec, &c_ipa_twist_vec);
    let (s_vec, s_const) =
        witness.trace_to_needles_map(&ipa_twist_cs_vec, [c_xor, c_xor2, c_sbox, c_rj2]);
    let z_vec = witness.full_witness();
    let [c_q] = merlin.challenge_scalars().unwrap();

    let cs_ipa_c_q_vec = linalg::add_constant(&cs_ipa_vec, c_q);
    debug_assert_eq!(
        linalg::inner_product(&cs_ipa_c_q_vec, &q_vec),
        ipa_q_fold + c_q * y
    );
    let z_twisted_fold =
        f_twist_fold - c_lup * ipa_twist_cs_vec.iter().sum::<G::ScalarField>() - s_const;

    let [c_lin_batch]: [G::ScalarField; 1] = merlin.challenge_scalars().unwrap();
    let c_lin_batch_vec = [c_lin_batch, c_lin_batch.square()];
    let mut lin_claims = [
        sumcheck::Claim::new(&m_vec, &h_vec),
        // <q_vec, ipa_cs_vec + c_q * 1> = q_fold + c_q * y
        sumcheck::Claim::new(&q_vec, &cs_ipa_c_q_vec),
        // <z_vec, s_vec> = z_twisted_fold
        sumcheck::Claim::new(&z_vec, &s_vec),
    ];
    debug_assert_eq!(linalg::inner_product(&m_vec, &h_vec), y);
    debug_assert_eq!(linalg::inner_product(&q_vec, &cs_ipa_vec), ipa_q_fold);
    debug_assert_eq!(linalg::inner_product(&z_vec, &s_vec), z_twisted_fold);
    debug_assert_eq!(q_vec.iter().sum::<G::ScalarField>(), y);
    debug_assert_eq!(
        y + (ipa_q_fold + c_q * y) * c_lin_batch_vec[0] + z_twisted_fold * c_lin_batch_vec[1],
        {
            let ip_m = linalg::inner_product(&m_vec, &h_vec);
            let ip_q = linalg::inner_product(&q_vec, &cs_ipa_vec);
            let ip_z = linalg::inner_product(&z_vec, &s_vec);
            let ip_q2 = q_vec.iter().sum::<G::ScalarField>();
            ip_m + (ip_q + c_q * ip_q2) * c_lin_batch_vec[0] + ip_z * c_lin_batch_vec[1]
        }
    );

    // construct the folded instances to be sent
    // invoke batch sumcheck
    let (cs_lin, lin_openings) =
        sumcheck::batch_sumcheck(merlin, ck, &mut lin_claims, &c_lin_batch_vec);
    // construct the folded instances to be sent
    debug_assert_eq!(lin_claims[0].0.len(), 1);
    debug_assert_eq!(lin_claims[1].0.len(), 1);
    debug_assert_eq!(lin_claims[2].0.len(), 1);
    let (lin_m_fold, lin_h_fold) = (lin_claims[0].0[0], lin_claims[0].1[0]);
    let (lin_q_fold, lin_ipa_cs_c_q_fold) = (lin_claims[1].0[0], lin_claims[1].1[0]);
    let (lin_z_fold, lin_s_fold) = (lin_claims[2].0[0], lin_claims[2].1[0]);

    // commit to the final claims
    let (_lin_Z_fold, lin_Z_fold_opening) =
        pedersen::commit_hiding(merlin.rng(), ck, &[lin_z_fold]);
    let (lin_Q_fold, lin_Q_fold_opening) = pedersen::commit_hiding(merlin.rng(), ck, &[lin_q_fold]);
    let lin_opening_claim = Y_opening
        + (ipa_Q_fold_opening + c_q * Y_opening) * c_lin_batch_vec[0]
        + ipa_F_twist_fold_opening * c_lin_batch_vec[1];
    let lin_sumcheck_opening =
        sumcheck::reduce_with_challenges(&lin_openings, &cs_lin, lin_opening_claim);
    let lin_M_fold_opening = lin_h_fold.inverse().unwrap()
        * (lin_sumcheck_opening
            - lin_ipa_cs_c_q_fold * lin_Q_fold_opening * c_lin_batch_vec[0]
            - lin_s_fold * lin_Z_fold_opening * c_lin_batch_vec[1]);
    let lin_M_fold = ck.G * lin_m_fold + ck.H * lin_M_fold_opening;
    merlin.add_points(&[lin_M_fold, lin_Q_fold]).unwrap();

    debug_assert_eq!(
        lin_sumcheck_opening,
        lin_M_fold_opening * lin_h_fold
            + lin_Q_fold_opening * lin_ipa_cs_c_q_fold * c_lin_batch_vec[0]
            + lin_Z_fold_opening * lin_s_fold * c_lin_batch_vec[1]
    );

    let Z_opening = W_opening + witness.full_witness_opening();
    let lin_sumcheck_chals_vec = linalg::tensor(&cs_lin);
    let [c_batch_eval]: [G::ScalarField; 1] = merlin.challenge_scalars().unwrap();
    let c_batch_eval2 = c_batch_eval.square();

    let c_batch_eval_vec = [c_batch_eval, c_batch_eval2];
    let e_vec = linalg::linear_combination(&[&m_vec, &q_vec, &z_vec], &c_batch_eval_vec);
    debug_assert_eq!(
        linalg::inner_product(&m_vec, &lin_sumcheck_chals_vec),
        lin_m_fold
    );
    debug_assert_eq!(
        linalg::inner_product(&q_vec, &lin_sumcheck_chals_vec),
        lin_q_fold
    );
    debug_assert_eq!(
        linalg::inner_product(&z_vec, &lin_sumcheck_chals_vec),
        lin_z_fold
    );

    let e_opening = M_opening + c_batch_eval_vec[0] * Q_opening + c_batch_eval_vec[1] * Z_opening;

    let a_vec = &lin_sumcheck_chals_vec[..e_vec.len()];
    LP::new(
        merlin,
        ck,
        &e_vec,
        &e_opening,
        &(lin_M_fold_opening
            + c_batch_eval_vec[0] * lin_Q_fold_opening
            + c_batch_eval_vec[1] * lin_Z_fold_opening),
        a_vec,
    )
    .unwrap();

    // println!("Proof size, {}", arthur.transcript().len());

    Ok(merlin.transcript())
}

#[test]
fn test_prove() {
    use crate::TinybearIO;
    use ark_ff::Zero;
    use nimue::IOPattern;

    type G = ark_curve25519::EdwardsProjective;
    type F = ark_curve25519::Fr;

    let iop = IOPattern::new("test_prove");
    let iop = TinybearIO::<G>::add_aes128_proof(iop);
    let mut merlin = iop.to_merlin();

    let message = [
        0x4A, 0x8F, 0x6D, 0xE2, 0x12, 0x7B, 0xC9, 0x34, 0xA5, 0x58, 0x91, 0xFD, 0x23, 0x69, 0x0C,
        0xE7,
    ];
    let key = [
        0xE7u8, 0x4A, 0x8F, 0x6D, 0xE2, 0x12, 0x7B, 0xC9, 0x34, 0xA5, 0x58, 0x91, 0xFD, 0x23, 0x69,
        0x0C,
    ];
    let ck = pedersen::setup::<G>(merlin.rng(), 2084);

    let proof = crate::aes128_prove::<G>(&mut merlin, &ck, message, F::zero(), &key, F::zero());
    println!("size: {}", proof.unwrap().len());
}
