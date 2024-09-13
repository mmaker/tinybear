#![allow(non_snake_case)]

use ark_ec::CurveGroup;
use ark_ff::Field;
use nimue::plugins::ark::{FieldChallenges, GroupReader};
use nimue::{Arthur, ProofResult};

use crate::linalg::powers;
use crate::pedersen::CommitmentKey;
use crate::traits::{Instance, LinProof};
use crate::{constrain, linalg, lookup, registry, sigma, sumcheck};

pub fn aes_verify<G, LP: LinProof<G>, const R: usize>(
    arthur: &mut Arthur,
    ck: &CommitmentKey<G>,
    instance: &impl Instance<G>,
) -> ProofResult<()>
where
    G: CurveGroup,
    for<'a> Arthur<'a>: GroupReader<G> + FieldChallenges<G::ScalarField>,
{
    let [W] = arthur.next_points().unwrap();
    let [c_lup_batch] = arthur.challenge_scalars().unwrap();
    let [_, c_xor, c_xor2, c_sbox, c_rj2] = linalg::powers(c_lup_batch, 5).try_into().unwrap();
    let [M] = arthur.next_points().unwrap();
    let [c_lup] = arthur.challenge_scalars().unwrap();
    let [Q, Y] = arthur.next_points().unwrap();

    // Compute h and t
    let needles_len = instance.needles_len();
    let (_t_vec, h_vec) = lookup::compute_haystack([c_xor, c_xor2, c_sbox, c_rj2], c_lup);

    // Sumcheck
    let [c_ipa_twist]: [G::ScalarField; 1] = arthur.challenge_scalars().unwrap();
    let ipa_sumcheck_claim = (c_ipa_twist.pow([needles_len as u64]) - G::ScalarField::from(1))
        * (c_ipa_twist - G::ScalarField::from(1)).inverse().unwrap();
    let ipa_sumcheck_claim = ck.G * ipa_sumcheck_claim;

    let (ipa_cs, ipa_claim_fold) = sumcheck::reduce::<G>(arthur, needles_len, ipa_sumcheck_claim);
    let [ipa_Q_fold, ipa_F_twist_fold]: [G; 2] = arthur.next_points().unwrap();

    sigma::mul_verify(arthur, ck, ipa_F_twist_fold, ipa_Q_fold, ipa_claim_fold).unwrap();

    let ipa_cs_vec = linalg::tensor(&ipa_cs);
    let twist_vec = powers(c_ipa_twist, needles_len);
    let ipa_twist_cs_vec = linalg::hadamard(&ipa_cs_vec, &twist_vec);
    let (s_vec, s_const) =
        instance.trace_to_needles_map(&ipa_twist_cs_vec, [c_xor, c_xor2, c_sbox, c_rj2]);

    let ipa_cs_vec = linalg::tensor(&ipa_cs);
    let [c_q] = arthur.challenge_scalars().unwrap();
    let ipa_cs_c_q_vec = linalg::add_constant(&ipa_cs_vec, c_q);

    let off = s_const + c_lup * ipa_twist_cs_vec.iter().sum::<G::ScalarField>();

    let [c_lin_batch]: [G::ScalarField; 1] = arthur.challenge_scalars().unwrap();
    let c_lin_batch2 = c_lin_batch.square();

    let lin_claim =
        Y + (ipa_Q_fold + Y * c_q) * c_lin_batch + (ipa_F_twist_fold - ck.G * off) * c_lin_batch2;
    let n = instance.witness_len() * 2;

    let (lin_sumcheck_chals, reduced_claim) = sumcheck::reduce(arthur, n, lin_claim);

    let lin_sumcheck_chals_vec = &linalg::tensor(&lin_sumcheck_chals)[..n];
    let lin_h_fold = linalg::inner_product(&lin_sumcheck_chals_vec, &h_vec);
    let lin_ipa_cs_c_q_fold = linalg::inner_product(&lin_sumcheck_chals_vec, &ipa_cs_c_q_vec);
    let lin_s_fold = linalg::inner_product(&lin_sumcheck_chals_vec, &s_vec);
    let Z = instance.full_witness_com(&W);
    let [lin_M_fold, lin_Q_fold]: [G; 2] = arthur.next_points().unwrap();
    let lin_Z_fold =
        (reduced_claim - lin_M_fold * lin_h_fold - lin_Q_fold * lin_ipa_cs_c_q_fold * c_lin_batch)
            * (lin_s_fold * c_lin_batch2).inverse().unwrap();

    debug_assert_eq!(
        reduced_claim,
        lin_M_fold * lin_h_fold
            + lin_Q_fold * lin_ipa_cs_c_q_fold * c_lin_batch
            + lin_Z_fold * lin_s_fold * c_lin_batch2
    );

    let [c_batch_eval]: [G::ScalarField; 1] = arthur.challenge_scalars().unwrap();
    let c_batch_eval2 = c_batch_eval.square();

    let E = M + Q * c_batch_eval + Z * c_batch_eval2;
    let P = lin_M_fold + lin_Q_fold * c_batch_eval + lin_Z_fold * c_batch_eval2;
    LP::verify(arthur, ck, lin_sumcheck_chals_vec, &E, &P)
}

pub struct AesCipherInstance<G: CurveGroup, const R: usize, const N: usize> {
    pub message_com: G,
    pub round_keys_com: G,
    pub ctx: [u8; 16],
}

pub struct AeskeySchInstance<G: CurveGroup, const R: usize, const N: usize> {
    pub round_keys_com: G,
}

impl<G: CurveGroup, const R: usize, const N: usize> AesCipherInstance<G, R, N> {
    pub fn new(&message_com: &G, &round_keys_com: &G, ctx: [u8; 16]) -> Self {
        Self {
            message_com,
            round_keys_com,
            ctx,
        }
    }
}

impl<G: CurveGroup, const R: usize, const N: usize> AeskeySchInstance<G, R, N> {
    pub fn new(&round_keys_com: &G) -> Self {
        Self { round_keys_com }
    }
}

impl<G: CurveGroup, const R: usize, const N: usize> Instance<G> for AeskeySchInstance<G, R, N> {
    fn needles_len(&self) -> usize {
        registry::aes_keysch_offsets::<R, N>().needles_len
    }

    fn witness_len(&self) -> usize {
        registry::aes_keysch_offsets::<R, N>().witness_len
    }

    fn trace_to_needles_map(
        &self,
        src: &[G::ScalarField],
        r: [G::ScalarField; 4],
    ) -> (Vec<G::ScalarField>, G::ScalarField) {
        constrain::aes_keysch_trace_to_needles::<G::ScalarField, R, N>(src, r)
    }

    fn full_witness_com(&self, &w_com: &G) -> G {
        w_com + self.round_keys_com
    }
}

impl<G: CurveGroup, const R: usize, const N: usize> Instance<G> for AesCipherInstance<G, R, N> {
    fn needles_len(&self) -> usize {
        registry::aes_offsets::<R>().needles_len
    }

    fn witness_len(&self) -> usize {
        registry::aes_offsets::<R>().witness_len
    }

    fn trace_to_needles_map(
        &self,
        src: &[<G>::ScalarField],
        r: [<G>::ScalarField; 4],
    ) -> (Vec<<G>::ScalarField>, <G>::ScalarField) {
        crate::constrain::aes_trace_to_needles::<_, R>(&self.ctx, src, r)
    }

    fn full_witness_com(&self, w_com: &G) -> G {
        self.message_com + self.round_keys_com + w_com
    }
}
