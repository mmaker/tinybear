#![allow(non_snake_case)]
use ark_ec::CurveGroup;
use ark_ff::Field;

use transcript::IOPTranscript;

use crate::linalg::powers;
use crate::traits::{Instance, LinProof};
use crate::{linalg, lookup, registry, sigma, sumcheck};

use crate::pedersen::CommitmentKey;
use crate::traits::{ProofResult, TinybearProof};

pub fn aes_verify<G, const R: usize>(
    transcript: &mut IOPTranscript<G::ScalarField>,
    ck: &CommitmentKey<G>,
    instance: &impl Instance<G>,
    proof: &TinybearProof<G, impl LinProof<G>>,
) -> ProofResult
where
    G: CurveGroup,
{
    transcript
        .append_serializable_element(b"witness_com", &[proof.W])
        .unwrap();

    let c_lup_batch = transcript.get_and_append_challenge(b"r_rj2").unwrap();
    let [_, c_xor, c_xor2, c_sbox, c_rj2] = linalg::powers(c_lup_batch, 5).try_into().unwrap();

    transcript
        .append_serializable_element(b"m", &[proof.M])
        .unwrap();

    let c_lup = transcript.get_and_append_challenge(b"c").unwrap();

    transcript
        .append_serializable_element(b"Q", &[proof.Q])
        .unwrap();
    transcript
        .append_serializable_element(b"Y", &[proof.Y])
        .unwrap();

    // Compute h and t
    let needles_len = registry::aes_offsets::<R>().needles_len;
    let (_t_vec, h_vec) = lookup::compute_haystack([c_xor, c_xor2, c_sbox, c_rj2], c_lup);

    // Sumcheck
    let ipa_twist = transcript.get_and_append_challenge(b"twist").unwrap();
    let ipa_sumcheck_claim = (ipa_twist.pow([needles_len as u64]) - G::ScalarField::from(1))
        * (ipa_twist - G::ScalarField::from(1)).inverse().unwrap();
    let ipa_sumcheck_claim = ck.G * ipa_sumcheck_claim;

    let (ipa_cs, ipa_claim_fold) =
        sumcheck::reduce::<G>(transcript, &proof.ipa_sumcheck, ipa_sumcheck_claim);
    transcript
        .append_serializable_element(b"ipa_Q_fold", &[proof.ipa_Q_fold])
        .unwrap();
    transcript
        .append_serializable_element(b"ipa_F_twisted_fold", &[proof.ipa_F_twist_fold])
        .unwrap();

    sigma::mul_verify(
        transcript,
        ck,
        proof.ipa_F_twist_fold,
        proof.ipa_Q_fold,
        ipa_claim_fold,
        &proof.mul_proof,
    )?;

    let ipa_cs_vec = linalg::tensor(&ipa_cs);
    // XXXXXXX very weird potential security bug.
    // using the line below leads to failed proof verification.
    // let twist_vec = powers(twist, helper::NEEDLES_LEN+1);
    let twist_vec = powers(ipa_twist, needles_len);
    let ipa_twist_cs_vec = linalg::hadamard(&ipa_cs_vec, &twist_vec);
    let (s_vec, s_const) =
        instance.trace_to_needles_map(&ipa_twist_cs_vec, [c_xor, c_xor2, c_sbox, c_rj2]);

    let ipa_cs_vec = linalg::tensor(&ipa_cs);
    let c_q = transcript.get_and_append_challenge(b"bc").unwrap();
    let ipa_cs_c_q_vec = linalg::add_constant(&ipa_cs_vec, c_q);

    let off = s_const + c_lup * ipa_twist_cs_vec.iter().sum::<G::ScalarField>();
    let Y = proof.ipa_F_twist_fold - ck.G * off;

    let c_lin_batch = transcript.get_and_append_challenge(b"sumcheck2").unwrap();
    let c_lin_batch2 = c_lin_batch.square();

    let lin_claim = proof.Y + (proof.ipa_Q_fold + proof.Y * c_q) * c_lin_batch + Y * c_lin_batch2;
    let (lin_sumcheck_chals, reduced_claim) =
        sumcheck::reduce(transcript, &proof.lin_sumcheck, lin_claim);
    let lin_sumcheck_chals_vec = linalg::tensor(&lin_sumcheck_chals);
    let lin_h_fold = linalg::inner_product(&lin_sumcheck_chals_vec, &h_vec);
    let lin_ipa_cs_c_q_fold = linalg::inner_product(&lin_sumcheck_chals_vec, &ipa_cs_c_q_vec);
    let lin_s_fold = linalg::inner_product(&lin_sumcheck_chals_vec, &s_vec);
    let Z = instance.full_witness_com(&proof.W);
    let lin_Z_fold = (reduced_claim
        - proof.lin_M_fold * lin_h_fold
        - proof.lin_Q_fold * lin_ipa_cs_c_q_fold * c_lin_batch)
        * (lin_s_fold * c_lin_batch2).inverse().unwrap();

    debug_assert_eq!(
        reduced_claim,
        proof.lin_M_fold * lin_h_fold
            + proof.lin_Q_fold * lin_ipa_cs_c_q_fold * c_lin_batch
            + lin_Z_fold * lin_s_fold * c_lin_batch2
    );

    let c_batch_eval = transcript.get_and_append_challenge(b"final").unwrap();
    let c_batch_eval2 = c_batch_eval.square();
    let E = proof.M + proof.Q * c_batch_eval + Z * c_batch_eval2;
    let P = proof.lin_M_fold + proof.lin_Q_fold * c_batch_eval + lin_Z_fold * c_batch_eval2;
    proof
        .lin_proof
        .verify(transcript, ck, &lin_sumcheck_chals_vec, &E, &P)?;

    Ok(())
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
    fn trace_to_needles_map(
        &self,
        _src: &[<G>::ScalarField],
        _r: [<G>::ScalarField; 4],
    ) -> (Vec<<G>::ScalarField>, <G>::ScalarField) {
        todo!()
    }

    fn full_witness_com(&self, w_com: &G) -> G {
        self.round_keys_com + w_com
    }
}

impl<G: CurveGroup, const R: usize, const N: usize> Instance<G> for AesCipherInstance<G, R, N> {
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
