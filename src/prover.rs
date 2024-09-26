//! See Figure 8 in the paper to learn how this protocol works
#![allow(non_snake_case)]

use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField};

use nimue::plugins::ark::*;
use nimue::ProofResult;

use super::{aes, constrain, linalg, lookup, pedersen, sigma, sumcheck};
use crate::aes::{AesCipherTrace, AesKeySchTrace};
use crate::pedersen::CommitmentKey;
use crate::registry::{aes_keysch_offsets, aes_offsets};
use crate::traits::{LinProof, Witness};

pub struct AesCipherWitness<F: Field, const R: usize, const N: usize> {
    trace: AesCipherTrace,
    witness_vec: Vec<u8>,
    message: [u8; 16],
    round_keys: [[u8; 16]; R],
    message_opening: F,
    key_opening: F,
}

pub struct AesKeySchWitness<F: Field, const R: usize, const N: usize> {
    trace: AesKeySchTrace<R, N>,
    witness_vec: Vec<u8>,
    round_keys_opening: F,
}

impl<F: Field, const R: usize, const N: usize> AesKeySchWitness<F, R, N> {
    pub fn new(key: &[u8], &round_keys_opening: &F) -> Self {
        let trace = AesKeySchTrace::<R, N>::new(key);
        let witness_vec = Self::vectorize_keysch(&trace);
        Self {
            trace,
            witness_vec,
            round_keys_opening,
        }
    }

    fn get_s_box_witness(&self) -> Vec<(u8, u8)> {
        let mut witness_s_box = Vec::new();
        let n_4 = N / 4;

        for i in n_4..R {
            let a = if N > 6 && (i * 4) % N == 4 {
                self.trace.round_keys[i - 1][3]
            } else {
                let mut a = self.trace.round_keys[i - 1][3];
                a.rotate_left(1);
                a
            };
            for (x, y) in a.into_iter().zip(self.trace.s_box[i]) {
                witness_s_box.push((x, y))
            }
        }
        witness_s_box
    }

    fn get_xor_witness(&self) -> Vec<(u8, u8, u8)> {
        let n_4 = N / 4;
        let mut witness_xor = Vec::new();

        for i in n_4..R {
            let xs = self.trace.round_keys[i - n_4][1..4]
                .iter()
                .flatten()
                .copied();
            let ys = self.trace.round_keys[i][0..3].iter().flatten().copied();
            let zs = self.trace.round_keys[i][1..4].iter().flatten().copied();

            let new_witness = xs.zip(ys).zip(zs).map(|((x, y), z)| (x, y, z));
            witness_xor.extend(new_witness)
        }

        for i in n_4..R {
            let xs = self.trace.round_keys[i - n_4][0].iter().copied();
            let ys = self.trace.xor[i].iter().copied();
            let zs = self.trace.round_keys[i][0].iter().copied();
            let new_witness = xs.zip(ys).zip(zs).map(|((x, y), z)| (x, y, z));
            witness_xor.extend(new_witness)
        }

        witness_xor
    }

    pub fn vectorize_keysch(witness: &aes::AesKeySchTrace<R, N>) -> Vec<u8> {
        let mut w = Vec::<u8>::new();
        let registry = aes_keysch_offsets::<R, N>();

        assert_eq!(registry.s_box, w.len());
        w.extend(witness.s_box.iter().flatten());
        assert_eq!(registry.xor, w.len());
        w.extend(witness.xor.iter().flatten());
        // assert_eq!(registry.round_keys, w.len());
        // w.extend(witness.round_keys.iter().flatten().flatten());
        // split the witness and low and high 4-bits.
        w.iter().flat_map(|x| [x & 0xf, x >> 4]).collect()
    }
}

impl<F: Field, const R: usize, const N: usize> Witness<F> for AesKeySchWitness<F, R, N> {
    fn witness_vec(&self) -> &[u8] {
        self.witness_vec.as_slice()
    }

    fn needles_len(&self) -> usize {
        aes_keysch_offsets::<R, N>().needles_len
    }

    fn compute_needles_and_frequencies(
        &self,
        [c_xor, c_xor2, c_sbox, _c_rj2]: [F; 4],
    ) -> (Vec<F>, Vec<F>, Vec<u8>) {
        let witness_s_box = self.get_s_box_witness();

        let witness_xor = self.get_xor_witness();
        let s_box_needles = lookup::compute_u8_needles(&witness_s_box, c_sbox);
        let xor_needles = lookup::compute_u16_needles(&witness_xor, [c_xor, c_xor2]);
        let needles = [s_box_needles, xor_needles].concat();

        let mut freq_u8 = vec![0u8; 256 * 3];
        lookup::count_u16_frequencies(&mut freq_u8[0..256], &witness_xor);
        lookup::count_u8_frequencies(&mut freq_u8[256..512], &witness_s_box);

        let freq = freq_u8.iter().map(|x| F::from(*x)).collect::<Vec<_>>();
        (needles, freq, freq_u8)
    }

    fn trace_to_needles_map(&self, src: &[F], r: [F; 4]) -> (Vec<F>, F) {
        constrain::aes_keysch_trace_to_needles::<F, R, N>(src, r)
    }

    fn full_witness(&self) -> Vec<F> {
        let round_keys = self
            .trace
            .round_keys
            .iter()
            .flatten()
            .flatten()
            .flat_map(|x| [x & 0xf, x >> 4]);
        self.witness_vec
            .iter()
            .copied()
            .chain(round_keys)
            .map(|x| F::from(x))
            .collect()
    }

    fn full_witness_opening(&self) -> F {
        self.round_keys_opening
    }
}

#[test]
fn test_linear_ks() {
    use crate::linalg::inner_product;
    use ark_curve25519::Fr as F;
    use ark_std::UniformRand;

    let rng = &mut ark_std::test_rng();
    let registry = aes_keysch_offsets::<11, 4>();
    let key = [
        0xE7u8, 0x4A, 0x8F, 0x6D, 0xE2, 0x12, 0x7B, 0xC9, 0x34, 0xA5, 0x58, 0x91, 0xFD, 0x23, 0x69,
        0x0C,
    ];
    let opening = F::from(1u8);
    let r = [F::rand(rng), F::rand(rng), F::rand(rng), F::rand(rng)];
    let ks = AesKeySchWitness::<F, 11, 4>::new(&key, &opening);
    let z = ks.full_witness();
    let v = (0..registry.needles_len)
        .map(|_| F::rand(rng))
        .collect::<Vec<_>>();

    let (Az, _f, _f8) = ks.compute_needles_and_frequencies(r);
    assert_eq!(Az.len(), registry.needles_len);
    // 180 constraints

    let (Av, _constant_term) = ks.trace_to_needles_map(&v, r);
    assert_eq!(inner_product(&Az, &v), inner_product(&Av, &z));
}

impl<F: Field, const R: usize, const N: usize> AesCipherWitness<F, R, N> {
    pub fn new(message: [u8; 16], key: &[u8], message_opening: F, key_opening: F) -> Self {
        assert_eq!(key.len(), N * 4);
        let round_keys = aes::keyschedule::<R, N>(key);
        let trace = aes::aes_trace(message, &round_keys);
        let witness_vec = Self::vectorize_witness(&trace);
        Self {
            trace,
            witness_vec,
            message,
            round_keys,
            message_opening,
            key_opening,
        }
    }

    /// Transforms an AES witness into a flattened vector representation.
    ///
    /// This function takes an AES witness, which captures the execution trace of AES encryption, and
    /// turns it into a continuous vector.
    /// Each 8-bit byte from the witness is split into two 4-bit parts to simplify
    /// the lookup operations.
    pub(crate) fn vectorize_witness(witness: &aes::AesCipherTrace) -> Vec<u8> {
        let mut w = Vec::<u8>::new();
        let registry = crate::registry::aes_offsets::<R>();

        assert_eq!(registry.start, w.len());
        w.extend(&witness.start);
        assert_eq!(registry.s_box, w.len());
        w.extend(&witness.s_box);
        for i in 0..5 {
            assert_eq!(registry.m_col[i], w.len());
            w.extend(&witness.m_col[i]);
        }
        // split the witness and low and high 4-bits.
        w.iter().flat_map(|x| [x & 0xf, x >> 4]).collect()
    }

    fn get_xor_witness(&self) -> Vec<(u8, u8, u8)> {
        let mut witness_xor = Vec::new();
        // m_col_xor
        for i in 0..4 {
            let xs = self.trace.m_col[i].iter().copied();
            let ys = self.trace._aux_m_col[i].iter().copied();
            let zs = self.trace.m_col[i + 1].iter().copied();
            let new_witness = xs.zip(ys).zip(zs).map(|((x, y), z)| (x, y, z));
            witness_xor.extend(new_witness)
        }
        // round key xor
        {
            let xs = self.trace.m_col[4].iter().copied();
            let zs = self.trace.start.iter().skip(16).copied();
            let ys = self.trace._keys.iter().flatten().skip(16).copied();
            // ys are the round keys
            let new_witness = xs.zip(ys).zip(zs).map(|((x, y), z)| (x, y, z));
            witness_xor.extend(new_witness)
        }
        // last round
        {
            let xs = self
                .trace
                .s_box
                .iter()
                .skip(self.trace.s_box.len() - 16)
                .copied();
            let ys = self.trace._keys.last().into_iter().flatten().copied();
            let zs = self.trace.output.iter().copied();
            let new_witness = xs.zip(ys).zip(zs).map(|((x, y), z)| (x, y, z));
            witness_xor.extend(new_witness);
        }
        // first round xor
        {
            let xs = self.trace.message.iter().copied();
            // let ys = witness._keys.iter().take(16).flatten().copied();
            let zs = self.trace.start.iter().take(16).copied();
            // ys is the 0th round key
            let new_witness = xs.zip(zs).map(|(x, z)| (x, x ^ z, z));
            witness_xor.extend(new_witness);
        }

        witness_xor
    }

    fn get_s_box_witness(&self) -> Vec<(u8, u8)> {
        let s_box = self.trace._s_row.iter().zip(&self.trace.s_box);
        // let k_sch_s_box = witness._k_rot.iter().zip(&witness.k_sch_s_box);
        s_box.map(|(&x, &y)| (x, y)).collect()
    }

    fn get_r2j_witness(&self) -> Vec<(u8, u8)> {
        let xs = self.trace.s_box.iter().copied();
        let ys = self.trace.m_col[0].iter().copied();
        xs.zip(ys).collect()
    }
}

impl<F: Field, const R: usize, const N: usize> Witness<F> for AesCipherWitness<F, R, N> {
    fn witness_vec(&self) -> &[u8] {
        self.witness_vec.as_slice()
    }

    fn needles_len(&self) -> usize {
        aes_offsets::<R>().needles_len
    }

    fn full_witness_opening(&self) -> F {
        self.message_opening + self.key_opening
    }

    fn compute_needles_and_frequencies(
        &self,
        [c_xor, c_xor2, c_sbox, c_rj2]: [F; 4],
    ) -> (Vec<F>, Vec<F>, Vec<u8>) {
        // Generate the witness.
        // witness_s_box = [(a, sbox(a)), (b, sbox(b)), ...]
        let witness_s_box = self.get_s_box_witness();
        // witness_r2j = [(a, r2j(a)), (b, r2j(b)), ...]
        let witness_r2j = self.get_r2j_witness();
        // witness_xor = [(a, b, xor(a, b)), (c, d, xor(c, d)), ...] for 4-bits
        let witness_xor = self.get_xor_witness();

        // Needles: these are the elements that want to be found in the haystack.
        // s_box_needles = [x_1 + r * sbox[x_1], x_2 + r * sbox[x_2], ...]
        let s_box_needles = lookup::compute_u8_needles(&witness_s_box, c_sbox);
        // r2j_needles = [x_1 + r2 * r2j[x_1], x_2 + r2 * r2j[x_2], ...]
        let r2j_needles = lookup::compute_u8_needles(&witness_r2j, c_rj2);
        // xor_needles = [x_1 + r * x_2 + r2 * xor[x_1 || x_2] , ...]
        let xor_needles = lookup::compute_u16_needles(&witness_xor, [c_xor, c_xor2]);
        // concatenate all needles
        let needles = [s_box_needles, r2j_needles, xor_needles].concat();

        // Frequencies: these count how many times each element will appear in the haystack.
        // To do so, we build the frequency vectors.
        // Frequencies are organized in this way
        // | 4-bit xor | sbox | r2j |
        // |  256      | 256  | 256 |
        // First, group witness by lookup table.
        let mut freq_u8 = vec![0u8; 256 * 3];
        lookup::count_u16_frequencies(&mut freq_u8[0..256], &witness_xor);
        lookup::count_u8_frequencies(&mut freq_u8[256..512], &witness_s_box);
        lookup::count_u8_frequencies(&mut freq_u8[512..768], &witness_r2j);

        let freq = freq_u8.iter().map(|x| F::from(*x)).collect::<Vec<_>>();
        (needles, freq, freq_u8)
    }

    fn trace_to_needles_map(&self, src: &[F], r: [F; 4]) -> (Vec<F>, F) {
        let output = &self.trace.output;
        crate::constrain::aes_trace_to_needles::<F, R>(output, src, r)
    }

    fn full_witness(&self) -> Vec<F> {
        let m = self.message.iter().flat_map(|x| [x & 0xf, x >> 4]);
        let rk = self
            .round_keys
            .iter()
            .flatten()
            .flat_map(|x| [x & 0xf, x >> 4]);
        self.witness_vec
            .iter()
            .copied()
            .chain(m)
            .chain(rk)
            .map(F::from)
            .collect()
    }
}

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
    let (f_vec, m_vec, m_u8) =
        witness.compute_needles_and_frequencies([c_xor, c_xor2, c_sbox, c_rj2]);
    debug_assert_eq!(f_vec.len(), witness.needles_len());
    // Commit to m (using mu as the blinder) and send it over
    let (M, M_opening) = pedersen::commit_hiding_u8(merlin.rng(), ck, &m_u8);
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
    debug_assert_eq!(h_vec.len(), m_u8.len());
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
    // check that the inner-product realtion is indeed correct.
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

#[test]
fn test_trace_to_needles_map() {
    use crate::linalg;
    type F = ark_curve25519::Fr;
    use ark_std::{UniformRand, Zero};

    let rng = &mut rand::thread_rng();

    let message = [
        0x4A, 0x8F, 0x6D, 0xE2, 0x12, 0x7B, 0xC9, 0x34, 0xA5, 0x58, 0x91, 0xFD, 0x23, 0x69, 0x0C,
        0xE7,
    ];
    let key = [
        0xE7u8, 0x4A, 0x8F, 0x6D, 0xE2, 0x12, 0x7B, 0xC9, 0x34, 0xA5, 0x58, 0x91, 0xFD, 0x23, 0x69,
        0x0C, 0xE7u8, 0x4A, 0x8F, 0x6D, 0xE2, 0x12, 0x7B, 0xC9, 0x34, 0xA5, 0x58, 0x91, 0xFD, 0x23,
        0x69, 0x0C,
    ];
    // actual length needed is: ceil(log(OFFSETS.cipher_len * 2))
    let challenges = (0..15).map(|_| F::rand(rng)).collect::<Vec<_>>();
    let vector = linalg::tensor(&challenges);

    let c_xor = F::rand(rng);
    let c_xor2 = F::rand(rng);
    let c_sbox = F::rand(rng);
    let c_rj2 = F::rand(rng);

    let witness = AesCipherWitness::<F, 15, 8>::new(message, &key, F::zero(), F::zero());
    let (needles, _, _) = witness.compute_needles_and_frequencies([c_xor, c_xor2, c_sbox, c_rj2]);
    let got = linalg::inner_product(&needles, &vector);

    let round_keys = aes::aes256_keyschedule(&key);

    // these elements will be commited to a separate vector.
    let message = witness.message.iter().flat_map(|x| [x & 0xf, x >> 4]);
    let keys = round_keys.iter().flatten().flat_map(|x| [x & 0xf, x >> 4]);

    let trace = witness
        .witness_vec
        .iter()
        .copied()
        .chain(message)
        .chain(keys)
        .map(F::from)
        .collect::<Vec<_>>();

    let (needled_vector, constant_term) =
        witness.trace_to_needles_map(&vector, [c_xor, c_xor2, c_sbox, c_rj2]);
    let expected = linalg::inner_product(&needled_vector, &trace) + constant_term;
    assert_eq!(got, expected);
}
