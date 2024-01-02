//! See Figure 8 in the paper to learn how this protocol works

#![allow(non_snake_case)]

use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_ff::UniformRand;
use ark_serialize::CanonicalSerialize;

use rand::{CryptoRng, RngCore};
use transcript::IOPTranscript;

use super::{aes, helper, linalg, lookup, pedersen, sigma, sumcheck, u8msm};
use crate::aes::AesCipherTrace;
use crate::aes::AesKeySchTrace;
use crate::helper::trace_to_needles_map;
use crate::pedersen::CommitmentKey;
use crate::sigma::SigmaProof;

#[derive(Default, CanonicalSerialize)]
pub struct TinybearProof<G: CurveGroup> {
    // prover sends w
    pub W: G,
    // sends commitments
    pub M: G, // com(m)
    pub Q: G, // com(q)
    // claimed evaluation of <m, h> = <q, 1>
    pub Y: G, // com(y)

    // runs sumcheck and sends commitments to folded elements
    pub ipa_sumcheck: Vec<[G; 2]>,
    pub ipa_Q_fold: G,
    pub ipa_F_twist_fold: G,
    pub mul_proof: SigmaProof<G>,

    // runs sumcheck and sends commitments to folded secret elements
    pub lin_sumcheck: Vec<[G; 2]>,
    pub lin_M_fold: G,
    pub lin_Q_fold: G,
    // lin_Z_fold computed from the reduced claim
    pub lin_proof: SigmaProof<G>,
}

pub trait Witness<F: Field> {
    fn witness_vec(&self) -> &[u8];
    /// xor needles to lookup in table (x, y, z = x ^ y)
    fn get_xor_witness(&self) -> Vec<(u8, u8, u8)>;
    /// sbox needles to lookup in table x -> SBOX[x]
    fn get_s_box_witness(&self) -> Vec<(u8, u8)>;
    /// Rijndael(2) needles to lookup in table x -> Rj(2)*x
    fn get_r2j_witness(&self) -> Vec<(u8, u8)>;
    /// Compute needles and frequencies
    /// Return (needles, frequencies, frequencies_u8)
    fn compute_needles_and_frequencies(&self, r: [F; 4]) -> (Vec<F>, Vec<F>, Vec<u8>);
    fn trace_to_needles_map(&self, src: &[F], r: [F; 4]) -> (Vec<F>, F);
    /// The full witness, aka vector z in the scheme,
    /// is the concatenation of the public and private information.
    fn full_witness(&self) -> Vec<F>;
    /// The full witness opening is the opening of
    fn full_witness_opening(&self) -> F;
}

pub struct AesCipherWitness<F: Field, const R: usize, const N: usize> {
    trace: AesCipherTrace,
    witness_vec: Vec<u8>,
    message: [u8; 16],
    round_keys: [[u8; 16]; R],
    message_opening: F,
    key_opening: F,
}

impl<F: Field, const R: usize, const N: usize> AesCipherWitness<F, R, N> {
    fn new(message: [u8; 16], key: &[u8], message_opening: F, key_opening: F) -> Self {
        assert_eq!(key.len(), N * 4);
        let round_keys = aes::keyschedule::<R, N>(key);
        let trace = aes::aes_trace(message, &round_keys);
        let witness_vec = helper::vectorize_witness::<R>(&trace);
        Self {
            trace,
            witness_vec,
            message,
            round_keys,
            message_opening,
            key_opening,
        }
    }
}

impl<F: Field, const R: usize, const N: usize> Witness<F> for AesCipherWitness<F, R, N> {
    fn witness_vec(&self) -> &[u8] {
        self.witness_vec.as_slice()
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
            let xs = self.trace.s_box.iter().skip(self.trace.s_box.len() - 16).copied();
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

    fn full_witness_opening(&self) -> F {
        self.message_opening + self.key_opening
    }

    fn compute_needles_and_frequencies(&self, [r_xor, r2_xor, r_sbox, r_rj2]: [F; 4]) -> (Vec<F>, Vec<F>, Vec<u8>) {
        // Generate the witness.
        // witness_s_box = [(a, sbox(a)), (b, sbox(b)), ...]
        let witness_s_box = self.get_s_box_witness();
        // witness_r2j = [(a, r2j(a)), (b, r2j(b)), ...]
        let witness_r2j = self.get_r2j_witness();
        // witness_xor = [(a, b, xor(a, b)), (c, d, xor(c, d)), ...] for 4-bits
        let witness_xor = self.get_xor_witness();

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
        (needles, frequencies, frequencies_u8)
    }

    fn trace_to_needles_map(&self, src: &[F], r: [F; 4]) -> (Vec<F>, F) {
        let output = &self.trace.output;
        trace_to_needles_map::<_, R>(output, src, r)
    }

    fn full_witness(&self) -> Vec<F> {
        let m = self.message.iter().flat_map(|x| [x & 0xf, x >> 4]);
        let rk = self.round_keys.iter().flatten().flat_map(|x| [x & 0xf, x >> 4]);
        self.witness_vec.iter().copied().chain(m).chain(rk).map(F::from).collect()
    }
}

pub fn commit_message<G: CurveGroup, const R: usize>(
    csrng: &mut (impl CryptoRng + RngCore),
    ck: &CommitmentKey<G>,
    m: [u8; 16],
) -> (G, G::ScalarField) {
    let message_offset = helper::aes_offsets::<R>().message;
    let m = m.iter().flat_map(|x| [x & 0xf, x >> 4]).collect::<Vec<_>>();
    let message_blinder = G::ScalarField::rand(csrng);
    let message_commitment =
        u8msm::u8msm::<G>(&ck.vec_G[message_offset * 2..], &m) + ck.H * message_blinder;

    (message_commitment, message_blinder)
}

pub fn commit_aes128_message<G: CurveGroup>(
    csrng: &mut (impl CryptoRng + RngCore),
    ck: &CommitmentKey<G>,
    m: [u8; 16],
) -> (G, G::ScalarField) {
    commit_message::<G, 11>(csrng, ck, m)
}

pub fn commit_aes256_message<G: CurveGroup>(
    csrng: &mut (impl CryptoRng + RngCore),
    ck: &CommitmentKey<G>,
    m: [u8; 16],
) -> (G, G::ScalarField) {
    commit_message::<G, 15>(csrng, ck, m)
}

pub fn commit_aes128_keys<G: CurveGroup>(
    csrng: &mut (impl CryptoRng + RngCore),
    ck: &CommitmentKey<G>,
    key: &[u8; 16],
) -> (G, G::ScalarField) {
    commit_round_keys(csrng, ck, &aes::aes128_keyschedule(key))
}

pub fn commit_aes256_keys<G: CurveGroup>(
    csrng: &mut (impl CryptoRng + RngCore),
    ck: &CommitmentKey<G>,
    key: &[u8; 32],
) -> (G, G::ScalarField) {
    commit_round_keys(csrng, ck, &aes::aes256_keyschedule(key))
}

fn commit_round_keys<G: CurveGroup, const R: usize>(
    csrng: &mut (impl CryptoRng + RngCore),
    ck: &CommitmentKey<G>,
    round_keys: &[[u8; 16]; R],
) -> (G, G::ScalarField) {
    let kk = round_keys
        .iter()
        .flatten()
        .flat_map(|x| [x & 0xf, x >> 4])
        .collect::<Vec<_>>();

    let key_blinder = G::ScalarField::rand(csrng);
    let round_keys_offset = helper::aes_offsets::<R>().round_keys * 2;
    let round_keys_commitment =
        crate::u8msm::u8msm::<G>(&ck.vec_G[round_keys_offset..], &kk) + ck.H * key_blinder;

    (round_keys_commitment, key_blinder)
}

fn ks_get_xor_witness<const N: usize, const R: usize>(
    trace: &AesKeySchTrace<R, N>,
) -> Vec<(u8, u8, u8)> {
    let n_4 = N / 4;
    let mut witness_xor = Vec::new();

    for i in n_4..R {
        let zs = trace.k_sch[i][1..4].iter().flatten().copied();
        let xs = trace.k_sch[i - n_4][1..4].iter().flatten().copied();
        let ys = trace.k_sch[i][0..3].iter().flatten().copied();

        let new_witness = xs.zip(ys).zip(zs).map(|((x, y), z)| (x, y, z));
        witness_xor.extend(new_witness)
    }

    for i in n_4..R {
        let zs = trace.k_sch[i][0].iter().copied();
        let xs = trace.k_sch[i - n_4][0].iter().copied();
        let ys = trace.k_sch_xor[i].iter().copied();
        let new_witness = xs.zip(ys).zip(zs).map(|((x, y), z)| (x, y, z));
        witness_xor.extend(new_witness)
    }

    witness_xor
}

// fn sbox_get_s_box_witness<const N: usize, const R: usize>(trace: &KeySchTrace<R>) -> Vec<(u8, u8)> {
//     let n_4 = N / 4;
//     let mut witness_s_box = Vec::new();

//     for i in (n_4 .. R) {
//         let xs = trace.k_sch[i-1][3];
//         xs.rotate_left(1);

//         let ys = trace.k_sch_s_box[i].iter().copied();
//         let new_witness = xs.zip(ys);
//         witness_s_box.extend(new_witness)
//     }

//     witness_s_box
// }

#[inline]
pub fn aes128_prove<G: CurveGroup>(
    transcript: &mut IOPTranscript<G::ScalarField>,
    ck: &CommitmentKey<G>,
    message: [u8; 16],
    message_blinder: G::ScalarField,
    key: &[u8; 16],
    key_blinder: G::ScalarField,
) -> TinybearProof<G> {
    let witness =
        AesCipherWitness::<G::ScalarField, 11, 4>::new(message, key, message_blinder, key_blinder);
    aes_prove::<G, 11>(transcript, ck, &witness)
}

#[inline]
pub fn aes256_prove<G: CurveGroup>(
    transcript: &mut IOPTranscript<G::ScalarField>,
    ck: &CommitmentKey<G>,
    message: [u8; 16],
    message_blinder: G::ScalarField,
    key: &[u8; 32],
    key_blinder: G::ScalarField,
) -> TinybearProof<G> {
    let witness =
        AesCipherWitness::<G::ScalarField, 15, 8>::new(message, key, message_blinder, key_blinder);
    aes_prove::<G, 15>(transcript, ck, &witness)
}

fn aes_prove<G: CurveGroup, const R: usize>(
    transcript: &mut IOPTranscript<G::ScalarField>,
    ck: &CommitmentKey<G>,
    witness: &impl Witness<G::ScalarField>,
) -> TinybearProof<G> {
    let rng = &mut rand::rngs::OsRng;
    let mut proof = TinybearProof::<G>::default();

    // Commit to the AES trace.
    // TIME: ~3-4ms [outdated]
    let w_vec = witness.witness_vec();
    let (W, W_opening) = pedersen::commit_hiding_u8(rng, ck, &w_vec);
    // Send W
    proof.W = W;
    transcript
        .append_serializable_element(b"witness_com", &[proof.W])
        .unwrap();

    // Lookup
    // Get challenges for the lookup protocol.
    // one for sbox + mxcolhelp, sbox, two for xor
    let c_lup_batch = transcript.get_and_append_challenge(b"r_rj2").unwrap();
    let [c_rj2, c_sbox, c_xor, c_xor2] = linalg::powers(c_lup_batch, 5)[1..].try_into().unwrap();
    // Compute needles and frequencies
    let (f_vec, m_vec, m_u8) =
        witness.compute_needles_and_frequencies([c_xor, c_xor2, c_sbox, c_rj2]);
    debug_assert_eq!(f_vec.len(), helper::aes_offsets::<R>().needles_len);
    // Commit to m (using mu as the blinder) and send it over
    let (M, M_opening) = pedersen::commit_hiding_u8(rng, ck, &m_u8);
    // Send M
    proof.M = M;
    transcript
        .append_serializable_element(b"m", &[proof.M])
        .unwrap();

    // Get the lookup challenge c and compute q and y
    let c_lup = transcript.get_and_append_challenge(b"c").unwrap();
    // Compute vector inverse_needles[i] = 1 / (needles[i] + a) = q
    let mut q_vec = linalg::add_constant(&f_vec, c_lup);
    ark_ff::batch_inversion(&mut q_vec);
    // Q = Com(q)
    let (Q, Q_opening) = pedersen::commit_hiding(rng, ck, &q_vec);
    // y = <g,1>
    let y = q_vec.iter().sum();
    let (Y, Y_opening) = pedersen::commit_hiding(rng, ck, &[y]);
    // Finally compute h and t
    let (t_vec, h_vec) = lookup::compute_haystack([c_xor, c_xor2, c_sbox, c_rj2], c_lup);
    // there are as many frequencies as elements in the haystack
    debug_assert_eq!(h_vec.len(), m_u8.len());
    // all needles are in the haystack
    assert!(f_vec.iter().all(|x| t_vec.contains(x)));
    // Send (Q,Y)
    proof.Q = Q;
    proof.Y = Y;
    transcript
        .append_serializable_element(b"Q", &[proof.Q])
        .unwrap();
    transcript
        .append_serializable_element(b"Y", &[proof.Y])
        .unwrap();

    // Sumcheck for inner product
    // reduce <f . twist_vec ,q> = Y into:
    // 1.  <f, twist_vec . ipa_tensor> = F_fold
    // 2.  <q, ipa_tensor> = Q_fold
    let c_ipa_twist = transcript.get_and_append_challenge(b"twist").unwrap();
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
    let (cs_ipa, ipa_sumcheck_messages, ipa_sumcheck_openings, (f_twist_fold, ipa_q_fold)) =
        sumcheck::sumcheck(transcript, rng, ck, &f_twist_vec, &q_vec);
    proof.ipa_sumcheck = ipa_sumcheck_messages;
    // Commit to the final folded claims
    let (ipa_F_twist_fold, ipa_F_twist_fold_opening) =
        pedersen::commit_hiding(rng, ck, &[f_twist_fold]);
    let (ipa_Q_fold, ipa_Q_fold_opening) = pedersen::commit_hiding(rng, ck, &[ipa_q_fold]);
    proof.ipa_Q_fold = ipa_Q_fold;
    proof.ipa_F_twist_fold = ipa_F_twist_fold;
    transcript
        .append_serializable_element(b"ipa_Q_fold", &[proof.ipa_Q_fold])
        .unwrap();
    transcript
        .append_serializable_element(b"ipa_F_twisted_fold", &[proof.ipa_F_twist_fold])
        .unwrap();

    // Prove that the folded sumcheck claims are consistent
    let ipa_sumcheck_opening =
        sumcheck::reduce_with_challenges(&ipa_sumcheck_openings, &cs_ipa, G::ScalarField::from(0));
    proof.mul_proof = sigma::mul_prove(
        rng,
        transcript,
        ck,
        f_twist_fold,
        ipa_Q_fold,
        ipa_F_twist_fold_opening,
        ipa_Q_fold_opening,
        ipa_sumcheck_opening,
    );

    // Sumcheck for linear evaluation
    let cs_ipa_vec = linalg::tensor(&cs_ipa);
    let ipa_twist_cs_vec = linalg::hadamard(&cs_ipa_vec, &c_ipa_twist_vec);
    let (s_vec, s_const) =
        witness.trace_to_needles_map(&ipa_twist_cs_vec, [c_sbox, c_rj2, c_xor, c_xor2]);
    let z_vec = witness.full_witness();
    let c_q = transcript.get_and_append_challenge(b"bc").unwrap();

    let cs_ipa_c_q_vec = linalg::add_constant(&cs_ipa_vec, c_q);
    debug_assert_eq!(
        linalg::inner_product(&cs_ipa_c_q_vec, &q_vec),
        ipa_q_fold + c_q * y
    );
    let z_twisted_fold =
        f_twist_fold - c_lup * ipa_twist_cs_vec.iter().sum::<G::ScalarField>() - s_const;

    let c_lin_batch = transcript.get_and_append_challenge(b"sumcheck2").unwrap();
    let c_lin_batch_vec = [c_lin_batch, c_lin_batch.square()];
    let mut lin_claims = [
        // <m_vec, h_vec> = y
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
    // invoke batch sumcheck
    let (cs_lin, lin_sumcheck, lin_openings) =
        sumcheck::batch_sumcheck(transcript, rng, ck, &mut lin_claims, &c_lin_batch_vec);
    proof.lin_sumcheck = lin_sumcheck;
    // construct the folded instances to be sent
    debug_assert_eq!(lin_claims[0].0.len(), 1);
    debug_assert_eq!(lin_claims[1].0.len(), 1);
    debug_assert_eq!(lin_claims[2].0.len(), 1);
    let (lin_m_fold, lin_h_fold) = (lin_claims[0].0[0], lin_claims[0].1[0]);
    let (lin_q_fold, lin_ipa_cs_c_q_fold) = (lin_claims[1].0[0], lin_claims[1].1[0]);
    let (lin_z_fold, lin_s_fold) = (lin_claims[2].0[0], lin_claims[2].1[0]);

    // commit to the final claims
    let (_lin_Z_fold, lin_Z_fold_opening) = pedersen::commit_hiding(rng, ck, &[lin_z_fold]);
    let (lin_Q_fold, lin_Q_fold_opening) = pedersen::commit_hiding(rng, ck, &[lin_q_fold]);
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
    proof.lin_M_fold = lin_M_fold;
    proof.lin_Q_fold = lin_Q_fold;

    debug_assert_eq!(
        lin_sumcheck_opening,
        lin_M_fold_opening * lin_h_fold
            + lin_Q_fold_opening * lin_ipa_cs_c_q_fold * c_lin_batch_vec[0]
            + lin_Z_fold_opening * lin_s_fold * c_lin_batch_vec[1]
    );

    let Z_opening = W_opening + witness.full_witness_opening();
    let lin_sumcheck_chals_vec = linalg::tensor(&cs_lin);
    let c_batch_eval = transcript.get_and_append_challenge(b"final").unwrap();
    let c_batch_eval_vec = [c_batch_eval, c_batch_eval.square()];

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

    proof.lin_proof = sigma::lin_prove(
        rng,
        transcript,
        ck,
        &e_vec,
        e_opening,
        lin_M_fold_opening
            + c_batch_eval_vec[0] * lin_Q_fold_opening
            + c_batch_eval_vec[1] * lin_Z_fold_opening,
        &lin_sumcheck_chals_vec,
    );

    proof
}

#[test]
fn test_prove() {
    use ark_ff::Zero;
    type G = ark_curve25519::EdwardsProjective;
    type F = ark_curve25519::Fr;

    let mut transcript = IOPTranscript::<F>::new(b"aes");
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

    let proof = aes128_prove::<G>(&mut transcript, &ck, message, F::zero(), &key, F::zero());
    println!("size: {}", proof.compressed_size());
    println!("lin size: {}", proof.lin_proof.compressed_size());
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
        0x0C,
    ];
    let witness = aes::AesCipherTrace::new_aes128(message, key);
    // actual length needed is: ceil(log(OFFSETS.cipher_len * 2))
    let challenges = (0..11).map(|_| F::rand(rng)).collect::<Vec<_>>();
    let vector = linalg::tensor(&challenges);

    let r_xor = F::rand(rng);
    let r2_xor = F::rand(rng);
    let r_sbox = F::rand(rng);
    let r_rj2 = F::rand(rng);


    let witness = AesCipherWitness::<F, 11, 4>::new(message, &key, F::zero(), F::zero());
    let (needles, _, _) =
        witness.compute_needles_and_frequencies([r_xor, r2_xor, r_sbox, r_rj2]);
    let got = linalg::inner_product(&needles, &vector);

    let cipher_trace = crate::helper::vectorize_witness::<11>(&witness.trace);
    let round_keys = aes::aes128_keyschedule(&key);

    // these elements will be commited to a separate vector.
    let message = witness.message.iter().flat_map(|x| [x & 0xf, x >> 4]);
    let keys = round_keys.iter().flatten().flat_map(|x| [x & 0xf, x >> 4]);

    let trace = cipher_trace
        .into_iter()
        .chain(message)
        .chain(keys)
        .map(F::from)
        .collect::<Vec<_>>();

    let (needled_vector, constant_term) =
        crate::helper::trace_to_needles_map::<F, 11>(&witness.trace.output, &vector, [r_sbox, r_rj2, r_xor, r2_xor]);
    let expected = linalg::inner_product(&needled_vector, &trace) + constant_term;
    assert_eq!(got, expected);
}
