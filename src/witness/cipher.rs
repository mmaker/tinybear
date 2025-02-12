//! See Figure 8 in the paper to learn how this protocol works
#![allow(non_snake_case)]

use ark_ff::Field;

use super::registry::aes_offsets;
use super::trace::{cipher, keyschedule};
use crate::lookup;
use crate::traits::Witness;

//See about moving the round keys once to the very end instead of the very front
#[derive(Clone)]
pub struct AesCipherWitness<F: Field, const R: usize, const N: usize> {
    pub trace: cipher::AesCipherTrace,
    pub witness_vec: Vec<u8>,
    pub message: [u8; 16],
    pub round_keys: [[u8; 16]; R],
    pub message_opening: F,
    pub key_opening: F,
}

impl<F: Field, const R: usize, const N: usize> AesCipherWitness<F, R, N> {
    pub fn new(message: [u8; 16], key: &[u8], message_opening: F, key_opening: F) -> Self {
        assert_eq!(key.len(), N * 4);
        let round_keys = keyschedule::keyschedule::<R, N>(key);
        let trace = cipher::aes_trace(message, &round_keys);
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
    pub(crate) fn vectorize_witness(witness: &cipher::AesCipherTrace) -> Vec<u8> {
        let mut w = Vec::<u8>::new();
        let registry = crate::witness::registry::aes_offsets::<R>();

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
    ) -> (Vec<F>, Vec<F>, Vec<u64>) {
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
        let mut freq_u64 = vec![0u64; 256 * 3]; //This probably cant be a u8 anymore, probably needs to be a u64
        lookup::count_u16_frequencies(&mut freq_u64[0..256], &witness_xor);
        lookup::count_u8_frequencies(&mut freq_u64[256..512], &witness_s_box);
        lookup::count_u8_frequencies(&mut freq_u64[512..768], &witness_r2j);

        let freq = freq_u64.iter().map(|x| F::from(*x)).collect::<Vec<_>>();
        (needles, freq, freq_u64)
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

    let round_keys = keyschedule::aes256_keyschedule(&key);

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
