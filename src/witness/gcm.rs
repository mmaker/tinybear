//! See Figure 8 in the paper to learn how this protocol works
#![allow(non_snake_case)]

use ark_ff::Field;

use crate::lookup;
use crate::traits::Witness;
use crate::witness::cipher::AesCipherWitness;
use crate::witness::registry::aes_gcm_block_offsets;
use crate::witness::trace::gcm::{self, AesGCMCipherBlockTrace, AesGCMCipherTrace, AesGCMCounter};
use crate::MultiBlockWitness;

#[derive(Default, Clone)]
pub struct AesGCMCipherBlockWitness<F: Field, const R: usize, const N: usize> {
    trace: AesGCMCipherBlockTrace,
    witness_vec: Vec<u8>,
    counter: [u8; 16],
    key_opening: F,
    plain_text: [u8; 16],
    plain_text_opening: F,
}

#[derive(Clone)]
pub struct AesGCMCipherWitness<F: Field, const R: usize, const N: usize> {
    icb_witness: AesCipherWitness<F, R, N>,
    block_witnesses: Vec<AesGCMCipherBlockWitness<F, R, N>>,
}

impl<F: Field, const R: usize, const N: usize> AesGCMCipherBlockWitness<F, R, N> {
    pub fn new(
        counter: AesGCMCounter,
        key: &[u8],
        plain_text: [u8; 16],
        key_opening: F,
        plain_text_opening: F,
    ) -> Self {
        assert_eq!(key.len(), N * 4);
        let trace = AesGCMCipherBlockTrace::new(
            key.try_into().expect("invalid keylenght"),
            counter,
            plain_text,
        );
        let witness_vec = Self::vectorize_witness(&trace);
        Self {
            trace,
            witness_vec,
            counter: counter.make_counter(),
            key_opening,
            plain_text,
            plain_text_opening,
        }
    }

    pub(crate) fn vectorize_witness(witness: &gcm::AesGCMCipherBlockTrace) -> Vec<u8> {
        let registry = aes_gcm_block_offsets::<R>();

        let mut w = Vec::<u8>::new();

        assert_eq!(registry.start, w.len());
        w.extend(&witness.aes_cipher_trace.start);

        assert_eq!(registry.s_box, w.len());
        w.extend(&witness.aes_cipher_trace.s_box);

        for i in 0..5 {
            assert_eq!(registry.m_col[i], w.len());
            w.extend(&witness.aes_cipher_trace.m_col[i]);
        }
        assert_eq!(registry.aes_output, w.len());

        w.extend(&witness.aes_cipher_trace.output);
        assert_eq!(registry.counter, w.len());

        // split the witness and low and high 4-bits.
        w.iter().flat_map(|x| [x & 0xf, x >> 4]).collect()
    }

    //This is wrong will need to update
    fn get_xor_witness(&self) -> Vec<(u8, u8, u8)> {
        let aes_trace = &self.trace.aes_cipher_trace;

        let mut witness_xor = Vec::new();
        // m_col_xor
        for i in 0..4 {
            let xs = aes_trace.m_col[i].iter().copied();
            let ys = aes_trace._aux_m_col[i].iter().copied();
            let zs = aes_trace.m_col[i + 1].iter().copied();
            let new_witness = xs.zip(ys).zip(zs).map(|((x, y), z)| (x, y, z));
            witness_xor.extend(new_witness)
        }
        // round key xor
        {
            let xs = aes_trace.m_col[4].iter().copied();
            let zs = aes_trace.start.iter().skip(16).copied();
            let ys = aes_trace._keys.iter().flatten().skip(16).copied();
            // ys are the round keys
            let new_witness = xs.zip(ys).zip(zs).map(|((x, y), z)| (x, y, z));
            witness_xor.extend(new_witness)
        }
        // last round
        {
            let xs = aes_trace
                .s_box
                .iter()
                .skip(aes_trace.s_box.len() - 16)
                .copied();
            let ys = aes_trace._keys.last().into_iter().flatten().copied();
            let zs = aes_trace.output.iter().copied();
            let new_witness = xs.zip(ys).zip(zs).map(|((x, y), z)| (x, y, z));
            witness_xor.extend(new_witness);
        }
        // first round xor
        {
            let xs = aes_trace.message.iter().copied();
            // let ys = witness._keys.iter().take(16).flatten().copied();
            let zs = aes_trace.start.iter().take(16).copied();
            // ys is the 0th round key
            let new_witness = xs.zip(zs).map(|(x, z)| (x, x ^ z, z));
            witness_xor.extend(new_witness);
        }
        //Plaintext XOR
        //Need to remember where the plaintext is
        //This will also affect the frequencies table
        //(plaintext, enc_ctr, XOR )
        {
            let xs = aes_trace.output.iter().copied();
            let ys = self.trace.plaintext.iter().copied();
            let zs = self.trace.output.iter().copied();
            let new_witness = xs.zip(ys).zip(zs).map(|((x, y), z)| (x, y, z));
            witness_xor.extend(new_witness);
        }
        witness_xor
    }

    fn get_s_box_witness(&self) -> Vec<(u8, u8)> {
        let s_box = self
            .trace
            .aes_cipher_trace
            ._s_row
            .iter()
            .zip(&self.trace.aes_cipher_trace.s_box);
        // let k_sch_s_box = witness._k_rot.iter().zip(&witness.k_sch_s_box);
        s_box.map(|(&x, &y)| (x, y)).collect()
    }

    fn get_r2j_witness(&self) -> Vec<(u8, u8)> {
        let xs = self.trace.aes_cipher_trace.s_box.iter().copied();
        let ys = self.trace.aes_cipher_trace.m_col[0].iter().copied();
        xs.zip(ys).collect()
    }
}

impl<F: Field, const R: usize, const N: usize> Witness<F> for AesGCMCipherBlockWitness<F, R, N> {
    fn witness_vec(&self) -> &[u8] {
        self.witness_vec.as_slice()
    }

    fn needles_len(&self) -> usize {
        aes_gcm_block_offsets::<R>().needles_len
    }

    fn full_witness_opening(&self) -> F {
        self.key_opening + self.plain_text_opening
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
        let mut freq_u64 = vec![0u64; 256 * 3];
        lookup::count_u16_frequencies(&mut freq_u64[0..256], &witness_xor);
        lookup::count_u8_frequencies(&mut freq_u64[256..512], &witness_s_box);
        lookup::count_u8_frequencies(&mut freq_u64[512..768], &witness_r2j);

        let freq = freq_u64.iter().map(|x| F::from(*x)).collect::<Vec<_>>();
        (needles, freq, freq_u64)
    }

    fn trace_to_needles_map(&self, _src: &[F], _r: [F; 4]) -> (Vec<F>, F) {
        let _aes_output = &self.trace.aes_cipher_trace.output;
        let _final_xor = &self.trace.output;
        let out: Vec<F> = Vec::new();
        (out, F::ZERO)
    }

    fn full_witness(&self) -> Vec<F> {
        let ctr = self.counter.iter().flat_map(|x| [x & 0xf, x >> 4]);
        let pt = self.plain_text.iter().flat_map(|x| [x & 0xf, x >> 4]);
        self.witness_vec
            .iter()
            .copied()
            .chain(ctr)
            .chain(pt)
            .map(F::from)
            .collect()
    }
}

#[test]
fn test_compute_needles_and_freq_single_block() {
    use crate::linalg;
    type F = ark_curve25519::Fr;
    use ark_std::{UniformRand, Zero};
    use hex_literal::hex;

    let rng = &mut rand::thread_rng();

    let plain_text: [u8; 16] = hex!("001d0c231287c1182784554ca3a21908");
    let key: [u8; 16] = hex!("5b9604fe14eadba931b0ccf34843dab9");
    let iv: [u8; 12] = hex!("028318abc1824029138141a2");
    let mut ctr = AesGCMCounter::create_icb(iv);
    ctr.count += 1;

    // actual length needed is: ceil(log(OFFSETS.cipher_len * 2))
    let challenges = (0..15).map(|_| F::rand(rng)).collect::<Vec<_>>();
    let vector = linalg::tensor(&challenges);

    let c_xor = F::rand(rng);
    let c_xor2 = F::rand(rng);
    let c_sbox = F::rand(rng);
    let c_rj2 = F::rand(rng);

    let witness =
        AesGCMCipherBlockWitness::<F, 11, 4>::new(ctr, &key, plain_text, F::zero(), F::zero());
    let (needles, _freq, _freq_u64) =
        witness.compute_needles_and_frequencies([c_xor, c_xor2, c_sbox, c_rj2]);

    let _got = linalg::inner_product(&needles, &vector);
}

impl<F: Field, const R: usize, const N: usize> AesGCMCipherWitness<F, R, N> {
    pub fn new(
        iv: [u8; 12],
        key: [u8; 16],
        plain_text: &[u8],
        icb_opening: F,
        plain_text_openings: Vec<F>,
        key_opening: F,
    ) -> Self {
        let traces = AesGCMCipherTrace::new(key, iv, plain_text);
        let icb = AesGCMCounter::create_icb(iv);
        let icb_witness = AesCipherWitness::new(icb.make_counter(), &key, icb_opening, key_opening);

        assert!(plain_text.len() % 16 == 0);
        let n_blocks = plain_text.len() / 16;

        //Need to figure out if there even is a plain text opening for the icb block
        assert!(n_blocks == plain_text_openings.len() - 1);

        let mut block_witnesses: Vec<AesGCMCipherBlockWitness<F, R, N>> = Vec::new();

        for i in 0..n_blocks {
            block_witnesses.push(AesGCMCipherBlockWitness::new(
                traces.blocks[i].counter,
                key.as_slice(),
                AesGCMCipherTrace::pt_slice(plain_text, i),
                key_opening,
                plain_text_openings[i + 1],
            ));
        }

        Self {
            icb_witness,
            block_witnesses,
        }
    }
}

impl<F: Field, const R: usize, const N: usize> MultiBlockWitness<F>
    for AesGCMCipherWitness<F, R, N>
{
    fn needles_len(&self) -> usize {
        let mut total_needles_len = 0;

        total_needles_len += self.icb_witness.needles_len();
        for block in &self.block_witnesses {
            total_needles_len += block.needles_len();
        }
        total_needles_len
    }

    //Only need to open the key once
    fn full_witness_opening(&self) -> F {
        let mut full_witness_opening = F::ZERO;

        full_witness_opening += self.icb_witness.full_witness_opening();

        for block in &self.block_witnesses {
            full_witness_opening += block.plain_text_opening;
        }

        full_witness_opening
    }

    fn compute_needles_and_frequencies(
        &self,
        [c_xor, c_xor2, c_sbox, c_rj2]: [F; 4],
    ) -> (Vec<F>, Vec<F>, Vec<u64>) {
        let mut needles_vec: Vec<F> = Vec::new();

        let challenges = [c_xor, c_xor2, c_sbox, c_rj2];

        let mut icb_needles_and_freqs =
            self.icb_witness.compute_needles_and_frequencies(challenges);

        needles_vec.append(&mut icb_needles_and_freqs.0);
        let mut freq = icb_needles_and_freqs.1;
        let mut freq_u64 = icb_needles_and_freqs.2;

        for block in self.block_witnesses.clone() {
            let mut block_needles_and_freqs = block.compute_needles_and_frequencies(challenges);

            needles_vec.append(&mut block_needles_and_freqs.0);

            freq = freq
                .iter()
                .zip(block_needles_and_freqs.1.iter())
                .map(|(&freq, &block)| freq + block)
                .collect();

            freq_u64 = freq_u64
                .iter()
                .zip(block_needles_and_freqs.2.iter())
                .map(|(&freq, &block)| freq + block)
                .collect();
        }

        (needles_vec, freq, freq_u64)
    }

    fn trace_to_needles_map(&self, _src: &[F], _r: [F; 4]) -> (Vec<F>, F) {
        let out: Vec<F> = Vec::new();
        (out, F::ZERO)
    }

    fn full_witness(&self) -> Vec<F> {
        let mut full_witness: Vec<F> = Vec::new();

        full_witness.append(&mut self.icb_witness.full_witness());
        for block in &self.block_witnesses {
            full_witness.append(&mut block.full_witness());
        }

        full_witness
    }
}
