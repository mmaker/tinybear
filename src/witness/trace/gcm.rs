use crate::witness::trace::cipher::{aes128, AesCipherTrace};
use crate::witness::trace::utils::xor;

#[derive(Default, Clone, Copy)]
// XXX. Maybe rename this? And modify the new function to support the GHASH option
pub struct AesGCMCounter {
    pub iv: [u8; 12],
    pub count: u32,
}

#[derive(Default, Clone)]
pub struct AesGCMCipherBlockTrace {
    pub plaintext: [u8; 16],
    pub counter: AesGCMCounter,
    pub aes_cipher_trace: AesCipherTrace,
    pub output: [u8; 16],
}

#[derive(Default, Clone)]
pub struct AesGCMCipherTrace {
    pub icb: [u8; 16],
    pub blocks: Vec<AesGCMCipherBlockTrace>,
}

impl AesGCMCipherBlockTrace {
    pub fn new(key: [u8; 16], ctr: AesGCMCounter, plain_text: [u8; 16]) -> Self {
        let cb = ctr.make_counter();
        let cipher_trace = AesCipherTrace::new_aes128(cb, key);

        let xor = xor(cipher_trace.output, plain_text);

        Self {
            plaintext: plain_text,
            counter: ctr,
            aes_cipher_trace: cipher_trace,
            output: xor,
        }
    }
}

impl AesGCMCounter {
    // Assuming len(iv) is 96, will deal with hashing later
    pub fn create_icb(iv: [u8; 12]) -> Self {
        Self { iv, count: 1 }
    }

    pub fn make_counter(&self) -> [u8; 16] {
        let mut iter = self.iv.into_iter().chain(self.count.to_be_bytes());

        std::array::from_fn(|_| iter.next().unwrap())
    }
}

impl AesGCMCipherTrace {
    pub fn pt_slice(pt: &[u8], index: usize) -> [u8; 16] {
        assert!((index + 1) * 16 <= pt.len());
        pt[16 * index..16 * (index + 1)]
            .try_into()
            .expect("slice with incorrect length")
    }

    pub fn new(key: [u8; 16], iv: [u8; 12], plain_text: &[u8]) -> Self {
        let icb = AesGCMCounter::create_icb(iv);
        // XXX. for right now just assert plain_text is divisible by 16
        assert!(plain_text.len() % 16 == 0);
        let n_blocks = plain_text.len() / 16;
        let mut blocks: Vec<AesGCMCipherBlockTrace> = Vec::new();
        for i in 0..n_blocks {
            let mut ctr_i = icb;
            ctr_i.count = ctr_i.count + 1 + (i as u32);
            let block_i = AesGCMCipherBlockTrace::new(key, ctr_i, Self::pt_slice(plain_text, i));
            blocks.push(block_i);
        }
        Self {
            icb: aes128(icb.make_counter(), key),
            blocks,
        }
    }
}

#[test]
fn test_aes128_gcm_single_block() {
    use hex_literal::hex;
    let plain_text: [u8; 16] = hex!("001d0c231287c1182784554ca3a21908");
    let key: [u8; 16] = hex!("5b9604fe14eadba931b0ccf34843dab9");
    let iv: [u8; 12] = hex!("028318abc1824029138141a2");
    let expected: [u8; 16] = hex!("26073cc1d851beff176384dc9896d5ff");
    let mut ctr = AesGCMCounter::create_icb(iv);
    ctr.count += 1;
    let block = AesGCMCipherBlockTrace::new(key, ctr, plain_text);

    assert_eq!(block.output, expected);
}

#[test]
fn test_aes128_gcm_full() {
    use hex_literal::hex;
    let plain_text: &[u8] = &hex!("d902deeab175c008329a33bfaccd5c0eb3a6a152a1510e7db04fa0aff7ce4288530db6a80fa7fea582aa7d46d7d56e708d2bb0c5edd3d26648d336c3620ea55e");
    let key: [u8; 16] = hex!("e12260fcd355a51a0d01bb1f6fa538c2");
    let iv: [u8; 12] = hex!("5dfc37366f5688275147d3f9");
    let expected: &[u8] = &hex!("d33bf6722fc29384fad75f990248b9528e0959aa67ec66869dc3996c67a2d559e7d77ce5955f8cad2a4df5fdc3acccafa7bc0def53d848111256903e5add0420");
    let out = AesGCMCipherTrace::new(key, iv, plain_text);

    let check = expected.to_vec();

    let mut result: Vec<u8> = Vec::new();

    for block in out.blocks {
        result.extend_from_slice(&(block.output));
    }

    assert_eq!(result, check);
}
