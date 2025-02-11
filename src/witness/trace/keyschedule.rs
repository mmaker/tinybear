use super::utils::{sbox, xor, RC};

#[inline]
pub fn aes128_keyschedule(key: &[u8; 16]) -> [[u8; 16]; 11] {
    keyschedule::<11, 4>(key)
}

#[inline]
pub fn aes256_keyschedule(key: &[u8; 32]) -> [[u8; 16]; 15] {
    keyschedule::<15, 8>(key)
}

/// Naive implementation of AES's keyschedule.
pub fn keyschedule<const R: usize, const N: usize>(key: &[u8]) -> [[u8; 16]; R] {
    let trace = AesKeySchTrace::<R, N>::new(key);

    let mut round_keys = [[0u8; 16]; R];
    for i in 0..R {
        round_keys[i][..4].copy_from_slice(&trace.round_keys[i][0]);
        round_keys[i][4..8].copy_from_slice(&trace.round_keys[i][1]);
        round_keys[i][8..12].copy_from_slice(&trace.round_keys[i][2]);
        round_keys[i][12..16].copy_from_slice(&trace.round_keys[i][3]);
    }
    round_keys
}

pub struct AesKeySchTrace<const R: usize, const N: usize> {
    pub xor: [[u8; 4]; R],
    pub s_box: [[u8; 4]; R],
    pub round_keys: [[[u8; 4]; 4]; R],
    pub _pre_xor: [[u8; 4]; R],
}

impl<const R: usize, const N: usize> Default for AesKeySchTrace<R, N> {
    fn default() -> Self {
        Self {
            s_box: [[0u8; 4]; R],
            round_keys: [[[0u8; 4]; 4]; R],
            xor: [[0u8; 4]; R],
            _pre_xor: [[0u8; 4]; R],
        }
    }
}

impl<const R: usize, const N: usize> AesKeySchTrace<R, N> {
    pub fn new_aes128(key: &[u8; 16]) -> AesKeySchTrace<11, 4> {
        AesKeySchTrace::new(key)
    }

    pub fn new_aes256(key: &[u8; 32]) -> AesKeySchTrace<15, 8> {
        AesKeySchTrace::new(key)
    }

    pub fn new(key: &[u8]) -> Self {
        let mut trace = AesKeySchTrace::default();
        let n_4 = N / 4;

        for i in 0..N {
            let k = i / 4;
            let j = i % 4;
            trace.round_keys[k][j].copy_from_slice(&key[i * 4..(i + 1) * 4]);
        }

        for i in n_4..R {
            if N > 6 && (i * 4) % N == 4 {
                trace.s_box[i] = sbox(trace.round_keys[i - 1][3]);
                trace._pre_xor[i] = trace.s_box[i];
            } else {
                let mut a = trace.round_keys[i - 1][3];
                a.rotate_left(1);
                trace.s_box[i] = sbox(a);
                trace.xor[i] = xor(trace.s_box[i], [RC[i * 4 / N], 0, 0, 0]);
                trace._pre_xor[i] = trace.xor[i];
            }

            trace.round_keys[i][0] = xor(trace.round_keys[i - n_4][0], trace._pre_xor[i]);
            trace.round_keys[i][1] = xor(trace.round_keys[i - n_4][1], trace.round_keys[i][0]);
            trace.round_keys[i][2] = xor(trace.round_keys[i - n_4][2], trace.round_keys[i][1]);
            trace.round_keys[i][3] = xor(trace.round_keys[i - n_4][3], trace.round_keys[i][2]);
        }

        trace
    }
}

#[test]
fn test_aes128_keyschedule() {
    let key = [0u8; 16];
    let expected = [
        *b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        *b"\x62\x63\x63\x63\x62\x63\x63\x63\x62\x63\x63\x63\x62\x63\x63\x63",
        *b"\x9b\x98\x98\xc9\xf9\xfb\xfb\xaa\x9b\x98\x98\xc9\xf9\xfb\xfb\xaa",
        *b"\x90\x97\x34\x50\x69\x6c\xcf\xfa\xf2\xf4\x57\x33\x0b\x0f\xac\x99",
        *b"\xee\x06\xda\x7b\x87\x6a\x15\x81\x75\x9e\x42\xb2\x7e\x91\xee\x2b",
        *b"\x7f\x2e\x2b\x88\xf8\x44\x3e\x09\x8d\xda\x7c\xbb\xf3\x4b\x92\x90",
        *b"\xec\x61\x4b\x85\x14\x25\x75\x8c\x99\xff\x09\x37\x6a\xb4\x9b\xa7",
        *b"\x21\x75\x17\x87\x35\x50\x62\x0b\xac\xaf\x6b\x3c\xc6\x1b\xf0\x9b",
        *b"\x0e\xf9\x03\x33\x3b\xa9\x61\x38\x97\x06\x0a\x04\x51\x1d\xfa\x9f",
        *b"\xb1\xd4\xd8\xe2\x8a\x7d\xb9\xda\x1d\x7b\xb3\xde\x4c\x66\x49\x41",
        *b"\xb4\xef\x5b\xcb\x3e\x92\xe2\x11\x23\xe9\x51\xcf\x6f\x8f\x18\x8e",
    ];
    let got = aes128_keyschedule(&key);
    assert_eq!(got[0], expected[0]);
    assert_eq!(got[1], expected[1]);
    assert_eq!(got, expected);
}

#[test]
fn test_aes256_keyschedule() {
    let key = *b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\
    \x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";
    let expected = [
        *b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
        *b"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",
        *b"\xa5\x73\xc2\x9f\xa1\x76\xc4\x98\xa9\x7f\xce\x93\xa5\x72\xc0\x9c",
        *b"\x16\x51\xa8\xcd\x02\x44\xbe\xda\x1a\x5d\xa4\xc1\x06\x40\xba\xde",
        *b"\xae\x87\xdf\xf0\x0f\xf1\x1b\x68\xa6\x8e\xd5\xfb\x03\xfc\x15\x67",
        *b"\x6d\xe1\xf1\x48\x6f\xa5\x4f\x92\x75\xf8\xeb\x53\x73\xb8\x51\x8d",
        *b"\xc6\x56\x82\x7f\xc9\xa7\x99\x17\x6f\x29\x4c\xec\x6c\xd5\x59\x8b",
        *b"\x3d\xe2\x3a\x75\x52\x47\x75\xe7\x27\xbf\x9e\xb4\x54\x07\xcf\x39",
        *b"\x0b\xdc\x90\x5f\xc2\x7b\x09\x48\xad\x52\x45\xa4\xc1\x87\x1c\x2f",
        *b"\x45\xf5\xa6\x60\x17\xb2\xd3\x87\x30\x0d\x4d\x33\x64\x0a\x82\x0a",
        *b"\x7c\xcf\xf7\x1c\xbe\xb4\xfe\x54\x13\xe6\xbb\xf0\xd2\x61\xa7\xdf",
        *b"\xf0\x1a\xfa\xfe\xe7\xa8\x29\x79\xd7\xa5\x64\x4a\xb3\xaf\xe6\x40",
        *b"\x25\x41\xfe\x71\x9b\xf5\x00\x25\x88\x13\xbb\xd5\x5a\x72\x1c\x0a",
        *b"\x4e\x5a\x66\x99\xa9\xf2\x4f\xe0\x7e\x57\x2b\xaa\xcd\xf8\xcd\xea",
        *b"\x24\xfc\x79\xcc\xbf\x09\x79\xe9\x37\x1a\xc2\x3c\x6d\x68\xde\x36",
    ];
    let got = aes256_keyschedule(&key);
    assert_eq!(got, expected);
}
