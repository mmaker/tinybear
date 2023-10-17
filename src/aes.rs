// Another implementation of AES for playing with zkps
pub const SBOX: [u8; 256] = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
];

pub const M_COL_HELP: [u8; 256] = [
    0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1A, 0x1C, 0x1E,
    0x20, 0x22, 0x24, 0x26, 0x28, 0x2A, 0x2C, 0x2E, 0x30, 0x32, 0x34, 0x36, 0x38, 0x3A, 0x3C, 0x3E,
    0x40, 0x42, 0x44, 0x46, 0x48, 0x4A, 0x4C, 0x4E, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5A, 0x5C, 0x5E,
    0x60, 0x62, 0x64, 0x66, 0x68, 0x6A, 0x6C, 0x6E, 0x70, 0x72, 0x74, 0x76, 0x78, 0x7A, 0x7C, 0x7E,
    0x80, 0x82, 0x84, 0x86, 0x88, 0x8A, 0x8C, 0x8E, 0x90, 0x92, 0x94, 0x96, 0x98, 0x9A, 0x9C, 0x9E,
    0xA0, 0xA2, 0xA4, 0xA6, 0xA8, 0xAA, 0xAC, 0xAE, 0xB0, 0xB2, 0xB4, 0xB6, 0xB8, 0xBA, 0xBC, 0xBE,
    0xC0, 0xC2, 0xC4, 0xC6, 0xC8, 0xCA, 0xCC, 0xCE, 0xD0, 0xD2, 0xD4, 0xD6, 0xD8, 0xDA, 0xDC, 0xDE,
    0xE0, 0xE2, 0xE4, 0xE6, 0xE8, 0xEA, 0xEC, 0xEE, 0xF0, 0xF2, 0xF4, 0xF6, 0xF8, 0xFA, 0xFC, 0xFE,
    0x27, 0x25, 0x31, 0x2F, 0x19, 0x17, 0x23, 0x21, 0x0B, 0x09, 0x0F, 0x0D, 0x03, 0x01, 0x07, 0x05,
    0x3B, 0x39, 0x3F, 0x3D, 0x33, 0x31, 0x37, 0x35, 0x2B, 0x29, 0x2F, 0x2D, 0x23, 0x21, 0x27, 0x25,
    0x5B, 0x59, 0x5F, 0x5D, 0x53, 0x51, 0x57, 0x55, 0x4B, 0x49, 0x4F, 0x4D, 0x43, 0x41, 0x47, 0x45,
    0x7B, 0x79, 0x7F, 0x7D, 0x73, 0x71, 0x77, 0x75, 0x6B, 0x69, 0x6F, 0x6D, 0x63, 0x61, 0x67, 0x65,
    0x9B, 0x99, 0x9F, 0x9D, 0x93, 0x91, 0x97, 0x95, 0x8B, 0x89, 0x8F, 0x8D, 0x83, 0x81, 0x87, 0x85,
    0xBB, 0xB9, 0xBF, 0xBD, 0xB3, 0xB1, 0xB7, 0xB5, 0xAB, 0xA9, 0xAF, 0xAD, 0xA3, 0xA1, 0xA7, 0xA5,
    0xDB, 0xD9, 0xDF, 0xDD, 0xD3, 0xD1, 0xD7, 0xD5, 0xCB, 0xC9, 0xCF, 0xCD, 0xC3, 0xC1, 0xC7, 0xC5,
    0xFB, 0xF9, 0xFF, 0xFD, 0xF3, 0xF1, 0xF7, 0xF5, 0xEB, 0xE9, 0xEF, 0xED, 0xE3, 0xE1, 0xE7, 0xE5,
];

static RC: [u8; 11] = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
];

pub fn sbox<const N: usize>(state: [u8; N]) -> [u8; N] {
    let mut result = [0u8; N];
    for i in 0..N {
        result[i] = SBOX[state[i] as usize];
    }
    result
}

pub fn shiftrows<T>(mut state: [T; 16]) -> [T; 16] {
    transpose_inplace(&mut state);
    state[0..4].rotate_left(0);
    state[4..8].rotate_left(1);
    state[8..12].rotate_left(2);
    state[12..16].rotate_left(3);
    transpose_inplace(&mut state);
    state
}

pub fn xor<const N: usize>(mut state: [u8; N], key: [u8; N]) -> [u8; N] {
    for i in 0..N {
        state[i] ^= key[i];
    }
    state
}

pub fn mixcolumns(mut state: [u8; 16]) -> [u8; 16] {
    let a = state;
    let mut b = [0u8; 16];
    for i in 0..16 {
        b[i] = M_COL_HELP[a[i] as usize];
    }

    for i in (0..16).step_by(4) {
        state[i + 0] = b[i + 0] ^ a[i + 3] ^ a[i + 2] ^ b[i + 1] ^ a[i + 1];
        state[i + 1] = b[i + 1] ^ a[i + 0] ^ a[i + 3] ^ b[i + 2] ^ a[i + 2];
        state[i + 2] = b[i + 2] ^ a[i + 1] ^ a[i + 0] ^ b[i + 3] ^ a[i + 3];
        state[i + 3] = b[i + 3] ^ a[i + 2] ^ a[i + 1] ^ b[i + 0] ^ a[i + 0];
    }
    state
}

pub fn keyschedule_trace(key: &[u8; 16]) -> KeySchTrace {
    let mut trace = KeySchTrace::default();
    let mut output = [[0u8; 16]; 11];

    trace.k_sch[1][0].copy_from_slice(&key[..4]);
    trace.k_sch[2][0].copy_from_slice(&key[4..8]);
    trace.k_sch[3][0].copy_from_slice(&key[8..12]);
    trace.k_sch[4][0].copy_from_slice(&key[12..16]);
    output[0] = key.clone();

    // this is not really needed
    // just easier for alignment of trace and key schedule
    trace._k_rot[0] = [0; 4];
    trace.k_sch_s_box[0] = sbox(trace._k_rot[0]);

    for i in 1..11 {
        trace._k_rot[i] = trace.k_sch[4][i - 1];
        trace._k_rot[i].rotate_left(1);
        trace.k_sch_s_box[i] = sbox(trace._k_rot[i]);

        trace.k_sch[0][i] = xor(trace.k_sch_s_box[i], [RC[i], 0, 0, 0]);
        trace.k_sch[1][i] = xor(trace.k_sch[1][i - 1], trace.k_sch[0][i]);
        trace.k_sch[2][i] = xor(trace.k_sch[2][i - 1], trace.k_sch[1][i]);
        trace.k_sch[3][i] = xor(trace.k_sch[3][i - 1], trace.k_sch[2][i]);
        trace.k_sch[4][i] = xor(trace.k_sch[4][i - 1], trace.k_sch[3][i]);

        // This is not really necessary, we reorder the output to make my life easier later.
        // The commitment keys should be such that this can be emulated by the verifier
        output[i][..4].copy_from_slice(trace.k_sch[1][i].as_ref());
        output[i][4..8].copy_from_slice(trace.k_sch[2][i].as_ref());
        output[i][8..12].copy_from_slice(trace.k_sch[3][i].as_ref());
        output[i][12..16].copy_from_slice(trace.k_sch[4][i].as_ref());
    }
    trace._keys = output;
    trace
}

/// Naive implementation of AES's keyschedule, for testing purposes.
#[cfg(test)]
fn keyschedule(key: &[u8; 16]) -> [[u8; 16]; 11] {
    let mut scheduled = [[0u8; 4]; 44];
    const N: usize = 4;

    scheduled[0].copy_from_slice(&key[..4]);
    scheduled[1].copy_from_slice(&key[4..8]);
    scheduled[2].copy_from_slice(&key[8..12]);
    scheduled[3].copy_from_slice(&key[12..16]);

    for i in 1..11 {
        // 11 rounds, i in 0..4*rounds-1
        let i = i * 4;
        let mut a = scheduled[i - 1];
        a.rotate_left(1);
        let a = sbox(a);
        let a = xor(a, [RC[i / N], 0, 0, 0]);

        scheduled[i + 0] = xor(scheduled[i + 0 - N], a);
        scheduled[i + 1] = xor(scheduled[i + 1 - N], scheduled[i]);
        scheduled[i + 2] = xor(scheduled[i + 2 - N], scheduled[i + 1]);
        scheduled[i + 3] = xor(scheduled[i + 3 - N], scheduled[i + 2]);
    }

    // yolo
    unsafe { std::mem::transmute(scheduled) }
}

/// Naive implementation of AES-128, for testing purposes.
#[cfg(test)]
pub fn aes_round(mut state: [u8; 16], round_key: [u8; 16]) -> [u8; 16] {
    // shiftrows before sbox so we can lookup SBOX and M_COL_HELP together
    state = shiftrows(state);
    state = sbox(state);
    state = mixcolumns(state);
    xor(state, round_key)
}

#[cfg(test)]
fn aes128(message: [u8; 16], key: [u8; 16]) -> [u8; 16] {
    let keys = keyschedule(&key);

    let mut state = xor(message, keys[0]);
    for i in 1..10 {
        state = aes_round(state, keys[i]);
    }
    let state = sbox(shiftrows(state));
    xor(state, keys[10])
}

/// Rotate a vector of states to the right `times` times.
pub fn rotate_right_inplace<T>(state: &mut [T], times: usize) {
    for row in state.chunks_mut(4) {
        row.rotate_right(times);
    }
}

/// Transpose a vector of states in-place.
pub fn transpose_inplace<T>(list: &mut [T]) {
    for chunk in list.chunks_mut(16) {
        for i in 0..4 {
            for j in i..4 {
                chunk.swap(i * 4 + j, j * 4 + i);
            }
        }
    }
}

#[derive(Default)]
pub struct KeySchTrace {
    pub _k_rot: [[u8; 4]; 11],
    pub k_sch_s_box: [[u8; 4]; 11],
    pub k_sch: [[[u8; 4]; 11]; 5],
    pub _keys: [[u8; 16]; 11],
}

#[derive(Default)]
pub struct RoundTrace {
    // be careful here: SBOX is applied after shiftrows
    pub s_box: [u8; 16],
    pub m_col: [[u8; 16]; 5],
    pub start: [u8; 16],

    pub _s_row: [u8; 16],
    pub _aux_m_col: [[u8; 16]; 4],
}

/// The AES witness containing the full computation trace.
///
/// To have a rough idea of the sizes:
///
/// k_sch_s_box: 44
/// start: 160
/// final_s_box: 1s6
/// k_sch: 44 * 5
/// m_col: 144 * 5
#[derive(Default)]
pub struct Witness {
    pub message: [u8; 16],
    pub key: [u8; 16],
    // keyschedule variables
    pub k_sch_s_box: Vec<u8>,
    pub k_sch: [Vec<u8>; 5],
    // cipher variables
    pub start: Vec<u8>,
    pub s_box: Vec<u8>,
    pub m_col: [Vec<u8>; 5],
    // last round
    pub output: [u8; 16],
    // key schedule permutations
    pub _k_rot: Vec<u8>,
    pub _keys: [[u8; 16]; 11],
    // cipher permutations
    pub _s_row: Vec<u8>,
    pub _aux_m_col: [Vec<u8>; 4],
}

impl Witness {
    pub fn add_round(&mut self, round_trace: &RoundTrace) {
        self._s_row.extend(&round_trace._s_row);
        self.s_box.extend(&round_trace.s_box);
        (0..5).for_each(|i| self.m_col[i].extend(&round_trace.m_col[i]));
        self.start.extend(&round_trace.start);
        (0..4).for_each(|i| self._aux_m_col[i].extend(&round_trace._aux_m_col[i]));
    }

    pub fn add_keyschedule(&mut self, k_sch_trace: &KeySchTrace) {
        self._k_rot.extend(k_sch_trace._k_rot.iter().flatten());
        self.k_sch_s_box
            .extend(k_sch_trace.k_sch_s_box.iter().flatten());
        (0..5).for_each(|i| self.k_sch[i].extend(k_sch_trace.k_sch[i].iter().flatten()));

        self.key = k_sch_trace._keys[0];
        self._keys = k_sch_trace._keys;
    }

    pub fn add_finalround(&mut self, trace: [[u8; 16]; 3]) {
        let [_final_s_row, final_s_box, output] = trace;
        self._s_row.extend(_final_s_row);
        self.s_box.extend(final_s_box);
        self.output = output;
    }
}

pub fn aes128_trace(message: [u8; 16], key: [u8; 16]) -> Witness {
    let mut witness = Witness::default();
    witness.message = message;

    let k_sch_trace = keyschedule_trace(&key);
    witness.add_keyschedule(&k_sch_trace);
    let round_keys = k_sch_trace._keys;

    // first round: add key to message
    let mut round_state = xor(message, round_keys[0]);
    // put the first message into the key schedule artificially.
    // The verifier will do the same using the statement
    witness.start.extend(&round_state);
    for i in 1..10 {
        let round_trace = aes_round_trace(round_state, round_keys[i]);
        witness.add_round(&round_trace);
        round_state = round_trace.start;
    }
    witness.add_finalround(final_round_trace(round_state, round_keys[10]));
    witness
}

pub fn final_round_trace(state: [u8; 16], key: [u8; 16]) -> [[u8; 16]; 3] {
    let _s_row = shiftrows(state);
    let s_box = sbox(_s_row);
    let start = xor(s_box, key);
    [_s_row, s_box, start]
}

pub fn aes_round_trace(state: [u8; 16], key: [u8; 16]) -> RoundTrace {
    let mut trace = RoundTrace::default();
    // shiftrows
    trace._s_row = shiftrows(state);
    // sbox
    trace.s_box = sbox(trace._s_row);
    for (i, &x) in trace.s_box.iter().enumerate() {
        trace.m_col[0][i] = M_COL_HELP[x as usize];
    }
    // mixcolumns: generate the rotations of the vectors to xor.
    trace._aux_m_col[0] = trace.s_box;
    rotate_right_inplace(&mut trace._aux_m_col[0], 1);
    trace._aux_m_col[1] = trace.s_box;
    rotate_right_inplace(&mut trace._aux_m_col[1], 2);
    trace._aux_m_col[2] = trace.s_box;
    rotate_right_inplace(&mut trace._aux_m_col[2], 3);
    trace._aux_m_col[3] = trace.m_col[0];
    rotate_right_inplace(&mut trace._aux_m_col[3], 3);
    // mixcolumns
    trace.m_col[1] = xor(trace.m_col[0], trace._aux_m_col[0]);
    trace.m_col[2] = xor(trace.m_col[1], trace._aux_m_col[1]);
    trace.m_col[3] = xor(trace.m_col[2], trace._aux_m_col[2]);
    trace.m_col[4] = xor(trace.m_col[3], trace._aux_m_col[3]);
    trace.start = xor(trace.m_col[4], key);
    trace
}

#[test]
fn test_mixcolumns() {
    let state = *b"63\x9dP\xf9\xb59&\x9f,\t-\xc4@m#";
    let expected = *b"\xf4\xbc\xd4T2\xe5T\xd0u\xf1\xd6\xc5\x1d\xd0;<";
    let got = mixcolumns(state);

    assert_eq!(got, expected);
}

#[test]
fn test_aes_round_trace() {
    let state = *b"\xc8\x16w\xbc\x9bz\xc9;%\x02y\x92\xb0&\x19\x96";
    let expected = *b"\xc6/\xe1\t\xf7^\xed\xc3\xccy9]\x84\xf9\xcf]";
    let round_key = *b"^9\x0f}\xf7\xa6\x92\x96\xa7U=\xc1\n\xa3\x1fk";

    let got = aes_round_trace(state, round_key);
    let naive = aes_round(state, round_key);

    assert_eq!(naive, expected);
    assert_eq!(got.start, expected);
}

#[test]
fn test_keyschedule_trace() {
    let key = [0u8; 16];
    let last_expected = b"\xb4\xef\x5b\xcb\x3e\x92\xe2\x11\x23\xe9\x51\xcf\x6f\x8f\x18\x8e".clone();
    let trace = keyschedule_trace(&key);
    let keys = trace._keys;
    assert_eq!(&trace.k_sch[1][10], &last_expected[..4]);
    assert_eq!(&trace.k_sch[2][10], &last_expected[4..8]);
    assert_eq!(&trace.k_sch[3][10], &last_expected[8..12]);
    assert_eq!(&trace.k_sch[4][10], &last_expected[12..]);
    assert_eq!(keys[10], last_expected);
    assert_eq!(keys[0], key);
}

#[test]
fn test_keyschedule() {
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
    let got = keyschedule(&key);
    assert_eq!(got[0], expected[0]);
    assert_eq!(got[1], expected[1]);
    assert_eq!(got, expected);
}

#[test]
fn test_aes128() {
    let message: [u8; 16] = *b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff";
    let key: [u8; 16] = *b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";

    let keys = keyschedule(&key);
    let expected = *b"\x00\x10 0@P`p\x80\x90\xa0\xb0\xc0\xd0\xe0\xf0";
    let state = xor(message, keys[0]);
    assert_eq!(
        expected,
        state,
        "\n{}\n{}",
        hex::encode(expected),
        hex::encode(state)
    );

    let state = sbox(state);
    let expected = *b"c\xca\xb7\x04\tS\xd0Q\xcd`\xe0\xe7\xbap\xe1\x8c";
    assert_eq!(
        expected,
        state,
        "\n{}\n{}",
        hex::encode(expected),
        hex::encode(state)
    );

    let state = shiftrows(state);
    let expected = *b"cS\xe0\x8c\t`\xe1\x04\xcdp\xb7Q\xba\xca\xd0\xe7";
    assert_eq!(
        expected,
        state,
        "\n{}\n{}",
        hex::encode(expected),
        hex::encode(state)
    );

    let state = mixcolumns(state);
    let expected = *b"_rd\x15W\xf5\xbc\x92\xf7\xbe;)\x1d\xb9\xf9\x1a";
    assert_eq!(
        expected,
        state,
        "\n{}\n{}",
        hex::encode(expected),
        hex::encode(state)
    );

    let state = xor(state, keys[1]);
    let expected = *b"\x89\xd8\x10\xe8\x85Z\xceh-\x18C\xd8\xcb\x12\x8f\xe4";
    assert_eq!(
        expected,
        state,
        "\n{}\n{}",
        hex::encode(expected),
        hex::encode(state)
    );

    let state = sbox(state);
    let state = shiftrows(state);
    let expected = *b"\xa7\xbe\x1ai\x97\xads\x9b\xd8\xc9\xcaE\x1fa\x8ba";
    assert_eq!(
        expected,
        state,
        "\n{}\n{}",
        hex::encode(expected),
        hex::encode(state)
    );

    let state = mixcolumns(state);
    let expected = *b"\xff\x87\x96\x841\xd8jQdQQ\xfaw:\xd0\t";
    assert_eq!(
        expected,
        state,
        "\n{}\n{}",
        hex::encode(expected),
        hex::encode(state)
    );

    let state = xor(state, keys[2]);
    let expected = *b"I\x15Y\x8fU\xe5\xd7\xa0\xda\xca\x94\xfa\x1f\nc\xf7";
    assert_eq!(
        expected,
        state,
        "\n{}\n{}",
        hex::encode(expected),
        hex::encode(state)
    );

    let got = aes128(message, key);
    let expected: [u8; 16] = *b"i\xc4\xe0\xd8j{\x040\xd8\xcd\xb7\x80p\xb4\xc5Z";
    assert_eq!(got, expected);
    let witness = aes128_trace(message, key);
    assert_eq!(witness.output, expected);
}

#[test]
fn test_aes128_wiring() {
    let message: [u8; 16] = *b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff";
    let key: [u8; 16] = *b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";

    let got = aes128(message, key);
    let expected: [u8; 16] = *b"i\xc4\xe0\xd8j{\x040\xd8\xcd\xb7\x80p\xb4\xc5Z";
    assert_eq!(got, expected);
    let witness = aes128_trace(message, key);
    assert_eq!(witness.output, expected);

    // check a bit more in-depth the trace.
    let round_keys = keyschedule(&key);
    let start0 = xor(message, round_keys[0]);
    assert_eq!(start0, witness.start[..16]);
}
