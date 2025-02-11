use super::keyschedule::{aes128_keyschedule, aes256_keyschedule, keyschedule};
use super::utils::{mixcolumns, rotate_right_inplace, sbox, shiftrows, xor, RJ2};

#[cfg(test)]
use hex_literal::hex;

fn aes_round(mut state: [u8; 16], round_key: [u8; 16]) -> [u8; 16] {
    // Note: shiftrows before sbox
    state = shiftrows(state);
    state = sbox(state);
    state = mixcolumns(state);
    xor(state, round_key)
}

/// Naive implementation of AES-128
fn aes<const R: usize, const N: usize, const L: usize>(
    message: [u8; 16],
    key: [u8; L],
) -> [u8; 16] {
    debug_assert!((R == 11 && N == 4 && L == 16) || (R == 15 && N == 8 && L == 32));
    let keys = keyschedule::<R, N>(&key);

    let mut state = xor(message, keys[0]);
    for i in 1..R - 1 {
        state = aes_round(state, keys[i]);
    }
    let state = sbox(shiftrows(state));
    xor(state, keys[R - 1])
}

/// Naive implementation of AES-128
#[inline]
pub fn aes128(message: [u8; 16], key: [u8; 16]) -> [u8; 16] {
    aes::<11, 4, 16>(message, key)
}

/// Naive implementation of AES-256
#[inline]
pub fn aes256(message: [u8; 16], key: [u8; 32]) -> [u8; 16] {
    aes::<15, 8, 32>(message, key)
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
#[derive(Default, Clone)]
pub struct AesCipherTrace {
    pub message: [u8; 16],
    pub key: [u8; 16],
    // cipher variables
    pub start: Vec<u8>,
    pub s_box: Vec<u8>,
    pub m_col: [Vec<u8>; 5],
    // last round
    pub output: [u8; 16],
    // key schedule permutations
    pub _keys: Vec<[u8; 16]>,
    // cipher permutations
    pub _s_row: Vec<u8>,
    pub _aux_m_col: [Vec<u8>; 4],
}

impl AesCipherTrace {
    pub fn add_round(&mut self, round_trace: &RoundTrace) {
        self._s_row.extend(&round_trace._s_row);
        self.s_box.extend(&round_trace.s_box);
        (0..5).for_each(|i| self.m_col[i].extend(&round_trace.m_col[i]));
        self.start.extend(&round_trace.start);
        (0..4).for_each(|i| self._aux_m_col[i].extend(&round_trace._aux_m_col[i]));
    }

    pub fn add_finalround(&mut self, trace: [[u8; 16]; 3]) {
        let [_final_s_row, final_s_box, output] = trace;
        self._s_row.extend(_final_s_row);
        self.s_box.extend(final_s_box);
        self.output = output;
    }

    pub fn new_aes128(message: [u8; 16], key: [u8; 16]) -> AesCipherTrace {
        let round_keys = aes128_keyschedule(&key);
        aes_trace(message, &round_keys)
    }

    pub fn new_aes256(message: [u8; 16], key: [u8; 32]) -> AesCipherTrace {
        let round_keys = aes256_keyschedule(&key);
        aes_trace(message, &round_keys)
    }
}

pub(crate) fn aes_trace<const R: usize>(
    message: [u8; 16],
    round_keys: &[[u8; 16]; R],
) -> AesCipherTrace {
    let mut witness = AesCipherTrace::default();
    witness.message = message;
    witness.key = round_keys[0];
    witness._keys = round_keys.to_vec();

    // first round: add key to message
    let mut round_state = xor(message, round_keys[0]);
    // put the first message into the key schedule artificially.
    // The verifier will do the same using the statement
    witness.start.extend(&round_state);
    #[allow(clippy::needless_range_loop)]
    for i in 1..R - 1 {
        let round_trace = aes_round_trace(round_state, round_keys[i]);
        witness.add_round(&round_trace);
        round_state = round_trace.start;
    }
    witness.add_finalround(final_round_trace(round_state, round_keys[R - 1]));
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
        trace.m_col[0][i] = RJ2[x as usize];
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
fn test_aes_round_trace() {
    let state = hex!("c81677bc9b7ac93b25027992b0261996");
    let expected = hex!("c62fe109f75eedc3cc79395d84f9cf5d");
    let round_key = hex!("5e390f7df7a69296a7553dc10aa31f6b");

    let got = aes_round_trace(state, round_key);
    let naive = aes_round(state, round_key);

    assert_eq!(naive, expected);
    assert_eq!(got.start, expected);
}

#[test]
fn test_aes128() {
    let message: [u8; 16] = hex!("00112233445566778899aabbccddeeff");
    let key: [u8; 16] = hex!("000102030405060708090a0b0c0d0e0f");

    let keys = aes128_keyschedule(&key);
    let expected = hex!("00102030405060708090a0b0c0d0e0f0");
    let state = xor(message, keys[0]);
    assert_eq!(
        expected,
        state,
        "\n{}\n{}",
        hex::encode(expected),
        hex::encode(state)
    );

    let state = sbox(state);
    let expected = hex!("63cab7040953d051cd60e0e7ba70e18c");
    assert_eq!(
        expected,
        state,
        "\n{}\n{}",
        hex::encode(expected),
        hex::encode(state)
    );

    let state = shiftrows(state);
    let expected = hex!("6353e08c0960e104cd70b751bacad0e7");
    assert_eq!(
        expected,
        state,
        "\n{}\n{}",
        hex::encode(expected),
        hex::encode(state)
    );

    let state = mixcolumns(state);
    let expected = hex!("5f72641557f5bc92f7be3b291db9f91a");
    assert_eq!(
        expected,
        state,
        "\n{}\n{}",
        hex::encode(expected),
        hex::encode(state)
    );

    let state = xor(state, keys[1]);
    let expected = hex!("89d810e8855ace682d1843d8cb128fe4");
    assert_eq!(
        expected,
        state,
        "\n{}\n{}",
        hex::encode(expected),
        hex::encode(state)
    );

    let state = sbox(state);
    let state = shiftrows(state);
    let expected = hex!("a7be1a6997ad739bd8c9ca451f618b61");
    assert_eq!(
        expected,
        state,
        "\n{}\n{}",
        hex::encode(expected),
        hex::encode(state)
    );

    let state = mixcolumns(state);
    let expected = hex!("ff87968431d86a51645151fa773ad009");
    assert_eq!(
        expected,
        state,
        "\n{}\n{}",
        hex::encode(expected),
        hex::encode(state)
    );

    let state = xor(state, keys[2]);
    let expected = hex!("4915598f55e5d7a0daca94fa1f0a63f7");
    assert_eq!(
        expected,
        state,
        "\n{}\n{}",
        hex::encode(expected),
        hex::encode(state)
    );

    let got = aes128(message, key);
    let expected: [u8; 16] = hex!("69c4e0d86a7b0430d8cdb78070b4c55a");
    assert_eq!(got, expected);
    let witness = AesCipherTrace::new_aes128(message, key);
    assert_eq!(witness.output, expected);
}

#[test]
fn test_aes256() {
    let message: [u8; 16] = hex!("00112233445566778899aabbccddeeff");
    let key: [u8; 32] = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let expected = hex!("8ea2b7ca516745bfeafc49904b496089");

    let round_keys = aes256_keyschedule(&key);
    let state = xor(message, round_keys[0]);
    assert_eq!(state, hex!("00102030405060708090a0b0c0d0e0f0"));
    let state = aes_round(state, round_keys[1]);
    assert_eq!(state, hex!("4f63760643e0aa85efa7213201a4e705"));
    let state = shiftrows(sbox(state));
    assert_eq!(state, hex!("84e1fd6b1a5c946fdf4938977cfbac23"));
    let state = mixcolumns(state);
    assert_eq!(state, hex!("bd2a395d2b6ac438d192443e615da195"));

    let got = aes256(message, key);
    assert_eq!(got, expected);
}

#[test]
fn test_aes128_wiring() {
    let message: [u8; 16] = hex!("00112233445566778899aabbccddeeff");
    let key: [u8; 16] = hex!("000102030405060708090a0b0c0d0e0f");

    let got = aes128(message, key);
    let expected: [u8; 16] = hex!("69c4e0d86a7b0430d8cdb78070b4c55a");
    assert_eq!(got, expected);
    let witness = AesCipherTrace::new_aes128(message, key);
    assert_eq!(witness.output, expected);

    // check a bit more in-depth the trace.
    let round_keys = aes128_keyschedule(&key);
    let start0 = xor(message, round_keys[0]);
    assert_eq!(start0, witness.start[..16]);
}
