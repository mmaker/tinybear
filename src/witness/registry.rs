/// Regions in the AES witness, parametrized by the number of rounds.
pub struct AesWitnessRegions {
    pub start: usize,
    pub s_box: usize,
    pub m_col: [usize; 5],
    pub message: usize,
    pub round_keys: usize,
    pub witness_len: usize,
    pub full_statement_len: usize,
    pub needles_len: usize,
}

// XXX. remove unused
#[allow(unused)]
pub struct AesGCMBlockWitnessRegions {
    pub start: usize,
    pub s_box: usize,
    pub m_col: [usize; 5],
    pub aes_output: usize,
    pub counter: usize,
    pub plain_text: usize,
    pub witness_len: usize,
    // pub full_statement_len: usize,
    pub needles_len: usize,
    pub full_witness_round_keys_location: usize,
}

pub struct AesKeySchWitnessRegions {
    pub s_box: usize,
    pub xor: usize,
    pub round_keys: usize,
    pub witness_len: usize,
    pub needles_len: usize,
}

pub(crate) const fn aes_keysch_offsets<const R: usize, const N: usize>() -> AesKeySchWitnessRegions
{
    AesKeySchWitnessRegions {
        s_box: 0,
        xor: 4 * R,
        round_keys: 4 * R + 4 * R,
        witness_len: 16 * R + 4 * R + 4 * R,
        // For aes 128: 4 * (R-1) Sbox and 320 XOR
        needles_len: 4 * (R - 1) + 16 * (R - 1) * 2,
    }
}

/// The witness is structured as follows:
///
/// ```text
/// +--------------+
/// |  .start      |
/// +--------------+
/// |  .sbox       |
/// ---------------+
/// |  .m_col      |
/// +--------------+
/// |  .message    | <-- from outside
/// +--------------+
/// |  .round_keys |  <-- from outside
/// +--------------+
/// |  .output     |  <-- from outside
/// +--------------+
/// ```
///
/// where:
/// - `.start`
///   denotes the state at the end of each round, except the final one.
///   In other words, it is the round state excluding message and ciphertext.
///   Therefore, it has length 10 * 16 = 160.
/// - `.s_box`
///   denotes the state at the end of each sbox operation.
///   Therefore, it has length 10 * 16 = 160.
/// - `.m_col`
///   denotes the intermediate states of each mixcolumn operation.
///   `m_col[0]` denotes the state after multiplication by Rj(2).
///   `m_col[1]` up to `m_col[4]` denotes the state at the end of each xor operation.
///    Therefore, it has length 16 * 9 * 5 = 720.
///    (Note: the final AddRoundKey operation is not included involves `.start` and `.m_col[4]`)
/// - `.message` and `.round_keys`
///  denote message and round keys, respectively. They are given as part of the statement.
/// - `.output' denote the output of the encryption
///    Therefore it has length 16
pub(crate) const fn aes_offsets<const R: usize>() -> AesWitnessRegions {
    let start = 0;
    let s_box = start + 16 * (R - 1);
    // thank Rust for const for loops
    let m_col_offset = s_box + 16 * (R - 1);
    let m_col_len = 16 * (R - 2);
    #[allow(clippy::all)]
    let m_col = [
        m_col_offset + m_col_len * 0,
        m_col_offset + m_col_len * 1,
        m_col_offset + m_col_len * 2,
        m_col_offset + m_col_len * 3,
        m_col_offset + m_col_len * 4,
    ];
    let message = m_col[4] + m_col_len;
    let round_keys = message + 16;
    let output = round_keys + 16 * R;
    let needles_len =
            16 * (R-1) + // s_box
            16 * (R-2) + // rj2
            16 * (R-2) * 5 * 2 + // m_col xor's
            16 * 2 * 2 // addroundkey first and last
        ;

    AesWitnessRegions {
        start,
        s_box,
        m_col,
        message,
        round_keys,
        witness_len: output,
        full_statement_len: output + 16,
        needles_len,
    }
}

/// The witness is structured as follows:
///
/// ```text
/// +--------------+
/// |  .start      |
/// +--------------+
/// |  .sbox       |
/// ---------------+
/// |  .m_col      |
/// +--------------+
/// |  .aes_output |
/// +--------------+
/// |  .counter    |  <-- from outside
/// +--------------+
/// |  .plain_text |  <-- from outside
/// +--------------+
/// ```
///
/// where:
/// - `.start`
///   denotes the state at the end of each round, except the final one.
///   In other words, it is the round state excluding message and ciphertext.
///   Therefore, it has length 10 * 16 = 160.
/// - `.s_box`
///   denotes the state at the end of each sbox operation.
///   Therefore, it has length 10 * 16 = 160.
/// - `.m_col`
///   denotes the intermediate states of each mixcolumn operation.
///   `m_col[0]` denotes the state after multiplication by Rj(2).
///   `m_col[1]` up to `m_col[4]` denotes the state at the end of each xor operation.
///    Therefore, it has length 16 * 9 * 5 = 720.
///    (Note: the final AddRoundKey operation is not included involves `.start` and `.m_col[4]`)
/// - `.aes_output`
///   denotes the final xor between the encrypted counter and the plain text
///    Therefore, it has length 16
/// - `.counter` and `.plain_text`
///  denote counter and plain_text, respectively. They are given as part of the statement.
pub(crate) const fn aes_gcm_block_offsets<const R: usize>() -> AesGCMBlockWitnessRegions {
    let start = 0;
    let s_box = start + 16 * (R - 1);
    // thank Rust for const for loops
    let m_col_offset = s_box + 16 * (R - 1);
    let m_col_len = 16 * (R - 2);
    #[allow(clippy::all)]
    let m_col = [
        m_col_offset + m_col_len * 0,
        m_col_offset + m_col_len * 1,
        m_col_offset + m_col_len * 2,
        m_col_offset + m_col_len * 3,
        m_col_offset + m_col_len * 4,
    ];
    let aes_output = m_col[4] + m_col_len;
    let counter = aes_output + 16;
    let plain_text = counter + 16;
    let needles_len =
            16 * (R-1) + // s_box
            16 * (R-2) + // rj2
            16 * (R-2) * 5 * 2 + // m_col xor's
            16 * 2 * 2 + // addroundkey first and last
            16 //final xor
        ;
    let icb_region = aes_offsets::<R>();
    let round_key_loc = icb_region.round_keys;

    AesGCMBlockWitnessRegions {
        start,
        s_box,
        m_col,
        aes_output,
        counter,
        plain_text,
        witness_len: plain_text + 16,
        // full_statement_len: aes_output,
        full_witness_round_keys_location: round_key_loc,
        needles_len,
    }
}

pub const AES128REG: AesWitnessRegions = aes_offsets::<11>();
pub const AES256REG: AesWitnessRegions = aes_offsets::<15>();
pub const AES128KSREG: AesKeySchWitnessRegions = aes_keysch_offsets::<11, 4>();
