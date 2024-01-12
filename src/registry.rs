/// Regions in the AES witness, parametrized by the number of rounds.
pub(super) struct AesWitnessRegions {
    pub start: usize,
    pub s_box: usize,
    pub m_col: [usize; 5],
    pub message: usize,
    pub round_keys: usize,
    pub len: usize,
    pub needles_len: usize,
}

pub(super) struct AesKeySchWitnessRegions {
    pub s_box: usize,
    pub xor: usize,
    pub round_keys: usize,
    pub len: usize,
    pub needles_len: usize,
}

pub(super) const fn aes_keysch_offsets<const R: usize, const N: usize>() -> AesKeySchWitnessRegions
{
    AesKeySchWitnessRegions {
        s_box: 0,
        xor: 4 * R,
        round_keys: 4 * R + 4 * R,
        len: 16 * R + 4 * R + 4 * R,
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
/// |  .message    |  <-- from outside
/// +--------------+
/// |  .round_keys |  <-- from outside
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
pub(super) const fn aes_offsets<const R: usize>() -> AesWitnessRegions {
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
    // let addroundkey_len = 16 * 11;
    let message = m_col[4] + m_col_len;
    let round_keys = message + 16;
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
        len: round_keys + 16 * R,
        needles_len,
    }
}

#[allow(dead_code)]
pub const AES128REG: AesWitnessRegions = aes_offsets::<11>();
#[allow(dead_code)]
pub const AES256REG: AesWitnessRegions = aes_offsets::<15>();
