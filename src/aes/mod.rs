mod tables;
use rand::RngCore;
use rand::thread_rng;

const DEBUG: bool = false;

macro_rules! debug_log {
    ($($arg:tt)*) => {
        if DEBUG {
            println!($($arg)*);
        }
    };
}

fn format_bytes(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect::<String>()
}

fn format_state(state: &[[u8; 4]; 4]) -> String {
    let mut bytes = Vec::new();
    for col in 0..4 {
        for row in 0..4 {
            bytes.push(state[row][col]);
        }
    }
    format_bytes(&bytes)
}

// usage
// debug_log!("round[ 0].input    {}", Self::format_state(&state));

pub struct AES {}

impl AES {
    pub fn genkey(key_length_bits: u32) -> Vec<u8> {
        let valid_lengths = [128, 192, 256];
        let bytes = if valid_lengths.contains(&key_length_bits) {
            key_length_bits / 8 // use given key length
        } else {
            eprintln!( "Warning: Invalid AES key length: {} bits. Must be 128, 192, or 256. Using 256 bits instead.",
                        key_length_bits );
            32 // fallback to 256 bits
        };
        let mut key = vec![0u8; bytes as usize];
        thread_rng().fill_bytes(&mut key);
        key
    }


    pub fn encrypt(data: u128, key: Vec<u8>) -> u128 {
        debug_log!("--------------------encryption---------------------");
        let round_keys = Self::gen_round_keys(key.clone());
        let nk = key.len() / 4;
        let nr = match nk {
            4 => 10, 6 => 12, 8 => 14,
            _ => panic!("Invalid key length")
        };

        let mut state = [[0u8; 4]; 4];
        let block = data.to_be_bytes();

        //state init
        for i in 0..16 {
            state[i % 4][i / 4] = block[i];
        }

        debug_log!("round[ 0].input    {}", format_state(&state));

        Self::add_round_key(&mut state, &round_keys[0..16]);
        debug_log!("round[ 0].k_sch    {}", format_bytes(&round_keys[0..16]));
        debug_log!("round[ 1].start    {}", format_state(&state));


        for round in 1..nr {
            Self::sub_bytes(&mut state);
            debug_log!("round[{:2}].s_box    {}", round, format_state(&state));

            Self::shift_rows(&mut state);
            debug_log!("round[{:2}].s_row    {}", round, format_state(&state));

            Self::mix_columns(&mut state);
            debug_log!("round[{:2}].m_col    {}", round, format_state(&state));

            Self::add_round_key(&mut state, &round_keys[round * 16..(round + 1) * 16]);
            debug_log!("round[{:2}].k_sch    {}", round, format_bytes(&round_keys[round * 16..(round + 1) * 16]));

            debug_log!("round[{:2}].start    {}", round + 1, format_state(&state));
        }

        // no mix cols
        Self::sub_bytes(&mut state);
        debug_log!("round[{:2}].s_box    {}", nr, format_state(&state));

        Self::shift_rows(&mut state);
        debug_log!("round[{:2}].s_row    {}", nr, format_state(&state));

        Self::add_round_key(&mut state, &round_keys[nr * 16..(nr + 1) * 16]);
        debug_log!("round[{:2}].k_sch    {}", nr, format_bytes(&round_keys[nr * 16..(nr + 1) * 16]));

        let result = Self::state_to_u128(&state);
        debug_log!("round[{:2}].output   {:032x}", nr, result);

        result
    }


    pub fn decrypt(ciphertext: u128, key: Vec<u8>) -> u128 {
        debug_log!("--------------------decryption---------------------");

        let round_keys = Self::gen_round_keys(key.clone());
        let nk = key.len() / 4;
        let nr = match nk {
            4 => 10, 6 => 12, 8 => 14,
            _ => panic!("Invalid key length")
        };

        let mut state = [[0u8; 4]; 4];
        let block = ciphertext.to_be_bytes();

        for i in 0..16 {
            state[i % 4][i / 4] = block[i];
        }

        debug_log!("round[{}].input    {}", nr, format_state(&state));
        Self::add_round_key(&mut state, &round_keys[nr * 16..(nr + 1) * 16]);
        debug_log!("round[{}].k_sch    {}", nr, format_bytes(&round_keys[nr * 16..(nr + 1) * 16]));
        debug_log!("round[{:2}].start    {}", nr, format_state(&state));

        for round in (1..nr).rev() {
            Self::inv_shift_rows(&mut state);
            debug_log!("round[{:2}].is_row    {}", round + 1, format_state(&state));

            Self::inv_sub_bytes(&mut state);
            debug_log!("round[{:2}].is_box    {}", round + 1, format_state(&state));

            Self::add_round_key(&mut state, &round_keys[round * 16..(round + 1) * 16]);
            debug_log!("round[{:2}].ik_sch    {}", round, format_bytes(&round_keys[round * 16..(round + 1) * 16]));
            debug_log!("round[{:2}].istart    {}", round, format_state(&state));

            Self::inv_mix_columns(&mut state);
            debug_log!("round[{:2}].im_col    {}", round, format_state(&state));
        }

        Self::inv_shift_rows(&mut state);
        debug_log!("round[ 1].is_row    {}", format_state(&state));

        Self::inv_sub_bytes(&mut state);
        debug_log!("round[ 1].is_box    {}", format_state(&state));

        Self::add_round_key(&mut state, &round_keys[0..16]);
        debug_log!("round[ 0].ik_sch    {}", format_bytes(&round_keys[0..16]));

        let result = Self::state_to_u128(&state);
        debug_log!("round[ 0].output   {:032x}", result);

        result
    }

    fn state_to_u128(state: &[[u8; 4]; 4]) -> u128 {
        let mut result = 0u128;
        for i in 0..16 {
            result |= (state[i % 4][i / 4] as u128) << (120 - 8 * i);
        }
        result
    }

    fn gen_round_keys(key: Vec<u8>) -> Vec<u8> {
        // Nk = key_length / 32

        let nk: usize = key.len() / 4;
        let nr: usize = match nk {
            4 => 10, //128
            6 => 12, //192
            8 => 14, //256
            _ => panic!("Unexpected AES key length at 'gen_round_keys'")
        };

        let words_needed = (nr + 1) * 4; // 44, 52, 60 words
        let mut w = vec![[0u8; 4]; words_needed];

        //initial copy
        for i in 0..nk {  w[i] = [key[4*i], key[4*i + 1], key[4*i + 2], key[4*i + 3]];  }

        for i in nk..words_needed {
            let mut temp = w[i - 1];

            /*
            It is important to note that the Key Expansion routine for 256-bit Cipher Keys (Nk = 8) is
            slightly different than for 128- and 192-bit Cipher Keys. If Nk = 8 and i-4 is a multiple of Nk,
            then SubWord() is applied to w[i-1] prior to the XOR.
            */

            if i % nk == 0 {
                temp = Self::sub_word(Self::rot_word(temp));
                temp[0] ^= tables::RCON_TABLE[(i / nk) - 1]; // Rcon[i]
            } else if (nk == 8) && (i % 8 == 4) { //256 case
                temp = Self::sub_word(temp);
            }

            for j in 0..4 { w[i][j] = w[i - nk][j] ^ temp[j]; }

        }

        let mut round_keys = Vec::with_capacity(words_needed * 4);

        for word in w {
            round_keys.extend_from_slice(&word);
        }

        round_keys
    }


    fn rot_word(word: [u8; 4]) -> [u8; 4] {
    // The function RotWord() takes a word [a0,a1,a2,a3] as input,
    // performs a cyclic permutation, and returns the word [a1,a2,a3,a0].
        [word[1], word[2], word[3], word[0]]
    }


    fn sub_word(word: [u8; 4]) -> [u8; 4] {
    // SubWord() is a function that takes a four-byte input word and applies the S-box
        [
            tables::S_BOX_TABLE[word[0] as usize],
            tables::S_BOX_TABLE[word[1] as usize],
            tables::S_BOX_TABLE[word[2] as usize],
            tables::S_BOX_TABLE[word[3] as usize],
        ]
    }


    fn add_round_key(state: &mut [[u8; 4]; 4], round_key: &[u8]) {
        for col in 0..4 {
            for row in 0..4 {
                state[row][col] ^= round_key[col * 4 + row];
            }
        }
    }

    fn sub_bytes(state: &mut [[u8; 4]; 4]) {
        for row in 0..4 {
            for col in 0..4 {
                state[row][col] = tables::S_BOX_TABLE[state[row][col] as usize];
            }
        }
    }

    fn inv_sub_bytes(state: &mut [[u8; 4]; 4]) {
        for row in 0..4 {
            for col in 0..4 {
                state[row][col] = tables::INV_S_BOX_TABLE[state[row][col] as usize];
            }
        }
    }

    fn shift_rows(state: &mut [[u8; 4]; 4]) {
        state[1].rotate_left(1);
        state[2].rotate_left(2);
        state[3].rotate_right(1);
    }

    fn inv_shift_rows(state: &mut [[u8; 4]; 4]) {
        state[1].rotate_right(1);
        state[2].rotate_right(2);
        state[3].rotate_left(1);
    }

    fn mix_columns(state: &mut [[u8; 4]; 4]) {
        for i in 0..4 {

            let mut temp = [0u8;4];
            for j in 0..4 { temp[j] = state[j][i]; }

            state[0][i] = Self::gf_multiply(temp[0], 2) ^ Self::gf_multiply(temp[3], 1) ^ Self::gf_multiply(temp[2], 1) ^ Self::gf_multiply(temp[1], 3);
            state[1][i] = Self::gf_multiply(temp[1], 2) ^ Self::gf_multiply(temp[0], 1) ^ Self::gf_multiply(temp[3], 1) ^ Self::gf_multiply(temp[2], 3);
            state[2][i] = Self::gf_multiply(temp[2], 2) ^ Self::gf_multiply(temp[1], 1) ^ Self::gf_multiply(temp[0], 1) ^ Self::gf_multiply(temp[3], 3);
            state[3][i] = Self::gf_multiply(temp[3], 2) ^ Self::gf_multiply(temp[2], 1) ^ Self::gf_multiply(temp[1], 1) ^ Self::gf_multiply(temp[0], 3);
        }
    }


    fn inv_mix_columns(state: &mut [[u8; 4]; 4]) {
        for i in 0..4 {

            let mut temp = [0u8;4];
            for j in 0..4 { temp[j] = state[j][i]; }

            state[0][i] = Self::gf_multiply(temp[0], 14) ^ Self::gf_multiply(temp[3], 9) ^ Self::gf_multiply(temp[2], 13) ^ Self::gf_multiply(temp[1], 11);
            state[1][i] = Self::gf_multiply(temp[1], 14) ^ Self::gf_multiply(temp[0], 9) ^ Self::gf_multiply(temp[3], 13) ^ Self::gf_multiply(temp[2], 11);
            state[2][i] = Self::gf_multiply(temp[2], 14) ^ Self::gf_multiply(temp[1], 9) ^ Self::gf_multiply(temp[0], 13) ^ Self::gf_multiply(temp[3], 11);
            state[3][i] = Self::gf_multiply(temp[3], 14) ^ Self::gf_multiply(temp[2], 9) ^ Self::gf_multiply(temp[1], 13) ^ Self::gf_multiply(temp[0], 11);
        }
    }


    fn gf_multiply(a: u8, b: u8) -> u8 {
        let mut p = 0u8;
        let mut high_bit = 0u8;
        let mut a = a;
        let mut b = b;
        for _ in 0..8 {
            if b & 1 == 1 {
                p ^= a;
            }
            high_bit = a & 0x80;
            a <<= 1;
            if high_bit == 0x80 {
                a ^= 0x1b;
            }
            b >>= 1;
        }
        p
    }


}
