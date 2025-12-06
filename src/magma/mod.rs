pub struct MAGMA;

const DEBUG: bool = false;

macro_rules! debug_log {
    ($($arg:tt)*) => {
        if DEBUG {
            println!($($arg)*);
        }
    };
}


impl MAGMA {
    pub const PI_TABLE: [[u8; 16]; 8] = [
        [12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1],
        [6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15],
        [11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0],
        [12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11],
        [7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12],
        [5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0],
        [8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7],
        [1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2],
    ];


    pub fn decrypt(ciphertext: u64, key: [u8; 32]) -> u64 {
        let mut right: u32 = ciphertext as u32;
        let mut left: u32 = (ciphertext >> 32) as u32;
        let round_keys = Self::gen_round_keys(key);

        left ^= Self::g(right, round_keys[31]);

        for i in 0..31 {
            let tmp = left;
            left = right ^ Self::g(tmp, round_keys[30 - i]);
            right = tmp;
        }

        ((left as u64) << 32) | (right as u64)
    }

    pub fn encrypt(plaintext: u64, key: [u8; 32]) -> u64 {
        let mut right: u32 = plaintext as u32;
        let mut left: u32 = (plaintext >> 32) as u32;
        let round_keys = Self::gen_round_keys(key);

        debug_log!("(a1, a0) = ({:08x}, {:08x})", left, right);

        for i in 0..31 {
            let new_left = right;
            let new_right = left ^ Self::g(right, round_keys[i]);

            debug_log!("G[K{}]...G[K1](a1, a0) = ({:08x}, {:08x})", i+1, new_left, new_right);

            left = new_left;
            right = new_right;
        }

        let last_g_res = Self::g(right, round_keys[31]);
        left = left ^ last_g_res;

        debug_log!("G[K32] ({:08x}, {:08x})", left, right);

        let result = ((left as u64) << 32) | (right as u64);
        result
    }


    fn gen_round_keys(key: [u8; 32]) -> [u32; 32] {
        let mut round_keys = [0u32; 32];
        let mut k = [0u32; 8]; // K1 K2 K3 K4 K5 K6 K7 K8
        for i in 0..8 {
            k[i] = u32::from_be_bytes( [key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]] );
        }
        for i in 0..24 { round_keys[i] = k[i % 8]; }        // K1 K2 K3 K4 K5 K6 K7 K8
        for i in 0..8  { round_keys[24 + i] = k[7 - i]; }   // K8 K7 K6 K5 K4 K3 K2 K1
        round_keys
    }


    fn g(data: u32, key: u32) -> u32 {
        Self::t(data.wrapping_add(key)).rotate_left(11)
    }


    fn t(value: u32) -> u32 {
        let mut result = 0u32;
        for i in 0..8 {
            let block = (value >> (4 * i)) & 0xF;
            let substituted: u32 = Self::PI_TABLE[i][block as usize] as u32;
            result |= substituted << (4 * i);
        }
        //debug_log!("t({:08x}) = {:08x}", value, result);
        result
    }
}
