pub mod tables;
pub mod permutations;
use permutations::*;

pub struct DES {}
impl DES {

    pub fn genkey() -> u64 {
        let mut key: u64 = rand::random();
        for i in 0..8 {
            let byte_start = i * 8;
            let mut parity = 0;
            for j in 0..7 {
                parity += (key >> (byte_start + j)) & 1;
            }
            let parity_bit = parity % 2;
            key &= !(1 << (byte_start + 7));
            key |= parity_bit << (byte_start + 7);
        }
        return key
    }


    pub fn encrypt(data: u64, key: u64) -> u64 {
        let permuted_data = permutation_64(data, &tables::IP_TABLE);
        let round_keys = Self::gen_round_keys(key);

        let mut left: u32 = (permuted_data >> 32) as u32;
        let mut right: u32 = permuted_data as u32;

        for i in 0..16 {
            let round_key = round_keys[i];

            let expanded = expansion_32_to_48(right, &tables::E_TABLE);
            let xored = expanded ^ round_key;
            let substituted = s_boxes_substitution(xored, &tables::S_BOXES);
            let permuted = permutation_32(substituted, &tables::P_TABLE);
            let new_left = right;
            let new_right = left ^ permuted;

            left = new_left;
            right = new_right;
        }

        let final_block = ((right as u64) << 32) | (left as u64);
        permutation_64(final_block, &tables::FP_TABLE)
    }


    fn gen_round_keys(key: u64) -> [u64; 16] {
        let mut round_keys = [0u64; 16];
        let permuted_key = compression_64_to_56(key, &tables::PC1_TABLE);
        let mut c = (permuted_key & 0x0FFFFFFF) as u32;
        let mut d = ((permuted_key >> 28) & 0x0FFFFFFF) as u32;


        const KEY_SHIFTS: [u8; 16] = [
            1, 1, 2, 2, 2, 2, 2, 2,
            1, 2, 2, 2, 2, 2, 2, 1
        ];

        for i in 0..16 {
            let shift = KEY_SHIFTS[i];
            c = ((c << shift) | (c >> (28 - shift))) & 0x0FFFFFFF;
            d = ((d << shift) | (d >> (28 - shift))) & 0x0FFFFFFF;
            let combined = ((d as u64) << 28) | (c as u64);
            round_keys[i] = compression_56_to_48(combined, &tables::PC2_TABLE);
        }
        round_keys
    }


    pub fn decrypt(ciphertext: u64, key: u64) -> u64 {
        let permuted_data = permutation_64(ciphertext, &tables::IP_TABLE);
        let mut left: u32 = (permuted_data >> 32) as u32;
        let mut right: u32 = (permuted_data & 0xFFFFFFFF) as u32;
        let round_keys = Self::gen_round_keys(key);

        // reverse
        for i in 0..16 {
            let round_key = round_keys[15 - i];

            let expanded = expansion_32_to_48(right, &tables::E_TABLE);
            let xored = expanded ^ round_key;
            let substituted = s_boxes_substitution(xored, &tables::S_BOXES);
            let permuted = permutation_32(substituted, &tables::P_TABLE);

            let new_left = right;
            let new_right = left ^ permuted;

            left = new_left;
            right = new_right;
        }

        let final_block = ((right as u64) << 32) | (left as u64);
        permutation_64(final_block, &tables::FP_TABLE)
    }

}
