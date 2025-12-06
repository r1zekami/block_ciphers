pub fn permutation_64(data: u64, table: &[u8]) -> u64 {
    let mut result: u64 = 0;
    for i in 0..64 {
        let bit = (data >> (64 - table[i])) & 1;
        result |= bit << (63 - i);
    }
    result
}

pub fn compression_64_to_56(data: u64, table: &[u8]) -> u64 {
    let mut result: u64 = 0;
    for i in 0..56 {
        let bit = (data >> (64 - table[i])) & 1;
        result |= bit << (55 - i);
    }
    result
}

pub fn compression_56_to_48(data: u64, table: &[u8]) -> u64 {
    let mut result: u64 = 0;
    for i in 0..48 {
        let bit = (data >> (56 - table[i])) & 1;
        result |= bit << (47 - i);
    }
    result
}

pub fn expansion_32_to_48(data: u32, table: &[u8]) -> u64 {
    let mut result: u64 = 0;
    for i in 0..table.len() {
        let pos: u8 = table[i];
        let bit: u32 = (data >> (32 - pos)) & 1;
        result |= (bit as u64) << (47 - i);
    } // 0x00000..abced
    return result;
}


pub fn permutation_32(data: u32, table: &[u8]) -> u32 {
    let mut result: u32 = 0;
    for i in 0..32 {
        let bit = (data >> (32 - table[i])) & 1;
        result |= bit << (31 - i);
    }
    result
}


pub fn s_boxes_substitution(input: u64, s_boxes: &[[[u8; 16]; 4]; 8]) -> u32 {
    let mut result = 0u32;
    for i in 0..8 {
        let six_bits = ((input >> (42 - 6 * i)) & 0x3F) as usize;
        let row = ((six_bits & 0x20) >> 4) | (six_bits & 0x01);
        let col = (six_bits & 0x1E) >> 1;
        let sbox_value = s_boxes[i][row as usize][col as usize];
        result = (result << 4) | sbox_value as u32;
    }
    result  
}
