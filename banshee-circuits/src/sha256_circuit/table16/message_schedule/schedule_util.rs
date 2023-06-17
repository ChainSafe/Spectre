use super::super::AssignedBits;
use super::MessageScheduleConfig;
use halo2_proofs::{
    circuit::{Region, Value},
    plonk::Error,
};
use eth_types::Field;

#[cfg(test)]
use super::super::{super::BLOCK_SIZE, BlockWord, ROUNDS};

// Rows needed for each gate
pub const DECOMPOSE_0_ROWS: usize = 2;
pub const DECOMPOSE_1_ROWS: usize = 2;
pub const DECOMPOSE_2_ROWS: usize = 3;
pub const DECOMPOSE_3_ROWS: usize = 2;
pub const SIGMA_0_V1_ROWS: usize = 4;
pub const SIGMA_0_V2_ROWS: usize = 4;
pub const SIGMA_1_V1_ROWS: usize = 4;
pub const SIGMA_1_V2_ROWS: usize = 4;

// Rows needed for each subregion
pub const SUBREGION_0_LEN: usize = 1; // W_0
pub const SUBREGION_0_ROWS: usize = SUBREGION_0_LEN * DECOMPOSE_0_ROWS;
pub const SUBREGION_1_WORD: usize = DECOMPOSE_1_ROWS + SIGMA_0_V1_ROWS;
pub const SUBREGION_1_LEN: usize = 13; // W_[1..14]
pub const SUBREGION_1_ROWS: usize = SUBREGION_1_LEN * SUBREGION_1_WORD;
pub const SUBREGION_2_WORD: usize = DECOMPOSE_2_ROWS + SIGMA_0_V2_ROWS + SIGMA_1_V2_ROWS;
pub const SUBREGION_2_LEN: usize = 35; // W_[14..49]
pub const SUBREGION_2_ROWS: usize = SUBREGION_2_LEN * SUBREGION_2_WORD;
pub const SUBREGION_3_WORD: usize = DECOMPOSE_3_ROWS + SIGMA_1_V1_ROWS;
pub const SUBREGION_3_LEN: usize = 13; // W[49..62]
pub const SUBREGION_3_ROWS: usize = SUBREGION_3_LEN * SUBREGION_3_WORD;
// pub const SUBREGION_4_LEN: usize = 2; // W_[62..64]
// pub const SUBREGION_4_ROWS: usize = SUBREGION_4_LEN * DECOMPOSE_0_ROWS;

/// Returns row number of a word
pub fn get_word_row(word_idx: usize) -> usize {
    assert!(word_idx <= 63);
    if word_idx == 0 {
        0
    } else if (1..=13).contains(&word_idx) {
        SUBREGION_0_ROWS + SUBREGION_1_WORD * (word_idx - 1) as usize
    } else if (14..=48).contains(&word_idx) {
        SUBREGION_0_ROWS + SUBREGION_1_ROWS + SUBREGION_2_WORD * (word_idx - 14) + 1
    } else if (49..=61).contains(&word_idx) {
        SUBREGION_0_ROWS
            + SUBREGION_1_ROWS
            + SUBREGION_2_ROWS
            + SUBREGION_3_WORD * (word_idx - 49) as usize
    } else {
        SUBREGION_0_ROWS
            + SUBREGION_1_ROWS
            + SUBREGION_2_ROWS
            + SUBREGION_3_ROWS
            + DECOMPOSE_0_ROWS * (word_idx - 62) as usize
    }
}

/// Test vector: "abc"
#[cfg(test)]
pub fn msg_schedule_test_input() -> [BlockWord; BLOCK_SIZE] {
    [
        BlockWord(Value::known(0b01100001011000100110001110000000)),
        BlockWord(Value::known(0b00000000000000000000000000000000)),
        BlockWord(Value::known(0b00000000000000000000000000000000)),
        BlockWord(Value::known(0b00000000000000000000000000000000)),
        BlockWord(Value::known(0b00000000000000000000000000000000)),
        BlockWord(Value::known(0b00000000000000000000000000000000)),
        BlockWord(Value::known(0b00000000000000000000000000000000)),
        BlockWord(Value::known(0b00000000000000000000000000000000)),
        BlockWord(Value::known(0b00000000000000000000000000000000)),
        BlockWord(Value::known(0b00000000000000000000000000000000)),
        BlockWord(Value::known(0b00000000000000000000000000000000)),
        BlockWord(Value::known(0b00000000000000000000000000000000)),
        BlockWord(Value::known(0b00000000000000000000000000000000)),
        BlockWord(Value::known(0b00000000000000000000000000000000)),
        BlockWord(Value::known(0b00000000000000000000000000000000)),
        BlockWord(Value::known(0b00000000000000000000000000011000)),
    ]
}

#[cfg(test)]
pub const MSG_SCHEDULE_TEST_OUTPUT: [u32; ROUNDS] = [
    0b01100001011000100110001110000000,
    0b00000000000000000000000000000000,
    0b00000000000000000000000000000000,
    0b00000000000000000000000000000000,
    0b00000000000000000000000000000000,
    0b00000000000000000000000000000000,
    0b00000000000000000000000000000000,
    0b00000000000000000000000000000000,
    0b00000000000000000000000000000000,
    0b00000000000000000000000000000000,
    0b00000000000000000000000000000000,
    0b00000000000000000000000000000000,
    0b00000000000000000000000000000000,
    0b00000000000000000000000000000000,
    0b00000000000000000000000000000000,
    0b00000000000000000000000000011000,
    0b01100001011000100110001110000000,
    0b00000000000011110000000000000000,
    0b01111101101010000110010000000101,
    0b01100000000000000000001111000110,
    0b00111110100111010111101101111000,
    0b00000001100000111111110000000000,
    0b00010010110111001011111111011011,
    0b11100010111000101100001110001110,
    0b11001000001000010101110000011010,
    0b10110111001101100111100110100010,
    0b11100101101111000011100100001001,
    0b00110010011001100011110001011011,
    0b10011101001000001001110101100111,
    0b11101100100001110010011011001011,
    0b01110000001000010011100010100100,
    0b11010011101101111001011100111011,
    0b10010011111101011001100101111111,
    0b00111011011010001011101001110011,
    0b10101111111101001111111111000001,
    0b11110001000010100101110001100010,
    0b00001010100010110011100110010110,
    0b01110010101011111000001100001010,
    0b10010100000010011110001100111110,
    0b00100100011001000001010100100010,
    0b10011111010001111011111110010100,
    0b11110000101001100100111101011010,
    0b00111110001001000110101001111001,
    0b00100111001100110011101110100011,
    0b00001100010001110110001111110010,
    0b10000100000010101011111100100111,
    0b01111010001010010000110101011101,
    0b00000110010111000100001111011010,
    0b11111011001111101000100111001011,
    0b11001100011101100001011111011011,
    0b10111001111001100110110000110100,
    0b10101001100110010011011001100111,
    0b10000100101110101101111011011101,
    0b11000010000101000110001010111100,
    0b00010100100001110100011100101100,
    0b10110010000011110111101010011001,
    0b11101111010101111011100111001101,
    0b11101011111001101011001000111000,
    0b10011111111000110000100101011110,
    0b01111000101111001000110101001011,
    0b10100100001111111100111100010101,
    0b01100110100010110010111111111000,
    0b11101110101010111010001011001100,
    0b00010010101100011110110111101011,
];

impl<Fr: Field>  MessageScheduleConfig<Fr> {
    // Assign a word and its hi and lo halves
    pub fn assign_word_and_halves(
        &self,
        region: &mut Region<'_, Fr>,
        word: Value<u32>,
        word_idx: usize,
    ) -> Result<(AssignedBits<Fr, 32>, (AssignedBits<Fr, 16>, AssignedBits<Fr, 16>)), Error> {
        // Rename these here for ease of matching the gates to the specification.
        let a_3 = self.extras[0];
        let a_4 = self.extras[1];

        let row = get_word_row(word_idx);

        let w_lo = {
            let w_lo_val = word.map(|word| word as u16);
            AssignedBits::<Fr, 16>::assign(region, || format!("W_{}_lo", word_idx), a_3, row, w_lo_val)?
        };
        let w_hi = {
            let w_hi_val = word.map(|word| (word >> 16) as u16);
            AssignedBits::<Fr, 16>::assign(region, || format!("W_{}_hi", word_idx), a_4, row, w_hi_val)?
        };

        let word = AssignedBits::<Fr, 32>::assign(
            region,
            || format!("W_{}", word_idx),
            self.message_schedule,
            row,
            word,
        )?;

        Ok((word, (w_lo, w_hi)))
    }
}
