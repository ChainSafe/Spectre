#[derive(Debug, Clone)]
pub enum HashInput {
    Single(Vec<u8>),
    TwoToOne {
        left: Vec<u8>,
        right: Vec<u8>,
        is_rlc: [bool; 2],
    },
}
