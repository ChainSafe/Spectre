#[derive(Debug, Clone)]
pub enum HashInput {
    Single(Vec<u8>),
    MerklePair(Vec<u8>, Vec<u8>),
}
