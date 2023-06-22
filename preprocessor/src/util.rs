
pub fn pad_to_ssz_chunk(le_bytes: &[u8]) -> Vec<u8> {
    assert!(le_bytes.len() <= 32);
    let mut chunk = le_bytes.to_vec();
    chunk.resize(32, 0);
    chunk
}
