use crate::{
    test_types::{ByteList, ByteVector, ExecutionAddress},
    U256_BYTE_COUNT,
};
use ssz_rs::prelude::*;
use std::ops::Deref;
#[derive(Default, Debug, Clone, SimpleSerialize, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExecutionPayloadHeader<
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
> {
    pub parent_hash: Node,
    pub fee_recipient: ExecutionAddress,
    pub state_root: Node,
    pub receipts_root: Node,
    pub logs_bloom: ByteVector<BYTES_PER_LOGS_BLOOM>,
    pub prev_randao: Node,
    pub block_number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: ByteList<MAX_EXTRA_DATA_BYTES>,
    pub base_fee_per_gas: U256,
    pub block_hash: Node,
    pub transactions_root: Node,
    pub withdrawals_root: Node,
}

impl<const BYTES_PER_LOGS_BLOOM: usize, const MAX_EXTRA_DATA_BYTES: usize>
    From<
        ethereum_consensus_types::light_client::ExecutionPayloadHeader<
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    > for ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>
{
    fn from(
        header: ethereum_consensus_types::light_client::ExecutionPayloadHeader<
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    ) -> Self {
        Self {
            parent_hash: header.parent_hash,
            fee_recipient: ByteVector(
                Vector::try_from(header.fee_recipient.0.as_ref().to_vec()).unwrap(),
            ),
            state_root: header.state_root.deref().try_into().unwrap(),
            receipts_root: header.receipts_root.deref().try_into().unwrap(),
            logs_bloom: ByteVector(
                Vector::try_from(header.logs_bloom.0.as_ref().to_vec()).unwrap(),
            ),
            prev_randao: header.prev_randao,
            block_number: header.block_number,
            gas_limit: header.gas_limit,
            gas_used: header.gas_used,
            timestamp: header.timestamp,
            extra_data: ByteList(List::try_from(header.extra_data.0.as_ref().to_vec()).unwrap()),
            base_fee_per_gas: U256::from_le_bytes::<U256_BYTE_COUNT>(
                header.base_fee_per_gas.as_le_slice().try_into().unwrap(),
            ),
            block_hash: header.block_hash,
            transactions_root: header.transactions_root,

            withdrawals_root: header.withdrawals_root,
        }
    }
}
