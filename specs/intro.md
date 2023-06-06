# Introduction

The aim of the BansheeZK protocol is to produce a succinct non-interactive proof for a finalized checkpoint (block root + epoch) on some origin chain running the Casper finality protocol.

The sub-goals for this are:
1. To minimize public inputs size to reduce storage costs on the destination chain.
2. To minimize the time between checkpoint finalization on the origin chain and it being verified on the destination.
3. To leverage as much as possible hardware acceleration.

## Complexity

As BansheeZK targets the Casper FFG protocol is bears the weight of its complexity that grows significantly with scale. 

The biggest bottlenecks are:
1. Number of validators: ~600k and counting.
2. Short time window to follow the chain: each epoch is 6.4 mins.
3. Abundance of SNARK-unfriendly cryptography:
	- SHA256
	- Point decompression
	- Pairing BLS12-381

## Use cases

The applications can use the verified `state_root` to approve internal state-transition within the execution of the destination chain based on the events occurred on one or more origin chains. This essentially requires checking that a particular transaction or variable of the application contract state is presented in the Merkle tree that has a root equal to the one in relayed block header. 

> **Note:** Since [`BeaconState`](https://eth2book.info/capella/annotated-spec/#beaconstate) contains [`eth1_data.block_hash`](https://eth2book.info/capella/annotated-spec/#eth1data) by establishing a trusted `state_root` it's enough for developers to check events on both execution (Eth1 chain) and consensus (Beacon chain) layers.
