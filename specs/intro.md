# Introduction

The aim of `BansheeZK` protocol is to produce a succinct non-interactive proof for a finalized checkpoint (block root + epoch) of some origin chain running the Casper finality protocol. 

The applications can then use the verified `state_root` to approve internal state-transition within the execution of the destination chain based on the events occurred in that origin chain.