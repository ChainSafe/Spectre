## SHA256 Circuit

```rust
pub struct Sha256 {
    chip: Table16Chip,
    state: State,
}
```

References:
- https://github.com/ChainSafe/recursive-zk-bridge/blob/main/halo2/src/sha256.rs
- github.com/sorasuegami/halo2-dynamic-sha256
- https://github.com/duguorong009/zk-mooc-halo2
- https://github.com/scroll-tech/zkevm-circuits/pull/398
