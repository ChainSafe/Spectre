# Aggregation circuit

The aggregation constraints the committees and aggregated public keys in the `StateTable` based on participation in current epoch.

Recall that each validator record in table contains `is_attested` flag that signals that validator took part in attestation. For the purposes of this circuit, `is_attested` flag is used to check that accumulated effective balance for committee and the aggregated public key is consistent with rest of the table.

> Depending on the proof generation approach and infrastructure at hand logic in this circuit can be combined together with `validators` circuit. If generated on one machine it is advised to do so. However, if distributed proof generation is considered it may be fruitful to separate these circuits.

## Circuit layout
1. `state_table`: The columns from [`StateTable`](/6B5be79aQni9TeRlxb0yIA#StateTable).
2. `pk_decompres_ext`: Extension table holding a mapping between compressed (Bytes48) encoding and uncompressed (G1Affine) public keys (see table below).
3. [`range_chip`](https://github.com/axiom-crypto/halo2-lib/blob/main/halo2-base/src/gates/range.rs#L33): Lookup table for range constraints on numbers.
4. [`ecc_chip`](https://github.com/axiom-crypto/halo2-lib/blob/main/halo2-ecc/src/ecc/mod.rs#L555): Custom gates and API for EC points addition.

| *ID*          | *Compressed* | *Affine* |
| ------------- | ------------ | -------- |
| $validatorIdx | $byte        | $x_chunk |
| ...           | ... (48)     | ... (7)  |
| ...           | ...          | $y_chunk |
| ...           | ...          | ... (7)  |

## Circuit behaviour

The circuit performs two main operations as specified below.

**Balance accumulation:**
1. Going from top of the table to bottom the circuit sequentially adds `value` of rows where `tag == 'validator' && attested == 1 && field_tag = 'Balance'` to the `value` of the first row where `tag == 'committee' && field_tag = 'Balance'` that comes after.
2. Check that `value` didn't exceeded the size of scalar field used by the prover
- This calculation is done using a custom gate $A_7(\omega^{?}x) =A_7(\omega^{?}x) + (A_3(x)-1)\cdot(A_5(x)-1)\cdot A_7(x)$
	> TODO: how to offset on a variable number of rows? 
	> is possible to use roots of unity in a variable degree such as $\omega^{(2048*17 - A_2(x)*17)}$.

**Public keys aggregation:**
1. Initialize the accumulation point:
	- The circuit starts by picking the first 7 rows where `tag == 'committee' && field_tag = 'PubKey.X'` and first 7 rows where  `tag == 'committee' && field_tag = 'PubKey.Y'`. 
	- Using selected values it initializes single `acc_point` of type [`EcPoint<Fp, G1Affine>`](https://github.com/axiom-crypto/halo2-lib/blob/main/halo2-ecc/src/ecc/mod.rs#L24).
	- Checks that `acc_point` is an identity (0, 1, 0).
	- > `acc_point` will act as first addend and accumulate the total sum of public keys of all validators who have attested.
2. Initialize compressed pubkey:
	- Assigns `pubkey_rlc = state_table.value` of the row with `tag == 'validator' && attested == 1 && field_tag = 'PubKeyRLC'`.
	- Assigns `pubkey_bytes = [pk_decompres_ext.compressed for i in pk_decompres_ext if pk_decompres_ext.id == state_table.id]`.
	- Checks that `pubkey_rlc == rlc(pubkey_bytes)` for rows with `not_verified == 1`.
3. Initialize second addend:
	- Assigns `pubkey_сhunks = [pk_decompres_ext.affine for i in pk_decompres_ext if pk_decompres_ext.id == state_table.id]`.
	- Assings `pubkey_affine = EcPoint<Fp, G1Affine>(x=Fp(pubkey_сhunks[0..6]), y=Fp(pubkey_сhunks[7..13])`.
	- Checks that `pubkey_affine` is a point on a curve and not identity.
4. Check encoding correctness `g1_decompress(pubkey_bytes) == pubkey_affine`  for new rows. All other rows are trusted after verifing previous instance of the recursive proof.
5. Sum two addends and assign to `acc_point = acc_point + pubkey_affine`.

Repeat steps 1-5 until end of table is reached.
