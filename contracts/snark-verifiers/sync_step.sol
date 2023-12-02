// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract Halo2Verifier {
    uint256 internal constant    PROOF_LEN_CPTR = 0x44;
    uint256 internal constant        PROOF_CPTR = 0x64;
    uint256 internal constant NUM_INSTANCE_CPTR = 0x10a4;
    uint256 internal constant     INSTANCE_CPTR = 0x10c4;

    uint256 internal constant FIRST_QUOTIENT_X_CPTR = 0x05e4;
    uint256 internal constant  LAST_QUOTIENT_X_CPTR = 0x0664;

    uint256 internal constant                VK_MPTR = 0x09a0;
    uint256 internal constant         VK_DIGEST_MPTR = 0x09a0;
    uint256 internal constant                 K_MPTR = 0x09c0;
    uint256 internal constant             N_INV_MPTR = 0x09e0;
    uint256 internal constant             OMEGA_MPTR = 0x0a00;
    uint256 internal constant         OMEGA_INV_MPTR = 0x0a20;
    uint256 internal constant    OMEGA_INV_TO_L_MPTR = 0x0a40;
    uint256 internal constant     NUM_INSTANCES_MPTR = 0x0a60;
    uint256 internal constant   HAS_ACCUMULATOR_MPTR = 0x0a80;
    uint256 internal constant        ACC_OFFSET_MPTR = 0x0aa0;
    uint256 internal constant     NUM_ACC_LIMBS_MPTR = 0x0ac0;
    uint256 internal constant NUM_ACC_LIMB_BITS_MPTR = 0x0ae0;
    uint256 internal constant              G1_X_MPTR = 0x0b00;
    uint256 internal constant              G1_Y_MPTR = 0x0b20;
    uint256 internal constant            G2_X_1_MPTR = 0x0b40;
    uint256 internal constant            G2_X_2_MPTR = 0x0b60;
    uint256 internal constant            G2_Y_1_MPTR = 0x0b80;
    uint256 internal constant            G2_Y_2_MPTR = 0x0ba0;
    uint256 internal constant      NEG_S_G2_X_1_MPTR = 0x0bc0;
    uint256 internal constant      NEG_S_G2_X_2_MPTR = 0x0be0;
    uint256 internal constant      NEG_S_G2_Y_1_MPTR = 0x0c00;
    uint256 internal constant      NEG_S_G2_Y_2_MPTR = 0x0c20;

    uint256 internal constant CHALLENGE_MPTR = 0x1180;

    uint256 internal constant THETA_MPTR = 0x1180;
    uint256 internal constant  BETA_MPTR = 0x11a0;
    uint256 internal constant GAMMA_MPTR = 0x11c0;
    uint256 internal constant     Y_MPTR = 0x11e0;
    uint256 internal constant     X_MPTR = 0x1200;
    uint256 internal constant  ZETA_MPTR = 0x1220;
    uint256 internal constant    NU_MPTR = 0x1240;
    uint256 internal constant    MU_MPTR = 0x1260;

    uint256 internal constant       ACC_LHS_X_MPTR = 0x1280;
    uint256 internal constant       ACC_LHS_Y_MPTR = 0x12a0;
    uint256 internal constant       ACC_RHS_X_MPTR = 0x12c0;
    uint256 internal constant       ACC_RHS_Y_MPTR = 0x12e0;
    uint256 internal constant             X_N_MPTR = 0x1300;
    uint256 internal constant X_N_MINUS_1_INV_MPTR = 0x1320;
    uint256 internal constant          L_LAST_MPTR = 0x1340;
    uint256 internal constant         L_BLIND_MPTR = 0x1360;
    uint256 internal constant             L_0_MPTR = 0x1380;
    uint256 internal constant   INSTANCE_EVAL_MPTR = 0x13a0;
    uint256 internal constant   QUOTIENT_EVAL_MPTR = 0x13c0;
    uint256 internal constant      QUOTIENT_X_MPTR = 0x13e0;
    uint256 internal constant      QUOTIENT_Y_MPTR = 0x1400;
    uint256 internal constant          R_EVAL_MPTR = 0x1420;
    uint256 internal constant   PAIRING_LHS_X_MPTR = 0x1440;
    uint256 internal constant   PAIRING_LHS_Y_MPTR = 0x1460;
    uint256 internal constant   PAIRING_RHS_X_MPTR = 0x1480;
    uint256 internal constant   PAIRING_RHS_Y_MPTR = 0x14a0;

    function verifyProof(
        bytes calldata proof,
        uint256[] calldata instances
    ) public returns (bool) {
        assembly {
            // Read EC point (x, y) at (proof_cptr, proof_cptr + 0x20),
            // and check if the point is on affine plane,
            // and store them in (hash_mptr, hash_mptr + 0x20).
            // Return updated (success, proof_cptr, hash_mptr).
            function read_ec_point(success, proof_cptr, hash_mptr, q) -> ret0, ret1, ret2 {
                let x := calldataload(proof_cptr)
                let y := calldataload(add(proof_cptr, 0x20))
                ret0 := and(success, lt(x, q))
                ret0 := and(ret0, lt(y, q))
                ret0 := and(ret0, eq(mulmod(y, y, q), addmod(mulmod(x, mulmod(x, x, q), q), 3, q)))
                mstore(hash_mptr, x)
                mstore(add(hash_mptr, 0x20), y)
                ret1 := add(proof_cptr, 0x40)
                ret2 := add(hash_mptr, 0x40)
            }

            // Squeeze challenge by keccak256(memory[0..hash_mptr]),
            // and store hash mod r as challenge in challenge_mptr,
            // and push back hash in 0x00 as the first input for next squeeze.
            // Return updated (challenge_mptr, hash_mptr).
            function squeeze_challenge(challenge_mptr, hash_mptr, r) -> ret0, ret1 {
                let hash := keccak256(0x00, hash_mptr)
                mstore(challenge_mptr, mod(hash, r))
                mstore(0x00, hash)
                ret0 := add(challenge_mptr, 0x20)
                ret1 := 0x20
            }

            // Squeeze challenge without absorbing new input from calldata,
            // by putting an extra 0x01 in memory[0x20] and squeeze by keccak256(memory[0..21]),
            // and store hash mod r as challenge in challenge_mptr,
            // and push back hash in 0x00 as the first input for next squeeze.
            // Return updated (challenge_mptr).
            function squeeze_challenge_cont(challenge_mptr, r) -> ret {
                mstore8(0x20, 0x01)
                let hash := keccak256(0x00, 0x21)
                mstore(challenge_mptr, mod(hash, r))
                mstore(0x00, hash)
                ret := add(challenge_mptr, 0x20)
            }

            // Batch invert values in memory[mptr_start..mptr_end] in place.
            // Return updated (success).
            function batch_invert(success, mptr_start, mptr_end, r) -> ret {
                let gp_mptr := mptr_end
                let gp := mload(mptr_start)
                let mptr := add(mptr_start, 0x20)
                for
                    {}
                    lt(mptr, sub(mptr_end, 0x20))
                    {}
                {
                    gp := mulmod(gp, mload(mptr), r)
                    mstore(gp_mptr, gp)
                    mptr := add(mptr, 0x20)
                    gp_mptr := add(gp_mptr, 0x20)
                }
                gp := mulmod(gp, mload(mptr), r)

                mstore(gp_mptr, 0x20)
                mstore(add(gp_mptr, 0x20), 0x20)
                mstore(add(gp_mptr, 0x40), 0x20)
                mstore(add(gp_mptr, 0x60), gp)
                mstore(add(gp_mptr, 0x80), sub(r, 2))
                mstore(add(gp_mptr, 0xa0), r)
                ret := and(success, staticcall(gas(), 0x05, gp_mptr, 0xc0, gp_mptr, 0x20))
                let all_inv := mload(gp_mptr)

                let first_mptr := mptr_start
                let second_mptr := add(first_mptr, 0x20)
                gp_mptr := sub(gp_mptr, 0x20)
                for
                    {}
                    lt(second_mptr, mptr)
                    {}
                {
                    let inv := mulmod(all_inv, mload(gp_mptr), r)
                    all_inv := mulmod(all_inv, mload(mptr), r)
                    mstore(mptr, inv)
                    mptr := sub(mptr, 0x20)
                    gp_mptr := sub(gp_mptr, 0x20)
                }
                let inv_first := mulmod(all_inv, mload(second_mptr), r)
                let inv_second := mulmod(all_inv, mload(first_mptr), r)
                mstore(first_mptr, inv_first)
                mstore(second_mptr, inv_second)
            }

            // Add (x, y) into point at (0x00, 0x20).
            // Return updated (success).
            function ec_add_acc(success, x, y) -> ret {
                mstore(0x40, x)
                mstore(0x60, y)
                ret := and(success, staticcall(gas(), 0x06, 0x00, 0x80, 0x00, 0x40))
            }

            // Scale point at (0x00, 0x20) by scalar.
            function ec_mul_acc(success, scalar) -> ret {
                mstore(0x40, scalar)
                ret := and(success, staticcall(gas(), 0x07, 0x00, 0x60, 0x00, 0x40))
            }

            // Add (x, y) into point at (0x80, 0xa0).
            // Return updated (success).
            function ec_add_tmp(success, x, y) -> ret {
                mstore(0xc0, x)
                mstore(0xe0, y)
                ret := and(success, staticcall(gas(), 0x06, 0x80, 0x80, 0x80, 0x40))
            }

            // Scale point at (0x80, 0xa0) by scalar.
            // Return updated (success).
            function ec_mul_tmp(success, scalar) -> ret {
                mstore(0xc0, scalar)
                ret := and(success, staticcall(gas(), 0x07, 0x80, 0x60, 0x80, 0x40))
            }

            // Perform pairing check.
            // Return updated (success).
            function ec_pairing(success, lhs_x, lhs_y, rhs_x, rhs_y) -> ret {
                mstore(0x00, lhs_x)
                mstore(0x20, lhs_y)
                mstore(0x40, mload(G2_X_1_MPTR))
                mstore(0x60, mload(G2_X_2_MPTR))
                mstore(0x80, mload(G2_Y_1_MPTR))
                mstore(0xa0, mload(G2_Y_2_MPTR))
                mstore(0xc0, rhs_x)
                mstore(0xe0, rhs_y)
                mstore(0x100, mload(NEG_S_G2_X_1_MPTR))
                mstore(0x120, mload(NEG_S_G2_X_2_MPTR))
                mstore(0x140, mload(NEG_S_G2_Y_1_MPTR))
                mstore(0x160, mload(NEG_S_G2_Y_2_MPTR))
                ret := and(success, staticcall(gas(), 0x08, 0x00, 0x180, 0x00, 0x20))
                ret := and(ret, mload(0x00))
            }

            // Modulus
            let q := 21888242871839275222246405745257275088696311157297823662689037894645226208583 // BN254 base field
            let r := 21888242871839275222246405745257275088548364400416034343698204186575808495617 // BN254 scalar field

            // Initialize success as true
            let success := true

            {
                // Load vk into memory
                mstore(0x09a0, 0x018b0a93b2ba7daec30e3b6c1bcd045511fd208c8d54227705591ca7ced9563c) // vk_digest
                mstore(0x09c0, 0x0000000000000000000000000000000000000000000000000000000000000016) // k
                mstore(0x09e0, 0x30644db14ff7d4a4f1cf9ed5406a7e5722d273a7aa184eaa5e1fb0846829b041) // n_inv
                mstore(0x0a00, 0x18c95f1ae6514e11a1b30fd7923947c5ffcec5347f16e91b4dd654168326bede) // omega
                mstore(0x0a20, 0x134f571fe34eb8c7b1685e875b324820e199bd70157493377cd65b204d1a3964) // omega_inv
                mstore(0x0a40, 0x1d3d878f52016737bda697d23b0cee81488efd02d67b27eae3edab5f39ef347d) // omega_inv_to_l
                mstore(0x0a60, 0x0000000000000000000000000000000000000000000000000000000000000001) // num_instances
                mstore(0x0a80, 0x0000000000000000000000000000000000000000000000000000000000000000) // has_accumulator
                mstore(0x0aa0, 0x0000000000000000000000000000000000000000000000000000000000000000) // acc_offset
                mstore(0x0ac0, 0x0000000000000000000000000000000000000000000000000000000000000000) // num_acc_limbs
                mstore(0x0ae0, 0x0000000000000000000000000000000000000000000000000000000000000000) // num_acc_limb_bits
                mstore(0x0b00, 0x0000000000000000000000000000000000000000000000000000000000000001) // g1_x
                mstore(0x0b20, 0x0000000000000000000000000000000000000000000000000000000000000002) // g1_y
                mstore(0x0b40, 0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2) // g2_x_1
                mstore(0x0b60, 0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed) // g2_x_2
                mstore(0x0b80, 0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b) // g2_y_1
                mstore(0x0ba0, 0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa) // g2_y_2
                mstore(0x0bc0, 0x0181624e80f3d6ae28df7e01eaeab1c0e919877a3b8a6b7fbc69a6817d596ea2) // neg_s_g2_x_1
                mstore(0x0be0, 0x1783d30dcb12d259bb89098addf6280fa4b653be7a152542a28f7b926e27e648) // neg_s_g2_x_2
                mstore(0x0c00, 0x00ae44489d41a0d179e2dfdc03bddd883b7109f8b6ae316a59e815c1a6b35304) // neg_s_g2_y_1
                mstore(0x0c20, 0x0b2147ab62a386bd63e6de1522109b8c9588ab466f5aadfde8c41ca3749423ee) // neg_s_g2_y_2
                mstore(0x0c40, 0x04d043081f0d55eead6d8ad7b10d09a6ee2718f445d9bce454075a8a37bacaf3) // fixed_comms[0].x
                mstore(0x0c60, 0x27d6bcbb02cd624ab80b5532a0a65fc6f88a0faf7cf3e0d106f4aa0aa25e758b) // fixed_comms[0].y
                mstore(0x0c80, 0x0d3b7c04b7391ddf5d9fc5f8906033e1d1442f341c4cab5c1584c8082ea8c21c) // fixed_comms[1].x
                mstore(0x0ca0, 0x1596df7247ab32fb79261c31617e2f2bbde95b6e8719386dacfeaa8f6d7df60c) // fixed_comms[1].y
                mstore(0x0cc0, 0x04d043081f0d55eead6d8ad7b10d09a6ee2718f445d9bce454075a8a37bacaf3) // fixed_comms[2].x
                mstore(0x0ce0, 0x27d6bcbb02cd624ab80b5532a0a65fc6f88a0faf7cf3e0d106f4aa0aa25e758b) // fixed_comms[2].y
                mstore(0x0d00, 0x2d07a1bca289cdb98b648a91cbb0809dfa3a06fe01047b291d1161ddf8d1732c) // fixed_comms[3].x
                mstore(0x0d20, 0x021d078d5869c57b3fe2413b517561205de5f297ac56c0e5ef0f1a7f4a31ee94) // fixed_comms[3].y
                mstore(0x0d40, 0x2808de5f33581574dd857304add28f30335fa32c49a3d7c9128f5a3f453360cc) // fixed_comms[4].x
                mstore(0x0d60, 0x07f10d421231cb6aa063db7a3cf7be709ff037fbb78d19c866d7c2c674a1aaf0) // fixed_comms[4].y
                mstore(0x0d80, 0x2a9d8bc0a06a141e47fa114e4e62686823227f5416f19f9b2b54b9948a0bfb4b) // fixed_comms[5].x
                mstore(0x0da0, 0x170610ca7497030a3dbbfeb52cc8f5f086e7a7a91e3b52e44988e6b24f1c6c34) // fixed_comms[5].y
                mstore(0x0dc0, 0x104eb8e796d7c0b0ac9eb316eac3aadbcf9ac5b42d4b14a95ec269fefd70d9ac) // fixed_comms[6].x
                mstore(0x0de0, 0x22e1365078923b7f828a54c75e0b0b108c311580bac730c92d8868c7781a917b) // fixed_comms[6].y
                mstore(0x0e00, 0x2e8f499835598c80e2ec4cabd4753e67822df35d0a29c05b60dca21d9173b11a) // fixed_comms[7].x
                mstore(0x0e20, 0x02990fa09b4831443e5956b84832f525976cd30aa6cafe055a45f7a04328d00f) // fixed_comms[7].y
                mstore(0x0e40, 0x258bbf1a0f256c29c1cee612fb7deaa2102870b85d7bda1ac8064307a593101f) // fixed_comms[8].x
                mstore(0x0e60, 0x2bbbde7d34cf03b70ea4a0125d6736aeb56da64f07226bf4d662a85e8d50db3a) // fixed_comms[8].y
                mstore(0x0e80, 0x05127b4a2ff58c747435761c7256b8094a0cf4e6d0f829a060c601d5cce0fdc0) // fixed_comms[9].x
                mstore(0x0ea0, 0x106a8cecab556f1a6d729cdeefd6dd70afbe4954cae4785871d68396dba88d95) // fixed_comms[9].y
                mstore(0x0ec0, 0x24c985411f901ba3e9fe3296d58db7a896d53a060afc4c3b85182122d2a06b16) // permutation_comms[0].x
                mstore(0x0ee0, 0x1e02136b244f617c37779b0cb970dce25ff03579c671e7f3f57a320e7b1a4b06) // permutation_comms[0].y
                mstore(0x0f00, 0x0e5c5a486399e328a6629926a042fde07863ce1a2e91995ee60e5c477008ebdc) // permutation_comms[1].x
                mstore(0x0f20, 0x223b4bdd8d3877955728258fd5be1b7f2ac8093891a83c738f80395720cc55ca) // permutation_comms[1].y
                mstore(0x0f40, 0x2e55f008e10b629fc37b0808b8264d2857e6fa34a1be704a4132f9c1621b8736) // permutation_comms[2].x
                mstore(0x0f60, 0x01c3487db12618c270ffe8251633753bdad9fd2968144a02b18447bee326d19d) // permutation_comms[2].y
                mstore(0x0f80, 0x0154bffa5c54063b60c4f4c66b2a9acb09fd7f1b2653a9f2b9ee75bcb1bc8ba2) // permutation_comms[3].x
                mstore(0x0fa0, 0x0b15f039df5ebe088e2231ce9a07c50dbb4739402712b56dd8bab6ab93a95f3f) // permutation_comms[3].y
                mstore(0x0fc0, 0x0032a37f146820eccad7796039d21d0c85504baff34e194f750d7f8c4eccf729) // permutation_comms[4].x
                mstore(0x0fe0, 0x2a655340cddc523abd37c3d77f022b8e616194a3c31e414dc5d466eb2e4c0b69) // permutation_comms[4].y
                mstore(0x1000, 0x0d6b367e25327ebd99fae2aaffa6fad2acae34ba7b329ef817a95fe425f65e4d) // permutation_comms[5].x
                mstore(0x1020, 0x2bc4769ce00a494fde791f07b3f092019995d323c0b067d61e0660e1ad84d94f) // permutation_comms[5].y
                mstore(0x1040, 0x0fef43d29ecdb947fc934c7adf7f38748fe212082d5a8e3bc621ff907213812b) // permutation_comms[6].x
                mstore(0x1060, 0x1ab8ccbb8486a5508a34837db62c3426d6f6210970a2b1351f12d0ba73e11874) // permutation_comms[6].y
                mstore(0x1080, 0x29cc03da3870fc7139115d43275baf04cc110d79f85d2c2e712b981c409df25e) // permutation_comms[7].x
                mstore(0x10a0, 0x016a8cd002e522595ef910f87dc707449ae5f56876eb88274b2e586fceacf165) // permutation_comms[7].y
                mstore(0x10c0, 0x0ec6d72e2ce7c233ca8af2fc2bd4223a6d81d545e8785579de4cb241740f36a2) // permutation_comms[8].x
                mstore(0x10e0, 0x028a4450999577e25fc7d191fecf7f1a8a0526f7e042f316767c7ff43299fdd9) // permutation_comms[8].y
                mstore(0x1100, 0x1fdb57cefe9c10024dfe402759cad8061e8d0edeba3f42f187ea796b1938118e) // permutation_comms[9].x
                mstore(0x1120, 0x1294d92ed67eec88a2adbb5cef0682a64fae9827c02d37e69beaddd3b6a145ad) // permutation_comms[9].y
                mstore(0x1140, 0x292267e75402bf3fb816d404fe987ec7b277ec539cd653568a31dc8fdd04b6f1) // permutation_comms[10].x
                mstore(0x1160, 0x0a2975f29c8f29df52ea4e941daa28752eea2da8c6b6135622e4a0d823accd78) // permutation_comms[10].y

                // Check valid length of proof
                success := and(success, eq(0x1040, calldataload(PROOF_LEN_CPTR)))

                // Check valid length of instances
                let num_instances := mload(NUM_INSTANCES_MPTR)
                success := and(success, eq(num_instances, calldataload(NUM_INSTANCE_CPTR)))

                // Absorb vk diegst
                mstore(0x00, mload(VK_DIGEST_MPTR))

                // Read instances and witness commitments and generate challenges
                let hash_mptr := 0x20
                let instance_cptr := INSTANCE_CPTR
                for
                    { let instance_cptr_end := add(instance_cptr, mul(0x20, num_instances)) }
                    lt(instance_cptr, instance_cptr_end)
                    {}
                {
                    let instance := calldataload(instance_cptr)
                    success := and(success, lt(instance, r))
                    mstore(hash_mptr, instance)
                    instance_cptr := add(instance_cptr, 0x20)
                    hash_mptr := add(hash_mptr, 0x20)
                }

                let proof_cptr := PROOF_CPTR
                let challenge_mptr := CHALLENGE_MPTR

                // Phase 1
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0240) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)

                // Phase 2
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0100) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)
                challenge_mptr := squeeze_challenge_cont(challenge_mptr, r)

                // Phase 3
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0240) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)

                // Phase 4
                for
                    { let proof_cptr_end := add(proof_cptr, 0xc0) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)

                // Read evaluations
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0980) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    let eval := calldataload(proof_cptr)
                    success := and(success, lt(eval, r))
                    mstore(hash_mptr, eval)
                    proof_cptr := add(proof_cptr, 0x20)
                    hash_mptr := add(hash_mptr, 0x20)
                }

                // Read batch opening proof and generate challenges
                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)       // zeta
                challenge_mptr := squeeze_challenge_cont(challenge_mptr, r)                        // nu

                success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q) // W

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)       // mu

                success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q) // W'

                // Read accumulator from instances
                if mload(HAS_ACCUMULATOR_MPTR) {
                    let num_limbs := mload(NUM_ACC_LIMBS_MPTR)
                    let num_limb_bits := mload(NUM_ACC_LIMB_BITS_MPTR)

                    let cptr := add(INSTANCE_CPTR, mul(mload(ACC_OFFSET_MPTR), 0x20))
                    let lhs_y_off := mul(num_limbs, 0x20)
                    let rhs_x_off := mul(lhs_y_off, 2)
                    let rhs_y_off := mul(lhs_y_off, 3)
                    let lhs_x := calldataload(cptr)
                    let lhs_y := calldataload(add(cptr, lhs_y_off))
                    let rhs_x := calldataload(add(cptr, rhs_x_off))
                    let rhs_y := calldataload(add(cptr, rhs_y_off))
                    for
                        {
                            let cptr_end := add(cptr, mul(0x20, num_limbs))
                            let shift := num_limb_bits
                        }
                        lt(cptr, cptr_end)
                        {}
                    {
                        cptr := add(cptr, 0x20)
                        lhs_x := add(lhs_x, shl(shift, calldataload(cptr)))
                        lhs_y := add(lhs_y, shl(shift, calldataload(add(cptr, lhs_y_off))))
                        rhs_x := add(rhs_x, shl(shift, calldataload(add(cptr, rhs_x_off))))
                        rhs_y := add(rhs_y, shl(shift, calldataload(add(cptr, rhs_y_off))))
                        shift := add(shift, num_limb_bits)
                    }

                    success := and(success, eq(mulmod(lhs_y, lhs_y, q), addmod(mulmod(lhs_x, mulmod(lhs_x, lhs_x, q), q), 3, q)))
                    success := and(success, eq(mulmod(rhs_y, rhs_y, q), addmod(mulmod(rhs_x, mulmod(rhs_x, rhs_x, q), q), 3, q)))

                    mstore(ACC_LHS_X_MPTR, lhs_x)
                    mstore(ACC_LHS_Y_MPTR, lhs_y)
                    mstore(ACC_RHS_X_MPTR, rhs_x)
                    mstore(ACC_RHS_Y_MPTR, rhs_y)
                }

                pop(q)
            }

            // Revert earlier if anything from calldata is invalid
            if iszero(success) {
                revert(0, 0)
            }

            // Compute lagrange evaluations and instance evaluation
            {
                let k := mload(K_MPTR)
                let x := mload(X_MPTR)
                let x_n := x
                for
                    { let idx := 0 }
                    lt(idx, k)
                    { idx := add(idx, 1) }
                {
                    x_n := mulmod(x_n, x_n, r)
                }

                let omega := mload(OMEGA_MPTR)

                let mptr := X_N_MPTR
                let mptr_end := add(mptr, mul(0x20, add(mload(NUM_INSTANCES_MPTR), 7)))
                if iszero(mload(NUM_INSTANCES_MPTR)) {
                    mptr_end := add(mptr_end, 0x20)
                }
                for
                    { let pow_of_omega := mload(OMEGA_INV_TO_L_MPTR) }
                    lt(mptr, mptr_end)
                    { mptr := add(mptr, 0x20) }
                {
                    mstore(mptr, addmod(x, sub(r, pow_of_omega), r))
                    pow_of_omega := mulmod(pow_of_omega, omega, r)
                }
                let x_n_minus_1 := addmod(x_n, sub(r, 1), r)
                mstore(mptr_end, x_n_minus_1)
                success := batch_invert(success, X_N_MPTR, add(mptr_end, 0x20), r)

                mptr := X_N_MPTR
                let l_i_common := mulmod(x_n_minus_1, mload(N_INV_MPTR), r)
                for
                    { let pow_of_omega := mload(OMEGA_INV_TO_L_MPTR) }
                    lt(mptr, mptr_end)
                    { mptr := add(mptr, 0x20) }
                {
                    mstore(mptr, mulmod(l_i_common, mulmod(mload(mptr), pow_of_omega, r), r))
                    pow_of_omega := mulmod(pow_of_omega, omega, r)
                }

                let l_blind := mload(add(X_N_MPTR, 0x20))
                let l_i_cptr := add(X_N_MPTR, 0x40)
                for
                    { let l_i_cptr_end := add(X_N_MPTR, 0xe0) }
                    lt(l_i_cptr, l_i_cptr_end)
                    { l_i_cptr := add(l_i_cptr, 0x20) }
                {
                    l_blind := addmod(l_blind, mload(l_i_cptr), r)
                }

                let instance_eval := 0
                for
                    {
                        let instance_cptr := INSTANCE_CPTR
                        let instance_cptr_end := add(instance_cptr, mul(0x20, mload(NUM_INSTANCES_MPTR)))
                    }
                    lt(instance_cptr, instance_cptr_end)
                    {
                        instance_cptr := add(instance_cptr, 0x20)
                        l_i_cptr := add(l_i_cptr, 0x20)
                    }
                {
                    instance_eval := addmod(instance_eval, mulmod(mload(l_i_cptr), calldataload(instance_cptr), r), r)
                }

                let x_n_minus_1_inv := mload(mptr_end)
                let l_last := mload(X_N_MPTR)
                let l_0 := mload(add(X_N_MPTR, 0xe0))

                mstore(X_N_MPTR, x_n)
                mstore(X_N_MINUS_1_INV_MPTR, x_n_minus_1_inv)
                mstore(L_LAST_MPTR, l_last)
                mstore(L_BLIND_MPTR, l_blind)
                mstore(L_0_MPTR, l_0)
                mstore(INSTANCE_EVAL_MPTR, instance_eval)
            }

            // Compute quotient evavluation
            {
                let quotient_eval_numer
                let delta := 4131629893567559867359510883348571134090853742863529169391034518566172092834
                let y := mload(Y_MPTR)
                {
                    let f_4 := calldataload(0x0a84)
                    let a_0 := calldataload(0x06a4)
                    let a_0_next_1 := calldataload(0x06c4)
                    let a_0_next_2 := calldataload(0x06e4)
                    let var0 := mulmod(a_0_next_1, a_0_next_2, r)
                    let var1 := addmod(a_0, var0, r)
                    let a_0_next_3 := calldataload(0x0704)
                    let var2 := sub(r, a_0_next_3)
                    let var3 := addmod(var1, var2, r)
                    let var4 := mulmod(f_4, var3, r)
                    quotient_eval_numer := var4
                }
                {
                    let f_5 := calldataload(0x0aa4)
                    let a_1 := calldataload(0x0724)
                    let a_1_next_1 := calldataload(0x0744)
                    let a_1_next_2 := calldataload(0x0764)
                    let var0 := mulmod(a_1_next_1, a_1_next_2, r)
                    let var1 := addmod(a_1, var0, r)
                    let a_1_next_3 := calldataload(0x0784)
                    let var2 := sub(r, a_1_next_3)
                    let var3 := addmod(var1, var2, r)
                    let var4 := mulmod(f_5, var3, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var4, r)
                }
                {
                    let f_6 := calldataload(0x0ac4)
                    let a_2 := calldataload(0x07a4)
                    let a_2_next_1 := calldataload(0x07c4)
                    let a_2_next_2 := calldataload(0x07e4)
                    let var0 := mulmod(a_2_next_1, a_2_next_2, r)
                    let var1 := addmod(a_2, var0, r)
                    let a_2_next_3 := calldataload(0x0804)
                    let var2 := sub(r, a_2_next_3)
                    let var3 := addmod(var1, var2, r)
                    let var4 := mulmod(f_6, var3, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var4, r)
                }
                {
                    let f_7 := calldataload(0x0ae4)
                    let a_3 := calldataload(0x0824)
                    let a_3_next_1 := calldataload(0x0844)
                    let a_3_next_2 := calldataload(0x0864)
                    let var0 := mulmod(a_3_next_1, a_3_next_2, r)
                    let var1 := addmod(a_3, var0, r)
                    let a_3_next_3 := calldataload(0x0884)
                    let var2 := sub(r, a_3_next_3)
                    let var3 := addmod(var1, var2, r)
                    let var4 := mulmod(f_7, var3, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var4, r)
                }
                {
                    let f_8 := calldataload(0x0b04)
                    let a_4 := calldataload(0x08a4)
                    let a_4_next_1 := calldataload(0x08c4)
                    let a_4_next_2 := calldataload(0x08e4)
                    let var0 := mulmod(a_4_next_1, a_4_next_2, r)
                    let var1 := addmod(a_4, var0, r)
                    let a_4_next_3 := calldataload(0x0904)
                    let var2 := sub(r, a_4_next_3)
                    let var3 := addmod(var1, var2, r)
                    let var4 := mulmod(f_8, var3, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var4, r)
                }
                {
                    let f_9 := calldataload(0x0b24)
                    let a_5 := calldataload(0x0924)
                    let a_5_next_1 := calldataload(0x0944)
                    let a_5_next_2 := calldataload(0x0964)
                    let var0 := mulmod(a_5_next_1, a_5_next_2, r)
                    let var1 := addmod(a_5, var0, r)
                    let a_5_next_3 := calldataload(0x0984)
                    let var2 := sub(r, a_5_next_3)
                    let var3 := addmod(var1, var2, r)
                    let var4 := mulmod(f_9, var3, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var4, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := addmod(l_0, sub(r, mulmod(l_0, calldataload(0x0cc4), r)), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let perm_z_last := calldataload(0x0ea4)
                    let eval := mulmod(mload(L_LAST_MPTR), addmod(mulmod(perm_z_last, perm_z_last, r), sub(r, perm_z_last), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(mload(L_0_MPTR), addmod(calldataload(0x0d24), sub(r, calldataload(0x0d04)), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(mload(L_0_MPTR), addmod(calldataload(0x0d84), sub(r, calldataload(0x0d64)), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(mload(L_0_MPTR), addmod(calldataload(0x0de4), sub(r, calldataload(0x0dc4)), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(mload(L_0_MPTR), addmod(calldataload(0x0e44), sub(r, calldataload(0x0e24)), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(mload(L_0_MPTR), addmod(calldataload(0x0ea4), sub(r, calldataload(0x0e84)), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x0ce4)
                    let rhs := calldataload(0x0cc4)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0a04), mulmod(beta, calldataload(0x0b64), r), r), gamma, r), r)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x06a4), mulmod(beta, calldataload(0x0b84), r), r), gamma, r), r)
                    mstore(0x00, mulmod(beta, mload(X_MPTR), r))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0a04), mload(0x00), r), gamma, r), r)
                    mstore(0x00, mulmod(mload(0x00), delta, r))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x06a4), mload(0x00), r), gamma, r), r)
                    mstore(0x00, mulmod(mload(0x00), delta, r))
                    let left_sub_right := addmod(lhs, sub(r, rhs), r)
                    let eval := addmod(left_sub_right, sub(r, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), r), r)), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x0d44)
                    let rhs := calldataload(0x0d24)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0724), mulmod(beta, calldataload(0x0ba4), r), r), gamma, r), r)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x07a4), mulmod(beta, calldataload(0x0bc4), r), r), gamma, r), r)
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0724), mload(0x00), r), gamma, r), r)
                    mstore(0x00, mulmod(mload(0x00), delta, r))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x07a4), mload(0x00), r), gamma, r), r)
                    mstore(0x00, mulmod(mload(0x00), delta, r))
                    let left_sub_right := addmod(lhs, sub(r, rhs), r)
                    let eval := addmod(left_sub_right, sub(r, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), r), r)), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x0da4)
                    let rhs := calldataload(0x0d84)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0824), mulmod(beta, calldataload(0x0be4), r), r), gamma, r), r)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x08a4), mulmod(beta, calldataload(0x0c04), r), r), gamma, r), r)
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0824), mload(0x00), r), gamma, r), r)
                    mstore(0x00, mulmod(mload(0x00), delta, r))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x08a4), mload(0x00), r), gamma, r), r)
                    mstore(0x00, mulmod(mload(0x00), delta, r))
                    let left_sub_right := addmod(lhs, sub(r, rhs), r)
                    let eval := addmod(left_sub_right, sub(r, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), r), r)), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x0e04)
                    let rhs := calldataload(0x0de4)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0924), mulmod(beta, calldataload(0x0c24), r), r), gamma, r), r)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x09a4), mulmod(beta, calldataload(0x0c44), r), r), gamma, r), r)
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0924), mload(0x00), r), gamma, r), r)
                    mstore(0x00, mulmod(mload(0x00), delta, r))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x09a4), mload(0x00), r), gamma, r), r)
                    mstore(0x00, mulmod(mload(0x00), delta, r))
                    let left_sub_right := addmod(lhs, sub(r, rhs), r)
                    let eval := addmod(left_sub_right, sub(r, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), r), r)), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x0e64)
                    let rhs := calldataload(0x0e44)
                    lhs := mulmod(lhs, addmod(addmod(mload(INSTANCE_EVAL_MPTR), mulmod(beta, calldataload(0x0c64), r), r), gamma, r), r)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x09c4), mulmod(beta, calldataload(0x0c84), r), r), gamma, r), r)
                    rhs := mulmod(rhs, addmod(addmod(mload(INSTANCE_EVAL_MPTR), mload(0x00), r), gamma, r), r)
                    mstore(0x00, mulmod(mload(0x00), delta, r))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x09c4), mload(0x00), r), gamma, r), r)
                    mstore(0x00, mulmod(mload(0x00), delta, r))
                    let left_sub_right := addmod(lhs, sub(r, rhs), r)
                    let eval := addmod(left_sub_right, sub(r, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), r), r)), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x0ec4)
                    let rhs := calldataload(0x0ea4)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x09e4), mulmod(beta, calldataload(0x0ca4), r), r), gamma, r), r)
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x09e4), mload(0x00), r), gamma, r), r)
                    let left_sub_right := addmod(lhs, sub(r, rhs), r)
                    let eval := addmod(left_sub_right, sub(r, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), r), r)), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := addmod(l_0, mulmod(l_0, sub(r, calldataload(0x0ee4)), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, addmod(mulmod(calldataload(0x0ee4), calldataload(0x0ee4), r), sub(r, calldataload(0x0ee4)), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let input
                    {
                        let a_6 := calldataload(0x09a4)
                        input := a_6
                    }
                    let table
                    {
                        let f_0 := calldataload(0x0a24)
                        table := f_0
                    }
                    let beta := mload(BETA_MPTR)
                    let gamma := mload(GAMMA_MPTR)
                    let lhs := mulmod(calldataload(0x0f04), mulmod(addmod(calldataload(0x0f24), beta, r), addmod(calldataload(0x0f64), gamma, r), r), r)
                    let rhs := mulmod(calldataload(0x0ee4), mulmod(addmod(input, beta, r), addmod(table, gamma, r), r), r)
                    let eval := mulmod(addmod(1, sub(r, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), r)), r), addmod(lhs, sub(r, rhs), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(mload(L_0_MPTR), addmod(calldataload(0x0f24), sub(r, calldataload(0x0f64)), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(addmod(1, sub(r, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), r)), r), mulmod(addmod(calldataload(0x0f24), sub(r, calldataload(0x0f64)), r), addmod(calldataload(0x0f24), sub(r, calldataload(0x0f44)), r), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := addmod(l_0, mulmod(l_0, sub(r, calldataload(0x0f84)), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, addmod(mulmod(calldataload(0x0f84), calldataload(0x0f84), r), sub(r, calldataload(0x0f84)), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let input
                    {
                        let a_7 := calldataload(0x09c4)
                        let a_8 := calldataload(0x09e4)
                        input := a_7
                        input := addmod(mulmod(input, theta, r), a_8, r)
                    }
                    let table
                    {
                        let f_2 := calldataload(0x0a44)
                        let f_3 := calldataload(0x0a64)
                        table := f_2
                        table := addmod(mulmod(table, theta, r), f_3, r)
                    }
                    let beta := mload(BETA_MPTR)
                    let gamma := mload(GAMMA_MPTR)
                    let lhs := mulmod(calldataload(0x0fa4), mulmod(addmod(calldataload(0x0fc4), beta, r), addmod(calldataload(0x1004), gamma, r), r), r)
                    let rhs := mulmod(calldataload(0x0f84), mulmod(addmod(input, beta, r), addmod(table, gamma, r), r), r)
                    let eval := mulmod(addmod(1, sub(r, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), r)), r), addmod(lhs, sub(r, rhs), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(mload(L_0_MPTR), addmod(calldataload(0x0fc4), sub(r, calldataload(0x1004)), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(addmod(1, sub(r, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), r)), r), mulmod(addmod(calldataload(0x0fc4), sub(r, calldataload(0x1004)), r), addmod(calldataload(0x0fc4), sub(r, calldataload(0x0fe4)), r), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }

                pop(y)
                pop(delta)

                let quotient_eval := mulmod(quotient_eval_numer, mload(X_N_MINUS_1_INV_MPTR), r)
                mstore(QUOTIENT_EVAL_MPTR, quotient_eval)
            }

            // Compute quotient commitment
            {
                mstore(0x00, calldataload(LAST_QUOTIENT_X_CPTR))
                mstore(0x20, calldataload(add(LAST_QUOTIENT_X_CPTR, 0x20)))
                let x_n := mload(X_N_MPTR)
                for
                    {
                        let cptr := sub(LAST_QUOTIENT_X_CPTR, 0x40)
                        let cptr_end := sub(FIRST_QUOTIENT_X_CPTR, 0x40)
                    }
                    lt(cptr_end, cptr)
                    {}
                {
                    success := ec_mul_acc(success, x_n)
                    success := ec_add_acc(success, calldataload(cptr), calldataload(add(cptr, 0x20)))
                    cptr := sub(cptr, 0x40)
                }
                mstore(QUOTIENT_X_MPTR, mload(0x00))
                mstore(QUOTIENT_Y_MPTR, mload(0x20))
            }

            // Compute pairing lhs and rhs
            {
                {
                    let x := mload(X_MPTR)
                    let omega := mload(OMEGA_MPTR)
                    let omega_inv := mload(OMEGA_INV_MPTR)
                    let x_pow_of_omega := mulmod(x, omega, r)
                    mstore(0x0460, x_pow_of_omega)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega, r)
                    mstore(0x0480, x_pow_of_omega)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega, r)
                    mstore(0x04a0, x_pow_of_omega)
                    mstore(0x0440, x)
                    x_pow_of_omega := mulmod(x, omega_inv, r)
                    mstore(0x0420, x_pow_of_omega)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, r)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, r)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, r)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, r)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, r)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, r)
                    mstore(0x0400, x_pow_of_omega)
                }
                {
                    let mu := mload(MU_MPTR)
                    for
                        {
                            let mptr := 0x04c0
                            let mptr_end := 0x0580
                            let point_mptr := 0x0400
                        }
                        lt(mptr, mptr_end)
                        {
                            mptr := add(mptr, 0x20)
                            point_mptr := add(point_mptr, 0x20)
                        }
                    {
                        mstore(mptr, addmod(mu, sub(r, mload(point_mptr)), r))
                    }
                    let s
                    s := mload(0x0500)
                    s := mulmod(s, mload(0x0520), r)
                    s := mulmod(s, mload(0x0540), r)
                    s := mulmod(s, mload(0x0560), r)
                    mstore(0x0580, s)
                    let diff
                    diff := mload(0x04c0)
                    diff := mulmod(diff, mload(0x04e0), r)
                    mstore(0x05a0, diff)
                    mstore(0x00, diff)
                    diff := mload(0x04c0)
                    diff := mulmod(diff, mload(0x04e0), r)
                    diff := mulmod(diff, mload(0x0520), r)
                    diff := mulmod(diff, mload(0x0540), r)
                    diff := mulmod(diff, mload(0x0560), r)
                    mstore(0x05c0, diff)
                    diff := mload(0x04e0)
                    diff := mulmod(diff, mload(0x0540), r)
                    diff := mulmod(diff, mload(0x0560), r)
                    mstore(0x05e0, diff)
                    diff := mload(0x04c0)
                    diff := mulmod(diff, mload(0x04e0), r)
                    diff := mulmod(diff, mload(0x0540), r)
                    diff := mulmod(diff, mload(0x0560), r)
                    mstore(0x0600, diff)
                    diff := mload(0x04c0)
                    diff := mulmod(diff, mload(0x0520), r)
                    diff := mulmod(diff, mload(0x0540), r)
                    diff := mulmod(diff, mload(0x0560), r)
                    mstore(0x0620, diff)
                }
                {
                    let point_2 := mload(0x0440)
                    let point_3 := mload(0x0460)
                    let point_4 := mload(0x0480)
                    let point_5 := mload(0x04a0)
                    let coeff
                    coeff := addmod(point_2, sub(r, point_3), r)
                    coeff := mulmod(coeff, addmod(point_2, sub(r, point_4), r), r)
                    coeff := mulmod(coeff, addmod(point_2, sub(r, point_5), r), r)
                    coeff := mulmod(coeff, mload(0x0500), r)
                    mstore(0x20, coeff)
                    coeff := addmod(point_3, sub(r, point_2), r)
                    coeff := mulmod(coeff, addmod(point_3, sub(r, point_4), r), r)
                    coeff := mulmod(coeff, addmod(point_3, sub(r, point_5), r), r)
                    coeff := mulmod(coeff, mload(0x0520), r)
                    mstore(0x40, coeff)
                    coeff := addmod(point_4, sub(r, point_2), r)
                    coeff := mulmod(coeff, addmod(point_4, sub(r, point_3), r), r)
                    coeff := mulmod(coeff, addmod(point_4, sub(r, point_5), r), r)
                    coeff := mulmod(coeff, mload(0x0540), r)
                    mstore(0x60, coeff)
                    coeff := addmod(point_5, sub(r, point_2), r)
                    coeff := mulmod(coeff, addmod(point_5, sub(r, point_3), r), r)
                    coeff := mulmod(coeff, addmod(point_5, sub(r, point_4), r), r)
                    coeff := mulmod(coeff, mload(0x0560), r)
                    mstore(0x80, coeff)
                }
                {
                    let point_2 := mload(0x0440)
                    let coeff
                    coeff := 1
                    coeff := mulmod(coeff, mload(0x0500), r)
                    mstore(0xa0, coeff)
                }
                {
                    let point_0 := mload(0x0400)
                    let point_2 := mload(0x0440)
                    let point_3 := mload(0x0460)
                    let coeff
                    coeff := addmod(point_0, sub(r, point_2), r)
                    coeff := mulmod(coeff, addmod(point_0, sub(r, point_3), r), r)
                    coeff := mulmod(coeff, mload(0x04c0), r)
                    mstore(0xc0, coeff)
                    coeff := addmod(point_2, sub(r, point_0), r)
                    coeff := mulmod(coeff, addmod(point_2, sub(r, point_3), r), r)
                    coeff := mulmod(coeff, mload(0x0500), r)
                    mstore(0xe0, coeff)
                    coeff := addmod(point_3, sub(r, point_0), r)
                    coeff := mulmod(coeff, addmod(point_3, sub(r, point_2), r), r)
                    coeff := mulmod(coeff, mload(0x0520), r)
                    mstore(0x0100, coeff)
                }
                {
                    let point_2 := mload(0x0440)
                    let point_3 := mload(0x0460)
                    let coeff
                    coeff := addmod(point_2, sub(r, point_3), r)
                    coeff := mulmod(coeff, mload(0x0500), r)
                    mstore(0x0120, coeff)
                    coeff := addmod(point_3, sub(r, point_2), r)
                    coeff := mulmod(coeff, mload(0x0520), r)
                    mstore(0x0140, coeff)
                }
                {
                    let point_1 := mload(0x0420)
                    let point_2 := mload(0x0440)
                    let coeff
                    coeff := addmod(point_1, sub(r, point_2), r)
                    coeff := mulmod(coeff, mload(0x04e0), r)
                    mstore(0x0160, coeff)
                    coeff := addmod(point_2, sub(r, point_1), r)
                    coeff := mulmod(coeff, mload(0x0500), r)
                    mstore(0x0180, coeff)
                }
                {
                    success := batch_invert(success, 0, 0x01a0, r)
                    let diff_0_inv := mload(0x00)
                    mstore(0x05a0, diff_0_inv)
                    for
                        {
                            let mptr := 0x05c0
                            let mptr_end := 0x0640
                        }
                        lt(mptr, mptr_end)
                        { mptr := add(mptr, 0x20) }
                    {
                        mstore(mptr, mulmod(mload(mptr), diff_0_inv, r))
                    }
                }
                {
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(mload(0x20), calldataload(0x0924), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x40), calldataload(0x0944), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x60), calldataload(0x0964), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x80), calldataload(0x0984), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0x20), calldataload(0x08a4), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x40), calldataload(0x08c4), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x60), calldataload(0x08e4), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x80), calldataload(0x0904), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0x20), calldataload(0x0824), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x40), calldataload(0x0844), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x60), calldataload(0x0864), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x80), calldataload(0x0884), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0x20), calldataload(0x07a4), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x40), calldataload(0x07c4), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x60), calldataload(0x07e4), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x80), calldataload(0x0804), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0x20), calldataload(0x0724), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x40), calldataload(0x0744), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x60), calldataload(0x0764), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x80), calldataload(0x0784), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0x20), calldataload(0x06a4), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x40), calldataload(0x06c4), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x60), calldataload(0x06e4), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x80), calldataload(0x0704), r), r)
                    mstore(0x0640, r_eval)
                }
                {
                    let coeff := mload(0xa0)
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x0b44), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(coeff, mload(QUOTIENT_EVAL_MPTR), r), r)
                    for
                        {
                            let mptr := 0x0ca4
                            let mptr_end := 0x0b44
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x20) }
                    {
                        r_eval := addmod(mulmod(r_eval, zeta, r), mulmod(coeff, calldataload(mptr), r), r)
                    }
                    for
                        {
                            let mptr := 0x0b24
                            let mptr_end := 0x09e4
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x20) }
                    {
                        r_eval := addmod(mulmod(r_eval, zeta, r), mulmod(coeff, calldataload(mptr), r), r)
                    }
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x1004), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x0f64), r), r)
                    for
                        {
                            let mptr := 0x09e4
                            let mptr_end := 0x0984
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x20) }
                    {
                        r_eval := addmod(mulmod(r_eval, zeta, r), mulmod(coeff, calldataload(mptr), r), r)
                    }
                    r_eval := mulmod(r_eval, mload(0x05c0), r)
                    mstore(0x0660, r_eval)
                }
                {
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(mload(0xc0), calldataload(0x0e84), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x0e44), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x0e64), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0xc0), calldataload(0x0e24), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x0de4), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x0e04), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0xc0), calldataload(0x0dc4), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x0d84), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x0da4), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0xc0), calldataload(0x0d64), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x0d24), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x0d44), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0xc0), calldataload(0x0d04), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x0cc4), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x0ce4), r), r)
                    r_eval := mulmod(r_eval, mload(0x05e0), r)
                    mstore(0x0680, r_eval)
                }
                {
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(mload(0x0120), calldataload(0x0f84), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x0140), calldataload(0x0fa4), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0x0120), calldataload(0x0ee4), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x0140), calldataload(0x0f04), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0x0120), calldataload(0x0ea4), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x0140), calldataload(0x0ec4), r), r)
                    r_eval := mulmod(r_eval, mload(0x0600), r)
                    mstore(0x06a0, r_eval)
                }
                {
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(mload(0x0160), calldataload(0x0fe4), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x0180), calldataload(0x0fc4), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0x0160), calldataload(0x0f44), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x0180), calldataload(0x0f24), r), r)
                    r_eval := mulmod(r_eval, mload(0x0620), r)
                    mstore(0x06c0, r_eval)
                }
                {
                    let sum := mload(0x20)
                    sum := addmod(sum, mload(0x40), r)
                    sum := addmod(sum, mload(0x60), r)
                    sum := addmod(sum, mload(0x80), r)
                    mstore(0x06e0, sum)
                }
                {
                    let sum := mload(0xa0)
                    mstore(0x0700, sum)
                }
                {
                    let sum := mload(0xc0)
                    sum := addmod(sum, mload(0xe0), r)
                    sum := addmod(sum, mload(0x0100), r)
                    mstore(0x0720, sum)
                }
                {
                    let sum := mload(0x0120)
                    sum := addmod(sum, mload(0x0140), r)
                    mstore(0x0740, sum)
                }
                {
                    let sum := mload(0x0160)
                    sum := addmod(sum, mload(0x0180), r)
                    mstore(0x0760, sum)
                }
                {
                    for
                        {
                            let mptr := 0x00
                            let mptr_end := 0xa0
                            let sum_mptr := 0x06e0
                        }
                        lt(mptr, mptr_end)
                        {
                            mptr := add(mptr, 0x20)
                            sum_mptr := add(sum_mptr, 0x20)
                        }
                    {
                        mstore(mptr, mload(sum_mptr))
                    }
                    success := batch_invert(success, 0, 0xa0, r)
                    let r_eval := mulmod(mload(0x80), mload(0x06c0), r)
                    for
                        {
                            let sum_inv_mptr := 0x60
                            let sum_inv_mptr_end := 0xa0
                            let r_eval_mptr := 0x06a0
                        }
                        lt(sum_inv_mptr, sum_inv_mptr_end)
                        {
                            sum_inv_mptr := sub(sum_inv_mptr, 0x20)
                            r_eval_mptr := sub(r_eval_mptr, 0x20)
                        }
                    {
                        r_eval := mulmod(r_eval, mload(NU_MPTR), r)
                        r_eval := addmod(r_eval, mulmod(mload(sum_inv_mptr), mload(r_eval_mptr), r), r)
                    }
                    mstore(R_EVAL_MPTR, r_eval)
                }
                {
                    let nu := mload(NU_MPTR)
                    mstore(0x00, calldataload(0x01a4))
                    mstore(0x20, calldataload(0x01c4))
                    for
                        {
                            let mptr := 0x0164
                            let mptr_end := 0x24
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_acc(success, mload(ZETA_MPTR))
                        success := ec_add_acc(success, calldataload(mptr), calldataload(add(mptr, 0x20)))
                    }
                    mstore(0x80, calldataload(0x05a4))
                    mstore(0xa0, calldataload(0x05c4))
                    success := ec_mul_tmp(success, mload(ZETA_MPTR))
                    success := ec_add_tmp(success, mload(QUOTIENT_X_MPTR), mload(QUOTIENT_Y_MPTR))
                    for
                        {
                            let mptr := 0x1140
                            let mptr_end := 0x0c80
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_tmp(success, mload(ZETA_MPTR))
                        success := ec_add_tmp(success, mload(mptr), mload(add(mptr, 0x20)))
                    }
                    success := ec_mul_tmp(success, mload(ZETA_MPTR))
                    success := ec_add_tmp(success, mload(0x0c40), mload(0x0c60))
                    success := ec_mul_tmp(success, mload(ZETA_MPTR))
                    success := ec_add_tmp(success, mload(0x0c80), mload(0x0ca0))
                    success := ec_mul_tmp(success, mload(ZETA_MPTR))
                    success := ec_add_tmp(success, calldataload(0x0364), calldataload(0x0384))
                    success := ec_mul_tmp(success, mload(ZETA_MPTR))
                    success := ec_add_tmp(success, calldataload(0x02e4), calldataload(0x0304))
                    for
                        {
                            let mptr := 0x0264
                            let mptr_end := 0x01a4
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_tmp(success, mload(ZETA_MPTR))
                        success := ec_add_tmp(success, calldataload(mptr), calldataload(add(mptr, 0x20)))
                    }
                    success := ec_mul_tmp(success, mulmod(nu, mload(0x05c0), r))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    nu := mulmod(nu, mload(NU_MPTR), r)
                    mstore(0x80, calldataload(0x04a4))
                    mstore(0xa0, calldataload(0x04c4))
                    for
                        {
                            let mptr := 0x0464
                            let mptr_end := 0x0364
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_tmp(success, mload(ZETA_MPTR))
                        success := ec_add_tmp(success, calldataload(mptr), calldataload(add(mptr, 0x20)))
                    }
                    success := ec_mul_tmp(success, mulmod(nu, mload(0x05e0), r))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    nu := mulmod(nu, mload(NU_MPTR), r)
                    mstore(0x80, calldataload(0x0564))
                    mstore(0xa0, calldataload(0x0584))
                    success := ec_mul_tmp(success, mload(ZETA_MPTR))
                    success := ec_add_tmp(success, calldataload(0x0524), calldataload(0x0544))
                    success := ec_mul_tmp(success, mload(ZETA_MPTR))
                    success := ec_add_tmp(success, calldataload(0x04e4), calldataload(0x0504))
                    success := ec_mul_tmp(success, mulmod(nu, mload(0x0600), r))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    nu := mulmod(nu, mload(NU_MPTR), r)
                    mstore(0x80, calldataload(0x0324))
                    mstore(0xa0, calldataload(0x0344))
                    success := ec_mul_tmp(success, mload(ZETA_MPTR))
                    success := ec_add_tmp(success, calldataload(0x02a4), calldataload(0x02c4))
                    success := ec_mul_tmp(success, mulmod(nu, mload(0x0620), r))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(0x80, mload(G1_X_MPTR))
                    mstore(0xa0, mload(G1_Y_MPTR))
                    success := ec_mul_tmp(success, sub(r, mload(R_EVAL_MPTR)))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(0x80, calldataload(0x1024))
                    mstore(0xa0, calldataload(0x1044))
                    success := ec_mul_tmp(success, sub(r, mload(0x0580)))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(0x80, calldataload(0x1064))
                    mstore(0xa0, calldataload(0x1084))
                    success := ec_mul_tmp(success, mload(MU_MPTR))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(PAIRING_LHS_X_MPTR, mload(0x00))
                    mstore(PAIRING_LHS_Y_MPTR, mload(0x20))
                    mstore(PAIRING_RHS_X_MPTR, calldataload(0x1064))
                    mstore(PAIRING_RHS_Y_MPTR, calldataload(0x1084))
                }
            }

            // Random linear combine with accumulator
            if mload(HAS_ACCUMULATOR_MPTR) {
                mstore(0x00, mload(ACC_LHS_X_MPTR))
                mstore(0x20, mload(ACC_LHS_Y_MPTR))
                mstore(0x40, mload(ACC_RHS_X_MPTR))
                mstore(0x60, mload(ACC_RHS_Y_MPTR))
                mstore(0x80, mload(PAIRING_LHS_X_MPTR))
                mstore(0xa0, mload(PAIRING_LHS_Y_MPTR))
                mstore(0xc0, mload(PAIRING_RHS_X_MPTR))
                mstore(0xe0, mload(PAIRING_RHS_Y_MPTR))
                let challenge := mod(keccak256(0x00, 0x100), r)

                // [pairing_lhs] += challenge * [acc_lhs]
                success := ec_mul_acc(success, challenge)
                success := ec_add_acc(success, mload(PAIRING_LHS_X_MPTR), mload(PAIRING_LHS_Y_MPTR))
                mstore(PAIRING_LHS_X_MPTR, mload(0x00))
                mstore(PAIRING_LHS_Y_MPTR, mload(0x20))

                // [pairing_rhs] += challenge * [acc_rhs]
                mstore(0x00, mload(ACC_RHS_X_MPTR))
                mstore(0x20, mload(ACC_RHS_Y_MPTR))
                success := ec_mul_acc(success, challenge)
                success := ec_add_acc(success, mload(PAIRING_RHS_X_MPTR), mload(PAIRING_RHS_Y_MPTR))
                mstore(PAIRING_RHS_X_MPTR, mload(0x00))
                mstore(PAIRING_RHS_Y_MPTR, mload(0x20))
            }

            // Perform pairing
            success := ec_pairing(
                success,
                mload(PAIRING_LHS_X_MPTR),
                mload(PAIRING_LHS_Y_MPTR),
                mload(PAIRING_RHS_X_MPTR),
                mload(PAIRING_RHS_Y_MPTR)
            )

            // Revert if anything fails
            if iszero(success) {
                revert(0x00, 0x00)
            }

            // Return 1 as result if everything succeeds
            mstore(0x00, 1)
            return(0x00, 0x20)
        }
    }
}