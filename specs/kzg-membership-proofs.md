# KZG Membership proofs

> inspired by https://research.polytope.technology/zkcasper

#### $KZG.Setup(t, s)$
- Given some secret value $s$, where $s \in \mathbb{F}_p$​. This method generates a common reference string $srs_{kzg}$ that allows anyone commit to a polynomial of degree $\leq t$ ie. to a maximum of $t$ validators.
- > IMPORTANT: The secret value $s$ should not be recoverable, otherwise the prover can generate fraudulent proofs that can successfully fool the verifier.
- In practice should involve trusted setup (powers of tau) ceremony.

#### $KZG.Commit(srs_{kzg}, T)$
- given a set of public keys $T =\{pk_i, \nu_i\}^t_{i=1}$
- for public keys $\{pk_i\}^t_{i=1}$, we commit to $x$ and $y$ coordinates separately producing $\langle C_x, C_y\rangle$
	- > NOTE: since coordinates are base fields the resulted commitments are to be projected on a curve whose scalar equals to the base field of BLS12-381 (eg. [BW6-767](https://hackmd.io/@gnark/bw6_bls12381) or [YT6-776](https://github.com/timoftime/zk-timelock/tree/main/src/yt6_776)).
- for balances $\{\nu_i\}^t_{i=1}$, we treat KZG as vector commitment scheme and encode balances as $\mathbb{F}_r$ elements and commit to them to get $C_{\nu}$
- we also want to generate proof to allow users/contract to succinctly verify this initial commitment (preferably) without knowing all the validators. Options are:
	1. KZG multi-proof to all values though it unclear whether that would be more efficient than just building commitment again TBD
	2. Commitment inside ZKP (not necessarily SNARK) TBD
- outputs $\langle C_x, C_y, C_{\nu}, \pi_{kzg}\rangle$

#### (alternative) $Merkle.Commit(T)$
- given a set of public keys $T =\{pk_i, \nu_i\}^t_{i=1}$
- generate a Merkle tree using a snark-friendly hash function
- depending on requirements public keys and balances can be committed using a single or separate Merkle trees
- Merkle tree implementation must be optimized for insert/delete complexity
	- Sparse Merkle trees?
- for public verification, this can be implemented as a layered arithmetic circuit for GKR (see [benchmarks](https://ethresear.ch/t/performance-improvement-for-gkr/12228)) - this assumes MIMC/gMIMC hash function
- outputs $\langle C_x, C_y, C_{\nu}, \pi_{kzg}\rangle$

#### $ProveValidatorSetUpdate(h, C, I)$
- given:
	- (public) state root $h$ of a beacon epoch boundary block
	- (public) last trusted commitment $C$ to the validator registry
	- (private) set $I$ of validators ${v_i: (pk_i, \nu_i)}^{|I|}_{i=0}$ whose status (`joined`, `exit_epoch`, `activated_epoch`, `slashed`) changed with respect to the latest trusted epoch block
- off-circuit:
	- generate Merkle multi-proof $\pi_{merkle}$ for all validators $v_i$
	- compute Lagrange bases $g^{\mathcal{L}_i(s)}$ and KZG multi-proof $\pi_{\mathcal{L}}$ that these values lie on the polynomial $L(x) = \sum^n_{i=0} \mathcal{L}_i(x)$
- circuit:
	- verify Merkle multi-proof $\pi_{merkle}$
	- update the commitment $C \rightarrow C'$  in values $\{v_i \rightarrow v'_i \} \forall i \in I$ by:
		- verify $\pi_{\mathcal{L}}$
		- multiply $C$ by the Lagrange bases $g^{\mathcal{L}_i(s)}$ (provided by the prover) and $\delta_i$:  $C' = C \cdot \prod^{|I|}_{i=0}$
		- $\delta_i = v'_i - v_i$ ie. $v_i$ to add value (activated validator pubkey) or $-v_i$ to remove value (deactivated validator pubkey)
- outputs $\langle C',\pi_{vsu}\rangle$
- notes:
	- the reason why protocol separates this function from the next one is that TODO
	- updating commitments would require dealing with non-native arithmetic for BW6-776-like curve

