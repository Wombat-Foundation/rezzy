# Ruma-Lean: ZK Public Interface (The Journal)

To verify a Matrix State Resolution proof, a verifier (homeserver or client) requires the following inputs. These inputs are cryptographically bound to the STARK proof.

## 1. The Verification Key (VK)

- **Type**: 32-byte Merkle Root (SHA-256/Poseidon2).
- **Role**: The "Fingerprint" of the business logic. It represents the abstract polynomial equations ($X \cdot (X-1) = 0$) proved in `RumaLean/Arithmetization.lean`.
- **Source**: Hardcoded in the official Matrix Specification (e.g., MSC4297).

## 2. The Public Journal (Inputs)

The **Journal** is a small, non-private data structure included in the proof. The STARK math ensures that the proof is _only_ valid for these specific values.

| Field             | Type        | Description                                         |
| :---------------- | :---------- | :-------------------------------------------------- |
| `merge_base_hash` | `Hash`      | The ZK-friendly hash of the last agreed-upon state. |
| `tip_hashes`      | `List Hash` | The hashes of the conflicting event heads.          |
| `post_state_root` | `Hash`      | The resulting state root after resolution.          |
| `room_version`    | `u8`        | The Matrix room version (e.g., 6, 10, 12).          |

## 3. The Verifier's Protocol

The verifier does not "trust" the prover. It performs the following steps:

1. **Load VK**: Ensure the local VK matches the official Matrix Spec.
2. **Bind Journal**: Extract the `merge_base_hash` and `tip_hashes` from the local database.
3. **Verify STARK**: Run the FRI (Fast Reed-Solomon Interactive) protocol checks.
4. **Sampling**: The verifier randomly samples the prover's execution trace (via the FRI protocol) to ensure the polynomials equal zero at every point.

**Result**: If `verify(VK, Journal, Proof) == True`, the post-state root is mathematically guaranteed to be the correct, deterministic resolution of the fork.
