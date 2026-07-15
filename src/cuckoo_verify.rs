// Copyright 2026 Shane Jaroch
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

extern crate alloc;

use alloc::string::String;
use core::fmt::Write;
use sha3::{Digest, Keccak256};

pub const ALGORITHM: &str = "tk.nutra.msc45xx.pow.cuckoo-cycle-42-29-keccak256-cogen";
pub const EDGE_BITS: u32 = 29;
pub const PROOF_SIZE: usize = 42;
pub const NEDGES: u64 = 1_u64 << EDGE_BITS;
pub const EDGE_MASK: u64 = NEDGES - 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    WrongAlgorithm,
    WrongProofSize { len: usize },
    EdgeTooBig,
    EdgesNotAscending,
    NonMatchingEndpoints,
    Branch,
    DeadEnd,
    ShortCycle,
    ShortKeyIdMismatch,
}

impl VerifyError {
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::WrongAlgorithm => "wrong algorithm",
            Self::WrongProofSize { .. } => "wrong proof size",
            Self::EdgeTooBig => "edge too big",
            Self::EdgesNotAscending => "edges not ascending",
            Self::NonMatchingEndpoints => "endpoints don't match up",
            Self::Branch => "branch in cycle",
            Self::DeadEnd => "cycle dead ends",
            Self::ShortCycle => "cycle too short",
            Self::ShortKeyIdMismatch => "short key id mismatch",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CuckooVerifier {
    keys: SipHashKeys,
}

impl CuckooVerifier {
    #[must_use]
    pub fn new(public_key: &str, server_name: &str, nonce: u64) -> Self {
        Self::from_graph_seed(graph_seed(public_key, server_name, nonce))
    }

    #[must_use]
    pub fn from_graph_seed(seed: [u8; 32]) -> Self {
        Self {
            keys: SipHashKeys::from_keybuf(&seed),
        }
    }

    /// Verify that `edges` form a single Cuckoo Cycle in this verifier's graph.
    ///
    /// # Errors
    ///
    /// Returns [`VerifyError`] if the proof has the wrong shape, contains an
    /// out-of-range or unsorted edge, or does not form one full 42-edge cycle.
    pub fn verify(self, edges: &[u64]) -> Result<(), VerifyError> {
        verify_edges(edges, self.keys)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MintingPow<'a> {
    pub algorithm: &'a str,
    pub nonce: u64,
    pub solution: &'a [u64],
}

/// Verify an MSC00E4 minting proof and return the full minting `key_id`.
///
/// # Errors
///
/// Returns [`VerifyError`] if the algorithm identifier is not the supported
/// MSC00E4 profile, the Cuckoo solution fails validation, or the advertised
/// short key id does not match the derived minting key id.
pub fn verify_minting_pow(
    server_name: &str,
    public_key: &str,
    advertised_short_key_id: &str,
    pow: MintingPow<'_>,
) -> Result<[u8; 32], VerifyError> {
    if pow.algorithm != ALGORITHM {
        return Err(VerifyError::WrongAlgorithm);
    }

    CuckooVerifier::new(public_key, server_name, pow.nonce).verify(pow.solution)?;

    let key_id = minting_key_id(server_name, public_key, pow)?;
    let short_key_id = short_key_id(&key_id);
    if short_key_id != advertised_short_key_id {
        return Err(VerifyError::ShortKeyIdMismatch);
    }

    Ok(key_id)
}

#[must_use]
pub fn graph_seed(public_key: &str, server_name: &str, nonce: u64) -> [u8; 32] {
    let mut graph_object = String::new();
    graph_object.push_str("{\"action\":\"fn-dsa-key-graph\",\"public_key\":");
    push_json_string(&mut graph_object, public_key);
    graph_object.push_str(",\"server_name\":");
    push_json_string(&mut graph_object, server_name);
    graph_object.push('}');

    let mut hasher = Keccak256::new();
    hasher.update(graph_object.as_bytes());
    hasher.update(nonce.to_le_bytes());
    hasher.finalize().into()
}

/// Derive the full MSC00E4 minting `key_id`.
///
/// # Errors
///
/// Returns [`VerifyError`] if `pow.algorithm` is not the supported MSC00E4
/// profile or if `pow.solution` is not exactly 42 strictly increasing in-range
/// edge indices.
pub fn minting_key_id(
    server_name: &str,
    public_key: &str,
    pow: MintingPow<'_>,
) -> Result<[u8; 32], VerifyError> {
    if pow.algorithm != ALGORITHM {
        return Err(VerifyError::WrongAlgorithm);
    }
    validate_solution_shape(pow.solution)?;

    let mut minting_object = String::new();
    minting_object.push_str("{\"action\":\"fn-dsa-minting-object\",\"algorithm\":");
    push_json_string(&mut minting_object, pow.algorithm);
    write!(minting_object, ",\"nonce\":{}", pow.nonce).expect("writing to String cannot fail");
    minting_object.push_str(",\"public_key\":");
    push_json_string(&mut minting_object, public_key);
    minting_object.push_str(",\"server_name\":");
    push_json_string(&mut minting_object, server_name);
    minting_object.push_str(",\"solution\":[");
    for (n, edge) in pow.solution.iter().enumerate() {
        if n > 0 {
            minting_object.push(',');
        }
        write!(minting_object, "{edge}").expect("writing to String cannot fail");
    }
    minting_object.push_str("]}");

    Ok(keccak256(minting_object.as_bytes()))
}

#[must_use]
pub fn short_key_id(key_id: &[u8; 32]) -> String {
    base64url_no_pad(key_id)
        .chars()
        .take(20)
        .collect::<String>()
}

fn verify_edges(edges: &[u64], keys: SipHashKeys) -> Result<(), VerifyError> {
    validate_solution_shape(edges)?;

    let mut uvs = [0_u64; 2 * PROOF_SIZE];
    let mut xor0 = 0_u64;
    let mut xor1 = 0_u64;

    for (uv_pair, edge) in uvs.chunks_exact_mut(2).zip(edges.iter().copied()) {
        let u = sipnode(keys, edge, 0);
        let v = sipnode(keys, edge, 1);
        uv_pair[0] = u;
        uv_pair[1] = v;
        xor0 ^= u;
        xor1 ^= v;
    }

    if (xor0 | xor1) != 0 {
        return Err(VerifyError::NonMatchingEndpoints);
    }

    verify_cycle_uvs(&uvs)
}

fn verify_cycle_uvs(uvs: &[u64; 2 * PROOF_SIZE]) -> Result<(), VerifyError> {
    let mut n = 0_usize;
    let mut i = 0_usize;
    loop {
        let mut j = i;
        let mut k = i;
        loop {
            k = next_same_partition_index(k, uvs.len());
            if k == i {
                break;
            }
            if uvs[k] == uvs[i] {
                if j != i {
                    return Err(VerifyError::Branch);
                }
                j = k;
            }
        }

        if j == i {
            return Err(VerifyError::DeadEnd);
        }

        i = j ^ 1;
        n = n
            .checked_add(1)
            .expect("cycle length cannot exceed proof size");
        if i == 0 {
            break;
        }
    }

    if n == PROOF_SIZE {
        Ok(())
    } else {
        Err(VerifyError::ShortCycle)
    }
}

fn validate_solution_shape(edges: &[u64]) -> Result<(), VerifyError> {
    if edges.len() != PROOF_SIZE {
        return Err(VerifyError::WrongProofSize { len: edges.len() });
    }

    let mut previous = None;
    for edge in edges.iter().copied() {
        if edge > EDGE_MASK {
            return Err(VerifyError::EdgeTooBig);
        }
        if previous.is_some_and(|previous| edge <= previous) {
            return Err(VerifyError::EdgesNotAscending);
        }
        previous = Some(edge);
    }

    Ok(())
}

fn next_same_partition_index(index: usize, len: usize) -> usize {
    index
        .checked_add(2)
        .filter(|next| *next < len)
        .unwrap_or(index & 1)
}

fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(input);
    hasher.finalize().into()
}

fn push_json_string(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch <= '\u{1f}' => {
                write!(out, "\\u{:04x}", ch as u32).expect("writing to String cannot fail");
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
}

fn base64url_no_pad(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    let mut out = String::new();
    let mut chunks = bytes.chunks_exact(3);
    for chunk in &mut chunks {
        let n = (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]);
        out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 6) & 0x3f) as usize] as char);
        out.push(ALPHABET[(n & 0x3f) as usize] as char);
    }

    match chunks.remainder() {
        [a] => {
            let n = u32::from(*a) << 16;
            out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
            out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        }
        [a, b] => {
            let n = (u32::from(*a) << 16) | (u32::from(*b) << 8);
            out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
            out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
            out.push(ALPHABET[((n >> 6) & 0x3f) as usize] as char);
        }
        [] => {}
        _ => unreachable!("chunks_exact remainder length is less than 3"),
    }

    out
}

#[derive(Debug, Clone, Copy)]
struct SipHashKeys {
    k0: u64,
    k1: u64,
    k2: u64,
    k3: u64,
}

impl SipHashKeys {
    fn from_keybuf(keybuf: &[u8; 32]) -> Self {
        let mut chunks = keybuf.chunks_exact(size_of::<u64>());
        Self {
            k0: next_u64_le(&mut chunks),
            k1: next_u64_le(&mut chunks),
            k2: next_u64_le(&mut chunks),
            k3: next_u64_le(&mut chunks),
        }
    }

    fn siphash24(self, nonce: u64) -> u64 {
        let mut state = SipHashState::from_keys(self);
        state.hash24(nonce);
        state.xor_lanes()
    }
}

#[derive(Debug, Clone, Copy)]
struct SipHashState {
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,
}

impl SipHashState {
    const fn from_keys(keys: SipHashKeys) -> Self {
        Self {
            v0: keys.k0,
            v1: keys.k1,
            v2: keys.k2,
            v3: keys.k3,
        }
    }

    const fn xor_lanes(self) -> u64 {
        (self.v0 ^ self.v1) ^ (self.v2 ^ self.v3)
    }

    fn sip_round(&mut self) {
        self.v0 = self.v0.wrapping_add(self.v1);
        self.v2 = self.v2.wrapping_add(self.v3);
        self.v1 = self.v1.rotate_left(13);
        self.v3 = self.v3.rotate_left(16);
        self.v1 ^= self.v0;
        self.v3 ^= self.v2;
        self.v0 = self.v0.rotate_left(32);
        self.v2 = self.v2.wrapping_add(self.v1);
        self.v0 = self.v0.wrapping_add(self.v3);
        self.v1 = self.v1.rotate_left(17);
        self.v3 = self.v3.rotate_left(21);
        self.v1 ^= self.v2;
        self.v3 ^= self.v0;
        self.v2 = self.v2.rotate_left(32);
    }

    fn hash24(&mut self, nonce: u64) {
        self.v3 ^= nonce;
        self.sip_round();
        self.sip_round();
        self.v0 ^= nonce;
        self.v2 ^= 0xff;
        self.sip_round();
        self.sip_round();
        self.sip_round();
        self.sip_round();
    }
}

fn sipnode(keys: SipHashKeys, edge: u64, uorv: u64) -> u64 {
    keys.siphash24(edge.wrapping_mul(2).wrapping_add(uorv)) & EDGE_MASK
}

fn next_u64_le(chunks: &mut core::slice::ChunksExact<'_, u8>) -> u64 {
    let bytes = chunks
        .next()
        .expect("32-byte key contains four 64-bit words");
    let mut word = [0_u8; size_of::<u64>()];
    word.copy_from_slice(bytes);
    u64::from_le_bytes(word)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_error_messages_cover_all_variants() {
        assert_eq!(VerifyError::WrongAlgorithm.message(), "wrong algorithm");
        assert_eq!(
            VerifyError::WrongProofSize { len: 3 }.message(),
            "wrong proof size"
        );
        assert_eq!(VerifyError::EdgeTooBig.message(), "edge too big");
        assert_eq!(
            VerifyError::EdgesNotAscending.message(),
            "edges not ascending"
        );
        assert_eq!(
            VerifyError::NonMatchingEndpoints.message(),
            "endpoints don't match up"
        );
        assert_eq!(VerifyError::Branch.message(), "branch in cycle");
        assert_eq!(VerifyError::DeadEnd.message(), "cycle dead ends");
        assert_eq!(VerifyError::ShortCycle.message(), "cycle too short");
        assert_eq!(
            VerifyError::ShortKeyIdMismatch.message(),
            "short key id mismatch"
        );
    }

    #[test]
    fn rejects_wrong_proof_size() {
        let verifier = CuckooVerifier::new("", "example.com", 0);
        assert_eq!(
            verifier.verify(&[]),
            Err(VerifyError::WrongProofSize { len: 0 })
        );
    }

    #[test]
    fn rejects_unsorted_edges() {
        let verifier = CuckooVerifier::new("", "example.com", 0);
        let mut edges = [0_u64; PROOF_SIZE];
        for (n, edge) in edges.iter_mut().enumerate() {
            *edge = n as u64;
        }
        edges[2] = edges[1];

        assert_eq!(verifier.verify(&edges), Err(VerifyError::EdgesNotAscending));
    }

    #[test]
    fn rejects_out_of_range_edges() {
        let verifier = CuckooVerifier::new("", "example.com", 0);
        let mut edges = [0_u64; PROOF_SIZE];
        for (n, edge) in edges.iter_mut().enumerate() {
            *edge = n as u64;
        }
        edges[PROOF_SIZE - 1] = NEDGES;

        assert_eq!(verifier.verify(&edges), Err(VerifyError::EdgeTooBig));
    }

    #[test]
    fn derives_short_key_id_from_minting_object() {
        let edges: [u64; PROOF_SIZE] = core::array::from_fn(|n| n as u64);
        let pow = MintingPow {
            algorithm: ALGORITHM,
            nonce: 84,
            solution: &edges,
        };

        let key_id = minting_key_id("nutra.tk", "abc", pow).unwrap();
        assert_eq!(short_key_id(&key_id).len(), 20);
    }

    #[test]
    fn rejects_wrong_algorithm_in_public_apis() {
        let edges: [u64; PROOF_SIZE] = core::array::from_fn(|n| n as u64);
        let pow = MintingPow {
            algorithm: "wrong",
            nonce: 84,
            solution: &edges,
        };

        assert_eq!(
            minting_key_id("nutra.tk", "abc", pow),
            Err(VerifyError::WrongAlgorithm)
        );
        assert_eq!(
            verify_minting_pow("nutra.tk", "abc", "whatever", pow),
            Err(VerifyError::WrongAlgorithm)
        );
    }

    #[test]
    fn rejects_short_key_id_mismatch() {
        let solution = [
            15_721_871,
            27_250_623,
            40_834_937,
            43_089_700,
            49_725_675,
            94_429_136,
            100_270_530,
            101_621_147,
            119_359_847,
            129_180_026,
            130_819_554,
            132_047_606,
            133_673_049,
            140_712_204,
            162_316_408,
            191_597_252,
            200_891_275,
            237_223_519,
            238_025_377,
            239_844_395,
            243_515_852,
            280_600_236,
            287_522_429,
            288_472_108,
            307_373_788,
            335_402_039,
            350_999_160,
            361_015_004,
            376_986_040,
            377_645_573,
            380_999_152,
            381_251_514,
            384_445_789,
            400_545_618,
            405_885_023,
            407_988_043,
            454_991_081,
            456_836_508,
            460_439_916,
            488_639_123,
            505_128_561,
            517_987_691,
        ];
        let pow = MintingPow {
            algorithm: ALGORITHM,
            nonce: 84,
            solution: &solution,
        };

        assert_eq!(
            verify_minting_pow("nutra.tk", TEST_PUBLIC_KEY, "wrong-short-key-id", pow),
            Err(VerifyError::ShortKeyIdMismatch)
        );
    }

    #[test]
    fn verify_cycle_uvs_rejects_non_matching_branch_dead_end_and_short_cycle() {
        let mut non_matching = [0_u64; 2 * PROOF_SIZE];
        for (n, pair) in non_matching.chunks_exact_mut(2).enumerate() {
            pair[0] = n as u64;
            pair[1] = n as u64;
        }
        let mut xor0 = 0_u64;
        let mut xor1 = 0_u64;
        for pair in non_matching.chunks_exact(2) {
            xor0 ^= pair[0];
            xor1 ^= pair[1];
        }
        assert_ne!(xor0 | xor1, 0);

        let verifier = CuckooVerifier::from_graph_seed([0_u8; 32]);
        let edges: [u64; PROOF_SIZE] = core::array::from_fn(|n| (n as u64) + 1);
        assert_eq!(
            verifier.verify(&edges),
            Err(VerifyError::NonMatchingEndpoints)
        );

        let mut branch = [0_u64; 2 * PROOF_SIZE];
        branch[0] = 7;
        branch[2] = 7;
        branch[4] = 7;
        assert_eq!(verify_cycle_uvs(&branch), Err(VerifyError::Branch));

        let mut dead_end = [0_u64; 2 * PROOF_SIZE];
        for (n, pair) in dead_end.chunks_exact_mut(2).enumerate() {
            pair[0] = n as u64;
            pair[1] = n as u64;
        }
        dead_end[2] = 99;
        assert_eq!(verify_cycle_uvs(&dead_end), Err(VerifyError::DeadEnd));

        let mut short_cycle = [0_u64; 2 * PROOF_SIZE];
        short_cycle[0] = 11;
        short_cycle[1] = 22;
        short_cycle[2] = 11;
        short_cycle[3] = 22;
        assert_eq!(verify_cycle_uvs(&short_cycle), Err(VerifyError::ShortCycle));
    }

    #[test]
    fn push_json_string_escapes_special_characters() {
        let mut out = String::new();
        push_json_string(&mut out, "\"\\\u{08}\u{0c}\n\r\t\u{001f}plain");
        assert_eq!(out, "\"\\\"\\\\\\b\\f\\n\\r\\t\\u001fplain\"");
    }

    #[test]
    fn base64url_no_pad_covers_remainder_cases() {
        assert_eq!(base64url_no_pad(&[]), "");
        assert_eq!(base64url_no_pad(b"f"), "Zg");
        assert_eq!(base64url_no_pad(b"fo"), "Zm8");
        assert_eq!(base64url_no_pad(b"foo"), "Zm9v");
    }

    #[test]
    fn verifies_00e4_minting_vector() {
        let solution = [
            15_721_871,
            27_250_623,
            40_834_937,
            43_089_700,
            49_725_675,
            94_429_136,
            100_270_530,
            101_621_147,
            119_359_847,
            129_180_026,
            130_819_554,
            132_047_606,
            133_673_049,
            140_712_204,
            162_316_408,
            191_597_252,
            200_891_275,
            237_223_519,
            238_025_377,
            239_844_395,
            243_515_852,
            280_600_236,
            287_522_429,
            288_472_108,
            307_373_788,
            335_402_039,
            350_999_160,
            361_015_004,
            376_986_040,
            377_645_573,
            380_999_152,
            381_251_514,
            384_445_789,
            400_545_618,
            405_885_023,
            407_988_043,
            454_991_081,
            456_836_508,
            460_439_916,
            488_639_123,
            505_128_561,
            517_987_691,
        ];
        let pow = MintingPow {
            algorithm: ALGORITHM,
            nonce: 84,
            solution: &solution,
        };

        let key_id = verify_minting_pow("nutra.tk", TEST_PUBLIC_KEY, "BjDCRkH5l3MJzj-Xu1yq", pow)
            .expect("minting proof should verify");

        assert_eq!(
            base64url_no_pad(&key_id),
            "BjDCRkH5l3MJzj-Xu1yq_SXCGhvaK9ZnQjqilaV8EHU"
        );
    }

    const TEST_PUBLIC_KEY: &str = "CTYtwUD318oD9bK6+eH+j3ZvomWtDoPMrQaXnEaIVrM34JJMfArWxtemeoeMNwbuIw4lnix6sKAjW5CW0BMD4Z8cs+vGznqWyH5i2krbetj5ClOFH2TllrXgAPuLcQp4qtMCANwaE/KSMomw3LOyyxo29djzPFu7VRRaAAvWGC66dAYiT9KH1JyxgwVjcChe+glZVEQIvjBiaklVjGdTqOZWpNiSNnQSYJsAIsCwpWAuWQ1S0UaYP4WKEQlsX5L6O8PChppEBl07OJnZv1QA1FvC1Uwxv0s13EUfSr4ojhtREZ2u+AGIS2reZLCc2ucGUQ9ZHI73aZSYulsGrgJZoKbOEjZvvM2WJkSHuNLGO14ll2t2XoLJ3BxTuFBFcsKXHAKi9VFk14BOMKFvboMfPS/glIlXbbUbQkTc3z2YdApSavhQxuIXDmctTx5ioj8eprWsHmrT3vwZSAkRW+bfNHRVWzjS0FvOYsfqxuxvJiM2iwLSHqgs8wPskLTOQwJoWjYBPjWDGlfLHXGJ5e8qXCQOAVQ+LthGTtrYHmCjlMyKi1BpIiHAm2tNI2yUmSaDJ9xhnt6Ve/QI2VRJfocZzRlZyaOHkEBpSKjjxm7GjXV2QmO7UROVVd7IKIZVeCTiG9jhfJ2VTbaXaYqVZRS3yFsKTtwyF5yW5FssQRV7JORKvecHGIMuPcSS+e0TSC+IMTHWK2hC1o+GMdwjpp0NNQCCL144tpVsb2a00kVSdkfcBeCKcXUPHrwYXki7ywd7GYgwVmj6HCo0ZrDAhnmsFse+I3VAhBikzCgZkzWaAFwA1nlwtrK42j2PaPLGS8r6qJSMFQ5R6kZNv8fnZT8F8ccCZuihpT43+SivwCQBMCKgQBinynrX/eGvVmTREv4BtLboWYbnwK9dLteR9y9GiPBHtGqsLzUAZ7KHmjRiEMtFJgXZlC2ygZov80SIZqJ/b8d8DKMGa25RrSzo1EMdoKGe8/NEiqKBdsM7aCjrrEC9SnuNtUre7QugoD5bcsXFSY+HaBqGse4fQbTdHnipZPwPLS2zLZyuoIivJKjBfaQZV0DfGlSHzR705QT3Ivh6F41Lpa7hsnDci6mfwIbnMMxcDLrsxkFhMWik6AjLYyuATVxBYiFrJhFRMx/FPh36SDXEDr9OrOM2jsIdYfKu2yVQAFxC1Ijez5iQfGqTUMVn";
}
