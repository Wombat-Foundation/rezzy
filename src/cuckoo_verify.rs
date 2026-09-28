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

//! Cuckoo Cycle proof-of-work verification and key minting primitives.

extern crate alloc;

use alloc::string::String;
use core::fmt::Write;
use core::mem::size_of;
use sha3::{Digest, Sha3_256};

pub const ALGORITHM: &str = "tk.nutra.msc45xx.pow.cuckoo-cycle-42-29-sha3-256-key-minting";
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
    verify_short_key_id(&key_id, advertised_short_key_id)?;

    Ok(key_id)
}

fn verify_short_key_id(
    key_id: &[u8; 32],
    advertised_short_key_id: &str,
) -> Result<(), VerifyError> {
    if short_key_id(key_id) == advertised_short_key_id {
        Ok(())
    } else {
        Err(VerifyError::ShortKeyIdMismatch)
    }
}

#[must_use]
pub fn graph_seed(public_key: &str, server_name: &str, nonce: u64) -> [u8; 32] {
    let mut graph_object = String::new();
    graph_object.push_str("{\"action\":\"fn-dsa-key-graph\",\"public_key\":");
    push_json_string(&mut graph_object, public_key);
    graph_object.push_str(",\"server_name\":");
    push_json_string(&mut graph_object, server_name);
    graph_object.push('}');

    let mut hasher = Sha3_256::new();
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

    Ok(sha3_256(minting_object.as_bytes()))
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
        if n > PROOF_SIZE || i == 0 {
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

fn sha3_256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
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
        _ => {}
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
    keys.siphash24(edge.wrapping_mul(2).wrapping_add(uorv)) & ((1_u64 << (EDGE_BITS - 1)) - 1)
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
#[cfg_attr(coverage_nightly, coverage(off))]
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
        assert_eq!(
            verify_short_key_id(&[0_u8; 32], "wrong-short-key-id"),
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
    fn derives_00e4_sha3_vectors() {
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
            graph_seed(TEST_PUBLIC_KEY, "nutra.tk", 84),
            [
                0xce, 0xc4, 0x0c, 0xa7, 0x52, 0x68, 0x16, 0x4c, 0x34, 0x76, 0x49, 0xbc, 0xec, 0x04,
                0xa1, 0xb0, 0xa8, 0x44, 0x7b, 0x0f, 0xe1, 0xfc, 0xec, 0x88, 0x1b, 0x91, 0x19, 0xd0,
                0xcd, 0x24, 0x61, 0x36,
            ]
        );

        assert_eq!(
            base64url_no_pad(
                &minting_key_id("nutra.tk", TEST_PUBLIC_KEY, pow)
                    .expect("shape-valid minting object should hash")
            ),
            "8e1YvU6n-P8kl0qV4SqxYF7YP0DV2orKYvIjwsuFduI"
        );
    }

    #[test]
    fn verify_short_key_id_matches() {
        let key_id = [42_u8; 32];
        let advertised = short_key_id(&key_id);
        assert_eq!(verify_short_key_id(&key_id, &advertised), Ok(()));
    }

    #[test]
    fn rejects_empty_invalid_and_dead_end_minting_pow() {
        let pow_empty = MintingPow {
            algorithm: ALGORITHM,
            nonce: 84,
            solution: &[],
        };
        assert_eq!(
            verify_minting_pow("nutra.tk", TEST_PUBLIC_KEY, "whatever", pow_empty),
            Err(VerifyError::WrongProofSize { len: 0 })
        );

        let edges: [u64; PROOF_SIZE] = core::array::from_fn(|n| n as u64);
        let pow_invalid = MintingPow {
            algorithm: ALGORITHM,
            nonce: 84,
            solution: &edges,
        };
        assert_eq!(
            verify_minting_pow("nutra.tk", TEST_PUBLIC_KEY, "whatever", pow_invalid),
            Err(VerifyError::NonMatchingEndpoints)
        );

        let valid_matching_edges = [
            0, 1, 2, 5, 7, 8, 9, 12, 15, 20, 21, 22, 23, 24, 25, 26, 27, 29, 31, 33, 34, 35, 37,
            39, 41, 42, 43, 46, 47, 49, 50, 51, 52, 53, 54, 56, 57, 58, 59, 60, 61, 62,
        ];
        let pow_matching = MintingPow {
            algorithm: ALGORITHM,
            nonce: 84,
            solution: &valid_matching_edges,
        };
        assert_eq!(
            verify_minting_pow("nutra.tk", TEST_PUBLIC_KEY, "whatever", pow_matching),
            Err(VerifyError::DeadEnd)
        );
    }

    #[test]
    fn verify_minting_pow_returns_key_id_on_success() {
        // Genuine 42-cycle mined offline for (TEST_PUBLIC_KEY, "nutra.tk", nonce 3).
        let solution: [u64; PROOF_SIZE] = [
            721_297,
            9_513_298,
            27_540_167,
            29_552_787,
            35_452_767,
            44_271_093,
            49_305_956,
            53_087_052,
            54_202_483,
            56_178_377,
            58_042_779,
            60_432_276,
            64_973_509,
            66_003_936,
            67_900_759,
            73_919_907,
            76_802_455,
            86_858_463,
            101_376_335,
            106_888_118,
            109_124_655,
            109_681_439,
            110_954_208,
            128_693_198,
            130_012_434,
            147_508_739,
            156_825_434,
            175_013_018,
            184_113_046,
            197_116_101,
            197_550_463,
            213_286_076,
            218_210_692,
            222_739_466,
            225_422_231,
            225_577_405,
            230_201_870,
            247_481_907,
            253_448_206,
            262_629_872,
            266_080_043,
            266_673_992,
        ];
        let pow = MintingPow {
            algorithm: ALGORITHM,
            nonce: 3,
            solution: &solution,
        };

        let key_id = minting_key_id("nutra.tk", TEST_PUBLIC_KEY, pow).unwrap();
        let short = short_key_id(&key_id);

        assert_eq!(
            verify_minting_pow("nutra.tk", TEST_PUBLIC_KEY, &short, pow),
            Ok(key_id)
        );
        assert_eq!(
            verify_minting_pow("nutra.tk", TEST_PUBLIC_KEY, "wrong-short-key-id", pow),
            Err(VerifyError::ShortKeyIdMismatch)
        );
    }

    #[test]
    fn test_verify_cycle_uvs_valid_cycle() {
        let mut uvs = [0_u64; 2 * PROOF_SIZE];
        for k in 0..PROOF_SIZE {
            if k % 2 == 0 {
                uvs[2 * k] = k as u64;
                uvs[2 * k + 1] = (k as u64) + 1;
            } else {
                uvs[2 * k] = (k as u64) + 1;
                uvs[2 * k + 1] = k as u64;
            }
        }
        uvs[2 * (PROOF_SIZE - 1)] = 0;
        uvs[2 * (PROOF_SIZE - 1) + 1] = (PROOF_SIZE as u64) - 1;

        assert_eq!(verify_cycle_uvs(&uvs), Ok(()));
    }

    #[test]
    fn verify_cycle_uvs_rejects_short_cycle() {
        let mut uvs = [0_u64; 2 * PROOF_SIZE];
        // 4-edge cycle: (10,20) -> (30,20) -> (30,40) -> (10,40) -> (10,20)
        uvs[0] = 10;
        uvs[1] = 20;
        uvs[2] = 30;
        uvs[3] = 20;
        uvs[4] = 30;
        uvs[5] = 40;
        uvs[6] = 10;
        uvs[7] = 40;

        for k in 4..PROOF_SIZE {
            uvs[2 * k] = (100 + k) as u64;
            uvs[2 * k + 1] = (200 + k) as u64;
        }

        assert_eq!(verify_cycle_uvs(&uvs), Err(VerifyError::ShortCycle));
    }

    const TEST_PUBLIC_KEY: &str = "CTYtwUD318oD9bK6+eH+j3ZvomWtDoPMrQaXnEaIVrM34JJMfArWxtemeoeMNwbuIw4lnix6sKAjW5CW0BMD4Z8cs+vGznqWyH5i2krbetj5ClOFH2TllrXgAPuLcQp4qtMCANwaE/KSMomw3LOyyxo29djzPFu7VRRaAAvWGC66dAYiT9KH1JyxgwVjcChe+glZVEQIvjBiaklVjGdTqOZWpNiSNnQSYJsAIsCwpWAuWQ1S0UaYP4WKEQlsX5L6O8PChppEBl07OJnZv1QA1FvC1Uwxv0s13EUfSr4ojhtREZ2u+AGIS2reZLCc2ucGUQ9ZHI73aZSYulsGrgJZoKbOEjZvvM2WJkSHuNLGO14ll2t2XoLJ3BxTuFBFcsKXHAKi9VFk14BOMKFvboMfPS/glIlXbbUbQkTc3z2YdApSavhQxuIXDmctTx5ioj8eprWsHmrT3vwZSAkRW+bfNHRVWzjS0FvOYsfqxuxvJiM2iwLSHqgs8wPskLTOQwJoWjYBPjWDGlfLHXGJ5e8qXCQOAVQ+LthGTtrYHmCjlMyKi1BpIiHAm2tNI2yUmSaDJ9xhnt6Ve/QI2VRJfocZzRlZyaOHkEBpSKjjxm7GjXV2QmO7UROVVd7IKIZVeCTiG9jhfJ2VTbaXaYqVZRS3yFsKTtwyF5yW5FssQRV7JORKvecHGIMuPcSS+e0TSC+IMTHWK2hC1o+GMdwjpp0NNQCCL144tpVsb2a00kVSdkfcBeCKcXUPHrwYXki7ywd7GYgwVmj6HCo0ZrDAhnmsFse+I3VAhBikzCgZkzWaAFwA1nlwtrK42j2PaPLGS8r6qJSMFQ5R6kZNv8fnZT8F8ccCZuihpT43+SivwCQBMCKgQBinynrX/eGvVmTREv4BtLboWYbnwK9dLteR9y9GiPBHtGqsLzUAZ7KHmjRiEMtFJgXZlC2ygZov80SIZqJ/b8d8DKMGa25RrSzo1EMdoKGe8/NEiqKBdsM7aCjrrEC9SnuNtUre7QugoD5bcsXFSY+HaBqGse4fQbTdHnipZPwPLS2zLZyuoIivJKjBfaQZV0DfGlSHzR705QT3Ivh6F41Lpa7hsnDci6mfwIbnMMxcDLrsxkFhMWik6AjLYyuATVxBYiFrJhFRMx/FPh36SDXEDr9OrOM2jsIdYfKu2yVQAFxC1Ijez5iQfGqTUMVn";
}
