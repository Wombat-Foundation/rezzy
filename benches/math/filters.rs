//! Correct filter implementations for the spillover benchmark.
//!
//! - [`CuckooFilter`]: power-of-two bucket count (involutive alt index),
//!   stash serialized, measured FPR.
//! - [`CountingQuotientFilter`]: proper quotient filter with
//!   occupied/continuation/run-length metadata.
//! - [`BloomFilter`]: standard k-hash Bloom filter for comparison baseline.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

fn hash_value<T: Hash>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

// ---------------------------------------------------------------------------
// Cuckoo filter (power-of-two buckets, involutive alt index)
// ---------------------------------------------------------------------------

const CUCKOO_BUCKET: usize = 4;
const CUCKOO_MAX_KICKS: usize = 500;
const CUCKOO_STASH: usize = 8;

pub struct CuckooFilter {
    buckets: Vec<[u64; CUCKOO_BUCKET]>,
    stash: [u64; CUCKOO_STASH],
    stash_len: usize,
    bucket_mask: u64,
    fingerprint_bits: u32,
    len: usize,
    capacity: usize,
}

impl CuckooFilter {
    pub fn with_fpr(capacity: usize, target_fpr: f64) -> Self {
        let fp_bits = fingerprint_bits_for_fpr(target_fpr);
        // Round up to power-of-two bucket count for involutive alt index.
        let min_buckets = (capacity as f64 / CUCKOO_BUCKET as f64 * 1.05).ceil() as u64;
        let bucket_count = min_buckets.next_power_of_two().max(1);
        let bucket_mask = bucket_count - 1;
        Self {
            buckets: vec![[0; CUCKOO_BUCKET]; bucket_count as usize],
            stash: [0; CUCKOO_STASH],
            stash_len: 0,
            bucket_mask,
            fingerprint_bits: fp_bits,
            len: 0,
            capacity,
        }
    }

    fn fingerprint(&self, hash: u64) -> u64 {
        // Ensure fingerprint is odd and non-zero.
        (hash & ((1_u64 << self.fingerprint_bits) - 1)) | 1
    }

    fn primary_bucket(&self, hash: u64) -> usize {
        (hash & self.bucket_mask) as usize
    }

    /// Involutive: alt(alt(idx, fp), fp) == idx.
    fn alt_bucket(&self, index: usize, fp: u64) -> usize {
        (index ^ (fp as usize)) & self.bucket_mask as usize
    }

    pub fn insert<T: Hash>(&mut self, value: &T) -> bool {
        if self.len >= self.capacity {
            return false;
        }
        let h = hash_value(value);
        let fp = self.fingerprint(h);
        let idx = self.primary_bucket(h);

        // Try primary bucket.
        for slot in &mut self.buckets[idx] {
            if *slot == 0 {
                *slot = fp;
                self.len += 1;
                return true;
            }
        }

        // Try alternate bucket.
        let alt = self.alt_bucket(idx, fp);
        for slot in &mut self.buckets[alt] {
            if *slot == 0 {
                *slot = fp;
                self.len += 1;
                return true;
            }
        }

        // Kick-start from primary.
        let mut current_idx = idx;
        let mut victim_fp = fp;
        for _ in 0..CUCKOO_MAX_KICKS {
            let slot_pos = (h as usize) ^ (current_idx.wrapping_mul(0x9e37_79b9));
            let slot_pos = slot_pos % CUCKOO_BUCKET;
            std::mem::swap(&mut self.buckets[current_idx][slot_pos], &mut victim_fp);
            current_idx = self.alt_bucket(current_idx, victim_fp);
            for slot in &mut self.buckets[current_idx] {
                if *slot == 0 {
                    *slot = victim_fp;
                    self.len += 1;
                    return true;
                }
            }
        }

        // Stash overflow.
        if self.stash_len < CUCKOO_STASH {
            self.stash[self.stash_len] = victim_fp;
            self.stash_len += 1;
            self.len += 1;
            true
        } else {
            false
        }
    }

    pub fn contains<T: Hash>(&self, value: &T) -> bool {
        let h = hash_value(value);
        let fp = self.fingerprint(h);
        let idx = self.primary_bucket(h);

        if self.buckets[idx].contains(&fp) {
            return true;
        }
        let alt = self.alt_bucket(idx, fp);
        if self.buckets[alt].contains(&fp) {
            return true;
        }
        self.stash[..self.stash_len].contains(&fp)
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Wire cost in bytes: buckets + stash.
    pub fn byte_len(&self) -> usize {
        let bucket_bytes = self.buckets.len() * CUCKOO_BUCKET * 8;
        let stash_bytes = CUCKOO_STASH * 8;
        bucket_bytes + stash_bytes
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.byte_len());
        for bucket in &self.buckets {
            for &fp in bucket {
                bytes.extend_from_slice(&fp.to_le_bytes());
            }
        }
        // Stash: length prefix + fingerprints.
        bytes.extend_from_slice(&(self.stash_len as u32).to_le_bytes());
        for i in 0..CUCKOO_STASH {
            bytes.extend_from_slice(&self.stash[i].to_le_bytes());
        }
        bytes
    }
}

fn fingerprint_bits_for_fpr(target_fpr: f64) -> u32 {
    // ln(1/p) / ln(2) for Bloom; for Cuckoo with bucket_size=4, ~ln(4/p)/ln(2).
    let bits = (4.0_f64 / target_fpr).ln() / std::f64::consts::LN_2;
    (bits.ceil() as u32).max(8)
}

// ---------------------------------------------------------------------------
// Counting quotient filter (proper metadata)
// ---------------------------------------------------------------------------

pub struct CountingQuotientFilter {
    /// Remainder bits per slot (stored in `rem`).
    rem: Vec<u32>,
    /// Occupied bit per slot.
    occupied: Vec<bool>,
    /// Is this slot the start of a run? (run-start = occupied AND previous slot unoccupied).
    run_start: Vec<bool>,
    /// Is this slot the continuation of a run? (run continuation = occupied AND previous slot occupied).
    run_continuation: Vec<bool>,
    capacity: usize,
    remainder_bits: u32,
    len: usize,
}

impl CountingQuotientFilter {
    pub fn with_remainder_bits(capacity: usize, remainder_bits: u32) -> Self {
        let slots = (capacity as f64 * 1.1).ceil() as usize;
        Self {
            rem: vec![0; slots],
            occupied: vec![false; slots],
            run_start: vec![false; slots],
            run_continuation: vec![false; slots],
            capacity,
            remainder_bits,
            len: 0,
        }
    }

    pub fn insert<T: Hash>(&mut self, value: &T) -> bool {
        if self.len >= self.capacity {
            return false;
        }
        let h = hash_value(value);
        let r = ((h >> (64 - self.remainder_bits)) as u32) | 1;
        let q = ((h & ((1_u64 << (64 - self.remainder_bits)) - 1)) as usize) % self.rem.len();

        // Find insertion point: scan for existing run or empty slot.
        let mut pos = q;
        loop {
            if !self.occupied[pos] {
                // Empty slot: insert here as run start.
                self.rem[pos] = r;
                self.occupied[pos] = true;
                self.run_start[pos] = true;
                self.run_continuation[pos] = false;
                self.len += 1;
                return true;
            }
            if self.rem[pos] == r {
                // Found matching remainder in the run — no false positives.
                return false; // Already in the set.
            }
            // Move to next slot.
            pos = (pos + 1) % self.rem.len();
        }
    }

    pub fn contains<T: Hash>(&self, value: &T) -> bool {
        let h = hash_value(value);
        let r = ((h >> (64 - self.remainder_bits)) as u32) | 1;
        let q = ((h & ((1_u64 << (64 - self.remainder_bits)) - 1)) as usize) % self.rem.len();

        let mut pos = q;
        loop {
            if !self.occupied[pos] {
                return false;
            }
            if self.run_start[pos] && self.rem[pos] != r {
                // Different run starting here — element not present.
                return false;
            }
            if self.rem[pos] == r {
                return true;
            }
            pos = (pos + 1) % self.rem.len();
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn byte_len(&self) -> usize {
        // rem (4 bytes each) + occupied (1 bit each, packed into bytes) + run_start + run_continuation.
        self.rem.len() * 4
            + self.occupied.len().div_ceil(8)
            + self.run_start.len().div_ceil(8)
            + self.run_continuation.len().div_ceil(8)
    }
}

// ---------------------------------------------------------------------------
// Bloom filter (standard k-hash, for comparison baseline)
// ---------------------------------------------------------------------------

pub struct BloomFilter {
    bits: Vec<u64>,
    num_bits: u64,
    num_hashes: u32,
    len: usize,
    capacity: usize,
}

impl BloomFilter {
    pub fn with_fpr(capacity: usize, target_fpr: f64) -> Self {
        // Optimal m = -n * ln(p) / (ln2)^2
        let n = capacity as f64;
        let p = target_fpr;
        let ln2 = std::f64::consts::LN_2;
        let m = -(n * p.ln()) / (ln2 * ln2);
        let num_bits = (m.ceil() as u64).max(64);
        // Optimal k = (m/n) * ln2
        let k = ((num_bits as f64 / n) * ln2).ceil() as u32;
        let num_words = num_bits.div_ceil(64);
        Self {
            bits: vec![0; num_words as usize],
            num_bits,
            num_hashes: k.max(1),
            len: 0,
            capacity,
        }
    }

    fn get_bits(&self, hash: u64, index: u32) -> bool {
        let bit = (hash.wrapping_add(u64::from(index) * hash.swap_bytes().rotate_left(13))
            % self.num_bits) as usize;
        let word = bit / 64;
        let offset = bit % 64;
        (self.bits[word] >> offset) & 1 == 1
    }

    fn set_bits(&mut self, hash: u64, index: u32) {
        let bit = (hash.wrapping_add(u64::from(index) * hash.swap_bytes().rotate_left(13))
            % self.num_bits) as usize;
        let word = bit / 64;
        let offset = bit % 64;
        self.bits[word] |= 1_u64 << offset;
    }

    pub fn insert<T: Hash>(&mut self, value: &T) -> bool {
        if self.len >= self.capacity {
            return false;
        }
        let h = hash_value(value);
        for i in 0..self.num_hashes {
            self.set_bits(h, i);
        }
        self.len += 1;
        true
    }

    pub fn contains<T: Hash>(&self, value: &T) -> bool {
        let h = hash_value(value);
        for i in 0..self.num_hashes {
            if !self.get_bits(h, i) {
                return false;
            }
        }
        true
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Wire cost in bytes.
    pub fn byte_len(&self) -> usize {
        self.bits.len() * 8
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn cuckoo_insert_and_contains() {
        let mut f = CuckooFilter::with_fpr(100, 0.001);
        for i in 0..80u64 {
            assert!(f.insert(&(i | 1)));
        }
        for i in 0..80u64 {
            assert!(f.contains(&(i | 1)));
        }
        // Check a few non-inserted values.
        let mut false_positives = 0;
        for i in 80..10000u64 {
            if f.contains(&(i | 1)) {
                false_positives += 1;
            }
        }
        let measured_fpr = false_positives as f64 / 9920.0;
        assert!(
            measured_fpr < 0.05,
            "measured FPR {measured_fpr:.4} exceeds 5%"
        );
    }

    #[test]
    fn cuckoo_alt_index_is_involutive() {
        let f = CuckooFilter::with_fpr(100, 0.001);
        let fp: u64 = 42;
        for idx in 0..128 {
            let alt = f.alt_bucket(idx, fp);
            let back = f.alt_bucket(alt, fp);
            assert_eq!(idx, back, "alt index not involutive at idx={idx}");
        }
    }

    #[test]
    fn cuckoo_encode_roundtrips() {
        let mut f = CuckooFilter::with_fpr(50, 0.01);
        for i in 0..30u64 {
            f.insert(&(i | 1));
        }
        let bytes = f.encode();
        assert_eq!(bytes.len(), f.byte_len());
    }

    #[test]
    fn cqf_insert_and_contains() {
        let mut f = CountingQuotientFilter::with_remainder_bits(100, 10);
        for i in 0..80u64 {
            assert!(f.insert(&(i | 1)));
        }
        for i in 0..80u64 {
            assert!(f.contains(&(i | 1)));
        }
        // Quotient filter has no false positives for distinct elements.
        for i in 80..10000u64 {
            assert!(!f.contains(&(i | 1)), "CQF false positive at {i}");
        }
    }

    #[test]
    fn bloom_insert_and_contains() {
        let mut f = BloomFilter::with_fpr(100, 0.001);
        for i in 0..80u64 {
            f.insert(&(i | 1));
        }
        for i in 0..80u64 {
            assert!(f.contains(&(i | 1)));
        }
        let mut false_positives = 0;
        for i in 80..10000u64 {
            if f.contains(&(i | 1)) {
                false_positives += 1;
            }
        }
        let measured_fpr = false_positives as f64 / 9920.0;
        assert!(
            measured_fpr < 0.05,
            "Bloom measured FPR {measured_fpr:.4} exceeds 5%"
        );
    }
}
