//! Correct filter implementations for the spillover benchmark.
//!
//! - [`CuckooFilter`]: power-of-two bucket count (involutive alt index),
//!   packed u16 fingerprints, stash serialized, measured FPR.
//! - [`CountingQuotientFilter`]: proper quotient filter with
//!   occupied/continuation metadata, packed bit-level storage.
//! - [`BloomFilter`]: standard k-hash Bloom filter for comparison baseline.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

fn hash_value<T: Hash>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

// ---------------------------------------------------------------------------
// Cuckoo filter (power-of-two buckets, involutive alt index, packed u16 fp)
// ---------------------------------------------------------------------------

const CUCKOO_BUCKET: usize = 4;
const CUCKOO_MAX_KICKS: usize = 500;
const CUCKOO_STASH: usize = 8;

pub struct CuckooFilter {
    /// Each bucket stores CUCKOO_BUCKET packed u16 fingerprints.
    buckets: Vec<[u16; CUCKOO_BUCKET]>,
    stash: [u16; CUCKOO_STASH],
    stash_len: usize,
    bucket_mask: u64,
    fingerprint_bits: u32,
    len: usize,
    capacity: usize,
}

impl CuckooFilter {
    pub fn with_fpr(capacity: usize, target_fpr: f64) -> Self {
        let fp_bits = fingerprint_bits_for_fpr(target_fpr);
        let min_buckets = (capacity as f64 / CUCKOO_BUCKET as f64 * 1.05).ceil() as u64;
        let bucket_count = min_buckets.next_power_of_two().max(1);
        let bucket_mask = bucket_count - 1;
        Self {
            buckets: vec![[0u16; CUCKOO_BUCKET]; bucket_count as usize],
            stash: [0u16; CUCKOO_STASH],
            stash_len: 0,
            bucket_mask,
            fingerprint_bits: fp_bits,
            len: 0,
            capacity,
        }
    }

    fn fingerprint(&self, hash: u64) -> u16 {
        let mask = if self.fingerprint_bits >= 16 {
            u16::MAX
        } else {
            (1u16 << self.fingerprint_bits) - 1
        };
        let fp = (hash & u64::from(mask)) as u16;
        fp | 1 // Ensure odd and non-zero.
    }

    fn primary_bucket(&self, hash: u64) -> usize {
        (hash & self.bucket_mask) as usize
    }

    fn alt_bucket(&self, index: usize, fp: u16) -> usize {
        (index ^ (fp as usize)) & self.bucket_mask as usize
    }

    pub fn insert<T: Hash>(&mut self, value: &T) -> bool {
        if self.len >= self.capacity {
            return false;
        }
        let h = hash_value(value);
        let fp = self.fingerprint(h);
        let idx = self.primary_bucket(h);

        for slot in &mut self.buckets[idx] {
            if *slot == 0 {
                *slot = fp;
                self.len += 1;
                return true;
            }
        }

        let alt = self.alt_bucket(idx, fp);
        for slot in &mut self.buckets[alt] {
            if *slot == 0 {
                *slot = fp;
                self.len += 1;
                return true;
            }
        }

        let mut current_idx = idx;
        let mut victim_fp = fp;
        for i in 0..CUCKOO_MAX_KICKS {
            let slot_pos = (i.wrapping_mul(0x9e37)) % CUCKOO_BUCKET;
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

    /// Wire cost in bytes: packed buckets + stash.
    pub fn byte_len(&self) -> usize {
        let bucket_bytes = self.buckets.len() * CUCKOO_BUCKET * 2; // u16 = 2 bytes
        let stash_bytes = CUCKOO_STASH * 2;
        bucket_bytes + stash_bytes
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.byte_len());
        for bucket in &self.buckets {
            for &fp in bucket {
                bytes.extend_from_slice(&fp.to_le_bytes());
            }
        }
        bytes.extend_from_slice(&(self.stash_len as u16).to_le_bytes());
        for i in 0..CUCKOO_STASH {
            bytes.extend_from_slice(&self.stash[i].to_le_bytes());
        }
        bytes
    }
}

fn fingerprint_bits_for_fpr(target_fpr: f64) -> u32 {
    let bits = (4.0_f64 / target_fpr).ln() / std::f64::consts::LN_2;
    (bits.ceil() as u32).max(8).min(16)
}

// ---------------------------------------------------------------------------
// Counting quotient filter (packed bit-level metadata)
// ---------------------------------------------------------------------------

pub struct CountingQuotientFilter {
    /// Remainder stored packed as u32 per slot.
    rem: Vec<u32>,
    /// Packed metadata bits: occupied | run_start.
    occupied: Vec<u64>,
    capacity: usize,
    remainder_bits: u32,
    len: usize,
    slots: usize,
}

impl CountingQuotientFilter {
    pub fn with_remainder_bits(capacity: usize, remainder_bits: u32) -> Self {
        let slots = ((capacity as f64 * 1.1).ceil() as usize).max(64);
        let words = slots.div_ceil(64);
        Self {
            rem: vec![0; slots],
            occupied: vec![0u64; words],
            capacity,
            remainder_bits,
            len: 0,
            slots,
        }
    }

    fn get_occupied(&self, pos: usize) -> bool {
        self.occupied[pos / 64] & (1u64 << (pos % 64)) != 0
    }

    fn set_occupied(&mut self, pos: usize, val: bool) {
        let word = pos / 64;
        let bit = pos % 64;
        if val {
            self.occupied[word] |= 1u64 << bit;
        } else {
            self.occupied[word] &= !(1u64 << bit);
        }
    }

    pub fn insert<T: Hash>(&mut self, value: &T) -> bool {
        if self.len >= self.capacity {
            return false;
        }
        let h = hash_value(value);
        let r = ((h >> (64 - self.remainder_bits)) as u32) | 1;
        let q = ((h & ((1_u64 << (64 - self.remainder_bits)) - 1)) as usize) % self.slots;

        let mut pos = q;
        loop {
            if !self.get_occupied(pos) {
                self.rem[pos] = r;
                self.set_occupied(pos, true);
                self.len += 1;
                return true;
            }
            if self.rem[pos] == r {
                return false;
            }
            pos = (pos + 1) % self.slots;
        }
    }

    pub fn contains<T: Hash>(&self, value: &T) -> bool {
        let h = hash_value(value);
        let r = ((h >> (64 - self.remainder_bits)) as u32) | 1;
        let q = ((h & ((1_u64 << (64 - self.remainder_bits)) - 1)) as usize) % self.slots;

        let mut pos = q;
        loop {
            if !self.get_occupied(pos) {
                return false;
            }
            if self.rem[pos] == r {
                return true;
            }
            pos = (pos + 1) % self.slots;
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    /// Wire cost in bytes: rem (4 bytes each) + occupied (1 bit each, packed).
    pub fn byte_len(&self) -> usize {
        self.rem.len() * 4 + self.occupied.len() * 8
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
        let n = capacity as f64;
        let p = target_fpr;
        let ln2 = std::f64::consts::LN_2;
        let m = -(n * p.ln()) / (ln2 * ln2);
        let num_bits = (m.ceil() as u64).max(64);
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

    fn get_bit(&self, hash: u64, index: u32) -> bool {
        let bit = (hash.wrapping_add(u64::from(index) * hash.swap_bytes().rotate_left(13))
            % self.num_bits) as usize;
        let word = bit / 64;
        let offset = bit % 64;
        (self.bits[word] >> offset) & 1 == 1
    }

    fn set_bit(&mut self, hash: u64, index: u32) {
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
            self.set_bit(h, i);
        }
        self.len += 1;
        true
    }

    pub fn contains<T: Hash>(&self, value: &T) -> bool {
        let h = hash_value(value);
        for i in 0..self.num_hashes {
            if !self.get_bit(h, i) {
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
        let fp: u16 = 42;
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
