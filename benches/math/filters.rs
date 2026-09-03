//! Correct filter implementations for the spillover benchmark.
//!
//! - [`CuckooFilter`]: power-of-two bucket count, 13-bit fingerprints for 0.1%
//!   FPR (accounts for 8-slot lookup), fingerprint hashed for fully independent
//!   alternate bucket, stash serialized, measured FPR validated.
//! - [`RemainderProbeFilter`]: linear-probed remainder array (NOT a true quotient
//!   filter — lacks run-length/continuation metadata). Labeled honestly for
//!   benchmark comparison.
//! - [`CountingQuotientFilter`]: a counting quotient filter with quotient runs
//!   and occupied/continuation/shifted metadata.
//! - [`BloomFilter`]: standard k-hash Bloom filter for comparison baseline.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

fn hash_value<T: Hash>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

/// Hash a fingerprint to produce a value in [0, table_len).
fn hash_fingerprint(fp: u16, table_len: u64) -> u64 {
    let mut hasher = DefaultHasher::new();
    fp.hash(&mut hasher);
    hasher.finish() % table_len
}

// ---------------------------------------------------------------------------
// Cuckoo filter (power-of-two buckets, hashed alt index, 13-bit fp)
// ---------------------------------------------------------------------------

const CUCKOO_BUCKET: usize = 4;
const CUCKOO_MAX_KICKS: usize = 500;
const CUCKOO_STASH: usize = 8;

pub struct CuckooFilter {
    buckets: Vec<[u16; CUCKOO_BUCKET]>,
    stash: [u16; CUCKOO_STASH],
    stash_len: usize,
    bucket_mask: u64,
    fp_mask: u16,
    table_len: u64,
    len: usize,
    capacity: usize,
}

impl CuckooFilter {
    /// Create a Cuckoo filter sized for `capacity` elements at `target_fpr`.
    ///
    /// Fingerprint bits: ceil(log2(8 / target_fpr)) — accounts for the 8-slot
    /// (2 buckets × 4 slots) lookup, not the 4-slot formula.
    pub fn with_fpr(capacity: usize, target_fpr: f64) -> Self {
        let fp_bits = fingerprint_bits_for_fpr(target_fpr);
        let fp_mask = if fp_bits >= 16 {
            u16::MAX
        } else {
            (1u16 << fp_bits) - 1
        };
        let min_buckets = u64::try_from(
            capacity
                .div_ceil(CUCKOO_BUCKET)
                .saturating_mul(21)
                .div_ceil(20),
        )
        .expect("benchmark capacity fits u64");
        let bucket_count = min_buckets.next_power_of_two().max(1);
        let bucket_mask = bucket_count - 1;
        Self {
            buckets: vec![[0u16; CUCKOO_BUCKET]; bucket_count as usize],
            stash: [0u16; CUCKOO_STASH],
            stash_len: 0,
            bucket_mask,
            fp_mask,
            table_len: bucket_count,
            len: 0,
            capacity,
        }
    }

    fn fingerprint(&self, hash: u64) -> u16 {
        let raw = (hash >> 16) as u16;
        (raw & self.fp_mask).max(1)
    }

    fn primary_bucket(&self, hash: u64) -> usize {
        (hash & self.bucket_mask) as usize
    }

    /// Alternate bucket: hash the fingerprint independently, then XOR with
    /// the current index. This preserves index-dependency (alt depends on
    /// which bucket you're in) while ensuring the fingerprint contribution
    /// is fully independent of the primary bucket's hash bits.
    fn alt_bucket(&self, index: usize, fp: u16) -> usize {
        let mixed = hash_fingerprint(fp, self.table_len);
        (index ^ mixed as usize) & self.bucket_mask as usize
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
            let slot_pos = i % CUCKOO_BUCKET;
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

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn byte_len(&self) -> usize {
        let bucket_bytes = self.buckets.len() * CUCKOO_BUCKET * 2;
        let stash_len_bytes = 2;
        let stash_bytes = CUCKOO_STASH * 2;
        bucket_bytes + stash_len_bytes + stash_bytes
    }

    #[allow(dead_code)]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.byte_len());
        for bucket in &self.buckets {
            for &fp in bucket {
                bytes.extend_from_slice(&fp.to_le_bytes());
            }
        }
        bytes.extend_from_slice(&(self.stash_len as u16).to_le_bytes());
        for item in self.stash.iter().take(CUCKOO_STASH) {
            bytes.extend_from_slice(&item.to_le_bytes());
        }
        bytes
    }
}

/// Fingerprint bits for Cuckoo: ceil(log2(8 / target_fpr)).
/// The 8 comes from checking 2 buckets × 4 slots = 8 fingerprints per lookup.
fn fingerprint_bits_for_fpr(target_fpr: f64) -> u32 {
    assert!((0.0..1.0).contains(&target_fpr));
    for bits in 8..=16 {
        if 8.0 / f64::from(1_u32 << bits) <= target_fpr {
            return bits;
        }
    }
    16
}

/// Remainder width for a quotient filter at the requested false-positive rate.
pub(crate) fn quotient_remainder_bits_for_fpr(target_fpr: f64) -> u32 {
    assert!((0.0..1.0).contains(&target_fpr));
    for bits in 8..=16 {
        // A query can compare every remainder in its quotient run. At the
        // 75%-load policy, budget four candidate remainders per lookup rather
        // than treating the remainder as a single-fingerprint comparison.
        if 4.0 / f64::from(1_u32 << bits) <= target_fpr {
            return bits;
        }
    }
    16
}

/// Remainder width for a linear-probed remainder table at the requested
/// false-positive rate.  Unlike the quotient-filter helper above, this
/// accounts for the ~91% load factor (10% extra slots) and the expected
/// probe length on a miss: probes ≈ 1/(1−α) ≈ 11 at α ≈ 0.91.
pub(crate) fn remainder_probe_bits_for_fpr(target_fpr: f64) -> u32 {
    assert!((0.0..1.0).contains(&target_fpr));
    // At load factor ≈ 0.91 the expected probes for a miss ≈ 11.
    // FPR ≈ probes / 2^(bits-1) because remainder values are always odd.
    let probes = 11.0;
    for bits in 8..=16 {
        if probes / f64::from(1_u32 << (bits - 1)) <= target_fpr {
            return bits;
        }
    }
    16
}

// ---------------------------------------------------------------------------
// Remainder-probe filter (linear-probed remainder array, NOT a quotient filter)
//
// This is a simple hash table using linear probing on remainder values.
// It is NOT a quotient filter: it lacks run-length encoding, continuation
// bits, and the quotient-based cluster structure. Labeled honestly for
// benchmark comparison.
// ---------------------------------------------------------------------------

pub struct RemainderProbeFilter {
    rem: Vec<u32>,
    occupied: Vec<bool>,
    capacity: usize,
    remainder_bits: u32,
    len: usize,
    slots: usize,
}

impl RemainderProbeFilter {
    pub fn with_remainder_bits(capacity: usize, remainder_bits: u32) -> Self {
        #[allow(clippy::cast_sign_loss)]
        let slots = ((capacity as f64 * 1.1).ceil() as usize).max(64);
        Self {
            rem: vec![0; slots],
            occupied: vec![false; slots],
            capacity,
            remainder_bits,
            len: 0,
            slots,
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
            if !self.occupied[pos] {
                self.rem[pos] = r;
                self.occupied[pos] = true;
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
            if !self.occupied[pos] {
                return false;
            }
            if self.rem[pos] == r {
                return true;
            }
            pos = (pos + 1) % self.slots;
        }
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn byte_len(&self) -> usize {
        self.rem.len() * 4 + self.occupied.len()
    }
}

// ---------------------------------------------------------------------------
// Counting quotient filter
// ---------------------------------------------------------------------------

/// A packed bitmap used for quotient-filter metadata.
struct BitSet {
    words: Vec<u64>,
}

impl BitSet {
    fn new(bits: usize) -> Self {
        Self {
            words: vec![0; bits.div_ceil(64)],
        }
    }

    fn get(&self, index: usize) -> bool {
        (self.words[index / 64] >> (index % 64)) & 1 != 0
    }

    fn set(&mut self, index: usize, value: bool) {
        let word = &mut self.words[index / 64];
        let mask = 1_u64 << (index % 64);
        if value {
            *word |= mask;
        } else {
            *word &= !mask;
        }
    }

    fn byte_len(&self) -> usize {
        self.words.len() * std::mem::size_of::<u64>()
    }
}

/// Counting quotient filter with explicit quotient-run metadata.
///
/// Each slot holds a remainder and count. The three packed metadata bitmaps
/// are the standard quotient-filter `occupied`, `continuation`, and `shifted`
/// flags. This benchmark implementation supports insertion and membership
/// queries; deletion is intentionally out of scope.
pub struct CountingQuotientFilter {
    remainders: Vec<u16>,
    counts: Vec<u16>,
    occupied: BitSet,
    continuation: BitSet,
    shifted: BitSet,
    remainder_bits: u32,
    slot_mask: usize,
    capacity: usize,
    len: usize,
}

impl CountingQuotientFilter {
    /// Creates a filter with a maximum load factor below 75%.
    pub fn with_remainder_bits(capacity: usize, remainder_bits: u32) -> Self {
        assert!((1..=16).contains(&remainder_bits));
        let min_slots = capacity.saturating_mul(4).div_ceil(3).max(2);
        let slots = min_slots.next_power_of_two();
        Self {
            remainders: vec![0; slots],
            counts: vec![0; slots],
            occupied: BitSet::new(slots),
            continuation: BitSet::new(slots),
            shifted: BitSet::new(slots),
            remainder_bits,
            slot_mask: slots - 1,
            capacity,
            len: 0,
        }
    }

    fn next(&self, index: usize) -> usize {
        (index + 1) & self.slot_mask
    }

    fn previous(&self, index: usize) -> usize {
        index.wrapping_sub(1) & self.slot_mask
    }

    fn is_empty(&self, index: usize) -> bool {
        !self.occupied.get(index) && !self.continuation.get(index) && !self.shifted.get(index)
    }

    fn split_hash(&self, hash: u64) -> (usize, u16) {
        let quotient = (hash as usize) & self.slot_mask;
        let mask = (1_u64 << self.remainder_bits) - 1;
        let quotient_bits = (self.slot_mask + 1).ilog2();
        let remainder = ((hash >> quotient_bits) & mask) as u16;
        (quotient, remainder)
    }

    fn cluster_start(&self, mut quotient: usize) -> usize {
        while self.shifted.get(quotient) {
            quotient = self.previous(quotient);
        }
        quotient
    }

    /// Finds the first slot in `quotient`'s run. `quotient` must be occupied.
    fn run_start(&self, quotient: usize) -> usize {
        let mut bucket = self.cluster_start(quotient);
        let mut run = bucket;
        while bucket != quotient {
            bucket = self.next(bucket);
            if self.occupied.get(bucket) {
                run = self.next(run);
                while self.continuation.get(run) {
                    run = self.next(run);
                }
            }
        }
        run
    }

    fn find_remainder(&self, quotient: usize, remainder: u16) -> Option<usize> {
        if !self.occupied.get(quotient) {
            return None;
        }

        let mut slot = self.run_start(quotient);
        loop {
            if self.remainders[slot] == remainder {
                return Some(slot);
            }
            let next = self.next(slot);
            if !self.continuation.get(next) {
                return None;
            }
            slot = next;
        }
    }

    fn shift_right_from(&mut self, insertion: usize) {
        let mut empty = insertion;
        while !self.is_empty(empty) {
            empty = self.next(empty);
        }

        while empty != insertion {
            let source = self.previous(empty);
            self.remainders[empty] = self.remainders[source];
            self.counts[empty] = self.counts[source];
            self.continuation.set(empty, self.continuation.get(source));
            self.shifted.set(empty, true);
            empty = source;
        }
    }

    /// Inserts `value`; repeated inserts increment the entry's saturated count.
    pub fn insert<T: Hash>(&mut self, value: &T) -> bool {
        let (quotient, remainder) = self.split_hash(hash_value(value));
        if let Some(slot) = self.find_remainder(quotient, remainder) {
            self.counts[slot] = self.counts[slot].saturating_add(1);
            return true;
        }
        if self.len >= self.capacity {
            return false;
        }

        let had_run = self.occupied.get(quotient);
        if self.is_empty(quotient) {
            self.occupied.set(quotient, true);
            self.remainders[quotient] = remainder;
            self.counts[quotient] = 1;
            self.len += 1;
            return true;
        }

        self.occupied.set(quotient, true);
        let mut insertion = self.run_start(quotient);
        if had_run {
            while self.continuation.get(self.next(insertion)) {
                insertion = self.next(insertion);
            }
            insertion = self.next(insertion);
        }

        self.shift_right_from(insertion);
        self.remainders[insertion] = remainder;
        self.counts[insertion] = 1;
        self.continuation.set(insertion, had_run);
        self.shifted.set(insertion, insertion != quotient);
        self.len += 1;
        true
    }

    pub fn contains<T: Hash>(&self, value: &T) -> bool {
        let (quotient, remainder) = self.split_hash(hash_value(value));
        self.find_remainder(quotient, remainder).is_some()
    }

    /// Returns the saturated count associated with `value`'s fingerprint.
    pub fn count<T: Hash>(&self, value: &T) -> u16 {
        let (quotient, remainder) = self.split_hash(hash_value(value));
        self.find_remainder(quotient, remainder)
            .map_or(0, |slot| self.counts[slot])
    }

    pub fn len(&self) -> usize {
        self.len
    }

    /// Serialized storage excluding protocol framing.
    pub fn byte_len(&self) -> usize {
        self.remainders.len() * std::mem::size_of::<u16>()
            + self.counts.len() * std::mem::size_of::<u16>()
            + self.occupied.byte_len()
            + self.continuation.byte_len()
            + self.shifted.byte_len()
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
        #[allow(clippy::cast_sign_loss)]
        let num_bits = (m.ceil() as u64).max(64);
        #[allow(clippy::cast_sign_loss)]
        let k = ((num_bits as f64 / n) * ln2).ceil() as u32;
        let num_words = u64::div_ceil(num_bits, 64);
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

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn byte_len(&self) -> usize {
        self.bits.len() * 8
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn cuckoo_insert_and_contains() {
        let n: u64 = 10_000;
        let insert_count = 5_000usize;
        let mut f = CuckooFilter::with_fpr(insert_count, 0.001);
        for i in 0..insert_count as u64 {
            assert!(f.insert(&(i | 1)), "cuckoo insert failed at {i}");
        }
        assert_eq!(f.len(), insert_count, "cuckoo len mismatch");
        for i in 0..insert_count as u64 {
            assert!(f.contains(&(i | 1)), "cuckoo missing element {i}");
        }
        let mut false_positives = 0u64;
        for i in insert_count as u64..n {
            if f.contains(&(i | 1)) {
                false_positives += 1;
            }
        }
        let queried = n - insert_count as u64;
        let measured = false_positives as f64 / queried as f64;
        assert!(
            measured < 0.005,
            "cuckoo measured FPR {measured:.6} exceeds 0.5% upper bound (target 0.1%)"
        );
    }

    #[test]
    fn cuckoo_alt_index_is_involutive() {
        let f = CuckooFilter::with_fpr(100, 0.001);
        let fp: u16 = 42;
        // alt_bucket must be involutive: alt(alt(idx, fp), fp) == idx
        for idx in 0..128.min(f.table_len as usize) {
            let alt = f.alt_bucket(idx, fp);
            let back = f.alt_bucket(alt, fp);
            assert_eq!(idx, back, "alt not involutive at idx={idx}");
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
    fn remainder_probe_insert_and_contains() {
        let n: u64 = 10_000;
        let insert_count = 5_000usize;
        let mut f = RemainderProbeFilter::with_remainder_bits(insert_count, 10);
        for i in 0..insert_count as u64 {
            assert!(f.insert(&(i | 1)), "rp insert failed at {i}");
        }
        assert_eq!(f.len(), insert_count);
        for i in 0..insert_count as u64 {
            assert!(f.contains(&(i | 1)));
        }
        for i in insert_count as u64..n {
            assert!(!f.contains(&(i | 1)), "rp false positive at {i}");
        }
    }

    #[test]
    fn counting_quotient_insert_contains_and_counts() {
        let mut filter = CountingQuotientFilter::with_remainder_bits(5_000, 12);
        for value in 0..5_000_u64 {
            assert!(filter.insert(&value), "CQF insert failed at {value}");
        }
        assert_eq!(filter.len(), 5_000);
        for value in 0..5_000_u64 {
            assert!(filter.contains(&value), "CQF missing {value}");
        }

        assert!(filter.insert(&123_u64));
        assert!(filter.insert(&123_u64));
        assert_eq!(filter.len(), 5_000, "duplicates must not allocate slots");
        assert_eq!(filter.count(&123_u64), 3);
    }

    #[test]
    fn bloom_insert_and_contains() {
        let n: u64 = 10_000;
        let insert_count = 5_000usize;
        let mut f = BloomFilter::with_fpr(insert_count, 0.001);
        for i in 0..insert_count as u64 {
            f.insert(&(i | 1));
        }
        assert_eq!(f.len(), insert_count);
        for i in 0..insert_count as u64 {
            assert!(f.contains(&(i | 1)));
        }
        let mut false_positives = 0u64;
        for i in insert_count as u64..n {
            if f.contains(&(i | 1)) {
                false_positives += 1;
            }
        }
        let queried = n - insert_count as u64;
        let measured = false_positives as f64 / queried as f64;
        assert!(
            measured < 0.005,
            "bloom measured FPR {measured:.6} exceeds 0.5% upper bound (target 0.1%)"
        );
    }
}
