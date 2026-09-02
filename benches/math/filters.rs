//! Compact probabilistic filters for the spillover benchmark.
//!
//! Two implementations:
//! - [`CuckooFilter`]: standard cuckoo with stash, configurable fingerprint width.
//! - [`CountingQuotientFilter`]: linear-probe quotient filter with a small
//!   counter per slot (exact membership, no false positives at low load factors).

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hash_value<T: Hash>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

fn fingerprint(hash: u64, bits: u32) -> u64 {
    hash & ((1_u64 << bits) - 1) | 1
}

fn bucket_index(hash: u64, num_buckets: u64) -> usize {
    (hash % num_buckets) as usize
}

fn alt_bucket(fingerprint: u64, index: usize, num_buckets: u64) -> usize {
    (index ^ (fingerprint as usize)) % num_buckets as usize
}

// ---------------------------------------------------------------------------
// Cuckoo filter
// ---------------------------------------------------------------------------

const CUCKOO_MAX_KICKS: usize = 500;
const CUCKOO_STASH: usize = 8;
const CUCKOO_BUCKET: usize = 4;

pub struct CuckooFilter {
    buckets: Vec<[u64; CUCKOO_BUCKET]>,
    stash: [u64; CUCKOO_STASH],
    stash_len: usize,
    num_buckets: u64,
    fingerprint_bits: u32,
    len: usize,
}

impl CuckooFilter {
    /// Creates a filter for `capacity` elements at approximately `target_fpr`.
    pub fn with_fpr(capacity: usize, target_fpr: f64) -> Self {
        let entries = (capacity as f64 / CUCKOO_BUCKET as f64 * 1.05).ceil() as u64;
        let num_buckets = entries.max(1);
        let fp_bits = fingerprint_bits_for_fpr(target_fpr);
        Self {
            buckets: vec![[0; CUCKOO_BUCKET]; num_buckets as usize],
            stash: [0; CUCKOO_STASH],
            stash_len: 0,
            num_buckets,
            fingerprint_bits: fp_bits,
            len: 0,
        }
    }

    pub fn insert<T: Hash>(&mut self, value: &T) -> bool {
        if self.len >= self.capacity() {
            return false;
        }
        let h = hash_value(value);
        let fp = fingerprint(h, self.fingerprint_bits);
        let idx = bucket_index(h, self.num_buckets);

        for slot in &mut self.buckets[idx] {
            if *slot == 0 {
                *slot = fp;
                self.len += 1;
                return true;
            }
        }

        let alt = alt_bucket(fp, idx, self.num_buckets);
        for slot in &mut self.buckets[alt] {
            if *slot == 0 {
                *slot = fp;
                self.len += 1;
                return true;
            }
        }

        let mut victim = fp;
        let mut current_idx = idx;
        for _ in 0..CUCKOO_MAX_KICKS {
            let bucket = &mut self.buckets[current_idx];
            let slot_idx = (h as usize) % CUCKOO_BUCKET;
            std::mem::swap(&mut bucket[slot_idx], &mut victim);
            current_idx = alt_bucket(victim, current_idx, self.num_buckets);
            for slot in &mut self.buckets[current_idx] {
                if *slot == 0 {
                    *slot = victim;
                    self.len += 1;
                    return true;
                }
            }
        }

        if self.stash_len < CUCKOO_STASH {
            self.stash[self.stash_len] = victim;
            self.stash_len += 1;
            self.len += 1;
            true
        } else {
            false
        }
    }

    pub fn contains<T: Hash>(&self, value: &T) -> bool {
        let h = hash_value(value);
        let fp = fingerprint(h, self.fingerprint_bits);
        let idx = bucket_index(h, self.num_buckets);

        if self.buckets[idx].contains(&fp) {
            return true;
        }
        let alt = alt_bucket(fp, idx, self.num_buckets);
        if self.buckets[alt].contains(&fp) {
            return true;
        }
        self.stash[..self.stash_len].contains(&fp)
    }

    pub fn capacity(&self) -> usize {
        (self.num_buckets as usize) * CUCKOO_BUCKET
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn byte_len(&self) -> usize {
        self.buckets.len() * CUCKOO_BUCKET * 8 + self.stash_len * 8
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.byte_len());
        for bucket in &self.buckets {
            for &fp in bucket {
                bytes.extend_from_slice(&fp.to_le_bytes());
            }
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8], capacity: usize, fingerprint_bits: u32) -> Option<Self> {
        let entries = (capacity as f64 / CUCKOO_BUCKET as f64 * 1.05).ceil() as u64;
        let num_buckets = entries.max(1);
        let expected = num_buckets as usize * CUCKOO_BUCKET * 8;
        if bytes.len() < expected {
            return None;
        }
        let mut buckets = vec![[0_u64; CUCKOO_BUCKET]; num_buckets as usize];
        let mut offset = 0;
        for bucket in &mut buckets {
            for slot in bucket {
                let mut buf = [0; 8];
                buf.copy_from_slice(&bytes[offset..offset + 8]);
                *slot = u64::from_le_bytes(buf);
                offset += 8;
            }
        }
        let len = buckets.iter().flatten().filter(|&&s| s != 0).count();
        Some(Self {
            buckets,
            stash: [0; CUCKOO_STASH],
            stash_len: 0,
            num_buckets,
            fingerprint_bits,
            len,
        })
    }
}

// ---------------------------------------------------------------------------
// Counting quotient filter
// ---------------------------------------------------------------------------

pub struct CountingQuotientFilter {
    remainder: Vec<u32>,
    count: Vec<u8>,
    capacity: usize,
    remainder_bits: u32,
    len: usize,
}

impl CountingQuotientFilter {
    /// Creates a filter for `capacity` elements with the given number of
    /// remainder bits (determines false-positive rate at typical load factors).
    pub fn with_remainder_bits(capacity: usize, remainder_bits: u32) -> Self {
        let slots = (capacity as f64 * 1.1).ceil() as usize;
        Self {
            remainder: vec![0; slots],
            count: vec![0; slots],
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
        let rem = (h >> (64 - self.remainder_bits)) as u32 | 1;
        let quot =
            (h & ((1_u64 << (64 - self.remainder_bits)) - 1)) as usize % self.remainder.len();

        let mut pos = quot;
        loop {
            if self.count[pos] == 0 {
                self.remainder[pos] = rem;
                self.count[pos] = 1;
                self.len += 1;
                return true;
            }
            if self.remainder[pos] == rem {
                if self.count[pos] < 7 {
                    self.count[pos] += 1;
                    self.len += 1;
                    return true;
                }
                return false;
            }
            pos = (pos + 1) % self.remainder.len();
        }
    }

    pub fn contains<T: Hash>(&self, value: &T) -> bool {
        let h = hash_value(value);
        let rem = (h >> (64 - self.remainder_bits)) as u32 | 1;
        let quot =
            (h & ((1_u64 << (64 - self.remainder_bits)) - 1)) as usize % self.remainder.len();

        let mut pos = quot;
        loop {
            if self.count[pos] == 0 {
                return false;
            }
            if self.remainder[pos] == rem {
                return true;
            }
            pos = (pos + 1) % self.remainder.len();
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn byte_len(&self) -> usize {
        self.remainder.len() * 4 + self.count.len()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.byte_len());
        for &r in &self.remainder {
            bytes.extend_from_slice(&r.to_le_bytes());
        }
        for &c in &self.count {
            bytes.push(c);
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8], capacity: usize, remainder_bits: u32) -> Option<Self> {
        let slots = (capacity as f64 * 1.1).ceil() as usize;
        let expected = slots * 4 + slots;
        if bytes.len() < expected {
            return None;
        }
        let mut remainder = vec![0_u32; slots];
        let mut offset = 0;
        for r in &mut remainder {
            let mut buf = [0; 4];
            buf.copy_from_slice(&bytes[offset..offset + 4]);
            *r = u32::from_le_bytes(buf);
            offset += 4;
        }
        let mut count = vec![0_u8; slots];
        for c in &mut count {
            *c = bytes[offset];
            offset += 1;
        }
        let len = count.iter().filter(|&&c| c > 0).count();
        Some(Self {
            remainder,
            count,
            capacity,
            remainder_bits,
            len,
        })
    }
}

fn fingerprint_bits_for_fpr(target_fpr: f64) -> u32 {
    // Cuckoo filter optimal fingerprint size: ln(1/p) / ln(2) ≈ -log2(p)
    // With bucket_size=4, we get ~1 extra bit of accuracy.
    let bits = -(target_fpr.ln() / std::f64::consts::LN_2);
    (bits.ceil() as u32).max(8)
}
