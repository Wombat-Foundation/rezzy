//! A dependency-free compressed set of `u32` values.
//!
//! This is the 16/16 split behind Roaring bitmaps (the format, not the crate), restricted to what rezzy
//! needs: each value is split into a high 16-bit key and a low 16-bit offset,
//! and values sharing a key live in one container. A container is either a
//! sorted `u16` array (at most 4096 values) or a fixed 8 KiB bitset.
//! There are no run containers and no SIMD; the representation is canonical
//! (a container is an array exactly when it holds `<= ARRAY_MAX` values, and
//! empty containers are dropped), so `==` is structural.
//!
//! Only `alloc` is required.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    reason = "indices are bounded by the 16-bit split and 1024-word bitsets"
)]

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::iter::FromIterator;
use core::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, Sub, SubAssign};

/// A sorted array container holds at most this many values; denser chunks use a bitset.
const ARRAY_MAX: usize = 4096;
/// Number of `u64` words in a bitset container (65 536 bits).
const WORDS: usize = 1024;

type Words = Box<[u64; WORDS]>;

#[derive(Clone, PartialEq, Eq)]
enum Store {
    /// Sorted, deduplicated low halves.
    Array(Vec<u16>),
    /// Bitset over all 65 536 low halves.
    Dense(Words),
}

#[derive(Clone, PartialEq, Eq)]
struct Chunk {
    key: u16,
    /// Cached cardinality; always equals the number of values in `store`.
    len: u32,
    store: Store,
}

fn empty_words() -> Words {
    Box::new([0u64; WORDS])
}

fn test_bit(words: &[u64; WORDS], lo: u16) -> bool {
    (words[usize::from(lo >> 6)] >> (lo & 63)) & 1 != 0
}

fn set_bit(words: &mut [u64; WORDS], lo: u16) -> bool {
    let w = &mut words[usize::from(lo >> 6)];
    let mask = 1u64 << (lo & 63);
    let fresh = *w & mask == 0;
    *w |= mask;
    fresh
}

fn popcount(words: &[u64; WORDS]) -> u32 {
    words.iter().map(|w| w.count_ones()).sum()
}

fn words_to_array(words: &[u64; WORDS]) -> Vec<u16> {
    let mut out = Vec::new();
    for (i, &word) in words.iter().enumerate() {
        let mut w = word;
        while w != 0 {
            out.push((i * 64) as u16 + w.trailing_zeros() as u16);
            w &= w - 1;
        }
    }
    out
}

fn array_to_words(values: &[u16]) -> Words {
    let mut words = empty_words();
    for &v in values {
        set_bit(&mut words, v);
    }
    words
}

impl Chunk {
    fn from_array(key: u16, values: Vec<u16>) -> Option<Self> {
        if values.is_empty() {
            return None;
        }
        let len = values.len() as u32;
        let store = if values.len() > ARRAY_MAX {
            Store::Dense(array_to_words(&values))
        } else {
            Store::Array(values)
        };
        Some(Self { key, len, store })
    }

    /// Builds a canonical chunk from a bitset, recounting its cardinality.
    fn from_words(key: u16, words: Words) -> Option<Self> {
        let len = popcount(&words);
        if len == 0 {
            return None;
        }
        let store = if len as usize <= ARRAY_MAX {
            Store::Array(words_to_array(&words))
        } else {
            Store::Dense(words)
        };
        Some(Self { key, len, store })
    }

    fn contains(&self, lo: u16) -> bool {
        match &self.store {
            Store::Array(v) => v.binary_search(&lo).is_ok(),
            Store::Dense(w) => test_bit(w, lo),
        }
    }

    fn insert(&mut self, lo: u16) -> bool {
        match &mut self.store {
            Store::Array(v) => {
                if v.last().is_none_or(|&last| last < lo) {
                    v.push(lo);
                } else {
                    match v.binary_search(&lo) {
                        Ok(_) => return false,
                        Err(pos) => v.insert(pos, lo),
                    }
                }
                self.len += 1;
                if v.len() > ARRAY_MAX {
                    self.store = Store::Dense(array_to_words(v));
                }
                true
            }
            Store::Dense(w) => {
                let fresh = set_bit(w, lo);
                self.len += u32::from(fresh);
                fresh
            }
        }
    }

    fn union(&self, other: &Self) -> Self {
        let key = self.key;
        let merged = match (&self.store, &other.store) {
            (Store::Array(a), Store::Array(b)) => {
                let mut out = Vec::with_capacity(a.len() + b.len());
                let (mut i, mut j) = (0, 0);
                while i < a.len() && j < b.len() {
                    match a[i].cmp(&b[j]) {
                        core::cmp::Ordering::Less => {
                            out.push(a[i]);
                            i += 1;
                        }
                        core::cmp::Ordering::Greater => {
                            out.push(b[j]);
                            j += 1;
                        }
                        core::cmp::Ordering::Equal => {
                            out.push(a[i]);
                            i += 1;
                            j += 1;
                        }
                    }
                }
                out.extend_from_slice(&a[i..]);
                out.extend_from_slice(&b[j..]);
                return Self::from_array(key, out).expect("union of non-empty chunks");
            }
            (Store::Dense(a), Store::Dense(b)) => {
                let mut w = a.clone();
                for (x, y) in w.iter_mut().zip(b.iter()) {
                    *x |= y;
                }
                w
            }
            (Store::Dense(d), Store::Array(v)) | (Store::Array(v), Store::Dense(d)) => {
                let mut w = d.clone();
                for &x in v {
                    set_bit(&mut w, x);
                }
                w
            }
        };
        Self::from_words(key, merged).expect("union of non-empty chunks")
    }

    /// Unions `other` into this chunk without replacing dense storage.
    fn union_assign(&mut self, other: &Self) {
        debug_assert_eq!(self.key, other.key);

        match (&mut self.store, &other.store) {
            (Store::Dense(a), Store::Dense(b)) => {
                let mut added = 0;
                for (x, y) in a.iter_mut().zip(b.iter()) {
                    let before = *x;
                    *x |= y;
                    added += (*x).count_ones() - before.count_ones();
                }
                self.len += added;
            }
            (Store::Dense(a), Store::Array(b)) => {
                let mut added = 0;
                for &x in b {
                    added += u32::from(set_bit(a, x));
                }
                self.len += added;
            }
            (Store::Array(a), Store::Dense(b)) => {
                let mut words = b.clone();
                for &x in a.iter() {
                    set_bit(&mut words, x);
                }
                let len = popcount(&words);
                self.store = Store::Dense(words);
                self.len = len;
            }
            (Store::Array(_), Store::Array(_)) => {
                *self = self.union(other);
            }
        }
    }

    fn intersection(&self, other: &Self) -> Option<Self> {
        let key = self.key;
        match (&self.store, &other.store) {
            (Store::Array(a), Store::Array(b)) => {
                let mut out = Vec::with_capacity(a.len().min(b.len()));
                let (mut i, mut j) = (0, 0);
                while i < a.len() && j < b.len() {
                    match a[i].cmp(&b[j]) {
                        core::cmp::Ordering::Less => i += 1,
                        core::cmp::Ordering::Greater => j += 1,
                        core::cmp::Ordering::Equal => {
                            out.push(a[i]);
                            i += 1;
                            j += 1;
                        }
                    }
                }
                Self::from_array(key, out)
            }
            (Store::Dense(a), Store::Dense(b)) => {
                let mut w = a.clone();
                for (x, y) in w.iter_mut().zip(b.iter()) {
                    *x &= y;
                }
                Self::from_words(key, w)
            }
            (Store::Array(v), Store::Dense(d)) | (Store::Dense(d), Store::Array(v)) => {
                let out = v.iter().copied().filter(|&x| test_bit(d, x)).collect();
                Self::from_array(key, out)
            }
        }
    }

    fn difference(&self, other: &Self) -> Option<Self> {
        let key = self.key;
        match (&self.store, &other.store) {
            (Store::Array(a), Store::Array(b)) => {
                let mut out = Vec::with_capacity(a.len());
                let mut j = 0;
                for &x in a {
                    while j < b.len() && b[j] < x {
                        j += 1;
                    }
                    if j >= b.len() || b[j] != x {
                        out.push(x);
                    }
                }
                Self::from_array(key, out)
            }
            (Store::Array(a), Store::Dense(d)) => {
                let out = a.iter().copied().filter(|&x| !test_bit(d, x)).collect();
                Self::from_array(key, out)
            }
            (Store::Dense(a), Store::Array(b)) => {
                let mut w = a.clone();
                for &x in b {
                    w[usize::from(x >> 6)] &= !(1u64 << (x & 63));
                }
                Self::from_words(key, w)
            }
            (Store::Dense(a), Store::Dense(b)) => {
                let mut w = a.clone();
                for (x, y) in w.iter_mut().zip(b.iter()) {
                    *x &= !y;
                }
                Self::from_words(key, w)
            }
        }
    }
}

/// A compressed set of `u32` values.
///
/// See the [module documentation](self) for the representation.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Bitmap {
    /// Non-empty chunks, strictly ascending by key.
    chunks: Vec<Arc<Chunk>>,
}

impl Bitmap {
    /// Creates an empty set.
    #[must_use]
    pub const fn new() -> Self {
        Self { chunks: Vec::new() }
    }

    /// Returns `true` if the set holds no values.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    /// Returns the number of values in the set.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.chunks.iter().map(|c| u64::from(c.len)).sum()
    }

    /// Returns `true` if `value` is in the set.
    #[must_use]
    pub fn contains(&self, value: u32) -> bool {
        let (key, lo) = split(value);
        self.chunks
            .binary_search_by_key(&key, |c| c.key)
            .is_ok_and(|i| self.chunks[i].contains(lo))
    }

    /// Adds `value`, returning `true` if it was not already present.
    pub fn insert(&mut self, value: u32) -> bool {
        let (key, lo) = split(value);
        // Ascending insertion (the common case) always lands on the last chunk.
        let pos = match self.chunks.last() {
            Some(last) if last.key == key => self.chunks.len() - 1,
            Some(last) if last.key < key => self.chunks.len(),
            None => 0,
            Some(_) => match self.chunks.binary_search_by_key(&key, |c| c.key) {
                Ok(i) | Err(i) => i,
            },
        };
        if self.chunks.get(pos).is_some_and(|c| c.key == key) {
            return Arc::make_mut(&mut self.chunks[pos]).insert(lo);
        }
        self.chunks.insert(
            pos,
            Arc::new(Chunk {
                key,
                len: 1,
                store: Store::Array(alloc::vec![lo]),
            }),
        );
        true
    }

    /// Iterates the values in ascending order.
    #[must_use]
    pub fn iter(&self) -> Iter<'_> {
        Iter {
            chunks: &self.chunks,
            cursor: Cursor { chunk: 0, pos: 0 },
        }
    }

    fn merge_with(&mut self, other: &Self, mode: Mode) {
        if core::ptr::eq(self, other) {
            if mode != Mode::Sub {
                return;
            }
            self.chunks.clear();
            return;
        }
        if other.is_empty() {
            if mode == Mode::And {
                self.chunks.clear();
            }
            return;
        }
        if self.is_empty() {
            if mode == Mode::Or {
                self.chunks.clone_from(&other.chunks);
            }
            return;
        }

        let mine = core::mem::take(&mut self.chunks);
        let mut out = Vec::with_capacity(mine.len());
        let mut theirs = other.chunks.iter().peekable();
        for mut chunk in mine {
            while let Some(o) = theirs.next_if(|o| o.key < chunk.key) {
                if mode == Mode::Or {
                    out.push(Arc::clone(o));
                }
            }
            match (theirs.next_if(|o| o.key == chunk.key), mode) {
                (Some(o), Mode::Or) => {
                    Arc::make_mut(&mut chunk).union_assign(o);
                    out.push(chunk);
                }
                (Some(o), Mode::And) => {
                    out.extend(chunk.intersection(o).map(Arc::new));
                }
                (Some(o), Mode::Sub) => {
                    out.extend(chunk.difference(o).map(Arc::new));
                }
                (None, Mode::And) => {}
                (None, Mode::Or | Mode::Sub) => out.push(chunk),
            }
        }
        if mode == Mode::Or {
            out.extend(theirs.map(Arc::clone));
        }
        self.chunks = out;
    }
}

/// Which set operation [`Bitmap::merge_with`] applies.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Or,
    And,
    Sub,
}

const fn split(value: u32) -> (u16, u16) {
    ((value >> 16) as u16, value as u16)
}

/// Position within the chunk list: which chunk, and the next array index or bit.
#[derive(Clone, Copy)]
struct Cursor {
    chunk: usize,
    pos: u32,
}

fn advance(chunks: &[Arc<Chunk>], cursor: &mut Cursor) -> Option<u32> {
    while let Some(chunk) = chunks.get(cursor.chunk) {
        let base = u32::from(chunk.key) << 16;
        match &chunk.store {
            Store::Array(v) => {
                if let Some(&lo) = v.get(cursor.pos as usize) {
                    cursor.pos += 1;
                    return Some(base | u32::from(lo));
                }
            }
            Store::Dense(w) => {
                let mut wi = (cursor.pos >> 6) as usize;
                if wi < WORDS {
                    let mut word = w[wi] & (!0u64 << (cursor.pos & 63));
                    loop {
                        if word != 0 {
                            let bit = (wi as u32) * 64 + word.trailing_zeros();
                            cursor.pos = bit + 1;
                            return Some(base | bit);
                        }
                        wi += 1;
                        if wi == WORDS {
                            break;
                        }
                        word = w[wi];
                    }
                }
            }
        }
        cursor.chunk += 1;
        cursor.pos = 0;
    }
    None
}

/// Borrowing iterator over a [`Bitmap`], ascending.
pub struct Iter<'a> {
    chunks: &'a [Arc<Chunk>],
    cursor: Cursor,
}

impl Iterator for Iter<'_> {
    type Item = u32;

    fn next(&mut self) -> Option<u32> {
        advance(self.chunks, &mut self.cursor)
    }
}

/// Owning iterator over a [`Bitmap`], ascending.
pub struct IntoIter {
    chunks: Vec<Arc<Chunk>>,
    cursor: Cursor,
}

impl Iterator for IntoIter {
    type Item = u32;

    fn next(&mut self) -> Option<u32> {
        advance(&self.chunks, &mut self.cursor)
    }
}

impl<'a> IntoIterator for &'a Bitmap {
    type Item = u32;
    type IntoIter = Iter<'a>;

    fn into_iter(self) -> Iter<'a> {
        self.iter()
    }
}

impl IntoIterator for Bitmap {
    type Item = u32;
    type IntoIter = IntoIter;

    fn into_iter(self) -> IntoIter {
        IntoIter {
            chunks: self.chunks,
            cursor: Cursor { chunk: 0, pos: 0 },
        }
    }
}

impl Extend<u32> for Bitmap {
    fn extend<I: IntoIterator<Item = u32>>(&mut self, iter: I) {
        for v in iter {
            self.insert(v);
        }
    }
}

impl FromIterator<u32> for Bitmap {
    fn from_iter<I: IntoIterator<Item = u32>>(iter: I) -> Self {
        let mut bitmap = Self::new();
        bitmap.extend(iter);
        bitmap
    }
}

impl fmt::Debug for Bitmap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.iter()).finish()
    }
}

impl BitOrAssign<&Self> for Bitmap {
    fn bitor_assign(&mut self, rhs: &Self) {
        self.merge_with(rhs, Mode::Or);
    }
}

impl BitAndAssign<&Self> for Bitmap {
    fn bitand_assign(&mut self, rhs: &Self) {
        self.merge_with(rhs, Mode::And);
    }
}

impl SubAssign<&Self> for Bitmap {
    fn sub_assign(&mut self, rhs: &Self) {
        self.merge_with(rhs, Mode::Sub);
    }
}

impl BitOr<&Bitmap> for &Bitmap {
    type Output = Bitmap;

    fn bitor(self, rhs: &Bitmap) -> Bitmap {
        let mut out = self.clone();
        out |= rhs;
        out
    }
}

impl BitAnd<&Bitmap> for &Bitmap {
    type Output = Bitmap;

    fn bitand(self, rhs: &Bitmap) -> Bitmap {
        let mut out = self.clone();
        out &= rhs;
        out
    }
}

impl Sub<&Self> for Bitmap {
    type Output = Self;

    fn sub(mut self, rhs: &Self) -> Self {
        self -= rhs;
        self
    }
}

impl Sub for Bitmap {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        self - &rhs
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    /// Random set over `span` values starting at `base`, with ~`density`/256 occupancy.
    fn random_set(rng: &mut Rng, base: u32, span: u32, density: u64) -> BTreeSet<u32> {
        (0..span)
            .filter(|_| rng.next() % 256 < density)
            .map(|v| base + v)
            .collect()
    }

    fn build(set: &BTreeSet<u32>) -> Bitmap {
        set.iter().copied().collect()
    }

    /// The bitmap equals `expected` and is in canonical form.
    fn check(bitmap: &Bitmap, expected: &BTreeSet<u32>) {
        assert_eq!(bitmap.len(), expected.len() as u64);
        assert_eq!(bitmap.is_empty(), expected.is_empty());
        assert!(bitmap.iter().eq(expected.iter().copied()));
        assert!(bitmap.clone().into_iter().eq(expected.iter().copied()));
        assert_eq!(bitmap, &build(expected), "non-canonical representation");
        for chunk in &bitmap.chunks {
            assert_ne!(chunk.len, 0);
            assert_eq!(
                matches!(chunk.store, Store::Array(_)),
                chunk.len as usize <= ARRAY_MAX
            );
        }
        assert!(bitmap.chunks.windows(2).all(|w| w[0].key < w[1].key));
    }

    #[test]
    fn insert_contains_and_dedup() {
        let mut b = Bitmap::new();
        assert!(b.insert(5));
        assert!(!b.insert(5));
        assert!(b.insert(u32::MAX));
        assert!(b.insert(0));
        assert!(b.insert(70_000));
        assert!(b.contains(70_000) && b.contains(u32::MAX) && b.contains(0));
        assert!(!b.contains(6) && !b.contains(70_001));
        assert_eq!(b.len(), 4);
        assert!(b.iter().eq([0, 5, 70_000, u32::MAX]));
    }

    #[test]
    fn out_of_order_insert_matches_sorted() {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let values: Vec<u32> = (0..20_000).map(|_| (rng.next() % 300_000) as u32).collect();
        let b: Bitmap = values.iter().copied().collect();
        check(&b, &values.iter().copied().collect());
    }

    #[test]
    fn array_dense_boundary() {
        let mut b = Bitmap::new();
        for v in 0..ARRAY_MAX as u32 {
            b.insert(v * 2);
        }
        assert!(matches!(b.chunks[0].store, Store::Array(_)));
        b.insert(1);
        assert!(matches!(b.chunks[0].store, Store::Dense(_)));
        // Subtracting back down to the threshold returns to an array.
        let drop: Bitmap = [1u32].into_iter().collect();
        let b = b - &drop;
        assert!(matches!(b.chunks[0].store, Store::Array(_)));
        assert_eq!(b.len(), ARRAY_MAX as u64);
    }

    #[test]
    fn set_ops_match_btreeset_across_densities() {
        let mut rng = Rng(0x2545_f491_4f6c_dd1d);
        // Densities straddle the 4096-of-65536 (16/256) array/bitset threshold.
        for &da in &[0u64, 1, 3, 16, 17, 64, 200, 256] {
            for &db in &[0u64, 2, 15, 16, 18, 128, 256] {
                // Overlapping but offset spans so some chunks pair up and others do not.
                let sa = random_set(&mut rng, 10_000, 40_000, da);
                let sb = random_set(&mut rng, 30_000, 40_000, db);
                let (a, b) = (build(&sa), build(&sb));
                check(&a, &sa);
                check(&b, &sb);

                let mut or = a.clone();
                or |= &b;
                check(&or, &sa.union(&sb).copied().collect());
                check(&(&a | &b), &sa.union(&sb).copied().collect());

                let mut and = a.clone();
                and &= &b;
                check(&and, &sa.intersection(&sb).copied().collect());
                check(&(&a & &b), &sa.intersection(&sb).copied().collect());

                let mut sub = a.clone();
                sub -= &b;
                check(&sub, &sa.difference(&sb).copied().collect());
                check(&(a.clone() - &b), &sa.difference(&sb).copied().collect());
                check(
                    &(a.clone() - b.clone()),
                    &sa.difference(&sb).copied().collect(),
                );

                for v in sa.iter().take(50) {
                    assert!(a.contains(*v));
                }
            }
        }
    }

    #[test]
    fn full_chunk_and_extremes() {
        let all: BTreeSet<u32> = (0..65_536).chain(u32::MAX - 3..=u32::MAX).collect();
        let b = build(&all);
        check(&b, &all);
        assert!(matches!(b.chunks[0].store, Store::Dense(_)));
        let empty = Bitmap::new();
        assert_eq!((&b & &empty).len(), 0);
        assert_eq!(&b | &empty, b);
        assert_eq!(b.clone() - &empty, b);
        assert!((b.clone() - &b).is_empty());
    }

    #[test]
    fn equality_and_debug() {
        let a: Bitmap = [3, 1, 2].into_iter().collect();
        let b: Bitmap = [1, 2, 3].into_iter().collect();
        assert_eq!(a, b);
        assert_eq!(alloc::format!("{a:?}"), "{1, 2, 3}");
        assert_eq!(Bitmap::default(), Bitmap::new());
    }

    #[test]
    fn dense_iteration_contains_and_word_boundaries() {
        // Bits straddling word (63/64) and chunk (65535/65536) edges in a dense chunk.
        let mut all: BTreeSet<u32> = (0..ARRAY_MAX as u32 + 10).map(|v| v * 3).collect();
        all.extend([63, 64, 65_535, 65_536, 131_071, 131_072]);
        let b = build(&all);
        check(&b, &all);
        assert!(matches!(b.chunks[0].store, Store::Dense(_)));
        for v in [63, 64, 65_535, 65_536, 131_071, 131_072, 0, 3] {
            assert!(b.contains(v), "{v}");
        }
        for v in [1, 2, 62, 65_534, 131_070, 131_073, u32::MAX] {
            assert!(!b.contains(v), "{v}");
        }
        // Owned and borrowed iteration agree and stay ascending.
        assert!(b.iter().eq(b.clone()));
        assert!(b.iter().zip(b.iter().skip(1)).all(|(x, y)| x < y));
    }

    #[test]
    fn union_of_arrays_crossing_threshold_densifies() {
        let a: BTreeSet<u32> = (0..3000).map(|v| v * 2).collect();
        let b: BTreeSet<u32> = (0..3000).map(|v| v * 2 + 1).collect();
        let (ba, bb) = (build(&a), build(&b));
        assert!(matches!(ba.chunks[0].store, Store::Array(_)));
        assert!(matches!(bb.chunks[0].store, Store::Array(_)));
        let both = &ba | &bb;
        assert!(matches!(both.chunks[0].store, Store::Dense(_)));
        check(&both, &a.union(&b).copied().collect());
        // Intersecting back down returns to an array.
        let back = &both & &ba;
        assert!(matches!(back.chunks[0].store, Store::Array(_)));
        check(&back, &a);
    }

    #[test]
    fn insert_into_middle_and_front_chunks() {
        let mut b = Bitmap::new();
        for v in [3 << 16, 1 << 16, 5 << 16, 2 << 16, 0, 4 << 16] {
            assert!(b.insert(v));
            assert!(b.contains(v));
        }
        assert!(!b.insert(2 << 16));
        assert!(b.chunks.windows(2).all(|w| w[0].key < w[1].key));
        assert_eq!(b.len(), 6);
    }

    #[test]
    fn dense_insert_counts_and_dedups() {
        let mut b: Bitmap = (0..=ARRAY_MAX as u32).collect();
        assert!(matches!(b.chunks[0].store, Store::Dense(_)));
        let before = b.len();
        assert!(!b.insert(10));
        assert!(b.insert(60_000));
        assert_eq!(b.len(), before + 1);
    }

    #[test]
    fn disjoint_chunk_keys_in_every_mode() {
        let a: BTreeSet<u32> = [1, 2, 3, 5 << 16].into();
        let b: BTreeSet<u32> = [4, 1 << 16, 9 << 16].into();
        let (ba, bb) = (build(&a), build(&b));
        check(&(&ba | &bb), &a.union(&b).copied().collect());
        check(&(&ba & &bb), &BTreeSet::new());
        check(&(ba.clone() - &bb), &a);
        let mut c = ba.clone();
        c.extend(b.iter().copied());
        check(&c, &a.union(&b).copied().collect());
    }
}
