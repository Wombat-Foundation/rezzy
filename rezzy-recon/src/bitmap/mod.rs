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

pub use self::wide::{Bitmap128, Bitmap64, Iter128, Iter64};

mod wide;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::iter::FromIterator;
use core::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, Sub, SubAssign};

/// Magic prefix for [`Bitmap::encode`].
pub const BITMAP_MAGIC: [u8; 4] = *b"RBMP";
/// Version of the [`Bitmap`] wire format.
pub const BITMAP_FORMAT_VERSION: u8 = 1;

/// Errors returned by [`Bitmap::decode`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitmapDecodeError {
    /// The input ended before a complete value could be read.
    Truncated,
    /// The input does not have the [`BITMAP_MAGIC`] prefix.
    InvalidMagic,
    /// The input uses a format version this crate does not understand.
    UnsupportedVersion(u8),
    /// A chunk kind byte is not defined by the format.
    InvalidChunkKind(u8),
    /// The payload is not in canonical bitmap form.
    NonCanonical,
    /// Bytes remain after the encoded bitmap.
    TrailingBytes,
}

impl fmt::Display for BitmapDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated bitmap encoding"),
            Self::InvalidMagic => f.write_str("invalid bitmap encoding magic"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported bitmap encoding version {version}")
            }
            Self::InvalidChunkKind(kind) => write!(f, "invalid bitmap chunk kind {kind}"),
            Self::NonCanonical => f.write_str("non-canonical bitmap encoding"),
            Self::TrailingBytes => f.write_str("trailing bytes after bitmap encoding"),
        }
    }
}

impl core::error::Error for BitmapDecodeError {}

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

fn clear_bit(words: &mut [u64; WORDS], lo: u16) -> bool {
    let w = &mut words[usize::from(lo >> 6)];
    let mask = 1u64 << (lo & 63);
    let present = *w & mask != 0;
    *w &= !mask;
    present
}

fn popcount(words: &[u64; WORDS]) -> u32 {
    words.iter().map(|w| w.count_ones()).sum()
}

fn words_to_array(words: &[u64; WORDS]) -> Vec<u16> {
    let mut out = Vec::new();
    for (i, &word) in words.iter().enumerate() {
        let mut w = word;
        while w != 0 {
            let base = u16::try_from(i.checked_mul(64).expect("bitmap word index fits u16"))
                .expect("bitmap word base fits u16");
            let offset = u16::try_from(w.trailing_zeros()).expect("trailing zero count fits u16");
            out.push(base.checked_add(offset).expect("bitmap bit index fits u16"));
            w &= w.checked_sub(1).expect("nonzero word is positive");
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
        let len = u32::try_from(values.len()).expect("bitmap chunk length fits u32");
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
        Self::from_counted_words(key, words, len)
    }

    /// Builds a canonical chunk from a bitset whose cardinality is `len`.
    fn from_counted_words(key: u16, words: Words, len: u32) -> Option<Self> {
        if len == 0 {
            return None;
        }
        let store = if usize::try_from(len).expect("bitmap length fits usize") <= ARRAY_MAX {
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
                self.len = self
                    .len
                    .checked_add(1)
                    .expect("bitmap chunk length overflow");
                if v.len() > ARRAY_MAX {
                    self.store = Store::Dense(array_to_words(v));
                }
                true
            }
            Store::Dense(w) => {
                let fresh = set_bit(w, lo);
                self.len = self
                    .len
                    .checked_add(u32::from(fresh))
                    .expect("bitmap chunk length overflow");
                fresh
            }
        }
    }

    fn remove(&mut self, lo: u16) -> bool {
        match &mut self.store {
            Store::Array(v) => {
                let Ok(pos) = v.binary_search(&lo) else {
                    return false;
                };
                v.remove(pos);
                self.len = self
                    .len
                    .checked_sub(1)
                    .expect("present bitmap value has length");
                true
            }
            Store::Dense(w) => {
                if !clear_bit(w, lo) {
                    return false;
                }
                self.len = self
                    .len
                    .checked_sub(1)
                    .expect("present bitmap value has length");
                if usize::try_from(self.len).expect("bitmap length fits usize") <= ARRAY_MAX {
                    self.store = Store::Array(words_to_array(w));
                }
                true
            }
        }
    }

    fn is_subset(&self, other: &Self) -> bool {
        match (&self.store, &other.store) {
            (Store::Array(a), Store::Array(b)) => a.iter().all(|x| b.binary_search(x).is_ok()),
            (Store::Array(a), Store::Dense(b)) => a.iter().all(|&x| test_bit(b, x)),
            (Store::Dense(_), Store::Array(_)) => false,
            (Store::Dense(a), Store::Dense(b)) => a.iter().zip(b.iter()).all(|(x, y)| x & !y == 0),
        }
    }

    fn is_disjoint(&self, other: &Self) -> bool {
        match (&self.store, &other.store) {
            (Store::Array(a), Store::Array(b)) => {
                let (mut i, mut j) = (0, 0);
                while i < a.len() && j < b.len() {
                    match a[i].cmp(&b[j]) {
                        core::cmp::Ordering::Less => {
                            i = i.checked_add(1).expect("array index fits");
                        }
                        core::cmp::Ordering::Greater => {
                            j = j.checked_add(1).expect("array index fits");
                        }
                        core::cmp::Ordering::Equal => return false,
                    }
                }
                true
            }
            (Store::Array(a), Store::Dense(b)) | (Store::Dense(b), Store::Array(a)) => {
                a.iter().all(|&x| !test_bit(b, x))
            }
            (Store::Dense(a), Store::Dense(b)) => a.iter().zip(b.iter()).all(|(x, y)| x & y == 0),
        }
    }

    fn union(&self, other: &Self) -> Self {
        let key = self.key;
        let merged = match (&self.store, &other.store) {
            (Store::Array(a), Store::Array(b)) => {
                let capacity = a
                    .len()
                    .checked_add(b.len())
                    .expect("bitmap union size fits");
                let mut out = Vec::with_capacity(capacity);
                let (mut i, mut j) = (0, 0);
                while i < a.len() && j < b.len() {
                    match a[i].cmp(&b[j]) {
                        core::cmp::Ordering::Less => {
                            out.push(a[i]);
                            i = i.checked_add(1).expect("array index fits");
                        }
                        core::cmp::Ordering::Greater => {
                            out.push(b[j]);
                            j = j.checked_add(1).expect("array index fits");
                        }
                        core::cmp::Ordering::Equal => {
                            out.push(a[i]);
                            i = i.checked_add(1).expect("array index fits");
                            j = j.checked_add(1).expect("array index fits");
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
                let mut added: u32 = 0;
                for (x, y) in a.iter_mut().zip(b.iter()) {
                    // Only the newly set bits need counting (one popcount per word).
                    added = added
                        .checked_add((y & !*x).count_ones())
                        .expect("bitmap chunk length overflow");
                    *x |= y;
                }
                self.len = self
                    .len
                    .checked_add(added)
                    .expect("bitmap chunk length overflow");
            }
            (Store::Dense(a), Store::Array(b)) => {
                let mut added: u32 = 0;
                for &x in b {
                    added = added
                        .checked_add(u32::from(set_bit(a, x)))
                        .expect("bitmap chunk length overflow");
                }
                self.len = self
                    .len
                    .checked_add(added)
                    .expect("bitmap chunk length overflow");
            }
            (Store::Array(a), Store::Dense(b)) => {
                let mut words = b.clone();
                let mut added: u32 = 0;
                for &x in a.iter() {
                    added = added
                        .checked_add(u32::from(set_bit(&mut words, x)))
                        .expect("bitmap chunk length overflow");
                }
                self.store = Store::Dense(words);
                self.len = other
                    .len
                    .checked_add(added)
                    .expect("bitmap chunk length overflow");
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
                let mut out = Vec::new();
                let (mut i, mut j) = (0, 0);
                // Branch-free cursor advance: the three-way `match` mispredicts
                // on interleaved random data, which dominates sparse `&`.
                while i < a.len() && j < b.len() {
                    let (lo_a, lo_b) = (a[i], b[j]);
                    if lo_a == lo_b {
                        out.push(lo_a);
                    }
                    i = i
                        .checked_add(usize::from(lo_a <= lo_b))
                        .expect("array index fits");
                    j = j
                        .checked_add(usize::from(lo_b <= lo_a))
                        .expect("array index fits");
                }
                Self::from_array(key, out)
            }
            (Store::Dense(a), Store::Dense(b)) => {
                // One pass: AND into a fresh bitset while counting, so the
                // result needs neither a clone of `a` nor a recount.
                let mut w = empty_words();
                let mut len: u32 = 0;
                for ((o, x), y) in w.iter_mut().zip(a.iter()).zip(b.iter()) {
                    *o = x & y;
                    len = len
                        .checked_add(o.count_ones())
                        .expect("bitmap chunk length overflow");
                }
                Self::from_counted_words(key, w, len)
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
                        j = j.checked_add(1).expect("array index fits");
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
    pub const fn is_empty(&self) -> bool {
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

    /// Removes `value`, returning `true` if it was present.
    pub fn remove(&mut self, value: u32) -> bool {
        let (key, lo) = split(value);
        let Ok(pos) = self.chunks.binary_search_by_key(&key, |c| c.key) else {
            return false;
        };
        let chunk = Arc::make_mut(&mut self.chunks[pos]);
        if !chunk.remove(lo) {
            return false;
        }
        if chunk.len == 0 {
            self.chunks.remove(pos);
        }
        true
    }

    /// Returns whether every value in `self` is also in `other`.
    #[must_use]
    pub fn is_subset(&self, other: &Self) -> bool {
        self.chunks.iter().all(|chunk| {
            other
                .chunks
                .binary_search_by_key(&chunk.key, |c| c.key)
                .is_ok_and(|i| chunk.is_subset(&other.chunks[i]))
        })
    }

    /// Returns whether `self` and `other` have no values in common.
    ///
    /// # Panics
    ///
    /// Panics only if the internal chunk index overflows, which is impossible
    /// for a valid in-memory bitmap.
    #[must_use]
    pub fn is_disjoint(&self, other: &Self) -> bool {
        let (mut i, mut j) = (0, 0);
        while let (Some(a), Some(b)) = (self.chunks.get(i), other.chunks.get(j)) {
            match a.key.cmp(&b.key) {
                core::cmp::Ordering::Less => i = i.checked_add(1).expect("chunk index fits"),
                core::cmp::Ordering::Greater => j = j.checked_add(1).expect("chunk index fits"),
                core::cmp::Ordering::Equal => {
                    if !a.is_disjoint(b) {
                        return false;
                    }
                    i = i.checked_add(1).expect("chunk index fits");
                    j = j.checked_add(1).expect("chunk index fits");
                }
            }
        }
        true
    }

    /// Encodes this bitmap in a stable, versioned binary format.
    ///
    /// The format is little-endian and stores each canonical chunk as either
    /// its sorted `u16` values or its 1024-word bitset. It is intentionally a
    /// payload format: callers that need domain separation should wrap it in
    /// their own domain-tagged envelope.
    ///
    /// # Panics
    ///
    /// Panics if the encoded size cannot be represented by `usize`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        // Header plus the smallest possible per-chunk records. The vector is
        // allowed to grow for dense chunks.
        let capacity = self
            .chunks
            .len()
            .checked_mul(7)
            .and_then(|n| n.checked_add(9))
            .expect("bitmap encoding size fits usize");
        let mut out = Vec::with_capacity(capacity);
        out.extend_from_slice(&BITMAP_MAGIC);
        out.push(BITMAP_FORMAT_VERSION);
        out.extend_from_slice(
            &u32::try_from(self.chunks.len())
                .expect("bitmap chunk count fits u32")
                .to_le_bytes(),
        );
        for chunk in &self.chunks {
            out.extend_from_slice(&chunk.key.to_le_bytes());
            match &chunk.store {
                Store::Array(values) => {
                    out.push(0);
                    out.extend_from_slice(&chunk.len.to_le_bytes());
                    for value in values {
                        out.extend_from_slice(&value.to_le_bytes());
                    }
                }
                Store::Dense(words) => {
                    out.push(1);
                    out.extend_from_slice(&chunk.len.to_le_bytes());
                    for word in words.iter() {
                        out.extend_from_slice(&word.to_le_bytes());
                    }
                }
            }
        }
        out
    }

    /// Decodes a bitmap produced by [`Bitmap::encode`].
    ///
    /// The decoder validates ordering, lengths, cardinalities and trailing
    /// bytes, rejecting malformed or non-canonical input.
    ///
    /// # Errors
    /// Returns [`BitmapDecodeError`] when the input is truncated, uses an
    /// unsupported version, or is otherwise malformed.
    pub fn decode(bytes: &[u8]) -> Result<Self, BitmapDecodeError> {
        let mut input = bytes;
        if input.len() < 9 {
            return Err(BitmapDecodeError::Truncated);
        }
        if input[..4] != BITMAP_MAGIC {
            return Err(BitmapDecodeError::InvalidMagic);
        }
        if input[4] != BITMAP_FORMAT_VERSION {
            return Err(BitmapDecodeError::UnsupportedVersion(input[4]));
        }
        input = &input[5..];
        let count =
            usize::try_from(read_u32(&mut input)?).map_err(|_| BitmapDecodeError::NonCanonical)?;
        let mut chunks = Vec::with_capacity(count.min(input.len() / 7));
        let mut previous = None;
        for _ in 0..count {
            let key = read_u16(&mut input)?;
            if previous.is_some_and(|previous| key <= previous) {
                return Err(BitmapDecodeError::NonCanonical);
            }
            previous = Some(key);
            let kind = read_byte(&mut input)?;
            let len = read_u32(&mut input)?;
            let chunk = match kind {
                0 => {
                    let len_usize =
                        usize::try_from(len).map_err(|_| BitmapDecodeError::NonCanonical)?;
                    if len == 0 || len_usize > ARRAY_MAX {
                        return Err(BitmapDecodeError::NonCanonical);
                    }
                    let raw = take(
                        &mut input,
                        len_usize
                            .checked_mul(2)
                            .ok_or(BitmapDecodeError::Truncated)?,
                    )?;
                    let values: Vec<u16> = raw
                        .chunks_exact(2)
                        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                        .collect();
                    if !values.windows(2).all(|pair| pair[0] < pair[1]) {
                        return Err(BitmapDecodeError::NonCanonical);
                    }
                    Chunk::from_array(key, values).ok_or(BitmapDecodeError::NonCanonical)?
                }
                1 => {
                    if usize::try_from(len).map_err(|_| BitmapDecodeError::NonCanonical)?
                        <= ARRAY_MAX
                    {
                        return Err(BitmapDecodeError::NonCanonical);
                    }
                    let raw = take(&mut input, WORDS * 8)?;
                    let mut words = empty_words();
                    for (word, bytes) in words.iter_mut().zip(raw.chunks_exact(8)) {
                        *word = u64::from_le_bytes([
                            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
                            bytes[7],
                        ]);
                    }
                    if popcount(&words) != len {
                        return Err(BitmapDecodeError::NonCanonical);
                    }
                    Chunk {
                        key,
                        len,
                        store: Store::Dense(words),
                    }
                }
                other => return Err(BitmapDecodeError::InvalidChunkKind(other)),
            };
            chunks.push(Arc::new(chunk));
        }
        if !input.is_empty() {
            return Err(BitmapDecodeError::TrailingBytes);
        }
        Ok(Self { chunks })
    }

    /// Adds `value`, returning `true` if it was not already present.
    ///
    /// # Panics
    ///
    /// Panics only if the internal chunk index underflows, which is impossible
    /// when the matched `last` chunk exists.
    pub fn insert(&mut self, value: u32) -> bool {
        let (key, lo) = split(value);
        // Ascending insertion (the common case) always lands on the last chunk.
        let pos = match self.chunks.last() {
            Some(last) if last.key == key => {
                self.chunks.len().checked_sub(1).expect("last chunk exists")
            }
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

fn split(value: u32) -> (u16, u16) {
    (
        u16::try_from(value >> 16).expect("bitmap high half fits u16"),
        u16::try_from(value & u32::from(u16::MAX)).expect("bitmap low half fits u16"),
    )
}

fn read_byte(input: &mut &[u8]) -> Result<u8, BitmapDecodeError> {
    let (&byte, rest) = input.split_first().ok_or(BitmapDecodeError::Truncated)?;
    *input = rest;
    Ok(byte)
}

fn read_array<const N: usize>(input: &mut &[u8]) -> Result<[u8; N], BitmapDecodeError> {
    if input.len() < N {
        return Err(BitmapDecodeError::Truncated);
    }
    let (head, rest) = input.split_at(N);
    *input = rest;
    head.try_into().map_err(|_| BitmapDecodeError::Truncated)
}

fn read_u16(input: &mut &[u8]) -> Result<u16, BitmapDecodeError> {
    Ok(u16::from_le_bytes(read_array(input)?))
}

fn read_u32(input: &mut &[u8]) -> Result<u32, BitmapDecodeError> {
    Ok(u32::from_le_bytes(read_array(input)?))
}

/// Splits `n` bytes off the front of `input`.
const fn take<'a>(input: &mut &'a [u8], n: usize) -> Result<&'a [u8], BitmapDecodeError> {
    if input.len() < n {
        return Err(BitmapDecodeError::Truncated);
    }
    let (head, rest) = input.split_at(n);
    *input = rest;
    Ok(head)
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
                    cursor.pos = cursor.pos.checked_add(1).expect("bitmap cursor fits u32");
                    return Some(base | u32::from(lo));
                }
            }
            Store::Dense(w) => {
                let mut wi =
                    usize::try_from(cursor.pos >> 6).expect("bitmap word index fits usize");
                if wi < WORDS {
                    let mut word = w[wi] & (!0u64 << (cursor.pos & 63));
                    loop {
                        if word != 0 {
                            let bit = u32::try_from(wi)
                                .expect("bitmap word index fits u32")
                                .checked_mul(64)
                                .and_then(|base| base.checked_add(word.trailing_zeros()))
                                .expect("bitmap bit index fits u32");
                            cursor.pos = bit.checked_add(1).expect("bitmap cursor fits u32");
                            return Some(base | bit);
                        }
                        wi = wi.checked_add(1).expect("bitmap word index fits");
                        if wi == WORDS {
                            break;
                        }
                        word = w[wi];
                    }
                }
            }
        }
        cursor.chunk = cursor
            .chunk
            .checked_add(1)
            .expect("bitmap chunk index fits");
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

impl Bitmap {
    fn subtract_assign(&mut self, rhs: &Self) {
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
        // Build the result directly: cloning `self` first would copy every
        // chunk that the intersection then discards or rewrites.
        let mut chunks = Vec::new();
        let mut theirs = rhs.chunks.iter().peekable();
        for chunk in &self.chunks {
            while theirs.next_if(|o| o.key < chunk.key).is_some() {}
            if let Some(o) = theirs.next_if(|o| o.key == chunk.key) {
                chunks.extend(chunk.intersection(o).map(Arc::new));
            }
        }
        Bitmap { chunks }
    }
}

impl Sub<&Self> for Bitmap {
    type Output = Self;

    fn sub(mut self, rhs: &Self) -> Self {
        self.subtract_assign(rhs);
        self
    }
}

impl Sub for Bitmap {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        let mut out = self;
        out.subtract_assign(&rhs);
        out
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
            .map(|v| base.checked_add(v).expect("test value fits u32"))
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
        for v in 0..u32::try_from(ARRAY_MAX).expect("test constant fits u32") {
            b.insert(v * 2);
        }
        assert!(matches!(b.chunks[0].store, Store::Array(_)));
        b.insert(1);
        assert!(matches!(b.chunks[0].store, Store::Dense(_)));
        // Subtracting back down to the threshold returns to an array.
        let drop: Bitmap = core::iter::once(1u32).collect();
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
        let array_max = u32::try_from(ARRAY_MAX).expect("test constant fits u32");
        let mut all: BTreeSet<u32> = (0..array_max + 10)
            .map(|v| v.checked_mul(3).expect("test value fits u32"))
            .collect();
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
        let array_max = u32::try_from(ARRAY_MAX).expect("test constant fits u32");
        let mut b: Bitmap = (0..=array_max).collect();
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
        let mut c = ba;
        c.extend(b.iter().copied());
        check(&c, &a.union(&b).copied().collect());
    }

    #[test]
    fn remove_and_relationships() {
        let mut bitmap: Bitmap = [0, 1, 65_536, u32::MAX].into_iter().collect();
        assert!(bitmap.is_subset(&bitmap));
        assert!(bitmap.is_disjoint(&Bitmap::new()));
        assert!(!bitmap.is_disjoint(&core::iter::once(1u32).collect()));
        assert!(!bitmap.is_subset(&[0, 1].into_iter().collect()));
        assert!(bitmap.remove(1));
        assert!(!bitmap.remove(1));
        assert!(!bitmap.contains(1));
        assert!(bitmap.remove(0));
        assert!(bitmap.remove(65_536));
        assert!(bitmap.remove(u32::MAX));
        assert!(bitmap.is_empty());
    }

    #[test]
    fn encode_decode_round_trip_and_rejects_bad_input() {
        let array_max = u32::try_from(ARRAY_MAX).expect("test constant fits u32");
        let values: BTreeSet<u32> = (0..=array_max)
            .map(|value| value * 3)
            .chain([u32::MAX])
            .collect();
        let bitmap = build(&values);
        let encoded = bitmap.encode();
        assert_eq!(Bitmap::decode(&encoded).unwrap(), bitmap);

        let mut bad = encoded.clone();
        bad[4] = 2;
        assert_eq!(
            Bitmap::decode(&bad),
            Err(BitmapDecodeError::UnsupportedVersion(2))
        );
        assert_eq!(
            Bitmap::decode(&encoded[..encoded.len() - 1]),
            Err(BitmapDecodeError::Truncated)
        );
        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            Bitmap::decode(&trailing),
            Err(BitmapDecodeError::TrailingBytes)
        );
    }

    #[test]
    fn remove_matches_btreeset_and_demotes() {
        let mut rng = Rng(0x1234_5678_9abc_def1);
        for &density in &[3u64, 16, 40, 200, 256] {
            let mut set = random_set(&mut rng, 5_000, 120_000, density);
            let mut bitmap = build(&set);
            let victims: Vec<u32> = set
                .iter()
                .copied()
                .filter(|_| rng.next() % 3 != 0)
                .chain([0, 7, u32::MAX])
                .collect();
            for v in victims {
                assert_eq!(bitmap.remove(v), set.remove(&v));
            }
            check(&bitmap, &set);
        }
        // Removing across the threshold returns a dense chunk to an array.
        let array_max = u32::try_from(ARRAY_MAX).expect("test constant fits u32");
        let mut b: Bitmap = (0..=array_max).collect();
        assert!(matches!(b.chunks[0].store, Store::Dense(_)));
        assert!(b.remove(0));
        assert!(matches!(b.chunks[0].store, Store::Array(_)));
        assert_eq!(b.len(), ARRAY_MAX as u64);
    }

    #[test]
    fn subset_and_disjoint_match_btreeset() {
        let mut rng = Rng(0xdead_beef_cafe_f00d);
        for &da in &[0u64, 3, 16, 64, 256] {
            for &db in &[0u64, 3, 16, 64, 256] {
                let sa = random_set(&mut rng, 10_000, 90_000, da);
                let sb = random_set(&mut rng, 40_000, 90_000, db);
                let (a, b) = (build(&sa), build(&sb));
                assert_eq!(a.is_subset(&b), sa.is_subset(&sb));
                assert_eq!(a.is_disjoint(&b), sa.is_disjoint(&sb));
                let both: Bitmap = &a | &b;
                assert!(a.is_subset(&both) && b.is_subset(&both));
                assert!(a.is_subset(&a) && a.is_disjoint(&(both.clone() - &both)));
            }
        }
    }

    #[test]
    fn encode_round_trips_across_densities() {
        let mut rng = Rng(0x0bad_5eed_0bad_5eed);
        for &density in &[0u64, 1, 16, 17, 128, 256] {
            let set = random_set(&mut rng, 70_000, 150_000, density);
            let bitmap = build(&set);
            let decoded = Bitmap::decode(&bitmap.encode()).unwrap();
            check(&decoded, &set);
            assert_eq!(decoded.encode(), bitmap.encode());
        }
    }

    #[test]
    fn decode_rejects_malformed_input() {
        let good = build(&[1u32, 2, 3, 70_000].into_iter().collect()).encode();
        assert_eq!(Bitmap::decode(&[]), Err(BitmapDecodeError::Truncated));
        let mut bad_magic = good.clone();
        bad_magic[0] ^= 1;
        assert_eq!(
            Bitmap::decode(&bad_magic),
            Err(BitmapDecodeError::InvalidMagic)
        );
        // Every proper prefix is rejected rather than panicking.
        for end in 0..good.len() {
            assert!(Bitmap::decode(&good[..end]).is_err(), "prefix {end}");
        }
        // Chunk kind 2 does not exist: kind byte follows magic(4) ver(1) count(4) key(2).
        let mut bad_kind = good.clone();
        bad_kind[11] = 2;
        assert_eq!(
            Bitmap::decode(&bad_kind),
            Err(BitmapDecodeError::InvalidChunkKind(2))
        );
        // Unsorted array values are non-canonical.
        let mut unsorted = good;
        let first = 16;
        unsorted.swap(first, first + 2);
        assert_eq!(
            Bitmap::decode(&unsorted),
            Err(BitmapDecodeError::NonCanonical)
        );
        // A dense chunk claiming a small cardinality is non-canonical.
        let mut dense = Vec::new();
        dense.extend_from_slice(&BITMAP_MAGIC);
        dense.push(BITMAP_FORMAT_VERSION);
        dense.extend_from_slice(&1u32.to_le_bytes());
        dense.extend_from_slice(&0u16.to_le_bytes());
        dense.push(1);
        dense.extend_from_slice(&5u32.to_le_bytes());
        dense.extend(core::iter::repeat_n(0u8, WORDS * 8));
        assert_eq!(Bitmap::decode(&dense), Err(BitmapDecodeError::NonCanonical));
        // Duplicate or descending chunk keys are non-canonical.
        let two = build(&[1u32, 70_000].into_iter().collect()).encode();
        let mut dup = two;
        dup[9..11].copy_from_slice(&1u16.to_le_bytes());
        assert!(Bitmap::decode(&dup).is_err());
    }
}
