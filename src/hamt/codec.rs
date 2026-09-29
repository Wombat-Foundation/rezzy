//! Dense binary serialization and deserialization for persisted HAMT nodes.

use super::hash::StructuralHash;
use alloc::{string::String, vec::Vec};
use core::hash::Hash;

/// Magic prefix for a persisted HAMT node record.
pub const HAMT_NODE_MAGIC: &[u8; 4] = b"MTHN";

/// Magic prefix for a persisted state-group root record.
pub const HAMT_ROOT_MAGIC: &[u8; 4] = b"MTHR";

/// Wire version of the current persisted-node layout (32-byte structural
/// hashes, inline leaves, then child hashes in nodemap order).
///
/// Recorded after the four-byte magic prefix in every HAMT node.
pub const HAMT_WIRE_VERSION: u8 = 0x01;

/// Custom binary codec for HAMT leaf payloads.
///
/// This stays explicit and versioned instead of delegating persistence
/// semantics to a generic serializer.
pub trait HamtCodec: Sized {
    /// Encodes the value into the provided buffer.
    fn encode_hamt(&self, out: &mut Vec<u8>);

    /// Decodes the value from the provided buffer cursor.
    ///
    /// # Errors
    /// Returns an error if the input buffer is too short or the encoded
    /// payload is malformed.
    fn decode_hamt(input: &[u8], cursor: &mut usize) -> Result<Self, &'static str>;
}

fn read_fixed<const N: usize>(input: &[u8], cursor: &mut usize) -> Result<[u8; N], &'static str> {
    let end = cursor.checked_add(N).ok_or("HAMT codec cursor overflow")?;
    let bytes = input
        .get(*cursor..end)
        .ok_or("HAMT codec buffer too short")?;
    let mut raw = [0u8; N];
    raw.copy_from_slice(bytes);
    *cursor = end;
    Ok(raw)
}

fn read_len_prefixed<'a>(input: &'a [u8], cursor: &mut usize) -> Result<&'a [u8], &'static str> {
    let len = u32::from_le_bytes(read_fixed::<4>(input, cursor)?) as usize;
    let end = cursor
        .checked_add(len)
        .ok_or("HAMT codec cursor overflow")?;
    let bytes = input
        .get(*cursor..end)
        .ok_or("HAMT codec buffer too short")?;
    *cursor = end;
    Ok(bytes)
}

fn decode_node_header(
    buf: &[u8],
    datamap_start: usize,
) -> Result<(u32, u32, usize, usize), &'static str> {
    let mut cursor = datamap_start;
    let datamap = u32::from_le_bytes(
        read_fixed::<4>(buf, &mut cursor).map_err(|_| "Buffer too short for datamap")?,
    );
    let nodemap = u32::from_le_bytes(
        read_fixed::<4>(buf, &mut cursor).map_err(|_| "Buffer too short for nodemap")?,
    );
    if (datamap & nodemap) != 0 {
        return Err("Datamap and nodemap overlap: node is corrupt");
    }
    let leaf_count = u32::from_le_bytes(
        read_fixed::<4>(buf, &mut cursor).map_err(|_| "Buffer too short for leaf count")?,
    ) as usize;
    let child_count = u32::from_le_bytes(
        read_fixed::<4>(buf, &mut cursor).map_err(|_| "Buffer too short for child count")?,
    ) as usize;
    let expected_leaves = datamap.count_ones() as usize;
    let expected_children = nodemap.count_ones() as usize;
    if leaf_count != expected_leaves {
        return Err("Leaf count does not match datamap");
    }
    if child_count != expected_children {
        return Err("Child count does not match nodemap");
    }
    Ok((datamap, nodemap, leaf_count, child_count))
}

fn decode_leaves<K, V>(
    buf: &[u8],
    cursor: &mut usize,
    leaf_count: usize,
) -> Result<Vec<(K, V)>, &'static str>
where
    K: HamtCodec,
    V: HamtCodec,
{
    let mut leaves = Vec::with_capacity(leaf_count);
    for _ in 0..leaf_count {
        let key = K::decode_hamt(buf, cursor)?;
        let value = V::decode_hamt(buf, cursor)?;
        leaves.push((key, value));
    }
    Ok(leaves)
}

fn check_child_payload(
    buf: &[u8],
    cursor: usize,
    child_count: usize,
    width: usize,
) -> Result<(), &'static str> {
    let child_bytes = child_count
        .checked_mul(width)
        .ok_or("Child hash payload size overflows usize")?;
    let total_len = cursor
        .checked_add(child_bytes)
        .ok_or("Child hash payload size overflows usize")?;
    if buf.len() < total_len {
        return Err("Buffer too short for child hashes");
    }
    if buf.len() > total_len {
        return Err("Buffer contains trailing bytes");
    }
    Ok(())
}

macro_rules! impl_fixed_hamt_codec {
    ($($ty:ty),* $(,)?) => {
        $(
            impl HamtCodec for $ty {
                #[inline]
                fn encode_hamt(&self, out: &mut Vec<u8>) {
                    out.extend_from_slice(&self.to_le_bytes());
                }

                #[inline]
                fn decode_hamt(input: &[u8], cursor: &mut usize) -> Result<Self, &'static str> {
                    let width = core::mem::size_of::<$ty>();
                    let end = cursor
                        .checked_add(width)
                        .ok_or("HAMT codec cursor overflow")?;
                    let bytes = input
                        .get(*cursor..end)
                        .ok_or("HAMT codec buffer too short")?;
                    let mut raw = [0u8; core::mem::size_of::<$ty>()];
                    raw.copy_from_slice(bytes);
                    *cursor = end;
                    Ok(<$ty>::from_le_bytes(raw))
                }
            }
        )*
    };
}

impl_fixed_hamt_codec!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128);

impl HamtCodec for usize {
    #[inline]
    fn encode_hamt(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&(*self as u64).to_le_bytes());
    }

    #[inline]
    fn decode_hamt(input: &[u8], cursor: &mut usize) -> Result<Self, &'static str> {
        usize::try_from(u64::from_le_bytes(read_fixed::<8>(input, cursor)?))
            .map_err(|_| "HAMT codec usize out of range")
    }
}

impl HamtCodec for isize {
    #[inline]
    fn encode_hamt(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&(*self as i64).to_le_bytes());
    }

    #[inline]
    fn decode_hamt(input: &[u8], cursor: &mut usize) -> Result<Self, &'static str> {
        isize::try_from(i64::from_le_bytes(read_fixed::<8>(input, cursor)?))
            .map_err(|_| "HAMT codec isize out of range")
    }
}

impl HamtCodec for bool {
    #[inline]
    fn encode_hamt(&self, out: &mut Vec<u8>) {
        out.push(u8::from(*self));
    }

    #[inline]
    fn decode_hamt(input: &[u8], cursor: &mut usize) -> Result<Self, &'static str> {
        let end = cursor.checked_add(1).ok_or("HAMT codec cursor overflow")?;
        let byte = *input.get(*cursor).ok_or("HAMT codec buffer too short")?;
        *cursor = end;
        match byte {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err("HAMT codec invalid bool encoding"),
        }
    }
}

impl HamtCodec for String {
    fn encode_hamt(&self, out: &mut Vec<u8>) {
        let len = u32::try_from(self.len()).expect("string too long for HAMT codec");
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(self.as_bytes());
    }

    fn decode_hamt(input: &[u8], cursor: &mut usize) -> Result<Self, &'static str> {
        String::from_utf8(read_len_prefixed(input, cursor)?.to_vec())
            .map_err(|_| "HAMT codec invalid UTF-8")
    }
}

impl HamtCodec for Vec<u8> {
    fn encode_hamt(&self, out: &mut Vec<u8>) {
        let len = u32::try_from(self.len()).expect("byte vector too long for HAMT codec");
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(self);
    }

    fn decode_hamt(input: &[u8], cursor: &mut usize) -> Result<Self, &'static str> {
        Ok(read_len_prefixed(input, cursor)?.to_vec())
    }
}

impl<A: HamtCodec, B: HamtCodec> HamtCodec for (A, B) {
    fn encode_hamt(&self, out: &mut Vec<u8>) {
        self.0.encode_hamt(out);
        self.1.encode_hamt(out);
    }

    fn decode_hamt(input: &[u8], cursor: &mut usize) -> Result<Self, &'static str> {
        let a = A::decode_hamt(input, cursor)?;
        let b = B::decode_hamt(input, cursor)?;
        Ok((a, b))
    }
}

impl HamtCodec for crate::basespec::event_types::EventType {
    fn encode_hamt(&self, out: &mut Vec<u8>) {
        let bytes = self.as_str().as_bytes();
        let len = u32::try_from(bytes.len()).expect("string too long for HAMT codec");
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(bytes);
    }

    fn decode_hamt(input: &[u8], cursor: &mut usize) -> Result<Self, &'static str> {
        let s = String::decode_hamt(input, cursor)?;
        Ok(crate::basespec::event_types::EventType::from(s))
    }
}

/// A representation of an internal node that is safe to persist to disk.
///
/// Leaves are stored inline as `(K, V)` pairs in datamap order, while child
/// references are stored separately in nodemap order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistedInternalNode<K, V> {
    pub datamap: u32,
    pub nodemap: u32,
    pub leaves: Vec<(K, V)>,
    pub child_hashes: Vec<StructuralHash>,
}

impl<K, V> PersistedInternalNode<K, V>
where
    K: HamtCodec,
    V: HamtCodec,
{
    /// Encodes the canonical v1 representation shared by persistence and
    /// structural hashing. Keeping this in one place ensures a node's
    /// storage key commits to precisely the bytes stored under that key.
    pub(crate) fn encode_v1_parts(
        datamap: u32,
        nodemap: u32,
        leaves: &[(K, V)],
        child_hashes: &[StructuralHash],
    ) -> Vec<u8> {
        let leaf_slots = datamap.count_ones() as usize;
        let child_slots = nodemap.count_ones() as usize;
        assert_eq!(
            leaves.len(),
            leaf_slots,
            "leaf count must match datamap bits"
        );
        assert_eq!(
            child_hashes.len(),
            child_slots,
            "child count must match nodemap bits"
        );
        assert_eq!(datamap & nodemap, 0, "datamap and nodemap must not overlap");

        let mut body = Vec::new();
        for (key, value) in leaves {
            key.encode_hamt(&mut body);
            value.encode_hamt(&mut body);
        }
        for hash in child_hashes {
            body.extend_from_slice(hash);
        }

        let leaf_count = u32::try_from(leaves.len()).expect("too many leaves for v1 encoding");
        let child_count =
            u32::try_from(child_hashes.len()).expect("too many child hashes for v1 encoding");
        let capacity = 1_usize
            .checked_add(4)
            .and_then(|value| value.checked_add(4))
            .and_then(|value| value.checked_add(4))
            .and_then(|value| value.checked_add(4))
            .and_then(|value| value.checked_add(4))
            .and_then(|value| value.checked_add(body.len()))
            .expect("encoded node size overflows usize");

        let mut buf = Vec::with_capacity(capacity);
        buf.extend_from_slice(HAMT_NODE_MAGIC);
        buf.push(HAMT_WIRE_VERSION);
        buf.extend_from_slice(&datamap.to_le_bytes());
        buf.extend_from_slice(&nodemap.to_le_bytes());
        buf.extend_from_slice(&leaf_count.to_le_bytes());
        buf.extend_from_slice(&child_count.to_le_bytes());
        buf.extend_from_slice(&body);
        buf
    }

    /// Encodes the node to a dense binary format.
    ///
    /// Layout:
    /// - Magic (4 bytes): `MTHN`
    /// - Version (1 byte): `0x01`
    /// - Datamap (4 bytes, LE)
    /// - Nodemap (4 bytes, LE)
    /// - Leaf count (4 bytes, LE)
    /// - Child count (4 bytes, LE)
    /// - Inline leaves (`K`, `V` pairs in datamap order)
    /// - Child hashes (`32 * child_count` bytes in nodemap order)
    ///
    /// # Panics
    /// Panics if the payload lengths disagree with the bitmaps, if `datamap`
    /// and `nodemap` overlap, or if the payloads would overflow `usize`.
    #[must_use]
    pub fn encode_v1(&self) -> Vec<u8> {
        Self::encode_v1_parts(self.datamap, self.nodemap, &self.leaves, &self.child_hashes)
    }

    /// Decodes the node from a dense binary format.
    ///
    /// # Errors
    /// Returns an error when the version byte is invalid or the buffer is too
    /// short for the declared payload.
    pub fn decode_v1_unverified(buf: &[u8]) -> Result<Self, &'static str> {
        if buf.get(..HAMT_NODE_MAGIC.len()) != Some(HAMT_NODE_MAGIC.as_slice()) {
            return Err("Invalid HAMT node magic");
        }
        if !matches!(buf.get(4).copied(), Some(HAMT_WIRE_VERSION)) {
            return Err("Invalid version byte");
        }
        if buf.len() < 21 {
            return Err("Buffer too short for v1 header");
        }

        let (datamap, nodemap, leaf_count, child_count) = decode_node_header(buf, 5)?;

        let mut cursor = 21_usize;
        let leaves = decode_leaves(buf, &mut cursor, leaf_count)?;

        check_child_payload(
            buf,
            cursor,
            child_count,
            core::mem::size_of::<StructuralHash>(),
        )?;

        let mut child_hashes = Vec::with_capacity(child_count);
        for i in 0..child_count {
            let start = cursor
                .checked_add(
                    i.checked_mul(core::mem::size_of::<StructuralHash>())
                        .ok_or("Child hash index overflows usize")?,
                )
                .ok_or("Child hash index overflows usize")?;
            let end = start
                .checked_add(core::mem::size_of::<StructuralHash>())
                .ok_or("Child hash index overflows usize")?;
            let mut hash = [0u8; core::mem::size_of::<StructuralHash>()];
            hash.copy_from_slice(&buf[start..end]);
            child_hashes.push(hash);
        }

        Ok(Self {
            datamap,
            nodemap,
            leaves,
            child_hashes,
        })
    }

    /// Explicit, parse-only decoder for pre-record-kind records that carried
    /// 16-byte structural hashes.
    ///
    /// This method is never used by the current decoder and must only be
    /// called by a caller that has independently identified the input as a
    /// legacy record. It exists solely so legacy bytes can be inspected or
    /// migrated: the
    /// current layout cannot recover the storage key those records were
    /// written under (the key committed to the 16-byte representation), so a
    /// legacy node can never satisfy [`Self::into_hamt_node_verified`].
    /// Decoded child hashes hold their legacy 16 bytes left-aligned in the
    /// 32-byte [`StructuralHash`] array; the trailing half is zero.
    ///
    /// # Errors
    /// Returns an error when the buffer lacks the legacy marker or does not
    /// match the legacy layout.
    pub fn decode_v1_legacy_unverified(buf: &[u8]) -> Result<Self, &'static str> {
        const LEGACY_HASH_WIDTH: usize = 16;

        if !matches!(buf.first().copied(), Some(HAMT_WIRE_VERSION)) {
            return Err("Invalid version byte");
        }
        if buf.len() < 17 {
            return Err("Buffer too short for v1 header");
        }

        let (datamap, nodemap, leaf_count, child_count) = decode_node_header(buf, 1)?;

        let mut cursor = 17_usize;
        let leaves = decode_leaves(buf, &mut cursor, leaf_count)?;

        check_child_payload(buf, cursor, child_count, LEGACY_HASH_WIDTH)?;

        let mut child_hashes = Vec::with_capacity(child_count);
        for _ in 0..child_count {
            let end = cursor
                .checked_add(LEGACY_HASH_WIDTH)
                .ok_or("Child hash index overflows usize")?;
            let mut hash = [0u8; core::mem::size_of::<StructuralHash>()];
            hash[..LEGACY_HASH_WIDTH].copy_from_slice(&buf[cursor..end]);
            child_hashes.push(hash);
            cursor = end;
        }

        Ok(Self {
            datamap,
            nodemap,
            leaves,
            child_hashes,
        })
    }

    /// Validates this decoded node against the storage key that selected it.
    ///
    /// Persisted v1 nodes deliberately do not carry a duplicate structural
    /// hash. Callers must supply the hash used to fetch the bytes; this
    /// recomputes the node identity under `structural_key` and rejects a
    /// shape-valid node stored under the wrong key.
    ///
    /// # Errors
    /// Returns an error if the node's contents do not reproduce
    /// `expected_hash`.
    pub fn into_hamt_node_verified(
        self,
        structural_key: &[u8],
        expected_hash: StructuralHash,
    ) -> Result<crate::hamt::HamtNode<K, V>, &'static str>
    where
        K: Hash,
        V: Hash,
    {
        if (self.datamap & self.nodemap) != 0 {
            return Err("PersistedInternalNode datamap and nodemap overlap");
        }
        if self.leaves.len() != self.datamap.count_ones() as usize {
            return Err("PersistedInternalNode leaf count does not match datamap");
        }
        if self.child_hashes.len() != self.nodemap.count_ones() as usize {
            return Err("PersistedInternalNode child count does not match nodemap");
        }

        let children: Vec<_> = self
            .child_hashes
            .into_iter()
            .map(crate::hamt::NodeRef::Lazy)
            .collect();
        let recomputed = crate::hamt::HamtNode::compute_structural_hash(
            structural_key,
            self.datamap,
            self.nodemap,
            &self.leaves,
            &children,
        );
        if recomputed != expected_hash {
            return Err("persisted node contents do not match expected structural hash");
        }

        Ok(crate::hamt::HamtNode {
            datamap: self.datamap,
            nodemap: self.nodemap,
            leaves: self.leaves,
            children,
            structural_hash: expected_hash,
        })
    }

    /// Decodes a v1 node and verifies it against the storage key that selected
    /// the bytes.
    ///
    /// This is the normal cold-storage load path.
    /// [`Self::decode_v1_unverified`] is only the syntactic decoder for
    /// callers that need to inspect persisted data before choosing an expected
    /// hash.
    ///
    /// # Errors
    /// Returns an error when the bytes are malformed or their recomputed
    /// structural hash does not match `expected_hash`.
    pub fn decode_v1_verified(
        buf: &[u8],
        structural_key: &[u8],
        expected_hash: StructuralHash,
    ) -> Result<crate::hamt::HamtNode<K, V>, &'static str>
    where
        K: Hash,
        V: Hash,
    {
        Self::decode_v1_unverified(buf)?.into_hamt_node_verified(structural_key, expected_hash)
    }
}

impl<K: Clone, V: Clone> From<&crate::hamt::HamtNode<K, V>> for PersistedInternalNode<K, V> {
    fn from(node: &crate::hamt::HamtNode<K, V>) -> Self {
        let child_hashes = node
            .children
            .iter()
            .map(super::NodeRef::structural_hash)
            .collect();

        Self {
            datamap: node.datamap,
            nodemap: node.nodemap,
            leaves: node.leaves.clone(),
            child_hashes,
        }
    }
}
