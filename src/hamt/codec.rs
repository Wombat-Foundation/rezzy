//! Dense binary serialization and deserialization for persisted HAMT nodes.

use alloc::{string::String, vec::Vec};
use core::convert::TryFrom;

use super::hash::StructuralHash;

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
        let end = cursor.checked_add(8).ok_or("HAMT codec cursor overflow")?;
        let bytes = input
            .get(*cursor..end)
            .ok_or("HAMT codec buffer too short")?;
        let mut raw = [0u8; 8];
        raw.copy_from_slice(bytes);
        *cursor = end;
        usize::try_from(u64::from_le_bytes(raw)).map_err(|_| "HAMT codec usize out of range")
    }
}

impl HamtCodec for isize {
    #[inline]
    fn encode_hamt(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&(*self as i64).to_le_bytes());
    }

    #[inline]
    fn decode_hamt(input: &[u8], cursor: &mut usize) -> Result<Self, &'static str> {
        let end = cursor.checked_add(8).ok_or("HAMT codec cursor overflow")?;
        let bytes = input
            .get(*cursor..end)
            .ok_or("HAMT codec buffer too short")?;
        let mut raw = [0u8; 8];
        raw.copy_from_slice(bytes);
        *cursor = end;
        isize::try_from(i64::from_le_bytes(raw)).map_err(|_| "HAMT codec isize out of range")
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
        let len_end = cursor.checked_add(4).ok_or("HAMT codec cursor overflow")?;
        let len_bytes = input
            .get(*cursor..len_end)
            .ok_or("HAMT codec buffer too short")?;
        let mut raw = [0u8; 4];
        raw.copy_from_slice(len_bytes);
        *cursor = len_end;

        let len = u32::from_le_bytes(raw) as usize;
        let end = cursor
            .checked_add(len)
            .ok_or("HAMT codec cursor overflow")?;
        let bytes = input
            .get(*cursor..end)
            .ok_or("HAMT codec buffer too short")?;
        *cursor = end;
        String::from_utf8(bytes.to_vec()).map_err(|_| "HAMT codec invalid UTF-8")
    }
}

impl HamtCodec for Vec<u8> {
    fn encode_hamt(&self, out: &mut Vec<u8>) {
        let len = u32::try_from(self.len()).expect("byte vector too long for HAMT codec");
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(self);
    }

    fn decode_hamt(input: &[u8], cursor: &mut usize) -> Result<Self, &'static str> {
        let len_end = cursor.checked_add(4).ok_or("HAMT codec cursor overflow")?;
        let len_bytes = input
            .get(*cursor..len_end)
            .ok_or("HAMT codec buffer too short")?;
        let mut raw = [0u8; 4];
        raw.copy_from_slice(len_bytes);
        *cursor = len_end;

        let len = u32::from_le_bytes(raw) as usize;
        let end = cursor
            .checked_add(len)
            .ok_or("HAMT codec cursor overflow")?;
        let bytes = input
            .get(*cursor..end)
            .ok_or("HAMT codec buffer too short")?;
        *cursor = end;
        Ok(bytes.to_vec())
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
    pub structural_hash: StructuralHash,
    pub leaves: Vec<(K, V)>,
    pub child_hashes: Vec<StructuralHash>,
}

impl<K, V> PersistedInternalNode<K, V>
where
    K: HamtCodec,
    V: HamtCodec,
{
    /// Encodes the node to a dense binary format.
    ///
    /// Layout:
    /// - Version (1 byte): `0x01`
    /// - Datamap (4 bytes, LE)
    /// - Nodemap (4 bytes, LE)
    /// - Structural hash (16 bytes)
    /// - Leaf count (4 bytes, LE)
    /// - Child count (4 bytes, LE)
    /// - Inline leaves (`K`, `V` pairs in datamap order)
    /// - Child hashes (`16 * child_count` bytes in nodemap order)
    ///
    /// # Panics
    /// Panics if the payload lengths disagree with the bitmaps, if `datamap`
    /// and `nodemap` overlap, or if the payloads would overflow `usize`.
    #[must_use]
    pub fn encode_v1(&self) -> Vec<u8> {
        let leaf_slots = self.datamap.count_ones() as usize;
        let child_slots = self.nodemap.count_ones() as usize;
        assert_eq!(
            self.leaves.len(),
            leaf_slots,
            "leaf count must match datamap bits"
        );
        assert_eq!(
            self.child_hashes.len(),
            child_slots,
            "child count must match nodemap bits"
        );
        assert_eq!(
            self.datamap & self.nodemap,
            0,
            "datamap and nodemap must not overlap"
        );

        let mut body = Vec::new();
        for (key, value) in &self.leaves {
            key.encode_hamt(&mut body);
            value.encode_hamt(&mut body);
        }
        for hash in &self.child_hashes {
            body.extend_from_slice(hash);
        }

        let leaf_count = u32::try_from(self.leaves.len()).expect("too many leaves for v1 encoding");
        let child_count =
            u32::try_from(self.child_hashes.len()).expect("too many child hashes for v1 encoding");
        let capacity = 1_usize
            .checked_add(4)
            .and_then(|value| value.checked_add(4))
            .and_then(|value| value.checked_add(16))
            .and_then(|value| value.checked_add(4))
            .and_then(|value| value.checked_add(4))
            .and_then(|value| value.checked_add(body.len()))
            .expect("encoded node size overflows usize");

        let mut buf = Vec::with_capacity(capacity);
        buf.push(0x01);
        buf.extend_from_slice(&self.datamap.to_le_bytes());
        buf.extend_from_slice(&self.nodemap.to_le_bytes());
        buf.extend_from_slice(&self.structural_hash);
        buf.extend_from_slice(&leaf_count.to_le_bytes());
        buf.extend_from_slice(&child_count.to_le_bytes());
        buf.extend_from_slice(&body);
        buf
    }

    /// Decodes the node from a dense binary format.
    ///
    /// # Errors
    /// Returns an error when the version byte is invalid or the buffer is too
    /// short for the declared payload.
    pub fn decode_v1(buf: &[u8]) -> Result<Self, &'static str> {
        if buf.is_empty() || buf[0] != 0x01 {
            return Err("Invalid version byte");
        }
        if buf.len() < 33 {
            return Err("Buffer too short for v1 header");
        }

        let datamap = u32::from_le_bytes(
            buf.get(1..5)
                .ok_or("Buffer too short for datamap")?
                .try_into()
                .map_err(|_| "Buffer too short for datamap")?,
        );
        let nodemap = u32::from_le_bytes(
            buf.get(5..9)
                .ok_or("Buffer too short for nodemap")?
                .try_into()
                .map_err(|_| "Buffer too short for nodemap")?,
        );

        if (datamap & nodemap) != 0 {
            return Err("Datamap and nodemap overlap: node is corrupt");
        }

        let mut structural_hash = [0u8; 16];
        structural_hash.copy_from_slice(&buf[9..25]);

        let leaf_count = u32::from_le_bytes(
            buf.get(25..29)
                .ok_or("Buffer too short for leaf count")?
                .try_into()
                .map_err(|_| "Buffer too short for leaf count")?,
        ) as usize;
        let child_count = u32::from_le_bytes(
            buf.get(29..33)
                .ok_or("Buffer too short for child count")?
                .try_into()
                .map_err(|_| "Buffer too short for child count")?,
        ) as usize;

        let expected_leaves = datamap.count_ones() as usize;
        let expected_children = nodemap.count_ones() as usize;
        if leaf_count != expected_leaves {
            return Err("Leaf count does not match datamap");
        }
        if child_count != expected_children {
            return Err("Child count does not match nodemap");
        }

        let mut cursor = 33_usize;
        let mut leaves = Vec::with_capacity(leaf_count);
        for _ in 0..leaf_count {
            let key = K::decode_hamt(buf, &mut cursor)?;
            let value = V::decode_hamt(buf, &mut cursor)?;
            leaves.push((key, value));
        }

        let child_bytes = child_count
            .checked_mul(16)
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

        let mut child_hashes = Vec::with_capacity(child_count);
        for i in 0..child_count {
            let start = cursor
                .checked_add(
                    i.checked_mul(16)
                        .ok_or("Child hash index overflows usize")?,
                )
                .ok_or("Child hash index overflows usize")?;
            let end = start
                .checked_add(16)
                .ok_or("Child hash index overflows usize")?;
            let mut hash = [0u8; 16];
            hash.copy_from_slice(&buf[start..end]);
            child_hashes.push(hash);
        }

        Ok(Self {
            datamap,
            nodemap,
            structural_hash,
            leaves,
            child_hashes,
        })
    }
}

impl<K, V> core::convert::TryFrom<PersistedInternalNode<K, V>> for crate::hamt::HamtNode<K, V> {
    type Error = &'static str;

    fn try_from(persisted: PersistedInternalNode<K, V>) -> Result<Self, Self::Error> {
        let expected_children = persisted.nodemap.count_ones() as usize;
        if persisted.child_hashes.len() != expected_children {
            return Err("PersistedInternalNode child count does not match nodemap");
        }

        let expected_leaves = persisted.datamap.count_ones() as usize;
        if persisted.leaves.len() != expected_leaves {
            return Err("PersistedInternalNode leaf count does not match datamap");
        }

        let children = persisted
            .child_hashes
            .into_iter()
            .map(crate::hamt::NodeRef::Lazy)
            .collect();

        Ok(crate::hamt::HamtNode {
            datamap: persisted.datamap,
            nodemap: persisted.nodemap,
            leaves: persisted.leaves,
            children,
            structural_hash: persisted.structural_hash,
        })
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
            structural_hash: node.structural_hash,
            leaves: node.leaves.clone(),
            child_hashes,
        }
    }
}
