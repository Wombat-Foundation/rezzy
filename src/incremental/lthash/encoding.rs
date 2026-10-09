//! BLAKE3 expansion and seed encodings for [`LtLattice`](super::LtLattice).

/// Adapter that lets `core::fmt::Display` values be streamed into a BLAKE3 hasher.
pub(super) struct HashWriter<'a> {
    pub(super) hasher: &'a mut blake3::Hasher,
}

impl core::fmt::Write for HashWriter<'_> {
    #[inline]
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.hasher.update(s.as_bytes());
        Ok(())
    }
}

/// Truncate a string to fit within a `u16` length prefix (65535 bytes).
///
/// Valid Matrix events are capped at 64KiB total, so real event types and state keys
/// can never reach this limit. Truncation only applies to malformed/adversarial input.
#[inline]
pub(crate) fn truncate_to_u16_limit(s: &str) -> (&str, u16) {
    let limit = usize::from(u16::MAX);
    let s_len = s.len();
    if s_len > limit {
        let mut end = limit;
        while !s.is_char_boundary(end) {
            end = end.saturating_sub(1);
        }
        (&s[..end], u16::try_from(end).unwrap())
    } else {
        (s, u16::try_from(s_len).unwrap())
    }
}

/// Squeezes `LANES * 2` bytes out of a fresh BLAKE3 hasher and unpacks them into
/// little-endian 16-bit lanes.
///
/// Lanes are unpacked in 128-lane (256-byte) windows so each [`blake3::OutputReader::fill`]
/// call is a whole number of 64-byte blocks; the scratch buffer is fixed-size so no
/// heap allocation happens on the hot insert path regardless of `LANES`.
#[must_use]
pub(crate) fn expand_lanes<const LANES: usize>(
    feed: impl FnOnce(&mut blake3::Hasher),
) -> [u16; LANES] {
    let mut hasher = blake3::Hasher::new();
    feed(&mut hasher);

    let mut reader = hasher.finalize_xof();
    let mut out = [0u16; LANES];
    let mut scratch = [0u8; 256];
    for chunk in out.chunks_mut(128) {
        let n = chunk.len().wrapping_mul(2);
        reader.fill(&mut scratch[..n]);
        for (lane, pair) in chunk.iter_mut().zip(scratch[..n].chunks_exact(2)) {
            *lane = u16::from_le_bytes([pair[0], pair[1]]);
        }
    }
    out
}

/// Computes the lane expansion for a single state entry under the given
/// domain-separation tag.
///
/// Input encoding: `len(type) || type || len(state_key) || state_key || event_id`
/// where each `len()` is an unsigned 16-bit little-endian byte count.
#[must_use]
pub(crate) fn seed_lattice<const LANES: usize>(
    dst: &[u8],
    event_type: &str,
    state_key: &str,
    event_id: &dyn core::fmt::Display,
) -> [u16; LANES] {
    let (event_type, type_len) = truncate_to_u16_limit(event_type);
    let (state_key, sk_len) = truncate_to_u16_limit(state_key);

    expand_lanes(|hasher| {
        hasher.update(dst);
        hasher.update(&type_len.to_le_bytes());
        hasher.update(event_type.as_bytes());
        hasher.update(&sk_len.to_le_bytes());
        hasher.update(state_key.as_bytes());

        // `HashWriter::write_str` only forwards to `Hasher::update`, so the
        // formatting result can never be an error.
        let mut writer = HashWriter { hasher };
        let _ = core::fmt::write(&mut writer, format_args!("{event_id}"));
    })
}

/// Expands an opaque byte string under `dst`: `dst || bytes`.
///
/// Unlike the field and state-entry encodings this one carries no length prefix, so the
/// caller must supply a byte string that cannot be confused with a neighboring element
/// by an alternate split (for example by hashing a framed length itself).
#[must_use]
pub(crate) fn seed_bytes_lattice<const LANES: usize>(dst: &[u8], bytes: &[u8]) -> [u16; LANES] {
    expand_lanes(|hasher| {
        hasher.update(dst);
        hasher.update(bytes);
    })
}

/// Expands one key-value field under `dst`:
/// `dst || len(key) || key || len(val) || val`.
///
/// Both lengths are unsigned 16-bit little-endian byte counts and both halves are
/// truncated to that limit exactly like a state entry.
#[must_use]
pub(crate) fn seed_field_lattice<const LANES: usize>(
    dst: &[u8],
    key: &str,
    val: &str,
) -> [u16; LANES] {
    let (key, key_len) = truncate_to_u16_limit(key);
    let (val, val_len) = truncate_to_u16_limit(val);

    expand_lanes(|hasher| {
        hasher.update(dst);
        hasher.update(&key_len.to_le_bytes());
        hasher.update(key.as_bytes());
        hasher.update(&val_len.to_le_bytes());
        hasher.update(val.as_bytes());
    })
}

/// Adds `src` into `dst` lane-wise with wrapping addition.
///
/// Processed in 8-lane chunks to assist SIMD auto-vectorization; any leftover lanes
/// (only reachable for a `LANES` that is not a multiple of 8) are handled scalar-wise.
#[inline]
pub(crate) fn add_lattice<const LANES: usize>(dst: &mut [u16; LANES], src: &[u16; LANES]) {
    let mut dst_chunks = dst.chunks_exact_mut(8);
    let mut src_chunks = src.chunks_exact(8);
    for (a, b) in (&mut dst_chunks).zip(&mut src_chunks) {
        a[0] = a[0].wrapping_add(b[0]);
        a[1] = a[1].wrapping_add(b[1]);
        a[2] = a[2].wrapping_add(b[2]);
        a[3] = a[3].wrapping_add(b[3]);
        a[4] = a[4].wrapping_add(b[4]);
        a[5] = a[5].wrapping_add(b[5]);
        a[6] = a[6].wrapping_add(b[6]);
        a[7] = a[7].wrapping_add(b[7]);
    }
    for (a, b) in dst_chunks
        .into_remainder()
        .iter_mut()
        .zip(src_chunks.remainder())
    {
        *a = a.wrapping_add(*b);
    }
}

/// Subtracts `src` from `dst` lane-wise with wrapping subtraction.
///
/// Processed in 8-lane chunks to assist SIMD auto-vectorization; see [`add_lattice`].
#[inline]
pub(crate) fn sub_lattice<const LANES: usize>(dst: &mut [u16; LANES], src: &[u16; LANES]) {
    let mut dst_chunks = dst.chunks_exact_mut(8);
    let mut src_chunks = src.chunks_exact(8);
    for (a, b) in (&mut dst_chunks).zip(&mut src_chunks) {
        a[0] = a[0].wrapping_sub(b[0]);
        a[1] = a[1].wrapping_sub(b[1]);
        a[2] = a[2].wrapping_sub(b[2]);
        a[3] = a[3].wrapping_sub(b[3]);
        a[4] = a[4].wrapping_sub(b[4]);
        a[5] = a[5].wrapping_sub(b[5]);
        a[6] = a[6].wrapping_sub(b[6]);
        a[7] = a[7].wrapping_sub(b[7]);
    }
    for (a, b) in dst_chunks
        .into_remainder()
        .iter_mut()
        .zip(src_chunks.remainder())
    {
        *a = a.wrapping_sub(*b);
    }
}

/// Collapses a lattice into its 32-byte wire digest: `BLAKE3(S)`, where `S` is the
/// little-endian serialization of the `LANES` 16-bit values.
#[must_use]
pub(crate) fn lattice_digest<const LANES: usize>(lattice: &[u16; LANES]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    let mut scratch = [0u8; 256];
    for chunk in lattice.chunks(128) {
        let n = chunk.len().wrapping_mul(2);
        for (pair, lane) in scratch[..n].chunks_exact_mut(2).zip(chunk) {
            pair.copy_from_slice(&lane.to_le_bytes());
        }
        hasher.update(&scratch[..n]);
    }
    *hasher.finalize().as_bytes()
}
