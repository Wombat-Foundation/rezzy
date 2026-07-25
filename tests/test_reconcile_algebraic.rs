use base64::{
    engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD},
    Engine as _,
};
use rezzy::reconcile::{
    verify_residual, AlgebraicError, ElementHash, EventIdFormat, RoomAccumulator, SyndromeSketch,
    MAX_LOCAL_SKETCH_DECODE_CAPACITY, MAX_SKETCH_CAPACITY,
};

fn event_id(bytes: [u8; 32]) -> String {
    format!("${}", URL_SAFE_NO_PAD.encode(bytes))
}

#[test]
fn generic_digest32_feeds_all_resident_layers() {
    let first_bytes = core::array::from_fn(|index| u8::try_from(index).unwrap());
    let second_bytes = core::array::from_fn(|index| u8::try_from(255 - index).unwrap());
    let first = ElementHash::from_digest32(first_bytes);
    let second = ElementHash::from_digest32(second_bytes);

    assert_eq!(first.h128, 0x0001_0203_0405_0607_0809_0a0b_0c0d_0e0f);
    assert_eq!(first.h64, 0x0001_0203_0405_0607);
    assert_eq!(second.h128, 0xfffe_fdfc_fbfa_f9f8_f7f6_f5f4_f3f2_f1f0);
    assert_eq!(second.h64, 0xfffe_fdfc_fbfa_f9f8);

    let mut accumulator = RoomAccumulator::new();
    let mut sketch = SyndromeSketch::new(8).unwrap();
    for hash in [first, second] {
        accumulator.insert(hash).unwrap();
        sketch.toggle(hash.h64).unwrap();
    }

    assert_eq!(accumulator.known_event_count(), 2);
    assert!(verify_residual(accumulator.digest(), [first, second]));
    assert_eq!(SyndromeSketch::decode(8, &sketch.encode()).unwrap(), sketch);
}

#[test]
fn matrix_hash_derived_event_ids_use_decoded_digest32() {
    let bytes = core::array::from_fn(|index| u8::try_from(index).unwrap());
    let event_id = event_id(bytes);
    let hash = ElementHash::from_matrix_event_id(&event_id, EventIdFormat::V4Plus).unwrap();
    assert_eq!(hash, ElementHash::from_digest32(bytes));
}

#[test]
fn legacy_ids_are_sha3_256_derived_and_stable() {
    let first =
        ElementHash::from_matrix_event_id("$opaque:example.org", EventIdFormat::Legacy).unwrap();
    let second =
        ElementHash::from_matrix_event_id("$opaque:example.org", EventIdFormat::Legacy).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.h128, 0x87d1_a07d_c174_b89c_e6b0_2374_d7fb_b274);
    assert_eq!(first.h64, 0x87d1_a07d_c174_b89c);
}

#[test]
fn room_v3_event_ids_use_standard_base64() {
    let bytes = [0xfb_u8; 32];
    let event_id = format!("${}", STANDARD_NO_PAD.encode(bytes));
    assert!(event_id.contains('+') || event_id.contains('/'));
    let hash = ElementHash::from_matrix_event_id(&event_id, EventIdFormat::V3).unwrap();
    assert_eq!(hash.h128, u128::from_be_bytes([0xfb; 16]));
    assert_eq!(hash.h64, u64::from_be_bytes([0xfb; 8]));
    assert_eq!(
        ElementHash::from_matrix_event_id(&event_id, EventIdFormat::V4Plus),
        Err(AlgebraicError::InvalidBase64)
    );
}

#[test]
fn short_id_uses_the_first_nonzero_digest_chunk() {
    let mut second_chunk = [0_u8; 32];
    second_chunk[8..16].copy_from_slice(&42_u64.to_be_bytes());
    assert_eq!(
        ElementHash::from_matrix_event_id(&event_id(second_chunk), EventIdFormat::V4Plus)
            .unwrap()
            .h64,
        42
    );
    assert_eq!(
        ElementHash::from_matrix_event_id(&event_id([0; 32]), EventIdFormat::V4Plus)
            .unwrap()
            .h64,
        1
    );
}

#[test]
fn sketch_wire_format_matches_libminisketch_64_bit_serialization() {
    let mut sketch = SyndromeSketch::new(2).unwrap();
    sketch.toggle(1_u64 << 63).unwrap();
    sketch.toggle(u64::MAX).unwrap();

    let wire = URL_SAFE_NO_PAD.decode(sketch.encode()).unwrap();
    // Generated independently with minisketch's tests/pyminisketch.py GF(2^64) reference.
    assert_eq!(
        wire,
        [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0xfd, 0x32, 0x33, 0x33, 0x33, 0x33,
            0x33, 0x93,
        ]
    );
    assert_eq!(SyndromeSketch::decode(2, &sketch.encode()).unwrap(), sketch);
}

#[test]
fn pinsketch_decodes_a_symmetric_difference() {
    let mut local = SyndromeSketch::new(8).unwrap();
    let mut remote = SyndromeSketch::new(8).unwrap();
    for value in [1, 2, 3, 0xdead_beef, u64::MAX] {
        local.toggle(value).unwrap();
    }
    for value in [2, 3, 5, 8, 0x0123_4567_89ab_cdef] {
        remote.toggle(value).unwrap();
    }

    let residual = remote.subtract(&local).unwrap();
    assert_eq!(
        residual.decode_elements(6).unwrap(),
        [1, 5, 8, 0xdead_beef, 0x0123_4567_89ab_cdef, u64::MAX]
    );
}

#[test]
fn pinsketch_fails_loudly_above_the_decode_bound() {
    let mut sketch = SyndromeSketch::new(4).unwrap();
    for value in 1..=4 {
        sketch.toggle(value).unwrap();
    }
    assert_eq!(sketch.decode_elements(4).unwrap(), [1, 2, 3, 4]);
    assert!(sketch.decode_elements(3).is_err());
    assert!(SyndromeSketch::new(1).unwrap().toggle(0).is_err());
    assert_eq!(
        SyndromeSketch::new(MAX_LOCAL_SKETCH_DECODE_CAPACITY + 1),
        Err(AlgebraicError::InvalidSketchCapacity)
    );
    assert_eq!(
        SyndromeSketch::new(1).unwrap().decode_elements(0),
        Err(AlgebraicError::InvalidSketchCapacity)
    );
}

#[test]
fn algebraic_wire_and_capacity_errors_are_rejected() {
    assert_eq!(
        ElementHash::from_matrix_event_id("$AQ", EventIdFormat::V4Plus),
        Err(AlgebraicError::InvalidEventId)
    );
    let overlong_hash = format!("${}", URL_SAFE_NO_PAD.encode([0_u8; 33]));
    for format in [EventIdFormat::V3, EventIdFormat::V4Plus] {
        assert_eq!(
            ElementHash::from_matrix_event_id(&overlong_hash, format),
            Err(AlgebraicError::InvalidBase64)
        );
    }
    assert_eq!(
        ElementHash::from_matrix_event_id("not-an-event-id", EventIdFormat::V4Plus),
        Err(AlgebraicError::InvalidEventId)
    );
    assert_eq!(
        ElementHash::from_matrix_event_id("$not base64", EventIdFormat::V4Plus),
        Err(AlgebraicError::InvalidBase64)
    );
    assert_eq!(
        RoomAccumulator::decode_digest("!!!!!!!!!!!!!!!!!!!!!!"),
        Err(AlgebraicError::InvalidBase64)
    );
    assert_eq!(
        RoomAccumulator::decode_digest(&URL_SAFE_NO_PAD.encode([0_u8; 15])),
        Err(AlgebraicError::InvalidDigestLength)
    );
    assert_eq!(
        RoomAccumulator::decode_digest(&"A".repeat(23)),
        Err(AlgebraicError::InvalidDigestLength)
    );

    assert_eq!(
        SyndromeSketch::new(0),
        Err(AlgebraicError::InvalidSketchCapacity)
    );
    assert_eq!(
        SyndromeSketch::new(MAX_SKETCH_CAPACITY + 1),
        Err(AlgebraicError::InvalidSketchCapacity)
    );
    let sketch = SyndromeSketch::new(2).unwrap();
    assert_eq!(sketch.coordinates(), [0, 0]);
    assert_eq!(
        sketch.decode_elements(3),
        Err(AlgebraicError::InvalidSketchCapacity)
    );
    assert_eq!(
        sketch.subtract(&SyndromeSketch::new(1).unwrap()),
        Err(AlgebraicError::InvalidSketchLength)
    );
    assert_eq!(
        SyndromeSketch::decode(2, "!!!!!!!!!!!!!!!!!!!!!!"),
        Err(AlgebraicError::InvalidBase64)
    );
    assert_eq!(
        SyndromeSketch::decode(2, &URL_SAFE_NO_PAD.encode([0_u8; 8])),
        Err(AlgebraicError::InvalidSketchLength)
    );
    assert_eq!(
        SyndromeSketch::decode(2, &"A".repeat(23)),
        Err(AlgebraicError::InvalidSketchLength)
    );
}

#[test]
fn accumulator_residual_is_the_digest_xor() {
    let first =
        ElementHash::from_matrix_event_id(&event_id([0x12; 32]), EventIdFormat::V4Plus).unwrap();
    let second =
        ElementHash::from_matrix_event_id(&event_id([0x34; 32]), EventIdFormat::V4Plus).unwrap();
    let mut left = RoomAccumulator::new();
    let mut right = RoomAccumulator::new();
    left.insert(first).unwrap();
    right.insert(second).unwrap();
    assert_eq!(left.residual(right), first.h128 ^ second.h128);
}
