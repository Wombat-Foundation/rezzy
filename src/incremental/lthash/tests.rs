use core::iter::Sum;
use std::vec::Vec;

use super::*;

#[test]
fn test_lthash_order_independence() {
    // Insert in different orders, same result
    let mut h1 = LtHash::ZERO;
    h1.insert("m.room.create", "", "$c");
    h1.insert("m.room.member", "@a:x", "$m");

    let mut h2 = LtHash::ZERO;
    h2.insert("m.room.member", "@a:x", "$m");
    h2.insert("m.room.create", "", "$c");

    assert_eq!(h1, h2);
}

#[test]
fn test_lthash_insert_remove_roundtrip() {
    let mut h = LtHash::ZERO;
    h.insert("m.room.topic", "", "$t");
    assert_ne!(h, LtHash::ZERO);
    h.remove("m.room.topic", "", "$t");
    assert_eq!(h, LtHash::ZERO);
}

#[test]
fn test_lthash_replace() {
    // Build state with $t1, then replace → $t2
    let mut h = LtHash::ZERO;
    h.insert("m.room.create", "", "$c");
    h.insert("m.room.topic", "", "$t1");
    h.replace("m.room.topic", "", "$t1", "$t2");

    // Build state with $t2 from scratch
    let mut expected = LtHash::ZERO;
    expected.insert("m.room.create", "", "$c");
    expected.insert("m.room.topic", "", "$t2");

    assert_eq!(h, expected);
}

#[test]
fn test_lthash_replace_checked_success() {
    let mut actual = LtHash::ZERO;
    actual.insert("m.room.topic", "", "$old");
    actual.replace_checked("m.room.topic", "", "$old", "m.room.topic", "", "$new");

    let mut expected = LtHash::ZERO;
    expected.insert("m.room.topic", "", "$new");
    assert_eq!(actual, expected);
}

#[test]
fn test_lthash_mismatched_state_key_replace_panics() {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut h = LtHash::ZERO;
        h.replace_checked(
            "m.room.member",
            "@alice:example.com",
            "$old",
            "m.room.member",
            "@bob:example.com",
            "$new",
        );
    }));

    assert!(result.is_err(), "mismatched replacement key should panic");
}

#[test]
#[should_panic(expected = "mismatched replacement key")]
fn test_lthash_mismatched_event_type_replace_panics() {
    let mut h = LtHash::ZERO;
    h.replace_checked(
        "m.room.member",
        "@alice:example.com",
        "$old",
        "m.room.power_levels",
        "@alice:example.com",
        "$new",
    );
}

#[test]
fn test_lthash_wrapping_algebraic_properties() {
    let seed = LtHash::seed("m.room.message", "", &"$1");

    // 2^16 = 65536 additions of the same seed to ZERO
    let mut h = LtHash::ZERO;
    for _ in 0..65536 {
        h.add_seed(&seed);
    }
    assert_eq!(
        h,
        LtHash::ZERO,
        "65536 additions of any seed should wrap to ZERO"
    );

    // 2^16 - 1 = 65535 subtractions from ZERO should equal exactly 1 addition
    let mut h_sub = LtHash::ZERO;
    for _ in 0..65535 {
        h_sub.sub_seed(&seed);
    }
    let mut h_add = LtHash::ZERO;
    h_add.add_seed(&seed);
    assert_eq!(
        h_sub, h_add,
        "65535 subtractions from ZERO should equal 1 addition"
    );
}

#[test]
fn test_lthash_algebraic_traits_match_seed_api() {
    let a = LtHash::seed("m.room.create", "", &"$c");
    let b = LtHash::seed("m.room.member", "@a:x", &"$m");

    let mut manual = LtHash::ZERO;
    manual.add_seed(&a);
    manual.add_seed(&b);
    assert_eq!(a + b, manual);

    let mut manual_sub = manual;
    manual_sub.sub_seed(&b);
    assert_eq!(manual - b, manual_sub);

    let mut manual_assign = LtHash::ZERO;
    manual_assign += a;
    manual_assign += b;
    assert_eq!(manual_assign, manual);

    manual_assign -= a;
    manual_assign -= b;
    assert_eq!(manual_assign, LtHash::ZERO);

    // Subtraction is the additive inverse: (a + b) - b == a.
    assert_eq!(manual - b + b, manual);

    assert_eq!(<LtHash as Sum>::sum([a, b, a].into_iter()), a + a + b);
    assert_eq!(
        <LtHash as Sum<&LtHash>>::sum([&a, &b, &a].into_iter()),
        <LtHash as Sum>::sum([a, a, b].into_iter())
    );
}

#[test]
fn test_lthash_batch_parity() {
    let rows = [
        ("m.room.create", "", "$c"),
        ("m.room.member", "@a:x", "$m"),
        ("m.room.topic", "", "$t"),
    ];

    let mut batched = LtHash::ZERO;
    batched.insert_batch(rows);

    let mut one_by_one = LtHash::ZERO;
    for row in rows {
        one_by_one.insert(row.0, row.1, row.2);
    }
    assert_eq!(batched, one_by_one);

    batched.remove_batch(rows);
    assert_eq!(batched, LtHash::ZERO);

    let collected: LtHash = rows.into_iter().collect();
    assert_eq!(collected, one_by_one);

    let mut extended = LtHash::ZERO;
    extended.extend(rows);
    assert_eq!(extended, collected);

    // A different domain tag is a different element, so a from-scratch
    // accumulator built under the tag must agree with the tagged batch.
    let custom = b"rezzy:test:tagged";
    let mut tagged = LtHash::ZERO;
    tagged.insert_batch_with_dst(custom, rows);
    let mut tagged_one_by_one = LtHash::ZERO;
    for row in rows {
        tagged_one_by_one.add_seed(&LtHash::seed_with_dst(custom, row.0, row.1, &row.2));
    }
    assert_eq!(tagged, tagged_one_by_one);
    assert_ne!(tagged, one_by_one);

    // Removal is the additive inverse, so undoing the tagged batch lands
    // back on the identity, and removing without a prior insert yields the
    // negated seeds rather than the identity.
    tagged.remove_batch_with_dst(custom, rows);
    assert_eq!(tagged, LtHash::ZERO);

    let mut untagged = LtHash::ZERO;
    untagged.remove_batch_with_dst(custom, rows);
    assert_ne!(untagged, LtHash::ZERO);
    let mut restored = untagged;
    restored.insert_batch_with_dst(custom, rows);
    assert_eq!(restored, LtHash::ZERO);
}

#[test]
fn test_lthash_raw_bytes_and_field_roundtrips() {
    let mut h = LtHash::ZERO;
    h.insert_bytes(b"rezzy:test:bytes", b"payload");
    assert_ne!(h, LtHash::ZERO);
    h.remove_bytes(b"rezzy:test:bytes", b"payload");
    assert_eq!(h, LtHash::ZERO);

    let mut f = LtHash::ZERO;
    f.insert_field(b"rezzy:test:field", "sender", "@alice:example.org");
    assert_ne!(f, LtHash::ZERO);
    f.replace_field(
        b"rezzy:test:field",
        "sender",
        "@alice:example.org",
        "@bob:example.org",
    );
    f.remove_field(b"rezzy:test:field", "sender", "@bob:example.org");
    assert_eq!(f, LtHash::ZERO);

    // A field encoding is length-delimited, so `ab`+`c` must not collide
    // with `a`+`bc`.
    let mut split_one = LtHash::ZERO;
    split_one.insert_field(b"rezzy:test:field", "ab", "c");
    let mut split_two = LtHash::ZERO;
    split_two.insert_field(b"rezzy:test:field", "a", "bc");
    assert_ne!(split_one, split_two);

    // ... and the domain tag is part of the element identity, so the same
    // field under a different tag is a different element.
    let under_other_tag = LtHash::seed_field(b"rezzy:test:other", "sender", "@alice:example.org");
    let under_field_tag = LtHash::seed_field(b"rezzy:test:field", "sender", "@alice:example.org");
    assert_ne!(under_other_tag, under_field_tag);

    let mut r = LtHash::ZERO;
    r.insert_bytes(b"rezzy:test:bytes", b"old");
    r.replace_bytes(b"rezzy:test:bytes", b"old", b"new");
    r.remove_bytes(b"rezzy:test:bytes", b"new");
    assert_eq!(r, LtHash::ZERO);
}

#[test]
fn test_lthash_tri_mode_output_agrees() {
    let mut h = LtHash::ZERO;
    h.insert("m.room.create", "", "$c");
    h.insert("m.room.member", "@a:x", "$m");

    assert_eq!(*h.lattice(), h.into_lattice());
    assert_eq!(h.finalize_both().0, h.into_lattice());
    assert_eq!(h.finalize_both().1, h.digest());
    assert_eq!(h.to_bytes().len(), 2048);
    assert_eq!(
        h.to_bytes(),
        h.into_lattice()
            .iter()
            .flat_map(|lane| lane.to_le_bytes())
            .collect::<Vec<u8>>()
    );
}

#[test]
fn test_bytes_roundtrip() {
    let mut h = LtHash::ZERO;
    h.insert("m.room.create", "", "$c");

    let bytes = h.to_bytes();
    assert_eq!(LtHash::from_bytes(&bytes), Some(h));
    assert_eq!(LtHash::try_from(bytes.as_slice()), Ok(h));

    // Every constructor spelling agrees, including the ones that work through the
    // `LtHash` alias rather than naming `LtLattice<1024>`.
    let lanes = h.into_lattice();
    assert_eq!(LtHash::from_lanes(lanes), h);
    assert_eq!(LtHash::from(lanes), h);
    assert_eq!(<[u16; 1024]>::from(h), lanes);
    assert_eq!(h.as_ref(), lanes.as_slice());

    // A wrong-width buffer is rejected, never zero-padded or truncated.
    assert_eq!(LtHash::from_bytes(&bytes[..2046]), None);
    assert_eq!(
        LtHash::try_from(&bytes[..2046]),
        Err(WrongLatticeLength {
            expected: 2048,
            found: 2046
        })
    );
    assert_eq!(LtHash::from_bytes(&[]), None);
    assert!(LtLattice::<8>::from_bytes(&[0u8; 16]).is_some());
    assert_eq!(LtLattice::<8>::from_bytes(&[0u8; 18]), None);
}

#[test]
fn test_lthash_non_default_lane_counts_work() {
    // Exercises the generic paths with lane counts that are and are not a
    // multiple of 8 (so the scalar remainder loop runs) and with the default.
    fn roundtrip<const LANES: usize>() {
        let mut h = LtLattice::<LANES>::ZERO;
        h.insert("m.room.create", "", "$c");
        h.insert("m.room.member", "@a:x", "$m");
        assert_ne!(h, LtLattice::<LANES>::ZERO);

        let digest = h.digest();
        assert_eq!(h.finalize_both(), (h.into_lattice(), digest));
        assert_eq!(h.to_bytes().len(), LANES.wrapping_mul(2));

        h.remove("m.room.create", "", "$c");
        h.remove("m.room.member", "@a:x", "$m");
        assert_eq!(h, LtLattice::<LANES>::ZERO);
        assert_ne!(h.digest(), digest);
    }

    roundtrip::<2>();
    roundtrip::<7>();
    roundtrip::<8>();
    roundtrip::<9>();
    roundtrip::<1024>();

    // A wider lattice gives a wider accumulator and an independent digest.
    let narrow = LtLattice::<8>::seed("m.room.create", "", &"$c");
    let wide = LtHash::seed("m.room.create", "", &"$c");
    assert_ne!(narrow.digest(), wide.digest());
    assert_ne!(narrow.to_bytes().len(), wide.to_bytes().len());
}

#[test]
fn test_lthash_boundary_validation() {
    // EXACT boundary of u16::MAX (65535 bytes) should work
    let max_event_type = "a".repeat(65535);
    let _seed_max = LtHash::seed(&max_event_type, "", &"$1");

    let max_state_key = "b".repeat(65535);
    let _seed_max_sk = LtHash::seed("", &max_state_key, &"$1");
}

#[test]
fn test_lthash_boundary_exceeded_event_type_truncates() {
    let over_max = "a".repeat(65536);
    let seed_over = LtHash::seed(&over_max, "", &"$1");
    let seed_exact = LtHash::seed(&"a".repeat(65535), "", &"$1");
    assert_eq!(
        seed_over, seed_exact,
        "over_max should truncate to exact 65535 boundary"
    );
}

#[test]
fn test_lthash_boundary_exceeded_state_key_truncates() {
    let over_max = "b".repeat(65536);
    let seed_over = LtHash::seed("", &over_max, &"$1");
    let seed_exact = LtHash::seed("", &"b".repeat(65535), &"$1");
    assert_eq!(
        seed_over, seed_exact,
        "over_max should truncate to exact 65535 boundary"
    );
}

#[test]
fn test_lthash_boundary_multibyte_truncation_rounds_back_to_char_boundary() {
    // Force the truncation point to land inside a 4-byte UTF-8 character so
    // the loop has to back up more than once before it reaches a boundary.
    let over_max = std::format!("{}🚀", "a".repeat(65533));
    let seed_over = LtHash::seed(&over_max, "", &"$1");
    let seed_exact = LtHash::seed(&"a".repeat(65533), "", &"$1");
    assert_eq!(
        seed_over, seed_exact,
        "truncate_to_u16_limit should back up to the previous char boundary"
    );
}

#[test]
fn test_lthash_field_boundary_truncates() {
    let over_max = "k".repeat(65536);
    assert_eq!(
        LtHash::seed_field(b"rezzy:test:f", &over_max, "v"),
        LtHash::seed_field(b"rezzy:test:f", &"k".repeat(65535), "v"),
    );
    assert_eq!(
        LtHash::seed_field(b"rezzy:test:f", "k", &over_max),
        LtHash::seed_field(b"rezzy:test:f", "k", &"k".repeat(65535)),
    );
}

#[test]
fn test_lthash_cryptographic_uniformity_and_avalanche() {
    let seed1 = LtHash::seed("m.room.message", "", &"$1");
    let seed2 = LtHash::seed("m.room.message", "", &"$2");

    // Avalanche Effect: seed1 and seed2 event_id differ by only 1 character ('1' vs '2').
    let mut different_elements = 0;
    for (a, b) in seed1.lattice().iter().zip(seed2.lattice().iter()) {
        if a != b {
            different_elements += 1;
        }
    }
    // At least 95% of the elements should differ.
    assert!(
        different_elements > 950,
        "Avalanche effect failed: only {different_elements} / 1024 elements differed"
    );

    // Uniformity: Mean of elements should be reasonably close to 32767.5.
    let sum: u32 = seed1.lattice().iter().map(|&x| u32::from(x)).sum();
    let mean = f64::from(sum) / 1024.0;
    assert!(
        (30000.0..=35000.0).contains(&mean),
        "Uniformity check failed: mean of elements is {mean}"
    );
}

#[test]
fn test_lthash_utf8_handling() {
    let key = ("m.room.message💥", "🔑_🦀");
    let val = "$🇩🇪_🇫🇷";
    let seed = LtHash::seed(key.0, key.1, &val);
    assert_ne!(seed, LtHash::ZERO);
}
