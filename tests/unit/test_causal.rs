use rezzy::merkle::causal::{
    compress_causal_path, decompress_causal_path, empty_root, verify_causal_inclusion,
    verify_causal_inclusion_compressed, verify_causal_non_inclusion,
    verify_causal_non_inclusion_compressed, CausalProofError, CausalProofStep, CausalSet,
    CompressedCausalStep, CAUSAL_DEPTH,
};
use rezzy::merkle::Hash;

fn key(byte: u8) -> Hash {
    [byte; 32]
}

#[test]
fn empty_causal_set_root_and_count() {
    let empty = CausalSet::empty();
    assert_eq!(empty.count(), 0);
    // Fixed MSC4511 vector; this must not be derived through the implementation
    // under test, or an accidental hash/domain change would be tautological.
    let expected = [
        41, 54, 137, 237, 168, 24, 19, 59, 65, 134, 194, 17, 172, 211, 80, 233, 171, 236, 1, 26,
        93, 144, 251, 251, 50, 52, 50, 29, 118, 89, 96, 147,
    ];
    assert_eq!(empty_root(), expected);
    assert_eq!(empty.root(), expected);
}

#[test]
fn insert_is_idempotent_and_order_independent() {
    let (a, b) = (key(0xa1), key(0xb2));

    let s1 = CausalSet::empty().insert(a).insert(b);
    let s2 = CausalSet::empty().insert(b).insert(a);
    let s3 = CausalSet::empty().insert(a).insert(b).insert(a);

    assert_eq!(s1.root(), s2.root());
    assert_eq!(s1.count(), s2.count());
    assert_eq!(s1.root(), s3.root());
    assert_eq!(s3.count(), 2);
}

#[test]
fn union_eliminates_duplicates() {
    let (a, b, c) = (key(0xa1), key(0xb2), key(0xc3));

    let left = CausalSet::empty().insert(a).insert(b);
    let right = CausalSet::empty().insert(a).insert(c);
    let union = left.union(&right);

    assert_eq!(union.count(), 3);
    let direct = CausalSet::empty().insert(a).insert(b).insert(c);
    assert_eq!(union.root(), direct.root());
}

#[test]
fn contains_inclusion_and_non_inclusion() {
    let (a, b) = (key(0xa1), key(0xb2));
    let s = CausalSet::empty().insert(a);

    assert!(s.contains(&a));
    assert!(!s.contains(&b));
}

#[test]
fn causal_inclusion_proof_verifies() {
    let (a, b, c) = (key(0xa1), key(0xb2), key(0xc3));
    let s = CausalSet::empty().insert(a).insert(b).insert(c);

    for k in [a, b, c] {
        let (path, root, count) = s.inclusion_proof(&k).unwrap();
        assert_eq!(root, s.root());
        assert_eq!(count, s.count());
        assert!(verify_causal_inclusion(&k, &path, root, count));
    }
}

#[test]
fn causal_inclusion_proof_rejects_non_member() {
    let (a, d) = (key(0xa1), key(0xd4));
    let s = CausalSet::empty().insert(a);
    assert!(s.inclusion_proof(&d).is_none());
    assert!(CausalSet::empty().inclusion_proof(&d).is_none());
}

#[test]
fn causal_non_inclusion_proof_verifies() {
    let (a, b, d) = (key(0xa1), key(0xb2), key(0xd4));
    let s = CausalSet::empty().insert(a).insert(b);

    let (path, terminal_depth, root, count) = s.non_inclusion_proof(&d).unwrap();
    assert_eq!(root, s.root());
    assert_eq!(count, s.count());
    assert!(verify_causal_non_inclusion(
        &d,
        terminal_depth,
        &path,
        root,
        count
    ));
}

#[test]
fn causal_non_inclusion_proof_rejects_member() {
    let a = key(0xa1);
    let s = CausalSet::empty().insert(a);
    assert!(s.non_inclusion_proof(&a).is_none());
}

#[test]
fn causal_non_inclusion_proof_on_empty_set() {
    let d = key(0xd4);
    let s = CausalSet::empty();

    let (path, terminal_depth, root, count) = s.non_inclusion_proof(&d).unwrap();
    assert_eq!(path, [] as [rezzy::merkle::causal::CausalProofStep; 0]);
    assert_eq!(terminal_depth, 0);
    assert!(verify_causal_non_inclusion(
        &d,
        terminal_depth,
        &path,
        root,
        count
    ));
}

#[test]
fn verify_causal_inclusion_rejects_tampered_sibling() {
    let (a, b) = (key(0xa1), key(0xb2));
    let s = CausalSet::empty().insert(a).insert(b);

    let (mut path, root, count) = s.inclusion_proof(&a).unwrap();
    assert_ne!(path, [] as [rezzy::merkle::causal::CausalProofStep; 0]);
    path[0].hash[0] ^= 0xFF;
    assert!(!verify_causal_inclusion(&a, &path, root, count));
}

#[test]
fn verify_causal_inclusion_rejects_extended_proof() {
    let k = key(0xa1);
    let s = CausalSet::empty().insert(k);

    let (mut path, root, count) = s.inclusion_proof(&k).unwrap();
    assert_eq!(path.len(), CAUSAL_DEPTH);

    // Append a hand-crafted step beyond CAUSAL_DEPTH.
    path.push(rezzy::merkle::causal::CausalProofStep {
        hash: [0xAA; 32],
        count: 0,
    });
    assert_eq!(path.len(), CAUSAL_DEPTH + 1);
    // The minimality check (path.len() != terminal_depth) must reject this.
    assert!(!verify_causal_inclusion(&k, &path, root, count));

    // Also test: prepend a step (path too long from the verifier's
    // perspective — it expects exactly CAUSAL_DEPTH for inclusion).
    let (path, root, count) = s.inclusion_proof(&k).unwrap();
    let mut extended = vec![rezzy::merkle::causal::CausalProofStep {
        hash: [0xBB; 32],
        count: 1,
    }];
    extended.extend_from_slice(&path);
    assert!(!verify_causal_inclusion(&k, &extended, root, count));
}

#[test]
fn verify_causal_non_inclusion_rejects_wrong_terminal_depth() {
    let (a, b, d) = (key(0xa1), key(0xb2), key(0xd4));
    let s = CausalSet::empty().insert(a).insert(b);

    let (path, terminal_depth, root, count) = s.non_inclusion_proof(&d).unwrap();
    assert!(!verify_causal_non_inclusion(
        &d,
        terminal_depth + 1,
        &path,
        root,
        count
    ));
}

#[test]
fn verify_causal_non_inclusion_rejects_out_of_range_depth() {
    assert!(!verify_causal_non_inclusion(
        &key(0xd4),
        CAUSAL_DEPTH + 1,
        &[],
        [0; 32],
        0
    ));
}

#[test]
fn verify_causal_inclusion_rejects_count_forgery() {
    let (a, b) = (key(0xa1), key(0xb2));
    let s = CausalSet::empty().insert(a).insert(b);

    let (mut path, root, count) = s.inclusion_proof(&a).unwrap();
    // Tampering with total root count
    assert!(!verify_causal_inclusion(&a, &path, root, count + 1));
    // Tampering with sibling count
    if !path.is_empty() {
        let mut overflow_path = path.clone();
        overflow_path[0].count = u64::MAX;
        assert!(!verify_causal_inclusion(&a, &overflow_path, root, count));

        path[0].count = path[0].count.saturating_add(10);
        assert!(!verify_causal_inclusion(&a, &path, root, count));
    }
}

#[test]
fn causal_deep_key_prefixes() {
    let mut k1 = [0xAA; 32];
    let mut k2 = [0xAA; 32];
    // Differentiate only at the very last bit
    k1[31] = 0x00;
    k2[31] = 0x01;

    let s = CausalSet::empty().insert(k1).insert(k2);
    assert_eq!(s.count(), 2);

    let (path1, root, count) = s.inclusion_proof(&k1).unwrap();
    assert!(verify_causal_inclusion(&k1, &path1, root, count));

    let (path2, root, count) = s.inclusion_proof(&k2).unwrap();
    assert!(verify_causal_inclusion(&k2, &path2, root, count));

    let mut non_member = [0xAA; 32];
    non_member[31] = 0x02;
    let (non_path, depth, root, count) = s.non_inclusion_proof(&non_member).unwrap();
    assert!(verify_causal_non_inclusion(
        &non_member,
        depth,
        &non_path,
        root,
        count
    ));
}

#[test]
fn insert_mut_and_extend_match_immutable_methods() {
    let (a, b, c) = (key(0xa1), key(0xb2), key(0xc3));

    let mut s_mut = CausalSet::empty();
    assert!(s_mut.insert_mut(a));
    assert!(!s_mut.insert_mut(a)); // duplicate insert returns false
    assert!(s_mut.insert_mut(b));

    let s_imm = CausalSet::empty().insert(a).insert(b);
    assert_eq!(s_mut.root(), s_imm.root());
    assert_eq!(s_mut.count(), s_imm.count());

    let mut s_ext = CausalSet::empty();
    s_ext.extend([a, b, c, a]);
    let s_direct = CausalSet::empty().insert(a).insert(b).insert(c);
    assert_eq!(s_ext.root(), s_direct.root());
    assert_eq!(s_ext.count(), s_direct.count());
}

// ── compressed proof tests ──────────────────────────────────────────

#[test]
fn compress_inclusion_roundtrip_root_level_sibling() {
    // Keys differing at bit 0 land in different branches at the root.
    // The sibling at the root is the other branch's subtree (non-empty),
    // but deeper levels may still have empty siblings where only one
    // branch is populated. The roundtrip must verify regardless.
    let mut k1 = [0u8; 32];
    let mut k2 = [0u8; 32];
    k1[0] = 0x00;
    k2[0] = 0x80; // bit 0 differs
    let s = CausalSet::empty().insert(k1).insert(k2);

    let (path, root, count) = s.inclusion_proof(&k1).unwrap();
    let compressed = compress_causal_path(CAUSAL_DEPTH, &path);
    // At least the root-level sibling should be a Step (the other
    // branch), but deeper levels may be EmptyRun.
    assert_ne!(
        compressed,
        [] as [rezzy::merkle::causal::CompressedCausalStep; 0]
    );
    let decompressed = decompress_causal_path(CAUSAL_DEPTH, &compressed).unwrap();
    assert_eq!(decompressed.len(), path.len());
    assert!(verify_causal_inclusion(&k1, &decompressed, root, count));
}

#[test]
fn compress_inclusion_roundtrip_many_empty_siblings() {
    // A single key means every sibling along the path is an empty
    // subtree — the entire path compresses to one EmptyRun.
    let k = key(0xa1);
    let s = CausalSet::empty().insert(k);

    let (path, root, count) = s.inclusion_proof(&k).unwrap();
    let compressed = compress_causal_path(CAUSAL_DEPTH, &path);
    // The single key diverges from the empty subtree at every level,
    // so all siblings are empty.
    assert_eq!(compressed.len(), 1);
    match &compressed[0] {
        CompressedCausalStep::EmptyRun {
            start_depth,
            length,
        } => {
            assert_eq!(*start_depth as usize, CAUSAL_DEPTH);
            assert_eq!(*length as usize, CAUSAL_DEPTH);
        }
        other @ CompressedCausalStep::Step(_) => panic!("expected EmptyRun, got {other:?}"),
    }
    let decompressed = decompress_causal_path(CAUSAL_DEPTH, &compressed).unwrap();
    assert!(verify_causal_inclusion(&k, &decompressed, root, count));
}

#[test]
fn compress_inclusion_roundtrip_mixed_siblings() {
    // Three keys: at least one level will have a non-empty sibling,
    // producing a mix of Step and EmptyRun entries.
    let (a, b, c) = (key(0xa1), key(0xb2), key(0xc3));
    let s = CausalSet::empty().insert(a).insert(b).insert(c);

    for k in [a, b, c] {
        let (path, root, count) = s.inclusion_proof(&k).unwrap();
        let compressed = compress_causal_path(CAUSAL_DEPTH, &path);
        let decompressed = decompress_causal_path(CAUSAL_DEPTH, &compressed).unwrap();
        assert!(verify_causal_inclusion(&k, &decompressed, root, count));
    }
}

#[test]
fn compress_non_inclusion_roundtrip() {
    let (a, d) = (key(0xa1), key(0xd4));
    let s = CausalSet::empty().insert(a);

    let (path, terminal_depth, root, count) = s.non_inclusion_proof(&d).unwrap();
    let compressed = compress_causal_path(terminal_depth, &path);
    let decompressed = decompress_causal_path(terminal_depth, &compressed).unwrap();
    assert!(verify_causal_non_inclusion(
        &d,
        terminal_depth,
        &decompressed,
        root,
        count,
    ));
}

#[test]
fn compress_non_inclusion_on_empty_set() {
    let d = key(0xd4);
    let s = CausalSet::empty();
    let (path, terminal_depth, root, count) = s.non_inclusion_proof(&d).unwrap();
    assert_eq!(path, [] as [rezzy::merkle::causal::CausalProofStep; 0]);
    assert_eq!(terminal_depth, 0);
    let compressed = compress_causal_path(terminal_depth, &path);
    assert_eq!(
        compressed,
        [] as [rezzy::merkle::causal::CompressedCausalStep; 0]
    );
    let decompressed = decompress_causal_path(terminal_depth, &compressed).unwrap();
    assert_eq!(
        decompressed,
        [] as [rezzy::merkle::causal::CausalProofStep; 0]
    );
    assert!(verify_causal_non_inclusion(
        &d,
        terminal_depth,
        &decompressed,
        root,
        count,
    ));
}

#[test]
fn compress_verify_compressed_inclusion_api() {
    let (a, b) = (key(0xa1), key(0xb2));
    let s = CausalSet::empty().insert(a).insert(b);
    let (path, root, count) = s.inclusion_proof(&a).unwrap();
    let compressed = compress_causal_path(CAUSAL_DEPTH, &path);
    assert!(verify_causal_inclusion_compressed(&a, &compressed, root, count).unwrap());
}

#[test]
fn compress_verify_compressed_non_inclusion_api() {
    let (a, d) = (key(0xa1), key(0xd4));
    let s = CausalSet::empty().insert(a);
    let (path, terminal_depth, root, count) = s.non_inclusion_proof(&d).unwrap();
    let compressed = compress_causal_path(terminal_depth, &path);
    assert!(
        verify_causal_non_inclusion_compressed(&d, terminal_depth, &compressed, root, count,)
            .unwrap()
    );
}

#[test]
fn decompress_path_independent_of_key() {
    let (a, b) = (key(0xa1), key(0xb2));
    let s = CausalSet::empty().insert(a).insert(b);
    let (path, root, count) = s.inclusion_proof(&a).unwrap();
    let compressed = compress_causal_path(CAUSAL_DEPTH, &path);

    // Decompressing with a different key produces the same { hash, count }
    // pairs because side is no longer stored — it is derived from the key
    // at verification time.
    let decompressed_b = decompress_causal_path(CAUSAL_DEPTH, &compressed).unwrap();
    let decompressed_a = decompress_causal_path(CAUSAL_DEPTH, &compressed).unwrap();
    assert_eq!(decompressed_b, decompressed_a);

    // Both verify correctly with the right key.
    assert!(verify_causal_inclusion(&a, &decompressed_a, root, count));
    assert!(verify_causal_inclusion(&a, &decompressed_b, root, count));
    // Verifying with the wrong key (b) fails — not a member.
    assert!(!verify_causal_inclusion(&b, &decompressed_a, root, count));
}

#[test]
fn decompress_rejects_truncated() {
    let result = decompress_causal_path(
        CAUSAL_DEPTH,
        &[CompressedCausalStep::EmptyRun {
            start_depth: u16::try_from(CAUSAL_DEPTH).unwrap(),
            length: 10,
        }],
    );
    assert!(matches!(
        result,
        Err(CausalProofError::PathLengthMismatch { .. })
    ));
}

#[test]
fn decompress_rejects_excess_data() {
    let k = key(0xa1);
    let s = CausalSet::empty().insert(k);
    let (path, _, _) = s.inclusion_proof(&k).unwrap();
    let mut compressed = compress_causal_path(CAUSAL_DEPTH, &path);
    // Append a spurious step — should be rejected as excess.
    compressed.push(CompressedCausalStep::Step(path[0]));
    let result = decompress_causal_path(CAUSAL_DEPTH, &compressed);
    assert!(matches!(result, Err(CausalProofError::ExcessData)));
}

#[test]
fn decompress_rejects_zero_length_run() {
    let result = decompress_causal_path(
        CAUSAL_DEPTH,
        &[CompressedCausalStep::EmptyRun {
            start_depth: u16::try_from(CAUSAL_DEPTH).unwrap(),
            length: 0,
        }],
    );
    assert!(matches!(result, Err(CausalProofError::Truncated)));
}

#[test]
fn decompress_rejects_run_below_root() {
    // Use terminal_depth=2 so expected_start = 2, making the run
    // contiguous. length=3 > start_depth=2 means the run would expand
    // past sibling depth 1 into depth 0 (the root), which is invalid.
    let result = decompress_causal_path(
        2,
        &[CompressedCausalStep::EmptyRun {
            start_depth: 2,
            length: 3,
        }],
    );
    assert!(matches!(result, Err(CausalProofError::RunBelowRoot)));
}

#[test]
fn decompress_rejects_non_contiguous_run() {
    // start_depth=200 but the path position expects 256 — non-contiguous.
    let result = decompress_causal_path(
        CAUSAL_DEPTH,
        &[CompressedCausalStep::EmptyRun {
            start_depth: 200,
            length: 1,
        }],
    );
    assert!(matches!(
        result,
        Err(CausalProofError::NonContiguousRun { .. })
    ));
}

#[test]
fn decompress_rejects_invalid_depth() {
    // start_depth > CAUSAL_DEPTH is invalid.
    let result = decompress_causal_path(
        CAUSAL_DEPTH,
        &[CompressedCausalStep::EmptyRun {
            start_depth: u16::try_from(CAUSAL_DEPTH + 1).unwrap(),
            length: 1,
        }],
    );
    assert!(matches!(
        result,
        Err(CausalProofError::InvalidDepth(d)) if d as usize == CAUSAL_DEPTH + 1
    ));
}

#[test]
fn decompress_rejects_terminal_depth_above_causal_depth() {
    // `terminal_depth` itself must not exceed `CAUSAL_DEPTH`, independent of
    // whatever `compressed` claims — an over-depth sequence of explicit
    // `Step` entries must not be silently accepted.
    let result = decompress_causal_path(CAUSAL_DEPTH + 1, &[]);
    assert!(matches!(
        result,
        Err(CausalProofError::InvalidDepth(d)) if d as usize == CAUSAL_DEPTH + 1
    ));
}

#[test]
fn deep_key_prefixes_compressed_roundtrip() {
    let mut k1 = [0xAA; 32];
    let mut k2 = [0xAA; 32];
    k1[31] = 0x00;
    k2[31] = 0x01;

    let s = CausalSet::empty().insert(k1).insert(k2);
    assert_eq!(s.count(), 2);

    for k in [k1, k2] {
        let (path, root, count) = s.inclusion_proof(&k).unwrap();
        let compressed = compress_causal_path(CAUSAL_DEPTH, &path);
        let decompressed = decompress_causal_path(CAUSAL_DEPTH, &compressed).unwrap();
        assert!(verify_causal_inclusion(&k, &decompressed, root, count));
    }

    let mut non_member = [0xAA; 32];
    non_member[31] = 0x02;
    let (path, td, root, count) = s.non_inclusion_proof(&non_member).unwrap();
    let compressed = compress_causal_path(td, &path);
    let decompressed = decompress_causal_path(td, &compressed).unwrap();
    assert!(verify_causal_non_inclusion(
        &non_member,
        td,
        &decompressed,
        root,
        count,
    ));
}

// ── canonicity rejection tests ─────────────────────────────────────

#[test]
fn decompress_rejects_adjacent_empty_runs() {
    // Two adjacent EmptyRuns that together cover the full depth: the
    // second should have been merged into the first.
    let result = decompress_causal_path(
        CAUSAL_DEPTH,
        &[
            CompressedCausalStep::EmptyRun {
                start_depth: u16::try_from(CAUSAL_DEPTH).unwrap(),
                length: 200,
            },
            CompressedCausalStep::EmptyRun {
                start_depth: 56,
                length: 56,
            },
        ],
    );
    assert!(matches!(result, Err(CausalProofError::NonMaximalRun)));
}

#[test]
fn decompress_rejects_non_canonical_step_with_empty_value() {
    let k = key(0xa1);
    let s = CausalSet::empty().insert(k);
    let (path, _root, _count) = s.inclusion_proof(&k).unwrap();
    let compressed = compress_causal_path(CAUSAL_DEPTH, &path);
    let decompressed = decompress_causal_path(CAUSAL_DEPTH, &compressed).unwrap();

    // All siblings in a single-element set are canonical-empty. The
    // decompressor expands EmptyRuns to steps with hash == empty[d] and
    // count == 0, which is fine. But if we craft a Step with those
    // same values directly, it should be rejected as non-canonical.
    // Use decompressed[0]'s hash which IS the empty hash at that depth.
    let fake_step = CompressedCausalStep::Step(CausalProofStep {
        hash: decompressed[0].hash,
        count: 0,
    });
    // This should be rejected because it's a Step carrying a canonical-empty value.
    let result = decompress_causal_path(CAUSAL_DEPTH, &[fake_step]);
    assert!(matches!(result, Err(CausalProofError::NonCanonicalStep)));
}

#[test]
fn decompress_rejects_non_canonical_step_interleaved_with_run() {
    let k = key(0xa1);
    // An EmptyRun followed by a Step with a canonical-empty value at the
    // next expected depth. The Step should be rejected even though the
    // EmptyRun is valid on its own.
    let s = CausalSet::empty().insert(k);
    let (path, _, _) = s.inclusion_proof(&k).unwrap();
    let decompressed =
        decompress_causal_path(CAUSAL_DEPTH, &compress_causal_path(CAUSAL_DEPTH, &path)).unwrap();
    // The first decompressed step is at sibling depth CAUSAL_DEPTH.
    let first_hash = decompressed[0].hash;

    // Use a single Step with the first step's values (which IS at a
    // canonical-empty position), followed by an EmptyRun for the rest.
    let result = decompress_causal_path(
        CAUSAL_DEPTH,
        &[
            CompressedCausalStep::Step(CausalProofStep {
                hash: first_hash,
                count: 0,
            }),
            CompressedCausalStep::EmptyRun {
                start_depth: 255,
                length: 255,
            },
        ],
    );
    assert!(matches!(result, Err(CausalProofError::NonCanonicalStep)));
}

#[test]
fn decompress_accepts_step_with_nonzero_count_at_empty_position() {
    let k = key(0xa1);
    let s = CausalSet::empty().insert(k);
    let (path, _, _) = s.inclusion_proof(&k).unwrap();
    let decompressed =
        decompress_causal_path(CAUSAL_DEPTH, &compress_causal_path(CAUSAL_DEPTH, &path)).unwrap();
    // Same hash as the first empty sibling, but with count=1. This is
    // non-empty (count != 0) so it should be accepted — it's a lie about
    // the count, but that's caught by verify, not decompress.
    let result = decompress_causal_path(
        CAUSAL_DEPTH,
        &[
            CompressedCausalStep::Step(CausalProofStep {
                hash: decompressed[0].hash,
                count: 1,
            }),
            CompressedCausalStep::EmptyRun {
                start_depth: 255,
                length: 255,
            },
        ],
    );
    assert!(result.is_ok());
}
