use rezzy::merkle::causal::{
    empty_root, verify_causal_inclusion, verify_causal_non_inclusion, CausalSet, CausalSide,
    CAUSAL_DEPTH,
};
use rezzy::merkle::Hash;

fn key(byte: u8) -> Hash {
    [byte; 32]
}

#[test]
fn empty_causal_set_root_and_count() {
    let empty = CausalSet::empty();
    assert_eq!(empty.count(), 0);
    // Assert against the canonical empty_root() — not a tautology comparing
    // two freshly-built empty sets. A regression in empty_table()[0] would
    // change empty_root() and fail this assertion.
    assert_eq!(empty.root(), empty_root());
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
    assert!(path.is_empty());
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
    assert!(!path.is_empty());
    path[0].hash[0] ^= 0xFF;
    assert!(!verify_causal_inclusion(&a, &path, root, count));
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
fn verify_causal_inclusion_rejects_side_forgery() {
    let (a, b) = (key(0xa1), key(0xb2));
    let s = CausalSet::empty().insert(a).insert(b);

    let (mut path, root, count) = s.inclusion_proof(&a).unwrap();
    if !path.is_empty() {
        path[0].side = match path[0].side {
            CausalSide::Left => CausalSide::Right,
            CausalSide::Right => CausalSide::Left,
        };
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
