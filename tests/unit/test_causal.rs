use rezzy::merkle::causal::{
    verify_causal_inclusion, verify_causal_non_inclusion, CausalSet, Side, CAUSAL_DEPTH,
};
use rezzy::merkle::Hash;

fn key(byte: u8) -> Hash {
    [byte; 32]
}

#[test]
fn empty_causal_set_root_and_count() {
    let empty = CausalSet::empty();
    assert_eq!(empty.count(), 0);
    assert_eq!(empty.root(), CausalSet::empty().root());
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
}

#[test]
fn causal_non_inclusion_proof_verifies() {
    let (a, b, d) = (key(0xa1), key(0xb2), key(0xd4));
    let s = CausalSet::empty().insert(a).insert(b);

    let (path, terminal_depth, root, count) = s.non_inclusion_proof(&d).unwrap();
    assert_eq!(root, s.root());
    assert_eq!(count, s.count());
    assert!(verify_causal_non_inclusion(
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
        terminal_depth + 1,
        &path,
        root,
        count
    ));
}

#[test]
fn verify_causal_non_inclusion_rejects_out_of_range_depth() {
    assert!(!verify_causal_non_inclusion(
        CAUSAL_DEPTH + 1,
        &[],
        [0; 32],
        0
    ));
}

#[test]
fn causal_proof_step_sides_are_distinct() {
    assert_ne!(Side::Left, Side::Right);
}
