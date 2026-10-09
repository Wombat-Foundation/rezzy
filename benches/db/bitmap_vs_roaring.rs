//! `rezzy::bitmap::Bitmap` against `roaring::RoaringBitmap`.
//!
//! `roaring` is a comparison baseline only; the library itself has no such
//! dependency. Every case checks both implementations agree before timing.

use std::collections::BTreeSet;
use std::hint::black_box;
use std::time::Instant;

use rezzy::bitmap::{Bitmap, Bitmap128, Bitmap64};
use roaring::{RoaringBitmap, RoaringTreemap};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn values(rng: &mut Rng, span: u32, per_mille: u64) -> Vec<u32> {
    (0..span)
        .filter(|_| rng.next() % 1000 < per_mille)
        .collect()
}

fn ns_per_iter<F: FnMut()>(iters: u32, mut f: F) -> f64 {
    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    start.elapsed().as_secs_f64() * 1e9 / f64::from(iters)
}

fn row(case: &str, iters: u32, mut ours: impl FnMut(), mut theirs: impl FnMut()) {
    let o = ns_per_iter(iters, &mut ours);
    let t = ns_per_iter(iters, &mut theirs);
    println!(
        "{case:<44} bitmap={o:>12.0} ns  roaring={t:>12.0} ns  ratio={:.2}x",
        o / t
    );
}

fn same(a: &Bitmap, b: &RoaringBitmap) {
    assert_eq!(a.len(), b.len());
    assert!(a.iter().eq(b.iter()));
}

fn pair(vals: &[u32]) -> (Bitmap, RoaringBitmap) {
    (
        vals.iter().copied().collect(),
        vals.iter().copied().collect(),
    )
}

/// Mirrors `ForwardReachabilityIndex::build` / `AuthGraph::build`: each node's
/// set is itself unioned with its children's sets, walked in reverse order.
fn dag_accumulate(n: u32, fanout: u32) -> (usize, usize) {
    let mut ours = vec![Bitmap::new(); n as usize];
    let mut theirs = vec![RoaringBitmap::new(); n as usize];
    for i in (0..n).rev() {
        let mut a = Bitmap::new();
        let mut b = RoaringBitmap::new();
        a.insert(i);
        b.insert(i);
        for k in 1..=fanout {
            if let Some(child) = i.checked_add(k).filter(|c| *c < n) {
                a |= &ours[child as usize];
                b |= &theirs[child as usize];
            }
        }
        ours[i as usize] = a;
        theirs[i as usize] = b;
    }
    let (a, b) = (&ours[0], &theirs[0]);
    same(a, b);
    (a.len() as usize, b.len() as usize)
}

fn dag_case(n: u32, fanout: u32, iters: u32) {
    dag_accumulate(n, fanout);
    let o = ns_per_iter(iters, || {
        let mut ours = vec![Bitmap::new(); n as usize];
        for i in (0..n).rev() {
            let mut a = Bitmap::new();
            a.insert(i);
            for k in 1..=fanout {
                if let Some(c) = i.checked_add(k).filter(|c| *c < n) {
                    a |= &ours[c as usize];
                }
            }
            ours[i as usize] = a;
        }
        black_box(ours);
    });
    let t = ns_per_iter(iters, || {
        let mut theirs = vec![RoaringBitmap::new(); n as usize];
        for i in (0..n).rev() {
            let mut b = RoaringBitmap::new();
            b.insert(i);
            for k in 1..=fanout {
                if let Some(c) = i.checked_add(k).filter(|c| *c < n) {
                    b |= &theirs[c as usize];
                }
            }
            theirs[i as usize] = b;
        }
        black_box(theirs);
    });
    println!(
        "{:<44} bitmap={o:>12.0} ns  roaring={t:>12.0} ns  ratio={:.2}x",
        format!("dag accumulate n={n} fanout={fanout}"),
        o / t
    );
}

/// `n` values spread over `groups` distinct high-bit groups, `per_mille` dense
/// within each group's first 200k low values.
fn wide_values(rng: &mut Rng, groups: u32, per_mille: u64, hi_stride: u128) -> Vec<u128> {
    let mut out = Vec::new();
    for g in 0..groups {
        let base = (u128::from(g) * hi_stride) << 32;
        out.extend(
            values(rng, 200_000, per_mille)
                .into_iter()
                .map(|v| base | u128::from(v)),
        );
    }
    out
}

fn wide_cases(rng: &mut Rng) {
    println!("\nBitmap64 / Bitmap128 (high bits in a BTreeMap, low 32 bits in Bitmap)");
    for &(groups, pm, label) in &[
        (4u32, 5u64, "sparse"),
        (4, 60, "boundary"),
        (4, 500, "dense"),
    ] {
        let a = wide_values(rng, groups, pm, 3);
        let b = wide_values(rng, groups, pm, 2);
        let iters = 20;

        // u64 vs RoaringTreemap.
        let a64: Vec<u64> = a.iter().map(|v| *v as u64).collect();
        let b64: Vec<u64> = b.iter().map(|v| *v as u64).collect();
        let (wa, wb): (Bitmap64, Bitmap64) =
            (a64.iter().copied().collect(), b64.iter().copied().collect());
        let (ta, tb): (RoaringTreemap, RoaringTreemap) =
            (a64.iter().copied().collect(), b64.iter().copied().collect());
        assert_eq!(wa.len(), ta.len());
        assert!(wa.iter().eq(ta.iter()));
        assert!((&wa | &wb).iter().eq((&ta | &tb).iter()));
        assert!((&wa & &wb).iter().eq((&ta & &tb).iter()));
        assert!((wa.clone() - &wb).iter().eq((&ta - &tb).iter()));
        row(
            &format!("u64 build {label} n={}", a64.len()),
            iters,
            || {
                black_box(a64.iter().copied().collect::<Bitmap64>());
            },
            || {
                black_box(a64.iter().copied().collect::<RoaringTreemap>());
            },
        );
        row(
            &format!("u64 or {label}"),
            iters,
            || {
                black_box(&wa | &wb);
            },
            || {
                black_box(&ta | &tb);
            },
        );
        row(
            &format!("u64 and {label}"),
            iters,
            || {
                black_box(&wa & &wb);
            },
            || {
                black_box(&ta & &tb);
            },
        );
        row(
            &format!("u64 sub {label}"),
            iters,
            || {
                black_box(wa.clone() - &wb);
            },
            || {
                black_box(&ta - &tb);
            },
        );
        row(
            &format!("u64 iterate {label}"),
            iters,
            || {
                black_box(wa.iter().fold(0u64, |s, v| s.wrapping_add(v)));
            },
            || {
                black_box(ta.iter().fold(0u64, |s, v| s.wrapping_add(v)));
            },
        );
        row(
            &format!("u64 contains x{} {label}", b64.len()),
            iters,
            || {
                black_box(b64.iter().filter(|v| wa.contains(**v)).count());
            },
            || {
                black_box(b64.iter().filter(|v| ta.contains(**v)).count());
            },
        );

        // u128 vs BTreeSet<u128> (roaring has no u128 type).
        let (xa, xb): (Bitmap128, Bitmap128) =
            (a.iter().copied().collect(), b.iter().copied().collect());
        let (sa, sb): (BTreeSet<u128>, BTreeSet<u128>) =
            (a.iter().copied().collect(), b.iter().copied().collect());
        assert_eq!(xa.len(), sa.len() as u128);
        assert!(xa.iter().eq(sa.iter().copied()));
        assert!((&xa | &xb).iter().eq(sa.union(&sb).copied()));
        assert!((&xa & &xb).iter().eq(sa.intersection(&sb).copied()));
        assert!((xa.clone() - &xb).iter().eq(sa.difference(&sb).copied()));
        row(
            &format!("u128 build {label} n={} (vs BTreeSet)", a.len()),
            iters,
            || {
                black_box(a.iter().copied().collect::<Bitmap128>());
            },
            || {
                black_box(a.iter().copied().collect::<BTreeSet<u128>>());
            },
        );
        row(
            &format!("u128 or {label} (vs BTreeSet)"),
            iters,
            || {
                black_box(&xa | &xb);
            },
            || {
                black_box(sa.union(&sb).copied().collect::<BTreeSet<u128>>());
            },
        );
        row(
            &format!("u128 and {label} (vs BTreeSet)"),
            iters,
            || {
                black_box(&xa & &xb);
            },
            || {
                black_box(sa.intersection(&sb).copied().collect::<BTreeSet<u128>>());
            },
        );
        row(
            &format!("u128 sub {label} (vs BTreeSet)"),
            iters,
            || {
                black_box(xa.clone() - &xb);
            },
            || {
                black_box(sa.difference(&sb).copied().collect::<BTreeSet<u128>>());
            },
        );
        row(
            &format!("u128 iterate {label} (vs BTreeSet)"),
            iters,
            || {
                black_box(xa.iter().fold(0u128, |s, v| s.wrapping_add(v)));
            },
            || {
                black_box(sa.iter().fold(0u128, |s, v| s.wrapping_add(*v)));
            },
        );
        row(
            &format!("u128 contains x{} {label} (vs BTreeSet)", b.len()),
            iters,
            || {
                black_box(b.iter().filter(|v| xa.contains(**v)).count());
            },
            || {
                black_box(b.iter().filter(|v| sa.contains(*v)).count());
            },
        );
    }
}

/// Entry point for the bitmap comparison benchmark.
pub fn run() {
    println!("Bitmap vs roaring (ratio < 1 means Bitmap is faster)");
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);

    for &(span, pm, label) in &[
        (200_000u32, 5u64, "sparse"),
        (200_000, 60, "boundary"),
        (200_000, 500, "dense"),
    ] {
        let a = values(&mut rng, span, pm);
        let b = values(&mut rng, span, pm);
        let (oa, ra) = pair(&a);
        let (ob, rb) = pair(&b);
        same(&oa, &ra);
        let iters = 50;

        row(
            &format!("build ascending {label} n={}", a.len()),
            iters,
            || {
                black_box(a.iter().copied().collect::<Bitmap>());
            },
            || {
                black_box(a.iter().copied().collect::<RoaringBitmap>());
            },
        );
        row(
            &format!("or {label}"),
            iters,
            || {
                black_box(&oa | &ob);
            },
            || {
                black_box(&ra | &rb);
            },
        );
        row(
            &format!("and {label}"),
            iters,
            || {
                black_box(&oa & &ob);
            },
            || {
                black_box(&ra & &rb);
            },
        );
        row(
            &format!("sub {label}"),
            iters,
            || {
                black_box(oa.clone() - &ob);
            },
            || {
                black_box(ra.clone() - &rb);
            },
        );
        row(
            &format!("iterate {label}"),
            iters,
            || {
                black_box(oa.iter().map(u64::from).sum::<u64>());
            },
            || {
                black_box(ra.iter().map(u64::from).sum::<u64>());
            },
        );
        row(
            &format!("contains x{} {label}", b.len()),
            iters,
            || {
                black_box(b.iter().filter(|v| oa.contains(**v)).count());
            },
            || {
                black_box(b.iter().filter(|v| ra.contains(**v)).count());
            },
        );
    }

    dag_case(2_000, 2, 5);
    dag_case(20_000, 2, 3);
    dag_case(20_000, 4, 3);

    wide_cases(&mut rng);
}
