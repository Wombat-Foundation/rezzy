#![allow(clippy::arithmetic_side_effects)]

use std::hint::black_box;
use std::time::{Duration, Instant};

use roaring::{MultiOps, RoaringBitmap};

/// Builds the reachable set by omitting every `missing_stride`-th index.
fn build_reachable(universe_len: u32, missing_stride: u32) -> RoaringBitmap {
    (0..universe_len)
        .filter(|idx| idx % missing_stride != 0)
        .collect()
}

/// Computes unreachable indices by filtering against `reachable`.
fn bench_once_filter(universe_len: u32, reachable: &RoaringBitmap) -> RoaringBitmap {
    (0..universe_len)
        .filter(|idx| !reachable.contains(*idx))
        .collect()
}

/// Computes unreachable indices with the `-` operator.
fn bench_once_operator(full_range: &RoaringBitmap, reachable: &RoaringBitmap) -> RoaringBitmap {
    full_range - reachable
}

/// Computes unreachable indices with `Sub::sub`.
fn bench_once_sub(full_range: &RoaringBitmap, reachable: &RoaringBitmap) -> RoaringBitmap {
    std::ops::Sub::sub(full_range, reachable)
}

/// Computes unreachable indices with `MultiOps::difference`.
fn bench_once_difference(full_range: &RoaringBitmap, reachable: &RoaringBitmap) -> RoaringBitmap {
    [full_range, reachable].difference()
}

/// Computes unreachable indices with `SubAssign`.
fn bench_once_sub_assign(full_range: &RoaringBitmap, reachable: &RoaringBitmap) -> RoaringBitmap {
    let mut out = full_range.clone();
    out -= reachable;
    out
}

/// Runs one timed benchmark case and prints the per-implementation timings.
fn time_case<F>(iters: usize, mut f: F) -> Duration
where
    F: FnMut() -> RoaringBitmap,
{
    let start = Instant::now();
    for _ in 0..iters {
        black_box(f());
    }
    start.elapsed()
}

/// Validates each bitmap construction strategy and reports their timings.
fn report_case(universe_len: u32, missing_stride: u32, iters: usize) {
    let reachable = build_reachable(universe_len, missing_stride);
    let full_range: RoaringBitmap = (0..universe_len).collect();

    let expected = bench_once_filter(universe_len, &reachable);
    assert_eq!(bench_once_operator(&full_range, &reachable), expected);
    assert_eq!(bench_once_sub(&full_range, &reachable), expected);
    assert_eq!(bench_once_difference(&full_range, &reachable), expected);
    assert_eq!(bench_once_sub_assign(&full_range, &reachable), expected);

    let filter = time_case(iters, || bench_once_filter(universe_len, &reachable));
    let operator = time_case(iters, || bench_once_operator(&full_range, &reachable));
    let sub = time_case(iters, || bench_once_sub(&full_range, &reachable));
    let difference = time_case(iters, || bench_once_difference(&full_range, &reachable));
    let sub_assign = time_case(iters, || bench_once_sub_assign(&full_range, &reachable));

    let iters_f64 = f64::from(u32::try_from(iters).expect("benchmark iteration count fits in u32"));
    let filter_ns = filter.as_secs_f64() * 1_000_000_000.0 / iters_f64;
    let operator_ns = operator.as_secs_f64() * 1_000_000_000.0 / iters_f64;
    let sub_ns = sub.as_secs_f64() * 1_000_000_000.0 / iters_f64;
    let difference_ns = difference.as_secs_f64() * 1_000_000_000.0 / iters_f64;
    let sub_assign_ns = sub_assign.as_secs_f64() * 1_000_000_000.0 / iters_f64;

    println!(
        "universe={universe_len} missing_stride={missing_stride} iters={iters}: filter={filter_ns:.1} ns/op, operator={operator_ns:.1} ns/op, sub={sub_ns:.1} ns/op, difference={difference_ns:.1} ns/op, sub_assign={sub_assign_ns:.1} ns/op"
    );
}

/// Entry point for the standalone bitmap benchmark.
fn main() {
    println!("HAMT audit bitmap unreachable-construction benchmark");
    report_case(8_192, 2, 200);
    report_case(8_192, 4, 200);
    report_case(65_536, 4, 50);
}
