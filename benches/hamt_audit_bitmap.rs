use std::hint::black_box;
use std::time::{Duration, Instant};

use roaring::{MultiOps, RoaringBitmap};

fn build_reachable(universe_len: u32, missing_stride: u32) -> RoaringBitmap {
    (0..universe_len)
        .filter(|idx| idx % missing_stride != 0)
        .collect()
}

fn bench_once_filter(universe_len: u32, reachable: &RoaringBitmap) -> RoaringBitmap {
    (0..universe_len)
        .filter(|idx| !reachable.contains(*idx))
        .collect()
}

fn bench_once_sub(full_range: &RoaringBitmap, reachable: &RoaringBitmap) -> RoaringBitmap {
    std::ops::Sub::sub(full_range, reachable)
}

fn bench_once_difference(full_range: &RoaringBitmap, reachable: &RoaringBitmap) -> RoaringBitmap {
    [&full_range, reachable].difference()
}

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

fn report_case(universe_len: u32, missing_stride: u32, iters: usize) {
    let reachable = build_reachable(universe_len, missing_stride);
    let full_range: RoaringBitmap = (0..universe_len).collect();

    let filter = time_case(iters, || bench_once_filter(universe_len, &reachable));
    let sub = time_case(iters, || bench_once_sub(&full_range, &reachable));
    let difference = time_case(iters, || bench_once_difference(&full_range, &reachable));

    let filter_ns = filter.as_nanos() as f64 / iters as f64;
    let sub_ns = sub.as_nanos() as f64 / iters as f64;
    let difference_ns = difference.as_nanos() as f64 / iters as f64;

    println!(
        "universe={universe_len} missing_stride={missing_stride} iters={iters}: filter={filter_ns:.1} ns/op, sub={sub_ns:.1} ns/op, difference={difference_ns:.1} ns/op"
    );
}

fn main() {
    println!("HAMT audit bitmap unreachable-construction benchmark");
    report_case(8_192, 2, 200);
    report_case(8_192, 4, 200);
    report_case(65_536, 4, 50);
}
