//! SIMD-accelerated GF(2^64) polynomial evaluation for minisketch reconciliation.

#![allow(unsafe_code)]

#[cfg(all(feature = "std", target_arch = "x86_64"))]
use std::io::Write as _;

#[cfg(all(target_arch = "x86_64", has_avx512_support))]
use core::arch::x86_64::{
    __m512i, _mm512_and_si512, _mm512_bsrli_epi128, _mm512_clmulepi64_epi128, _mm512_set_epi64,
    _mm512_slli_epi64, _mm512_srli_epi64, _mm512_store_si512, _mm512_xor_si512,
};

#[cfg(all(target_arch = "x86_64", has_avx512_support))]
#[repr(align(64))]
struct AlignedArray([u64; 8]);

/// Evaluates polynomial roots in parallel blocks of 8.
pub trait Gf64Evaluator {
    /// Multiplies a constant `term` by all coefficients in `source`,
    /// and XOR-adds the results into the corresponding positions in `target`.
    /// `source` and `target` must have the same length.
    fn poly_mac(term: u64, source: &[u64], target: &mut [u64]);
}

#[derive(Clone, Copy)]
pub struct ScalarEvaluator;

impl Gf64Evaluator for ScalarEvaluator {
    fn poly_mac(term: u64, source: &[u64], target: &mut [u64]) {
        for (i, &coefficient) in source.iter().enumerate() {
            target[i] ^= crate::reconcile::gf64::mul(term, coefficient);
        }
    }
}

#[cfg(all(target_arch = "x86_64", has_avx512_support))]
#[derive(Clone, Copy)]
pub(crate) struct Avx512Evaluator;

#[cfg(all(target_arch = "x86_64", has_avx512_support))]
impl Gf64Evaluator for Avx512Evaluator {
    #[allow(clippy::incompatible_msrv)]
    #[cfg_attr(all(coverage_nightly, not(has_avx512_host_support)), coverage(off))]
    fn poly_mac(term: u64, source: &[u64], target: &mut [u64]) {
        // SAFETY: The dispatcher only selects this backend after runtime AVX-512 detection.
        unsafe { poly_mac_avx512(term, source, target) }
    }
}

#[cfg(all(target_arch = "x86_64", has_avx512_support))]
#[target_feature(enable = "avx512f,avx512bw,vpclmulqdq")]
#[allow(clippy::incompatible_msrv)]
#[cfg_attr(all(coverage_nightly, not(has_avx512_host_support)), coverage(off))]
// SAFETY: Only called by `Avx512Evaluator::poly_mac`, which enforces CPU feature constraints.
unsafe fn poly_mac_avx512(term: u64, source: &[u64], target: &mut [u64]) {
    assert_eq!(source.len(), target.len());
    let mut i = 0;
    let len = source.len();

    // SAFETY: This helper is only entered after the caller has selected the
    // AVX-512 backend, and the `target_feature` annotation enables the
    // required intrinsics for this block.
    unsafe {
        // Broadcast the scalar term to all lanes. We only need it in the lower 64 bits of each 128-bit lane.
        let t = i64::from_ne_bytes(term.to_ne_bytes());
        let term_vec = _mm512_set_epi64(0, t, 0, t, 0, t, 0, t);

        // Process chunks of 8
        let chunk_limit = len.saturating_sub(7);
        while i < chunk_limit {
            // Load 8 coefficients from source (unaligned)
            let s_ptr = source.as_ptr().add(i);
            // We need to unpack 8 contiguous 64-bit values into two 512-bit registers,
            // placing each 64-bit value into the lower half of a 128-bit lane.
            // Since they are contiguous in memory, we can't just do a single 512-bit load.
            // We could load them scalar, or use shuffle/unpack instructions.
            // For simplicity and to ensure correctness, we manually set them.
            // (In a heavily optimized pass, we could use AVX-512 gather or shuffle).
            let s0 = _mm512_set_epi64(
                0,
                i64::from_ne_bytes((*s_ptr.add(3)).to_ne_bytes()),
                0,
                i64::from_ne_bytes((*s_ptr.add(2)).to_ne_bytes()),
                0,
                i64::from_ne_bytes((*s_ptr.add(1)).to_ne_bytes()),
                0,
                i64::from_ne_bytes((*s_ptr.add(0)).to_ne_bytes()),
            );
            let s1 = _mm512_set_epi64(
                0,
                i64::from_ne_bytes((*s_ptr.add(7)).to_ne_bytes()),
                0,
                i64::from_ne_bytes((*s_ptr.add(6)).to_ne_bytes()),
                0,
                i64::from_ne_bytes((*s_ptr.add(5)).to_ne_bytes()),
                0,
                i64::from_ne_bytes((*s_ptr.add(4)).to_ne_bytes()),
            );

            // Multiply
            let p0 = gf64_mul_x4_avx512(term_vec, s0);
            let p1 = gf64_mul_x4_avx512(term_vec, s1);

            let mut tmp0 = AlignedArray([0u64; 8]);
            let mut tmp1 = AlignedArray([0u64; 8]);
            let tmp0_ptr = core::ptr::addr_of_mut!(tmp0).cast::<__m512i>();
            let tmp1_ptr = core::ptr::addr_of_mut!(tmp1).cast::<__m512i>();

            _mm512_store_si512(tmp0_ptr, p0);
            _mm512_store_si512(tmp1_ptr, p1);

            let t_ptr = target.as_mut_ptr().add(i);
            *t_ptr.add(0) ^= tmp0.0[0];
            *t_ptr.add(1) ^= tmp0.0[2];
            *t_ptr.add(2) ^= tmp0.0[4];
            *t_ptr.add(3) ^= tmp0.0[6];

            *t_ptr.add(4) ^= tmp1.0[0];
            *t_ptr.add(5) ^= tmp1.0[2];
            *t_ptr.add(6) ^= tmp1.0[4];
            *t_ptr.add(7) ^= tmp1.0[6];

            i = i.checked_add(8).expect("i cannot overflow len");
        }
    }

    // Handle remainder
    for idx in i..len {
        target[idx] ^= crate::reconcile::gf64::mul(term, source[idx]);
    }
}

#[cfg(all(target_arch = "x86_64", has_avx512_support))]
#[target_feature(enable = "avx512f,avx512bw,vpclmulqdq")]
#[allow(clippy::incompatible_msrv)]
#[cfg_attr(all(coverage_nightly, not(has_avx512_host_support)), coverage(off))]
// SAFETY: Only called by `Avx512Evaluator::poly_mac` which enforces CPU feature constraints.
unsafe fn gf64_mul_x4_avx512(a: __m512i, b: __m512i) -> __m512i {
    let product = _mm512_clmulepi64_epi128(a, b, 0x00);
    let high = _mm512_bsrli_epi128::<8>(product);

    let mut reduced = _mm512_xor_si512(product, high);
    reduced = _mm512_xor_si512(reduced, _mm512_slli_epi64::<1>(high));
    reduced = _mm512_xor_si512(reduced, _mm512_slli_epi64::<3>(high));
    reduced = _mm512_xor_si512(reduced, _mm512_slli_epi64::<4>(high));

    // `high << 1/3/4` can themselves carry past bit 63 (whenever `high`'s top
    // nibble is set), and `_mm512_slli_epi64` truncates those bits instead of
    // carrying them into a wider lane. Fold that second-order overflow back
    // through `REDUCTION` before masking, mirroring the scalar `mul_pclmul`
    // reduction loop above.
    let overflow = _mm512_xor_si512(
        _mm512_xor_si512(_mm512_srli_epi64::<63>(high), _mm512_srli_epi64::<61>(high)),
        _mm512_srli_epi64::<60>(high),
    );
    let mut correction = _mm512_xor_si512(overflow, _mm512_slli_epi64::<1>(overflow));
    correction = _mm512_xor_si512(correction, _mm512_slli_epi64::<3>(overflow));
    correction = _mm512_xor_si512(correction, _mm512_slli_epi64::<4>(overflow));
    reduced = _mm512_xor_si512(reduced, correction);

    let low_mask = _mm512_set_epi64(0, -1, 0, -1, 0, -1, 0, -1);
    _mm512_and_si512(reduced, low_mask)
}

#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy)]
pub struct SseEvaluator;

#[cfg(target_arch = "x86_64")]
impl Gf64Evaluator for SseEvaluator {
    fn poly_mac(term: u64, source: &[u64], target: &mut [u64]) {
        // We could manually unroll PCLMULQDQ here, but for now we fall back to
        // `ScalarEvaluator`, whose per-coefficient multiply is already
        // hardware-accelerated with PCLMULQDQ via `gf64::mul`.
        ScalarEvaluator::poly_mac(term, source, target);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvaluatorBackend {
    Scalar,
    #[cfg(target_arch = "x86_64")]
    Sse,
    #[cfg(all(target_arch = "x86_64", has_avx512_support))]
    Avx512,
}

#[cfg(all(feature = "std", target_arch = "x86_64"))]
static BACKEND: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

#[cfg(all(feature = "std", target_arch = "x86_64"))]
fn get_evaluator_with_cache(cache: &core::sync::atomic::AtomicU8) -> EvaluatorBackend {
    use core::sync::atomic::Ordering;

    let val = cache.load(Ordering::Relaxed);
    if val != 0 {
        return cached_evaluator(val, EvaluatorBackend::Scalar);
    }

    let backend = get_evaluator_internal();
    let encoded = encode_backend(backend);
    // Only the thread that wins initialization emits the diagnostic. Other
    // concurrent callers use the winner's cached backend and must not repeat
    // the scalar warning.
    if cache
        .compare_exchange(0, encoded, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        let cached = cache.load(Ordering::Acquire);
        return cached_evaluator(cached, backend);
    }
    warn_if_scalar(backend);
    backend
}

#[cfg(all(feature = "std", target_arch = "x86_64"))]
#[must_use]
pub fn get_evaluator() -> EvaluatorBackend {
    get_evaluator_with_cache(&BACKEND)
}

#[cfg(all(feature = "std", target_arch = "x86_64"))]
fn cached_evaluator(cached: u8, fallback: EvaluatorBackend) -> EvaluatorBackend {
    match cached {
        1 => EvaluatorBackend::Scalar,
        2 => EvaluatorBackend::Sse,
        #[cfg(has_avx512_support)]
        3 => EvaluatorBackend::Avx512,
        _ => fallback,
    }
}

#[cfg(all(feature = "std", target_arch = "x86_64"))]
fn encode_backend(backend: EvaluatorBackend) -> u8 {
    match backend {
        EvaluatorBackend::Scalar => 1,
        EvaluatorBackend::Sse => 2,
        #[cfg(has_avx512_support)]
        EvaluatorBackend::Avx512 => 3,
    }
}

#[cfg(all(feature = "std", target_arch = "x86_64"))]
const SCALAR_EVALUATOR_WARNING: &str =
    "rezzy: WARN: GF64 non-SIMD (scalar) evaluator in use; PCLMULQDQ/AVX-512 not detected on this CPU";

#[cfg(all(feature = "std", target_arch = "x86_64", test))]
fn write_scalar_evaluator_warning<W: core::fmt::Write>(out: &mut W) {
    let _ = out.write_str(SCALAR_EVALUATOR_WARNING);
}

#[cfg(all(feature = "std", target_arch = "x86_64"))]
fn warn_scalar_evaluator() {
    // Ignore stderr write errors — this is a diagnostic, not a correctness path.
    let _ = writeln!(std::io::stderr(), "{SCALAR_EVALUATOR_WARNING}");
}

#[cfg(all(feature = "std", target_arch = "x86_64", test))]
fn warn_if_scalar_to<W: core::fmt::Write>(backend: EvaluatorBackend, out: &mut W) {
    if matches!(backend, EvaluatorBackend::Scalar) {
        write_scalar_evaluator_warning(out);
    }
}

#[cfg(all(feature = "std", target_arch = "x86_64"))]
fn warn_if_scalar(backend: EvaluatorBackend) {
    if matches!(backend, EvaluatorBackend::Scalar) {
        warn_scalar_evaluator();
    }
}

#[cfg(any(not(feature = "std"), not(target_arch = "x86_64")))]
#[must_use]
pub fn get_evaluator() -> EvaluatorBackend {
    EvaluatorBackend::Scalar
}

#[cfg(all(feature = "std", target_arch = "x86_64"))]
fn get_evaluator_internal() -> EvaluatorBackend {
    let (has_avx512, has_pclmul) = get_evaluator_features();
    select_evaluator_backend(has_avx512, has_pclmul)
}

#[cfg(all(feature = "std", target_arch = "x86_64"))]
#[cfg_attr(all(coverage_nightly, not(has_avx512_host_support)), coverage(off))]
fn get_evaluator_features() -> (bool, bool) {
    #[cfg(has_avx512_support)]
    let has_avx512 = std::is_x86_feature_detected!("avx512f")
        && std::is_x86_feature_detected!("avx512bw")
        && std::is_x86_feature_detected!("vpclmulqdq");
    #[cfg(not(has_avx512_support))]
    let has_avx512 = false;
    let has_pclmul = std::is_x86_feature_detected!("pclmulqdq");
    (has_avx512, has_pclmul)
}

#[cfg(all(feature = "std", target_arch = "x86_64", has_avx512_support))]
fn select_evaluator_backend(has_avx512: bool, has_pclmul: bool) -> EvaluatorBackend {
    if has_avx512 {
        EvaluatorBackend::Avx512
    } else if has_pclmul {
        EvaluatorBackend::Sse
    } else {
        EvaluatorBackend::Scalar
    }
}

#[cfg(all(feature = "std", target_arch = "x86_64", not(has_avx512_support)))]
fn select_evaluator_backend(_has_avx512: bool, has_pclmul: bool) -> EvaluatorBackend {
    if has_pclmul {
        EvaluatorBackend::Sse
    } else {
        EvaluatorBackend::Scalar
    }
}

#[cfg(test)]
#[cfg(not(tarpaulin_include))]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use alloc::{string::String, vec::Vec};

    #[cfg(all(feature = "std", target_arch = "x86_64", not(has_avx512_support)))]
    #[test]
    fn select_evaluator_backend_prefers_sse_then_scalar() {
        assert_eq!(select_evaluator_backend(true, true), EvaluatorBackend::Sse);
        assert_eq!(select_evaluator_backend(false, true), EvaluatorBackend::Sse);
        assert_eq!(
            select_evaluator_backend(false, false),
            EvaluatorBackend::Scalar
        );
    }

    #[cfg(all(target_arch = "x86_64", has_avx512_support))]
    #[test]
    fn select_evaluator_backend_prefers_avx512_when_available() {
        assert_eq!(
            select_evaluator_backend(true, true),
            EvaluatorBackend::Avx512
        );
        assert_eq!(select_evaluator_backend(false, true), EvaluatorBackend::Sse);
        assert_eq!(
            select_evaluator_backend(false, false),
            EvaluatorBackend::Scalar
        );
    }

    #[test]
    fn test_evaluators_match_scalar() {
        let _ = get_evaluator();
        let term = 0x8000_0000_0000_0000;
        let source: Vec<u64> = (0..20_u64).map(|i| i * 0x0123_4567_89ab_cdef).collect();
        let mut expected = alloc::vec![0u64; 20];
        ScalarEvaluator::poly_mac(term, &source, &mut expected);

        #[cfg(target_arch = "x86_64")]
        {
            if std::is_x86_feature_detected!("pclmulqdq") {
                let mut target_sse = alloc::vec![0u64; 20];
                SseEvaluator::poly_mac(term, &source, &mut target_sse);
                assert_eq!(target_sse, expected, "SseEvaluator results mismatch");
            }
        }

        #[cfg(all(target_arch = "x86_64", has_avx512_support))]
        {
            if std::is_x86_feature_detected!("avx512f")
                && std::is_x86_feature_detected!("avx512bw")
                && std::is_x86_feature_detected!("vpclmulqdq")
            {
                let mut target_avx = alloc::vec![0u64; 20];
                Avx512Evaluator::poly_mac(term, &source, &mut target_avx);
                assert_eq!(target_avx, expected, "Avx512Evaluator results mismatch");
            }
        }
    }

    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    #[test]
    fn cached_backend_values_decode_with_the_requested_fallback() {
        assert_eq!(
            cached_evaluator(1, EvaluatorBackend::Sse),
            EvaluatorBackend::Scalar
        );
        assert_eq!(
            cached_evaluator(2, EvaluatorBackend::Scalar),
            EvaluatorBackend::Sse
        );
        assert_eq!(
            cached_evaluator(255, EvaluatorBackend::Sse),
            EvaluatorBackend::Sse
        );
        #[cfg(has_avx512_support)]
        assert_eq!(
            cached_evaluator(3, EvaluatorBackend::Scalar),
            EvaluatorBackend::Avx512
        );
    }

    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    #[test]
    fn evaluator_backends_encode_to_cache_values() {
        assert_eq!(encode_backend(EvaluatorBackend::Scalar), 1);
        assert_eq!(encode_backend(EvaluatorBackend::Sse), 2);
        #[cfg(has_avx512_support)]
        assert_eq!(encode_backend(EvaluatorBackend::Avx512), 3);
    }

    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    #[test]
    fn scalar_backend_warning_is_emitted() {
        let mut warning = String::new();
        warn_if_scalar_to(EvaluatorBackend::Scalar, &mut warning);
        assert_eq!(warning, SCALAR_EVALUATOR_WARNING);
        warning.clear();
        warn_if_scalar_to(EvaluatorBackend::Sse, &mut warning);
        assert_eq!(warning, "");
    }

    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    #[test]
    fn warning_writer_matches_the_real_scalar_warning() {
        warn_scalar_evaluator();
    }

    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    #[test]
    fn concurrent_initialization_uses_the_acquire_cached_backend() {
        use std::sync::Barrier;

        let test_cache = core::sync::atomic::AtomicU8::new(0);
        let cache_ref = &test_cache;
        let barrier = std::sync::Arc::new(Barrier::new(16));
        std::thread::scope(|scope| {
            for _ in 0..15 {
                let barrier = std::sync::Arc::clone(&barrier);
                scope.spawn(move || {
                    barrier.wait();
                    let _ = get_evaluator_with_cache(cache_ref);
                });
            }
            barrier.wait();
            let _ = get_evaluator_with_cache(cache_ref);
        });
        assert_ne!(test_cache.load(core::sync::atomic::Ordering::Acquire), 0);
    }

    /// Regression test for a missing second-order field reduction in
    /// `gf64_mul_x4_avx512`: the first XOR-fold of `high << {1,3,4}` can
    /// itself carry past bit 63 whenever `high`'s top nibble is set, and
    /// `_mm512_slli_epi64` truncates rather than carries those bits. That
    /// dropped carry produced wrong products (and, transitively, wrong
    /// `PinSketch` syndromes / bogus `DecodeFailure`s) on any host where the
    /// AVX-512 backend was actually selected. `0..20` sequential inputs, as
    /// used by `test_evaluators_match_scalar` above, don't happen to trigger
    /// it, so this test drives many random and top-nibble-heavy operands
    /// directly through `gf64_mul_x4_avx512` and checks each lane against
    /// the known-correct scalar `mul_bitwise` reference.
    #[cfg(all(target_arch = "x86_64", has_avx512_support))]
    #[test]
    fn avx512_mul_matches_scalar_for_high_bit_heavy_operands() {
        use core::arch::x86_64::{_mm512_set_epi64, _mm512_store_si512};

        if !(std::is_x86_feature_detected!("avx512f")
            && std::is_x86_feature_detected!("avx512bw")
            && std::is_x86_feature_detected!("vpclmulqdq"))
        {
            return;
        }

        // Fixed patterns known to set the top nibble of the carry-less
        // product's high half, which is exactly what the dropped
        // second-order reduction mishandled.
        let fixed: &[u64] = &[
            0,
            1,
            u64::MAX,
            1_u64 << 63,
            0x8000_0000_0000_0001,
            0xF000_0000_0000_0000,
            0xFFFF_FFFF_0000_0000,
        ];

        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let random: alloc::vec::Vec<u64> = (0..512).map(|_| next()).collect();

        let operands: alloc::vec::Vec<u64> = fixed.iter().copied().chain(random).collect();

        for &a in &operands {
            for &b in &operands
                .iter()
                .step_by(37)
                .copied()
                .collect::<alloc::vec::Vec<_>>()
            {
                let expected = crate::reconcile::gf64::mul_bitwise(a, b);

                // SAFETY: gated on the same runtime feature checks used by
                // `get_evaluator_internal`; a single-lane call is sufficient
                // to exercise the reduction logic.
                let actual = unsafe {
                    let av = i64::from_ne_bytes(a.to_ne_bytes());
                    let bv = i64::from_ne_bytes(b.to_ne_bytes());
                    let va = _mm512_set_epi64(0, av, 0, av, 0, av, 0, av);
                    let vb = _mm512_set_epi64(0, bv, 0, bv, 0, bv, 0, bv);
                    let result = gf64_mul_x4_avx512(va, vb);
                    let mut out = AlignedArray([0u64; 8]);
                    _mm512_store_si512(core::ptr::addr_of_mut!(out).cast(), result);
                    out.0[0]
                };

                assert_eq!(
                    actual, expected,
                    "gf64_mul_x4_avx512({a:#x}, {b:#x}) mismatch"
                );
            }
        }
    }
}
