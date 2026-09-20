// Copyright 2026 Shane Jaroch
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//! Arithmetic for the MSC4521 minisketch-compatible binary field.

/// Reduction polynomial without its implicit `x^64` term.
const REDUCTION: u64 = 0x1b;

/// Portable constant-time carry-less multiplication in
/// `GF(2)[x] / (x^64 + x^4 + x^3 + x + 1)`.
#[must_use]
pub fn mul_bitwise(mut left: u64, mut right: u64) -> u64 {
    let mut product = 0;
    for _ in 0..64 {
        product ^= left & 0_u64.wrapping_sub(right & 1);
        right >>= 1;

        let carry = left >> 63;
        left <<= 1;
        left ^= REDUCTION & 0_u64.wrapping_sub(carry);
    }
    product
}

/// Multiplies two elements of the MSC4521 64-bit binary field.
///
/// Uses the portable fallback unless a target-specific accelerated implementation is enabled.
#[must_use]
#[cfg(all(feature = "std", any(target_arch = "x86", target_arch = "x86_64")))]
#[allow(unsafe_code)]
pub fn mul(left: u64, right: u64) -> u64 {
    // SAFETY: accelerated_mul selects the intrinsic only after runtime feature
    // detection and otherwise returns the portable implementation.
    unsafe { accelerated_mul()(left, right) }
}

#[must_use]
#[cfg(not(all(feature = "std", any(target_arch = "x86", target_arch = "x86_64"))))]
pub fn mul(left: u64, right: u64) -> u64 {
    mul_bitwise(left, right)
}

#[cfg(all(feature = "std", any(target_arch = "x86", target_arch = "x86_64")))]
fn accelerated_mul() -> unsafe fn(u64, u64) -> u64 {
    use std::sync::OnceLock;

    static IMPLEMENTATION: OnceLock<unsafe fn(u64, u64) -> u64> = OnceLock::new();
    *IMPLEMENTATION.get_or_init(|| {
        let mut func: unsafe fn(u64, u64) -> u64 = mul_portable;
        if std::is_x86_feature_detected!("pclmulqdq") {
            // SAFETY: the function is only selected when the CPU advertises
            // the required instruction set.
            func = mul_pclmul;
        }
        func
    })
}

#[cfg(all(feature = "std", any(target_arch = "x86", target_arch = "x86_64")))]
#[allow(unsafe_code)]
unsafe fn mul_portable(left: u64, right: u64) -> u64 {
    mul_bitwise(left, right)
}

#[cfg(all(feature = "std", any(target_arch = "x86", target_arch = "x86_64")))]
#[target_feature(enable = "pclmulqdq")]
#[allow(unsafe_code)]
unsafe fn mul_pclmul(left: u64, right: u64) -> u64 {
    #[cfg(target_arch = "x86")]
    use core::arch::x86::{_mm_clmulepi64_si128, _mm_set_epi64x, _mm_storeu_si128};
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::{_mm_clmulepi64_si128, _mm_set_epi64x, _mm_storeu_si128};

    let left = _mm_set_epi64x(0, i64::from_ne_bytes(left.to_ne_bytes()));
    let right = _mm_set_epi64x(0, i64::from_ne_bytes(right.to_ne_bytes()));
    let low = _mm_clmulepi64_si128(left, right, 0x00);
    let mut low_word = [0_u64; 2];
    _mm_storeu_si128(low_word.as_mut_ptr().cast(), low);
    let high = low_word[1];
    // Since x^64 = x^4 + x^3 + x + 1, fold the high half directly into the
    // low half. Only four overflow bits remain and need a final reduction.
    let mut product = u128::from(low_word[0])
        ^ (u128::from(high) << 4)
        ^ (u128::from(high) << 3)
        ^ (u128::from(high) << 1)
        ^ u128::from(high);
    for bit in (64_usize..68).rev() {
        if (product >> bit) & 1 != 0 {
            let offset = bit.wrapping_sub(64);
            product ^= 1_u128 << bit;
            product ^= u128::from(REDUCTION) << offset;
        }
    }
    u64::try_from(product).expect("field reduction clears the upper bits")
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn reduction_sensitive_vectors_match_minisketch() {
        assert_eq!(mul(0, u64::MAX), 0);
        assert_eq!(mul(1, u64::MAX), u64::MAX);
        assert_eq!(mul(0x1b, 0x1b), 0x145);
        assert_eq!(mul(u64::MAX, u64::MAX), 0x5555_5555_5555_5513);
        assert_eq!(mul(1_u64 << 63, 1_u64 << 63), 0xc000_0000_0000_005a);
    }

    #[test]
    fn multiplication_is_distributive() {
        let mut state = 0x6a09_e667_f3bc_c909_u64;
        for _ in 0..256 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let left = state;
            state = state.rotate_left(23) ^ 0x9e37_79b9_7f4a_7c15;
            let right = state;
            state = state.rotate_right(11) ^ 0x3c6e_f372_fe94_f82b;
            let addend = state;
            assert_eq!(
                mul(left, right ^ addend),
                mul(left, right) ^ mul(left, addend)
            );
        }
    }

    #[test]
    fn mul_bitwise_matches_mul() {
        let mut state = 0x6a09_e667_f3bc_c909_u64;
        for _ in 0..256 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let left = state;
            state = state.rotate_left(23) ^ 0x9e37_79b9_7f4a_7c15;
            let right = state;
            assert_eq!(mul_bitwise(left, right), mul(left, right));
        }
    }

    #[test]
    #[cfg(all(feature = "std", any(target_arch = "x86", target_arch = "x86_64")))]
    #[allow(unsafe_code)]
    fn mul_portable_matches_mul() {
        let mut state = 0x6a09_e667_f3bc_c909_u64;
        for _ in 0..256 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let left = state;
            state = state.rotate_left(23) ^ 0x9e37_79b9_7f4a_7c15;
            let right = state;
            // SAFETY: The portable implementation does not actually rely on any hardware features.
            assert_eq!(unsafe { mul_portable(left, right) }, mul(left, right));
        }
    }
}
