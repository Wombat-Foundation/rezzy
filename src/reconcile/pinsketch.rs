// Copyright 2026 Shane Jaroch
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//! `PinSketch` decoding over the MSC4521 GF(2^64) profile.

use alloc::{vec, vec::Vec};

use crate::reconcile::gf64_simd::Gf64Evaluator;

use super::algebraic::{gf64_mul, AlgebraicError};

type Polynomial = Vec<u64>;

const FIELD_BITS: usize = 64;
const MIXED_FACTOR_TRIALS: usize = 8;
const FACTOR_TRIALS: usize = MIXED_FACTOR_TRIALS + FIELD_BITS;
const FACTOR_PARAMETER_SEED: u64 = 0x9e37_79b9_7f4a_7c15;
// Only the test-only reference `trace_mod` still uses this directly; the
// production path (`build_frobenius_basis`) derives the same round count
// from `FIELD_BITS - 1`.
#[cfg(test)]
const TRACE_SQUARES: usize = 63;
// KNOWN GAP, still open: this covers observed *balanced* recursive
// splitting, not a proven worst case. Per node, cost is roughly
// `frobenius_basis_cost + factor_trial_cost_with_basis` for the first
// (successful) trial, i.e. ~65*d^2. Summed over a balanced split tree
// that's ~130*d^2, which at d=256 is ~8.5M -- matching the measured
// 9.2-9.4M (across both adversarial-consecutive-value and random input
// shapes) that this constant leaves ~1.7x headroom over. But equal-degree
// splitting does not guarantee a balanced tree: a degenerate chain of
// (1, d-1) splits sums to `65 * sum_{k=2}^{d} k^2`, which at d=256 is
// ~363M, roughly 40x this budget. Random locators split near-binomially
// in practice, so this is not something a benchmark will surface, and it
// fails safe into `BudgetExhausted` (routing to the same fallback ladder
// callers already handle) rather than corrupting anything -- but "degree
// 256 is decodable within MAX_FACTOR_WORK" is a statement about typical
// inputs, not a bound. A real worst-case bound on the recursion, or a
// balance guarantee on the splitting itself, would be needed to close
// this properly.
const MAX_FACTOR_WORK: usize = 16_000_000;

pub(crate) fn decode(
    odd_syndromes: &[u64],
    max_elements: usize,
) -> Result<Vec<u64>, AlgebraicError> {
    let all = reconstruct_syndromes(odd_syndromes);
    let mut locator = berlekamp_massey(&all, max_elements).ok_or(AlgebraicError::DecodeFailure)?;
    if locator.len() == 1 {
        return Ok(Vec::new());
    }
    locator.reverse();
    let expected = locator
        .len()
        .checked_sub(1)
        .ok_or(AlgebraicError::DecodeFailure)?;
    let mut roots = Vec::with_capacity(expected);
    find_roots(locator, &mut roots)?;
    if roots.len() != expected || roots.contains(&0) {
        return Err(AlgebraicError::DecodeFailure);
    }
    roots.sort_unstable();
    Ok(roots)
}

/// Like [`decode`], but draws factoring work from `budget` and leaves the
/// unspent remainder in it, so a caller decoding multiple sketches can share
/// one budget across all of them instead of each call getting its own
/// implicit ceiling.
pub(crate) fn decode_with_budget(
    odd_syndromes: &[u64],
    max_elements: usize,
    budget: &mut usize,
) -> Result<Vec<u64>, AlgebraicError> {
    let all = reconstruct_syndromes(odd_syndromes);
    let mut locator = berlekamp_massey(&all, max_elements).ok_or(AlgebraicError::DecodeFailure)?;
    if locator.len() == 1 {
        return Ok(Vec::new());
    }
    locator.reverse();
    let expected = locator
        .len()
        .checked_sub(1)
        .ok_or(AlgebraicError::DecodeFailure)?;
    let mut roots = Vec::with_capacity(expected);
    find_roots_with_budget(locator, &mut roots, budget)?;
    if roots.len() != expected || roots.contains(&0) {
        return Err(AlgebraicError::DecodeFailure);
    }
    roots.sort_unstable();
    Ok(roots)
}

fn reconstruct_syndromes(odd: &[u64]) -> Vec<u64> {
    let mut all = vec![0; odd.len().saturating_mul(2)];
    for (index, value) in odd.iter().copied().enumerate() {
        all[index.saturating_mul(2)] = value;
        // Earlier iterations have already reconstructed the source at `index`.
        all[index.saturating_mul(2).saturating_add(1)] = gf64_mul(all[index], all[index]);
    }
    all
}

fn berlekamp_massey(syndromes: &[u64], max_degree: usize) -> Option<Polynomial> {
    let mut current = vec![1];
    let mut previous = vec![1];
    let mut previous_discrepancy = 1;

    for (n, syndrome) in syndromes.iter().copied().enumerate() {
        let mut discrepancy = syndrome;
        for (i, coefficient) in current.iter().copied().enumerate().skip(1) {
            let Some(syndrome_index) = n.checked_sub(i) else {
                continue;
            };
            discrepancy ^= gf64_mul(syndromes[syndrome_index], coefficient);
        }
        if discrepancy == 0 {
            continue;
        }

        let current_degree = current.len().checked_sub(1)?;
        let previous_degree = previous.len().checked_sub(1)?;
        let shift = n
            .checked_add(1)?
            .checked_sub(current_degree)?
            .checked_sub(previous_degree)?;
        let swap = current_degree.checked_mul(2)? <= n;
        let old_current = current.clone();
        if swap {
            let new_len = previous.len().checked_add(shift)?;
            if new_len.checked_sub(1)? > max_degree {
                return None;
            }
            current.resize(new_len, 0);
        }
        let scale = gf64_mul(discrepancy, gf64_inv(previous_discrepancy)?);
        for (i, coefficient) in previous.iter().copied().enumerate() {
            let target = i.checked_add(shift)?;
            current[target] ^= gf64_mul(scale, coefficient);
        }
        if swap {
            previous = old_current;
            previous_discrepancy = discrepancy;
        }
    }
    (current.last().copied().unwrap_or(0) != 0).then_some(current)
}

fn gf64_inv(value: u64) -> Option<u64> {
    if value == 0 {
        return None;
    }
    // a^(2^64-2), using a fixed square-and-multiply schedule.
    let mut result = 1;
    let exponent = u64::MAX - 1;
    for bit in (0..64).rev() {
        result = gf64_mul(result, result);
        if exponent & (1_u64 << bit) != 0 {
            result = gf64_mul(result, value);
        }
    }
    Some(result)
}

fn trim(poly: &mut Polynomial) {
    while poly.last() == Some(&0) {
        poly.pop();
    }
}

fn make_monic(poly: &mut Polynomial) -> Option<()> {
    let leading = *poly.last()?;
    if leading == 1 {
        return Some(());
    }
    let inverse = gf64_inv(leading)?;
    for coefficient in poly {
        *coefficient = gf64_mul(*coefficient, inverse);
    }
    Some(())
}

fn poly_mod(modulus: &[u64], value: &mut Polynomial) -> Option<()> {
    let modulus_degree = modulus.len().checked_sub(1)?;
    if modulus.last() != Some(&1) {
        return None;
    }
    let evaluator = crate::reconcile::gf64_simd::get_evaluator();
    while value.len() >= modulus.len() {
        let term = value.pop()?;
        if term != 0 {
            let offset = value.len().checked_sub(modulus_degree)?;
            let target = &mut value[offset..offset.checked_add(modulus_degree)?];
            let source = &modulus[..modulus_degree];

            match evaluator {
                #[cfg(all(target_arch = "x86_64", has_avx512_support))]
                crate::reconcile::gf64_simd::EvaluatorBackend::Avx512 => {
                    crate::reconcile::gf64_simd::Avx512Evaluator::poly_mac(term, source, target);
                }
                #[cfg(target_arch = "x86_64")]
                crate::reconcile::gf64_simd::EvaluatorBackend::Sse => {
                    crate::reconcile::gf64_simd::SseEvaluator::poly_mac(term, source, target);
                }
                crate::reconcile::gf64_simd::EvaluatorBackend::Scalar => {
                    crate::reconcile::gf64_simd::ScalarEvaluator::poly_mac(term, source, target);
                }
            }
        }
    }
    trim(value);
    Some(())
}

fn poly_div(mut dividend: Polynomial, divisor: &[u64]) -> Option<Polynomial> {
    if divisor.last() != Some(&1) || dividend.len() < divisor.len() {
        return None;
    }
    let mut quotient = vec![0; dividend.len().checked_sub(divisor.len())?.checked_add(1)?];
    let divisor_degree = divisor.len().checked_sub(1)?;
    let evaluator = crate::reconcile::gf64_simd::get_evaluator();
    while dividend.len() >= divisor.len() {
        let term = dividend.pop()?;
        let position = dividend.len().checked_sub(divisor_degree)?;
        quotient[position] = term;
        if term != 0 {
            let target = &mut dividend[position..position.checked_add(divisor_degree)?];
            let source = &divisor[..divisor_degree];

            match evaluator {
                #[cfg(all(target_arch = "x86_64", has_avx512_support))]
                crate::reconcile::gf64_simd::EvaluatorBackend::Avx512 => {
                    crate::reconcile::gf64_simd::Avx512Evaluator::poly_mac(term, source, target);
                }
                #[cfg(target_arch = "x86_64")]
                crate::reconcile::gf64_simd::EvaluatorBackend::Sse => {
                    crate::reconcile::gf64_simd::SseEvaluator::poly_mac(term, source, target);
                }
                crate::reconcile::gf64_simd::EvaluatorBackend::Scalar => {
                    crate::reconcile::gf64_simd::ScalarEvaluator::poly_mac(term, source, target);
                }
            }
        }
    }
    trim(&mut quotient);
    Some(quotient)
}

fn poly_gcd(mut left: Polynomial, mut right: Polynomial) -> Option<Polynomial> {
    if left.len() < right.len() {
        core::mem::swap(&mut left, &mut right);
    }
    while !right.is_empty() {
        make_monic(&mut right)?;
        poly_mod(&right, &mut left)?;
        core::mem::swap(&mut left, &mut right);
    }
    make_monic(&mut left)?;
    Some(left)
}

fn poly_square(poly: &mut Polynomial) -> Option<()> {
    if poly.is_empty() {
        return Some(());
    }
    let new_len = poly.len().checked_mul(2)?.checked_sub(1)?;
    let old = core::mem::take(poly);
    poly.resize(new_len, 0);
    for (target, coefficient) in (0..new_len).step_by(2).zip(old) {
        poly[target] = gf64_mul(coefficient, coefficient);
    }
    Some(())
}

/// Naive reference implementation of `Tr(parameter * X) mod modulus`,
/// re-deriving the full squaring recurrence from scratch for every
/// `parameter`. Cost is `O(TRACE_SQUARES * degree^2)` *per call*. Superseded
/// in the production path by `build_frobenius_basis` +
/// `trace_from_basis`, which amortize the squaring recurrence across every
/// trial for a given `modulus` instead of repeating it per trial (see that
/// pair's doc comments). Kept as a test-only cross-check that the
/// precomputed path computes the same trace.
#[cfg(test)]
fn trace_mod(modulus: &[u64], parameter: u64) -> Option<Polynomial> {
    let mut trace = vec![0, parameter];
    for _ in 0..TRACE_SQUARES {
        poly_square(&mut trace)?;
        if trace.len() < 2 {
            trace.resize(2, 0);
        }
        trace[1] = parameter;
        poly_mod(modulus, &mut trace)?;
    }
    Some(trace)
}

/// One-time-per-polynomial precomputation consumed by `trace_from_basis`:
/// the images `X^(2^0), X^(2^1), ..., X^(2^63) mod modulus`.
///
/// Squaring is GF(2)-linear in characteristic 2 (`(a+b)^2 = a^2+b^2`), so
/// `(parameter*X)^(2^i) = parameter^(2^i) * X^(2^i)` -- the trace
/// `sum_i (parameter*X)^(2^i) mod modulus` decomposes into
/// `sum_i parameter^(2^i) * B_i`, where `B_i = X^(2^i) mod modulus` does not
/// depend on `parameter` at all. Building this basis once per polynomial and
/// reusing it across every trial in `find_roots_with_budget`'s ladder turns
/// each trial's dominant cost from `O(TRACE_SQUARES * degree^2)` (the naive
/// `trace_mod`, repeating the squaring-and-reduce recurrence per trial) into
/// `O(FIELD_BITS * degree)` for the linear combination, leaving only the
/// unavoidable `O(degree^2)` GCD/division per trial. See
/// `frobenius_basis_cost` and `factor_trial_cost_with_basis`.
fn build_frobenius_basis(modulus: &[u64]) -> Option<Vec<Polynomial>> {
    let mut basis = Vec::with_capacity(FIELD_BITS);
    let mut current = vec![0, 1]; // X
    poly_mod(modulus, &mut current)?;
    basis.push(current.clone());
    for _ in 1..FIELD_BITS {
        poly_square(&mut current)?;
        poly_mod(modulus, &mut current)?;
        basis.push(current.clone());
    }
    Some(basis)
}

/// Computes `Tr(parameter * X) mod modulus` from a basis built by
/// `build_frobenius_basis` for the same `modulus`.
fn trace_from_basis(basis: &[Polynomial], parameter: u64) -> Polynomial {
    let width = basis.iter().map(Vec::len).max().unwrap_or(0);
    let mut trace = vec![0_u64; width];
    let mut power = parameter;
    for basis_term in basis {
        if power != 0 {
            for (coefficient, term) in trace.iter_mut().zip(basis_term.iter()) {
                *coefficient ^= gf64_mul(power, *term);
            }
        }
        power = gf64_mul(power, power);
    }
    trim(&mut trace);
    trace
}

const fn next_factor_parameter(mut state: u64) -> u64 {
    state ^= state << 13;
    state ^= state >> 7;
    state ^ (state << 17)
}

fn solve_quadratic_form(target: u64) -> Option<u64> {
    // Solve the GF(2)-linear map z -> z^2 + z using a reduced 64x65 matrix.
    #[derive(Clone, Copy)]
    struct Row {
        coefficients: u64,
        rhs: bool,
    }

    let mut rows = [Row {
        coefficients: 0,
        rhs: false,
    }; 64];
    for column in 0..64 {
        let basis = 1_u64 << column;
        let image = gf64_mul(basis, basis) ^ basis;
        for (row, equation) in rows.iter_mut().enumerate() {
            if image & (1_u64 << row) != 0 {
                equation.coefficients |= 1_u64 << column;
            }
        }
    }
    for (row, equation) in rows.iter_mut().enumerate() {
        if target & (1_u64 << row) != 0 {
            equation.rhs = true;
        }
    }

    let mut rank = 0;
    for column in 0..64 {
        let pivot = (rank..64).find(|row| rows[*row].coefficients & (1_u64 << column) != 0);
        let Some(pivot) = pivot else { continue };
        rows.swap(rank, pivot);
        let pivot_row = rows[rank];
        for (row, equation) in rows.iter_mut().enumerate() {
            if row != rank && equation.coefficients & (1_u64 << column) != 0 {
                equation.coefficients ^= pivot_row.coefficients;
                equation.rhs ^= pivot_row.rhs;
            }
        }
        rank = rank.checked_add(1)?;
    }
    if rows.iter().any(|row| row.coefficients == 0 && row.rhs) {
        return None;
    }
    let mut solution = 0_u64;
    for row in rows.iter().take(rank) {
        if row.coefficients == 0 {
            return None;
        }
        let pivot = row.coefficients.trailing_zeros();
        if row.rhs {
            solution |= 1_u64 << pivot;
        }
    }
    (gf64_mul(solution, solution) ^ solution == target).then_some(solution)
}

fn find_roots(poly: Polynomial, roots: &mut Vec<u64>) -> Result<(), AlgebraicError> {
    let mut work = MAX_FACTOR_WORK;
    find_roots_with_budget(poly, roots, &mut work)
}

/// One-time cost of `build_frobenius_basis` for a degree-`degree`
/// polynomial: `FIELD_BITS - 1` squaring+reduce rounds, each `O(degree^2)`
/// -- the same per-round cost the naive `trace_mod` paid per trial, now
/// paid once per recursion node instead.
fn frobenius_basis_cost(degree: usize) -> Option<usize> {
    degree
        .checked_mul(degree)?
        .checked_mul(FIELD_BITS.checked_sub(1)?)
}

/// Per-trial cost once the node's Frobenius basis is already built:
/// `O(FIELD_BITS * degree)` for `trace_from_basis`'s linear combination,
/// plus `O(degree^2)` for `poly_gcd` (which runs a `poly_mod` internally)
/// and `O(degree^2)` for `poly_div` on a successful split. The GCD and
/// division terms are both charged unconditionally, even on trials that
/// don't split, to keep this a safe upper bound rather than an average.
fn factor_trial_cost_with_basis(degree: usize) -> Option<usize> {
    let trace_cost = FIELD_BITS.checked_mul(degree)?;
    let gcd_cost = degree.checked_mul(degree)?;
    let div_cost = degree.checked_mul(degree)?;
    trace_cost.checked_add(gcd_cost)?.checked_add(div_cost)
}

/// Upper bound on the work one `find_roots_with_budget` call can need for a
/// locator of degree `degree`, covering the basis build plus a full
/// `FACTOR_TRIALS`-trial ladder at that degree alone.
///
/// This deliberately does **not** try to bound the cost of the recursive
/// splits below the root -- that recursion has no proven worst-case bound
/// (see `MAX_FACTOR_WORK`'s comment). It exists so a caller decoding many
/// sketches under one shared budget (`triage::decode_bucket_sketches`) can
/// clamp how much of that shared budget any single sketch's decode is
/// allowed to draw, so one pathological sketch can't starve the rest of a
/// batch by exhausting the shared pool before later, cheaper sketches are
/// even attempted. A sketch whose own recursion exceeds this ceiling will
/// simply hit `BudgetExhausted` for its own allotment -- which is the
/// intended outcome here, not a bug in this bound.
pub(crate) fn single_call_work_ceiling(degree: usize) -> Option<usize> {
    let basis = frobenius_basis_cost(degree)?;
    let ladder = factor_trial_cost_with_basis(degree)?.checked_mul(FACTOR_TRIALS)?;
    basis.checked_add(ladder)
}

fn find_roots_with_budget(
    poly: Polynomial,
    roots: &mut Vec<u64>,
    work: &mut usize,
) -> Result<(), AlgebraicError> {
    let mut pending = vec![poly];
    while let Some(poly) = pending.pop() {
        let degree = poly
            .len()
            .checked_sub(1)
            .ok_or(AlgebraicError::DecodeFailure)?;
        if degree == 0 {
            continue;
        }
        if degree == 1 {
            roots.push(poly[0]);
            continue;
        }
        if degree == 2 {
            let linear = poly[1];
            if linear == 0 {
                return Err(AlgebraicError::DecodeFailure);
            }
            let inverse = gf64_inv(linear).ok_or(AlgebraicError::DecodeFailure)?;
            let normalized = gf64_mul(poly[0], gf64_mul(inverse, inverse));
            let root = gf64_mul(
                solve_quadratic_form(normalized).ok_or(AlgebraicError::DecodeFailure)?,
                linear,
            );
            roots.push(root);
            roots.push(root ^ linear);
            continue;
        }

        let basis_cost = frobenius_basis_cost(degree).ok_or(AlgebraicError::DecodeFailure)?;
        *work = work
            .checked_sub(basis_cost)
            .ok_or(AlgebraicError::BudgetExhausted)?;
        let basis = build_frobenius_basis(&poly).ok_or(AlgebraicError::DecodeFailure)?;

        let mut split = None;
        let mut parameter = FACTOR_PARAMETER_SEED;
        for trial in 0..FACTOR_TRIALS {
            if trial >= MIXED_FACTOR_TRIALS {
                let basis_bit = trial
                    .checked_sub(MIXED_FACTOR_TRIALS)
                    .ok_or(AlgebraicError::DecodeFailure)?;
                let basis_bit =
                    u32::try_from(basis_bit).map_err(|_| AlgebraicError::DecodeFailure)?;
                parameter = 1_u64
                    .checked_shl(basis_bit)
                    .ok_or(AlgebraicError::DecodeFailure)?;
            }
            let cost = factor_trial_cost_with_basis(degree).ok_or(AlgebraicError::DecodeFailure)?;
            *work = work
                .checked_sub(cost)
                .ok_or(AlgebraicError::BudgetExhausted)?;
            let trace = trace_from_basis(&basis, parameter);
            let factor = poly_gcd(poly.clone(), trace).ok_or(AlgebraicError::DecodeFailure)?;
            if factor.len() > 1 && factor.len() < poly.len() {
                let quotient = poly_div(poly, &factor).ok_or(AlgebraicError::DecodeFailure)?;
                split = Some((factor, quotient));
                break;
            }
            if trial < MIXED_FACTOR_TRIALS {
                parameter = next_factor_parameter(parameter);
            }
        }
        let (factor, quotient) = split.ok_or(AlgebraicError::DecodeFailure)?;
        pending.push(quotient);
        pending.push(factor);
    }
    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn inverses_roundtrip() {
        for value in [1, 2, 3, 0xdead_beef, u64::MAX] {
            assert_eq!(gf64_mul(value, gf64_inv(value).unwrap()), 1);
        }
    }

    #[test]
    fn decodes_small_sets() {
        for expected in [vec![1], vec![1, 2], vec![1, 2, 3], vec![1, 2, 3, 4]] {
            let mut odd = vec![0; expected.len()];
            for value in &expected {
                let squared = gf64_mul(*value, *value);
                let mut power = *value;
                for syndrome in &mut odd {
                    *syndrome ^= power;
                    power = gf64_mul(power, squared);
                }
            }
            assert_eq!(decode(&odd, expected.len()), Ok(expected));
        }
    }

    #[test]
    fn factors_a_quadratic() {
        let mut roots = Vec::new();
        find_roots(vec![gf64_mul(1, 2), 1 ^ 2, 1], &mut roots).unwrap();
        roots.sort_unstable();
        assert_eq!(roots, [1, 2]);
    }

    #[test]
    fn decodes_deterministic_varied_sets() {
        let mut state = 0x6a09_e667_f3bc_c909_u64;
        for size in (1..=24).chain([32, 64]) {
            let mut expected = Vec::new();
            while expected.len() < size {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                if state != 0 && !expected.contains(&state) {
                    expected.push(state);
                }
            }
            expected.sort_unstable();
            let mut odd = vec![0; size];
            for value in &expected {
                let squared = gf64_mul(*value, *value);
                let mut power = *value;
                for syndrome in &mut odd {
                    *syndrome ^= power;
                    power = gf64_mul(power, squared);
                }
            }
            assert_eq!(decode(&odd, size), Ok(expected));
        }
    }

    #[test]
    fn decodes_a_triple_unsplit_by_the_mixed_parameter_prefix() {
        let expected = vec![1, 0xcd2, 0x1_d71a];
        let mut odd = vec![0; expected.len()];
        for value in &expected {
            let squared = gf64_mul(*value, *value);
            let mut power = *value;
            for syndrome in &mut odd {
                *syndrome ^= power;
                power = gf64_mul(power, squared);
            }
        }
        assert_eq!(decode(&odd, expected.len()), Ok(expected));
    }

    #[test]
    fn empty_sketch_decodes_to_empty_set() {
        assert_eq!(decode(&[0; 4], 4), Ok(Vec::new()));
    }

    #[test]
    fn polynomial_helpers_reject_invalid_inputs() {
        assert_eq!(gf64_inv(0), None);

        let mut value = vec![1, 2, 3];
        assert_eq!(poly_mod(&[1, 2], &mut value), None);
        assert_eq!(poly_div(vec![1], &[1, 1]), None);
        assert_eq!(poly_div(vec![1, 2], &[1, 2]), None);
        assert_eq!(poly_div(vec![2, 3, 1], &[1, 1]), Some(vec![2, 1]));
        assert_eq!(poly_div(vec![0, 1, 1], &[1, 1]), Some(vec![0, 1]));

        let mut empty = Vec::new();
        poly_square(&mut empty).unwrap();
        assert_eq!(empty, [] as [u64; 0]);
    }

    #[test]
    fn gcd_swaps_lower_degree_left_operand() {
        assert_eq!(poly_gcd(vec![1, 1], vec![1, 0, 1]), Some(vec![1, 1]));
    }

    #[test]
    fn trace_handles_constant_modulus() {
        assert_eq!(trace_mod(&[1], 1), Some(Vec::new()));
    }

    #[test]
    fn root_finding_handles_constant_and_inseparable_polynomials() {
        let mut roots = Vec::new();
        find_roots(vec![1], &mut roots).unwrap();
        assert_eq!(roots, [] as [u64; 0]);
        assert_eq!(
            find_roots(vec![1, 0, 1], &mut roots),
            Err(AlgebraicError::DecodeFailure)
        );
        assert_eq!(
            find_roots(vec![1, 1, 0, 1], &mut roots),
            Err(AlgebraicError::DecodeFailure)
        );
    }

    #[test]
    fn root_finding_stops_when_its_work_budget_is_exhausted() {
        let pair_products = gf64_mul(1, 2) ^ gf64_mul(1, 3) ^ gf64_mul(2, 3);
        let polynomial = vec![gf64_mul(gf64_mul(1, 2), 3), pair_products, 0, 1];
        let mut roots = Vec::new();
        assert_eq!(
            find_roots_with_budget(polynomial, &mut roots, &mut 0),
            Err(AlgebraicError::BudgetExhausted)
        );
        assert_eq!(roots, [] as [u64; 0]);
    }

    #[test]
    fn maximum_degree_trace_exceeds_the_absolute_work_budget() {
        // The one-time basis build alone already exceeds the budget at
        // this degree (per-trial cost is deliberately small -- that's the
        // whole point of the precompute -- so it wouldn't on its own).
        assert!(frobenius_basis_cost(1_000).unwrap() > MAX_FACTOR_WORK);
        // The combined single-call ceiling (basis + full trial ladder)
        // pins both halves of the cost model together.
        assert!(single_call_work_ceiling(1_000).unwrap() > MAX_FACTOR_WORK);
    }

    #[test]
    fn frobenius_basis_matches_naive_trace_for_every_parameter() {
        // A degree-4 modulus (x^4 + x + 1, i.e. coefficients low-to-high
        // [1, 1, 0, 0, 1]) is enough to exercise every basis position for a
        // handful of parameters, checked against the O(d^2)-per-call
        // reference implementation.
        let modulus = vec![1, 1, 0, 0, 1];
        let basis = build_frobenius_basis(&modulus).unwrap();
        for parameter in [0, 1, 2, 3, 0xdead_beef, u64::MAX] {
            assert_eq!(
                trace_from_basis(&basis, parameter),
                trace_mod(&modulus, parameter).unwrap(),
                "mismatch at parameter={parameter}"
            );
        }
    }

    #[test]
    fn quadratic_solver_rejects_an_inconsistent_target() {
        let target = (0..64)
            .map(|bit| 1_u64 << bit)
            .find(|target| {
                let mut trace = *target;
                let mut power = *target;
                for _ in 1..64 {
                    power = gf64_mul(power, power);
                    trace ^= power;
                }
                trace == 1
            })
            .expect("the absolute trace is a nonzero linear map");
        assert_eq!(solve_quadratic_form(target), None);
    }
}
