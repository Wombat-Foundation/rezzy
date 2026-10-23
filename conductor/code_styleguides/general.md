# General Code Style Principles

This document outlines general coding principles that apply across all languages and crates in `rezzy`.

## Readability & Clarity
- Code should be easy to read, audit, and formally reason about.
- Document invariants, preconditions, and complexity bounds explicitly.

## Consistency
- Follow existing workspace conventions in `Cargo.toml`, `rustfmt.toml`, and `Makefile`.
- Keep crate boundaries clean (`rezzy` core vs. `rezzy-json` vs. `rezzy-recon` vs. `rezzy-cli`).

## Fail-Closed Simplicity
- Prefer explicit types and exhaustive pattern matching over stringly-typed or opt-in checks.
- Minimize dependencies and preserve `#![no_std]` + `alloc` compatibility in core crates.
