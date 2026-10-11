# rezzy

Matrix state resolution engine, in Rust. `no_std` core, synchronous by design,
no I/O.

Currently implements state resolution V1 only. Later Matrix room versions and
state-resolution variants remain specification, design, or experimental work;
they are not claimed as supported implementations here.

[![CI](https://img.shields.io/github/actions/workflow/status/gamesguru/rezzy/rust.yml?branch=master&label=CI)](https://github.com/gamesguru/rezzy/actions/workflows/rust.yml)
[![codecov](https://codecov.io/gh/gamesguru/rezzy/graph/badge.svg)](https://codecov.io/gh/gamesguru/rezzy)
[![crates.io](https://img.shields.io/crates/v/rezzy.svg)](https://crates.io/crates/rezzy)

- Auth check engine and full state resolution pipeline.
- Topological and mainline sorting, `n`-way fork resolution.
- Roaring bitmaps and lazy projection for fast, low-memory graph work.
- Generic over event ID, state key and content types.

## Room versions

<!-- markdownlint-disable MD013 -->

|      Room Version       | State Resolution | Notes                                  |
| :---------------------: | :--------------: | :------------------------------------- |
|         **1**           |      **V1**      | **Supported — depth-based ordering**   |
|         2–11            |       —          | Not currently supported                |
|          12             |       —          | Not currently supported ([MSC4297])    |
| _org.matrix.msc4242_ \* |       —          | Design/experimental only ([MSC4242])   |

<!-- markdownlint-enable MD013 -->

> \* Experimental or legacy; not actively supported.

## Usage

```rust
use rezzy::*; // resolve_iterative_sort, LeanEvent, SharedState, StateResVersion, ...
```

See [`docs/design_notes.md`](docs/design_notes.md) for the API overview and
[`docs/architecture.md`](docs/architecture.md) for the design.

## Development

Development is test-first: write the failing test, then the fix.

```bash
git -c submodule.res.update=checkout submodule update --init --recursive  # fixtures
make test
make cov    # needs cargo-llvm-cov
```

For maximum speed, build with the `release-max-perf` profile (see `Cargo.toml`)
and `RUSTFLAGS="-C target-cpu=native"`.

[MSC4242]: https://github.com/matrix-org/matrix-spec-proposals/pull/4242
[MSC4297]: https://github.com/matrix-org/matrix-spec-proposals/pull/4297
