# JSON numeric limits in `rezzy-json`

How integers behave across the parse, permissive-canonical, and strict-canonical
paths, where the boundaries are, and why they are where they are.

The short version: **`Number` keeps the source spelling of integers, so they
round-trip byte-exactly across an enormous range — but the range that is
_canonical_ is much narrower, and anything above it must not be signed as a JSON
number.**

## The three ranges

| Range                        | Parse / `write_string_value` / permissive canonical | Strict canonical (`write_raw_canonical_filtered_strict` & `rezzy` v6+) | `ruma` canonical JSON    |
| ---------------------------- | --------------------------------------------------- | ---------------------------------------------------------------------- | ------------------------ |
| `\|n\| <= 2^53-1`            | exact                                               | accepted                                                               | accepted                 |
| `2^53-1 < \|n\| <= u64::MAX` | exact                                               | `Err(InvalidNumber)` / `Err(OutOfRangeNumber)`                         | `Err` (`js_int::Int`)    |
| `\|n\| > u64::MAX`           | exact                                               | `Err(InvalidNumber)` / `Err(OutOfRangeNumber)`                         | `Err` (cannot serialize) |

All three rows round-trip byte-exactly in the first column, including integers
far wider than `u64`:

```text
9007199254740991                     permissive=9007199254740991                     strict=ok
9007199254740992                     permissive=9007199254740992                     strict=ERR(InvalidNumber)
175928847299117063                   permissive=175928847299117063                   strict=ERR(InvalidNumber)
9223372036854775807                  permissive=9223372036854775807                  strict=ERR(InvalidNumber)
18446744073709551615                 permissive=18446744073709551615                 strict=ERR(InvalidNumber)
18446744073709551616                 permissive=18446744073709551616                 strict=ERR(InvalidNumber)
1267650600228229401496703205376      permissive=1267650600228229401496703205376      strict=ERR(InvalidNumber)
```

### Canonical-safe: `|n| <= 2^53-1`

`9007199254740991` is the largest integer every JSON consumer carries exactly,
and it is what `MAX_SAFE_INTEGER` / `MIN_SAFE_INTEGER` encode. `ruma` enforces
the identical bound via `js_int::Int`. This is the only range that is safe to
sign.

### Wide but not canonical: `2^53` and above

Integers above the bound are parsed and re-emitted **exactly**, including ones
that overflow `u64`, because `Number` holds the source digits rather than a
parsed machine value. But exactness is not enough, because the signing paths
refuse them:

```text
175928847299117063   ERR  integer is out of the range of `js_int::Int`
18446744073709551615 ERR  integer is out of the range of `js_int::Int`
```

So a wide integer survives `rezzy-json` and then fails in `ruma`, or fails at
strict canonicalization, depending on which code path signs it. Treat
"rezzy-json accepted it" as _not_ evidence that it is signable.

### simd-json diverges above `u64`

`simd-json` **rejects** integers wider than `u64`, because its DOM stores
numbers as machine floats:

```text
18446744073709551616   simd-json: InvalidNumber
```

`rezzy-json` preserves them instead. This divergence is intentional and pinned
by `wide_integers_are_preserved` in `src/basespec/rezzy_types.rs`.

An earlier revision of this crate rewrote such integers through `f64`, turning
`18446744073709551616` into `1.8446744073709552e+19`. That silently changed the
value _and_ the signed bytes, and contradicted the crate's own contract that
integers retain their source spelling. It is fixed; the behaviour is now covered
by tests rather than documentation alone.

## `as_f64` is lossy from `2^53 + 1` (use `try_as_f64_exact` for checked conversion)

The canonical _string_ stays correct; only the lossy `as_f64` accessor rounds.
`f64` is exact through `2^53` inclusive — `2^53` is a power of two, so it
survives — and lossy for essentially everything above it. By contrast,
`Number::try_as_f64_exact` (and `Value::try_as_f64_exact`) rejects any integer
literal outside `[-(2^53 - 1), 2^53 - 1]` (`[MIN_SAFE_INTEGER, MAX_SAFE_INTEGER]`):

| input                         | `as_f64`               | `try_as_f64_exact`     | exact?            |
| ----------------------------- | ---------------------- | ---------------------- | ----------------- |
| `9007199254740991` (`2^53-1`) | `9007199254740991`     | `Some(9007199254740991.0)` | yes           |
| `9007199254740992` (`2^53`)   | `9007199254740992`     | `None`                 | yes, power of two (outside canonical range) |
| `9007199254740993` (`2^53+1`) | `9007199254740992`     | `None`                 | **no**            |
| `175928847299117063`          | `175928847299117060`   | `None`                 | **no**            |
| `9223372036854775807`         | `9223372036854776000`  | `None`                 | **no**            |
| `18446744073709551615`        | `18446744073709552000` | `None`                 | **no**            |
| `18446744073709551616`        | `18446744073709552000` | `None`                 | **no**            |
| `1e400`                       | `None`                 | `None`                 | n/a, not finite   |

Two things worth internalising. The loss in `as_f64` starts at `2^53 + 1`, not
at `2^53`, so a spot check on `2^53` will not reveal it. And `as_f64` returns
`Some` with a rounded value rather than `None` for these — `None` appears only
when the literal overflows `f64` entirely, as with `1e400`. `as_f64` is
therefore not a validity check; use `try_as_f64_exact` whenever out-of-range
integers must fail closed instead of silently rounding.

Anything that routes an identifier through a float — an `f64` field, a
`serde_json::Value` conversion, an `f64`-keyed map — corrupts it. For integer
identifiers use `as_i64` / `as_u64`, `try_as_f64_exact`, or `Number::as_str`
when the range is unknown.

## Snowflake IDs

X/Twitter snowflake ids are `int64`, topping out at `9223372036854775807`,
roughly 1024x larger than `2^53 - 1`. A snowflake id in the `2^53`..`2^63` band
therefore parses and re-emits exactly but is **not canonical**, and `ruma` will
refuse it.

```rust
// Wrong: parses fine here, rejected by strict mode and by ruma.
let value = Value::parse(r#"{"id":175928847299117063}"#)?;
write_raw_canonical_filtered_strict(br#"{"id":175928847299117063}"#, |_| false)?;
// Err(InvalidNumber)

// Right: survives strict canonicalization and ruma.
let value = Value::parse(r#"{"id":"175928847299117063"}"#)?;
write_raw_canonical_filtered_strict(br#"{"id":"175928847299117063"}"#, |_| false)?;
// Ok({"id":"175928847299117063"})
```

**Store external 64-bit identifiers as JSON strings.** That is the only encoding
which is canonical, interoperable, and lossless. It costs a `Number::as_str()`
at the read site and nothing at all in the signed bytes.

## Floats are re-rendered

Only integers keep their source spelling. A literal containing `.`, `e` or `E`
is parsed as `f64` and re-rendered through `ryu`, so `1e2` becomes `100.0` and
`1.0` stays `1.0`. Literals that overflow `f64` (`1e400`) are the exception and
keep their spelling. Anything that parses a float, re-serializes it and then
hashes or signs the result would see different bytes, so signing must go through
the strict canonical writer, which rejects floats.

## `-0`

The scalar path maps the source spelling `-0` to `-0.0` and preserves the sign
of negative zero through `as_f64` (`Some(-0.0)`), because `-0` is
distinguishable and Matrix-significant.

## Strict versus non-strict (Consensus Hash-Split Risk)

`write_raw_canonical_filtered` is the **permissive** writer. Integer spellings
pass through unchanged; floats are normalized in place (`1e21` becomes `1e+21`).
Use it only to inspect or re-emit content you do not sign or hash.

`write_raw_canonical_filtered_strict` (along with `rezzy`'s DOM-based
`validate_canonical_number` in `reference_hash`, `compute_content_hash`, and
`try_canonical_redacted_json` for Room Versions 6+) enforces Matrix's rule that
numbers are integers with no fraction or exponent, within `±(2^53-1)`. Both the
raw-span writer (`is_canonical_integer_str`) and the DOM validator
(`validate_canonical_number`) explicitly reject integers exceeding `u64::MAX` or
below `i64::MIN` (where both `as_i64()` and `as_u64()` return `None`).

The distinction is consensus-critical: the permissive writer's acceptance is
**not** a signing guarantee. Passing untrusted federation payloads through
`write_raw_canonical_filtered` for event signing or reference hashing will
produce a hash/signature split against RFC 8785 / Matrix Spec compliant
homeservers (`ruma` `js_int::Int`).

## Verifying changes to this behaviour

Behaviour in the tables above was first established differentially against
`simd-json` as an oracle. `simd-json` is no longer a dependency of the workspace
(only of `benches/`), so the behaviour is now pinned by explicit tests in
`src/basespec/rezzy_types.rs` and `rezzy-json/src/lib.rs`.

A caution learned the hard way: **a golden corpus of realistic Matrix payloads
detects none of this.** Real events carry `origin_server_ts` and depth integers
well inside `2^53`, no exponent-notation floats, no identifiers past `u64::MAX`,
no lone surrogates, and no nesting past 128. Such a corpus passes with zero
golden mismatches on a build that gets every row of these tables wrong. Any
regression harness for this crate needs the boundary values as explicit cases:
`2^53-1`, `2^53`, `2^53+1`, `i64::MAX`, `i64::MIN-1`, `u64::MAX`, `u64::MAX+1`,
`2^100`, `1e21`, `1e308`, `1e400`, `"\ud800"`, and 200-deep nesting.
`numeric_range_boundaries_are_pinned` and
`number_try_as_f64_exact_enforces_canonical_integer_bounds` in
`rezzy-json/src/lib.rs`, together with
`validate_rejects_integers_beyond_u64_max_and_i64_min` and
`strict_version_rejects_beyond_u64_max_and_i64_min` in
`src/basespec/rezzy_types.rs`, cover these integer and `f64` boundary rows.

## Resolved remediations (`Track 15`)

- **`T10-F1` (`> u64::MAX` / `< i64::MIN` fallthrough in `validate_canonical_number`)**:
  `validate_canonical_number` in `src/basespec/rezzy_types.rs` now explicitly returns
  `Err(CanonicalizationError::OutOfRangeNumber)` when an integer token overflows
  both `as_i64()` and `as_u64()` (and verifies `n.is_canonical_integer()`), matching
  `write_raw_canonical_filtered_strict`.
- **`T10-F2` (Permissive vs. strict canonical writer warnings)**:
  `write_raw_canonical_filtered` and the `rezzy-json` crate docs carry explicit
  consensus hash-split security warnings directing all signing and hashing callers
  to `write_raw_canonical_filtered_strict` (also re-exported at the `rezzy` root).
- **`T10-F3` (Checked `try_as_f64_exact`)**:
  `Number::try_as_f64_exact` and `Value::try_as_f64_exact` reject integer literals
  outside `[-(2^53 - 1), 2^53 - 1]` with `None` instead of silently rounding via `as f64`.
