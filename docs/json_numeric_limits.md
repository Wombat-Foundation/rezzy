# JSON numeric limits in `rezzy-json`

How integers behave across the parse, canonical-write, and strict-canonical
paths, where the boundaries are, and why they are where they are. Every claim
here was checked against a pinned `HEAD` build of `rezzy-json` and against
`ruma-common` 0.19 as the interop reference.

The short version: **`Number` keeps the source spelling, so integers round-trip
byte-exactly across a very wide range — but the range that is _canonical_ is
much narrower, and anything above it must not be signed as a JSON number.**

## The three ranges

| Range                    | Parse / `write_string_value` / non-strict canonical | `write_raw_canonical_filtered_strict` | `ruma` canonical JSON                |
| ------------------------ | --------------------------------------------------- | ------------------------------------- | ------------------------------------ |
| `\|n\| <= 2^53-1`        | exact                                               | accepted                              | accepted                             |
| `2^53-1 < n <= u64::MAX` | exact                                               | `Err(InvalidNumber)`                  | `Err` (`js_int::Int`)                |
| `n > u64::MAX`           | source spelling preserved                           | `Err(InvalidNumber)`                  | `Err` (`float cannot be serialized`) |

### Canonical-safe: `|n| <= 2^53-1`

`9007199254740991` is the largest integer JSON can carry exactly in every
consumer, and it is the bound `MAX_SAFE_INTEGER` / `MIN_SAFE_INTEGER` encode.
`is_canonical_integer_str` enforces it, strict mode is built on it, and `ruma`
enforces the identical bound via `js_int::Int`. This is the only range that is
safe to sign.

### Wide but not canonical: `2^53` to `u64::MAX`

Integers in this range are parsed and re-emitted **exactly**, because `Number`
stores the source spelling and `Number::parse` returns it verbatim whenever it
parses as `i64` or `u64`:

```
snowflake 175928847299117063   canonical=175928847299117063   (byte-exact)
i64::MAX 9223372036854775807  canonical=9223372036854775807  (byte-exact)
u64::MAX 18446744073709551615 canonical=18446744073709551615 (byte-exact)
```

The exactness is real but it is not enough, because these values are rejected
downstream. Strict mode refuses them, and so does `ruma`:

```
175928847299117063   ERR  integer is out of the range of `js_int::Int`
18446744073709551615 ERR  integer is out of the range of `js_int::Int`
```

So a wide integer survives `rezzy-json` and then fails in `ruma`, or fails at
strict canonicalization, depending on which code path signs it. Treat
"rezzy-json accepted it" as _not_ evidence that it is signable.

### Beyond `u64::MAX`: preserved, but not canonical

Integer literals above `u64::MAX` retain their source spelling. They remain
non-canonical and are rejected by strict canonicalization, but their bytes are
not silently rewritten:

```
18446744073709551616  ->  1.8446744073709552e+19
1267650600228229401496703205376  ->  1.2676506002282294e+30
```

`as_i64`, `as_u64`, and `as_f64` return `None` for such an integer. Use strict
canonicalization or parse the source string explicitly when a range check is
required.

## `as_f64` is lossy above `2^53`

The canonical _string_ stays correct; only the accessor rounds.

| input                  | `as_i64`      | `as_u64`      | `as_f64`               |
| ---------------------- | ------------- | ------------- | ---------------------- |
| `9007199254740991`     | `Some(..991)` | `Some(..991)` | exact                  |
| `175928847299117063`   | `Some(..063)` | `Some(..063)` | `175928847299117056`   |
| `9223372036854775807`  | `Some(..807)` | `None`        | `9223372036854775808`  |
| `18446744073709551615` | `None`        | `Some(..615)` | `18446744073709551616` |

Anything that routes an identifier through a float — a `f64` field, a
`serde_json::Value` conversion, an f64-keyed map — corrupts it. For integer
identifiers use `as_i64`/`as_u64`, or `as_str` when the range is unknown.

## Snowflake IDs

X/Twitter snowflake ids are `int64`, topping out at `9223372036854775807`, which
is roughly 1024x larger than `2^53-1`. A snowflake id in the `2^53`..`2^63` band
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

**Store external 64-bit identifiers as JSON strings.** This is the only encoding
that is canonical, interop-safe, and lossless. It costs a `Number` accessor at
the read site and nothing at all in the signed bytes.

## `-0`

The scalar path maps the source spelling `-0` to `-0.0`, and preserves the sign
of negative zero through `as_f64` (`Some(-0.0)`), because `-0` is
distinguishable and Matrix-significant. Under the `simd` feature the parse path
falls back to the scalar parser whenever `-0` appears in the input, because
`simd-json` collapses numbers to machine values and would lose the spelling.

## Strict versus non-strict

`write_raw_canonical_filtered` is the permissive writer: it accepts any
well-formed JSON number and normalizes its spelling (`1E1` becomes `10.0`). Use
it for reading and re-emitting content you do not sign.

`write_raw_canonical_filtered_strict` enforces Matrix's rule that numbers are
integers with no fraction or exponent, within `±(2^53-1)`. This is the signing
path. It validates numeric spans in place without building a DOM, and rejects
anything in the two upper ranges above with `Error::InvalidNumber`.

The distinction matters because the permissive writer's acceptance is not a
signing guarantee. A value can canonicalize cleanly under the permissive writer
and still be rejected by the strict writer or by `ruma`.

## Verifying changes to this behaviour

Behaviour in the table above was established differentially: the same corpus was
run through a build with the `simd` feature and a build with
`--no-default-features`, and the canonical outputs compared byte-for-byte.

A caution learned the hard way: a golden corpus of _realistic Matrix payloads_
does not detect any of this. Real events carry `origin_server_ts` and depth
integers well inside `2^53`, no exponent-notation floats, no identifiers past
`u64::MAX`, no lone surrogates, and no nesting past 128. Such a corpus passes
with `golden_cmp=0` on a build that gets every row of the table above wrong. Any
regression harness for this crate needs the boundary values as explicit cases:
`2^53-1`, `2^53`, `i64::MAX`, `u64::MAX`, `u64::MAX+1`, `1e21`, `1e308`,
`1e400`, `"\ud800"`, and 200-deep nesting.

## Open items

- **`as_f64` has no guard.** It is lossy above `2^53` by construction and the
  docs now say so, but nothing at the call site warns.
- **The `simd` fast-path gate is coarser than it needs to be.** It scans raw
  bytes without tracking string context, so braces, long digit runs, and `e` /
  `E` inside ordinary message bodies count as JSON syntax and force the scalar
  path. Correct, but it silently gives up the SIMD win on exactly the prose-
  heavy events that dominate a real `/sync`. Tracking string context in the gate
  would recover it. Floats still need to defer to the scalar path so that
  `1e400` keeps yielding a value whose `as_f64` is `None` rather than an error.
