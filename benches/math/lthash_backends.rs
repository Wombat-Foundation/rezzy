//! LtHash primitive-stack comparison: `SHAKE256 + BLAKE2b-256` versus
//! `BLAKE3 + BLAKE3`.
//!
//! MSC4500's original instantiation expands each element with SHAKE256 and
//! collapses the 2048-byte lattice with BLAKE2b-256 under
//! `msc4500:lthash16:v1`. rezzy now does both halves with the BLAKE3 XOF under
//! `msc4500:lthash16:blake3:v1` (see `rezzy::state::lthash`). This bench puts
//! the two stacks back side by side over the *same* element encoding, so the
//! only variable is the primitive, and measures every place the primitives
//! appear:
//!
//! - **expansion**: element -> 2048-byte lattice seed (the per-insert cost)
//! - **collapse**: lattice -> 32-byte wire digest (the per-digest cost)
//! - **insert**: expansion + lattice add
//! - **build**: from-scratch state hash of `n` entries, end to end
//! - **mutate**: insert/overwrite/remove stream over a live state
//! - **candidate backends**: the shipped stacks beside the hand-rolled
//!   SHA-512 CTR and AES-256-CTR expansions (AES-NI and portable paths timed
//!   separately), plus end-to-end builds with each candidate. These are
//!   non-wire-compatible experiments with their own DSTs — see
//!   [`expansion_backends`] for the constructions and the cache-timing caveat
//!   that applies to the portable AES path.
//!
//! Before timing anything the bench proves it is measuring what it claims: the
//! `shake+blake2` stack must reproduce the published MSC4500 test vectors, the
//! `blake3+blake3` stack must match `rezzy::incremental::LtHash` byte for byte, and
//! every candidate primitive must clear its own published vectors (NIST/FIPS)
//! before it is timed. A fast number can therefore never come from a
//! different (or broken) algorithm.
//!
//! Run with: `cargo bench --manifest-path benches/Cargo.toml -- lthash_backends`

#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::items_after_statements,
    clippy::doc_markdown
)]

use std::collections::HashMap;
use std::hint::black_box;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use rezzy::incremental::LtHash;
use sha3::Shake256;

use crate::common::{
    generate_state_ops, generate_unique_entries, random_member_key, StateKey, StateOp, Xorshift128,
};

use super::expansion_backends;

/// Lattice width of the MSC4500 instantiation: 1024 little-endian 16-bit lanes.
const LANES: usize = 1024;

/// Domain-separation tag of the pre-migration (SHAKE256 + BLAKE2b) stack.
const DST_SHAKE: &[u8] = b"msc4500:lthash16:v1";

/// The two primitive stacks this bench compares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stack {
    /// MSC4500's original stack: SHAKE256 expansion, BLAKE2b-256 collapse.
    ShakeBlake2,
    /// rezzy's current stack: BLAKE3 XOF expansion, BLAKE3 collapse.
    Blake3,
}

impl Stack {
    const ALL: [Stack; 2] = [Stack::ShakeBlake2, Stack::Blake3];

    fn name(self) -> &'static str {
        match self {
            Stack::ShakeBlake2 => "shake+blake2",
            Stack::Blake3 => "blake3+blake3",
        }
    }

    fn dst(self) -> &'static [u8] {
        match self {
            Stack::ShakeBlake2 => DST_SHAKE,
            Stack::Blake3 => LtHash::DST,
        }
    }

    /// Expands one state element into a 2048-byte lattice seed.
    fn expand(self, event_type: &str, state_key: &str, event_id: &str) -> [u16; LANES] {
        let mut bytes = [0u8; LANES * 2];
        match self {
            Stack::Blake3 => {
                let mut hasher = blake3::Hasher::new();
                feed_element(&mut hasher, self.dst(), event_type, state_key, event_id);
                hasher.finalize_xof().fill(&mut bytes);
            }
            Stack::ShakeBlake2 => {
                let mut xof = Shake256::default();
                feed_element(&mut xof, self.dst(), event_type, state_key, event_id);
                sha3::digest::ExtendableOutput::finalize_xof_into(xof, &mut bytes);
            }
        }
        unpack_lanes(&bytes)
    }

    /// Expands one state element straight into a [`LtHash`] seed.
    fn seed(self, event_type: &str, state_key: &str, event_id: &str) -> LtHash {
        LtHash::from_lanes(self.expand(event_type, state_key, event_id))
    }

    /// Serializes the lattice little-endian and collapses it to 32 bytes.
    fn collapse(self, lattice: &[u16; LANES]) -> [u8; 32] {
        let mut bytes = [0u8; LANES * 2];
        for (pair, lane) in bytes.chunks_exact_mut(2).zip(lattice) {
            pair.copy_from_slice(&lane.to_le_bytes());
        }
        match self {
            Stack::Blake3 => *blake3::Hasher::new().update(&bytes).finalize().as_bytes(),
            Stack::ShakeBlake2 => {
                let mut hasher = Blake2b::<U32>::new();
                hasher.update(bytes);
                hasher.finalize().into()
            }
        }
    }
}

/// Expansion backends compared by the candidate section: the two shipped
/// stacks plus the experimental backends in [`expansion_backends`]. All five
/// hash the same buffered framing, so only the primitive varies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expand {
    Blake3,
    Shake256,
    Sha512Ctr,
    AesCtrNi,
    AesCtrPortable,
}

impl Expand {
    const ALL: [Expand; 5] = [
        Expand::Blake3,
        Expand::Shake256,
        Expand::Sha512Ctr,
        Expand::AesCtrNi,
        Expand::AesCtrPortable,
    ];

    fn name(self) -> &'static str {
        match self {
            Expand::Blake3 => "blake3",
            Expand::Shake256 => "shake256",
            Expand::Sha512Ctr => "sha512-ctr",
            Expand::AesCtrNi => "aes-ctr-ni",
            Expand::AesCtrPortable => "aes-ctr-portable",
        }
    }

    fn dst(self) -> &'static [u8] {
        match self {
            Expand::Blake3 => LtHash::DST,
            Expand::Shake256 => DST_SHAKE,
            Expand::Sha512Ctr => expansion_backends::DST_SHA512_CTR,
            Expand::AesCtrNi | Expand::AesCtrPortable => expansion_backends::DST_AES_CTR,
        }
    }

    /// Expands already-framed element bytes into a 2048-byte seed.
    fn expand(self, frame: &[u8], out: &mut [u8]) {
        match self {
            Expand::Blake3 => blake3::Hasher::new().update(frame).finalize_xof().fill(out),
            Expand::Shake256 => {
                let mut xof = Shake256::default();
                sha3::digest::Update::update(&mut xof, frame);
                sha3::digest::ExtendableOutput::finalize_xof_into(xof, out);
            }
            Expand::Sha512Ctr => expansion_backends::expand_sha512_ctr(frame, out),
            Expand::AesCtrNi => expansion_backends::expand_aes_ctr(frame, out, true),
            Expand::AesCtrPortable => expansion_backends::expand_aes_ctr(frame, out, false),
        }
    }

    /// The backends measurable on this CPU: the AES-NI path only exists where
    /// the CPU (and the target) actually has AES-NI.
    fn available() -> Vec<Expand> {
        Expand::ALL
            .into_iter()
            .filter(|backend| {
                *backend != Expand::AesCtrNi || expansion_backends::aes_ni_available()
            })
            .collect()
    }
}

/// Byte sink shared by both stacks, so the element framing is byte-identical
/// no matter which primitive is being timed.
trait Sink {
    fn put(&mut self, bytes: &[u8]);
}

impl Sink for blake3::Hasher {
    #[inline]
    fn put(&mut self, bytes: &[u8]) {
        self.update(bytes);
    }
}

impl Sink for Shake256 {
    #[inline]
    fn put(&mut self, bytes: &[u8]) {
        // Qualified so `blake2::Digest` and `sha3::digest::Update` (which both
        // offer `update`) never collide at a call site in this module.
        sha3::digest::Update::update(self, bytes);
    }
}

/// Feeds `dst || len(type) || type || len(state_key) || state_key || event_id`
/// into `sink`, with both lengths unsigned 16-bit little-endian.
fn feed_element(
    sink: &mut impl Sink,
    dst: &[u8],
    event_type: &str,
    state_key: &str,
    event_id: &str,
) {
    let (event_type, type_len) = truncate_to_u16_limit(event_type);
    let (state_key, sk_len) = truncate_to_u16_limit(state_key);
    sink.put(dst);
    sink.put(&type_len.to_le_bytes());
    sink.put(event_type.as_bytes());
    sink.put(&sk_len.to_le_bytes());
    sink.put(state_key.as_bytes());
    sink.put(event_id.as_bytes());
}

/// Truncates a string to the 65535-byte `u16` length-prefix limit, exactly as
/// `rezzy::state::lthash` does (event IDs are streamed untruncated).
fn truncate_to_u16_limit(s: &str) -> (&str, u16) {
    let limit = usize::from(u16::MAX);
    let s_len = s.len();
    if s_len > limit {
        let mut end = limit;
        while !s.is_char_boundary(end) {
            end = end.saturating_sub(1);
        }
        (&s[..end], u16::try_from(end).unwrap())
    } else {
        (s, u16::try_from(s_len).unwrap())
    }
}

/// Byte-buffer twin of [`feed_element`]: writes the identical framing bytes
/// into `buf` (cleared first) for backends that need the element as a slice
/// instead of a stream. [`check_framing_parity`] proves the two never drift.
fn frame_element<'a>(
    dst: &[u8],
    event_type: &str,
    state_key: &str,
    event_id: &str,
    buf: &'a mut Vec<u8>,
) -> &'a [u8] {
    buf.clear();
    let (event_type, type_len) = truncate_to_u16_limit(event_type);
    let (state_key, sk_len) = truncate_to_u16_limit(state_key);
    buf.extend_from_slice(dst);
    buf.extend_from_slice(&type_len.to_le_bytes());
    buf.extend_from_slice(event_type.as_bytes());
    buf.extend_from_slice(&sk_len.to_le_bytes());
    buf.extend_from_slice(state_key.as_bytes());
    buf.extend_from_slice(event_id.as_bytes());
    buf
}

/// Unpacks `2 * LANES` bytes into little-endian 16-bit lanes.
fn unpack_lanes(bytes: &[u8]) -> [u16; LANES] {
    let mut out = [0u16; LANES];
    for (lane, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
        *lane = u16::from_le_bytes([pair[0], pair[1]]);
    }
    out
}

/// Input-size categories: a short `$0`-style ID, a real `$ev:domain` ID, and a
/// ~400-byte ID — the realistic upper bound for an event ID. (The framing
/// format tolerates up to 65535 bytes; no real event ID comes close, so this
/// bench deliberately does not use `lthash_comprehensive`'s `Stress` category.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Size {
    Small,
    Medium,
    Large,
}

impl Size {
    fn name(self) -> &'static str {
        match self {
            Size::Small => "small",
            Size::Medium => "medium",
            Size::Large => "large",
        }
    }

    fn event_id(self, rng: &mut Xorshift128, idx: usize) -> String {
        match self {
            Size::Small => format!("${idx}"),
            Size::Medium => format!("$event{idx}:example.org"),
            Size::Large => {
                // ~400 bytes: the realistic worst case for an event ID.
                let len = 400;
                let mut s = String::with_capacity(len + 2);
                s.push('$');
                for i in 0..len {
                    let c = ((rng.next_u64() >> (i % 8)) & 0xFF) as u8;
                    if c.is_ascii_alphanumeric() {
                        s.push(c as char);
                    } else {
                        s.push('a');
                    }
                }
                s
            }
        }
    }
}

/// Times `op` `iterations` times.
fn time<F: FnMut()>(iterations: u32, mut op: F) -> Duration {
    let start = Instant::now();
    for _ in 0..iterations {
        op();
    }
    start.elapsed()
}

fn ns_per_op(elapsed: Duration, iterations: u32) -> f64 {
    elapsed.as_nanos() as f64 / f64::from(iterations)
}

/// Per-op metric line in nanoseconds; `compare_bench.py` parses the `ns` unit.
fn fmt_ns(elapsed: Duration, iterations: u32) -> String {
    format!("{:.1} ns/op", ns_per_op(elapsed, iterations))
}

/// Whole-run metric line in milliseconds (used for bulk builds).
fn fmt_ms(elapsed: Duration, iterations: u32) -> String {
    format!(
        "{:.3} ms/op",
        elapsed.as_secs_f64() * 1000.0 / f64::from(iterations)
    )
}

/// Runs `f` once per stack, prints `<label> <stack>: <metric>`, then a
/// speedup line, and returns the durations as `[shake+blake2, blake3+blake3]`.
fn measure(
    iterations: u32,
    label: &str,
    fmt: fn(Duration, u32) -> String,
    mut f: impl FnMut(Stack),
) -> [Duration; 2] {
    let mut out = [Duration::ZERO; 2];
    for (i, stack) in Stack::ALL.into_iter().enumerate() {
        // Warm each stack on its own code path so the timed loop does not pay
        // cold i-cache and first-touch costs for one stack only.
        for _ in 0..iterations.min(2_000) {
            f(stack);
        }
        let elapsed = time(iterations, || f(stack));
        out[i] = elapsed;
        println!("  {label} {}: {}", stack.name(), fmt(elapsed, iterations));
    }
    let [shake, blake3] = out;
    let (fastest, slowest, ratio) = if shake < blake3 {
        (
            Stack::ShakeBlake2,
            Stack::Blake3,
            blake3.as_nanos() as f64 / shake.as_nanos().max(1) as f64,
        )
    } else {
        (
            Stack::Blake3,
            Stack::ShakeBlake2,
            shake.as_nanos() as f64 / blake3.as_nanos().max(1) as f64,
        )
    };
    println!(
        "  => {label}: {} is {ratio:.2}x faster than {}",
        fastest.name(),
        slowest.name()
    );
    out
}

/// Start a new metric group so `scripts/compare_bench.py` keys the labels below
/// by group instead of letting repeats collide.
fn checkpoint(step: &mut u32) {
    *step += 1;
    println!("S={step}:");
}

/// First `n` lanes of `lt` serialized little-endian (the form MSC4500 prints
/// expansion vectors in).
fn lanes_prefix(lt: &LtHash, n: usize) -> Vec<u8> {
    lt.lattice()[..n]
        .iter()
        .flat_map(|lane| lane.to_le_bytes())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Proves the measured stacks are the algorithms they claim to be:
/// `shake+blake2` against the published MSC4500 vectors, `blake3+blake3`
/// against the production `rezzy::incremental::LtHash`.
fn check_correctness(step: &mut u32) {
    checkpoint(step);
    println!("\n=== Correctness ===");

    let event_type = "m.room.member";
    let state_key = "@alice:example.com";
    let event_id = "$event_1";

    // The blake3 stack must be byte-identical to production `LtHash`.
    assert_eq!(
        Stack::Blake3.dst(),
        LtHash::DST,
        "DST drifted from production"
    );
    let production = LtHash::seed(event_type, state_key, &event_id);
    assert_eq!(
        Stack::Blake3.expand(event_type, state_key, event_id),
        *production.lattice(),
        "bench blake3 expansion drifted from production `LtHash::seed`"
    );
    let mut lattice = LtHash::ZERO;
    lattice.add_seed(&production);
    assert_eq!(
        Stack::Blake3.collapse(lattice.lattice()),
        lattice.digest(),
        "bench blake3 collapse drifted from production `LtHash::digest`"
    );
    println!("  production parity (blake3+blake3): ok");

    // The shake+blake2 stack must reproduce MSC4500's published vectors.
    let s0 = LtHash::ZERO;
    assert_eq!(
        URL_SAFE_NO_PAD.encode(Stack::ShakeBlake2.collapse(s0.lattice())),
        "IAgj5RWLN3TBG1xhhQradi-CZBRKm-vsPrrFoq3eZ7g",
        "empty-state vector"
    );

    let seed1 = Stack::ShakeBlake2.seed(event_type, state_key, event_id);
    assert_eq!(
        hex(&lanes_prefix(&seed1, 8)),
        "dbcadc58c85d7be0efca00e478a66697",
        "element 1 expansion vector"
    );
    let mut s1 = s0;
    s1.add_seed(&seed1);
    assert_eq!(
        URL_SAFE_NO_PAD.encode(Stack::ShakeBlake2.collapse(s1.lattice())),
        "bX7ccIPg0lyRZyBYO_UZs5nC4iVitD62L6cJfL2iAiU",
        "scenario 1 digest vector"
    );

    let seed2 = Stack::ShakeBlake2.seed("m.room.name", "", "$event_2");
    assert_eq!(
        hex(&lanes_prefix(&seed2, 8)),
        "118e0b32fac730c01f1351378389793a",
        "element 2 expansion vector"
    );
    let mut s2 = s1;
    s2.add_seed(&seed2);
    assert_eq!(
        URL_SAFE_NO_PAD.encode(Stack::ShakeBlake2.collapse(s2.lattice())),
        "uPdh4wkYWs0awGqFQmf3ieHSoFoMXFPwZmdqrwSPhkM",
        "scenario 3 digest vector"
    );

    let seed3 = Stack::ShakeBlake2.seed(event_type, state_key, "$event_3");
    assert_eq!(
        hex(&lanes_prefix(&seed3, 8)),
        "4f026432409d32757f83fd088659c6c6",
        "element 3 expansion vector"
    );
    let mut s3 = s2;
    s3.sub_seed(&seed1);
    s3.add_seed(&seed3);
    assert_eq!(
        URL_SAFE_NO_PAD.encode(Stack::ShakeBlake2.collapse(s3.lattice())),
        "eqev6DfKxlhX6RocDu97tQghpBYRRQ9TfbGXiiQiSZA",
        "scenario 4 digest vector"
    );
    println!("  MSC4500 published vectors (shake+blake2): ok");
}

/// Expansion: element -> 2048-byte seed. This is the per-insert cost and the
/// part the SHAKE256 -> BLAKE3 migration was made for.
fn bench_expansion(step: &mut u32) {
    checkpoint(step);
    println!("\n=== Expansion (element -> 2048-byte seed) ===");

    for (size, seed) in [
        (Size::Small, 0x5EED_0001),
        (Size::Medium, 0x5EED_0002),
        (Size::Large, 0x5EED_0003),
    ] {
        let mut rng = Xorshift128::new(seed);
        let event_id = size.event_id(&mut rng, 0);
        let iterations = 20_000;
        measure(
            iterations,
            &format!("expand ({})", size.name()),
            fmt_ns,
            |stack| {
                black_box(stack.expand("m.room.member", "@alice:example.org", &event_id));
            },
        );
    }
}

/// Collapse: 2048-byte lattice -> 32-byte wire digest.
fn bench_collapse(step: &mut u32) {
    checkpoint(step);
    println!("\n=== Collapse (2048-byte lattice -> 32-byte digest) ===");

    let entries = generate_unique_entries(100, 0xC011_0001, random_member_key, |rng| {
        format!("$event{}:example.org", rng.next_u64())
    });
    let lattice = build_lattice(Stack::Blake3, &entries);

    measure(50_000, "collapse", fmt_ns, |stack| {
        black_box(stack.collapse(lattice.lattice()));
    });
}

/// Insert: expansion + lattice add, the real per-event cost of maintaining the
/// accumulator.
fn bench_insert(step: &mut u32) {
    checkpoint(step);
    println!("\n=== Insert (expansion + lattice add) ===");

    let mut rng = Xorshift128::new(0x1EED_0001);
    let event_id = Size::Medium.event_id(&mut rng, 0);
    let mut lattice = LtHash::ZERO;

    measure(20_000, "insert", fmt_ns, |stack| {
        lattice.add_seed(&stack.seed("m.room.member", "@alice:example.org", &event_id));
        black_box(&lattice);
    });
}

/// Bulk build: from-scratch state hash of `n` entries, including the final
/// collapse — the number a cold-start state sync actually pays.
fn bench_bulk_build(step: &mut u32) {
    checkpoint(step);
    println!("\n=== Bulk state build (n entries, end to end incl. digest) ===");

    for n in [64usize, 1024, 8192] {
        let entries =
            generate_unique_entries(n, 0xB01C_0000 + n as u64, random_member_key, |rng| {
                format!("$event{}:example.org", rng.next_u64())
            });
        let iterations = ((60_000 / n) as u32).max(2);

        measure(iterations, &format!("build (n={n})"), fmt_ms, |stack| {
            let lattice = build_lattice(stack, &entries);
            black_box(stack.collapse(lattice.lattice()));
        });
    }
}

/// Incremental mutation: a realistic insert/overwrite/remove stream over a
/// live state, digesting after every step.
///
/// Setup (cloning the base state and rebuilding the accumulator) is deliberately
/// outside the timed window, so the number below is only the mutation stream.
fn bench_incremental(step: &mut u32) {
    checkpoint(step);
    println!("\n=== Incremental mutations (live state, digest per step) ===");

    let n = 4096;
    let entries = generate_unique_entries(n, 0x5EED_BEEF, random_member_key, |rng| {
        format!("$event{}:example.org", rng.next_u64())
    });
    let base: HashMap<StateKey, String> = entries.iter().cloned().collect();
    let keys: Vec<StateKey> = base.keys().cloned().collect();
    let mut rng = Xorshift128::new(0xBEEF);
    let ops = generate_state_ops(&mut rng, &keys, 1_500);
    let iterations = 8u32;
    let steps = ops.len() as u32;
    let label = format!("mutate (n={n})");

    let mut out = [Duration::ZERO; 2];
    for (i, stack) in Stack::ALL.into_iter().enumerate() {
        let mut elapsed = Duration::ZERO;
        for _ in 0..iterations {
            let mut state = base.clone();
            let mut lattice = build_lattice(stack, &entries);
            let start = Instant::now();
            for op in &ops {
                apply_op(stack, &mut state, &mut lattice, op);
                black_box(&lattice);
                black_box(stack.collapse(lattice.lattice()));
            }
            elapsed += start.elapsed();
        }
        out[i] = elapsed;
        let total = iterations * steps;
        println!("  {label} {}: {}", stack.name(), fmt_ns(elapsed, total));
    }
    let [shake, blake3] = out;
    let ratio = shake.as_nanos() as f64 / blake3.as_nanos().max(1) as f64;
    if ratio >= 1.0 {
        println!("  => {label}: blake3+blake3 is {ratio:.2}x faster than shake+blake2");
    } else {
        println!(
            "  => {label}: blake3+blake3 is {:.2}x slower than shake+blake2",
            1.0 / ratio
        );
    }
}

/// Builds an accumulator covering every entry using `stack`'s expansion.
fn build_lattice(stack: Stack, entries: &[(StateKey, String)]) -> LtHash {
    let mut lattice = LtHash::ZERO;
    for ((event_type, state_key), event_id) in entries {
        lattice.add_seed(&stack.seed(event_type, state_key, event_id));
    }
    lattice
}

/// Applies one state mutation to both the plain map and the accumulator.
fn apply_op(
    stack: Stack,
    state: &mut HashMap<StateKey, String>,
    lattice: &mut LtHash,
    op: &StateOp,
) {
    match op {
        StateOp::Insert(key, value) | StateOp::Overwrite(key, value) => {
            if let Some(old) = state.insert(key.clone(), value.clone()) {
                lattice.sub_seed(&stack.seed(&key.0, &key.1, &old));
                lattice.add_seed(&stack.seed(&key.0, &key.1, value));
            } else {
                lattice.add_seed(&stack.seed(&key.0, &key.1, value));
            }
        }
        StateOp::Remove(key) => {
            if let Some(old) = state.remove(key) {
                lattice.sub_seed(&stack.seed(&key.0, &key.1, &old));
            }
        }
    }
}

/// Proves the buffered framing used by the candidate section hashes the same
/// bytes as the streaming framing the shipped stacks hash — including the
/// `u16` truncation path — and that the buffered BLAKE3 path lands on the same
/// seed as the streaming stack.
fn check_framing_parity() {
    struct Collect(Vec<u8>);

    impl Sink for Collect {
        fn put(&mut self, bytes: &[u8]) {
            self.0.extend_from_slice(bytes);
        }
    }

    let event_id = "$event_1";
    let long_state_key = "k".repeat(70_000);
    for (event_type, state_key) in [
        ("m.room.member", "@alice:example.org"),
        ("m.room.member", ""),
        ("m.room.name", long_state_key.as_str()),
    ] {
        let mut streamed = Collect(Vec::new());
        feed_element(&mut streamed, LtHash::DST, event_type, state_key, event_id);
        let mut buf = Vec::new();
        let buffered = frame_element(LtHash::DST, event_type, state_key, event_id, &mut buf);
        assert_eq!(
            buffered,
            streamed.0.as_slice(),
            "buffered framing drifted from the streaming framing"
        );
    }

    let mut buf = Vec::new();
    let frame = frame_element(
        LtHash::DST,
        "m.room.member",
        "@alice:example.org",
        event_id,
        &mut buf,
    );
    let mut out = [0u8; LANES * 2];
    Expand::Blake3.expand(frame, &mut out);
    assert_eq!(
        unpack_lanes(&out),
        Stack::Blake3.expand("m.room.member", "@alice:example.org", event_id),
        "buffered blake3 expansion drifted from the streaming stack"
    );
    println!("  element framing (streaming vs buffered): ok");
}

/// Ratio lines shared by both candidate sections: how each backend compares
/// against the `blake3` baseline (which is the shipped production expansion).
fn print_speedups(label: &str, times: &[(&'static str, Duration)], baseline: &str) {
    let base = times
        .iter()
        .find(|(name, _)| *name == baseline)
        .map_or(Duration::ZERO, |(_, elapsed)| *elapsed);
    for (name, elapsed) in times {
        if *name == baseline {
            continue;
        }
        let ratio = base.as_secs_f64() / elapsed.as_secs_f64();
        if ratio >= 1.0 {
            println!("  => {label}: {name} is {ratio:.2}x faster than {baseline}");
        } else {
            println!(
                "  => {label}: {name} is {:.2}x slower than {baseline}",
                1.0 / ratio
            );
        }
    }
}

/// Candidate expansion backends: every stack and candidate hashing the same
/// buffered element, at the three input sizes, with the candidate primitives
/// proved correct first.
fn bench_expansion_backends(step: &mut u32) {
    checkpoint(step);
    println!("\n=== Expansion backends (framed element -> 2048-byte seed) ===");
    println!("  candidates are NOT MSC4500 wire-compatible: own DSTs, throughput only");
    println!("  both AES paths share the blake3 key derivation and the scalar key schedule,");
    println!("  so block encryption is the only thing that differs between them");
    println!("  aes-ctr-portable is the wasm/portable stand-in: 4 KiB of T-tables with");
    println!("  secret-dependent lookups (the classic AES cache-timing surface). This is a");
    println!("  throughput bench: it cannot observe that side channel, so the number is the");
    println!("  cost of the portable path, never a claim that the path is safe");
    expansion_backends::check();
    check_framing_parity();
    let backends = Expand::available();
    if !expansion_backends::aes_ni_available() {
        println!("  AES-NI: unavailable on this CPU; aes-ctr-ni omitted (portable still timed)");
    }

    let mut buf: Vec<u8> = Vec::with_capacity(70_000);
    for (size, seed) in [
        (Size::Small, 0xE0FF_0001),
        (Size::Medium, 0xE0FF_0002),
        (Size::Large, 0xE0FF_0003),
    ] {
        let mut rng = Xorshift128::new(seed);
        let event_id = size.event_id(&mut rng, 0);
        let iterations = 20_000;
        let label = format!("expand ({})", size.name());
        let mut times: Vec<(&'static str, Duration)> = Vec::new();
        for backend in &backends {
            let backend = *backend;
            let mut op = || {
                // `black_box` on the frame keeps the framing itself inside the
                // timed window instead of letting it hoist out of the loop.
                let frame = black_box(frame_element(
                    backend.dst(),
                    "m.room.member",
                    "@alice:example.org",
                    &event_id,
                    &mut buf,
                ));
                let mut out = [0u8; LANES * 2];
                backend.expand(frame, &mut out);
                black_box(out);
            };
            for _ in 0..iterations.min(2_000) {
                op();
            }
            let elapsed = time(iterations, &mut op);
            println!(
                "  {label} {}: {}",
                backend.name(),
                fmt_ns(elapsed, iterations)
            );
            times.push((backend.name(), elapsed));
        }
        print_speedups(&label, &times, "blake3");
    }
}

/// Builds an accumulator over `entries` with `backend`'s expansion, framing
/// each element into the reusable `buf` — the candidate harness's input path.
fn build_buffered(backend: Expand, entries: &[(StateKey, String)], buf: &mut Vec<u8>) -> LtHash {
    let mut lattice = LtHash::ZERO;
    let mut bytes = [0u8; LANES * 2];
    for ((event_type, state_key), event_id) in entries {
        let frame = black_box(frame_element(
            backend.dst(),
            event_type,
            state_key,
            event_id,
            buf,
        ));
        backend.expand(frame, &mut bytes);
        lattice.add_seed(&LtHash::from_lanes(unpack_lanes(&bytes)));
    }
    lattice
}

/// End-to-end bulk build with each candidate expansion: the number that would
/// actually change if a candidate were adopted. Collapse stays BLAKE3 for all
/// of them, so expansion is the only variable.
fn bench_backend_builds(step: &mut u32) {
    checkpoint(step);
    println!("\n=== Bulk build with candidate expansions (n=1024, blake3 collapse) ===");

    let entries = generate_unique_entries(1024, 0xB01C_0A51, random_member_key, |rng| {
        format!("$event{}:example.org", rng.next_u64())
    });
    let iterations = 10u32;
    let backends = Expand::available();
    let mut buf: Vec<u8> = Vec::with_capacity(70_000);
    let mut times: Vec<(&'static str, Duration)> = Vec::new();
    for backend in &backends {
        let backend = *backend;
        let mut op = || {
            let lattice = build_buffered(backend, &entries, &mut buf);
            black_box(lattice.digest());
        };
        for _ in 0..2 {
            op();
        }
        let elapsed = time(iterations, &mut op);
        println!(
            "  build (n=1024) {}: {}",
            backend.name(),
            fmt_ms(elapsed, iterations)
        );
        times.push((backend.name(), elapsed));
    }
    print_speedups("build (n=1024)", &times, "blake3");
}

/// Run all benchmarks.
pub fn run() {
    println!("============================================================");
    println!(" LTHASH PRIMITIVE STACK: shake+blake2 vs blake3+blake3");
    println!("============================================================");
    println!("Same element encoding, same lattice arithmetic, two primitive stacks");
    println!("Sections: correctness, expansion, collapse, insert, build, mutate,");
    println!("          candidate expansion backends, candidate builds");

    let mut step = 0;

    check_correctness(&mut step);
    bench_expansion(&mut step);
    bench_collapse(&mut step);
    bench_insert(&mut step);
    bench_bulk_build(&mut step);
    bench_incremental(&mut step);
    bench_expansion_backends(&mut step);
    bench_backend_builds(&mut step);

    println!("\n============================================================");
    println!(" PRIMITIVE STACK COMPARISON COMPLETE");
    println!("============================================================");
}
