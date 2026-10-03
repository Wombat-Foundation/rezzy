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
//!
//! Before timing anything the bench proves it is measuring what it claims: the
//! `shake+blake2` stack must reproduce the published MSC4500 test vectors, and
//! the `blake3+blake3` stack must match `rezzy::state::LtHash` byte for byte.
//! A fast number can therefore never come from a different (or broken)
//! algorithm.
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
use rezzy::state::LtHash;
use sha3::Shake256;

use crate::common::{
    generate_state_ops, generate_unique_entries, random_member_key, StateKey, StateOp, Xorshift128,
};

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

/// Unpacks `2 * LANES` bytes into little-endian 16-bit lanes.
fn unpack_lanes(bytes: &[u8]) -> [u16; LANES] {
    let mut out = [0u16; LANES];
    for (lane, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
        *lane = u16::from_le_bytes([pair[0], pair[1]]);
    }
    out
}

/// Input-size categories, mirroring `lthash_comprehensive`.
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
                let len = 65535;
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
/// against the production `rezzy::state::LtHash`.
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
        let iterations = match size {
            Size::Small | Size::Medium => 20_000,
            Size::Large => 300,
        };
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
    println!("  => {label}: blake3+blake3 is {ratio:.2}x faster than shake+blake2");
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

/// Run all benchmarks.
pub fn run() {
    println!("============================================================");
    println!(" LTHASH PRIMITIVE STACK: shake+blake2 vs blake3+blake3");
    println!("============================================================");
    println!("Same element encoding, same lattice arithmetic, two primitive stacks");
    println!("Sections: correctness, expansion, collapse, insert, build, mutate");

    let mut step = 0;

    check_correctness(&mut step);
    bench_expansion(&mut step);
    bench_collapse(&mut step);
    bench_insert(&mut step);
    bench_bulk_build(&mut step);
    bench_incremental(&mut step);

    println!("\n============================================================");
    println!(" PRIMITIVE STACK COMPARISON COMPLETE");
    println!("============================================================");
}
