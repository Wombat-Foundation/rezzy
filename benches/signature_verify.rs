//! Head-to-head event signature verification: ruma's `verify_event`
//! (redaction + content-hash + ed25519-dalek) vs rezzy's native pipeline
//! (`canonical_redacted_json` + `verify_content_hash` + ed25519-dalek).
//!
//! The Ed25519 curve math is identical underneath, so this measures the
//! redaction/canonicalization + JSON-manipulation + pipeline overhead —
//! exactly the part where a single-source-of-truth redaction/canonicalization
//! engine (rezzy) can diverge from a verification-time re-implementation
//! (ruma). Run with: `cargo bench --bench signature_verify --features
//! signing,mock-ruma,simd-json-serde`.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    clippy::items_after_statements,
    clippy::doc_markdown,
    clippy::pedantic,
    clippy::unit_arg
)]

use std::hint::black_box;
use std::time::{Duration, Instant};

use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use ruma_common::room_version_rules::RoomVersionRules;
use ruma_common::{serde::Base64, CanonicalJsonObject, RoomVersionId};
use ruma_signatures::{verify_event, PublicKeyMap, PublicKeySet};
use serde_json::{json, Value};

use rezzy::basespec::rezzy_types::{compute_content_hash, verify_content_hash};
use rezzy::signing::{verify_event_signatures, DalekVerifier};

const ROOM_VERSION: &str = "10";

/// Builds a signed, content-hash-valid `m.room.message` PDU signed by
/// `example.com` under `ed25519:0`. Returns the event plus the raw public key.
fn build_signed_event() -> (Value, [u8; 32]) {
    let sk = SigningKey::from_bytes(&[42_u8; 32]);
    let vk = sk.verifying_key();

    let mut value = json!({
        "type": "m.room.message",
        "room_id": "!room:example.com",
        "sender": "@alice:example.com",
        "origin_server_ts": 1_000_000,
        "depth": 3,
        "prev_events": [],
        "auth_events": [],
        "content": { "body": "hello world", "msgtype": "m.text" },
    });

    // Set a valid content hash so the full verify pipeline (hash + sig) passes.
    let content_hash = compute_content_hash(&value, ROOM_VERSION).unwrap();
    value["hashes"] = json!({ "sha256": content_hash });

    // Sign the canonical redacted JSON (the string an ed25519 PDU signature covers).
    let canonical = rezzy::basespec::rezzy_types::canonical_redacted_json(&value, ROOM_VERSION);
    let sig = sk.sign(canonical.as_bytes());
    let sig_b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(sig.to_bytes());
    value["signatures"] = json!({ "example.com": { "ed25519:0": sig_b64 } });

    (value, vk.to_bytes())
}

fn bench_rezzy(value: &Value, keys: &DalekVerifier) -> Result<(), String> {
    verify_event_signatures(value, ROOM_VERSION, keys)?;
    verify_content_hash(value, ROOM_VERSION)?;
    Ok(())
}

fn bench_ruma(object: &CanonicalJsonObject, map: &PublicKeyMap, rules: &RoomVersionRules) {
    verify_event(map, object, rules).expect("ruma verify_event succeeds");
}

fn time<F: FnMut()>(label: &str, iters: u32, mut f: F) -> Duration {
    // warm up
    for _ in 0..100 {
        f();
    }
    let start = Instant::now();
    for _ in 0..iters {
        black_box(f());
    }
    let elapsed = start.elapsed();
    let per = elapsed / iters;
    println!("{label:<28} {elapsed:>10.3?} total  |  {per:>8.1?} / iter",);
    elapsed
}

fn main() {
    let (value, vk) = build_signed_event();
    let object: CanonicalJsonObject = serde_json::from_value(value.clone()).expect("convert");
    let iters = 10_000;

    // Build both key maps once, outside the timed loop.
    let mut keys = DalekVerifier::new();
    keys.insert_public_key("example.com", "ed25519:0", &vk)
        .expect("valid public key");
    let mut set = PublicKeySet::new();
    set.insert("ed25519:0".to_string(), Base64::new(vk.to_vec()));
    let mut map = PublicKeyMap::new();
    map.insert("example.com".to_string(), set);
    let rules = RoomVersionId::V10.rules().expect("v10 rules exist");

    // sanity: both paths actually verify the fixture
    bench_rezzy(&value, &keys).expect("rezzy verifies fixture");
    bench_ruma(&object, &map, &rules);

    println!("signature-verify head-to-head (room v10, 1 server sig + content hash)");
    let rz = time("rezzy native", iters, || {
        let _ = black_box(bench_rezzy(&value, &keys));
    });
    let rm = time("ruma verify_event", iters, || {
        bench_ruma(&object, &map, &rules);
    });

    let speedup = rm.as_secs_f64() / rz.as_secs_f64();
    println!("\nruma / rezzy = {speedup:.2}x");

    // Batch vs sequential at two scales.
    bench_batch(&value, &keys, 64, 1_000);
    bench_batch(&value, &keys, 5_000, 20);

    // Parse: bytes -> Value, serde_json vs simd-json.
    let event_bytes = serde_json::to_vec(&value).expect("serialize");
    let parse_iters = 10_000;
    println!("\nparse bytes -> Value (event JSON)");
    let pj = time("serde_json parse", parse_iters, || {
        let _ = black_box(serde_json::from_slice::<Value>(&event_bytes));
    });
    let ps = time("simd-json parse", parse_iters, || {
        let mut buf = event_bytes.clone();
        let _ = black_box(simd_json::serde::from_slice::<Value>(&mut buf));
    });
    println!(
        "serde_json / simd-json = {:.2}x",
        pj.as_secs_f64() / ps.as_secs_f64()
    );
}

/// Times verifying `n` distinct signed PDUs (same server key) one-at-a-time vs
/// a single `verify_batch` call.
fn bench_batch(value: &Value, keys: &DalekVerifier, n: usize, iters: u32) {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[42_u8; 32]);
    let events: Vec<Value> = (0..n)
        .map(|i| {
            let mut v = value.clone();
            v["origin_server_ts"] = json!(i);
            // Recompute the content hash after mutating origin_server_ts so each
            // batch event is a self-consistent PDU, not just signature-valid.
            let content_hash = rezzy::basespec::rezzy_types::compute_content_hash(&v, ROOM_VERSION)
                .expect("content hash computation is infallible");
            v["hashes"] = json!({ "sha256": content_hash });
            let canonical = rezzy::basespec::rezzy_types::canonical_redacted_json(&v, ROOM_VERSION);
            let sig = sk.sign(canonical.as_bytes());
            let sig_b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(sig.to_bytes());
            v["signatures"] = json!({ "example.com": { "ed25519:0": sig_b64 } });
            v
        })
        .collect();

    println!("\nbatch vs sequential: {n} signed PDUs, 1 server sig each");
    let seq = time("sequential xN", iters, || {
        for e in &events {
            let _ = black_box(verify_event_signatures(e, ROOM_VERSION, keys));
        }
    });
    let bat = time("verify_batch xN", iters, || {
        let _ = black_box(rezzy::signing::verify_batch(&events, ROOM_VERSION, keys));
    });
    println!(
        "sequential / batch = {:.2}x",
        seq.as_secs_f64() / bat.as_secs_f64()
    );
}
