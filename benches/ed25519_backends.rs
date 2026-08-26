//! Isolated raw Ed25519 backend comparison.
//!
//! `ed25519-consensus` is deliberately a dev-dependency used only here. This
//! benchmark compares identical valid messages and signatures across dalek's
//! RFC-8032-strict verifier and the ZIP-215 consensus verifier, sequentially
//! and in batches.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    clippy::items_after_statements,
    clippy::pedantic,
    clippy::print_stdout,
    clippy::unit_arg
)]

use std::hint::black_box;
use std::time::{Duration, Instant};

use ed25519_consensus::{batch, Signature as ConsensusSignature, VerificationKey};
use ed25519_dalek::{Signature as DalekSignature, Signer as _, SigningKey, VerifyingKey};

struct Fixture {
    messages: Vec<Vec<u8>>,
    dalek_signatures: Vec<DalekSignature>,
    consensus_signatures: Vec<ConsensusSignature>,
    dalek_key: VerifyingKey,
    consensus_key: VerificationKey,
}

fn fixture(size: usize) -> Fixture {
    let signing_key = SigningKey::from_bytes(&[42_u8; 32]);
    let dalek_key = signing_key.verifying_key();
    let consensus_key = VerificationKey::try_from(dalek_key.to_bytes()).expect("valid key");

    let messages: Vec<Vec<u8>> = (0..size)
        .map(|index| format!("rezzy ed25519 backend benchmark message {index}").into_bytes())
        .collect();
    let dalek_signatures: Vec<DalekSignature> = messages
        .iter()
        .map(|message| signing_key.sign(message))
        .collect();
    let consensus_signatures = dalek_signatures
        .iter()
        .map(|signature| ConsensusSignature::from(signature.to_bytes()))
        .collect();

    Fixture {
        messages,
        dalek_signatures,
        consensus_signatures,
        dalek_key,
        consensus_key,
    }
}

fn time(mut operation: impl FnMut(), iterations: u32) -> Duration {
    for _ in 0..10 {
        black_box(operation());
    }
    let start = Instant::now();
    for _ in 0..iterations {
        black_box(operation());
    }
    start.elapsed()
}

fn report(label: &str, duration: Duration, iterations: u32, signatures: usize) {
    let operations = f64::from(iterations) * signatures as f64;
    let nanos_per_signature = duration.as_secs_f64() * 1_000_000_000.0 / operations;
    println!("{label:<24} {nanos_per_signature:>10.1} ns/signature");
}

fn benchmark(size: usize, iterations: u32) {
    let fixture = fixture(size);
    let message_refs: Vec<&[u8]> = fixture.messages.iter().map(Vec::as_slice).collect();
    let dalek_keys = vec![fixture.dalek_key; size];

    let dalek_sequential = time(
        || {
            for (message, signature) in fixture.messages.iter().zip(&fixture.dalek_signatures) {
                fixture
                    .dalek_key
                    .verify_strict(message, signature)
                    .expect("dalek verification");
            }
        },
        iterations,
    );
    let consensus_sequential = time(
        || {
            for (message, signature) in fixture.messages.iter().zip(&fixture.consensus_signatures) {
                fixture
                    .consensus_key
                    .verify(signature, message)
                    .expect("consensus verification");
            }
        },
        iterations,
    );
    let dalek_batch = time(
        || {
            ed25519_dalek::verify_batch(&message_refs, &fixture.dalek_signatures, &dalek_keys)
                .expect("dalek batch verification");
        },
        iterations,
    );
    let consensus_batch = time(
        || {
            let mut verifier = batch::Verifier::new();
            for (message, signature) in fixture.messages.iter().zip(&fixture.consensus_signatures) {
                verifier.queue((fixture.consensus_key.into(), *signature, message));
            }
            verifier
                .verify(rand_08::thread_rng())
                .expect("consensus batch verification");
        },
        iterations,
    );

    println!("\n{size} signatures ({iterations} iterations, one shared key)");
    report("dalek sequential", dalek_sequential, iterations, size);
    report(
        "consensus sequential",
        consensus_sequential,
        iterations,
        size,
    );
    report("dalek batch", dalek_batch, iterations, size);
    report("consensus batch", consensus_batch, iterations, size);
    println!(
        "consensus/dalek: sequential {:.2}x, batch {:.2}x",
        dalek_sequential.as_secs_f64() / consensus_sequential.as_secs_f64(),
        dalek_batch.as_secs_f64() / consensus_batch.as_secs_f64(),
    );
}

fn main() {
    benchmark(1, 10_000);
    benchmark(64, 1_000);
    benchmark(5_000, 20);
}
