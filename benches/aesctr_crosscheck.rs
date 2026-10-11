// Cross-implementation check: computes the AES-256-CTR LtHash16 accumulator
// digest for the two entries pinned in gomatrixcrypto's
// lthash.TestAESCTRVector, using the real expansion_backends.rs (included,
// not copied). Run with:
//
//	cargo test --manifest-path ../rezzy/benches/Cargo.toml --test aesctr_crosscheck
//
// The lane mapping and collapse here must match gomatrixcrypto exactly:
// 1024 little-endian uint16 lanes, wrapping (mod 2^16) add, BLAKE3-256 of the
// LE-serialized lattice, unpadded base64url.

#[allow(dead_code)]
#[path = "math/expansion_backends.rs"]
mod expansion_backends;

use expansion_backends::{expand_aes_ctr, DST_AES_CTR, SEED_BYTES};

const LANES: usize = SEED_BYTES / 2;

fn frame_element(dst: &[u8], event_type: &str, state_key: &str, event_id: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(dst);
    buf.extend_from_slice(&(event_type.len() as u16).to_le_bytes());
    buf.extend_from_slice(event_type.as_bytes());
    buf.extend_from_slice(&(state_key.len() as u16).to_le_bytes());
    buf.extend_from_slice(state_key.as_bytes());
    buf.extend_from_slice(event_id.as_bytes());
    buf
}

fn unpack_lanes(bytes: &[u8]) -> [u16; LANES] {
    let mut out = [0u16; LANES];
    for (lane, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
        *lane = u16::from_le_bytes([pair[0], pair[1]]);
    }
    out
}

fn seed(event_type: &str, state_key: &str, event_id: &str, ni: bool) -> [u16; LANES] {
    let frame = frame_element(DST_AES_CTR, event_type, state_key, event_id);
    let mut bytes = [0u8; SEED_BYTES];
    expand_aes_ctr(&frame, &mut bytes, ni);
    unpack_lanes(&bytes)
}

fn add_seed(acc: &mut [u16; LANES], s: &[u16; LANES]) {
    for (a, b) in acc.iter_mut().zip(s) {
        *a = a.wrapping_add(*b);
    }
}

fn collapse(lattice: &[u16; LANES]) -> String {
    let mut bytes = Vec::with_capacity(LANES * 2);
    for lane in lattice {
        bytes.extend_from_slice(&lane.to_le_bytes());
    }
    let digest = blake3::hash(&bytes);
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, digest.as_bytes())
}

fn accumulate(ni: bool) -> String {
    let entries = [
        ("m.room.create", "", "$a"),
        ("m.room.member", "@alice:example.org", "$b"),
    ];
    let mut lattice = [0u16; LANES];
    for (event_type, state_key, event_id) in entries {
        add_seed(&mut lattice, &seed(event_type, state_key, event_id, ni));
    }
    collapse(&lattice)
}

#[test]
fn aesctr_digest_matches_gomatrixcrypto_pin() {
    let got = accumulate(false);
    let want = "L5WCOKR7yn1u44_LVhGVrttjSxq5gLCbwWUCs0eq1iQ";
    assert_eq!(
        got, want,
        "portable AES-CTR digest diverged from gomatrixcrypto's pin"
    );
}

#[test]
fn aesctr_ni_matches_portable() {
    if !expansion_backends::aes_ni_available() {
        eprintln!("AES-NI unavailable; skipping NI-vs-portable differential");
        return;
    }
    assert_eq!(
        accumulate(true),
        accumulate(false),
        "AES-NI and portable AES-CTR paths diverged"
    );
}
