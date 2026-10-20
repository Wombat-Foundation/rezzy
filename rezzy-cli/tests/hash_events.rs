//! `rezzy hash events` against a real room-v12 event whose ID is known.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

const TARGET: &str = "$IYh3j5DDlpXmmErAivzq4d1PVT0DxegxvvKtlWVDoFE";
const PARENT: &str = "$YgQCx1FMxaNlpl8CoymZCmPLcE9YJ95kwnp8VBHJiqY";
const AUTH_A: &str = "$sbusQdJu8vp4mYghGgIdFrz9K_UbSNVmVr3UBxLM2Mk";
/// A real v12 event as it travels on the wire (no `event_id`).
const PDU: &str = r#"{"auth_events":["$sbusQdJu8vp4mYghGgIdFrz9K_UbSNVmVr3UBxLM2Mk","$SbBcrKoU8Wo-rq9hH6NORFEcD7jrSgLkyYBgvlvNZVc"],"content":{"body":"A nice sunny day spent near the window.","m.mentions":{},"msgtype":"m.text"},"depth":265,"hashes":{"sha256":"BN2Mpld9Ox01qmZjEh+2SXjc3hf67Z+UrUvCc/TdJoc"},"origin_server_ts":1763426725083,"prev_events":["$YgQCx1FMxaNlpl8CoymZCmPLcE9YJ95kwnp8VBHJiqY"],"room_id":"!L58ME6ufiP49v97UIOBIpvWKEgj4912JmECPuDzlvCI","sender":"@chtr-x:matrix.org","signatures":{"matrix.org":{"ed25519:a_RXGa":"EKGxFhkSSIlattBwQDE9V1moJdRz6FGd4tC+u43q6z0/8v3oys743hvIStLWTO0LYR1GrntNOHyztbUaIVQOAw"}},"type":"m.room.message","unsigned":{"age_ts":1763426725083}}"#;

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rezzy-hash-events-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn hash_events(name: &str, lines: &[String], version: &str) -> Output {
    let dir = dir(name);
    let input = dir.join("in.jsonl");
    fs::write(&input, lines.join("\n") + "\n").unwrap();
    Command::new(env!("CARGO_BIN_EXE_rezzy"))
        .args(["hash", "events", "--room-version", version, "-i"])
        .arg(&input)
        .output()
        .unwrap()
}

fn compact(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .collect()
}

#[test]
fn a_real_event_hashes_to_its_known_id_with_its_links() {
    let out = hash_events("real", &[PDU.to_owned()], "12");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json = compact(&out);
    assert!(
        json.contains(&format!("\"event_id\":\"{TARGET}\"")),
        "{json}"
    );
    assert!(json.contains("\"content_hash_ok\":true"), "{json}");
    assert!(json.contains("\"depth\":265"), "{json}");
    assert!(
        json.contains(&format!("\"prev_events\":[\"{PARENT}\"]")),
        "{json}"
    );
    assert!(
        json.contains(&format!("\"auth_events\":[\"{AUTH_A}\"")),
        "{json}"
    );
    assert!(!json.contains("\"redacted\""), "{json}");
}

#[test]
fn an_event_id_field_on_the_event_is_not_part_of_what_is_hashed() {
    // Exports and bounty submissions carry `event_id`; the wire PDU does not.
    // It must not change the reference hash or the content-hash check.
    let with_id = PDU.replacen('{', &format!("{{\"event_id\":\"{TARGET}\","), 1);
    let out = hash_events("with-id", &[with_id], "12");
    let json = compact(&out);
    assert!(
        json.contains(&format!("\"event_id\":\"{TARGET}\"")),
        "{json}"
    );
    assert!(
        json.contains(&format!("\"claimed_event_id\":\"{TARGET}\"")),
        "{json}"
    );
    assert!(json.contains("\"content_hash_ok\":true"), "{json}");
}

#[test]
fn a_content_hash_mismatch_is_flagged_and_the_redacted_form_is_given() {
    // The body is dropped by redaction, so the ID is unchanged, but the content
    // hash no longer covers the content.
    let tampered = PDU.replace("A nice sunny day", "A different day");
    let out = hash_events("tampered", &[tampered], "12");
    let json = compact(&out);
    assert!(
        json.contains(&format!("\"event_id\":\"{TARGET}\"")),
        "{json}"
    );
    assert!(json.contains("\"content_hash_ok\":false"), "{json}");
    assert!(json.contains("\"redacted\""), "{json}");
    assert!(!json.contains("different day"), "{json}");
}

#[test]
fn a_change_to_a_preserved_field_changes_the_id() {
    let moved = PDU.replace("\"depth\":265", "\"depth\":266");
    let json = compact(&hash_events("depth", &[moved], "12"));
    assert!(
        !json.contains(&format!("\"event_id\":\"{TARGET}\"")),
        "{json}"
    );
}

#[test]
fn a_bad_line_gets_an_error_record_and_the_rest_are_still_hashed() {
    let lines = ["not json".to_owned(), PDU.to_owned()];
    let out = hash_events("badline", &lines, "12");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json = compact(&out);
    assert!(json.contains("\"error\":\"invalidJSON"), "{json}");
    assert!(json.contains("\"line\":1"), "{json}");
    assert!(json.contains("\"line\":2"), "{json}");
    assert!(
        json.contains(&format!("\"event_id\":\"{TARGET}\"")),
        "{json}"
    );
}

#[test]
fn an_unknown_room_version_is_an_error_per_event_not_a_guess() {
    let json = compact(&hash_events("version", &[PDU.to_owned()], "999"));
    assert!(json.contains("\"error\""), "{json}");
    assert!(
        !json.contains(&format!("\"event_id\":\"{TARGET}\"")),
        "{json}"
    );
}

#[test]
fn empty_input_is_an_error() {
    let out = hash_events("empty", &[String::new()], "12");
    assert!(!out.status.success());
}
