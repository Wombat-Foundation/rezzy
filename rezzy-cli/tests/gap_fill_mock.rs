//! End-to-end `rezzy federation gap-fill` against a local mock federation
//! server. These pin the behaviour that went wrong in practice: a run that
//! fetched nothing and said nothing.
//!
//! The mock speaks plain HTTP, which rezzy only allows with
//! `REZZY_ALLOW_INSECURE_HTTP=1`. Keys are throwaway; nothing leaves localhost.

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};
use std::thread;

const ROOM: &str = "!L58ME6ufiP49v97UIOBIpvWKEgj4912JmECPuDzlvCI";
/// A real v12 event ID and its wire PDU (no `event_id` field, as on the wire).
const TARGET: &str = "$IYh3j5DDlpXmmErAivzq4d1PVT0DxegxvvKtlWVDoFE";
const PARENT: &str = "$YgQCx1FMxaNlpl8CoymZCmPLcE9YJ95kwnp8VBHJiqY";
const AUTH_A: &str = "$sbusQdJu8vp4mYghGgIdFrz9K_UbSNVmVr3UBxLM2Mk";
const AUTH_B: &str = "$SbBcrKoU8Wo-rq9hH6NORFEcD7jrSgLkyYBgvlvNZVc";
const STILL_MISSING: &str = "$stillMissingEventThatNoServerHas000000000000";
const PDU: &str = r#"{"auth_events":["$sbusQdJu8vp4mYghGgIdFrz9K_UbSNVmVr3UBxLM2Mk","$SbBcrKoU8Wo-rq9hH6NORFEcD7jrSgLkyYBgvlvNZVc"],"content":{"body":"A nice sunny day spent near the window.","m.mentions":{},"msgtype":"m.text"},"depth":265,"hashes":{"sha256":"BN2Mpld9Ox01qmZjEh+2SXjc3hf67Z+UrUvCc/TdJoc"},"origin_server_ts":1763426725083,"prev_events":["$YgQCx1FMxaNlpl8CoymZCmPLcE9YJ95kwnp8VBHJiqY"],"room_id":"!L58ME6ufiP49v97UIOBIpvWKEgj4912JmECPuDzlvCI","sender":"@chtr-x:matrix.org","signatures":{"matrix.org":{"ed25519:a_RXGa":"EKGxFhkSSIlattBwQDE9V1moJdRz6FGd4tC+u43q6z0/8v3oys743hvIStLWTO0LYR1GrntNOHyztbUaIVQOAw"}},"type":"m.room.message","unsigned":{"age_ts":1763426725083}}"#;
/// 32 bytes (0..31), base64 without padding: a valid, throwaway ed25519 seed.
const KEY_LINE: &str = "ed25519 test AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

#[derive(Clone, Copy)]
enum Backfill {
    /// Returns the target event.
    Events,
    /// 200 with an empty `pdus` list.
    Blank,
    /// HTTP 500.
    Error,
}

#[derive(Clone, Copy)]
enum EventShape {
    /// `{"origin":…, "pdus":[…]}`, what matrix.org returns.
    Pdus,
    /// `{"pdu": {…}}`, an older/custom shape.
    Pdu,
}

struct Mock {
    url: String,
    requests: Arc<Mutex<Vec<String>>>,
}

impl Mock {
    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
    fn count(&self, needle: &str) -> usize {
        self.requests()
            .iter()
            .filter(|r| r.contains(needle))
            .count()
    }
}

fn respond(stream: &mut TcpStream, code: u16, body: &str) {
    let head = format!(
        "HTTP/1.1 {code} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body.as_bytes());
}

fn handle(mut stream: TcpStream, backfill: Backfill, shape: EventShape, log: &Mutex<Vec<String>>) {
    let mut buf = Vec::new();
    let mut chunk = [0_u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    let text = String::from_utf8_lossy(&buf).into_owned();
    let path = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("")
        .replace("%24", "$");
    let signed = text
        .to_ascii_lowercase()
        .contains("authorization: x-matrix");
    log.lock()
        .unwrap()
        .push(format!("{path}{}", if signed { "" } else { " UNSIGNED" }));
    if path.contains("/federation/v1/backfill/") {
        match backfill {
            Backfill::Events => respond(
                &mut stream,
                200,
                &format!(r#"{{"origin":"mock","origin_server_ts":1,"pdus":[{PDU}]}}"#),
            ),
            Backfill::Blank => respond(
                &mut stream,
                200,
                r#"{"origin":"mock","origin_server_ts":1,"pdus":[]}"#,
            ),
            Backfill::Error => respond(&mut stream, 500, r#"{"errcode":"M_UNKNOWN"}"#),
        }
    } else if path.contains("/federation/v1/event/") {
        if path.ends_with(TARGET) {
            let body = match shape {
                EventShape::Pdus => {
                    format!(r#"{{"origin":"mock","origin_server_ts":1,"pdus":[{PDU}]}}"#)
                }
                EventShape::Pdu => format!(r#"{{"pdu":{PDU}}}"#),
            };
            respond(&mut stream, 200, &body);
        } else {
            respond(
                &mut stream,
                404,
                r#"{"errcode":"M_NOT_FOUND","error":"nope"}"#,
            );
        }
    } else {
        respond(&mut stream, 404, "{}");
    }
}

fn spawn_mock(backfill: Backfill, shape: EventShape) -> Mock {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&requests);
    // Serves until the test process exits.
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            handle(stream, backfill, shape, &log);
        }
    });
    Mock { url, requests }
}

struct Fixture {
    dir: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("rezzy-gapfill-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        // The local copy: a child whose parents are the target (missing) and
        // one more event nobody has; the target's own parent and auth events
        // are held locally and so must never be requested.
        let ev = |id: &str, prev: &[&str]| {
            let list = prev
                .iter()
                .map(|p| format!("\"{p}\""))
                .collect::<Vec<_>>()
                .join(",");
            format!(
                r#"{{"event_id":"{id}","room_id":"{ROOM}","type":"m.room.message","sender":"@a:x","depth":1,"origin_server_ts":1,"content":{{}},"prev_events":[{list}],"auth_events":[]}}"#
            )
        };
        let lines = [
            ev("$child", &[TARGET, STILL_MISSING]),
            ev(PARENT, &[]),
            ev(AUTH_A, &[]),
            ev(AUTH_B, &[]),
        ];
        fs::write(dir.join("base.jsonl"), lines.join("\n") + "\n").unwrap();
        fs::write(dir.join("key.plain"), format!("{KEY_LINE}\n")).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_rezzy"))
            .env("REZZY_KEY_PASSPHRASE", "test")
            .args(["federation", "encrypt-key", "-i"])
            .arg(dir.join("key.plain"))
            .arg("-o")
            .arg(dir.join("key.enc"))
            .output()
            .unwrap();
        assert!(out.status.success(), "encrypt-key failed: {out:?}");
        Self { dir }
    }

    fn gap_fill(&self, destination: &str, insecure: bool) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_rezzy"));
        cmd.env("REZZY_KEY_PASSPHRASE", "test");
        if insecure {
            cmd.env("REZZY_ALLOW_INSECURE_HTTP", "1");
        } else {
            cmd.env_remove("REZZY_ALLOW_INSECURE_HTTP");
        }
        cmd.args(["federation", "gap-fill", "-i"])
            .arg(self.dir.join("base.jsonl"))
            .args(["--destination", destination, "--room", ROOM])
            .args(["--origin", "test.example", "--rounds", "0", "--signing-key"])
            .arg(self.dir.join("key.enc"))
            .arg("--output-dir")
            .arg(self.dir.join("out"))
            .output()
            .unwrap()
    }

    /// Everything fetched, across rounds.
    fn fetched(&self) -> String {
        let mut all = String::new();
        let mut rounds: Vec<PathBuf> = fs::read_dir(self.dir.join("out"))
            .map(|d| d.flatten().map(|e| e.path()).collect())
            .unwrap_or_default();
        rounds.sort();
        for round in rounds {
            for file in fs::read_dir(&round).into_iter().flatten().flatten() {
                all.push_str(&fs::read_to_string(file.path()).unwrap_or_default());
            }
        }
        all
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn run(name: &str, backfill: Backfill, shape: EventShape) -> (Mock, Fixture, Output) {
    let mock = spawn_mock(backfill, shape);
    let fx = Fixture::new(name);
    let out = fx.gap_fill(&mock.url, true);
    (mock, fx, out)
}

#[test]
fn backfill_is_tried_first_and_its_events_are_used() {
    let (mock, fx, out) = run("backfill-first", Backfill::Events, EventShape::Pdus);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(mock.count("/backfill/") >= 1, "{:?}", mock.requests());
    assert!(fx.fetched().contains(TARGET), "target not written");
}

#[test]
fn blank_backfill_falls_back_to_fetching_by_event_id() {
    let (mock, fx, out) = run("blank-backfill", Backfill::Blank, EventShape::Pdus);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(mock.count("/backfill/") >= 1);
    assert!(
        mock.count(&format!("/event/{TARGET}")) >= 1,
        "{:?}",
        mock.requests()
    );
    assert!(fx.fetched().contains(TARGET));
}

#[test]
fn failing_backfill_falls_back_to_fetching_by_event_id() {
    let (mock, fx, out) = run("error-backfill", Backfill::Error, EventShape::Pdus);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(mock.count(&format!("/event/{TARGET}")) >= 1);
    assert!(fx.fetched().contains(TARGET));
}

#[test]
fn single_pdu_event_response_shape_is_accepted() {
    // Regression: the by-ID fallback once read only `{"pdu": …}`, but servers
    // return `{"pdus": […]}`; the reverse must keep working too.
    let (_mock, fx, out) = run("pdu-shape", Backfill::Blank, EventShape::Pdu);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(fx.fetched().contains(TARGET));
}

#[test]
fn wire_pdu_without_event_id_is_written_under_its_reference_hash() {
    // Wire PDUs carry no `event_id` in room v3+; it must be derived, and must
    // equal the ID we asked for.
    let (_mock, fx, out) = run("reference-hash", Backfill::Blank, EventShape::Pdus);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let line = fx
        .fetched()
        .lines()
        .find(|l| l.contains("A nice sunny day"))
        .map(str::to_owned)
        .expect("fetched event line");
    let compact: String = line.split_whitespace().collect();
    assert!(
        compact.contains(&format!("\"event_id\":\"{TARGET}\"")),
        "{line}"
    );
}

#[test]
fn events_we_already_hold_are_never_requested() {
    let (mock, _fx, out) = run("known-skipped", Backfill::Blank, EventShape::Pdus);
    assert!(out.status.success(), "{}", text(&out.stderr));
    for held in [PARENT, AUTH_A, AUTH_B] {
        assert_eq!(
            mock.count(held),
            0,
            "{held} requested: {:?}",
            mock.requests()
        );
    }
}

#[test]
fn every_request_is_signed() {
    let (mock, _fx, _out) = run("signed", Backfill::Blank, EventShape::Pdus);
    assert!(!mock.requests().is_empty());
    assert!(
        mock.requests().iter().all(|r| !r.ends_with("UNSIGNED")),
        "{:?}",
        mock.requests()
    );
}

#[test]
fn unfetchable_events_are_reported_not_fatal() {
    let (_mock, _fx, out) = run("incomplete", Backfill::Blank, EventShape::Pdus);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(stdout.contains("incomplete"), "{stdout}");
    assert!(stdout.contains(STILL_MISSING), "{stdout}");
    assert!(
        text(&out.stderr).contains("[warn]"),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn progress_is_reported_while_running() {
    let (_mock, _fx, out) = run("progress", Backfill::Blank, EventShape::Pdus);
    let stderr = text(&out.stderr);
    assert!(stderr.contains("[info] round 0"), "{stderr}");
    assert!(stderr.contains("[progress]"), "{stderr}");
}

#[test]
fn an_unreachable_server_is_an_error_not_silence() {
    let port = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    }; // listener dropped: nothing is listening on `port`
    let fx = Fixture::new("unreachable");
    let out = fx.gap_fill(&format!("http://127.0.0.1:{port}"), true);
    assert!(!out.status.success(), "{}", text(&out.stdout));
    assert!(
        !text(&out.stderr).trim().is_empty(),
        "no diagnostic on stderr"
    );
}

#[test]
fn plaintext_http_is_refused_without_explicit_opt_in() {
    let mock = spawn_mock(Backfill::Events, EventShape::Pdus);
    let fx = Fixture::new("insecure-refused");
    let out = fx.gap_fill(&mock.url, false);
    assert!(text(&out.stderr).contains("REZZY_ALLOW_INSECURE_HTTP"));
    assert!(mock.requests().is_empty(), "signed request sent over http");
    assert!(!fx.fetched().contains(TARGET));
}
