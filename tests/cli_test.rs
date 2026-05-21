use std::process::Command;
use std::fs;
use serde_json::Value;

#[test]
fn test_cli_ignores_non_state_events() {
    let temp_file = "res/temp_non_state_test.jsonl";
    let events = r#"
{"event_id": "$1", "type": "m.room.create", "state_key": "", "depth": 1, "sender": "@alice:localhost"}
{"event_id": "$2", "type": "m.room.message", "depth": 2, "sender": "@alice:localhost"}
"#;
    fs::write(temp_file, events.trim()).unwrap();

    let output = Command::new("cargo")
        .args(["run", "--features", "cli", "--", "-i", temp_file, "-f", "default"])
        .output()
        .expect("failed to execute process");

    assert!(output.status.success(), "CLI failed: {:?}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Find the JSON part by skipping "Compiling" lines
    let json_str = stdout.lines().find(|l| l.starts_with('{')).expect("No JSON output");
    let val: Value = serde_json::from_str(json_str).unwrap();

    let state_event_ids = val["state_event_ids"].as_array().unwrap();
    // It should ONLY contain "$1", ignoring "$2" because it's a non-state event (missing state_key).
    assert_eq!(state_event_ids.len(), 1);
    assert_eq!(state_event_ids[0].as_str().unwrap(), "$1");

    fs::remove_file(temp_file).unwrap();
}
