#![allow(unsafe_code)]

use core::cell::Cell;
use std::alloc::{GlobalAlloc, Layout, System};

struct CountingAlloc;

thread_local! {
    static THREAD_ALLOC_COUNT: Cell<usize> = const { Cell::new(0) };
    static TRACKING_ENABLED: Cell<bool> = const { Cell::new(false) };
}

fn set_tracking(enabled: bool) {
    TRACKING_ENABLED.with(|t| t.set(enabled));
}

fn get_thread_alloc_count() -> usize {
    THREAD_ALLOC_COUNT.with(std::cell::Cell::get)
}

fn reset_thread_alloc_count() {
    THREAD_ALLOC_COUNT.with(|c| c.set(0));
}

fn record_alloc() {
    TRACKING_ENABLED.with(|enabled| {
        if enabled.get() {
            THREAD_ALLOC_COUNT.with(|count| {
                count.set(count.get().saturating_add(1));
            });
        }
    });
}

/// Runs `body` `iterations` times with allocation tracking on and asserts it
/// never touched the heap.
fn assert_no_alloc(iterations: usize, message: &str, mut body: impl FnMut()) {
    reset_thread_alloc_count();
    set_tracking(true);
    for _ in 0..iterations {
        body();
    }
    set_tracking(false);
    assert_eq!(get_thread_alloc_count(), 0, "{message}");
}

/// Expected fields of one extracted event.
struct Expected<'a> {
    event_id: &'a str,
    room_id: &'a str,
    event_type: &'a str,
    prev_events: &'a [&'a str],
    auth_events: &'a [&'a str],
    relates_to: (&'a str, &'a str),
}

/// Warms `scratch` on `raw`, then asserts steady-state extraction matches
/// `expected` without allocating.
fn assert_zero_alloc_extraction(raw: &[u8], expected: &Expected<'_>, message: &str) {
    let mut scratch = rezzy::MatrixEventScratch::with_capacity(16, 16, 64);
    let _ = rezzy::extract_matrix_event_into(raw, &mut scratch).unwrap();
    assert_no_alloc(1000, message, || {
        let view = rezzy::extract_matrix_event_into(raw, &mut scratch).unwrap();
        assert_eq!(view.event_id, Some(expected.event_id));
        assert_eq!(view.room_id, Some(expected.room_id));
        assert_eq!(view.event_type, Some(expected.event_type));
        assert_eq!(view.state_key, Some(""));
        assert_eq!(view.prev_events, expected.prev_events);
        assert_eq!(view.auth_events, expected.auth_events);
        assert_eq!(view.room_version, Some("10"));
        assert_eq!(view.relates_to, Some(expected.relates_to));
    });
}

// SAFETY: CountingAlloc delegates to System allocator.
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_alloc();
        // SAFETY: Delegating directly to System::alloc.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: Delegating directly to System::dealloc.
        unsafe { System.dealloc(ptr, layout) };
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record_alloc();
        // SAFETY: Delegating directly to System::realloc.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

#[test]
fn test_zero_alloc_extraction_steady_state() {
    let raw = br#"{"event_id":"$e:example.com","room_id":"!r:example.com","type":"m.room.message","state_key":"","prev_events":["$p1","$p2"],"auth_events":[["$a1",{}],["$a2",{}]],"content":{"room_version":"10","m.relates_to":{"rel_type":"m.thread","event_id":"$root"},"body":"hello world","msgtype":"m.text"}}"#;
    assert_zero_alloc_extraction(
        raw,
        &Expected {
            event_id: "$e:example.com",
            room_id: "!r:example.com",
            event_type: "m.room.message",
            prev_events: &["$p1", "$p2"],
            auth_events: &["$a1", "$a2"],
            relates_to: ("m.thread", "$root"),
        },
        "Expected exact 0 heap allocations during steady-state extraction!",
    );
}

#[test]
fn test_zero_alloc_escaped_keys() {
    let raw = br#"{"\u0065vent_id":"$e","\u0072oom_id":"!r","\u0074ype":"m.room.message","\u0073tate_key":"","\u0070rev_events":["$p"],"\u0061uth_events":["$a"],"content":{"\u0072oom_version":"10","\u006d.relates_to":{"rel_type":"m.annotation","event_id":"$parent"}}}"#;
    assert_zero_alloc_extraction(
        raw,
        &Expected { event_id: "$e", room_id: "!r", event_type: "m.room.message", prev_events: &["$p"], auth_events: &["$a"], relates_to: ("m.annotation", "$parent") },
        "Expected exact 0 heap allocations during escaped-key extraction with preallocated key_buffer!",
    );
}

#[test]
fn test_zero_alloc_escaped_values() {
    let raw = br#"{"event_id":"\u0024escaped_event:example.com","room_id":"\u0021escaped_room:example.com","type":"\u006d.room.message","state_key":"","prev_events":["$p1"],"auth_events":["$a1"],"content":{"room_version":"\u0031\u0030","m.relates_to":{"rel_type":"\u006d.thread","event_id":"\u0024root"}}}"#;
    assert_zero_alloc_extraction(
        raw,
        &Expected { event_id: "$escaped_event:example.com", room_id: "!escaped_room:example.com", event_type: "m.room.message", prev_events: &["$p1"], auth_events: &["$a1"], relates_to: ("m.thread", "$root") },
        "Expected exact 0 heap allocations during escaped-value extraction with preallocated scratch buffers!",
    );
}

#[test]
fn test_zero_alloc_malformed_and_varying_sizes() {
    let inputs: [&[u8]; 4] = [
        br#"{"event_id":"$short","room_id":"!r","type":"m.room.create"}"#,
        br#"{"event_id":"$longer_event_identifier_0123456789","room_id":"!longer_room_identifier:matrix.org","type":"m.room.member","state_key":"@user:matrix.org","prev_events":["$p1","$p2","$p3","$p4"]}"#,
        br#"{"invalid_json_missing_brace": true"#,
        br#"{"event_id":12345}"#, // invalid type for event_id
    ];

    let mut scratch = rezzy::MatrixEventScratch::with_capacity(16, 16, 64);

    // Warm-up across inputs
    for input in &inputs {
        let _ = rezzy::extract_matrix_event_into(input, &mut scratch);
    }

    assert_no_alloc(
        500,
        "Expected exact 0 heap allocations across varied event sizes and error paths!",
        || {
            for (i, input) in inputs.iter().enumerate() {
                let res = rezzy::extract_matrix_event_into(input, &mut scratch);
                match i.cmp(&2) {
                    std::cmp::Ordering::Less => assert!(res.is_ok()),
                    std::cmp::Ordering::Equal => assert!(res.is_err()),
                    std::cmp::Ordering::Greater => assert_eq!(res.unwrap().event_id, None),
                }
            }
        },
    );
}

#[test]
fn test_capacity_growth_steady_state() {
    // Start with 0 capacity
    let mut scratch = rezzy::MatrixEventScratch::new();

    let large_event = br#"{"event_id":"$large","room_id":"!r:x","type":"m.room.message","prev_events":["$p1","$p2","$p3","$p4","$p5","$p6","$p7","$p8","$p9","$p10"],"auth_events":["$a1","$a2","$a3","$a4","$a5","$a6","$a7","$a8"]}"#;

    // First iteration may allocate to grow capacity
    let _ = rezzy::extract_matrix_event_into(large_event, &mut scratch).unwrap();

    // Now in steady state, subsequent extractions of the large event must not allocate
    assert_no_alloc(
        1000,
        "Expected 0 allocations once scratch buffers have grown to accommodate event!",
        || {
            let view = rezzy::extract_matrix_event_into(large_event, &mut scratch).unwrap();
            assert_eq!(view.event_id, Some("$large"));
            assert_eq!(view.prev_events.len(), 10);
            assert_eq!(view.auth_events.len(), 8);
        },
    );
}
