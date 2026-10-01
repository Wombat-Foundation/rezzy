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

// SAFETY: CountingAlloc delegates to System allocator.
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        TRACKING_ENABLED.with(|enabled| {
            if enabled.get() {
                THREAD_ALLOC_COUNT.with(|count| {
                    count.set(count.get().saturating_add(1));
                });
            }
        });
        // SAFETY: Delegating directly to System::alloc.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: Delegating directly to System::dealloc.
        unsafe { System.dealloc(ptr, layout) };
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        TRACKING_ENABLED.with(|enabled| {
            if enabled.get() {
                THREAD_ALLOC_COUNT.with(|count| {
                    count.set(count.get().saturating_add(1));
                });
            }
        });
        // SAFETY: Delegating directly to System::realloc.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

#[test]
fn test_zero_alloc_extraction_steady_state() {
    let raw = br#"{"event_id":"$e:example.com","room_id":"!r:example.com","type":"m.room.message","state_key":"","prev_events":["$p1","$p2"],"auth_events":[["$a1",{}],["$a2",{}]],"content":{"room_version":"10","m.relates_to":{"rel_type":"m.thread","event_id":"$root"},"body":"hello world","msgtype":"m.text"}}"#;

    let mut scratch = rezzy::MatrixEventScratch::with_capacity(16, 16, 64);

    // Warm-up once
    let _ = rezzy::extract_matrix_event_into(raw, &mut scratch).unwrap();

    reset_thread_alloc_count();
    set_tracking(true);

    for _ in 0..1000 {
        let view = rezzy::extract_matrix_event_into(raw, &mut scratch).unwrap();
        assert_eq!(view.event_id, Some("$e:example.com"));
        assert_eq!(view.room_id, Some("!r:example.com"));
        assert_eq!(view.event_type, Some("m.room.message"));
        assert_eq!(view.state_key, Some(""));
        assert_eq!(view.prev_events, &["$p1", "$p2"]);
        assert_eq!(view.auth_events, &["$a1", "$a2"]);
        assert_eq!(view.room_version, Some("10"));
        assert_eq!(view.relates_to, Some(("m.thread", "$root")));
    }

    set_tracking(false);
    let alloc_count = get_thread_alloc_count();
    assert_eq!(
        alloc_count, 0,
        "Expected exact 0 heap allocations during steady-state extraction!"
    );
}

#[test]
fn test_zero_alloc_escaped_keys() {
    let raw_escaped = br#"{"\u0065vent_id":"$e","\u0072oom_id":"!r","\u0074ype":"m.room.message","\u0073tate_key":"","\u0070rev_events":["$p"],"\u0061uth_events":["$a"],"content":{"\u0072oom_version":"10","\u006d.relates_to":{"rel_type":"m.annotation","event_id":"$parent"}}}"#;

    let mut scratch = rezzy::MatrixEventScratch::with_capacity(16, 16, 64);

    // Warm-up once
    let _ = rezzy::extract_matrix_event_into(raw_escaped, &mut scratch).unwrap();

    reset_thread_alloc_count();
    set_tracking(true);

    for _ in 0..1000 {
        let view = rezzy::extract_matrix_event_into(raw_escaped, &mut scratch).unwrap();
        assert_eq!(view.event_id, Some("$e"));
        assert_eq!(view.room_id, Some("!r"));
        assert_eq!(view.event_type, Some("m.room.message"));
        assert_eq!(view.state_key, Some(""));
        assert_eq!(view.prev_events, &["$p"]);
        assert_eq!(view.auth_events, &["$a"]);
        assert_eq!(view.room_version, Some("10"));
        assert_eq!(view.relates_to, Some(("m.annotation", "$parent")));
    }

    set_tracking(false);
    let alloc_count = get_thread_alloc_count();
    assert_eq!(
        alloc_count,
        0,
        "Expected exact 0 heap allocations during escaped-key extraction with preallocated key_buffer!"
    );
}

#[test]
fn test_zero_alloc_escaped_values() {
    let raw_escaped_val = br#"{"event_id":"\u0024escaped_event:example.com","room_id":"\u0021escaped_room:example.com","type":"\u006d.room.message","state_key":"","prev_events":["$p1"],"auth_events":["$a1"],"content":{"room_version":"\u0031\u0030","m.relates_to":{"rel_type":"\u006d.thread","event_id":"\u0024root"}}}"#;

    let mut scratch = rezzy::MatrixEventScratch::with_capacity(16, 16, 64);

    // Warm-up once
    let _ = rezzy::extract_matrix_event_into(raw_escaped_val, &mut scratch).unwrap();

    reset_thread_alloc_count();
    set_tracking(true);

    for _ in 0..1000 {
        let view = rezzy::extract_matrix_event_into(raw_escaped_val, &mut scratch).unwrap();
        assert_eq!(view.event_id, Some("$escaped_event:example.com"));
        assert_eq!(view.room_id, Some("!escaped_room:example.com"));
        assert_eq!(view.event_type, Some("m.room.message"));
        assert_eq!(view.state_key, Some(""));
        assert_eq!(view.prev_events, &["$p1"]);
        assert_eq!(view.auth_events, &["$a1"]);
        assert_eq!(view.room_version, Some("10"));
        assert_eq!(view.relates_to, Some(("m.thread", "$root")));
    }

    set_tracking(false);
    let alloc_count = get_thread_alloc_count();
    assert_eq!(
        alloc_count,
        0,
        "Expected exact 0 heap allocations during escaped-value extraction with preallocated scratch buffers!"
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

    reset_thread_alloc_count();
    set_tracking(true);

    for _ in 0..500 {
        for (i, input) in inputs.iter().enumerate() {
            let res = rezzy::extract_matrix_event_into(input, &mut scratch);
            match i.cmp(&2) {
                std::cmp::Ordering::Less => assert!(res.is_ok()),
                std::cmp::Ordering::Equal => assert!(res.is_err()),
                std::cmp::Ordering::Greater => assert_eq!(res.unwrap().event_id, None),
            }
        }
    }

    set_tracking(false);
    let alloc_count = get_thread_alloc_count();
    assert_eq!(
        alloc_count, 0,
        "Expected exact 0 heap allocations across varied event sizes and error paths!"
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
    reset_thread_alloc_count();
    set_tracking(true);

    for _ in 0..1000 {
        let view = rezzy::extract_matrix_event_into(large_event, &mut scratch).unwrap();
        assert_eq!(view.event_id, Some("$large"));
        assert_eq!(view.prev_events.len(), 10);
        assert_eq!(view.auth_events.len(), 8);
    }

    set_tracking(false);
    let alloc_count = get_thread_alloc_count();
    assert_eq!(
        alloc_count, 0,
        "Expected 0 allocations once scratch buffers have grown to accommodate event!"
    );
}
