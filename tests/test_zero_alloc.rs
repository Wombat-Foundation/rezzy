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
