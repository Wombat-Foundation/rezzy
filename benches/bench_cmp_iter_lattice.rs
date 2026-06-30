use imbl::OrdMap;
use rezzy::{
    basespec::rezzy_types::LeanEvent, resolve_iterative_sort, resolve_lattice_fold, StateResVersion,
};
use std::collections::HashMap;
use std::time::Instant;

type GeneratedDag = (
    OrdMap<(String, String), String>,
    HashMap<String, LeanEvent>,
    HashMap<String, LeanEvent>,
);

fn generate_dag(base_n: usize, forks: usize, fork_depth: usize) -> GeneratedDag {
    let mut auth_context = HashMap::new();
    let mut conflicted_events = HashMap::new();
    let mut unconflicted = OrdMap::new();

    let create = LeanEvent {
        event_id: "$create".to_string(),
        event_type: "m.room.create".to_string(),
        state_key: Some(String::new()),
        power_level: 0,
        origin_server_ts: 0,
        sender: "@creator:matrix.org".to_string(),
        content: serde_json::json!({"creator": "@creator:matrix.org"}),
        prev_events: vec![],
        auth_events: vec![],
        depth: 1,
    };
    let pl = LeanEvent {
        event_id: "$pl".to_string(),
        event_type: "m.room.power_levels".to_string(),
        state_key: Some(String::new()),
        power_level: 100,
        origin_server_ts: 1,
        sender: "@creator:matrix.org".to_string(),
        content: serde_json::json!({"users": {"@creator:matrix.org": 100}, "state_default": 0, "events_default": 0}),
        prev_events: vec!["$create".to_string()],
        auth_events: vec!["$create".to_string()],
        depth: 2,
    };

    auth_context.insert(create.event_id.clone(), create.clone());
    auth_context.insert(pl.event_id.clone(), pl.clone());
    unconflicted.insert(
        ("m.room.create".to_string(), String::new()),
        create.event_id.clone(),
    );
    unconflicted.insert(
        ("m.room.power_levels".to_string(), String::new()),
        pl.event_id.clone(),
    );

    let mut last_base_id = "$pl".to_string();
    let mut last_depth: u64 = 2;

    for i in 0..base_n {
        let ev = LeanEvent {
            event_id: format!("$base_{i}"),
            event_type: "m.room.member".to_string(),
            state_key: Some(format!("@user_{i}:matrix.org")),
            power_level: 0,
            origin_server_ts: i.checked_add(2).expect("ts ran over") as u64,
            sender: "@creator:matrix.org".to_string(),
            content: serde_json::json!({"membership": "join"}),
            prev_events: vec![last_base_id.clone()],
            auth_events: vec!["$create".to_string(), "$pl".to_string()],
            depth: last_depth.saturating_add(1),
        };
        last_base_id.clone_from(&ev.event_id);
        last_depth = last_depth.saturating_add(1);
        auth_context.insert(ev.event_id.clone(), ev.clone());
        unconflicted.insert(
            ("m.room.member".to_string(), format!("@user_{i}:matrix.org")),
            ev.event_id.clone(),
        );
    }

    for f in 0..forks {
        let mut fork_last_id = last_base_id.clone();

        for (fork_last_depth, d) in (last_depth..).zip(0..fork_depth) {
            let ev = LeanEvent {
                event_id: format!("$fork_{f}_{d}"),
                event_type: "m.room.topic".to_string(),
                state_key: Some(String::new()),
                power_level: 100,
                origin_server_ts: last_depth.saturating_add(d.try_into().unwrap()),
                sender: "@creator:matrix.org".to_string(),
                content: serde_json::json!({"topic": format!("Fork {f} Depth {d}")}),
                prev_events: vec![fork_last_id.clone()],
                auth_events: vec!["$create".to_string(), "$pl".to_string()],
                depth: fork_last_depth.saturating_add(1),
            };
            fork_last_id.clone_from(&ev.event_id);
            auth_context.insert(ev.event_id.clone(), ev.clone());
            conflicted_events.insert(ev.event_id.clone(), ev.clone());
        }
    }

    (unconflicted, conflicted_events, auth_context)
}

fn main() {
    println!("BaseSize,NumForks,ForkDepth,TotalConflicted,Iterative_us,Lattice_us");

    let base_sizes = vec![10, 100, 1000, 5000];
    let fork_counts = vec![2, 5, 10, 20, 50];
    let fork_depth = 10;

    let iterations: u128 = 10;

    for &n in &base_sizes {
        for &f in &fork_counts {
            let (unconflicted, conflicted, auth_context) = generate_dag(n, f, fork_depth);

            // Warmup Iterative
            for _ in 0..2 {
                let _ = resolve_iterative_sort(
                    unconflicted.clone(),
                    conflicted.clone(),
                    &auth_context,
                    StateResVersion::V2_1_1,
                );
            }

            let start = Instant::now();
            for _ in 0..iterations {
                let _ = resolve_iterative_sort(
                    unconflicted.clone(),
                    conflicted.clone(),
                    &auth_context,
                    StateResVersion::V2_1_1,
                );
            }
            let iter_time = start.elapsed().as_micros().checked_div(iterations).unwrap();

            // Warmup Lattice
            for _ in 0..2 {
                let _ = resolve_lattice_fold(
                    unconflicted.clone(),
                    conflicted.clone(),
                    &auth_context,
                    StateResVersion::V2_1_1,
                );
            }

            let start = Instant::now();
            for _ in 0..iterations {
                let _ = resolve_lattice_fold(
                    unconflicted.clone(),
                    conflicted.clone(),
                    &auth_context,
                    StateResVersion::V2_1_1,
                );
            }
            let lattice_time = start.elapsed().as_micros().checked_div(iterations).unwrap();

            println!(
                "{},{},{},{},{},{}",
                n,
                f,
                fork_depth,
                conflicted.len(),
                iter_time,
                lattice_time
            );
        }
    }
}
