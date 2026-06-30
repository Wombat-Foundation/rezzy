use imbl::OrdMap;
use rezzy::{
    basespec::rezzy_types::LeanEvent, resolve_iterative_sort, resolve_lattice_fold, StateResVersion,
};
use std::collections::HashMap;
use std::env;
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

fn parse_env_list(key: &str, default: Vec<usize>) -> Vec<usize> {
    if let Ok(val) = env::var(key) {
        val.split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect()
    } else {
        default
    }
}

fn parse_env_single<T: std::str::FromStr>(key: &str, default: T) -> T {
    if let Ok(val) = env::var(key) {
        val.parse().unwrap_or(default)
    } else {
        default
    }
}

fn main() {
    println!(
        "{:>8},{:>8},{:>9},{:>15},{:>12},{:>10},{:>10},{:>10},{:>8}",
        "BaseSize",
        "NumForks",
        "ForkDepth",
        "TotalConflicted",
        "Iterative_us",
        "Lattice_us",
        "Total_s",
        "Δ",
        "%"
    );

    let base_sizes = parse_env_list("BASE_SIZES", vec![10, 500, 5000, 20000, 50000]);
    let fork_counts = parse_env_list("FORK_COUNTS", vec![2, 10, 50, 200]);
    let fork_depth = parse_env_single("FORK_DEPTH", 50);

    let iterations: u128 = parse_env_single("ITERATIONS", 5);

    for &n in &base_sizes {
        for &f in &fork_counts {
            let row_start = Instant::now();
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

            let total_s = row_start.elapsed().as_secs_f32();
            let delta = iter_time
                .cast_signed()
                .checked_sub(lattice_time.cast_signed())
                .unwrap();

            let percent_faster = (f64::from(i32::try_from(delta).unwrap_or(i32::MAX))
                / f64::from(u32::try_from(iter_time).unwrap_or(u32::MAX)))
                * 100.0;

            println!(
                "{:>8},{:>8},{:>9},{:>15},{:>12},{:>10},{:>10.2},{:>10},{:>7.1}%",
                n,
                f,
                fork_depth,
                conflicted.len(),
                iter_time,
                lattice_time,
                total_s,
                delta,
                percent_faster
            );
        }
    }
}
