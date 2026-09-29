use rezzy::reconcile::{
    build_bucket_sketches, ElementHash, EventIdFormat, ReconciliationClient, RemoteDigest,
    ResidentKernel,
};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::time::Instant;

fn load_uuids(filename: &str) -> (ResidentKernel, Vec<ElementHash>) {
    let mut resident = ResidentKernel::new();
    let mut elements = Vec::new();

    let file = File::open(filename).unwrap();
    for line in BufReader::new(file).lines() {
        let uuid = format!("${}", line.unwrap());
        if uuid == "$" {
            continue;
        }
        let hash = ElementHash::from_matrix_event_id(&uuid, EventIdFormat::Legacy).unwrap();
        resident.insert(hash).unwrap();
        elements.push(hash);
    }
    (resident, elements)
}

fn main() {
    println!("Loading A.txt...");
    let start = Instant::now();
    let (local_resident, local_elements) = load_uuids("A.txt");
    println!("Loaded A.txt in {:?}", start.elapsed());

    println!("Loading B.txt...");
    let start = Instant::now();
    let (remote_resident, remote_elements) = load_uuids("B.txt");
    println!("Loaded B.txt in {:?}", start.elapsed());

    let client = ReconciliationClient::default();

    // Step 1: Client determines the difference and generates bucket requests
    let start_triage = Instant::now();
    let remote_digest = RemoteDigest {
        digest: remote_resident.accumulator().digest(),
        known_event_count: remote_resident.accumulator().known_event_count(),
        strata: *remote_resident.strata(),
        frame_matches: true,
        has_unknown_extremity: false,
    };

    let action = client.select_action(&local_resident, remote_digest, 0);
    let triage_duration = start_triage.elapsed();
    println!("Client triage completed in {triage_duration:?}");

    match action {
        rezzy::reconcile::ClientAction::BucketSketches { requests, .. } => {
            println!("Requested {} buckets.", requests.len());

            // Step 2: Server builds the requested sketches
            let start_server = Instant::now();
            let mut sorted_remote_h64: Vec<u64> = remote_elements.iter().map(|h| h.h64).collect();
            sorted_remote_h64.sort_unstable();
            let sketches = build_bucket_sketches(&sorted_remote_h64, &requests).unwrap();
            let server_duration = start_server.elapsed();
            println!("Server extraction completed in {server_duration:?}");

            // Step 3: Client decodes the sketches
            let start_decode = Instant::now();
            let mut sorted_local_h64: Vec<u64> = local_elements.iter().map(|h| h.h64).collect();
            sorted_local_h64.sort_unstable();
            let local_sketches = build_bucket_sketches(&sorted_local_h64, &requests).unwrap();

            let mut total_roots: usize = 0;
            let mut failed_buckets: usize = 0;

            for (mut remote_sketch, local_sketch) in sketches.into_iter().zip(local_sketches) {
                remote_sketch.xor(&local_sketch).unwrap();

                if let Ok(roots) = remote_sketch.decode_elements(remote_sketch.capacity()) {
                    total_roots = total_roots.saturating_add(roots.len());
                } else {
                    failed_buckets = failed_buckets.saturating_add(1);
                }
            }

            let decode_duration = start_decode.elapsed();
            println!("Client decoding completed in {decode_duration:?}");
            println!(
                "Decode summary: {total_roots} roots recovered, {failed_buckets} buckets failed"
            );
        }
        _ => {
            println!("Client action: {action:?}");
        }
    }
}
