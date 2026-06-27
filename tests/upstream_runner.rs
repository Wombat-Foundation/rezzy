// Shadow the ruma_state_res dependency with our own ruma-lean crate
extern crate ruma_lean as ruma_state_res;

// Inject the unmodified upstream integration tests directly into this runner
#[path = "resolve.rs"]
mod resolve;
