// Shadow the ruma_state_res dependency with our own rezzy crate
mod mock_ruma;
//;
extern crate rezzy as ruma_state_res;

// Inject the unmodified upstream integration tests directly into this runner
#[path = "resolve.rs"]
mod resolve;
