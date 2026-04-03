// Library entry point — re-exports internal modules for integration tests and
// downstream users. Only modules needed for testing are made public here;
// implementation details remain crate-private.
pub mod audit;
pub mod crypto;
pub mod detectors;
pub mod engine;
pub mod error;
pub mod hooks;
pub mod util;

// cli and build.rs helpers are binary-only
mod cli;
