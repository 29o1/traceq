//! Native query and Agent entry for the traceq executable.
#![deny(unsafe_op_in_unsafe_fn)]
mod agent;
pub mod cli;
pub use agent::native_main as agent_main;
