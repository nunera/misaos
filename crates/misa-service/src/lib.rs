//! Portable service graph compilation for MisaOS init adapters.
//!
//! The graph comes from a `misa.plan/v1` `serviceGraph`; `misa-plan` owns its schema and
//! graph rules. This crate negotiates adapter capabilities, compiles the graph into an
//! adapter's native tree, and provides the `misa-svcrun` launcher every service runs through.
pub mod capability;
pub mod dinit;
pub mod graph;
pub mod spec;
pub mod svcrun;
