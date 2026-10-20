//! Privileged MisaOS host state transitions. This slice publishes BLS type 1 entries
//! with the B4 write order and reads the running loader's Boot Loader Interface
//! variables; the journaled publication transaction builds on both.
pub mod bls;
pub mod efi;
