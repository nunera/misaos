//! Unprivileged S1 image admission and retained storage, not host activation.
//! An operator signature authorizes exact locked bytes; it is not a publisher signature.

pub mod model;
pub mod resolve;
pub mod store;
pub mod tools;
pub mod trust;
pub mod verify;

pub use misa_plan::{Error, Result};
pub use model::{Descriptor, ForeignLock, Limits, LockedImage};
pub use store::{ImportReceipt, Store, StoreStatus};
pub use tools::Tools;
pub use trust::AuthorizedLock;
