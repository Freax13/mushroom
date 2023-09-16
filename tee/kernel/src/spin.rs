//! Various synchronization abstractions that spin until they reach the desired
//! state.

pub mod lazy;
pub mod mutex;
pub mod once;
