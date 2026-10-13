//! Validated per-account tunnel service. Networking stays outside the GUI process.
#![forbid(unsafe_code)]
#[cfg(unix)]
pub mod server;
pub mod service;
pub mod storage;
