//! Userspace WireGuard tunnel engine. Wraps `gotatun` behind our own types so
//! the implementation can be swapped.

#![forbid(unsafe_code)]
