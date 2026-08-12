// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]

//! The busbar-admin library surface.
//!
//! The binary (`src/main.rs`) is the clap surface + rendering; everything it needs to talk to a
//! gateway, and every pure mapping it applies to CLI arguments, lives here so integration tests
//! under `tests/` exercise the SAME code the binary runs (a `[[bin]]`-only crate cannot be
//! imported by a test, which is why the wire types could previously only be tested from an
//! inline `#[cfg(test)]` module).

pub mod argmap;
pub mod client;
