//! Explicit API authorization regression tests. No endpoint discovery or policy inference.

mod config;
mod json;
mod runner;

pub use config::{Assertion, Case, Expectation, Identity, Suite, MAX_SUITE_BYTES};
pub use runner::{Failure, Options, Report, ResultRow, Runner};
