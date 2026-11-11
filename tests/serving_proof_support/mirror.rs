//! Read-only mirror of the crate's `rootyard` path, for the crate-internal
//! contract cases that are compiled *inside* the library's own test build.
//!
//! `serving_reads_support` and `serving_support` are integration fixtures that
//! import `rootyard::…`. When the contract cases are compiled as part of the
//! library crate (they must be, because the sealed builder is crate-private),
//! there is no external `rootyard` crate, so this alias puts the same crate root
//! at that path. Nothing is duplicated: the sources are `#[path]`-included.

pub use crate as rootyard;
