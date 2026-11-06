//! Opt-in local workspace experiment. This binary is not a network service.
#![allow(unused_imports, dead_code, clippy::too_many_arguments, clippy::type_complexity, clippy::needless_range_loop)]
#[rustfmt::skip]
#[path = "../workspace_lab.rs"]
mod workspace_lab;

fn main() -> anyhow::Result<()> {
    workspace_lab::run(std::env::args_os().skip(1).collect())
}
