//! Opt-in local workspace experiment. This binary is not a network service.
#[path = "../workspace_lab.rs"]
mod workspace_lab;

fn main() -> anyhow::Result<()> {
    workspace_lab::run(std::env::args_os().skip(1).collect())
}
