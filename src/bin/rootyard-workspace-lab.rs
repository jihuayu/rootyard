//! Opt-in local workspace experiment. This binary is not a network service.
fn main() -> anyhow::Result<()> {
    rootyard::workspace_lab::run(std::env::args_os().skip(1).collect())
}
