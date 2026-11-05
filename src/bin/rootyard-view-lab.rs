//! Opt-in local Namespace, Git View and cross-repository ChangeSet experiment.
#[path = "../view_lab.rs"]
mod view_lab;

fn main() -> anyhow::Result<()> {
    view_lab::run(std::env::args_os().skip(1).collect())
}
