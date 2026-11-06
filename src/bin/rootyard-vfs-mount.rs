//! Mount a checkpoint tree through the transparent Linux FUSE CoW backend.
fn main() -> anyhow::Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    anyhow::ensure!(
        args.len() == 3,
        "usage: rootyard-vfs-mount LOWER_DIR UPPER_DIR MOUNTPOINT"
    );
    rootyard::workspace_lab::fuse_mount::mount(
        args[0].clone().into(),
        args[1].clone().into(),
        args[2].clone().into(),
    )?;
    Ok(())
}
