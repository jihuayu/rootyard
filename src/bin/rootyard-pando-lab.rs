//! Explicitly opt-in, loopback-only synthetic storage experiment. Never a GitFS switch.
#![allow(dead_code, private_interfaces, clippy::too_many_arguments)]
#[rustfmt::skip]
#[path = "../pando_lab/mod.rs"]
mod pando_lab;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    pando_lab::run().await
}
