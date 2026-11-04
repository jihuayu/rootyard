//! Explicitly opt-in, loopback-only synthetic storage experiment. Never a GitFS switch.
#[path = "../pando_lab/mod.rs"]
mod pando_lab;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    pando_lab::run().await
}
