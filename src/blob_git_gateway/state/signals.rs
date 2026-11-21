//! Advisory dispatch accessors split from the gateway state module.
//!
//! The `BlobGitState::dispatch` field is a local advisory wake signal set. Only a fresh
//! committed terminal whose audit outbox rows committed with it may call
//! `committed()`. It carries no event data and never participates in authority
//! or delivery state.
use super::BlobGitState;
use crate::dispatch;

impl BlobGitState {
    /// Share the one local advisory signal set with the embedded worker and the
    /// publisher (if any). It carries no event data and never participates in
    /// authority or delivery state.
    pub fn with_dispatch(mut self, dispatch: dispatch::Signals) -> Self {
        self.dispatch = dispatch;
        self
    }

    pub(in crate::blob_git_gateway) fn dispatch(&self) -> &dispatch::Signals {
        &self.dispatch
    }
}
