//! Closed static cause/site codes for bounded quorum diagnostics.
//!
//! `RaftBackendError::QuorumUnavailable(&'static str)` remains the public error shape. The
//! backend only places one of [`Site::code`]'s literals in that payload after matching the typed
//! OpenRaft variant. The diagnostic consumer decodes exact literals to a typed [`Site`]; it never
//! parses `Display`, `Debug`, peer text or an error chain. Unknown literals are unclassified.

#![allow(dead_code)]

/// Fixed operation tier for a quorum-capable backend call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Operation {
    Prepare,
    ReadView,
    Receipt,
    ScopeDrain,
    ClientWrite,
}

impl Operation {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::Prepare => "prepare",
            Self::ReadView => "read_view",
            Self::Receipt => "receipt",
            Self::ScopeDrain => "scope_drain",
            Self::ClientWrite => "client_write",
        }
    }
}

/// Read-only operation tier accepted by the shared ReadIndex helper.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReadOperation {
    Prepare,
    ReadView,
    Receipt,
    ScopeDrain,
}

impl ReadOperation {
    pub(crate) fn operation(self) -> Operation {
        match self {
            Self::Prepare => Operation::Prepare,
            Self::ReadView => Operation::ReadView,
            Self::Receipt => Operation::Receipt,
            Self::ScopeDrain => Operation::ScopeDrain,
        }
    }

    pub(crate) fn quorum_shortfall(self) -> Site {
        match self {
            Self::Prepare => Site::PrepareQuorumShortfall,
            Self::ReadView => Site::ReadViewQuorumShortfall,
            Self::Receipt => Site::ReceiptQuorumShortfall,
            Self::ScopeDrain => Site::ScopeDrainQuorumShortfall,
        }
    }

    pub(crate) fn fatal_storage(self) -> Site {
        match self {
            Self::Prepare => Site::PrepareFatalStorage,
            Self::ReadView => Site::ReadViewFatalStorage,
            Self::Receipt => Site::ReceiptFatalStorage,
            Self::ScopeDrain => Site::ScopeDrainFatalStorage,
        }
    }

    pub(crate) fn fatal_panicked(self) -> Site {
        match self {
            Self::Prepare => Site::PrepareFatalPanicked,
            Self::ReadView => Site::ReadViewFatalPanicked,
            Self::Receipt => Site::ReceiptFatalPanicked,
            Self::ScopeDrain => Site::ScopeDrainFatalPanicked,
        }
    }

    pub(crate) fn fatal_stopped(self) -> Site {
        match self {
            Self::Prepare => Site::PrepareFatalStopped,
            Self::ReadView => Site::ReadViewFatalStopped,
            Self::Receipt => Site::ReceiptFatalStopped,
            Self::ScopeDrain => Site::ScopeDrainFatalStopped,
        }
    }

    pub(crate) fn outer_deadline(self) -> Site {
        match self {
            Self::Prepare => Site::PrepareOuterDeadline,
            Self::ReadView => Site::ReadViewOuterDeadline,
            Self::Receipt => Site::ReceiptOuterDeadline,
            Self::ScopeDrain => Site::ScopeDrainOuterDeadline,
        }
    }
}

/// Typed cause carried by one `QuorumUnavailable` return.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Cause {
    ReadQuorumShortfall,
    ReadFatalStorage,
    ReadFatalPanicked,
    ReadFatalStopped,
    ReadOuterDeadline,
    WriteFatalStorage,
    WriteFatalPanicked,
    WriteFatalStopped,
    WriteApiOther,
    WriteOuterDeadline,
}

impl Cause {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::ReadQuorumShortfall => "read_quorum_shortfall",
            Self::ReadFatalStorage => "read_fatal_storage",
            Self::ReadFatalPanicked => "read_fatal_panicked",
            Self::ReadFatalStopped => "read_fatal_stopped",
            Self::ReadOuterDeadline => "read_outer_deadline",
            Self::WriteFatalStorage => "write_fatal_storage",
            Self::WriteFatalPanicked => "write_fatal_panicked",
            Self::WriteFatalStopped => "write_fatal_stopped",
            Self::WriteApiOther => "write_api_other",
            Self::WriteOuterDeadline => "write_outer_deadline",
        }
    }
}

macro_rules! define_sites {
    ($(($variant:ident, $operation:ident, $cause:ident, $text:literal)),+ $(,)?) => {
        /// One exact backend operation/cause pair.
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub(crate) enum Site {
            $($variant),+
        }

        impl Site {
            pub(crate) fn code(self) -> &'static str {
                match self {
                    $(Self::$variant => $text),+
                }
            }

            pub(crate) fn operation(self) -> Operation {
                match self {
                    $(Self::$variant => Operation::$operation),+
                }
            }

            pub(crate) fn cause(self) -> Cause {
                match self {
                    $(Self::$variant => Cause::$cause),+
                }
            }

            /// Exact literal decoder. Unknown values are unclassified, never inferred.
            #[cfg(test)]
            pub(crate) fn decode(code: &str) -> Option<Self> {
                match code {
                    $($text => Some(Self::$variant),)+
                    _ => None,
                }
            }
        }
    };
}

define_sites! {
    (PrepareQuorumShortfall, Prepare, ReadQuorumShortfall, "q.prepare.quorum_shortfall"),
    (PrepareFatalStorage, Prepare, ReadFatalStorage, "q.prepare.fatal_storage"),
    (PrepareFatalPanicked, Prepare, ReadFatalPanicked, "q.prepare.fatal_panicked"),
    (PrepareFatalStopped, Prepare, ReadFatalStopped, "q.prepare.fatal_stopped"),
    (PrepareOuterDeadline, Prepare, ReadOuterDeadline, "q.prepare.outer_deadline"),
    (ReadViewQuorumShortfall, ReadView, ReadQuorumShortfall, "q.read_view.quorum_shortfall"),
    (ReadViewFatalStorage, ReadView, ReadFatalStorage, "q.read_view.fatal_storage"),
    (ReadViewFatalPanicked, ReadView, ReadFatalPanicked, "q.read_view.fatal_panicked"),
    (ReadViewFatalStopped, ReadView, ReadFatalStopped, "q.read_view.fatal_stopped"),
    (ReadViewOuterDeadline, ReadView, ReadOuterDeadline, "q.read_view.outer_deadline"),
    (ReceiptQuorumShortfall, Receipt, ReadQuorumShortfall, "q.receipt.quorum_shortfall"),
    (ReceiptFatalStorage, Receipt, ReadFatalStorage, "q.receipt.fatal_storage"),
    (ReceiptFatalPanicked, Receipt, ReadFatalPanicked, "q.receipt.fatal_panicked"),
    (ReceiptFatalStopped, Receipt, ReadFatalStopped, "q.receipt.fatal_stopped"),
    (ReceiptOuterDeadline, Receipt, ReadOuterDeadline, "q.receipt.outer_deadline"),
    (ScopeDrainQuorumShortfall, ScopeDrain, ReadQuorumShortfall, "q.scope_drain.quorum_shortfall"),
    (ScopeDrainFatalStorage, ScopeDrain, ReadFatalStorage, "q.scope_drain.fatal_storage"),
    (ScopeDrainFatalPanicked, ScopeDrain, ReadFatalPanicked, "q.scope_drain.fatal_panicked"),
    (ScopeDrainFatalStopped, ScopeDrain, ReadFatalStopped, "q.scope_drain.fatal_stopped"),
    (ScopeDrainOuterDeadline, ScopeDrain, ReadOuterDeadline, "q.scope_drain.outer_deadline"),
    (ClientWriteFatalStorage, ClientWrite, WriteFatalStorage, "q.client_write.fatal_storage"),
    (ClientWriteFatalPanicked, ClientWrite, WriteFatalPanicked, "q.client_write.fatal_panicked"),
    (ClientWriteFatalStopped, ClientWrite, WriteFatalStopped, "q.client_write.fatal_stopped"),
    (ClientWriteApiOther, ClientWrite, WriteApiOther, "q.client_write.api_other"),
    (ClientWriteOuterDeadline, ClientWrite, WriteOuterDeadline, "q.client_write.outer_deadline"),
}
