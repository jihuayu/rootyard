//! Finite Provider diagnostics for fault-case open/build errors.
//!
//! Only fixed enums, audited static labels, and optional typed io kind/errno
//! are retained. No raw provider string, error chain, path, or payload is kept
//! or printed.

use std::fmt;

use anyhow::Error;
use rootyard::blob_store::{BlobError, disposable_view::DisposableViewError, read_accel::ReadAccelError};

use super::detail_classifier::provider_detail_class;
use super::{BlobClass, DetailClass, ErrorClass, IoKindClass, ViewClass};

pub(super) struct FaultError {
    phase: &'static str,
    error: ErrorClass,
    blob: BlobClass,
    blob_detail: DetailClass,
    view: ViewClass,
    io_kind: IoKindClass,
    raw_os_error: Option<i32>,
}

impl FaultError {
    pub(super) fn from_anyhow(phase: &'static str, err: &Error) -> Self {
        let mut fault = Self {
            phase,
            error: ErrorClass::None,
            blob: BlobClass::None,
            blob_detail: DetailClass::from_label("none"),
            view: ViewClass::None,
            io_kind: IoKindClass::None,
            raw_os_error: None,
        };
        if let Some(err) = err.downcast_ref::<ReadAccelError>() {
            fault.classify_read_accel(err);
        } else if let Some(err) = err.downcast_ref::<BlobError>() {
            fault.classify_blob(err);
        } else if let Some(err) = err.downcast_ref::<DisposableViewError>() {
            fault.error = ErrorClass::DisposableView;
            fault.view = ViewClass::from_error(err);
        } else if let Some(err) = err.downcast_ref::<std::io::Error>() {
            fault.error = ErrorClass::Io;
            fault.io_kind = IoKindClass::from_kind(err.kind());
            fault.raw_os_error = err.raw_os_error();
        } else if err.downcast_ref::<std::string::FromUtf8Error>().is_some()
            || err.downcast_ref::<std::str::Utf8Error>().is_some()
        {
            fault.error = ErrorClass::InvalidUtf8;
        } else {
            fault.error = ErrorClass::Unknown;
        }
        fault
    }

    fn classify_blob(&mut self, err: &BlobError) {
        self.error = ErrorClass::Blob;
        self.blob = BlobClass::from_error(err);
        if let BlobError::Provider(detail) = err {
            self.blob_detail = provider_detail_class(detail);
        }
    }

    fn classify_read_accel(&mut self, err: &ReadAccelError) {
        match err {
            ReadAccelError::Manifest(_) => self.error = ErrorClass::Manifest,
            ReadAccelError::DisabledByDefault => self.error = ErrorClass::DisabledByDefault,
            ReadAccelError::InvalidInput(_) => self.error = ErrorClass::InvalidInput,
            ReadAccelError::Blob(err) => self.classify_blob(err),
            ReadAccelError::Envelope(_) => self.error = ErrorClass::Envelope,
            ReadAccelError::Closure(_) => self.error = ErrorClass::Closure,
            ReadAccelError::DisposableView(err) => {
                self.error = ErrorClass::DisposableView;
                self.view = ViewClass::from_error(err);
            }
            ReadAccelError::GitCommandFailed { .. } => self.error = ErrorClass::GitCommandFailed,
            ReadAccelError::SidecarIntegrityFailed(_) => self.error = ErrorClass::SidecarIntegrityFailed,
            ReadAccelError::DeadlineExceeded => self.error = ErrorClass::DeadlineExceeded,
            ReadAccelError::Io(_) => self.error = ErrorClass::Io,
        }
    }
}

impl fmt::Debug for FaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for FaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "read-accel fault diagnostic: {} error={} blob={} blob_detail={} disposable_view={} io_kind={} raw_os_error={:?}",
            self.phase,
            self.error.label(),
            self.blob.label(),
            self.blob_detail.label(),
            self.view.label(),
            self.io_kind.label(),
            self.raw_os_error
        )
    }
}

impl std::error::Error for FaultError {}
