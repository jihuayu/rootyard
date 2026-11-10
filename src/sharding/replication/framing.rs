//! Length-framed snapshot manifest and bundle transfer helpers.
//!
//! [`encode_meta`] prefixes the JSON `TransferMeta` with one big-endian `u64`
//! length. [`FrameReader`] reads exactly that one frame, then streams the rest
//! of the request body into a newly-created private staging file under the
//! caller's size bounds. Framing limits and conflict errors are unchanged.

use super::{MAX_MANIFEST_BYTES, TransferMeta};
use crate::{Error, sharding::models::conflict};
use axum::body::{Body, BodyDataStream};
use futures_util::StreamExt;
use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt, path::Path as FsPath};
use tokio::io::AsyncWriteExt;

pub(crate) fn encode_meta(meta: &TransferMeta) -> Result<Vec<u8>, Error> {
    let json = serde_json::to_vec(meta).map_err(Error::internal)?;
    if json.is_empty() || json.len() > MAX_MANIFEST_BYTES {
        return Err(conflict("snapshot manifest exceeds transfer limit"));
    }
    let mut framed = Vec::with_capacity(8 + json.len());
    framed.extend_from_slice(&(json.len() as u64).to_be_bytes());
    framed.extend_from_slice(&json);
    Ok(framed)
}

pub(crate) struct FrameReader {
    stream: BodyDataStream,
    buffered: Vec<u8>,
}

impl FrameReader {
    pub(crate) fn new(body: Body) -> Self {
        Self { stream: body.into_data_stream(), buffered: Vec::new() }
    }

    async fn fill(&mut self) -> Result<(), Error> {
        match self.stream.next().await {
            Some(Ok(chunk)) => {
                if self.buffered.len().saturating_add(chunk.len()) > MAX_MANIFEST_BYTES * 2 {
                    return Err(conflict("snapshot framing exceeds limit"));
                }
                self.buffered.extend_from_slice(&chunk);
                Ok(())
            }
            Some(Err(_)) => Err(conflict("snapshot body stream failed")),
            None => Err(conflict("truncated snapshot frame")),
        }
    }

    pub(crate) async fn read_meta(&mut self) -> Result<TransferMeta, Error> {
        while self.buffered.len() < 8 {
            self.fill().await?;
        }
        let mut length = [0_u8; 8];
        length.copy_from_slice(&self.buffered[..8]);
        let length = u64::from_be_bytes(length) as usize;
        if length == 0 || length > MAX_MANIFEST_BYTES {
            return Err(conflict("snapshot manifest length is invalid"));
        }
        while self.buffered.len() < 8 + length {
            self.fill().await?;
        }
        let json = self.buffered[8..8 + length].to_vec();
        self.buffered.drain(..8 + length);
        let meta: TransferMeta = serde_json::from_slice(&json).map_err(|_| conflict("corrupt snapshot manifest"))?;
        meta.base.validate()?;
        if let Some(final_refs) = &meta.final_refs {
            final_refs.validate()?;
        }
        Ok(meta)
    }

    /// Write the remaining bytes of the request body to `path` and return the
    /// measured size. The caller owns the newly-created private staging file.
    pub(crate) async fn write_bundle(&mut self, path: &FsPath, maximum: u64, allow_empty: bool) -> Result<u64, Error> {
        let file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).map_err(Error::internal)?;
        let mut file = tokio::fs::File::from_std(file);
        let mut total = self.buffered.len() as u64;
        if total > maximum {
            return Err(conflict("snapshot bundle exceeds configured repository size"));
        }
        if !self.buffered.is_empty() {
            file.write_all(&self.buffered).await.map_err(Error::internal)?;
            self.buffered.clear();
        }
        while let Some(chunk) = self.stream.next().await {
            let chunk = chunk.map_err(|_| conflict("snapshot body stream failed"))?;
            total = total.saturating_add(chunk.len() as u64);
            if total > maximum {
                return Err(conflict("snapshot bundle exceeds configured repository size"));
            }
            file.write_all(&chunk).await.map_err(Error::internal)?;
        }
        file.sync_all().await.map_err(Error::internal)?;
        if total == 0 && !allow_empty {
            return Err(conflict("empty snapshot bundle"));
        }
        Ok(total)
    }
}
