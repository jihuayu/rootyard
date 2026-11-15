//! Strict non-authoritative cache serialization models for browse endpoints.
//!
//! These DTOs mirror `browse::models` without `#[serde(flatten)]` so every
//! deserialized cache entry can enforce `#[serde(deny_unknown_fields)]`.
use crate::browse::models::{
    BlobResponse, CommitDetail, CommitSummary, HeadInfo, RefItem, RefsResponse, TreeEntry, TreeResponse,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CachedHeadInfo {
    pub kind: String,
    pub target: Option<String>,
    pub oid: Option<String>,
}

impl From<&HeadInfo> for CachedHeadInfo {
    fn from(value: &HeadInfo) -> Self {
        Self { kind: value.kind.clone(), target: value.target.clone(), oid: value.oid.clone() }
    }
}

impl From<CachedHeadInfo> for HeadInfo {
    fn from(value: CachedHeadInfo) -> Self {
        Self { kind: value.kind, target: value.target, oid: value.oid }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CachedRefItem {
    pub name: String,
    pub oid: String,
    pub kind: String,
    pub peeled_oid: Option<String>,
}

impl From<&RefItem> for CachedRefItem {
    fn from(value: &RefItem) -> Self {
        Self {
            name: value.name.clone(),
            oid: value.oid.clone(),
            kind: value.kind.clone(),
            peeled_oid: value.peeled_oid.clone(),
        }
    }
}

impl From<CachedRefItem> for RefItem {
    fn from(value: CachedRefItem) -> Self {
        Self { name: value.name, oid: value.oid, kind: value.kind, peeled_oid: value.peeled_oid }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CachedRefSnapshotHint {
    pub repository_id: Uuid,
    pub storage_generation: i64,
    pub head: CachedHeadInfo,
    pub items: Vec<CachedRefItem>,
    pub next_after: Option<String>,
}

impl CachedRefSnapshotHint {
    pub(crate) fn from_model(value: &RefsResponse) -> Self {
        Self {
            repository_id: value.repository_id,
            storage_generation: value.storage_generation,
            head: CachedHeadInfo::from(&value.head),
            items: value.items.iter().map(CachedRefItem::from).collect(),
            next_after: value.next_after.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CachedRefTipHint {
    pub spec: String,
    pub resolved_oid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CachedCommitDetail {
    pub oid: String,
    pub tree_oid: String,
    pub parents: Vec<String>,
    pub author_name: String,
    pub author_email: String,
    pub authored_at: i64,
    pub committer_name: String,
    pub committer_email: String,
    pub committed_at: i64,
    pub subject: String,
    pub message: String,
    pub changed_paths: Vec<String>,
}

impl From<&CommitDetail> for CachedCommitDetail {
    fn from(value: &CommitDetail) -> Self {
        let s = &value.summary;
        Self {
            oid: s.oid.clone(),
            tree_oid: s.tree_oid.clone(),
            parents: s.parents.clone(),
            author_name: s.author_name.clone(),
            author_email: s.author_email.clone(),
            authored_at: s.authored_at,
            committer_name: s.committer_name.clone(),
            committer_email: s.committer_email.clone(),
            committed_at: s.committed_at,
            subject: s.subject.clone(),
            message: s.message.clone(),
            changed_paths: value.changed_paths.clone(),
        }
    }
}

impl From<CachedCommitDetail> for CommitDetail {
    fn from(value: CachedCommitDetail) -> Self {
        Self {
            summary: CommitSummary {
                oid: value.oid,
                tree_oid: value.tree_oid,
                parents: value.parents,
                author_name: value.author_name,
                author_email: value.author_email,
                authored_at: value.authored_at,
                committer_name: value.committer_name,
                committer_email: value.committer_email,
                committed_at: value.committed_at,
                subject: value.subject,
                message: value.message,
            },
            changed_paths: value.changed_paths,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CachedTreeEntry {
    pub name: String,
    pub path: String,
    pub mode: String,
    pub kind: String,
    pub oid: String,
    pub size: Option<u64>,
}

impl From<&TreeEntry> for CachedTreeEntry {
    fn from(value: &TreeEntry) -> Self {
        Self {
            name: value.name.clone(),
            path: value.path.clone(),
            mode: value.mode.clone(),
            kind: value.kind.clone(),
            oid: value.oid.clone(),
            size: value.size,
        }
    }
}

impl From<CachedTreeEntry> for TreeEntry {
    fn from(value: CachedTreeEntry) -> Self {
        Self {
            name: value.name,
            path: value.path,
            mode: value.mode,
            kind: value.kind,
            oid: value.oid,
            size: value.size,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CachedTreeResponse {
    pub oid: String,
    pub tree_oid: String,
    pub path: String,
    pub items: Vec<CachedTreeEntry>,
    pub next_after: Option<String>,
}

impl From<&TreeResponse> for CachedTreeResponse {
    fn from(value: &TreeResponse) -> Self {
        Self {
            oid: value.oid.clone(),
            tree_oid: value.tree_oid.clone(),
            path: value.path.clone(),
            items: value.items.iter().map(CachedTreeEntry::from).collect(),
            next_after: value.next_after.clone(),
        }
    }
}

impl From<CachedTreeResponse> for TreeResponse {
    fn from(value: CachedTreeResponse) -> Self {
        Self {
            oid: value.oid,
            tree_oid: value.tree_oid,
            path: value.path,
            items: value.items.into_iter().map(TreeEntry::from).collect(),
            next_after: value.next_after,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CachedBlobResponse {
    pub oid: String,
    pub size: u64,
    pub is_binary: bool,
    pub content: Option<String>,
    pub content_base64: String,
}

impl From<&BlobResponse> for CachedBlobResponse {
    fn from(value: &BlobResponse) -> Self {
        Self {
            oid: value.oid.clone(),
            size: value.size,
            is_binary: value.is_binary,
            content: value.content.clone(),
            content_base64: value.content_base64.clone(),
        }
    }
}

impl From<CachedBlobResponse> for BlobResponse {
    fn from(value: CachedBlobResponse) -> Self {
        Self {
            oid: value.oid,
            size: value.size,
            is_binary: value.is_binary,
            content: value.content,
            content_base64: value.content_base64,
        }
    }
}
