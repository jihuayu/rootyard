//! Root lifetime: the head, its generation-1 capture and its release tombstone.
//!
//! Every decision is pure so a corrupted source is refused identically in
//! production and in unit tests. [`super::check_heads`] is the module entry
//! point.

use super::{DeclaredPair, RootCapture, RootHead, RootTombstone};
use std::collections::BTreeMap;
use uuid::Uuid;

/// The root lifetime must be observable in the exact shape `retention_root`
/// writes: `register` inserts an `active`/1 head plus its generation-1 capture
/// (no tombstone), `release` moves that head to `released`/2 and inserts one
/// generation-2 tombstone binding the full capture scope and the register
/// digest, and a release before `register` writes only a `released`/2 head plus
/// that same tombstone (release-before-register, no capture).
///
/// The producer `owner_id` (head, tombstone, capture) is the requester and may
/// differ from the repository tenant; the capture itself must carry the same
/// full scope as the head, and the tombstone must repeat it.
///
/// A capture's presence is decided by its key alone. The verdicts are stable and
/// distinct: `root_capture_missing:{at}:{state}` when the key has no capture,
/// `root_capture_mismatch:{at}:{state}` when it has one that disagrees with the
/// head (generation, scope, owner or register digest). A missing capture is the
/// only shape a release tombstone may explain (release-before-register); a
/// present but disagreeing capture is never accepted.
pub(super) fn check_heads(
    heads: &[RootHead],
    tombstones: &[RootTombstone],
    roots: &[RootCapture],
    declared: &[DeclaredPair],
) -> Vec<String> {
    let captures: BTreeMap<(Uuid, Uuid), &RootCapture> =
        roots.iter().map(|root| ((root.repository_id, root.root_id), root)).collect();
    let mut lines = Vec::new();
    let by_key = |tombstone: &RootTombstone| (tombstone.repository_id, tombstone.root_id);
    for head in heads {
        let key = (head.repository_id, head.root_id);
        let at = format!("{}:{}", key.0, key.1);
        let rows = tombstones.iter().filter(|t| by_key(t) == key).collect::<Vec<_>>();
        let fence = rows.iter().any(|t| release_fence(t, head));
        // Existence is decided by the key alone: a capture that is present but
        // carries another scope, owner or register digest is a violation, never a
        // release-before-register. Only a key with no capture row at all may be
        // explained by a release tombstone. `register` only ever writes the
        // generation-1 capture of the root.
        let capture = captures.get(&key).copied();
        let valid = capture.is_some_and(|capture| {
            capture.generation == 1
                && same_scope(
                    head,
                    capture.tenant_id,
                    capture.owner_id,
                    &capture.purpose,
                    &capture.business_intent_digest,
                )
                && capture.register_digest == head.register_digest
                && source_owner(capture, declared).is_some()
        });
        let captured = capture.is_some();
        match (head.state.as_str(), head.last_generation) {
            // Registered and still active: `register` writes no tombstone.
            ("active", 1) => {
                // A missing and a present-but-wrong capture are different facts
                // with different verdicts; neither is ever accepted here.
                if !captured {
                    lines.push(format!("root_capture_missing:{at}:active"));
                } else if !valid {
                    lines.push(format!("root_capture_mismatch:{at}:active"));
                } else if fence {
                    lines.push(format!("root_head_mismatch:{at}:tombstone_without_release"));
                }
            }
            // Registered, then released: the capture stays and one release tombstone fences it.
            ("released", 2) => {
                if captured && !valid {
                    lines.push(format!("root_capture_mismatch:{at}:released"));
                } else if !captured {
                    // Released before `register`: the tombstone alone fences the intent.
                    if !fence {
                        lines.push(format!("root_capture_missing:{at}:released"));
                    }
                } else if !fence {
                    lines.push(format!("root_head_mismatch:{at}:unreleased"));
                }
            }
            _ => lines.push(format!("root_head_mismatch:{at}:state")),
        }
    }
    for root in roots {
        if !heads.iter().any(|head| (head.repository_id, head.root_id) == (root.repository_id, root.root_id)) {
            lines.push(format!("root_head_missing:{}:{}", root.repository_id, root.root_id));
        }
    }
    // Every stored tombstone row of a key is judged, never only the one row that
    // happens to match: an active root has no tombstone, a registered-then-
    // released root has exactly one generation-2 tombstone bound to its scope and
    // regenerated register digest, and a release-before-register root has exactly
    // one such tombstone whose expected register digest is the intent it fences.
    // An extra, duplicate, generation-3, foreign-scope or malformed row is refused.
    //
    // Any other lifetime shape was already refused above; it is refused here too
    // (its own shape, not its tombstones) and never reaches the row access, so a
    // corrupted source is always a violation instead of a validator panic.
    for head in heads {
        let key = (head.repository_id, head.root_id);
        let at = format!("{}:{}", key.0, key.1);
        let rows = tombstones.iter().filter(|t| by_key(t) == key).collect::<Vec<_>>();
        let shape = |t: &RootTombstone| {
            t.generation == 2
                && same_scope(head, t.tenant_id, t.owner_id, &t.purpose, &t.business_intent_digest)
                && canonical_digest(&t.release_digest)
        };
        let lifetime = match (head.state.as_str(), head.last_generation) {
            ("active", 1) => Lifecycle::Active,
            ("released", 2) => Lifecycle::Released,
            _ => Lifecycle::Invalid,
        };
        match (lifetime, rows.as_slice()) {
            (Lifecycle::Invalid, _) => lines.push(format!("root_head_mismatch:{at}:state")),
            (Lifecycle::Active, []) => {}
            (Lifecycle::Active, _) => lines.push(format!("root_head_mismatch:{at}:tombstone_without_release")),
            // The only place a tombstone row is indexed: exactly one row, after
            // the released/2 shape is known.
            (Lifecycle::Released, [row]) if !shape(row) => {
                lines.push(format!("root_head_mismatch:{at}:tombstone_mismatch"));
            }
            // A release digest is already canonical above, so only the bound
            // register digest can still disagree here.
            (Lifecycle::Released, [row]) if row.expected_register_digest != head.register_digest => {
                lines.push(format!("root_tombstone_mismatch:{at}:register_digest"));
            }
            (Lifecycle::Released, [_]) => {}
            (Lifecycle::Released, _) => lines.push(format!("root_head_mismatch:{at}:tombstone_mismatch")),
        }
    }
    for tombstone in tombstones {
        let key = by_key(tombstone);
        if !heads.iter().any(|head| (head.repository_id, head.root_id) == key) {
            lines.push(format!("root_tombstone_without_head:{}:{}", key.0, key.1));
        }
    }
    lines
}

/// The head's lifetime state as `retention_root` writes it.
enum Lifecycle {
    /// `register`: generation 1, no tombstone yet.
    Active,
    /// `release` (recorded) or release-before-register: generation 2, one fence.
    Released,
    /// Any other pair of state and generation.
    Invalid,
}

/// A release digest as `release` stores it: canonical lowercase SHA-256 hex.
fn canonical_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Whether a row's own full scope (tenant, producer owner, purpose and business
/// intent digest) is exactly the head's.
fn same_scope(head: &RootHead, tenant: Uuid, owner: Uuid, purpose: &str, intent: &str) -> bool {
    tenant == head.tenant_id
        && owner == head.owner_id
        && purpose == head.purpose
        && intent == head.business_intent_digest
}

/// One generation-2 release tombstone that fences exactly this head's scope and
/// its bound register digest.
fn release_fence(tombstone: &RootTombstone, head: &RootHead) -> bool {
    tombstone.generation == 2
        && tombstone.expected_register_digest == head.register_digest
        && same_scope(
            head,
            tombstone.tenant_id,
            tombstone.owner_id,
            &tombstone.purpose,
            &tombstone.business_intent_digest,
        )
        && canonical_digest(&tombstone.release_digest)
}

/// The declared registration a root capture was taken from, via one of its
/// retained packs.
fn source_owner(capture: &RootCapture, declared: &[DeclaredPair]) -> Option<()> {
    capture
        .packs
        .iter()
        .find_map(|pack| declared.iter().find(|pair| pair.registration_id == pack.registration_id))
        .and_then(|pair| pair.publication.as_ref())
        .map(|_| ())
}
