use super::shared::*;

/// The single legal generation-2 release fence of `valid_source`.
fn base_tombstone() -> RootTombstone {
    valid_source().tombstones.remove(0)
}

/// Every stored tombstone row of a key is judged, never only the one row that
/// matches: an active root has none, a released root (captured or released
/// before `register`) has exactly one generation-2 row carrying its scope, the
/// expected register digest and a canonical release digest.
#[test]
fn every_tombstone_row_of_a_key_must_be_the_single_legal_release_fence() {
    let valid = valid_source();
    assert!(valid.violations().is_empty(), "{:?}", valid.violations());
    // An active root never carries a tombstone, even a well-formed one.
    let mut active = valid.clone();
    active.heads = vec![head("active", 1)];
    assert_root_refused(&active.violations(), "root_head_mismatch", "tombstone_without_release");
    // A recorded-then-released and a released-before-register root are valid.
    let mut released_first = valid.clone();
    released_first.roots.clear();
    assert!(released_first.violations().is_empty(), "{:?}", released_first.violations());
    // One bad extra row beside the legal fence, under every released shape: an
    // extra generation-3 row, a foreign scope or a malformed release digest must
    // be refused, and so must a released root whose only tombstone is one of them.
    let broken: [(&str, RootTombstone); 6] = [
        ("generation-3", RootTombstone { generation: 3, ..base_tombstone() }),
        ("owner", RootTombstone { owner_id: Uuid::from_u128(0x1600), ..base_tombstone() }),
        ("purpose", RootTombstone { purpose: "other".into(), ..base_tombstone() }),
        ("uppercase-release", RootTombstone { release_digest: "AB".repeat(32), ..base_tombstone() }),
        ("short-release", RootTombstone { release_digest: "ab".repeat(31), ..base_tombstone() }),
        ("non-hex-release", RootTombstone { release_digest: "zz".repeat(32), ..base_tombstone() }),
    ];
    // `sha(0x33)` is all digits, so upper-casing it would change nothing; the
    // uppercase row must really differ from the legal fence.
    let uppercase = &broken[3].1.release_digest;
    assert_eq!(uppercase.len(), 64);
    assert_ne!(uppercase, &sha(0x33));
    assert!(uppercase.bytes().any(|byte| byte.is_ascii_uppercase()));
    for (name, row) in broken {
        for captured in [true, false] {
            let mut sets = valid.clone();
            sets.tombstones.push(row.clone());
            if !captured {
                sets.roots.clear();
            }
            assert_root_refused(&sets.violations(), "root_head_mismatch", "tombstone_mismatch");
            // The same bad row as the only tombstone is refused too: a malformed
            // row is a tombstone mismatch, a foreign-scope row simply never fences.
            sets.tombstones = vec![row.clone()];
            let reason = match name {
                "generation-3" | "uppercase-release" | "short-release" | "non-hex-release" => "tombstone_mismatch",
                _ if captured => "unreleased",
                _ => "released",
            };
            let lines = sets.violations();
            let refused = lines.iter().any(|line| line.starts_with("root_") && line.ends_with(reason));
            assert!(refused, "{name} alone (captured={captured}): expected {reason} in {lines:?}");
        }
    }
    // A duplicate of the legal fence is an extra row too.
    for captured in [true, false] {
        let mut sets = valid.clone();
        sets.tombstones.push(base_tombstone());
        if !captured {
            sets.roots.clear();
        }
        assert_root_refused(&sets.violations(), "root_head_mismatch", "tombstone_mismatch");
    }
    // A released root whose only tombstone binds another register digest stays a
    // mismatch of the fence itself.
    let mut bound = valid.clone();
    bound.tombstones = vec![RootTombstone { expected_register_digest: sha(0x34), ..base_tombstone() }];
    assert_root_refused(&bound.violations(), "root_tombstone_mismatch", "register_digest");
}
