//! Membership-only declared-pair regressions, compiled as
//! `ledger_sets_tests::membership_tests`.
//!
//! A pair declared only by membership is restated by no snapshot or root, so
//! `check_declared` is the only place that can refuse it. It must still be the
//! canonical A4 set: the stored publication digest has to equal the digest the
//! issuer recomputes over the rows.
use super::*;

/// The declaration of `declared`, and of both its digest columns alone.
fn membership_only(declared: &[DeclaredPair]) -> SourceSets {
    let declared = declared
        .iter()
        .map(|pair| {
            let publication = pair.publication.as_ref().expect("a membership-only pair is published");
            DeclaredPair {
                declared_by: vec!["membership".to_owned()],
                declared_sets: vec![(
                    "membership".to_owned(),
                    publication.digest.clone(),
                    publication.gate_revision.saturating_add(1),
                )],
                ..pair.clone()
            }
        })
        .collect::<Vec<_>>();
    SourceSets { declared, ..Default::default() }
}

/// One digest written to both columns: `declared_sets` stays equal to the
/// publication, so only the recomputation over the rows can refuse it.
fn relabel(sets: &mut SourceSets, digest: &str) {
    let pair = &mut sets.declared[0];
    pair.publication.as_mut().unwrap().digest = digest.to_owned();
    for (_, stored, _) in &mut pair.declared_sets {
        *stored = digest.to_owned();
    }
}

#[test]
fn a_membership_only_pair_must_be_the_canonical_a4_set() {
    let mut valid = valid_source();
    valid.roots.clear();
    valid.heads.clear();
    valid.tombstones.clear();
    let clean = membership_only(&valid.declared);
    assert_eq!(clean.declared[0].declared_by, ["membership"]);
    assert_eq!(clean.violations(), Vec::<String>::new());
    // The canonical digest is untouched: the same artifacts under an equally
    // wrong stored digest on both sides are still refused.
    let mut relabelled = clean.clone();
    relabel(&mut relabelled, &sha(0x44));
    let lines = relabelled.violations();
    assert_eq!(lines, vec![format!("canonical_pair_mismatch:{}", tag(&relabelled.declared[0]))]);
    // A locator and its hold that agree with each other but not with the stored
    // digest are refused the same way.
    let mut artifacts = base_artifacts();
    artifacts[0].hold.as_mut().unwrap().generation = 4;
    let mut moved = membership_only(&[pair(artifacts)]);
    relabel(&mut moved, &valid.declared[0].publication.as_ref().unwrap().digest.clone());
    assert_eq!(moved.violations(), vec![format!("canonical_pair_mismatch:{}", tag(&moved.declared[0]))]);
}
