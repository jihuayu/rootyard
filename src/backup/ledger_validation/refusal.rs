//! The bounded, fixed-vocabulary source-ledger refusal.
//!
//! Only [`LedgerValidationRefusal::of`] can construct a refusal, and it is
//! called exclusively at the validator's final branch. The public surface is a
//! total count and sorted summary codes; ids, reasons, SQL, paths and
//! credentials are never retained, so no generic error can be mistaken for a
//! source-ledger violation.
/// The fixed summary code of a violation prefix outside [`VIOLATION_CODES`].
/// The input prefix is never echoed.
pub const OTHER_VIOLATION_CODE: &str = "other";

/// The source artifact ledger is inconsistent: [`validate_source`] completed
/// every read and check and found a non-empty, sorted, de-duplicated violation
/// set. Its only constructor, [`Self::of`], is called at that final branch and
/// nowhere else, and no field is public, so a generic backup, query, decode,
/// timeout, root-proof, backend or filesystem error can never be constructed
/// as this type and never reaches the CLI's typed classification.
///
/// The public summary is bounded on purpose: the total count and the sorted,
/// unique summary codes. Violation ids, free-form reason tails, raw messages,
/// SQL, paths and credentials are never retained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerValidationRefusal {
    count: usize,
    codes: Vec<&'static str>,
}

impl LedgerValidationRefusal {
    /// `None` for the consistent empty set, else the typed refusal carrying
    /// only the count and the sorted, unique summary codes.
    pub(super) fn of(violations: &[String]) -> Option<Self> {
        if violations.is_empty() {
            return None;
        }
        Some(Self { count: violations.len(), codes: summary_codes(violations.iter().map(String::as_str)) })
    }

    /// The total number of distinct violations.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Sorted, unique summary codes: a fixed vocabulary, never an id or reason
    /// tail.
    pub fn codes(&self) -> &[&'static str] {
        &self.codes
    }

    /// The one deterministic, fixed-vocabulary summary the CLI appends.
    pub fn diagnostic(&self) -> String {
        format!("source artifact ledger is inconsistent ({} violations; codes: {})", self.count, self.codes.join(","))
    }
}

impl std::fmt::Display for LedgerValidationRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.diagnostic())
    }
}

impl std::error::Error for LedgerValidationRefusal {}

/// A whole-line known violation: the exact prefix such a line starts with.
struct ViolationCode {
    prefix: &'static str,
    code: &'static str,
}

/// Every violation line the checkers can emit, matched as the whole text before
/// the first `:`. The prefixes are listed longest first within a family, so the
/// first match is decisive even for a discriminator that itself contains `:`
/// (an artifact `role:slot` of the `owner_scope_mismatch` line). Derived from
/// `ledger_sets`, `ledger_sets/declared_owner_scope`, `ledger_sets/root_lifetime`,
/// `ledger_sets/serving_reads` and [`realm_violations`]; a prefix missing here
/// is collapsed to [`OTHER_VIOLATION_CODE`] and cannot be spoofed.
const VIOLATION_CODES: [ViolationCode; 38] = [
    ViolationCode { prefix: "serving_read_artifact_mismatch", code: "serving_read_artifact_mismatch" },
    ViolationCode { prefix: "serving_read_backend_mismatch", code: "serving_read_backend_mismatch" },
    ViolationCode { prefix: "serving_read_capture_mismatch", code: "serving_read_capture_mismatch" },
    ViolationCode { prefix: "serving_read_membership_mismatch", code: "serving_read_membership_mismatch" },
    ViolationCode { prefix: "serving_read_pack_mismatch", code: "serving_read_pack_mismatch" },
    ViolationCode { prefix: "serving_read_pack_missing", code: "serving_read_pack_missing" },
    ViolationCode { prefix: "serving_read_realm_mismatch", code: "serving_read_realm_mismatch" },
    ViolationCode { prefix: "serving_read_unregistered_pack", code: "serving_read_unregistered_pack" },
    ViolationCode { prefix: "serving_read_orphan", code: "serving_read_orphan" },
    ViolationCode { prefix: "snapshot_membership_mismatch", code: "snapshot_membership_mismatch" },
    ViolationCode { prefix: "snapshot_set_mismatch", code: "snapshot_set_mismatch" },
    ViolationCode { prefix: "root_tombstone_without_head", code: "root_tombstone_without_head" },
    ViolationCode { prefix: "root_tombstone_mismatch", code: "root_tombstone_mismatch" },
    ViolationCode { prefix: "root_selector_mismatch", code: "root_selector_mismatch" },
    ViolationCode { prefix: "root_capture_mismatch", code: "root_capture_mismatch" },
    ViolationCode { prefix: "root_capture_missing", code: "root_capture_missing" },
    ViolationCode { prefix: "root_capture_invalid", code: "root_capture_invalid" },
    ViolationCode { prefix: "root_pack_set_mismatch", code: "root_pack_set_mismatch" },
    ViolationCode { prefix: "root_head_mismatch", code: "root_head_mismatch" },
    ViolationCode { prefix: "root_head_missing", code: "root_head_missing" },
    ViolationCode { prefix: "root_refs_mismatch", code: "root_refs_mismatch" },
    ViolationCode { prefix: "root_set_mismatch", code: "root_set_mismatch" },
    ViolationCode { prefix: "unregistered_publication", code: "unregistered_publication" },
    ViolationCode { prefix: "canonical_pair_mismatch", code: "canonical_pair_mismatch" },
    ViolationCode { prefix: "publication_binding_mismatch", code: "publication_binding_mismatch" },
    ViolationCode { prefix: "owner_scope_mismatch", code: "owner_scope_mismatch" },
    // The whole publication-key line: its key holds no `:` itself.
    ViolationCode { prefix: "publication_key", code: "publication_key" },
    ViolationCode { prefix: "declared_set_digest_mismatch", code: "declared_set_digest_mismatch" },
    ViolationCode { prefix: "declared_joined_revision_mismatch", code: "declared_joined_revision_mismatch" },
    ViolationCode { prefix: "missing_artifacts", code: "missing_artifacts" },
    ViolationCode { prefix: "incomplete_pair", code: "incomplete_pair" },
    ViolationCode { prefix: "extra_artifacts", code: "extra_artifacts" },
    ViolationCode { prefix: "illegal_roles", code: "illegal_roles" },
    ViolationCode { prefix: "foreign_hold_binding", code: "foreign_hold_binding" },
    ViolationCode { prefix: "missing_receipt", code: "missing_receipt" },
    ViolationCode { prefix: "hold_mismatch", code: "hold_mismatch" },
    ViolationCode { prefix: "repository_realm_mismatch", code: "repository_realm_mismatch" },
    // The fixed fallback must stay last.
    ViolationCode { prefix: OTHER_VIOLATION_CODE, code: OTHER_VIOLATION_CODE },
];

/// The allowlisted summary code of one violation line: the text before its first
/// `:`, exactly one [`VIOLATION_CODES`] prefix, else the fixed
/// [`OTHER_VIOLATION_CODE`]. Never echoes the input.
pub fn violation_code(line: &str) -> &'static str {
    let prefix = line.split(':').next().unwrap_or("");
    VIOLATION_CODES.iter().find(|code| code.prefix == prefix).map_or(OTHER_VIOLATION_CODE, |code| code.code)
}

/// The sorted, unique summary codes of `lines` in first-seen order.
fn summary_codes<'a>(lines: impl Iterator<Item = &'a str>) -> Vec<&'static str> {
    let mut codes = lines.map(violation_code).collect::<Vec<_>>();
    codes.sort_unstable();
    codes.dedup();
    codes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    /// Every prefix the checkers can emit maps to itself, the fallback stays
    /// `other`, and no line ever leaks its id, reason tail or an unknown prefix.
    #[test]
    fn the_typed_refusal_exposes_only_count_and_summary_codes() {
        let violations = lines(&[
            "canonical_pair_mismatch:00000000-0000-0000-0000-000000000001:secret/reason:tail",
            "root_set_mismatch:00000000-0000-0000-0000-000000000002:bad_free_text",
            "canonical_pair_mismatch:another:pair",
            "canonical_pair:not-a-known-prefix",
            "cd_secret:postgres://user:password@host/db",
            "owner_scope_mismatch:a:b:c:pack:0",
            "publication_key:a:b:c",
            "",
        ]);
        let refusal = LedgerValidationRefusal::of(&violations).expect("a non-empty set is a refusal");
        assert_eq!(refusal.count(), 8);
        assert_eq!(
            refusal.codes(),
            [
                "canonical_pair_mismatch",
                OTHER_VIOLATION_CODE,
                "owner_scope_mismatch",
                "publication_key",
                "root_set_mismatch"
            ]
        );
        assert_eq!(
            refusal.diagnostic(),
            "source artifact ledger is inconsistent (8 violations; codes: canonical_pair_mismatch,other,owner_scope_mismatch,publication_key,root_set_mismatch)"
        );
        for leaked in ["00000000", "secret", "postgres", "cd_secret", "pack:0", "reason"] {
            assert!(!refusal.diagnostic().contains(leaked), "{leaked} leaked: {}", refusal.diagnostic());
        }
        // Every allowlisted code is reachable from its own line and is never `other`.
        for entry in &VIOLATION_CODES[..VIOLATION_CODES.len() - 1] {
            assert_ne!(entry.code, OTHER_VIOLATION_CODE);
            assert_eq!(violation_code(&format!("{}:id", entry.prefix)), entry.code, "{}", entry.prefix);
        }
        assert_eq!(violation_code(&format!("{OTHER_VIOLATION_CODE}:id")), OTHER_VIOLATION_CODE);
        let all = VIOLATION_CODES.map(|entry| format!("{}:id", entry.prefix));
        assert_eq!(summary_codes(all.iter().map(String::as_str)).len(), VIOLATION_CODES.len());
        assert!(LedgerValidationRefusal::of(&[]).is_none());
        assert!(LedgerValidationRefusal::of(&lines(&["", ""])).is_some());
    }

    /// The SQL-decoded `missing_hold` and `mismatched_hold_locator` shapes keep
    /// the refusal causal: both are canonical-pair and hold mismatches, and a
    /// deleted hold row (no hold, request or hold slot left) must never emit
    /// `foreign_hold_binding`.
    #[test]
    fn sql_decoded_hold_corruptions_keep_only_causal_summary_codes() {
        use uuid::Uuid;
        let valid_source = super::super::ledger_sets::ledger_sets_tests::valid_source_without;
        let recompute = super::super::ledger_sets::declared_violations;
        let allowed = [
            "canonical_pair_mismatch",
            "hold_mismatch",
            "owner_scope_mismatch",
            "root_set_mismatch",
            "root_pack_set_mismatch",
            "snapshot_set_mismatch",
            "snapshot_membership_mismatch",
            "serving_read_pack_mismatch",
        ];
        let mut missing = valid_source(&[]);
        {
            let pair = &mut missing.declared[0];
            let artifact = &mut pair.artifacts[0];
            artifact.hold = None;
            artifact.request = None;
            artifact.issuer_operation = false;
            artifact.hold_slot = None;
            pair.scope = recompute(pair);
        }
        let mut moved = valid_source(&[]);
        {
            let pair = &mut moved.declared[0];
            pair.artifacts[0].hold.as_mut().expect("the fixture holds both roles").storage_tenant_id =
                Uuid::from_u128(0x169);
            pair.scope = recompute(pair);
        }
        for (name, sets, expected) in [
            (
                "missing_hold",
                &missing,
                &[
                    "canonical_pair_mismatch",
                    "hold_mismatch",
                    "owner_scope_mismatch",
                    "root_pack_set_mismatch",
                    "root_set_mismatch",
                ][..],
            ),
            (
                "mismatched_hold_locator",
                &moved,
                &["canonical_pair_mismatch", "hold_mismatch", "root_pack_set_mismatch", "root_set_mismatch"][..],
            ),
        ] {
            let violations = sets.violations();
            let refusal = LedgerValidationRefusal::of(&violations).expect("a damaged source is refused");
            let codes = refusal.codes();
            assert_eq!(codes, expected, "{name}");
            assert!(codes.contains(&"canonical_pair_mismatch"), "{name}: {codes:?}");
            assert!(codes.contains(&"hold_mismatch"), "{name}: {codes:?}");
            assert!(!codes.contains(&"foreign_hold_binding"), "{name}: {codes:?}");
            assert!(!codes.contains(&OTHER_VIOLATION_CODE), "{name}: {codes:?}");
            assert!(codes.iter().all(|code| allowed.contains(code)), "{name}: {codes:?}");
            assert!(violations.iter().all(|line| violation_code(line) != "foreign_hold_binding"), "{name}");
        }
    }

    /// A real damaged set becomes the typed refusal through its only
    /// construction site, while any other failure (even one whose text looks
    /// like the summary) stays foreign to the type.
    #[test]
    fn a_real_violation_set_becomes_the_typed_refusal_and_a_deeper_error_stays_generic() {
        // The released root is dropped so only the damaged membership remains.
        let mut sets = super::super::ledger_sets::ledger_sets_tests::valid_source_without(&["idx"]);
        sets.roots.clear();
        sets.heads.clear();
        sets.tombstones.clear();
        sets.declared[0].publication.as_mut().unwrap().digest = "00".repeat(32);
        let violations = sets.violations();
        let mut codes = violations.iter().map(|line| violation_code(line)).collect::<Vec<_>>();
        codes.sort_unstable();
        codes.dedup();
        assert!(codes.contains(&"canonical_pair_mismatch") && codes.contains(&"incomplete_pair"), "{violations:?}");
        let error = prove(violations.clone()).unwrap_err().context("wrapped");
        let found = error
            .chain()
            .find_map(|cause| cause.downcast_ref::<LedgerValidationRefusal>())
            .expect("the typed cause is found through its context");
        assert_eq!(found.codes(), codes);
        assert_eq!(found.count(), violations.len());
        // A different failure underneath the same context is not the refusal.
        let error = anyhow::anyhow!("source artifact ledger cannot be archived: Caused by: {}", {
            let refusal = LedgerValidationRefusal::of(&violations).unwrap();
            refusal.diagnostic()
        })
        .context("source artifact ledger cannot be archived");
        assert!(error.chain().all(|cause| cause.downcast_ref::<LedgerValidationRefusal>().is_none()));
    }

    /// Calls the validator's final branch: refused iff a violation exists.
    fn prove(violations: Vec<String>) -> anyhow::Result<()> {
        match LedgerValidationRefusal::of(&violations) {
            Some(refusal) => Err(anyhow::Error::new(refusal)),
            None => Ok(()),
        }
    }
}
