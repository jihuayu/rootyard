//! CI pin tests implementation.
use super::*;
#[cfg(test)]
mod ci_pin_tests {
    use super::*;
    #[test]
    fn exact_oid_and_reserved_namespace() {
        assert!(valid_oid(&"a".repeat(40)));
        assert!(valid_oid(&"a".repeat(64)));
        for value in [
            "HEAD".to_owned(),
            "A".repeat(40),
            "a".repeat(39),
            "a".repeat(63),
        ] {
            assert!(!valid_oid(&value));
        }
        for name in [
            "refs/rootyard-ci",
            "refs/rootyard-ci/jobs",
            "refs/rootyard-ci/jobs/a",
        ] {
            assert!(reserved(name));
        }
        for name in [
            "refs/heads/rootyard-ci",
            "refs/rootyard-ci-other",
            "refs/rootyard",
        ] {
            assert!(!reserved(name));
        }
    }
    #[test]
    fn metadata_identity_and_receipt_are_immutable() {
        let root = tempfile::tempdir().unwrap();
        let intent = Intent {
            version: 1,
            job_id: Uuid::new_v4(),
            owner_id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            storage_generation: 1,
            object_format: "sha1".into(),
            target_oid: "a".repeat(40),
            retention_ref: String::new(),
        };
        let intent = Intent {
            retention_ref: format!("{NAMESPACE}/jobs/{}", intent.job_id),
            ..intent
        };
        journal::mkdir(&root.path().join("ci-pins")).unwrap();
        let directory = directory(root.path(), intent.repository_id);
        journal::mkdir(&directory).unwrap();
        journal::atomic(
            &directory.join(format!("{}.json", intent.job_id)),
            &serde_json::to_vec(&intent).unwrap(),
            false,
        )
        .unwrap();
        receipt(root.path(), &intent).unwrap();
        receipt(root.path(), &intent).unwrap();
        assert_eq!(
            load_intent(root.path(), intent.repository_id, intent.job_id).unwrap(),
            intent
        );
        let changed = Intent {
            target_oid: "b".repeat(40),
            ..intent.clone()
        };
        assert!(receipt(root.path(), &changed).is_err());
        assert_eq!(intents(root.path(), intent.repository_id).unwrap().len(), 1);
        let changed = Intent {
            object_format: "sha256".into(),
            ..intent
        };
        assert!(changed.validate().is_err());
    }
}
