use super::*;

#[test]
fn ref_transaction_intent_precedes_receipt_and_accepts_sha256() {
    let (_root, op) = setup();
    let changes = vec![RefChange {
        ref_name: "refs/heads/main".into(),
        old_oid: "0".repeat(64),
        new_oid: "a".repeat(64),
    }];
    record_ref_transaction_intent(&op, &changes).unwrap();
    assert_eq!(requests(&op).unwrap(), Some(changes.clone()));
    assert_eq!(receipts(&op).unwrap(), None);
    record_ref_transaction_receipt(&op, &changes).unwrap();
    assert_eq!(receipts(&op).unwrap(), Some(changes));
    assert_eq!(events(&op).unwrap()[0].phase, HookPhase::Committed);
}
fn setup() -> (tempfile::TempDir, Operation) {
    let root = tempfile::tempdir().unwrap();
    let op = begin(
        root.path(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        "actor".into(),
        Uuid::new_v4(),
        1,
    )
    .unwrap();
    (root, op)
}
#[test]
fn concurrent_admission_reserves_unique_durable_sequences() {
    let root = tempfile::tempdir().unwrap();
    let repo = Uuid::new_v4();
    let operations = std::thread::scope(|scope| {
        let handles = (0..48)
            .map(|_| {
                scope.spawn(|| {
                    begin(
                        root.path(),
                        repo,
                        Uuid::new_v4(),
                        "parallel-actor".into(),
                        Uuid::new_v4(),
                        1,
                    )
                    .unwrap()
                })
            })
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>()
    });
    let mut sequences = operations.iter().map(|op| op.sequence).collect::<Vec<_>>();
    sequences.sort_unstable();
    assert_eq!(sequences, (1..=48).collect::<Vec<_>>());
    assert_eq!(sequence(root.path(), repo).unwrap(), 48);
    assert_eq!(pending(root.path(), repo).unwrap().len(), 48);
}
#[test]
fn active_admission_is_visible_before_other_recovery_scans() {
    let root = tempfile::tempdir().unwrap();
    let repo = Uuid::new_v4();
    let (op, guard) = begin_active(
        root.path(),
        repo,
        Uuid::new_v4(),
        "active-actor".into(),
        Uuid::new_v4(),
        1,
    )
    .unwrap();
    assert!(ActiveGuard::operation_is_live(&op).unwrap());
    assert_eq!(pending(root.path(), repo).unwrap(), vec![op.clone()]);
    assert!(events(&op).unwrap().is_empty());
    drop(guard);
    assert!(!ActiveGuard::operation_is_live(&op).unwrap());
    mark_interrupted(&op).unwrap();
    finish(&op).unwrap();
    assert!(is_interrupted(&op).unwrap());
}
#[test]
fn ci_service_journal_has_no_human_identity() {
    let root = tempfile::tempdir().unwrap();
    let job_id = Uuid::new_v4();
    let intent = crate::ci_pins::Intent {
        version: 1,
        job_id,
        owner_id: Uuid::new_v4(),
        repository_id: Uuid::new_v4(),
        storage_generation: 1,
        object_format: "sha1".into(),
        target_oid: "a".repeat(40),
        retention_ref: format!("refs/rootyard-ci/jobs/{job_id}"),
    };
    let principal = Uuid::new_v4();
    let op = begin_ci_service(root.path(), &intent, principal).unwrap();
    assert!(op.actor_id.is_nil() && op.token_id.is_nil());
    assert_eq!(op.service_principal_id, Some(principal));
    assert_eq!(
        pending(root.path(), intent.repository_id).unwrap(),
        vec![op]
    );
}
fn payload(old: char, new: char) -> Vec<u8> {
    format!(
        "{} {} refs/heads/main\n",
        old.to_string().repeat(40),
        new.to_string().repeat(40)
    )
    .into_bytes()
}
#[test]
fn interrupted_admission_staging_preserves_sequence_gap() {
    let (root, op) = setup();
    let repo = op.path.parent().unwrap();
    let staging = repo.join(".tmp-operation-interrupted");
    mkdir(&staging).unwrap();
    atomic(&staging.join("operation.json"), b"incomplete", false).unwrap();
    atomic(&repo.join("sequence"), b"2", true).unwrap();
    assert_eq!(
        pending(root.path(), op.repository_id).unwrap(),
        vec![op.clone()]
    );
    let next = begin(
        root.path(),
        op.repository_id,
        op.actor_id,
        op.actor_name,
        op.token_id,
        1,
    )
    .unwrap();
    assert_eq!(next.sequence, 3);
    assert_eq!(pending(root.path(), next.repository_id).unwrap().len(), 2);
    assert!(staging.exists());
}
#[test]
fn lifecycle_and_monotonic_sequence() {
    let (root, op) = setup();
    let p = payload('0', 'a');
    record(&op, HookPhase::Prepared, &p).unwrap();
    assert!(retire(&op).is_err());
    record_receipt(&op, &p).unwrap();
    finish(&op).unwrap();
    retire(&op).unwrap();
    let next = begin(
        root.path(),
        op.repository_id,
        op.actor_id,
        op.actor_name,
        op.token_id,
        1,
    )
    .unwrap();
    assert_eq!(next.sequence, 2);
    assert_eq!(pending(root.path(), op.repository_id).unwrap().len(), 1);
}
#[test]
fn repeated_events_and_nested_noise_are_preserved() {
    let (_root, op) = setup();
    let p = payload('a', 'b');
    let noise = payload('0', '0');
    for (phase, input) in [
        (HookPhase::Preparing, &p),
        (HookPhase::Prepared, &p),
        (HookPhase::Prepared, &noise),
        (HookPhase::Committed, &noise),
        (HookPhase::Committed, &p),
        (HookPhase::Aborted, &noise),
        (HookPhase::Prepared, &p),
    ] {
        record(&op, phase, input).unwrap();
    }
    let e = events(&op).unwrap();
    assert_eq!(e.len(), 7);
    assert_eq!(e[1].changes, e[6].changes);
    assert_eq!(e[2].changes[0].old_oid, e[2].changes[0].new_oid);
    assert!(receipts(&op).unwrap().is_none());
}
#[test]
fn receipt_is_separate_and_preserves_order() {
    let (_root, op) = setup();
    let mut p = payload('a', 'b');
    p.extend(payload('b', 'a'));
    p.extend(payload('a', 'b'));
    record_receipt(&op, &p).unwrap();
    let r = receipts(&op).unwrap().unwrap();
    assert_eq!(r.len(), 3);
    assert_eq!(r[0], r[2]);
    assert_ne!(r[0], r[1]);
    assert!(record_receipt(&op, &p).is_err());
    assert!(events(&op).unwrap().is_empty());
}
#[test]
fn invalid_inputs_and_truncated_receipt() {
    let (_root, op) = setup();
    assert!(parse(b"\xff").is_err());
    assert!(parse(&vec![b'x'; MAX_BYTES + 1]).is_err());
    let mut p = payload('0', 'a');
    p.pop();
    assert!(record_receipt(&op, &p).is_err());
    assert!(receipts(&op).unwrap().is_none());
    assert!(parse(format!("{} ref:refs/heads/main HEAD\n", "0".repeat(40)).as_bytes()).is_err());
    assert!(parse(format!("{} {} HEAD\n", "0".repeat(40), "a".repeat(40)).as_bytes()).is_ok());
    assert!(valid_ref("refs/heads/topic"));
    assert!(!valid_ref("refs/../escape"));
}
#[test]
fn refuses_symlinks_and_corrupt_metadata() {
    let (_root, op) = setup();
    fs::remove_file(op.path.join("operation.json")).unwrap();
    std::os::unix::fs::symlink("/etc/passwd", op.path.join("operation.json")).unwrap();
    assert!(events(&op).is_err());
}
#[test]
fn detects_missing_events_and_blocking_marker() {
    let (_root, op) = setup();
    record(&op, HookPhase::Prepared, &payload('0', 'a')).unwrap();
    record(&op, HookPhase::Committed, &payload('0', 'a')).unwrap();
    fs::remove_file(op.path.join("00000000000000000001.event.json")).unwrap();
    assert!(events(&op).is_err());
    atomic(&op.path.join("corrupt"), b"", false).unwrap();
    assert!(receipts(&op).is_err());
}
fn near_limit_input() -> Vec<u8> {
    let line = format!(
        "{} {} refs/heads/{}\n",
        "0".repeat(40),
        "a".repeat(40),
        "x".repeat(150)
    );
    line.repeat(MAX_REFS).into_bytes()
}
#[test]
fn expanded_json_above_one_mib_round_trips() {
    let (_root, op) = setup();
    let input = near_limit_input();
    assert!(input.len() < MAX_BYTES && input.len() > MAX_BYTES * 9 / 10);
    record(&op, HookPhase::Prepared, &input).unwrap();
    let bytes = read(&op.path.join("00000000000000000001.event.json")).unwrap();
    assert!(bytes.len() > MAX_BYTES && bytes.len() < MAX_RECORD_BYTES);
    assert_eq!(events(&op).unwrap()[0].changes.len(), MAX_REFS);
    record_receipt(&op, &input).unwrap();
    assert_eq!(receipts(&op).unwrap().unwrap().len(), MAX_REFS);
}
#[test]
fn aggregate_event_cap_rejects_append_and_oversized_recovery() {
    let (_root, op) = setup();
    let input = near_limit_input();
    let mut count = 0;
    while record(&op, HookPhase::Prepared, &input).is_ok() {
        count += 1;
        assert!(count < 32);
    }
    let (saved, size) = events_with_size(&op).unwrap();
    assert_eq!(saved.len(), count);
    assert!(size <= MAX_EVENT_BYTES);
    // Receipt has its own allowance and remains writable at event capacity.
    record_receipt(&op, &input).unwrap();
    assert!(receipts(&op).unwrap().is_some());
    let mut extra = saved[0].clone();
    extra.ordinal = count as i64 + 1;
    atomic(
        &op.path.join(format!("{:020}.event.json", extra.ordinal)),
        &serde_json::to_vec(&extra).unwrap(),
        false,
    )
    .unwrap();
    assert!(events(&op).is_err());
}
#[test]
fn reference_name_byte_boundary() {
    let prefix = format!("refs/heads/{}", "segment/".repeat(120));
    let name = format!("{}{}", prefix, "x".repeat(1024 - prefix.len()));
    assert_eq!(name.len(), 1024);
    assert!(valid_ref(&name));
    assert!(!valid_ref(&format!("{name}x")));
    let unicode = format!("{}é", &name[..1022]);
    assert_eq!(unicode.len(), 1024);
    assert!(valid_ref(&unicode));
    assert!(!valid_ref(&format!("{unicode}x")));
    let (_root, op) = setup();
    let input = format!("{} {} {}x\n", "0".repeat(40), "a".repeat(40), name);
    assert!(record(&op, HookPhase::Prepared, input.as_bytes()).is_err());
    assert!(events(&op).unwrap().is_empty());
}
fn batch(count: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    for i in 0..count {
        writeln!(
            bytes,
            "{} {} refs/heads/branch-{i}",
            "0".repeat(40),
            "a".repeat(40)
        )
        .unwrap();
    }
    bytes
}
#[test]
fn pre_receive_admits_4096_ordered_unique_refs() {
    let (_root, op) = setup();
    let input = batch(4096);
    record_request(&op, &input).unwrap();
    let request = requests(&op).unwrap().unwrap();
    assert_eq!(request.len(), 4096);
    assert_eq!(request[0].ref_name, "refs/heads/branch-0");
    assert_eq!(request[4095].ref_name, "refs/heads/branch-4095");
    assert!(events(&op).unwrap().is_empty());
    assert!(receipts(&op).unwrap().is_none());
}
#[test]
fn pre_receive_rejects_batch_limits_without_ambiguity() {
    let mut duplicate = payload('0', 'a');
    duplicate.extend(payload('a', 'b'));
    let long = format!(
        "{} {} refs/heads/{}\n",
        "0".repeat(40),
        "a".repeat(40),
        "x".repeat(1024)
    );
    for input in [
        batch(4097),
        duplicate,
        long.into_bytes(),
        vec![b'x'; MAX_BYTES + 1],
    ] {
        let (_root, op) = setup();
        assert!(record_request(&op, &input).is_err());
        assert!(requests(&op).unwrap().is_none());
        assert!(events(&op).unwrap().is_empty());
        assert!(!exists(&op.path.join("corrupt")).unwrap());
    }
}
#[test]
fn interruption_and_corruption_markers_are_durable_and_checked() {
    let (_root, op) = setup();
    assert!(!is_interrupted(&op).unwrap());
    mark_interrupted(&op).unwrap();
    mark_interrupted(&op).unwrap();
    finish(&op).unwrap();
    assert!(is_interrupted(&op).unwrap());
    assert!(is_finished(&op).unwrap());
    assert!(events(&op).unwrap().is_empty());
    fs::write(op.path.join("interrupted"), b"unexpected").unwrap();
    assert!(is_interrupted(&op).is_err());
    mark_corrupt(&op).unwrap();
    assert!(events(&op).is_err());
}
