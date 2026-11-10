
    use super::*;

    #[test]
    fn cross_cluster_runner_queue_epochs_and_stale_heartbeat_rejection() {
        let mut q = RunnerQueueState {
            repository_id: Uuid::new_v4(), storage_generation: 1, runners: Vec::new(), claims: Vec::new(),
        };
        let r1 = RunnerQueueRequest {
            action: "claim".into(), runner_id: "runner-a".into(), cluster_zone: "us-east-1a".into(),
            job_id: Some("job-1".into()), target_oid: Some("a".repeat(40)), lease_ttl_secs: Some(60),
            now_unix: Some(1000), attempt: None, storage_generation: Some(1),
        };
        assert_eq!(apply_runner_action(&mut q, &r1, None, 1000).unwrap().active_claim.unwrap().attempt, 1);
        let reap = RunnerQueueRequest { action: "reap_expired".into(), now_unix: Some(1065), ..r1.clone() };
        assert_eq!(apply_runner_action(&mut q, &reap, None, 1065).unwrap().reaped_jobs, vec!["job-1"]);
        let r2 = RunnerQueueRequest { runner_id: "runner-b".into(), cluster_zone: "eu-west-1b".into(), now_unix: Some(1070), ..r1.clone() };
        assert_eq!(apply_runner_action(&mut q, &r2, None, 1070).unwrap().active_claim.unwrap().attempt, 2);
        let stale_hb = RunnerQueueRequest { action: "heartbeat".into(), now_unix: Some(1075), attempt: Some(1), ..r1 };
        assert_eq!(apply_runner_action(&mut q, &stale_hb, None, 1075).unwrap_err().0, StatusCode::CONFLICT);
    }
