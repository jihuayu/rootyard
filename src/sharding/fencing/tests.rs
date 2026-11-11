use super::*;
use std::collections::BTreeMap;

#[test]
fn dual_layer_barrier_rejects_stale_epoch_token_generation_and_marker() {
    let repo_id = Uuid::new_v4();
    let route = RepoShardRoute {
        tenant_id: Uuid::nil(),
        repository_id: repo_id,
        bucket_id: 1,
        primary_node_id: "node-a".into(),
        read_replica_nodes: vec![],
        replica_watermarks: BTreeMap::new(),
        explicit_override: false,
        route_epoch: 3,
        fencing_token: 4,
        fenced_epoch: 2,
        draining: false,
        read_only_degraded: false,
        degraded_reason: String::new(),
        in_flight_writes: 0,
        required_generation: 2,
        required_op_sequence: 0,
        version: 1,
        created_at: String::new(),
        updated_at: String::new(),
    };
    let primary = ShardNode {
        node_id: "node-a".into(),
        endpoint: "http://node-a:8080".into(),
        role: "primary".into(),
        status: "healthy".into(),
        capacity_bytes: 1000,
        used_bytes: 0,
        lease_epoch: 3,
        lease_expires_unix: 500,
        fenced_epoch: 2,
        version: 1,
        created_at: String::new(),
        updated_at: String::new(),
    };
    let marker = VolumeFenceMarker::from_route(&route, 2, Some("node-old".into()), 100);
    assert!(evaluate_write_barrier(&route, &primary, 2, Some(&marker), None, 200).is_ok());

    let stale_ep = FenceActionInput { action: "verify".into(), writer_route_epoch: Some(2), ..Default::default() };
    assert!(evaluate_write_barrier(&route, &primary, 2, Some(&marker), Some(&stale_ep), 200).is_err());

    let stale_gen = FenceActionInput { action: "verify".into(), writer_storage_generation: Some(1), ..Default::default() };
    assert!(evaluate_write_barrier(&route, &primary, 2, Some(&marker), Some(&stale_gen), 200).is_err());
}
