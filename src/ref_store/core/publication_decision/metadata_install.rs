//! Install a real metadata command; private child of the metadata capability module.
use super::*;

/// Install the metadata-only decision from the real `CommitRefsRequest` and the captured PG ref map.
pub(crate) async fn select_and_install_metadata(
    tx: &Transaction<'_>,
    request: &CommitRefsRequest,
    actor: &Identity,
    deadline: Instant,
) -> Result<MetadataSelectedDecision, DecisionError> {
    if request.identity().issuer_id() != actor.id {
        return Err(DecisionError::Denied(DenialCode::TokenInvalid));
    }
    if request.refs().is_empty() || request.refs().len() > MAX_DECISION_REFS {
        return Err(DecisionError::Ledger("metadata decision ref count is out of bounds"));
    }
    if request.repository_id() != request.identity().repository_id() {
        return Err(DecisionError::Ledger("metadata request identity belongs to another repository"));
    }
    crate::ref_store::pg::bound(tx, deadline).await?;
    let action = PublicationAction::Push;
    sql_locks::lock_source_tables(tx, &action).await?;
    sql_locks::lock_repository_row(tx, request.repository_id()).await?;
    let tenant_id = request.tenant_id();
    sql_locks::lock_usage(tx, request.repository_id(), tenant_id).await?;
    let tombstone = tx
        .query_opt(
            "SELECT request_digest FROM ref_store_decision_cancellations
             WHERE repository_id=$1 AND operation_id=$2 FOR UPDATE",
            &[&request.repository_id(), &request.identity().operation_id()],
        )
        .await
        .map_err(sql_locks::sql_error)?;
    if tombstone.is_some() {
        return Err(DecisionError::Cancelled { operation_id: request.identity().operation_id(), decision_id: None });
    }
    let authority = metadata_authority(tx, request.repository_id(), actor).await?;
    if authority.owner_id != tenant_id
        || authority.object_format != request.object_format().as_str()
        || authority.tenant_id != tenant_id
        || authority.history_incarnation != request.history_incarnation()
        || authority.authority_epoch != request.authority_epoch()
        || authority.group_epoch != request.group_epoch()
        || authority.revision != request.expected_revision()
    {
        return Err(DecisionError::Denied(DenialCode::GateDigestMismatch));
    }

    let head_oids = request
        .refs()
        .iter()
        .filter_map(|update| update.target().oid().map(|oid| oid.as_hex()))
        .collect::<Vec<String>>();
    let policy = policy::read_policy_repo(tx, request.repository_id(), tenant_id, &head_oids).await?;
    let captured = capture_metadata_refs(tx, request.repository_id(), request.object_format()).await?;
    let (rows, accepted) = metadata_rows(request, &captured, &policy, &authority.head_ref);
    let selection_digest = metadata_selection_digest(request, &captured, &rows);
    let facts = metadata_facts_digest(request, &captured);
    let captured_digests = captured_digest(&captured);
    let dependencies = metadata_dependencies(request, actor, &authority, &policy);

    if let Some(existing) =
        sql_locks::decision_by_operation(tx, request.repository_id(), request.identity().operation_id(), true).await?
    {
        if existing.command_digest != *request.digest()
            || existing.actor_id != actor.id
            || existing.token_id != actor.token_id
            || existing.token_digest != hex::encode(&actor.token_digest)
            || existing.authz_digest != authority.authz_digest
            || existing.policy_digest != digest::policy_digest(&policy)
            || existing.dependencies_digest != digest::dependencies_digest(&dependencies)
            || existing.selection_digest != selection_digest
            || existing.facts_digest != digest::native_facts_digest(&facts)
            || existing.mode != metadata_kind(request)
        {
            return Err(DecisionError::Ledger("replayed metadata decision does not bind this exact request"));
        }
        if existing.state != DecisionState::Open {
            return Err(DecisionError::DecisionConflict { decision_id: existing.decision_id, state: existing.state });
        }
        let capability = DecisionCapability::mint(
            existing.decision_id,
            request.repository_id(),
            existing.tenant_id,
            existing.owner_id,
            actor.id,
            actor.token_id,
            request.identity().operation_id(),
            metadata_kind(request),
            PublicationAction::Push,
            request.object_format(),
            existing.base_revision,
            existing.not_after_millis,
            existing.created_db_millis,
            crate::ref_store::core::publication_decision::install::digests_from_row(&existing),
        );
        return Ok(MetadataSelectedDecision { capability, selection_digest, accepted, verdict_rows: rows, captured });
    }

    for dependency in &dependencies {
        sql_locks::observe_scope(tx, dependency.kind, dependency.id, dependency.version).await?;
    }

    let token_digest = hex::encode(&actor.token_digest);
    let delta = usage::delta_for(&rows, dependencies.len(), token_digest.len())?;
    usage::charge(tx, request.repository_id(), tenant_id, delta).await?;
    // Admission prepays the bounded terminal/event copies and every possible
    // ref-row write. Final consume can finish even if later installs fill the
    // monotone counter. Reservations are retained and never refunded.
    let ref_bytes = request
        .refs()
        .iter()
        .map(|update| update.name().as_str().len() + request.object_format().oid_hex_len() + 256)
        .sum::<usize>();
    usage::reserve_metadata_terminal(tx, request.repository_id(), tenant_id, 65_536, ref_bytes).await?;
    let now = sql_locks::db_clock(tx).await?;
    let not_after_millis = metadata_not_after(now, authority.token_expires_millis)?;
    let decision_id = Uuid::new_v4();
    let digests = super::digest::DecisionDigests {
        base_gate_digest: authority.gate_digest,
        command_digest: *request.digest(),
        refs_digest: digest::refs_digest(request.refs()),
        selected_refs_digest: selection_digest,
        selection_digest,
        policy_digest: digest::policy_digest(&policy),
        facts_digest: digest::native_facts_digest(&facts),
        authz_digest: authority.authz_digest,
        dependencies_digest: digest::dependencies_digest(&dependencies),
        packs_digest: captured_digests,
        hold_receipts_digest: captured_digests,
        captured_oid_digest: captured_digests,
    };
    let action_text = action.as_str();
    let object_format = request.object_format().as_str();
    let history = request.history_incarnation();
    let authority_epoch = request.authority_epoch();
    let group_epoch = request.group_epoch();
    let base_revision = request.expected_revision();
    let operation_id = request.identity().operation_id();
    let issuer_id = request.identity().issuer_id();
    let lane = request.identity().lane().as_str();
    let sequence = request.identity().sequence();
    let state = "OPEN";
    let closed: Option<&str> = None;
    let base_gate = digests.base_gate_digest.as_hex();
    let command = digests.command_digest.as_hex();
    let refs_text = digests.refs_digest.as_hex();
    let selection_text = digests.selection_digest.as_hex();
    let policy_text = digests.policy_digest.as_hex();
    let facts_text = digests.facts_digest.as_hex();
    let deps_text = digests.dependencies_digest.as_hex();
    let captured_text = digests.captured_oid_digest.as_hex();
    let mode_text = metadata_kind(request).as_str();
    let repository_id = request.repository_id();
    let params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = vec![
        &decision_id,
        &repository_id,
        &tenant_id,
        &authority.owner_id,
        &actor.id,
        &actor.token_id,
        &token_digest,
        &operation_id,
        &issuer_id,
        &lane,
        &sequence,
        &mode_text,
        &object_format,
        &history,
        &authority_epoch,
        &group_epoch,
        &base_revision,
        &base_gate,
        &command,
        &refs_text,
        &selection_text,
        &selection_text,
        &policy_text,
        &facts_text,
        &facts_text,
        &deps_text,
        &captured_text,
        &captured_text,
        &captured_text,
        &not_after_millis,
        &now,
        &state,
        &closed,
        &action_text,
    ];
    tx.execute(
        "INSERT INTO ref_store_publication_decisions(
             decision_id,repository_id,tenant_id,owner_id,actor_id,token_id,token_digest,operation_id,
             issuer_id,lane,sequence,mode,object_format,history_incarnation,authority_epoch,group_epoch,
             base_revision,base_gate_digest,command_digest,refs_digest,selected_refs_digest,
             selection_digest,policy_digest,facts_digest,authz_digest,dependencies_digest,packs_digest,
             hold_receipts_digest,captured_oid_digest,not_after_millis,created_db_millis,state,
             closed_code,action)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,
                $23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34)",
        &params,
    )
    .await
    .map_err(sql_locks::sql_error)?;
    for dependency in &dependencies {
        tx.execute(
            "INSERT INTO ref_store_decision_dependencies(
                 decision_id,scope_kind,scope_id,observed_version,observed_digest)
             VALUES($1,$2,$3,$4,$5)",
            &[
                &decision_id,
                &dependency.kind.as_str(),
                &dependency.id,
                &dependency.version,
                &dependency.digest.as_hex(),
            ],
        )
        .await
        .map_err(sql_locks::sql_error)?;
    }
    for (ordinal, (name, canonical)) in rows.iter().enumerate() {
        let ordinal = ordinal as i32;
        let verdict = if canonical == "accepted" { "accept" } else { "reject" };
        let reason = crate::ref_store::core::publication_decision::install::reject_code_of(canonical);
        tx.execute(
            "INSERT INTO ref_store_decision_refs(
                 decision_id,ref_ordinal,ref_name,verdict,reject_code,old_oid,new_oid,selection_verdict)
             VALUES($1,$2,$3,$4,$5,NULL,NULL,$6)",
            &[&decision_id, &ordinal, &name, &verdict, &reason, &canonical],
        )
        .await
        .map_err(sql_locks::sql_error)?;
    }
    let capability = DecisionCapability::mint(
        decision_id,
        request.repository_id(),
        tenant_id,
        authority.owner_id,
        actor.id,
        actor.token_id,
        operation_id,
        metadata_kind(request),
        PublicationAction::Push,
        request.object_format(),
        base_revision,
        not_after_millis,
        now,
        digests,
    );
    Ok(MetadataSelectedDecision { capability, selection_digest, accepted, verdict_rows: rows, captured })
}
