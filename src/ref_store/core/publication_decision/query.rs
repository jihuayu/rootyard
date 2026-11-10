//! Historical, data-only decision reads.
//!
//! These functions never re-authorize, never replay authority, never refund quota and never change
//! state. Only the exact canonical selection rows of a committed decision are read: the install path
//! compares them with the freshly sealed projection (exact replay) and the replay path reconstructs
//! the sealed policy input from them. There is no second lookup/verdict/cancellation reader here; an
//! unknown operation stays unknown for the caller instead of being materialized into a record type.
use super::contract::DecisionError;
use super::sql_locks;
use tokio_postgres::Transaction;
use uuid::Uuid;

/// Exact canonical selection rows persisted for this decision, ordered by ref name. New rows carry
/// `selection_verdict`; historical rows without it are reconstructed from verdict/reject_code.
pub(super) async fn load_selection_rows(
    tx: &Transaction<'_>,
    decision_id: Uuid,
) -> Result<Vec<(String, String)>, DecisionError> {
    let rows = tx
        .query(
            "SELECT ref_name,verdict,reject_code,selection_verdict
             FROM ref_store_decision_refs WHERE decision_id=$1 ORDER BY ref_ordinal",
            &[&decision_id],
        )
        .await
        .map_err(sql_locks::sql_error)?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let name: String = row.get(0);
        let verdict: String = row.get(1);
        let selection: Option<String> = row.get(3);
        let canonical = match selection {
            Some(value) => value,
            None => match (verdict.as_str(), row.get::<_, Option<String>>(2)) {
                ("accept", _) => "accepted".to_owned(),
                ("reject", Some(code)) => format!("rejected:policy:{code}"),
                _ => return Err(DecisionError::Ledger("stored ref verdict is not canonical")),
            },
        };
        out.push((name, canonical));
    }
    Ok(out)
}
