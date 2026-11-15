//! Deterministic state classification (`ready`, `waiting`, `denied`, `missing`,
//! `overloaded`) and structured HTTP response mapping for CI run checkouts.
use crate::Error;
use axum::{
    Json,
    http::{HeaderName, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct OriginBudgetStatus {
    pub global_active: i64,
    pub global_limit: i64,
    pub per_repo_active: i64,
    pub per_repo_limit: i64,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct MirrorNodeStatus {
    pub mirror_id: String,
    pub url: String,
    pub audience: Uuid,
    pub storage_generation: i64,
    pub active: bool,
    pub alive: bool,
    pub audience_matches: bool,
    pub capacity: i64,
    pub active_leases: i64,
    pub ready_oid_count: usize,
    pub target_ready: Option<bool>,
    pub heartbeat_unix: i64,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct AvailabilitySummary {
    pub ready_available_mirrors: usize,
    pub ready_total_mirrors: usize,
    pub healthy_unready_mirrors: usize,
    pub origin_budget: OriginBudgetStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckoutStateClass {
    Ready,
    Waiting,
    Denied,
    Missing,
    Overloaded,
}

impl CheckoutStateClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Waiting => "waiting",
            Self::Denied => "denied",
            Self::Missing => "missing",
            Self::Overloaded => "overloaded",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ClassificationInput {
    pub trusted_bound: bool,
    pub candidate_valid: bool,
    pub ready_available_mirrors: usize,
    pub ready_total_mirrors: usize,
    pub healthy_unready_mirrors: usize,
    pub origin_global_active: i64,
    pub origin_global_limit: i64,
    pub origin_per_repo_active: i64,
    pub origin_per_repo_limit: i64,
    pub allow_origin: bool,
    pub wait_requested: bool,
}

pub fn classify_checkout_state(input: ClassificationInput) -> CheckoutStateClass {
    if !input.trusted_bound {
        return CheckoutStateClass::Denied;
    }
    if !input.candidate_valid {
        return CheckoutStateClass::Missing;
    }
    if input.ready_available_mirrors > 0 {
        return CheckoutStateClass::Ready;
    }
    if !input.allow_origin {
        if input.healthy_unready_mirrors > 0 {
            return CheckoutStateClass::Waiting;
        }
        if input.ready_total_mirrors > 0 {
            return CheckoutStateClass::Overloaded;
        }
        return CheckoutStateClass::Missing;
    }
    let origin_enabled = input.origin_global_limit > 0 && input.origin_per_repo_limit > 0;
    if !origin_enabled {
        if input.healthy_unready_mirrors > 0 {
            return CheckoutStateClass::Waiting;
        }
        if input.ready_total_mirrors > 0 {
            return CheckoutStateClass::Overloaded;
        }
        return CheckoutStateClass::Missing;
    }
    let origin_available = input.origin_global_active < input.origin_global_limit
        && input.origin_per_repo_active < input.origin_per_repo_limit;
    if origin_available {
        return CheckoutStateClass::Ready;
    }
    if input.wait_requested && input.healthy_unready_mirrors > 0 {
        return CheckoutStateClass::Waiting;
    }
    CheckoutStateClass::Overloaded
}

pub fn classify_http_error(status: StatusCode, msg: &str) -> CheckoutStateClass {
    match status {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => CheckoutStateClass::Denied,
        StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE => {
            if msg.contains("no ready mirror") {
                CheckoutStateClass::Missing
            } else {
                CheckoutStateClass::Overloaded
            }
        }
        StatusCode::NOT_FOUND | StatusCode::CONFLICT => CheckoutStateClass::Missing,
        _ => CheckoutStateClass::Missing,
    }
}

pub fn classified_response(status: StatusCode, class: CheckoutStateClass, body: Value) -> Response {
    let mut resp = (status, [(header::CACHE_CONTROL, "no-store")], Json(body)).into_response();
    if let Ok(val) = HeaderValue::from_str(class.as_str()) {
        resp.headers_mut().insert(HeaderName::from_static("x-rootyard-ci-state"), val);
    }
    resp
}

pub fn classified_error(
    status: StatusCode,
    msg: &'static str,
    class: CheckoutStateClass,
    extra: Value,
) -> Response {
    let mut obj = match extra {
        Value::Object(map) => map,
        _ => serde_json::Map::new(),
    };
    obj.insert("error".into(), Value::String(msg.into()));
    obj.insert("classification".into(), Value::String(class.as_str().into()));
    classified_response(status, class, Value::Object(obj))
}

pub fn error_with_classification(err: Error) -> Response {
    let class = classify_http_error(err.0, err.1);
    let mut resp = err.into_response();
    if let Ok(val) = HeaderValue::from_str(class.as_str()) {
        resp.headers_mut().insert(HeaderName::from_static("x-rootyard-ci-state"), val);
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkout_state_classification_covers_all_required_states() {
        let base = ClassificationInput {
            trusted_bound: true,
            candidate_valid: true,
            ready_available_mirrors: 0,
            ready_total_mirrors: 0,
            healthy_unready_mirrors: 0,
            origin_global_active: 0,
            origin_global_limit: 4,
            origin_per_repo_active: 0,
            origin_per_repo_limit: 2,
            allow_origin: true,
            wait_requested: false,
        };
        assert_eq!(
            classify_checkout_state(ClassificationInput { trusted_bound: false, ..base }),
            CheckoutStateClass::Denied
        );
        assert_eq!(
            classify_checkout_state(ClassificationInput { candidate_valid: false, ..base }),
            CheckoutStateClass::Missing
        );
        assert_eq!(
            classify_checkout_state(ClassificationInput { ready_available_mirrors: 1, ..base }),
            CheckoutStateClass::Ready
        );
        assert_eq!(
            classify_checkout_state(ClassificationInput {
                healthy_unready_mirrors: 1,
                allow_origin: false,
                ..base
            }),
            CheckoutStateClass::Waiting
        );
        assert_eq!(
            classify_checkout_state(ClassificationInput { origin_per_repo_active: 2, ..base }),
            CheckoutStateClass::Overloaded
        );
        assert_eq!(
            classify_checkout_state(ClassificationInput {
                origin_per_repo_active: 2,
                healthy_unready_mirrors: 1,
                wait_requested: true,
                ..base
            }),
            CheckoutStateClass::Waiting
        );
        assert_eq!(
            classify_checkout_state(ClassificationInput { allow_origin: false, ..base }),
            CheckoutStateClass::Missing
        );
    }
}
