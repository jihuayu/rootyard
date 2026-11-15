//! Benchmark receipt schema, latency percentiles, and Linux RSS (`/proc/self/status` `VmHWM`) helpers.

use anyhow::Result;
use rootyard::ref_store::core::pack_commit::PackVerifier;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LatencyStats {
    pub count: usize,
    pub min_ms: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
    pub mean_ms: f64,
}

impl LatencyStats {
    pub fn from_micros(samples: &[u64]) -> Self {
        if samples.is_empty() {
            return Self { count: 0, min_ms: 0.0, p50_ms: 0.0, p95_ms: 0.0, p99_ms: 0.0, max_ms: 0.0, mean_ms: 0.0 };
        }
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        let sum: u128 = sorted.iter().map(|&v| v as u128).sum();
        let to_ms = |us: u64| us as f64 / 1000.0;
        let pct = |num: usize, den: usize| -> f64 {
            let idx = ((sorted.len() - 1) * num).div_ceil(den);
            to_ms(sorted[idx.min(sorted.len() - 1)])
        };
        Self {
            count: sorted.len(),
            min_ms: to_ms(sorted[0]),
            p50_ms: pct(50, 100),
            p95_ms: pct(95, 100),
            p99_ms: pct(99, 100),
            max_ms: to_ms(sorted[sorted.len() - 1]),
            mean_ms: (sum as f64 / sorted.len() as f64) / 1000.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CohortMeasurement {
    pub total_ops: usize,
    pub wall_ms: f64,
    pub throughput_ops_per_sec: f64,
    pub all_latency: LatencyStats,
    pub slow_latency: LatencyStats,
    pub fast_latency: LatencyStats,
    pub peak_active_ops: usize,
    pub download_queue_wait_micros: u64,
    pub native_queue_wait_micros: u64,
    pub view_queue_wait_micros: u64,
    pub blob_get_requests: u64,
    pub blob_get_bytes: u64,
    pub readback_bytes: u64,
    pub staging_reserved_bytes_peak: u64,
    pub staging_reclaimed_bytes_delta: u64,
    pub download_in_flight_peak: u64,
    pub native_in_flight_peak: u64,
    pub cohort_sampled_staging_bytes_peak: u64,
    pub cohort_sampled_download_in_flight_peak: u64,
    pub cohort_sampled_native_in_flight_peak: u64,
    pub s3_get_requests: u64,
    pub s3_get_bytes: u64,
    pub proc_vm_hwm_kib: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComparisonDeltas {
    pub wall_speedup: f64,
    pub fast_p95_ratio: f64,
    pub fast_p99_ratio: f64,
    pub native_wait_delta_micros: i64,
    pub download_wait_delta_micros: i64,
    pub reclaimed_bytes_after: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct EnvironmentInfo {
    pub os: &'static str,
    pub arch: &'static str,
    pub binary_path: String,
    pub blob_backend: &'static str,
    pub postgres_source: &'static str,
    pub git_version: String,
    pub source_commit: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BenchmarkReceipt {
    pub issue: &'static str,
    pub baseline_kind: &'static str,
    pub process_isolation: &'static str,
    pub rss_measurement: &'static str,
    pub peak_measurement: &'static str,
    pub workload: String,
    pub methodology: &'static str,
    pub limitations: Vec<String>,
    pub environment: EnvironmentInfo,
    pub before_coupled: CohortMeasurement,
    pub after_separated: CohortMeasurement,
    pub deltas: ComparisonDeltas,
}

pub fn verifier_metrics() -> serde_json::Value {
    PackVerifier::budget_metrics_json()
}

pub fn metric_u64(snapshot: &serde_json::Value, key: &str) -> u64 {
    snapshot.get(key).and_then(|v| v.as_u64()).unwrap_or(0)
}

pub fn metric_delta(after: &serde_json::Value, before: &serde_json::Value, key: &str) -> u64 {
    metric_u64(after, key).saturating_sub(metric_u64(before, key))
}

pub fn read_proc_vm_hwm_kib() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmHWM:") {
                let num = rest.split_whitespace().next()?;
                return num.parse::<u64>().ok();
            }
        }
        None
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

pub fn write_cohort_file(path: &Path, cohort: &CohortMeasurement) -> Result<()> {
    let json = serde_json::to_string_pretty(cohort)?;
    std::fs::write(path, format!("{json}\n"))?;
    Ok(())
}

pub fn read_cohort_file(path: &Path) -> Result<CohortMeasurement> {
    let raw = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&raw)?)
}

pub fn write_receipt(receipt: &BenchmarkReceipt) -> Result<PathBuf> {
    let dir = PathBuf::from("test-results");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("verifier-budget-bench.json");
    let json = serde_json::to_string_pretty(receipt)?;
    std::fs::write(&path, format!("{json}\n"))?;
    Ok(path)
}
