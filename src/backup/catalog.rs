//! Frozen schema contracts for each backup format.
use anyhow::{Result, bail};
use sha2::{Digest, Sha256};

pub(super) const FORMAT: u32 = 6;

pub(super) fn catalogs(format: u32) -> Result<[serde_json::Value; 3]> {
    let raw = match format {
        4 => [
            include_str!("../../schema/007_catalog.json"),
            include_str!("../../schema/007_restored_catalog.json"),
            include_str!("../../schema/007_upgraded_catalog.json"),
        ],
        5 => [
            include_str!("../../schema/060_catalog.json"),
            include_str!("../../schema/060_restored_catalog.json"),
            include_str!("../../schema/060_upgraded_catalog.json"),
        ],
        6 => [
            include_str!("../../schema/126_catalog.json"),
            include_str!("../../schema/126_restored_catalog.json"),
            include_str!("../../schema/126_upgraded_catalog.json"),
        ],
        _ => bail!("unsupported backup format"),
    };
    Ok([serde_json::from_str(raw[0])?, serde_json::from_str(raw[1])?, serde_json::from_str(raw[2])?])
}

pub(super) fn versions(format: u32) -> Result<Vec<i32>> {
    match format {
        4 => Ok(vec![1, 2, 3, 6, 7]),
        5 => Ok(vec![1, 2, 3, 6, 7, 8, 9, 20, 30, 40, 50, 60]),
        6 => Ok(crate::db::SCHEMA_VERSIONS.to_vec()),
        _ => bail!("unsupported backup format"),
    }
}

pub(super) fn digest(format: u32) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&catalogs(format)?)?)))
}

pub(super) fn relations(format: u32, only_tables: bool) -> Result<Vec<String>> {
    let catalog = catalogs(format)?;
    let tables = catalog[0]["tables"].as_array().ok_or_else(|| anyhow::anyhow!("invalid catalog tables"))?;
    let mut names = Vec::new();
    for entry in tables {
        if !only_tables || entry["kind"] == "r" {
            names.push(entry["name"].as_str().ok_or_else(|| anyhow::anyhow!("invalid catalog relation"))?.to_owned());
        }
    }
    names.sort();
    Ok(names)
}
