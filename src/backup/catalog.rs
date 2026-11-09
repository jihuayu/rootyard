//! Frozen schema contracts for each backup format.
use anyhow::{Result, bail};
use sha2::{Digest, Sha256};

/// Current archives use format 21 / schema 147 (Blob-only serving bindings
/// and bounded transient serving-read leases). Prior format catalogs remain
/// frozen; format 20 is exactly schema 144. The new schema catalogs were
/// generated from real PostgreSQL, never copied from a previous schema.
pub(super) const FORMAT: u32 = 21;

/// Paired PG + OpenDAL Blob closure archive (#120). The schema does not change:
/// format tags the archive layout, not the frozen PostgreSQL catalog, so every
/// same-schema archive maps unchanged to the same reviewed catalog/versions.
pub(super) const FORMAT_PAIRED: u32 = 22;

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
            include_str!("../../schema/130_catalog.json"),
            include_str!("../../schema/130_restored_catalog.json"),
            include_str!("../../schema/130_upgraded_catalog.json"),
        ],
        7 => [
            include_str!("../../schema/131_catalog.json"),
            include_str!("../../schema/131_restored_catalog.json"),
            include_str!("../../schema/131_upgraded_catalog.json"),
        ],
        8 => [
            include_str!("../../schema/132_catalog.json"),
            include_str!("../../schema/132_restored_catalog.json"),
            include_str!("../../schema/132_upgraded_catalog.json"),
        ],
        9 => [
            include_str!("../../schema/133_catalog.json"),
            include_str!("../../schema/133_restored_catalog.json"),
            include_str!("../../schema/133_upgraded_catalog.json"),
        ],
        10 => [
            include_str!("../../schema/134_catalog.json"),
            include_str!("../../schema/134_restored_catalog.json"),
            include_str!("../../schema/134_upgraded_catalog.json"),
        ],
        11 => [
            include_str!("../../schema/135_catalog.json"),
            include_str!("../../schema/135_restored_catalog.json"),
            include_str!("../../schema/135_upgraded_catalog.json"),
        ],
        12 => [
            include_str!("../../schema/136_catalog.json"),
            include_str!("../../schema/136_restored_catalog.json"),
            include_str!("../../schema/136_upgraded_catalog.json"),
        ],
        13 => [
            include_str!("../../schema/137_catalog.json"),
            include_str!("../../schema/137_restored_catalog.json"),
            include_str!("../../schema/137_upgraded_catalog.json"),
        ],
        14 => [
            include_str!("../../schema/138_catalog.json"),
            include_str!("../../schema/138_restored_catalog.json"),
            include_str!("../../schema/138_upgraded_catalog.json"),
        ],
        15 => [
            include_str!("../../schema/139_catalog.json"),
            include_str!("../../schema/139_restored_catalog.json"),
            include_str!("../../schema/139_upgraded_catalog.json"),
        ],
        16 => [
            include_str!("../../schema/140_catalog.json"),
            include_str!("../../schema/140_restored_catalog.json"),
            include_str!("../../schema/140_upgraded_catalog.json"),
        ],
        17 => [
            include_str!("../../schema/141_catalog.json"),
            include_str!("../../schema/141_restored_catalog.json"),
            include_str!("../../schema/141_upgraded_catalog.json"),
        ],
        18 => [
            include_str!("../../schema/142_catalog.json"),
            include_str!("../../schema/142_restored_catalog.json"),
            include_str!("../../schema/142_upgraded_catalog.json"),
        ],
        19 => [
            include_str!("../../schema/143_catalog.json"),
            include_str!("../../schema/143_restored_catalog.json"),
            include_str!("../../schema/143_upgraded_catalog.json"),
        ],
        20 => [
            include_str!("../../schema/144_catalog.json"),
            include_str!("../../schema/144_restored_catalog.json"),
            include_str!("../../schema/144_upgraded_catalog.json"),
        ],
        21 | 22 => [
            include_str!("../../schema/147_catalog.json"),
            include_str!("../../schema/147_restored_catalog.json"),
            include_str!("../../schema/147_upgraded_catalog.json"),
        ],
        _ => bail!("unsupported backup format"),
    };
    Ok([serde_json::from_str(raw[0])?, serde_json::from_str(raw[1])?, serde_json::from_str(raw[2])?])
}

pub(super) fn versions(format: u32) -> Result<Vec<i32>> {
    match format {
        4 => Ok(vec![1, 2, 3, 6, 7]),
        5 => Ok(vec![1, 2, 3, 6, 7, 8, 9, 20, 30, 40, 50, 60]),
        6 => Ok(crate::db::SCHEMA_VERSIONS.iter().copied().filter(|version| *version <= 130).collect()),
        7 => Ok(crate::db::SCHEMA_VERSIONS.iter().copied().filter(|version| *version <= 131).collect()),
        8 => Ok(crate::db::SCHEMA_VERSIONS.iter().copied().filter(|version| *version <= 132).collect()),
        9 => Ok(crate::db::SCHEMA_VERSIONS.iter().copied().filter(|version| *version <= 133).collect()),
        10 => Ok(crate::db::SCHEMA_VERSIONS.iter().copied().filter(|version| *version <= 134).collect()),
        11 => Ok(crate::db::SCHEMA_VERSIONS.iter().copied().filter(|version| *version <= 135).collect()),
        12 => Ok(crate::db::SCHEMA_VERSIONS.iter().copied().filter(|version| *version <= 136).collect()),
        13 => Ok(crate::db::SCHEMA_VERSIONS.iter().copied().filter(|version| *version <= 137).collect()),
        14 => Ok(crate::db::SCHEMA_VERSIONS.iter().copied().filter(|version| *version <= 138).collect()),
        15 => Ok(crate::db::SCHEMA_VERSIONS.iter().copied().filter(|version| *version <= 139).collect()),
        16 => Ok(crate::db::SCHEMA_VERSIONS.iter().copied().filter(|version| *version <= 140).collect()),
        17 => Ok(crate::db::SCHEMA_VERSIONS.iter().copied().filter(|version| *version <= 141).collect()),
        18 => Ok(crate::db::SCHEMA_VERSIONS.iter().copied().filter(|version| *version <= 142).collect()),
        19 => Ok(crate::db::SCHEMA_VERSIONS.iter().copied().filter(|version| *version <= 143).collect()),
        20 => Ok(crate::db::SCHEMA_VERSIONS.iter().copied().filter(|version| *version <= 144).collect()),
        21 | 22 => Ok(crate::db::SCHEMA_VERSIONS.to_vec()),
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
