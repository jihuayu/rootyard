//! Frozen schema contracts for each backup format.
use anyhow::{Result, bail};
use sha2::{Digest, Sha256};

/// New archives use format 19 / schema 143. Formats 4-18 stay frozen so older
/// archives remain verifiable and restorable through their explicit legacy
/// upgrade paths (schema007, schema130, schema131, schema132, schema133,
/// schema134, schema135, schema136, schema137, schema138, schema139, schema140,
/// schema141 and schema142). Format15 is exactly schema139, format16 is exactly
/// schema140, format17 is exactly schema141, format18 is exactly schema142 and
/// format19 consumes exactly the migration set embedded in this executable
/// (schema143). Their canonical schema/139_* through schema/143_* catalogs are
/// generated from real PostgreSQL by the root runner; this module references
/// those fixtures but deliberately does not fabricate a schema143 catalog.
pub(super) const FORMAT: u32 = 19;

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
        19 => Ok(crate::db::SCHEMA_VERSIONS.to_vec()),
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
