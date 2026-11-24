//! Frozen schema contracts for each backup format.
use anyhow::{Result, bail};
use sha2::{Digest, Sha256};

/// Current metadata archives use schema 152, including public attempt history.
pub(super) const FORMAT: u32 = 31;

/// Paired PG + OpenDAL Blob closure archive (#120). The schema does not change:
/// format tags the archive layout, not the frozen PostgreSQL catalog, so every
/// same-schema archive maps unchanged to the same reviewed catalog/versions.
pub(super) const FORMAT_PAIRED: u32 = 32;

pub(super) fn is_paired(format: u32) -> bool {
    matches!(format, 28 | 30 | FORMAT_PAIRED)
}

pub(super) fn has_public_attempts(format: u32) -> bool {
    matches!(format, 31 | 32)
}

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
        23 | 24 => [
            include_str!("../../schema/148_catalog.json"),
            include_str!("../../schema/148_restored_catalog.json"),
            include_str!("../../schema/148_upgraded_catalog.json"),
        ],
        25 | 26 => [
            include_str!("../../schema/149_catalog.json"),
            include_str!("../../schema/149_restored_catalog.json"),
            include_str!("../../schema/149_upgraded_catalog.json"),
        ],
        27 | 28 => [
            include_str!("../../schema/150_catalog.json"),
            include_str!("../../schema/150_restored_catalog.json"),
            include_str!("../../schema/150_upgraded_catalog.json"),
        ],
        29 | 30 => [
            include_str!("../../schema/151_catalog.json"),
            include_str!("../../schema/151_restored_catalog.json"),
            include_str!("../../schema/151_upgraded_catalog.json"),
        ],
        31 | 32 => [
            include_str!("../../schema/152_catalog.json"),
            include_str!("../../schema/152_restored_catalog.json"),
            include_str!("../../schema/152_upgraded_catalog.json"),
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
        21 | 22 => Ok(crate::db::SCHEMA_VERSIONS.iter().copied().filter(|version| *version <= 147).collect()),
        23 | 24 => Ok(crate::db::SCHEMA_VERSIONS.iter().copied().filter(|version| *version <= 148).collect()),
        25 | 26 => Ok(crate::db::SCHEMA_VERSIONS.iter().copied().filter(|version| *version <= 149).collect()),
        27 | 28 => Ok(crate::db::SCHEMA_VERSIONS.iter().copied().filter(|version| *version <= 150).collect()),
        29 | 30 => Ok(crate::db::SCHEMA_VERSIONS.iter().copied().filter(|version| *version <= 151).collect()),
        31 | 32 => Ok(crate::db::SCHEMA_VERSIONS.iter().copied().filter(|version| *version <= 152).collect()),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_29_and_30_keep_the_schema_151_prefix() -> Result<()> {
        let frozen = crate::db::SCHEMA_VERSIONS.iter().copied().filter(|version| *version <= 151).collect::<Vec<_>>();
        assert_eq!(frozen.last(), Some(&151));
        assert_eq!(versions(29)?, frozen);
        assert_eq!(versions(30)?, frozen);
        assert_eq!(versions(29)?, versions(30)?);
        Ok(())
    }
}
