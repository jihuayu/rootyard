use super::delta::{ObjectType, PackReport};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedCommit {
    pub tree: String,
    pub parents: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TreeEntryKind {
    Tree,
    Blob,
    Gitlink,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeEntry {
    pub mode: String,
    pub name: String,
    pub oid: String,
    pub kind: TreeEntryKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedTag {
    pub target_oid: String,
    pub target_type: ObjectType,
    pub tag_name: String,
}

#[derive(Debug, Default, Clone)]
pub struct ObjectStore {
    pub objects: BTreeMap<String, (ObjectType, Vec<u8>)>,
}

impl ObjectStore {
    pub fn insert_pack(&mut self, report: &PackReport) {
        for obj in &report.objects {
            self.objects
                .insert(obj.oid.clone(), (obj.obj_type, obj.data.clone()));
        }
    }

    pub fn insert_object(&mut self, oid: String, obj_type: ObjectType, data: Vec<u8>) {
        self.objects.insert(oid, (obj_type, data));
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphWalkReport {
    pub wants: Vec<String>,
    pub haves: Vec<String>,
    pub reachable_count: usize,
    pub excluded_count: usize,
    pub commits: usize,
    pub trees: usize,
    pub blobs: usize,
    pub tags: usize,
    pub reachable_oids: Vec<String>,
}

pub fn is_valid_oid(oid: &str) -> bool {
    (oid.len() == 40 || oid.len() == 64)
        && oid
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn parse_commit(data: &[u8]) -> Result<ParsedCommit> {
    let header_end = data
        .windows(2)
        .position(|w| w == b"\n\n")
        .unwrap_or(data.len());
    let header = std::str::from_utf8(&data[..header_end]).context("invalid UTF-8 commit header")?;
    let mut tree = None;
    let mut parents = Vec::new();
    for line in header.lines() {
        if let Some(rest) = line.strip_prefix("tree ") {
            ensure!(tree.is_none(), "commit contains multiple tree headers");
            ensure!(is_valid_oid(rest), "invalid tree OID in commit: {rest}");
            tree = Some(rest.to_owned());
        } else if let Some(rest) = line.strip_prefix("parent ") {
            ensure!(is_valid_oid(rest), "invalid parent OID in commit: {rest}");
            parents.push(rest.to_owned());
        }
    }
    Ok(ParsedCommit {
        tree: tree.context("commit missing tree header")?,
        parents,
    })
}

pub fn parse_tree_with_raw_oid_len(data: &[u8], raw_oid_len: usize) -> Result<Vec<TreeEntry>> {
    ensure!(
        raw_oid_len == 20 || raw_oid_len == 32,
        "unsupported raw tree OID length {raw_oid_len}"
    );
    let mut pos = 0usize;
    let mut entries = Vec::new();
    while pos < data.len() {
        let space_rel = data[pos..]
            .iter()
            .position(|&b| b == b' ')
            .context("malformed tree entry: missing mode separator space")?;
        let space_idx = pos + space_rel;
        let mode = std::str::from_utf8(&data[pos..space_idx]).context("invalid tree entry mode")?;
        let kind = match mode {
            "40000" | "040000" => TreeEntryKind::Tree,
            "100644" | "100755" | "120000" => TreeEntryKind::Blob,
            "160000" => TreeEntryKind::Gitlink,
            other => bail!("unsupported tree entry mode {other}"),
        };
        let name_start = space_idx + 1;
        let nul_rel = data[name_start..]
            .iter()
            .position(|&b| b == 0)
            .context("malformed tree entry: missing NUL after name")?;
        let nul_idx = name_start + nul_rel;
        let name_bytes = &data[name_start..nul_idx];
        ensure!(
            !name_bytes.is_empty()
                && !name_bytes.contains(&b'/')
                && name_bytes != b"."
                && name_bytes != b"..",
            "invalid tree entry filename"
        );
        let name = String::from_utf8_lossy(name_bytes).into_owned();
        let oid_end = nul_idx + 1 + raw_oid_len;
        ensure!(
            oid_end <= data.len(),
            "truncated {raw_oid_len}-byte OID in tree entry {name}"
        );
        let oid = hex::encode(&data[nul_idx + 1..oid_end]);
        entries.push(TreeEntry {
            mode: mode.to_owned(),
            name,
            oid,
            kind,
        });
        pos = oid_end;
    }
    Ok(entries)
}

pub fn parse_tree(data: &[u8]) -> Result<Vec<TreeEntry>> {
    parse_tree_with_raw_oid_len(data, 20)
}

pub fn parse_tag(data: &[u8]) -> Result<ParsedTag> {
    let header_end = data
        .windows(2)
        .position(|w| w == b"\n\n")
        .unwrap_or(data.len());
    let header = std::str::from_utf8(&data[..header_end]).context("invalid UTF-8 tag header")?;
    let mut target_oid = None;
    let mut target_type = None;
    let mut tag_name = String::new();
    for line in header.lines() {
        if let Some(rest) = line.strip_prefix("object ") {
            ensure!(is_valid_oid(rest), "invalid target OID in tag: {rest}");
            target_oid = Some(rest.to_owned());
        } else if let Some(rest) = line.strip_prefix("type ") {
            target_type = Some(match rest {
                "commit" => ObjectType::Commit,
                "tree" => ObjectType::Tree,
                "blob" => ObjectType::Blob,
                "tag" => ObjectType::Tag,
                other => bail!("unsupported tag target type {other}"),
            });
        } else if let Some(rest) = line.strip_prefix("tag ") {
            tag_name = rest.to_owned();
        }
    }
    Ok(ParsedTag {
        target_oid: target_oid.context("tag missing object header")?,
        target_type: target_type.context("tag missing type header")?,
        tag_name,
    })
}

/// Computes the reachable object closure starting from `wants` while excluding all objects
/// reachable from `haves`.
pub fn walk_reachable(
    store: &ObjectStore,
    wants: &[String],
    haves: &[String],
) -> Result<GraphWalkReport> {
    for oid in wants.iter().chain(haves.iter()) {
        ensure!(is_valid_oid(oid), "invalid OID in graph walk: {oid}");
    }

    // Phase 1: Compute exclusion closure from `haves`.
    let mut excluded = BTreeSet::new();
    let mut have_queue: VecDeque<String> = haves.iter().cloned().collect();
    while let Some(oid) = have_queue.pop_front() {
        if !excluded.insert(oid.clone()) {
            continue;
        }
        let Some((obj_type, data)) = store.objects.get(&oid) else {
            continue;
        };
        let raw_oid_len = if oid.len() == 64 { 32 } else { 20 };
        match obj_type {
            ObjectType::Tag => {
                let tag = parse_tag(data)?;
                have_queue.push_back(tag.target_oid);
            }
            ObjectType::Commit => {
                let commit = parse_commit(data)?;
                have_queue.push_back(commit.tree);
                for parent in commit.parents {
                    have_queue.push_back(parent);
                }
            }
            ObjectType::Tree => {
                for entry in parse_tree_with_raw_oid_len(data, raw_oid_len)? {
                    if entry.kind != TreeEntryKind::Gitlink {
                        have_queue.push_back(entry.oid);
                    }
                }
            }
            ObjectType::Blob => {}
        }
    }

    // Phase 2: Traverse `wants` closure minus `excluded`.
    let mut visited: BTreeMap<String, ObjectType> = BTreeMap::new();
    let mut want_queue: VecDeque<(String, Option<ObjectType>)> =
        wants.iter().map(|w| (w.clone(), None)).collect();

    while let Some((oid, expected_type)) = want_queue.pop_front() {
        if excluded.contains(&oid) {
            continue;
        }
        let (obj_type, data) = store
            .objects
            .get(&oid)
            .with_context(|| format!("missing reachable object {oid}"))?;
        if let Some(expected) = expected_type {
            ensure!(
                *obj_type == expected,
                "object {oid} type mismatch: expected {}, got {}",
                expected.as_str(),
                obj_type.as_str()
            );
        }
        if visited.contains_key(&oid) {
            continue;
        }
        visited.insert(oid.clone(), *obj_type);
        let raw_oid_len = if oid.len() == 64 { 32 } else { 20 };

        match obj_type {
            ObjectType::Tag => {
                let tag = parse_tag(data)?;
                want_queue.push_back((tag.target_oid, Some(tag.target_type)));
            }
            ObjectType::Commit => {
                let commit = parse_commit(data)?;
                want_queue.push_back((commit.tree, Some(ObjectType::Tree)));
                for parent in commit.parents {
                    want_queue.push_back((parent, Some(ObjectType::Commit)));
                }
            }
            ObjectType::Tree => {
                for entry in parse_tree_with_raw_oid_len(data, raw_oid_len)? {
                    match entry.kind {
                        TreeEntryKind::Tree => {
                            want_queue.push_back((entry.oid, Some(ObjectType::Tree)));
                        }
                        TreeEntryKind::Blob => {
                            want_queue.push_back((entry.oid, Some(ObjectType::Blob)));
                        }
                        TreeEntryKind::Gitlink => {}
                    }
                }
            }
            ObjectType::Blob => {}
        }
    }

    let mut commits = 0usize;
    let mut trees = 0usize;
    let mut blobs = 0usize;
    let mut tags = 0usize;
    let mut reachable_oids = Vec::with_capacity(visited.len());
    for (oid, kind) in visited {
        match kind {
            ObjectType::Commit => commits += 1,
            ObjectType::Tree => trees += 1,
            ObjectType::Blob => blobs += 1,
            ObjectType::Tag => tags += 1,
        }
        reachable_oids.push(oid);
    }

    Ok(GraphWalkReport {
        wants: wants.to_vec(),
        haves: haves.to_vec(),
        reachable_count: reachable_oids.len(),
        excluded_count: excluded.len(),
        commits,
        trees,
        blobs,
        tags,
        reachable_oids,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pando_lab::delta::git_object_oid;

    fn make_tree_bytes(entries: &[(&str, &str, &str)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (mode, name, oid) in entries {
            out.extend_from_slice(mode.as_bytes());
            out.push(b' ');
            out.extend_from_slice(name.as_bytes());
            out.push(0);
            out.extend_from_slice(&hex::decode(oid).unwrap());
        }
        out
    }

    #[test]
    fn commit_tree_tag_walk_with_have_exclusions() {
        let mut store = ObjectStore::default();

        let blob1 = b"base file\n".to_vec();
        let blob1_oid = git_object_oid(ObjectType::Blob, &blob1);
        store.insert_object(blob1_oid.clone(), ObjectType::Blob, blob1);

        let tree1 = make_tree_bytes(&[("100644", "file.txt", &blob1_oid)]);
        let tree1_oid = git_object_oid(ObjectType::Tree, &tree1);
        store.insert_object(tree1_oid.clone(), ObjectType::Tree, tree1);

        let commit1 = format!(
            "tree {tree1_oid}\nauthor A <a@b.c> 1 +0000\ncommitter A <a@b.c> 1 +0000\n\nc1\n"
        )
        .into_bytes();
        let commit1_oid = git_object_oid(ObjectType::Commit, &commit1);
        store.insert_object(commit1_oid.clone(), ObjectType::Commit, commit1);

        let blob2 = b"second file\n".to_vec();
        let blob2_oid = git_object_oid(ObjectType::Blob, &blob2);
        store.insert_object(blob2_oid.clone(), ObjectType::Blob, blob2);

        let sub_oid = "1111111111111111111111111111111111111111";
        let tree2 = make_tree_bytes(&[
            ("100644", "file.txt", &blob1_oid),
            ("100755", "run.sh", &blob2_oid),
            ("160000", "submodule", sub_oid),
        ]);
        let tree2_oid = git_object_oid(ObjectType::Tree, &tree2);
        store.insert_object(tree2_oid.clone(), ObjectType::Tree, tree2);

        let commit2 = format!(
            "tree {tree2_oid}\nparent {commit1_oid}\nauthor A <a@b.c> 2 +0000\ncommitter A <a@b.c> 2 +0000\n\nc2\n"
        )
        .into_bytes();
        let commit2_oid = git_object_oid(ObjectType::Commit, &commit2);
        store.insert_object(commit2_oid.clone(), ObjectType::Commit, commit2);

        let tag_data = format!(
            "object {commit2_oid}\ntype commit\ntag v1\ntagger A <a@b.c> 3 +0000\n\ntag v1\n"
        )
        .into_bytes();
        let tag_oid = git_object_oid(ObjectType::Tag, &tag_data);
        store.insert_object(tag_oid.clone(), ObjectType::Tag, tag_data);

        // Full walk from tag
        let full = walk_reachable(&store, std::slice::from_ref(&tag_oid), &[]).unwrap();
        assert_eq!(full.tags, 1);
        assert_eq!(full.commits, 2);
        assert_eq!(full.trees, 2);
        assert_eq!(full.blobs, 2);
        assert_eq!(full.reachable_count, 7);

        // Incremental walk excluding commit1
        let inc = walk_reachable(
            &store,
            std::slice::from_ref(&commit2_oid),
            std::slice::from_ref(&commit1_oid),
        )
        .unwrap();
        assert_eq!(inc.commits, 1);
        assert_eq!(inc.trees, 1);
        assert_eq!(inc.blobs, 1);
        assert_eq!(inc.reachable_count, 3);
        assert!(inc.reachable_oids.contains(&commit2_oid));
        assert!(inc.reachable_oids.contains(&tree2_oid));
        assert!(inc.reachable_oids.contains(&blob2_oid));
        assert!(!inc.reachable_oids.contains(&blob1_oid));
    }
}
