use super::*;
use std::io::{Read, Write};

#[derive(Clone, Serialize)]
struct RefCommand {
    old: String,
    new: String,
    name: String,
}

fn block(input: &mut impl Read) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    loop {
        let mut head = [0; 4];
        input.read_exact(&mut head)?;
        let n = usize::from_str_radix(std::str::from_utf8(&head)?, 16)?;
        if n == 0 {
            return Ok(out);
        }
        ensure!((4..=65520).contains(&n), "invalid hook packet");
        let mut body = vec![0; n - 4];
        input.read_exact(&mut body)?;
        out.push(body);
        ensure!(out.len() <= 256, "lab ref command limit");
    }
}
fn packet(out: &mut impl Write, s: &str) -> Result<()> {
    write!(out, "{:04x}{}", s.len() + 4, s)?;
    Ok(())
}
fn flush(out: &mut impl Write) -> Result<()> {
    out.write_all(b"0000")?;
    out.flush()?;
    Ok(())
}
fn oid(s: &str) -> bool {
    s.len() == 40
        && s.bytes()
            .all(|x| x.is_ascii_digit() || (b'a'..=b'f').contains(&x))
}

fn parse_command(s: &str) -> Result<RefCommand> {
    let parts: Vec<_> = s.split(' ').collect();
    ensure!(
        parts.len() == 3 && oid(parts[0]) && oid(parts[1]),
        "bad hook command"
    );
    Ok(RefCommand {
        old: parts[0].to_owned(),
        new: parts[1].to_owned(),
        name: parts[2].to_owned(),
    })
}

/// Native Git can remove failed commands before invoking proc-receive, even
/// during an atomic push. pre-receive is called with skip_broken=0 and therefore
/// provides the complete command group that we must publish all-or-nothing.
pub(super) async fn pre_receive(config: &Config) -> Result<()> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 1024 * 1024 && bytes.last() == Some(&b'\n'),
        "invalid or oversized pre-receive group"
    );
    let commands: Vec<RefCommand> = std::str::from_utf8(&bytes)?
        .split_terminator('\n')
        .map(parse_command)
        .collect::<Result<_>>()?;
    ensure!(
        !commands.is_empty() && commands.len() <= 256,
        "lab ref command limit"
    );
    let op: Uuid = std::env::var("PANDO_OPERATION")?.parse()?;
    let repo: Uuid = std::env::var("PANDO_REPO")?.parse()?;
    let principal = std::env::var("PANDO_PRINCIPAL")?;
    let c = config.db().await?;
    let repo_row = c
        .query_one(
            "SELECT write_paused, storage_backend FROM pando_lab.repositories WHERE id=$1",
            &[&repo],
        )
        .await?;
    ensure!(
        !repo_row.get::<_, bool>(0) && repo_row.get::<_, String>(1) == "pando",
        "repository writes paused or storage backend is not pando"
    );
    let n=c.execute("UPDATE pando_lab.operations SET state='PREPARED',commands=$4 WHERE id=$1 AND repo=$2 AND principal=$3 AND state='RECEIVING'",&[&op,&repo,&principal,&serde_json::to_value(&commands)?]).await?;
    ensure!(
        n == 1,
        "operation must belong to the complete pre-receive group"
    );
    Ok(())
}

pub(super) async fn run(config: &Config) -> Result<()> {
    let mut input = std::io::stdin().lock();
    let mut out = std::io::stdout().lock();
    let hello = block(&mut input)?;
    let atomic = hello.iter().any(|s| s.windows(6).any(|v| v == b"atomic"));
    packet(
        &mut out,
        if atomic {
            "version=1\0atomic"
        } else {
            "version=1"
        },
    )?;
    flush(&mut out)?;
    let mut commands = Vec::new();
    for raw in block(&mut input)? {
        let s = std::str::from_utf8(&raw)?.trim_end_matches('\n');
        commands.push(parse_command(s)?);
    }
    ensure!(!commands.is_empty(), "empty command group");
    let op: Uuid = std::env::var("PANDO_OPERATION")?.parse()?;
    match publish(config, op, &commands).await {
        Ok(()) => {
            for c in &commands {
                packet(&mut out, &format!("ok {}", c.name))?;
            }
        }
        Err(error) => {
            eprintln!("pando lab hook rejected: {error:#}");
            if let Ok(c) = config.db().await {
                // Never overwrite COMMITTED after a lost commit acknowledgment.
                let _=c.execute("UPDATE pando_lab.operations SET state='REJECTED',result=$2 WHERE id=$1 AND state<>'COMMITTED'",&[&op,&serde_json::json!({"error":error.to_string()})]).await;
            }
            for c in &commands {
                packet(
                    &mut out,
                    &format!("ng {} pando-validation-or-CAS-rejected", c.name),
                )?;
            }
        }
    }
    flush(&mut out)
}

async fn publish(config: &Config, op: Uuid, commands: &[RefCommand]) -> Result<()> {
    let repo: Uuid = std::env::var("PANDO_REPO")?.parse()?;
    let principal = std::env::var("PANDO_PRINCIPAL")?;
    let storage_generation: i64 = std::env::var("PANDO_STORAGE_GENERATION")?.parse()?;
    let ctl = control(config)?;
    let git_dir = std::env::current_dir()?;
    let value = serde_json::to_value(commands)?;
    let mut c = config.db().await?;
    // Do not overwrite the complete pre-receive command group with Git's filtered
    // proc-receive subset. Matching JSON arrays checks old/new/name and ordering.
    let n=c.execute("UPDATE pando_lab.operations SET state='PREPARING' WHERE id=$1 AND repo=$2 AND principal=$3 AND state='PREPARED' AND commands=$4",&[&op,&repo,&principal,&value]).await?;
    ensure!(
        n == 1,
        "proc-receive group differs from complete pre-receive group"
    );
    let mut names = std::collections::BTreeSet::new();
    for cmd in commands {
        ensure!(names.insert(&cmd.name), "duplicate ref command");
        ensure!(
            cmd.name.starts_with("refs/heads/") || cmd.name.starts_with("refs/tags/"),
            "unsupported ref namespace"
        );
        config
            .git(&git_dir, &["check-ref-format", &cmd.name], b"")
            .await?;
        if cmd.new != ZERO && cmd.name.starts_with("refs/heads/") {
            ensure!(
                config
                    .git(&git_dir, &["cat-file", "-t", &cmd.new], b"")
                    .await?
                    == b"commit\n",
                "branch target must be commit"
            );
            if cmd.old != ZERO {
                config
                    .git(
                        &git_dir,
                        &["merge-base", "--is-ancestor", &cmd.old, &cmd.new],
                        b"",
                    )
                    .await?;
            }
        }
    }
    let roots: Vec<_> = commands
        .iter()
        .filter(|c| c.new != ZERO)
        .map(|c| c.new.clone())
        .collect();
    if !roots.is_empty() {
        let mut args = vec!["fsck", "--full", "--strict", "--no-reflogs"];
        args.extend(roots.iter().map(String::as_str));
        config.git(&git_dir, &args, b"").await?;
    }
    if ctl.fault == "before-objects" {
        std::process::exit(71);
    }
    let pack = store::publish_pack(config, repo, op, &git_dir, &roots).await?;
    c.execute(
        "UPDATE pando_lab.operations SET state='OBJECTS_DURABLE' WHERE id=$1",
        &[&op],
    )
    .await?;
    if ctl.fault == "after-objects" {
        std::process::exit(72);
    }
    if let Some(dir) = ctl.barrier {
        ensure!(dir.is_absolute(), "barrier path must be absolute");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join(format!("{op}.ready")), b"")?;
        let start = std::time::Instant::now();
        while !dir.join("release").exists() {
            ensure!(start.elapsed().as_secs() < 30, "barrier timeout");
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
    let t = c.transaction().await?;
    let row = t
        .query_one(
            "SELECT generation,storage_generation,write_paused,storage_backend FROM pando_lab.repositories WHERE id=$1 FOR UPDATE",
            &[&repo],
        )
        .await?;
    let generation: i64 = row.get(0);
    ensure!(
        row.get::<_, i64>(1) == storage_generation,
        "stale storage generation"
    );
    ensure!(!row.get::<_, bool>(2), "repository writes paused");
    ensure!(
        row.get::<_, String>(3) == "pando",
        "repository storage backend is not pando"
    );
    let acl = t
        .query_opt(
            "SELECT write_allowed FROM pando_lab.acl WHERE repo=$1 AND principal=$2 FOR SHARE",
            &[&repo, &principal],
        )
        .await?;
    ensure!(
        acl.is_some_and(|r| r.get::<_, bool>(0)),
        "write access revoked"
    );
    let mut refs: BTreeMap<String, String> = t
        .query(
            "SELECT name,oid FROM pando_lab.refs WHERE repo=$1",
            &[&repo],
        )
        .await?
        .into_iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    for cmd in commands {
        ensure!(
            refs.get(&cmd.name).map(String::as_str).unwrap_or(ZERO) == cmd.old,
            "compare-and-swap conflict"
        );
        if cmd.new == ZERO {
            refs.remove(&cmd.name);
        } else {
            refs.insert(cmd.name.clone(), cmd.new.clone());
        }
    }
    for name in refs.keys() {
        for (i, _) in name.match_indices('/') {
            ensure!(
                !refs.contains_key(&name[..i]),
                "ref directory/file conflict"
            );
        }
    }
    if let Some((pack, oids)) = &pack {
        t.execute(
            "INSERT INTO pando_lab.manifests VALUES($1,$2,$3,$4)",
            &[&repo, &pack.id, &pack.pack_sha256, &pack.idx_sha256],
        )
        .await?;
        for oid in oids {
            t.execute(
                "INSERT INTO pando_lab.objects VALUES($1,$2,$3) ON CONFLICT DO NOTHING",
                &[&repo, oid, &pack.id],
            )
            .await?;
        }
    }
    for cmd in commands {
        if cmd.new == ZERO {
            t.execute(
                "DELETE FROM pando_lab.refs WHERE repo=$1 AND name=$2",
                &[&repo, &cmd.name],
            )
            .await?;
        } else {
            t.execute("INSERT INTO pando_lab.refs VALUES($1,$2,$3) ON CONFLICT(repo,name) DO UPDATE SET oid=excluded.oid",&[&repo,&cmd.name,&cmd.new]).await?;
        }
    }
    let next = generation.checked_add(1).context("generation exhausted")?;
    t.execute(
        "UPDATE pando_lab.repositories SET generation=$2 WHERE id=$1",
        &[&repo, &next],
    )
    .await?;
    t.execute(
        "INSERT INTO pando_lab.changes VALUES($1,$2,$3,$4)",
        &[&repo, &next, &op, &value],
    )
    .await?;
    t.execute(
        "UPDATE pando_lab.operations SET state='COMMITTED',result=$2 WHERE id=$1",
        &[
            &op,
            &serde_json::json!({"generation":next,"status":"committed"}),
        ],
    )
    .await?;
    if ctl.fault == "before-commit" {
        std::process::exit(73);
    }
    t.commit().await?;
    if ctl.fault == "after-commit" {
        std::process::exit(74);
    }
    Ok(())
}
