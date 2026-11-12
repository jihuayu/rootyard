#!/usr/bin/env python3
"""Regression guard for operational entrypoint docs (issue #78).

Ensures README.md, docs/backup-restore.md, docs/operations.md, and
docs/operations-HA.md stay synchronized with the live backup format constants,
latest SQL migration version, supported legacy restore flags, RBAC/PAT/session
security contracts, default-disabled destructive deletion, and local links.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINTS = (
    ROOT / "README.md",
    ROOT / "docs/backup-restore.md",
    ROOT / "docs/operations.md",
    ROOT / "docs/operations-HA.md",
)

FORBIDDEN_STALE_CLAIMS = (
    "there is no sharing model",
    "users access only their own repositories",
    "sslmode=require is not a way to enable tls",
    "exact schema008 backup contract",
    "this does not add organization sharing, prs, lfs, ci or a web ui",
    "all four forge tables",
    "all sixteen tables",
)

LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


def parse_backup_formats() -> tuple[int, int]:
    catalog_rs = (ROOT / "src/backup/catalog.rs").read_text(encoding="utf-8")
    backup_rs = (ROOT / "src/backup.rs").read_text(encoding="utf-8")
    fmt_match = re.search(r"pub\(super\)\s+const\s+FORMAT:\s*u32\s*=\s*(\d+);", catalog_rs)
    paired_match = re.search(r"pub\(super\)\s+const\s+FORMAT_PAIRED:\s*u32\s*=\s*(\d+);", catalog_rs)
    if fmt_match is None or paired_match is None:
        raise AssertionError("FORMAT / FORMAT_PAIRED missing in src/backup/catalog.rs")
    if "FORMAT" not in backup_rs or "FORMAT_PAIRED" not in backup_rs:
        raise AssertionError("src/backup.rs must import FORMAT and FORMAT_PAIRED")
    return int(fmt_match.group(1)), int(paired_match.group(1))


def parse_latest_migration_version() -> int:
    versions = sorted(
        int(path.name.split("_", 1)[0])
        for path in (ROOT / "migrations").glob("*.sql")
    )
    if not versions:
        raise AssertionError("no SQL migrations found in migrations/")
    db_rs = (ROOT / "src/db.rs").read_text(encoding="utf-8")
    const_match = re.search(r"pub const SCHEMA_VERSIONS:\s*&\[i32\]\s*=\s*&\[([0-9,\s]+)\];", db_rs)
    if const_match is None:
        raise AssertionError("SCHEMA_VERSIONS missing in src/db.rs")
    rust_versions = [int(tok.strip()) for tok in const_match.group(1).split(",") if tok.strip()]
    if versions != rust_versions:
        raise AssertionError(f"migrations/ {versions} != SCHEMA_VERSIONS {rust_versions}")
    return versions[-1]


def parse_legacy_restore_flags() -> set[str]:
    main_rs = (ROOT / "src/main.rs").read_text(encoding="utf-8")
    restore_rs = (ROOT / "src/backup/restore.rs").read_text(encoding="utf-8")
    cli_flags = set(re.findall(r'"(--allow-legacy-schema\d+)"', main_rs))
    param_flags = {
        f"--allow-legacy-schema{num}"
        for num in re.findall(r"\ballow_legacy_schema(\d+)\s*:\s*bool", restore_rs)
    }
    if not cli_flags or cli_flags != param_flags:
        raise AssertionError(f"CLI legacy flags {cli_flags} != restore params {param_flags}")
    return cli_flags


def current_contract_section(text: str) -> str:
    parts = re.split(r"(?m)^##\s+Historical\b", text, maxsplit=1)
    return parts[0]


def normalize_prose(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower().replace("`", ""))


def positive_legacy_flags_in_doc(text: str) -> set[str]:
    scrubbed = re.sub(
        r"(?:\bno\s+(?:\*\*no\*\*\s+)?|\*\*no\*\*\s+|无\s*)`?--allow-legacy-schema\d+`?",
        "",
        text,
        flags=re.IGNORECASE,
    )
    return set(re.findall(r"--allow-legacy-schema\d+", scrubbed))


def check_current_header_sync(name: str, text: str, fmt: int, fmt_paired: int, schema: int) -> list[str]:
    errors: list[str] = []
    head = current_contract_section(text)
    for token in (f"format {fmt}", f"format {fmt_paired}", f"schema {schema}"):
        if token not in head:
            errors.append(f"{name}: current-contract section missing '{token}'")
    claim_scope = normalize_prose(head if name == "backup-restore.md" else text)
    for phrase in FORBIDDEN_STALE_CLAIMS:
        if phrase in claim_scope:
            errors.append(f"{name}: contains stale claim '{phrase}'")
    normalized_full = normalize_prose(text)
    stale_patterns = (
        (r"current integration uses backup format ?(\d+)", {fmt, fmt_paired}),
        (r"currently produces format ?(\d+)", {fmt, fmt_paired}),
        (r"new backups use format ?(\d+)", {fmt, fmt_paired}),
    )
    for pattern, allowed in stale_patterns:
        for match in re.finditer(pattern, normalized_full):
            observed = int(match.group(1))
            if observed not in allowed:
                errors.append(f"{name}: stale current-format claim '{match.group(0)}'")
    return errors


def check_markdown_fences_and_links(path: Path, text: str, root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    in_fence = False
    root_resolved = root.resolve()
    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.lstrip()
        if stripped.startswith(("```", "~~~")):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        for raw_target in LINK_RE.findall(line):
            target = raw_target.strip().split()[0]
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            rel = target.split("#", 1)[0]
            if not rel:
                continue
            resolved = (path.parent / rel).resolve()
            try:
                resolved.relative_to(root_resolved)
            except ValueError:
                errors.append(f"{path.name}:{lineno}: link escapes repository root: {raw_target}")
                continue
            if not resolved.exists():
                errors.append(f"{path.name}:{lineno}: broken local link: {raw_target}")
    if in_fence:
        errors.append(f"{path.name}: unbalanced markdown code fence")
    return errors


class OperationalEntrypointsTest(unittest.TestCase):
    def test_current_backup_formats_and_schema_sync_across_entrypoints(self) -> None:
        fmt, fmt_paired = parse_backup_formats()
        schema = parse_latest_migration_version()
        self.assertEqual(fmt_paired, fmt + 1)
        self.assertTrue((ROOT / "schema" / f"{schema:03d}_catalog.json").is_file())

        for doc_path in ENTRYPOINTS:
            text = doc_path.read_text(encoding="utf-8")
            errors = check_current_header_sync(doc_path.name, text, fmt, fmt_paired, schema)
            self.assertEqual(errors, [], "\n".join(errors))

    def test_backup_restore_doc_matches_exact_cli_legacy_flags(self) -> None:
        expected_flags = parse_legacy_restore_flags()
        schema = parse_latest_migration_version()
        self.assertNotIn(f"--allow-legacy-schema{schema}", expected_flags)
        self.assertNotIn("--allow-legacy-schema060", expected_flags)
        self.assertNotIn("--allow-legacy-schema144", expected_flags)

        backup_doc = (ROOT / "docs/backup-restore.md").read_text(encoding="utf-8")
        self.assertEqual(positive_legacy_flags_in_doc(backup_doc), expected_flags)
        for rel in ("README.md", "docs/operations.md", "docs/operations-HA.md"):
            doc_text = (ROOT / rel).read_text(encoding="utf-8")
            self.assertTrue(positive_legacy_flags_in_doc(doc_text).issubset(expected_flags))

    def test_operational_security_gc_and_non_claim_contracts_present(self) -> None:
        for doc_path in (ROOT / "README.md", ROOT / "docs/operations.md"):
            head = current_contract_section(doc_path.read_text(encoding="utf-8"))
            for token in (
                "`read` < `triage` < `write` < `maintain` < `admin`",
                "`404`",
                "`403`",
                "`actor.id`",
                "`tenant_id`",
                "`FOR SHARE`",
                "`rootyard_session`",
                "`X-CSRF-Token`",
                "`X-Forwarded-Proto: https`",
                "`sslmode=require`",
                "`ROOTYARD_PG_CA_PEM`",
                "`DeleteDisabled`",
                "`ROOTYARD_STORAGE_MAINTENANCE`",
                "`ROOTYARD_PANDO_REMOTE_DELETE=true`",
                "`ROOTYARD_WORKSPACE_UNSAFE_REMOTE_DELETE=true`",
                "#77",
                "#83",
                "#84",
                "#120",
                "#148",
                "serve-blob",
            ):
                self.assertIn(token, head, f"{doc_path.name} current contract missing {token}")

        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertRegex(
            readme,
            r"\| 职责 \| 轻量单机 \| 分布式 \|\n\| --- \| --- \| --- \|\n\| 应用 \|",
            "README.md target-architecture table must retain data rows",
        )
        self.assertIn("## Historical Incremental Milestones", readme)

    def test_fences_and_relative_links_resolve_across_all_entrypoints(self) -> None:
        for doc_path in ENTRYPOINTS:
            self.assertTrue(doc_path.is_file(), f"Missing {doc_path}")
            errors = check_markdown_fences_and_links(doc_path, doc_path.read_text(encoding="utf-8"))
            self.assertEqual(errors, [], "\n".join(errors))

    def test_validator_helpers_reject_stale_claims_and_bad_links(self) -> None:
        fmt, fmt_paired = parse_backup_formats()
        schema = parse_latest_migration_version()
        valid_base = f"Status: active contract uses format {fmt} and format {fmt_paired} on schema {schema}.\n"
        self.assertEqual(check_current_header_sync("synthetic.md", valid_base, fmt, fmt_paired, schema), [])

        for missing_token in (f"format {fmt}", f"format {fmt_paired}", f"schema {schema}"):
            errs = check_current_header_sync(
                "synthetic.md", valid_base.replace(missing_token, "removed"), fmt, fmt_paired, schema
            )
            self.assertEqual(errs, [f"synthetic.md: current-contract section missing '{missing_token}'"])

        for phrase in FORBIDDEN_STALE_CLAIMS:
            plain_errs = check_current_header_sync("synthetic.md", f"{valid_base}\n{phrase}.\n", fmt, fmt_paired, schema)
            self.assertEqual(plain_errs, [f"synthetic.md: contains stale claim '{phrase}'"])
            wrapped = phrase.replace(" ", "\n  ", 1)
            wrap_errs = check_current_header_sync("synthetic.md", f"{valid_base}\n{wrapped}.\n", fmt, fmt_paired, schema)
            self.assertEqual(wrap_errs, [f"synthetic.md: contains stale claim '{phrase}'"])

        backticked_tls = f"{valid_base}\n`sslmode=require` is not a way to enable TLS.\n"
        self.assertEqual(
            check_current_header_sync("synthetic.md", backticked_tls, fmt, fmt_paired, schema),
            ["synthetic.md: contains stale claim 'sslmode=require is not a way to enable tls'"],
        )

        hist_doc = f"{valid_base}\n## Historical format & schema increment notes\nAll sixteen tables in old drill.\n"
        self.assertEqual(check_current_header_sync("backup-restore.md", hist_doc, fmt, fmt_paired, schema), [])
        self.assertEqual(
            check_current_header_sync("operations.md", hist_doc, fmt, fmt_paired, schema),
            ["operations.md: contains stale claim 'all sixteen tables'"],
        )

        for snippet, expected_match in (
            (f"current integration uses backup `format {fmt - 1}`", f"current integration uses backup format {fmt - 1}"),
            ("the tool currently produces\n  format 7 archives", "currently produces format 7"),
            ("new backups use `format20`", "new backups use format20"),
        ):
            errs = check_current_header_sync("synthetic.md", f"{valid_base}\n{snippet}\n", fmt, fmt_paired, schema)
            self.assertEqual(errs, [f"synthetic.md: stale current-format claim '{expected_match}'"])

        expected_flags = parse_legacy_restore_flags()
        self.assertFalse(positive_legacy_flags_in_doc("Use --allow-legacy-schema144").issubset(expected_flags))
        self.assertEqual(positive_legacy_flags_in_doc("**no** `--allow-legacy-schema144`"), set())

        self.assertEqual(len(check_markdown_fences_and_links(ROOT / "docs/operations.md", "[x](does-not-exist.md)")), 1)
        self.assertEqual(len(check_markdown_fences_and_links(ROOT / "docs/operations.md", "[x](../../etc/passwd)")), 1)
        self.assertEqual(len(check_markdown_fences_and_links(ROOT / "docs/operations.md", "```sh\nunclosed\n")), 1)


if __name__ == "__main__":
    unittest.main()
