"""Offline structural and CI contracts for Issue #46 organization endpoints and suites."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
ORG_ENTRY = ROOT / "src" / "organizations.rs"
ORG_DIR = ROOT / "src" / "organizations"
CI_YML = ROOT / ".github" / "workflows" / "ci.yml"


class OrganizationsContractTest(unittest.TestCase):
    def test_organization_module_boundaries_and_serde_guards(self):
        self.assertTrue(ORG_ENTRY.is_file())
        self.assertFalse((ORG_DIR / "mod.rs").exists())
        entry_lines = ORG_ENTRY.read_text(encoding="utf-8").splitlines()
        self.assertLess(len(entry_lines), 100, f"src/organizations.rs exceeded 100 lines: {len(entry_lines)}")
        entry_text = "\n".join(entry_lines)
        for route in (
            '"/api/orgs"',
            '"/api/orgs/{slug}"',
            '"/api/orgs/{slug}/audit"',
            '"/api/orgs/{slug}/members"',
            '"/api/orgs/{slug}/members/{username}"',
            '"/api/orgs/{slug}/teams"',
            '"/api/orgs/{slug}/teams/{team_slug}"',
            '"/api/orgs/{slug}/teams/{team_slug}/members"',
            '"/api/orgs/{slug}/teams/{team_slug}/members/{username}"',
        ):
            self.assertIn(route, entry_text, f"missing route {route} in src/organizations.rs")
        self.assertNotIn("Command::new", entry_text)

        for path in sorted(ORG_DIR.glob("*.rs")):
            text = path.read_text(encoding="utf-8")
            lines = text.splitlines()
            self.assertLess(len(lines), 500, f"{path} exceeded 500 lines: {len(lines)}")
            self.assertNotIn("#[allow(", text, f"{path} must not suppress lints with #[allow(...)]")
            # Every Deserialize struct must deny unknown fields.
            for match in re.finditer(r"#\[derive\([^]]*Deserialize[^]]*\)\]", text):
                window = text[match.start(): match.start() + 200]
                self.assertIn("#[serde(deny_unknown_fields)]", window, f"missing deny_unknown_fields in {path}")

    def test_org_and_backup_suites_are_wired_into_ci_and_manifest(self):
        ci_text = CI_YML.read_text(encoding="utf-8")
        for script, report_name, report_file in (
            ("tests/organizations.py", "organizations", "test-results/organizations.json"),
            ("tests/organizations_web.py", "organizations_web", "test-results/organizations-web.json"),
            ("tests/backup_capabilities.py", "backup_capabilities", "test-results/backup-capabilities.json"),
            ("tests/organizations_lifecycle.py", "organizations_lifecycle", "test-results/organizations-lifecycle.json"),
        ):
            self.assertIn(f'python3 {script} --binary "$ROOTYARD_BIN" --report {report_file}', ci_text)
            self.assertIn(f"--report {report_name}={report_file}", ci_text)
            self.assertIn(f"--harness {script}", ci_text)


if __name__ == "__main__":
    unittest.main()
