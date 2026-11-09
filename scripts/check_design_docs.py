#!/usr/bin/env python3
"""Validate the archived design export and its repository navigation.

Standard-library only. This does not run Mermaid's parser or product tests.
"""

import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DESIGN = ROOT / "docs" / "design"
START = "<!-- BEGIN SOURCE BODY -->\n"
END = "<!-- END SOURCE BODY -->"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def source_body(path):
    text = path.read_text(encoding="utf-8")
    require(text.count(START) == 1 and text.count(END) == 1,
            f"{path}: expected exactly one source-body boundary pair")
    return text.split(START, 1)[1].split(END, 1)[0]


def digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def check_implementation_tasks():
    plan = json.loads((DESIGN / "implementation-tasks.json").read_text())
    require(plan["architecture"] == "blob-only-v2", "unexpected task architecture")
    tasks = plan["tasks"]
    numbers = [task["number"] for task in tasks]
    require(all(type(number) is int and number > 0 for number in numbers),
            "all implementation tasks must have published issue numbers")
    require(len(numbers) == len(set(numbers)), "duplicate implementation issue")
    by_number = {task["number"]: task for task in tasks}
    by_key = {task["key"]: task for task in tasks}
    require(len(by_key) == len(tasks), "duplicate implementation key")
    deleted = {item["number"] for item in plan["deleted_issues"]}
    require(not deleted.intersection(numbers), "retired issue remains an active task")
    require(not deleted.intersection(plan["preserved_issues"]), "retired issue marked preserved")
    visiting, done, ancestors = set(), set(), {}

    def visit(number):
        require(number in by_number, f"unknown prerequisite issue {number}")
        if number in done:
            return ancestors[number]
        require(number not in visiting, f"implementation dependency cycle at {number}")
        visiting.add(number)
        parents = set()
        for dependency in by_number[number]["dependencies"]:
            parents.add(dependency)
            parents.update(visit(dependency))
        visiting.remove(number)
        done.add(number)
        ancestors[number] = parents
        return parents

    for number in numbers:
        visit(number)
    remote = {by_key[key]["number"] for key in plan["distributed_keys"]}
    for key in plan["standalone_entry_keys"]:
        require(not ancestors[by_key[key]["number"]].intersection(remote),
                f"standalone task {key} depends on distributed delivery")
    for item in plan["deleted_issues"]:
        if item["disposition"] == "dropped_no_replacement":
            require(not item["replacements"], "dropped legacy migration has a replacement")
        else:
            require(item["replacements"], "superseded issue lacks replacement coverage")
            require(set(item["replacements"]).issubset(by_number),
                    "retired issue has an unpublished replacement")
    retired = plan["retired_roadmap"]
    path = (DESIGN / retired["path"]).resolve()
    require(path.is_relative_to(ROOT), "retired roadmap escapes repository")
    text = path.read_text()
    start, end = "<!-- BEGIN RETIRED ISSUE 48 BODY -->\n", "\n<!-- END RETIRED ISSUE 48 BODY -->"
    require(text.count(start) == text.count(end) == 1, "retired roadmap boundaries changed")
    body = text.split(start, 1)[1].split(end, 1)[0]
    require(digest(body) == retired["body_sha256"], "retired roadmap historical body changed")
    return len(tasks)


def main():
    manifest = json.loads((DESIGN / "source-manifest.json").read_text())
    archive = source_body(DESIGN / "source-page.md")
    require(digest(archive) == manifest["source_body_sha256"],
            "source archive digest differs from the recorded snapshot")
    require("https://chatgpt.com/c/" not in archive,
            "private conversation URL found in published archive")
    parts = []
    next_block = 1
    for chapter in manifest["chapters"]:
        require(chapter["first_block"] == next_block,
                f"{chapter['file']}: block coverage is not contiguous")
        require(chapter["last_block"] - chapter["first_block"] + 1
                == chapter["block_count"], "invalid chapter block count")
        body = source_body(DESIGN / chapter["file"])
        require(digest(body) == chapter["body_sha256"],
                f"{chapter['file']}: source body changed")
        require(body.endswith("\n"), "chapter body must end with newline")
        parts.append(body[:-1])
        next_block = chapter["last_block"] + 1
    require(next_block - 1 == manifest["source_block_count"],
            "incomplete source block coverage")
    require("\n\n".join(parts) + "\n" == archive,
            "topic chapters do not reconstruct the source archive")

    diagrams = (DESIGN / "architecture-diagrams.md").read_text()
    blocks = re.findall(r"```mermaid\n(.*?)```", diagrams, re.S)
    files = sorted((DESIGN / "diagrams").glob("*.mmd"))
    current = json.loads((DESIGN / "diagram-manifest.json").read_text())
    require(current["architecture"] == "blob-only-v2", "unexpected current architecture")
    roles = current["diagrams"]
    require({"standalone", "distributed"}.issubset(roles),
            "current diagrams must describe both deployment profiles")
    names = list(roles.values())
    require(len(names) == len(set(names)), "diagram roles must have distinct source files")
    require(all(Path(name).name == name and name.endswith(".mmd") for name in names),
            "invalid current diagram filename")
    require({file.name for file in files} == set(names),
            "current diagram sources differ from the explicit manifest")
    require(len(blocks) == len(files), "current diagram embed count differs from sources")
    for file in files:
        body = file.read_text()
        require(blocks.count(body) == 1, f"{file}: diagram embed is not identical")
    # The archived source (including its old diagram) remains hash-verified
    # above. Current architecture sources must not keep an obsolete diagram
    # merely to satisfy a historical filename/count assertion.

    task_count = check_implementation_tasks()

    pages = sorted(DESIGN.glob("*.md")) + [ROOT / "docs" / "README.md", ROOT / "README.md"]
    links = 0
    for page in pages:
        text = page.read_text()
        fences = re.findall(r"^\s*(`{3,}|~{3,})[^\n]*$", text, re.M)
        require(len(fences) % 2 == 0, f"{page}: unbalanced code fences")
        without_code = re.sub(r"```.*?```", "", text, flags=re.S)
        for target in re.findall(r"\[[^\]]*\]\(([^)]+)\)", without_code):
            target = target.split("#", 1)[0]
            if not target or re.match(r"[a-zA-Z][a-zA-Z0-9+.-]*:", target):
                continue
            resolved = (page.parent / target).resolve()
            require(resolved.is_relative_to(ROOT), f"{page}: link escapes repository")
            require(resolved.exists(), f"{page}: missing relative link {target}")
            links += 1
    print(f"PASS: {manifest['source_block_count']} source blocks, "
          f"{len(parts)} chapters, {len(files)} synchronized diagrams, "
          f"{links} repository links; {task_count} published tasks with acyclic dependencies; "
          f"archive SHA-256 {digest(archive)}")


if __name__ == "__main__":
    main()
