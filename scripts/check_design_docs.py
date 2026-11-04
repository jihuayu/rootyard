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
    require(len(blocks) == len(files) == 7, "expected seven architecture diagrams")
    for file in files:
        body = file.read_text()
        require(blocks.count(body) == 1, f"{file}: diagram embed is not identical")
    original = (DESIGN / "diagrams" / "target-overview.mmd").read_text()
    require(f"```mermaid\n{original}```" in archive,
            "original target architecture differs from the archived diagram")

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
          f"{links} repository links; archive SHA-256 {digest(archive)}")


if __name__ == "__main__":
    main()
