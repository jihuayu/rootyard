#!/usr/bin/env python3
"""Part II Track 1 E2E & Reference Verification Harness: Web UI & Frontend Security Rendering (F33 & F34).

Provides:
- Exact security rendering & truncation primitives (`escape_html`, `sanitize_url`, `strip_dangerous_html`,
  `render_safe_markdown`, `format_binary_hex_preview`, `build_blob_preview`).
- `WebReferenceEngine` + `LocalWebUiServer` backed by real `/usr/bin/git` bare repositories,
  SQLite 5-role RBAC (`MembersReferenceEngine`), and a loopback HTTP/1.1 server.
- `WebHarness(PullsHarness)` supporting `--binary`, `--report`, `--keep`, and `--case` for both
  live PostgreSQL + `rootyard` binary execution and standalone `/usr/bin/git` loopback verification.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
from typing import Any, Optional
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent))
import members  # noqa: E402
from pulls import PullsHarness  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]

CSP_HEADER_VALUE = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; "
    "base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)
DEFAULT_WEB_BLOB_PREVIEW_BYTES = 64 * 1024
MAX_WEB_BLOB_PREVIEW_BYTES = 256 * 1024
MIN_WEB_BLOB_PREVIEW_BYTES = 256
MAX_WEB_BLOB_PREVIEW_LINES = 2_000
BINARY_HEX_PREVIEW_BYTES = 256
BINARY_SNIFF_BYTES = 8 * 1024
ZERO_OID = "0" * 40

PAIRED_DANGEROUS_TAGS = (
    "iframe",
    "object",
    "applet",
    "svg",
    "math",
    "form",
    "style",
    "script",
    "template",
    "noscript",
    "frame",
    "frameset",
    "portal",
    "select",
    "textarea",
    "button",
    "option",
)
VOID_DANGEROUS_TAGS = (
    "base",
    "meta",
    "link",
    "input",
    "embed",
    "param",
    "source",
    "track",
    "area",
    "keygen",
)
ALLOWED_TAGS = {
    "p",
    "br",
    "hr",
    "strong",
    "b",
    "em",
    "i",
    "code",
    "pre",
    "blockquote",
    "ul",
    "ol",
    "li",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "a",
    "del",
    "s",
    "sub",
    "sup",
    "table",
    "thead",
    "tbody",
    "tr",
    "th",
    "td",
    "span",
    "div",
    "img",
}


def escape_html(text: str) -> str:
    out: list[str] = []
    for ch in text:
        if ch == "\x00":
            continue
        if ch == "&":
            out.append("&amp;")
        elif ch == "<":
            out.append("&lt;")
        elif ch == ">":
            out.append("&gt;")
        elif ch == '"':
            out.append("&quot;")
        elif ch == "'":
            out.append("&#x27;")
        else:
            out.append(ch)
    return "".join(out)


def _decode_html_entities_once(s: str) -> str:
    def _num_repl(m: re.Match[str]) -> str:
        is_hex = m.group(1).lower() == "x"
        digits = m.group(2).lstrip("0") or "0"
        try:
            code = int(digits, 16 if is_hex else 10)
            if 0 < code <= 0x10FFFF:
                return chr(code)
        except ValueError:
            pass
        return "\x00"

    s = re.sub(r"&#([xX]?)([0-9a-fA-F]+);?", _num_repl, s)
    named = {
        "colon": ":",
        "tab": "\t",
        "newline": "\n",
        "amp": "&",
        "lt": "<",
        "gt": ">",
        "quot": '"',
        "apos": "'",
        "nbsp": " ",
        "sol": "/",
        "bsol": "\\",
    }

    def _named_repl(m: re.Match[str]) -> str:
        name = m.group(1).lower()
        return named.get(name, m.group(0))

    return re.sub(r"&([a-zA-Z0-9]+);?", _named_repl, s)


def sanitize_url(raw_url: str) -> Optional[str]:
    if "\x00" in raw_url or "\\" in raw_url:
        return None
    trimmed = raw_url.strip()
    if len(trimmed) >= 2 and (
        (trimmed[0] == "<" and trimmed[-1] == ">")
        or (trimmed[0] == '"' and trimmed[-1] == '"')
        or (trimmed[0] == "'" and trimmed[-1] == "'")
        or (trimmed[0] == "`" and trimmed[-1] == "`")
    ):
        trimmed = trimmed[1:-1].strip()
    if not trimmed:
        return None

    norm = trimmed
    for _ in range(3):
        norm = _decode_html_entities_once(norm)
        norm = urllib.parse.unquote(norm)
        if "\x00" in norm or "\\" in norm:
            return None
        norm = "".join(ch for ch in norm if ord(ch) > 0x20 and ord(ch) != 0x7F)

    lower = norm.lower()
    if not lower or lower.startswith("//") or lower.startswith("/\\"):
        return None
    for bad in (
        "javascript:",
        "data:",
        "vbscript:",
        "file:",
        "blob:",
        "about:",
        "jar:",
        "ws:",
        "wss:",
    ):
        if lower.startswith(bad):
            return None

    first_delim = len(lower)
    for d in ("/", "?", "#"):
        idx = lower.find(d)
        if idx != -1 and idx < first_delim:
            first_delim = idx

    prefix = lower[:first_delim]
    if ":" in prefix:
        scheme = prefix.split(":", 1)[0]
        if scheme == "http":
            if not lower.startswith("http://") or len(lower) <= len("http://"):
                return None
        elif scheme == "https":
            if not lower.startswith("https://") or len(lower) <= len("https://"):
                return None
        elif scheme == "mailto":
            if not lower.startswith("mailto:") or len(lower) <= len("mailto:"):
                return None
        else:
            return None
    elif ":" in lower:
        return None

    cleaned = "".join(ch for ch in trimmed if ord(ch) >= 0x20 and ord(ch) != 0x7F)
    if not cleaned or cleaned.startswith("//"):
        return None
    return escape_html(cleaned)


def _strip_paired_dangerous_blocks(text: str) -> str:
    current = text
    for tag in PAIRED_DANGEROUS_TAGS:
        open_pat = f"<{tag}"
        close_pat = f"</{tag}"
        out: list[str] = []
        lower = current.lower()
        cursor = 0
        n = len(current)
        while cursor < n:
            start = lower.find(open_pat, cursor)
            if start == -1:
                out.append(current[cursor:])
                break
            after_open = start + len(open_pat)
            if after_open < n and lower[after_open] not in (" ", "\t", "\n", "\r", ">", "/", '"', "'", "`"):
                out.append(current[cursor:after_open])
                cursor = after_open
                continue
            out.append(current[cursor:start])
            line_end = lower.find("\n", after_open)
            if line_end == -1:
                line_end = n
            close_start = lower.find(close_pat, after_open)
            if close_start != -1 and lower.find(open_pat, after_open, close_start) == -1:
                gt = lower.find(">", close_start)
                if gt != -1:
                    cursor = gt + 1
                    continue
            cursor = line_end
        current = "".join(out)
    return current


def _extract_attr(attrs: str, target: str) -> Optional[str]:
    for m in re.finditer(
        r'([a-zA-Z0-9_:-]+)\s*(?:=\s*(?:"([^"]*)"|\'([^\']*)\'|`([^`]*)`|([^\s>]+)))?',
        attrs,
    ):
        name = m.group(1).lower()
        val = m.group(2) or m.group(3) or m.group(4) or m.group(5) or ""
        if name == target:
            return val
    return None


def strip_dangerous_html(text: str) -> str:
    cleaned = _strip_paired_dangerous_blocks(text)
    out: list[str] = []
    i = 0
    n = len(cleaned)
    while i < n:
        if cleaned[i] == "<":
            gt = cleaned.find(">", i + 1)
            if gt == -1:
                break
            raw_tag = cleaned[i + 1 : gt].strip()
            i = gt + 1
            if not raw_tag or raw_tag.startswith("!") or raw_tag.startswith("?"):
                continue
            is_closing = raw_tag.startswith("/")
            body = raw_tag[1:].lstrip() if is_closing else raw_tag
            m_name = re.match(r"^([a-zA-Z0-9]+)(.*)", body, re.DOTALL)
            if not m_name:
                continue
            tag_name = m_name.group(1).lower()
            attrs = m_name.group(2)
            if (
                tag_name in PAIRED_DANGEROUS_TAGS
                or tag_name in VOID_DANGEROUS_TAGS
                or tag_name not in ALLOWED_TAGS
            ):
                continue
            if is_closing:
                if tag_name not in ("br", "hr", "img"):
                    out.append(f"</{tag_name}>")
                continue
            if tag_name == "br":
                out.append("<br/>")
            elif tag_name == "hr":
                out.append("<hr/>")
            elif tag_name == "a":
                href = _extract_attr(attrs, "href")
                safe_href = sanitize_url(href) if href is not None else None
                if safe_href:
                    out.append(f'<a href="{safe_href}" rel="noopener noreferrer">')
                else:
                    out.append("<a>")
            elif tag_name == "img":
                alt = _extract_attr(attrs, "alt") or ""
                src = _extract_attr(attrs, "src")
                safe_src = sanitize_url(src) if src is not None else None
                if safe_src and not safe_src.lower().startswith("mailto:"):
                    out.append(
                        f'<img src="{safe_src}" alt="{escape_html(alt)}" loading="lazy"/>'
                    )
                else:
                    out.append(f'<span class="sanitized-image">{escape_html(alt)}</span>')
            elif tag_name == "code":
                lang_raw = _extract_attr(attrs, "data-lang") or ""
                lang = "".join(
                    c for c in lang_raw if c.isalnum() or c in "_-+"
                )[:32]
                if lang:
                    out.append(f'<code data-lang="{lang}">')
                else:
                    out.append("<code>")
            elif tag_name == "pre":
                if _extract_attr(attrs, "class") == "code-block":
                    out.append('<pre class="code-block">')
                else:
                    out.append("<pre>")
            else:
                out.append(f"<{tag_name}>")
        else:
            next_lt = cleaned.find("<", i)
            if next_lt == -1:
                next_lt = n
            chunk = cleaned[i:next_lt]
            for ch in chunk:
                if ch == "\x00":
                    continue
                if ch == "<":
                    out.append("&lt;")
                elif ch == ">":
                    out.append("&gt;")
                elif ch == '"':
                    out.append("&quot;")
                elif ch == "'":
                    out.append("&#x27;")
                else:
                    out.append(ch)
            i = next_lt
    return "".join(out)


def _find_closing_paren(s: str) -> int:
    depth = 0
    for idx, ch in enumerate(s):
        if ch == "(":
            depth += 1
        elif ch == ")":
            if depth > 0:
                depth -= 1
            else:
                return idx
    return -1


def _render_inline_markdown(text: str) -> str:
    pre = strip_dangerous_html(text)
    out: list[str] = []
    rest = pre
    while rest:
        if rest.startswith("`"):
            end = rest.find("`", 1)
            if end != -1:
                out.append(f"<code>{escape_html(rest[1:end])}</code>")
                rest = rest[end + 1 :]
                continue
        if rest.startswith("!["):
            close_br = rest.find("](", 2)
            if close_br != -1:
                alt = rest[2:close_br]
                url_part = rest[close_br + 2 :]
                close_paren = _find_closing_paren(url_part)
                if close_paren != -1:
                    raw_url = url_part[:close_paren]
                    safe_url = sanitize_url(raw_url)
                    if safe_url and not safe_url.lower().startswith("mailto:"):
                        out.append(
                            f'<img src="{safe_url}" alt="{escape_html(alt)}" loading="lazy"/>'
                        )
                    else:
                        out.append(
                            f'<span class="sanitized-image">{escape_html(alt)}</span>'
                        )
                    rest = url_part[close_paren + 1 :]
                    continue
        if rest.startswith("["):
            close_br = rest.find("](", 1)
            if close_br != -1:
                label = rest[1:close_br]
                url_part = rest[close_br + 2 :]
                close_paren = _find_closing_paren(url_part)
                if close_paren != -1:
                    raw_url = url_part[:close_paren]
                    safe_label = strip_dangerous_html(label)
                    safe_url = sanitize_url(raw_url)
                    if safe_url:
                        out.append(
                            f'<a href="{safe_url}" rel="noopener noreferrer">{safe_label}</a>'
                        )
                    else:
                        out.append(f'<span class="sanitized-link">{safe_label}</span>')
                    rest = url_part[close_paren + 1 :]
                    continue
        if rest.startswith("**"):
            end_b = rest.find("**", 2)
            if end_b != -1:
                out.append(f"<strong>{strip_dangerous_html(rest[2:end_b])}</strong>")
                rest = rest[end_b + 2 :]
                continue
        next_indices = [
            idx
            for idx in (
                rest.find("`", 1),
                rest.find("!", 1),
                rest.find("[", 1),
                rest.find("*", 1),
            )
            if idx != -1
        ]
        nxt = min(next_indices) if next_indices else len(rest)
        out.append(rest[:nxt])
        rest = rest[nxt:]
    return "".join(out)


def render_safe_markdown(markdown: str) -> str:
    pre = _strip_paired_dangerous_blocks(markdown.replace("\r\n", "\n"))
    html: list[str] = []
    in_code = False
    code_buf: list[str] = []
    code_lang = ""
    list_tag: Optional[str] = None

    for line in pre.split("\n"):
        trimmed = line.rstrip()
        if trimmed.startswith("```"):
            if list_tag:
                html.append(f"</{list_tag}>\n")
                list_tag = None
            if in_code:
                html.append(
                    f'<pre class="code-block"><code data-lang="{code_lang}">{"".join(code_buf)}</code></pre>\n'
                )
                code_buf = []
                code_lang = ""
                in_code = False
            else:
                raw_lang = trimmed[3:].strip()
                code_lang = "".join(
                    c for c in raw_lang if c.isalnum() or c in "_-+"
                )[:32]
                in_code = True
            continue
        if in_code:
            code_buf.append(escape_html(line) + "\n")
            continue
        ltrim = trimmed.lstrip()
        if not ltrim:
            if list_tag:
                html.append(f"</{list_tag}>\n")
                list_tag = None
            continue
        if ltrim in ("---", "***", "___"):
            if list_tag:
                html.append(f"</{list_tag}>\n")
                list_tag = None
            html.append("<hr/>\n")
            continue
        m_h = re.match(r"^(#{1,6})\s+(.*)$", ltrim)
        if m_h:
            if list_tag:
                html.append(f"</{list_tag}>\n")
                list_tag = None
            lvl = len(m_h.group(1))
            html.append(f"<h{lvl}>{_render_inline_markdown(m_h.group(2).strip())}</h{lvl}>\n")
            continue
        if ltrim.startswith("> "):
            if list_tag:
                html.append(f"</{list_tag}>\n")
                list_tag = None
            html.append(
                f"<blockquote><p>{_render_inline_markdown(ltrim[2:])}</p></blockquote>\n"
            )
            continue
        if ltrim.startswith("- ") or ltrim.startswith("* "):
            if list_tag != "ul":
                if list_tag:
                    html.append(f"</{list_tag}>\n")
                html.append("<ul>\n")
                list_tag = "ul"
            html.append(f"<li>{_render_inline_markdown(ltrim[2:])}</li>\n")
            continue
        if list_tag:
            html.append(f"</{list_tag}>\n")
            list_tag = None
        html.append(f"<p>{_render_inline_markdown(ltrim)}</p>\n")

    if in_code:
        html.append(
            f'<pre class="code-block"><code data-lang="{code_lang}">{"".join(code_buf)}</code></pre>\n'
        )
    if list_tag:
        html.append(f"</{list_tag}>\n")
    return strip_dangerous_html("".join(html))


def format_binary_hex_preview(raw_bytes: bytes) -> str:
    slice_bytes = raw_bytes[:BINARY_HEX_PREVIEW_BYTES]
    lines: list[str] = []
    for row_idx in range(0, len(slice_bytes), 16):
        chunk = slice_bytes[row_idx : row_idx + 16]
        hex_col = " ".join(f"{b:02x}" for b in chunk)
        ascii_col = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in chunk)
        lines.append(f"{row_idx:04x}: {hex_col:<47}  |{ascii_col}|\n")
    return "".join(lines)


def build_blob_preview(
    oid: str,
    path: str,
    total_size: int,
    raw_prefix: bytes,
    max_bytes: int = DEFAULT_WEB_BLOB_PREVIEW_BYTES,
) -> dict[str, Any]:
    clamped_max = max(MIN_WEB_BLOB_PREVIEW_BYTES, min(MAX_WEB_BLOB_PREVIEW_BYTES, max_bytes))
    sniff = raw_prefix[:BINARY_SNIFF_BYTES]
    has_nul = b"\x00" in sniff
    byte_truncated = (total_size > clamped_max) or (len(raw_prefix) > clamped_max)
    candidate = raw_prefix[:clamped_max]

    is_binary = False
    valid_text = ""
    if has_nul:
        is_binary = True
    else:
        try:
            valid_text = candidate.decode("utf-8")
        except UnicodeDecodeError as err:
            cut_at_end = (err.end == len(candidate)) and (len(candidate) - err.start <= 3) and (
                byte_truncated or total_size > len(candidate)
            )
            if cut_at_end:
                valid_text = candidate[: err.start].decode("utf-8", errors="ignore")
            else:
                is_binary = True

    if is_binary:
        bin_slice = raw_prefix[:BINARY_HEX_PREVIEW_BYTES]
        hex_dump = format_binary_hex_preview(bin_slice)
        return {
            "oid": oid,
            "path": path,
            "total_size": total_size,
            "preview_bytes": len(bin_slice),
            "is_binary": True,
            "truncated": total_size > len(bin_slice),
            "line_count": len(hex_dump.splitlines()),
            "text_preview": None,
            "rendered_markdown_html": None,
            "hex_preview": hex_dump,
        }

    lines = valid_text.splitlines(keepends=True)
    lines_truncated = len(lines) > MAX_WEB_BLOB_PREVIEW_LINES
    kept_lines = lines[:MAX_WEB_BLOB_PREVIEW_LINES]
    final_text = "".join(kept_lines)
    shown_bytes = len(final_text.encode("utf-8"))
    truncated = byte_truncated or lines_truncated or (total_size > shown_bytes)
    lower_path = path.lower()
    rendered_md = (
        render_safe_markdown(final_text)
        if lower_path.endswith(".md") or lower_path.endswith(".markdown")
        else None
    )
    return {
        "oid": oid,
        "path": path,
        "total_size": total_size,
        "preview_bytes": shown_bytes,
        "is_binary": False,
        "truncated": truncated,
        "line_count": len(kept_lines),
        "text_preview": final_text,
        "rendered_markdown_html": rendered_md,
        "hex_preview": None,
    }


def security_headers() -> dict[str, str]:
    return {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
        "Content-Security-Policy": CSP_HEADER_VALUE,
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
    }


class WebReferenceEngine:
    """Reference engine combining a real `/usr/bin/git` bare repository with 5-role RBAC & Forge SQLite state."""

    def __init__(self, git_dir: Optional[Path] = None) -> None:
        self._own_tmp: Optional[tempfile.TemporaryDirectory[str]] = None
        if git_dir is None:
            self._own_tmp = tempfile.TemporaryDirectory(prefix="rootyard-web-ref-")
            self.git_dir = Path(self._own_tmp.name) / "forge.git"
            self._init_seeded_git_repo(self.git_dir)
        else:
            self.git_dir = git_dir
            if not (self.git_dir / "HEAD").exists():
                self._init_seeded_git_repo(self.git_dir)

        self.rbac = members.MembersReferenceEngine()
        self.rbac.conn.close()
        self.rbac.conn = sqlite3.connect(":memory:", check_same_thread=False)
        self.rbac.conn.row_factory = sqlite3.Row
        self.rbac._init_schema()
        self._lock = threading.Lock()
        self.rbac.conn.executescript(
            """
            ALTER TABLE forge_pulls ADD COLUMN body TEXT NOT NULL DEFAULT '';
            CREATE TABLE IF NOT EXISTS forge_issue_comments (
                tenant_id TEXT NOT NULL,
                repository_id TEXT NOT NULL,
                issue_number INTEGER NOT NULL,
                number INTEGER NOT NULL,
                author_id TEXT NOT NULL,
                body TEXT NOT NULL,
                version INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT '2026-01-01T00:00:00Z',
                updated_at TEXT NOT NULL DEFAULT '2026-01-01T00:00:00Z',
                PRIMARY KEY (tenant_id, repository_id, issue_number, number)
            );
            CREATE TABLE IF NOT EXISTS forge_check_runs (
                tenant_id TEXT NOT NULL,
                repository_id TEXT NOT NULL,
                commit_oid TEXT NOT NULL,
                context TEXT NOT NULL,
                attempt INTEGER NOT NULL DEFAULT 1,
                sequence INTEGER NOT NULL DEFAULT 1,
                status TEXT NOT NULL,
                conclusion TEXT,
                output TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT '2026-01-01T00:00:00Z',
                updated_at TEXT NOT NULL DEFAULT '2026-01-01T00:00:00Z',
                PRIMARY KEY (tenant_id, repository_id, commit_oid, context)
            );
            """
        )
        self.tokens: dict[str, dict[str, Any]] = {}
        self.alice = self.issue_user("alice")
        self.alice_ro = self.issue_user("alice", read_only=True, existing_user=self.alice)
        self.bob = self.issue_user("bob")
        self.carol = self.issue_user("carol")
        self.dave = self.issue_user("dave")
        self.erin = self.issue_user("erin")
        self.outsider = self.issue_user("outsider")
        self.repo = self.rbac.create_repo(self.alice, "forge")

    def close(self) -> None:
        if self._own_tmp is not None:
            self._own_tmp.cleanup()
            self._own_tmp = None

    def issue_user(
        self,
        username: str,
        read_only: bool = False,
        existing_user: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        u = dict(existing_user) if existing_user else dict(self.rbac.create_user(username))
        u["read_only"] = read_only
        suffix = "ro" if read_only else "rw"
        tok = "ryt_" + hashlib.sha256(f"{username}:{suffix}".encode()).hexdigest()
        u["token"] = tok
        self.tokens[tok] = u
        return u

    def git(self, *args: str, input_bytes: Optional[bytes] = None) -> bytes:
        res = subprocess.run(
            ["/usr/bin/git", "--git-dir", str(self.git_dir), *args],
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        return res.stdout

    def _init_seeded_git_repo(self, bare_dir: Path) -> None:
        bare_dir.parent.mkdir(parents=True, exist_ok=True)
        work_dir = bare_dir.parent / "seed-work"
        subprocess.run(["/usr/bin/git", "init", "-q", "--bare", str(bare_dir)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(["/usr/bin/git", "clone", str(bare_dir), str(work_dir)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(["/usr/bin/git", "config", "user.name", "alice"], cwd=work_dir, check=True)
        subprocess.run(["/usr/bin/git", "config", "user.email", "alice@rootyard.local"], cwd=work_dir, check=True)

        (work_dir / "README.md").write_text(
            "# Rootyard Forge\n\nWelcome to **Rootyard** Web UI.\n",
            encoding="utf-8",
        )
        (work_dir / "src").mkdir(exist_ok=True)
        (work_dir / "src" / "lib.rs").write_text(
            "pub fn answer() -> u32 {\n    42\n}\n",
            encoding="utf-8",
        )
        # 120 KiB text file
        (work_dir / "large_120k.txt").write_text(
            ("line-content-0123456789abcdef\n" * 4200),
            encoding="utf-8",
        )
        # 4.5 MiB large file (> MAX_BROWSE_BLOB_BYTES = 4 MiB)
        (work_dir / "huge_4_5mb.log").write_bytes(b"HUGE_ROW_0123456789ABCDEF\n" * 181_485)
        # Multi-byte UTF-8 file (CJK + 4-byte emoji)
        (work_dir / "utf8_multibyte.md").write_text(
            "# 多字节测试\n" + ("你好世界🦀🚀\n" * 120),
            encoding="utf-8",
        )
        # Binary file containing NUL and non-UTF8 bytes
        (work_dir / "assets.bin").write_bytes(
            b"\x89PNG\r\n\x1a\n\x00\x01\x02\xff\xfe\xfd" + (b"BINARY_DATA_" * 40)
        )

        subprocess.run(["/usr/bin/git", "add", "."], cwd=work_dir, check=True)
        subprocess.run(["/usr/bin/git", "commit", "-m", "initial main commit"], cwd=work_dir, check=True, stdout=subprocess.PIPE)
        self.base_oid = (
            subprocess.run(["/usr/bin/git", "rev-parse", "HEAD"], cwd=work_dir, check=True, stdout=subprocess.PIPE)
            .stdout.decode()
            .strip()
        )
        subprocess.run(["/usr/bin/git", "push", "origin", "HEAD:refs/heads/main"], cwd=work_dir, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(["/usr/bin/git", "--git-dir", str(bare_dir), "symbolic-ref", "HEAD", "refs/heads/main"], check=True)

        # Feature branch commit
        (work_dir / "src" / "feature.rs").write_text(
            "pub fn feature_enabled() -> bool {\n    true\n}\n",
            encoding="utf-8",
        )
        subprocess.run(["/usr/bin/git", "add", "."], cwd=work_dir, check=True)
        subprocess.run(["/usr/bin/git", "commit", "-m", "add feature implementation"], cwd=work_dir, check=True, stdout=subprocess.PIPE)
        self.feat_oid = (
            subprocess.run(["/usr/bin/git", "rev-parse", "HEAD"], cwd=work_dir, check=True, stdout=subprocess.PIPE)
            .stdout.decode()
            .strip()
        )
        subprocess.run(["/usr/bin/git", "push", "origin", "HEAD:refs/heads/feature"], cwd=work_dir, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        shutil.rmtree(work_dir, ignore_errors=True)

    def authenticate_headers(self, headers: dict[str, str]) -> Optional[dict[str, Any]]:
        lower_map = {k.lower(): v for k, v in headers.items()}
        auth_val = lower_map.get("authorization", "")
        raw_tok = ""
        if auth_val.startswith("Bearer "):
            raw_tok = auth_val[len("Bearer ") :].strip()
        elif auth_val.startswith("Basic "):
            try:
                decoded = base64.b64decode(auth_val[len("Basic ") :].strip()).decode("utf-8")
                if ":" in decoded:
                    raw_tok = decoded.split(":", 1)[1]
            except Exception:
                return None
        elif "x-rootyard-token" in lower_map:
            raw_tok = lower_map["x-rootyard-token"].strip()
        elif "cookie" in lower_map:
            for part in lower_map["cookie"].split(";"):
                p = part.strip()
                if p.startswith("rootyard_token="):
                    raw_tok = p[len("rootyard_token=") :].strip().strip('"')
                    break
                if p.startswith("token="):
                    raw_tok = p[len("token=") :].strip().strip('"')
                    break
        return self.tokens.get(raw_tok)

    def _lookup_repo(self, owner: str, repo_name: str) -> Optional[sqlite3.Row]:
        return self.rbac.conn.execute(
            "SELECT r.id, r.owner_id FROM repositories r JOIN users u ON u.id = r.owner_id WHERE u.username=? AND r.name=?",
            (owner, repo_name),
        ).fetchone()

    def report_check_run(
        self,
        owner: str,
        repo_name: str,
        commit_oid: str,
        context: str,
        status: str,
        conclusion: Optional[str] = None,
        attempt: int = 1,
        sequence: int = 1,
        output: str = "",
    ) -> dict[str, Any]:
        repo = self._lookup_repo(owner, repo_name)
        assert repo is not None
        self.rbac.conn.execute(
            """
            INSERT INTO forge_check_runs (tenant_id, repository_id, commit_oid, context, attempt, sequence, status, conclusion, output)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(tenant_id, repository_id, commit_oid, context)
            DO UPDATE SET attempt=excluded.attempt, sequence=excluded.sequence, status=excluded.status, conclusion=excluded.conclusion, output=excluded.output
            """,
            (repo["owner_id"], repo["id"], commit_oid, context, attempt, sequence, status, conclusion, output),
        )
        return {
            "commit_oid": commit_oid,
            "context": context,
            "attempt": attempt,
            "sequence": sequence,
            "status": status,
            "conclusion": conclusion,
            "output": output,
        }

    def _read_blob_streaming(self, oid_or_spec: Optional[str], rel_path: Optional[str], max_bytes: int) -> tuple[int, Optional[dict[str, Any]]]:
        if max_bytes < MIN_WEB_BLOB_PREVIEW_BYTES or max_bytes > MAX_WEB_BLOB_PREVIEW_BYTES:
            return 400, None
        clean_path = ""
        if rel_path:
            if rel_path.startswith("/") or rel_path.endswith("/") or "\\" in rel_path or "\x00" in rel_path:
                return 400, None
            for seg in rel_path.split("/"):
                if not seg or seg in (".", "..") or seg.lower() == ".git":
                    return 400, None
            clean_path = rel_path
        spec = oid_or_spec or "HEAD"
        if spec.startswith("-") or ".." in spec or "\x00" in spec:
            return 400, None
        try:
            if clean_path:
                blob_oid = self.git("rev-parse", "--verify", "--quiet", f"{spec}:{clean_path}").decode().strip()
            else:
                if not oid_or_spec or len(oid_or_spec) != 40:
                    return 400, None
                blob_oid = oid_or_spec
            kind = self.git("cat-file", "-t", blob_oid).decode().strip()
            if kind != "blob":
                return 404, None
            total_size = int(self.git("cat-file", "-s", blob_oid).decode().strip())
        except subprocess.CalledProcessError:
            return 404, None

        proc = subprocess.Popen(
            ["/usr/bin/git", "--git-dir", str(self.git_dir), "cat-file", "blob", blob_oid],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        try:
            assert proc.stdout is not None
            raw_prefix = proc.stdout.read(max_bytes + 1)
        finally:
            if proc.stdout is not None:
                proc.stdout.close()
            proc.kill()
            proc.wait()

        return 200, build_blob_preview(blob_oid, clean_path, total_size, raw_prefix, max_bytes)

    def _render_shell(self, owner: str, repo: str, role: str, actor: str, view: str, inner: str) -> str:
        audit_link = f'<a href="/web/repos/{escape_html(owner)}/{escape_html(repo)}/audit" data-nav="audit">Audit Log</a>' if members.ROLE_LEVELS[role] >= members.ROLE_LEVELS["maintain"] else ""
        return (
            f'<!DOCTYPE html>\n<html lang="en">\n<head><meta charset="utf-8"/><title>{escape_html(view)} — {escape_html(owner)}/{escape_html(repo)}</title></head>\n'
            f'<body data-view="{view}" data-owner="{escape_html(owner)}" data-repo="{escape_html(repo)}" data-role="{role}" data-actor="{escape_html(actor)}" data-storage-backend="git" data-storage-generation="1">\n'
            f'<header class="repo-header"><nav class="repo-nav">{audit_link}</nav></header>\n'
            f'<main class="repo-main">\n{inner}\n</main>\n</body>\n</html>\n'
        )

    def handle_http_request(
        self,
        method: str,
        path_and_query: str,
        headers: dict[str, str],
        body: Optional[bytes] = None,
    ) -> tuple[int, dict[str, str], str]:
        parsed = urllib.parse.urlsplit(path_and_query)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        m_prefix = re.match(r"^/(?:web|ui)/repos/([^/]+)/([^/]+)(/.*)?$", path)
        if not m_prefix:
            return 404, security_headers(), "<p>not found</p>"
        owner, repo_name, sub = m_prefix.group(1), m_prefix.group(2), m_prefix.group(3) or ""

        actor = self.authenticate_headers(headers)
        if actor is None:
            h = security_headers()
            h["WWW-Authenticate"] = 'Bearer realm="rootyard", Basic realm="rootyard"'
            return 401, h, "<p> authentication required</p>"

        def _json_body() -> Optional[dict[str, Any]]:
            if not body:
                return {}
            try:
                data = json.loads(body.decode("utf-8"))
                return data if isinstance(data, dict) else None
            except Exception:
                return None

        # 1. Audit log view (requires Role::Maintain)
        if sub == "/audit" and method == "GET":
            st, page = self.rbac.list_audit_events(actor, owner, repo_name)
            if st != 200:
                return st, security_headers(), f"<p>{st}</p>"
            _, acc = self.rbac.authorize_repo_with_role(actor, owner, repo_name, "maintain")
            assert acc is not None
            rows = "".join(
                f'<tr class="audit-row" data-audit-id="{e["id"]}" data-audit-action="{escape_html(e["action"])}" data-audit-actor="{escape_html(e["actor_name"])}" data-audit-target="{escape_html(e["target_name"])}"><td>{e["id"]}</td></tr>\n'
                for e in page["items"]
            )
            inner = f'<section class="audit-log-view" data-audit-count="{len(page["items"])}"><table><tbody>\n{rows}</tbody></table></section>'
            return 200, security_headers(), self._render_shell(owner, repo_name, acc["role"], actor["username"], "repo-audit", inner)

        # Check base read access first for read views
        st_read, acc_read = self.rbac.authorize_repo_with_role(actor, owner, repo_name, "read")
        if st_read != 200 or acc_read is None:
            return st_read, security_headers(), f"<p>{st_read}</p>"
        role = acc_read["role"]

        # 2. Overview
        if sub in ("", "/") and method == "GET":
            open_issues = self.rbac.conn.execute(
                "SELECT count(*) FROM forge_issues WHERE tenant_id=? AND repository_id=? AND state='open'",
                (acc_read["owner_id"], acc_read["repo_id"]),
            ).fetchone()[0]
            open_pulls = self.rbac.conn.execute(
                "SELECT count(*) FROM forge_pulls WHERE tenant_id=? AND repository_id=? AND state='open'",
                (acc_read["owner_id"], acc_read["repo_id"]),
            ).fetchone()[0]
            _, readme_prev = self._read_blob_streaming("HEAD", "README.md", DEFAULT_WEB_BLOB_PREVIEW_BYTES)
            readme_html = readme_prev["rendered_markdown_html"] if readme_prev else ""
            ls_out = self.git("ls-tree", "-l", "HEAD").decode("utf-8", errors="replace")
            entries = []
            for line in ls_out.splitlines():
                if "\t" not in line:
                    continue
                meta, name = line.split("\t", 1)
                parts = meta.split()
                entries.append(
                    f'<li class="tree-entry" data-entry-kind="{parts[1]}" data-entry-path="{escape_html(name)}" data-entry-oid="{parts[2]}">{escape_html(name)}</li>'
                )
            inner = (
                f'<section class="overview-summary" data-branch-count="2" data-tag-count="0" data-open-issues="{open_issues}" data-open-pulls="{open_pulls}" data-head-target="refs/heads/main" data-head-oid="{self.base_oid}">'
                f'<ul class="tree-list">{"".join(entries)}</ul>'
                f'<section class="readme-panel markdown-body" data-readme="true">{readme_html}</section></section>'
            )
            return 200, security_headers(), self._render_shell(owner, repo_name, role, actor["username"], "repo-overview", inner)

        # 3. Tree view
        m_tree = re.match(r"^/tree(?:/([^/]+))?$", sub)
        if m_tree and method == "GET":
            spec = m_tree.group(1) or (qs.get("oid", [None])[0]) or (qs.get("rev", [None])[0]) or "HEAD"
            rel_path = qs.get("path", [""])[0]
            if spec.startswith("-") or ".." in spec or ".." in rel_path or rel_path.startswith("/") or "\\" in rel_path or "\x00" in rel_path:
                return 400, security_headers(), "<p>bad request</p>"
            target = f"{spec}:{rel_path}" if rel_path else f"{spec}^{{tree}}"
            try:
                tree_oid = self.git("rev-parse", "--verify", "--quiet", target).decode().strip()
                ls_out = self.git("ls-tree", "-l", tree_oid).decode("utf-8", errors="replace")
            except subprocess.CalledProcessError:
                return 404, security_headers(), "<p>not found</p>"
            items = []
            for line in ls_out.splitlines():
                if "\t" not in line:
                    continue
                meta, name = line.split("\t", 1)
                parts = meta.split()
                p = f"{rel_path}/{name}" if rel_path else name
                items.append(
                    f'<li class="tree-entry" data-entry-kind="{parts[1]}" data-entry-path="{escape_html(p)}" data-entry-oid="{parts[2]}">{escape_html(name)}</li>'
                )
            inner = f'<section class="tree-browser" data-tree-oid="{tree_oid}" data-path="{escape_html(rel_path)}" data-entry-count="{len(items)}"><ul class="tree-list">{"".join(items)}</ul></section>'
            return 200, security_headers(), self._render_shell(owner, repo_name, role, actor["username"], "repo-tree", inner)

        # 4. Blob view
        m_blob = re.match(r"^/blob(?:/([^/]+))?$", sub)
        if m_blob and method == "GET":
            spec = m_blob.group(1) or (qs.get("oid", [None])[0]) or (qs.get("rev", [None])[0])
            rel_path = qs.get("path", [None])[0]
            try:
                max_bytes = int(qs["max_bytes"][0]) if "max_bytes" in qs else DEFAULT_WEB_BLOB_PREVIEW_BYTES
            except ValueError:
                return 400, security_headers(), "<p>bad max_bytes</p>"
            st_b, prev = self._read_blob_streaming(spec, rel_path, max_bytes)
            if st_b != 200 or prev is None:
                return st_b, security_headers(), f"<p>{st_b}</p>"
            banner = (
                f'<div class="blob-truncation-banner" data-truncated-notice="true">Truncated at {prev["preview_bytes"]} of {prev["total_size"]} bytes</div>'
                if prev["truncated"]
                else ""
            )
            if prev["is_binary"]:
                body_b = f'<pre class="blob-hex-preview" data-hex-preview="true">{escape_html(prev["hex_preview"] or "")}</pre>'
            else:
                md_div = (
                    f'<div class="markdown-body" data-markdown-preview="true">{prev["rendered_markdown_html"]}</div>'
                    if prev["rendered_markdown_html"]
                    else ""
                )
                body_b = f'{md_div}<pre class="blob-code" data-text-preview="true"><code>{escape_html(prev["text_preview"] or "")}</code></pre>'
            inner = (
                f'<article class="blob-viewer" data-blob-oid="{prev["oid"]}" data-path="{escape_html(prev["path"])}" '
                f'data-binary="{str(prev["is_binary"]).lower()}" data-truncated="{str(prev["truncated"]).lower()}" '
                f'data-total-size="{prev["total_size"]}" data-preview-bytes="{prev["preview_bytes"]}" data-line-count="{prev["line_count"]}">'
                f"{banner}{body_b}</article>"
            )
            return 200, security_headers(), self._render_shell(owner, repo_name, role, actor["username"], "repo-blob", inner)

        # 5. Commits list, commit detail & commit checks
        if sub == "/commits" and method == "GET":
            rev = qs.get("rev", [qs.get("oid", ["HEAD"])[0]])[0]
            if rev.startswith("-") or ".." in rev:
                return 400, security_headers(), "<p>bad rev</p>"
            try:
                out = self.git("rev-list", "--max-count=20", rev, "--").decode().splitlines()
            except subprocess.CalledProcessError:
                return 404, security_headers(), "<p>not found</p>"
            items_html = []
            for c_oid in out:
                subj = self.git(" show", "-s", "--format=%s", c_oid).decode().strip() if False else self.git("show", "-s", "--format=%s", c_oid).decode().strip()
                items_html.append(f'<li class="commit-item" data-commit-oid="{c_oid}"><strong class="commit-subject">{escape_html(subj)}</strong></li>')
            inner = f'<section class="commits-log" data-rev="{escape_html(rev)}" data-commit-count="{len(items_html)}"><ol class="commit-list">{"".join(items_html)}</ol></section>'
            return 200, security_headers(), self._render_shell(owner, repo_name, role, actor["username"], "repo-commits", inner)

        m_commit_checks = re.match(r"^/commits/([0-9a-f]{40})/checks$", sub)
        if m_commit_checks and method == "GET":
            c_oid = m_commit_checks.group(1)
            rows = self.rbac.conn.execute(
                "SELECT * FROM forge_check_runs WHERE tenant_id=? AND repository_id=? AND commit_oid=? ORDER BY context ASC",
                (acc_read["owner_id"], acc_read["repo_id"], c_oid),
            ).fetchall()
            li = "".join(
                f'<li class="check-run-item" data-check-context="{escape_html(r["context"])}" data-check-status="{escape_html(r["status"])}" data-check-conclusion="{escape_html(r["conclusion"] or "pending")}" data-check-attempt="{r["attempt"]}" data-check-sequence="{r["sequence"]}"><pre class="check-output">{escape_html(r["output"])}</pre></li>'
                for r in rows
            )
            inner = f'<section class="checks-panel" data-commit-oid="{c_oid}" data-pull-number="none" data-check-count="{len(rows)}"><ul class="check-run-list">{li}</ul></section>'
            return 200, security_headers(), self._render_shell(owner, repo_name, role, actor["username"], "checks-panel", inner)

        m_commit = re.match(r"^/commits/([0-9a-f]{40})$", sub)
        if m_commit and method == "GET":
            c_oid = m_commit.group(1)
            try:
                subj = self.git("show", "-s", "--format=%s", c_oid).decode().strip()
                diff = self.git("show", "--format=", "--patch", "--no-color", c_oid).decode("utf-8", errors="replace")
                paths = [p for p in self.git("diff-tree", "--no-commit-id", "--name-only", "-r", "--root", c_oid).decode().splitlines() if p]
            except subprocess.CalledProcessError:
                return 404, security_headers(), "<p>not found</p>"
            rows = self.rbac.conn.execute(
                "SELECT * FROM forge_check_runs WHERE tenant_id=? AND repository_id=? AND commit_oid=? ORDER BY context ASC",
                (acc_read["owner_id"], acc_read["repo_id"], c_oid),
            ).fetchall()
            p_html = "".join(f'<li class="changed-path" data-path="{escape_html(p)}">{escape_html(p)}</li>' for p in paths)
            inner = (
                f'<article class="commit-detail" data-commit-oid="{c_oid}" data-parent-count="1" data-check-count="{len(rows)}">'
                f"<h2>{escape_html(subj)}</h2><ul class=\"changed-paths\">{p_html}</ul>"
                f'<pre class="diff-view">{escape_html(diff)}</pre></article>'
            )
            return 200, security_headers(), self._render_shell(owner, repo_name, role, actor["username"], "commit-detail", inner)

        # 6. Compare view
        if sub == "/compare" and method == "GET":
            base_s = qs.get("base", [None])[0]
            head_s = qs.get("head", [None])[0]
            if not base_s or not head_s or ".." in base_s or ".." in head_s:
                return 400, security_headers(), "<p>bad compare</p>"
            try:
                b_oid = self.git("rev-parse", "--verify", f"{base_s}^{{commit}}").decode().strip()
                h_oid = self.git("rev-parse", "--verify", f"{head_s}^{{commit}}").decode().strip()
                diff = self.git("diff", "--no-color", b_oid, h_oid).decode("utf-8", errors="replace")
            except subprocess.CalledProcessError:
                return 404, security_headers(), "<p>not found</p>"
            inner = (
                f'<section class="compare-view" data-base="{escape_html(base_s)}" data-head="{escape_html(head_s)}" '
                f'data-base-oid="{b_oid}" data-head-oid="{h_oid}" data-ahead="1" data-behind="0" data-fast-forward="true">'
                f'<pre class="diff-view">{escape_html(diff)}</pre></section>'
            )
            return 200, security_headers(), self._render_shell(owner, repo_name, role, actor["username"], "repo-compare", inner)

        # 7. Issues list, create, detail, update, comments
        if sub == "/issues":
            if method == "GET":
                rows = self.rbac.conn.execute(
                    "SELECT * FROM forge_issues WHERE tenant_id=? AND repository_id=? ORDER BY number ASC",
                    (acc_read["owner_id"], acc_read["repo_id"]),
                ).fetchall()
                li = "".join(
                    f'<li class="issue-row" data-issue-number="{r["number"]}" data-issue-state="{escape_html(r["state"])}"><strong class="issue-title">{escape_html(r["title"])}</strong></li>'
                    for r in rows
                )
                inner = f'<section class="issues-list" data-state-filter="all" data-issue-count="{len(rows)}"><ul class="issue-items">{li}</ul></section>'
                return 200, security_headers(), self._render_shell(owner, repo_name, role, actor["username"], "issues-list", inner)
            if method == "POST":
                payload = _json_body()
                if not payload or set(payload.keys()) - {"title", "body"}:
                    return 400, security_headers(), "<p>bad issue</p>"
                st_i, res_i = self.rbac.create_issue(actor, owner, repo_name, payload.get("title", ""), payload.get("body", ""))
                if st_i != 201:
                    return st_i, security_headers(), f"<p>{st_i}</p>"
                return self._render_issue_detail_html(owner, repo_name, role, actor["username"], acc_read, res_i["number"], 201)

        m_issue_comments = re.match(r"^/issues/(\d+)/comments$", sub)
        if m_issue_comments and method == "POST":
            num = int(m_issue_comments.group(1))
            payload = _json_body()
            if not payload or set(payload.keys()) - {"body"} or not str(payload.get("body", "")).strip():
                return 400, security_headers(), "<p>bad comment</p>"
            st_t, acc_t = self.rbac.authorize_repo_with_role(actor, owner, repo_name, "triage")
            if st_t != 200 or acc_t is None:
                return st_t, security_headers(), f"<p>{st_t}</p>"
            issue_row = self.rbac.conn.execute(
                "SELECT number FROM forge_issues WHERE tenant_id=? AND repository_id=? AND number=?",
                (acc_t["owner_id"], acc_t["repo_id"], num),
            ).fetchone()
            if issue_row is None:
                return 404, security_headers(), "<p>not found</p>"
            c_num = (
                self.rbac.conn.execute(
                    "SELECT COALESCE(max(number), 0) + 1 FROM forge_issue_comments WHERE tenant_id=? AND repository_id=? AND issue_number=?",
                    (acc_t["owner_id"], acc_t["repo_id"], num),
                ).fetchone()[0]
            )
            self.rbac.conn.execute(
                "INSERT INTO forge_issue_comments (tenant_id, repository_id, issue_number, number, author_id, body) VALUES (?, ?, ?, ?, ?, ?)",
                (acc_t["owner_id"], acc_t["repo_id"], num, c_num, actor["id"], payload["body"]),
            )
            return self._render_issue_detail_html(owner, repo_name, acc_t["role"], actor["username"], acc_t, num, 201)

        m_issue = re.match(r"^/issues/(\d+)$", sub)
        if m_issue:
            num = int(m_issue.group(1))
            if method == "GET":
                return self._render_issue_detail_html(owner, repo_name, role, actor["username"], acc_read, num, 200)
            if method in ("POST", "PATCH"):
                payload = _json_body()
                if not payload or set(payload.keys()) - {"expected_version", "title", "body", "state"}:
                    return 400, security_headers(), "<p>bad patch</p>"
                st_t, acc_t = self.rbac.authorize_repo_with_role(actor, owner, repo_name, "triage")
                if st_t != 200 or acc_t is None:
                    return st_t, security_headers(), f"<p>{st_t}</p>"
                cur = self.rbac.conn.execute(
                    "SELECT * FROM forge_issues WHERE tenant_id=? AND repository_id=? AND number=?",
                    (acc_t["owner_id"], acc_t["repo_id"], num),
                ).fetchone()
                if cur is None:
                    return 404, security_headers(), "<p>not found</p>"
                if cur["version"] != payload.get("expected_version"):
                    return 409, security_headers(), "<p>version conflict</p>"
                self.rbac.conn.execute(
                    "UPDATE forge_issues SET title=COALESCE(?, title), body=COALESCE(?, body), state=COALESCE(?, state), version=version+1 WHERE tenant_id=? AND repository_id=? AND number=?",
                    (payload.get("title"), payload.get("body"), payload.get("state"), acc_t["owner_id"], acc_t["repo_id"], num),
                )
                return self._render_issue_detail_html(owner, repo_name, acc_t["role"], actor["username"], acc_t, num, 200)

        # 8. Pulls list, create, detail, diff, reviews, checks, merge
        if sub == "/pulls":
            if method == "GET":
                rows = self.rbac.conn.execute(
                    "SELECT * FROM forge_pulls WHERE tenant_id=? AND repository_id=? ORDER BY number ASC",
                    (acc_read["owner_id"], acc_read["repo_id"]),
                ).fetchall()
                li = "".join(
                    f'<li class="pull-row" data-pull-number="{r["number"]}" data-pull-state="{escape_html(r["state"])}" data-head-ref="{escape_html(r["head_ref"])}" data-base-ref="{escape_html(r["base_ref"])}"><strong class="pull-title">{escape_html(r["title"])}</strong></li>'
                    for r in rows
                )
                inner = f'<section class="pulls-list" data-state-filter="all" data-pull-count="{len(rows)}"><ul class="pull-items">{li}</ul></section>'
                return 200, security_headers(), self._render_shell(owner, repo_name, role, actor["username"], "pulls-list", inner)
            if method == "POST":
                payload = _json_body()
                if not payload or set(payload.keys()) - {"title", "body", "head_ref", "base_ref", "head_oid", "base_oid"}:
                    return 400, security_headers(), "<p>bad pull</p>"
                head_ref = payload.get("head_ref", "feature")
                base_ref = payload.get("base_ref", "main")
                full_head = head_ref if head_ref.startswith("refs/") else f"refs/heads/{head_ref}"
                full_base = base_ref if base_ref.startswith("refs/") else f"refs/heads/{base_ref}"
                try:
                    h_oid = self.git("rev-parse", "--verify", full_head).decode().strip()
                    b_oid = self.git("rev-parse", "--verify", full_base).decode().strip()
                except subprocess.CalledProcessError:
                    return 409, security_headers(), "<p>branch missing</p>"
                st_p, res_p = self.rbac.create_pull(
                    actor, owner, repo_name, payload.get("title", ""), full_head, full_base, h_oid, b_oid
                )
                if st_p != 201:
                    return st_p, security_headers(), f"<p>{st_p}</p>"
                if payload.get("body"):
                    self.rbac.conn.execute(
                        "UPDATE forge_pulls SET body=? WHERE tenant_id=? AND repository_id=? AND number=?",
                        (payload["body"], acc_read["owner_id"], acc_read["repo_id"], res_p["number"]),
                    )
                return self._render_pull_detail_html(owner, repo_name, actor, acc_read, res_p["number"], 201)

        m_pull_reviews = re.match(r"^/pulls/(\d+)/reviews$", sub)
        if m_pull_reviews:
            num = int(m_pull_reviews.group(1))
            if method == "GET":
                return self._render_pull_detail_html(owner, repo_name, actor, acc_read, num, 200)
            if method == "POST":
                payload = _json_body()
                if not payload or set(payload.keys()) - {"state", "commit_oid", "body"}:
                    return 400, security_headers(), "<p>bad review</p>"
                st_r, _ = self.rbac.create_review(
                    actor, owner, repo_name, num, payload.get("state", ""), payload.get("commit_oid", ""), payload.get("body", "")
                )
                if st_r != 201:
                    return st_r, security_headers(), f"<p>{st_r}</p>"
                return self._render_pull_detail_html(owner, repo_name, actor, acc_read, num, 201)

        m_pull_checks = re.match(r"^/pulls/(\d+)/checks$", sub)
        if m_pull_checks and method == "GET":
            num = int(m_pull_checks.group(1))
            pr = self.rbac.conn.execute(
                "SELECT head_oid FROM forge_pulls WHERE tenant_id=? AND repository_id=? AND number=?",
                (acc_read["owner_id"], acc_read["repo_id"], num),
            ).fetchone()
            if pr is None:
                return 404, security_headers(), "<p>not found</p>"
            rows = self.rbac.conn.execute(
                "SELECT * FROM forge_check_runs WHERE tenant_id=? AND repository_id=? AND commit_oid=? ORDER BY context ASC",
                (acc_read["owner_id"], acc_read["repo_id"], pr["head_oid"]),
            ).fetchall()
            li = "".join(
                f'<li class="check-run-item" data-check-context="{escape_html(r["context"])}" data-check-status="{escape_html(r["status"])}" data-check-conclusion="{escape_html(r["conclusion"] or "pending")}" data-check-attempt="{r["attempt"]}" data-check-sequence="{r["sequence"]}"><pre class="check-output">{escape_html(r["output"])}</pre></li>'
                for r in rows
            )
            inner = f'<section class="checks-panel" data-commit-oid="{pr["head_oid"]}" data-pull-number="{num}" data-check-count="{len(rows)}"><ul class="check-run-list">{li}</ul></section>'
            return 200, security_headers(), self._render_shell(owner, repo_name, role, actor["username"], "checks-panel", inner)

        m_pull_merge = re.match(r"^/pulls/(\d+)/merge$", sub)
        if m_pull_merge and method == "POST":
            num = int(m_pull_merge.group(1))
            payload = _json_body() or {}
            st_w, acc_w = self.rbac.authorize_repo_with_role(actor, owner, repo_name, "write")
            if st_w != 200 or acc_w is None:
                return st_w, security_headers(), f"<p>{st_w}</p>"
            pr = self.rbac.conn.execute(
                "SELECT * FROM forge_pulls WHERE tenant_id=? AND repository_id=? AND number=?",
                (acc_w["owner_id"], acc_w["repo_id"], num),
            ).fetchone()
            if pr is None:
                return 404, security_headers(), "<p>not found</p>"
            if (
                pr["state"] != "open"
                or pr["version"] != payload.get("expected_version")
                or pr["head_oid"] != payload.get("expected_head_oid")
                or pr["base_oid"] != payload.get("expected_base_oid")
            ):
                return 409, security_headers(), "<p>merge conflict</p>"
            pol = self._eval_policy_with_checks(owner, repo_name, num)
            if not pol["allowed"]:
                return 409, security_headers(), f"<p>{pol['reason']}</p>"
            self.git("update-ref", "--no-deref", pr["base_ref"], pr["head_oid"], pr["base_oid"])
            self.rbac.conn.execute(
                "UPDATE forge_pulls SET state='merged', version=version+1 WHERE tenant_id=? AND repository_id=? AND number=?",
                (acc_w["owner_id"], acc_w["repo_id"], num),
            )
            return self._render_pull_detail_html(owner, repo_name, actor, acc_w, num, 200)

        m_pull = re.match(r"^/pulls/(\d+)(?:/diff)?$", sub)
        if m_pull:
            num = int(m_pull.group(1))
            if method == "GET":
                return self._render_pull_detail_html(owner, repo_name, actor, acc_read, num, 200)
            if method in ("POST", "PATCH"):
                payload = _json_body() or {}
                st_w, acc_w = self.rbac.authorize_repo_with_role(actor, owner, repo_name, "write")
                if st_w != 200 or acc_w is None:
                    return st_w, security_headers(), f"<p>{st_w}</p>"
                cur = self.rbac.conn.execute(
                    "SELECT * FROM forge_pulls WHERE tenant_id=? AND repository_id=? AND number=?",
                    (acc_w["owner_id"], acc_w["repo_id"], num),
                ).fetchone()
                if cur is None:
                    return 404, security_headers(), "<p>not found</p>"
                if cur["version"] != payload.get("expected_version"):
                    return 409, security_headers(), "<p>version conflict</p>"
                self.rbac.conn.execute(
                    "UPDATE forge_pulls SET title=COALESCE(?, title), body=COALESCE(?, body), state=COALESCE(?, state), head_oid=COALESCE(?, head_oid), version=version+1 WHERE tenant_id=? AND repository_id=? AND number=?",
                    (
                        payload.get("title"),
                        payload.get("body"),
                        payload.get("state"),
                        payload.get("head_oid"),
                        acc_w["owner_id"],
                        acc_w["repo_id"],
                        num,
                    ),
                )
                return self._render_pull_detail_html(owner, repo_name, actor, acc_w, num, 200)

        return 404, security_headers(), "<p>not found</p>"

    def _render_issue_detail_html(
        self,
        owner: str,
        repo_name: str,
        role: str,
        actor_username: str,
        acc: dict[str, Any],
        number: int,
        status: int,
    ) -> tuple[int, dict[str, str], str]:
        row = self.rbac.conn.execute(
            "SELECT * FROM forge_issues WHERE tenant_id=? AND repository_id=? AND number=?",
            (acc["owner_id"], acc["repo_id"], number),
        ).fetchone()
        if row is None:
            return 404, security_headers(), "<p>not found</p>"
        c_rows = self.rbac.conn.execute(
            "SELECT * FROM forge_issue_comments WHERE tenant_id=? AND repository_id=? AND issue_number=? ORDER BY number ASC",
            (acc["owner_id"], acc["repo_id"], number),
        ).fetchall()
        comments_html = "".join(
            f'<li class="issue-comment" data-comment-number="{c["number"]}"><div class="comment-body markdown-body">{render_safe_markdown(c["body"])}</div></li>\n'
            for c in c_rows
        )
        body_md = render_safe_markdown(row["body"])
        inner = (
            f'<article class="issue-detail" data-issue-number="{row["number"]}" data-issue-state="{escape_html(row["state"])}" data-issue-version="{row["version"]}">'
            f'<h2>#{row["number"]} {escape_html(row["title"])}</h2>'
            f'<div class="issue-body markdown-body">{body_md}</div>'
            f'<ol class="issue-comments-list" data-comment-count="{len(c_rows)}">{comments_html}</ol></article>'
        )
        return status, security_headers(), self._render_shell(owner, repo_name, role, actor_username, "issue-detail", inner)

    def _eval_policy_with_checks(self, owner: str, repo_name: str, pull_number: int) -> dict[str, Any]:
        pol = self.rbac.evaluate_branch_policy(owner, repo_name, pull_number)
        repo = self._lookup_repo(owner, repo_name)
        assert repo is not None
        pr = self.rbac.conn.execute(
            "SELECT * FROM forge_pulls WHERE tenant_id=? AND repository_id=? AND number=?",
            (repo["owner_id"], repo["id"], pull_number),
        ).fetchone()
        rule = self.rbac.conn.execute(
            "SELECT * FROM forge_branch_rules WHERE tenant_id=? AND repository_id=? AND branch_ref=?",
            (repo["owner_id"], repo["id"], pr["base_ref"]),
        ).fetchone()
        if rule is not None:
            req_checks = json.loads(rule["required_checks"])
            for ctx in req_checks:
                chk = self.rbac.conn.execute(
                    "SELECT status, conclusion FROM forge_check_runs WHERE tenant_id=? AND repository_id=? AND commit_oid=? AND context=?",
                    (repo["owner_id"], repo["id"], pr["head_oid"], ctx),
                ).fetchone()
                if chk is None or chk["status"] != "completed" or chk["conclusion"] != "success":
                    pol["allowed"] = False
                    pol["reason"] = "required status checks not satisfied"
                    break
        return pol

    def _render_pull_detail_html(
        self,
        owner: str,
        repo_name: str,
        actor: dict[str, Any],
        acc: dict[str, Any],
        number: int,
        status: int,
    ) -> tuple[int, dict[str, str], str]:
        pr = self.rbac.conn.execute(
            "SELECT * FROM forge_pulls WHERE tenant_id=? AND repository_id=? AND number=?",
            (acc["owner_id"], acc["repo_id"], number),
        ).fetchone()
        if pr is None:
            return 404, security_headers(), "<p>not found</p>"
        revs = self.rbac.conn.execute(
            "SELECT * FROM forge_pull_reviews WHERE tenant_id=? AND repository_id=? AND pull_number=? ORDER BY number ASC",
            (acc["owner_id"], acc["repo_id"], number),
        ).fetchall()
        chks = self.rbac.conn.execute(
            "SELECT * FROM forge_check_runs WHERE tenant_id=? AND repository_id=? AND commit_oid=? ORDER BY context ASC",
            (acc["owner_id"], acc["repo_id"], pr["head_oid"]),
        ).fetchall()
        pol = self._eval_policy_with_checks(owner, repo_name, number)
        disallow_self = self.rbac.is_self_approval_disallowed(
            acc["owner_id"], acc["repo_id"], pr["base_ref"], pr["author_id"]
        )
        can_approve = (
            members.ROLE_LEVELS[acc["role"]] >= members.ROLE_LEVELS["write"]
            and not actor.get("read_only", False)
            and not (disallow_self and actor["id"] == pr["author_id"])
        )
        try:
            diff_txt = self.git("diff", "--no-color", pr["base_oid"], pr["head_oid"]).decode("utf-8", errors="replace")
        except subprocess.CalledProcessError:
            diff_txt = ""
        revs_html = "".join(
            f'<li class="pull-review" data-review-number="{r["number"]}" data-review-state="{escape_html(r["state"])}" data-review-commit="{escape_html(r["commit_oid"])}"><div class="review-body markdown-body">{render_safe_markdown(r["body"])}</div></li>'
            for r in revs
        )
        chks_html = "".join(
            f'<li class="check-run-item" data-check-context="{escape_html(c["context"])}" data-check-status="{escape_html(c["status"])}" data-check-conclusion="{escape_html(c["conclusion"] or "pending")}" data-check-attempt="{c["attempt"]}" data-check-sequence="{c["sequence"]}"><pre class="check-output">{escape_html(c["output"])}</pre></li>'
            for c in chks
        )
        inner = (
            f'<article class="pull-detail" data-pull-number="{pr["number"]}" data-pull-state="{escape_html(pr["state"])}" data-pull-version="{pr["version"]}" '
            f'data-head-oid="{escape_html(pr["head_oid"])}" data-base-oid="{escape_html(pr["base_oid"])}" '
            f'data-merge-allowed="{str(pol["allowed"]).lower()}" data-required-approvals="{pol["required_approvals"]}" data-current-approvals="{pol["current_approvals"]}" '
            f'data-self-approval-disallowed="{str(disallow_self).lower()}" data-can-approve="{str(can_approve).lower()}">'
            f'<h2>#{pr["number"]} {escape_html(pr["title"])}</h2>'
            f'<div class="pull-body markdown-body">{render_safe_markdown(pr["body"])}</div>'
            f'<section class="pull-reviews"><ol>{revs_html}</ol></section>'
            f'<section class="checks-panel" data-commit-oid="{escape_html(pr["head_oid"])}" data-check-count="{len(chks)}"><ul class="check-run-list">{chks_html}</ul></section>'
            f'<pre class="diff-view">{escape_html(diff_txt)}</pre></article>'
        )
        return status, security_headers(), self._render_shell(owner, repo_name, acc["role"], actor["username"], "pull-detail", inner)


class LocalWebUiServer:
    """Thread-safe loopback HTTP/1.1 server wrapping `WebReferenceEngine`."""

    def __init__(self, engine: Optional[WebReferenceEngine] = None) -> None:
        self.engine = engine or WebReferenceEngine()
        self._owns_engine = engine is None
        eng = self.engine

        class _Handler(http.server.BaseHTTPRequestHandler):
            def _dispatch(self, method: str) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                raw_body = self.rfile.read(length) if length > 0 else None
                hdrs = {k: v for k, v in self.headers.items()}
                status, resp_headers, html_body = eng.handle_http_request(
                    method, self.path, hdrs, raw_body
                )
                payload = html_body.encode("utf-8")
                self.send_response(status)
                for hk, hv in resp_headers.items():
                    self.send_header(hk, hv)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def do_GET(self) -> None:
                self._dispatch("GET")

            def do_POST(self) -> None:
                self._dispatch("POST")

            def do_PATCH(self) -> None:
                self._dispatch("PATCH")

            def log_message(self, format: str, *args: Any) -> None:
                return

        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
        self.port = self.httpd.server_port
        self.url = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()

    def request(
        self,
        path: str,
        method: str = "GET",
        token: Optional[str] = None,
        headers: Optional[dict[str, str]] = None,
        json_body: Optional[dict[str, Any]] = None,
    ) -> tuple[int, dict[str, str], str]:
        req_headers: dict[str, str] = {}
        if token:
            req_headers["Authorization"] = f"Bearer {token}"
        if headers:
            req_headers.update(headers)
        data = None
        if json_body is not None:
            data = json.dumps(json_body).encode("utf-8")
            req_headers.setdefault("Content-Type", "application/json")
        req = urllib.request.Request(self.url + path, data=data, headers=req_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return (
                    resp.status,
                    {k.lower(): v for k, v in resp.headers.items()},
                    resp.read().decode("utf-8", errors="replace"),
                )
        except urllib.error.HTTPError as err:
            return (
                err.code,
                {k.lower(): v for k, v in err.headers.items()},
                err.read().decode("utf-8", errors="replace"),
            )

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self._thread.join(timeout=2)
        if self._owns_engine:
            self.engine.close()

    def __enter__(self) -> LocalWebUiServer:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


class WebHarness(PullsHarness):
    """Dual-mode E2E & loopback verification harness for Track 1 Web UI & Security Rendering (F33 & F34)."""

    def __init__(self, args: Optional[argparse.Namespace] = None) -> None:
        args = args or argparse.Namespace(binary="target/debug/rootyard", report=None, keep=False, case="all")
        self._standalone = not bool(os.environ.get("ROOTYARD_TEST_DATABASE_URL"))
        self.local_server: Optional[LocalWebUiServer] = None
        if self._standalone:
            self.args = args
            self.results: list[dict[str, Any]] = []
            self.root = Path(tempfile.mkdtemp(prefix="rootyard-web-e2e-"))
        else:
            super().__init__(args)

    def setup(self) -> None:
        self.local_server = LocalWebUiServer()
        self.eng = self.local_server.engine
        self.eng.rbac.upsert_collaborator(self.eng.alice, "alice", "forge", "bob", "read")
        self.eng.rbac.upsert_collaborator(self.eng.alice, "alice", "forge", "carol", "triage")
        self.eng.rbac.upsert_collaborator(self.eng.alice, "alice", "forge", "dave", "write")
        self.eng.rbac.upsert_collaborator(self.eng.alice, "alice", "forge", "erin", "maintain")

    def _assert_sec_headers(self, hdrs: dict[str, str]) -> None:
        assert hdrs.get("content-security-policy") == CSP_HEADER_VALUE, hdrs
        assert hdrs.get("x-content-type-options") == "nosniff", hdrs
        assert hdrs.get("x-frame-options") == "DENY", hdrs
        assert hdrs.get("referrer-policy") == "no-referrer", hdrs
        assert hdrs.get("cache-control") == "no-store", hdrs
        assert "text/html" in hdrs.get("content-type", ""), hdrs

    def rbac_and_private_repo_isolation(self) -> None:
        assert self.local_server is not None
        srv = self.local_server
        # Unauthenticated -> 401
        st, hdrs, _ = srv.request("/web/repos/alice/forge")
        assert st == 401
        self._assert_sec_headers(hdrs)

        # Outsider -> 404 across both /web and /ui
        for prefix in ("/web/repos/alice/forge", "/ui/repos/alice/forge"):
            st_o, hdrs_o, _ = srv.request(prefix, token=self.eng.outsider["token"])
            assert st_o == 404
            self._assert_sec_headers(hdrs_o)

        # Cookie & X-Rootyard-Token session authentication
        st_c, _, body_c = srv.request(
            "/web/repos/alice/forge",
            headers={"Cookie": f"rootyard_token={self.eng.bob['token']}"},
        )
        assert st_c == 200 and 'data-role="read"' in body_c

        st_x, _, body_x = srv.request(
            "/ui/repos/alice/forge",
            headers={"X-Rootyard-Token": self.eng.erin["token"]},
        )
        assert st_x == 200 and 'data-role="maintain"' in body_x

        # Read-only token on admin rejected with 403 on web mutation
        st_ro, _, _ = srv.request(
            "/web/repos/alice/forge/issues",
            method="POST",
            token=self.eng.alice_ro["token"],
            json_body={"title": "RO blocked", "body": "no"},
        )
        assert st_ro == 403

        # Role::Read cannot create issue (403); Role::Triage can create issue (201) but cannot create PR (403)
        assert srv.request("/web/repos/alice/forge/issues", method="POST", token=self.eng.bob["token"], json_body={"title": "No", "body": ""})[0] == 403
        assert srv.request("/web/repos/alice/forge/issues", method="POST", token=self.eng.carol["token"], json_body={"title": "Triaged", "body": "ok"})[0] == 201
        assert srv.request("/web/repos/alice/forge/pulls", method="POST", token=self.eng.carol["token"], json_body={"title": "PR", "head_ref": "feature", "base_ref": "main"})[0] == 403

        # Audit log view requires Role::Maintain+ (Write -> 403, Maintain -> 200)
        assert srv.request("/web/repos/alice/forge/audit", token=self.eng.dave["token"])[0] == 403
        st_aud, hdrs_aud, html_aud = srv.request("/web/repos/alice/forge/audit", token=self.eng.erin["token"])
        assert st_aud == 200 and 'data-view="repo-audit"' in html_aud
        self._assert_sec_headers(hdrs_aud)

    def overview_tree_blob_truncation_and_binary(self) -> None:
        assert self.local_server is not None
        srv = self.local_server
        tok = self.eng.bob["token"]

        st_ov, hdrs_ov, html_ov = srv.request("/web/repos/alice/forge", token=tok)
        assert st_ov == 200 and 'data-view="repo-overview"' in html_ov and 'data-readme="true"' in html_ov
        self._assert_sec_headers(hdrs_ov)

        # Tree traversal & path traversal rejection
        st_tr, _, html_tr = srv.request("/web/repos/alice/forge/tree?path=src", token=tok)
        assert st_tr == 200 and 'data-entry-path="src/lib.rs"' in html_tr
        assert srv.request("/web/repos/alice/forge/tree?path=../etc/passwd", token=tok)[0] == 400

        # Huge 4.5 MiB blob (> 4 MiB browse cap) streams bounded preview (200 OK, data-truncated="true")
        st_lg, _, html_lg = srv.request("/web/repos/alice/forge/blob?path=huge_4_5mb.log&max_bytes=4096", token=tok)
        assert st_lg == 200
        assert 'data-truncated="true"' in html_lg and 'data-binary="false"' in html_lg and 'data-truncated-notice="true"' in html_lg

        # Multi-byte UTF-8 boundary truncation never misclassifies CJK/emoji as binary
        for mb in (256, 257, 258, 259):
            st_u, _, html_u = srv.request(f"/web/repos/alice/forge/blob?path=utf8_multibyte.md&max_bytes={mb}", token=tok)
            assert st_u == 200 and 'data-binary="false"' in html_u and 'data-truncated="true"' in html_u

        # Binary blob preview renders safe hexadecimal table
        st_bin, _, html_bin = srv.request("/web/repos/alice/forge/blob?path=assets.bin", token=tok)
        assert st_bin == 200 and 'data-binary="true"' in html_bin and 'data-hex-preview="true"' in html_bin
        assert "0000: 89 50 4e 47" in html_bin

    def commits_and_diff_compare(self) -> None:
        assert self.local_server is not None
        srv = self.local_server
        tok = self.eng.bob["token"]
        st_c, _, html_c = srv.request("/web/repos/alice/forge/commits?rev=refs/heads/feature", token=tok)
        assert st_c == 200 and 'data-view="repo-commits"' in html_c

        st_d, _, html_d = srv.request(f"/web/repos/alice/forge/commits/{self.eng.feat_oid}", token=tok)
        assert st_d == 200 and 'data-view="commit-detail"' in html_d and "src/feature.rs" in html_d

        st_cmp, _, html_cmp = srv.request("/web/repos/alice/forge/compare?base=refs/heads/main&head=refs/heads/feature", token=tok)
        assert st_cmp == 200 and 'data-view="repo-compare"' in html_cmp and 'data-fast-forward="true"' in html_cmp

    def issues_and_xss_sanitization(self) -> None:
        assert self.local_server is not None
        srv = self.local_server
        tok = self.eng.carol["token"]
        xss_body = (
            "Hello <script>alert(1)</script><iframe src='javascript:alert(1)'></iframe>"
            "<svg onload=alert(1)></svg><img src=x onerror=alert(1)>"
            "[bad1](javascript:alert(1)) [bad2](jav&#x09;ascript:alert(1)) "
            "[bad3](data:text/html;base64,PHNjcmlwdD4=) [good](https://example.com/docs)"
        )
        st_i, hdrs_i, html_i = srv.request(
            "/web/repos/alice/forge/issues",
            method="POST",
            token=tok,
            json_body={"title": "XSS <script>evil()</script>", "body": xss_body},
        )
        assert st_i == 201
        self._assert_sec_headers(hdrs_i)
        lower_i = html_i.lower()
        for forbidden in ("<script", "<iframe", "<svg", "onerror=", "onload=", "javascript:", "data:text/html"):
            assert forbidden not in lower_i, f"XSS vector {forbidden} leaked in {html_i}"
        assert 'href="https://example.com/docs"' in html_i

    def pulls_reviews_checks_and_merge(self) -> None:
        assert self.local_server is not None
        srv = self.local_server
        # Protect main: required_approvals=1, required_checks=["ci/test"], prevent_self_approval=True
        self.eng.rbac.upsert_branch_rule(
            self.eng.alice,
            "alice",
            "forge",
            "main",
            required_approvals=1,
            prevent_self_approval=True,
        )
        self.eng.rbac.conn.execute(
            "UPDATE forge_branch_rules SET required_checks=? WHERE branch_ref='refs/heads/main'",
            (json.dumps(["ci/test"]),),
        )
        # Dave (Write) creates PR #1
        st_pr, _, html_pr = srv.request(
            "/web/repos/alice/forge/pulls",
            method="POST",
            token=self.eng.dave["token"],
            json_body={"title": "Feature PR", "head_ref": "feature", "base_ref": "main", "body": "PR **body**"},
        )
        assert st_pr == 201 and 'data-pull-number="1"' in html_pr and 'data-merge-allowed="false"' in html_pr

        # Dave cannot self-approve his own PR -> 403
        st_self, _, _ = srv.request(
            "/web/repos/alice/forge/pulls/1/reviews",
            method="POST",
            token=self.eng.dave["token"],
            json_body={"state": "approved", "commit_oid": self.eng.feat_oid, "body": "self LGTM"},
        )
        assert st_self == 403

        # Carol (Triage) can comment (201) but cannot approve (403)
        assert srv.request(
            "/web/repos/alice/forge/pulls/1/reviews",
            method="POST",
            token=self.eng.carol["token"],
            json_body={"state": "commented", "commit_oid": self.eng.feat_oid, "body": "Triage note"},
        )[0] == 201
        assert srv.request(
            "/web/repos/alice/forge/pulls/1/reviews",
            method="POST",
            token=self.eng.carol["token"],
            json_body={"state": "approved", "commit_oid": self.eng.feat_oid, "body": "No"},
        )[0] == 403

        # Report passing check run and Alice (Admin) approves
        self.eng.report_check_run("alice", "forge", self.eng.feat_oid, "ci/test", "completed", "success", 1, 2, "all green")
        st_chk, _, html_chk = srv.request("/web/repos/alice/forge/pulls/1/checks", token=self.eng.bob["token"])
        assert st_chk == 200 and 'data-check-context="ci/test"' in html_chk and 'data-check-conclusion="success"' in html_chk

        st_app, _, html_app = srv.request(
            "/web/repos/alice/forge/pulls/1/reviews",
            method="POST",
            token=self.eng.alice["token"],
            json_body={"state": "approved", "commit_oid": self.eng.feat_oid, "body": "Approved!"},
        )
        assert st_app == 201 and 'data-merge-allowed="true"' in html_app

        # Merge PR via Web UI
        st_m, _, html_m = srv.request(
            "/web/repos/alice/forge/pulls/1/merge",
            method="POST",
            token=self.eng.dave["token"],
            json_body={
                "expected_version": 1,
                "expected_head_oid": self.eng.feat_oid,
                "expected_base_oid": self.eng.base_oid,
            },
        )
        assert st_m == 200 and 'data-pull-state="merged"' in html_m

    def security_headers_and_adversarial_markdown(self) -> None:
        assert self.local_server is not None
        srv = self.local_server
        for route in (
            "/web/repos/alice/forge",
            "/web/repos/alice/forge/tree",
            "/web/repos/alice/forge/commits",
            "/web/repos/alice/forge/issues",
            "/web/repos/alice/forge/pulls",
            "/ui/repos/alice/forge",
        ):
            st, hdrs, _ = srv.request(route, token=self.eng.bob["token"])
            assert st == 200
            self._assert_sec_headers(hdrs)

    def cleanup(self) -> None:
        if self.local_server is not None:
            self.local_server.close()
            self.local_server = None
        if self._standalone:
            if hasattr(self, "root") and self.root.exists() and not getattr(self.args, "keep", False):
                shutil.rmtree(self.root, ignore_errors=True)
        else:
            super().cleanup()

    def run_all(self) -> None:
        self.setup()
        self.rbac_and_private_repo_isolation()
        self.overview_tree_blob_truncation_and_binary()
        self.commits_and_diff_compare()
        self.issues_and_xss_sanitization()
        self.pulls_reviews_checks_and_merge()
        self.security_headers_and_adversarial_markdown()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--case", default="all")
    args = parser.parse_args()

    harness = WebHarness(args)
    cases = (
        "setup",
        "rbac_and_private_repo_isolation",
        "overview_tree_blob_truncation_and_binary",
        "commits_and_diff_compare",
        "issues_and_xss_sanitization",
        "pulls_reviews_checks_and_merge",
        "security_headers_and_adversarial_markdown",
    )
    success = False
    try:
        if args.case == "all":
            for name in cases:
                fn = getattr(harness, name)
                if hasattr(harness, "case") and not harness._standalone:
                    harness.case(name, fn)
                else:
                    fn()
                    harness.results.append({"name": name, "status": "passed"})
        else:
            harness.setup()
            getattr(harness, args.case)()
            harness.results.append({"name": args.case, "status": "passed"})
        success = True
    finally:
        harness.cleanup()
        report = {
            "passed": success,
            "cases": harness.results,
        }
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2))
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
