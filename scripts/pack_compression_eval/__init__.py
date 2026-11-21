"""Reproducible stock-Git and live serve-blob pack/delta evaluation suite (Refs #178)."""

from __future__ import annotations

from .corpus import DATASET_ARCHETYPES, OBJECT_FORMATS, build_archetype_commits
from .pack_matrix import CANDIDATE_CONFIGS, PackConfigSpec
from .report import redact_text, render_summary_markdown, validate_report

__all__ = [
    "CANDIDATE_CONFIGS",
    "DATASET_ARCHETYPES",
    "OBJECT_FORMATS",
    "PackConfigSpec",
    "build_archetype_commits",
    "redact_text",
    "render_summary_markdown",
    "validate_report",
]
