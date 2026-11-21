"""Deterministic mechanical risk evaluation for Software Factory changes."""

from __future__ import annotations

from fnmatch import fnmatch
from pathlib import PurePosixPath
from typing import Any

from software_factory.config import DEFAULT_DENIED_PATHS, DEFAULT_MANIFEST_FILES
from software_factory.models import DiffStat, RiskReport

HUMAN_ONLY_KINDS = {"feature", "proposal"}


def parse_git_numstat(output: str) -> list[DiffStat]:
    stats: list[DiffStat] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = raw_line.split("\t")
        if len(parts) < 3:
            continue
        added_str, deleted_str, path = parts[0], parts[1], parts[2]
        # Binary files report "-" for additions/deletions; treat conservatively as 100 lines.
        additions = 100 if added_str == "-" else int(added_str)
        deletions = 100 if deleted_str == "-" else int(deleted_str)
        stats.append(DiffStat(path=path, additions=additions, deletions=deletions))
    return stats


def _matches_any_pattern(path: str, patterns: list[str]) -> bool:
    norm = path.lstrip("./")
    basename = PurePosixPath(norm).name
    for pat in patterns:
        if fnmatch(norm, pat) or fnmatch(basename, pat):
            return True
    return False


def evaluate_risk(
    *,
    kind: str,
    diff_stats: list[DiffStat],
    auto_merge_policy: dict[str, Any],
) -> RiskReport:
    reasons: list[str] = []
    matched_denied: list[str] = []
    touched_manifests: list[str] = []

    files_changed = len(diff_stats)
    lines_added = sum(s.additions for s in diff_stats)
    lines_deleted = sum(s.deletions for s in diff_stats)
    total_lines = lines_added + lines_deleted

    if kind in HUMAN_ONLY_KINDS:
        reasons.append(f"Task kind '{kind}' always requires human approval.")

    if not bool(auto_merge_policy.get("enabled", False)):
        reasons.append("Auto-merge is disabled for this repository.")

    if files_changed == 0:
        reasons.append("No changed files detected in diff.")

    max_files = int(auto_merge_policy.get("maxFiles", 10))
    if files_changed > max_files:
        reasons.append(f"Changed files ({files_changed}) exceed maxFiles ({max_files}).")

    max_lines = int(auto_merge_policy.get("maxChangedLines", 250))
    if total_lines > max_lines:
        reasons.append(f"Changed lines ({total_lines}) exceed maxChangedLines ({max_lines}).")

    denied_paths = list(auto_merge_policy.get("deniedPaths", DEFAULT_DENIED_PATHS))
    manifest_files = list(auto_merge_policy.get("manifestFiles", DEFAULT_MANIFEST_FILES))
    allow_manifests = bool(auto_merge_policy.get("allowManifestChanges", False))

    for stat in diff_stats:
        if _matches_any_pattern(stat.path, denied_paths):
            matched_denied.append(stat.path)
        if _matches_any_pattern(stat.path, manifest_files):
            touched_manifests.append(stat.path)

    if matched_denied:
        reasons.append(
            "Diff touches high-risk paths: " + ", ".join(sorted(set(matched_denied)))
        )

    if touched_manifests and not allow_manifests and kind != "security":
        reasons.append(
            "Diff modifies dependency/build manifests: "
            + ", ".join(sorted(set(touched_manifests)))
        )

    eligible = len(reasons) == 0
    return RiskReport(
        level="low" if eligible else "high",
        auto_merge_eligible=eligible,
        reasons=reasons,
        files_changed=files_changed,
        lines_added=lines_added,
        lines_deleted=lines_deleted,
        matched_denied_paths=sorted(set(matched_denied)),
        touched_manifests=sorted(set(touched_manifests)),
    )
