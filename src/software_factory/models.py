"""Core data models for Software Factory."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
import hashlib
import re
from typing import Any

VALID_KINDS = ("feature", "bugfix", "security", "efficiency", "proposal")
VALID_SEVERITIES = ("low", "medium", "high", "critical")
VALID_VERDICTS = ("approve", "request-changes", "escalate-human")
VALID_IMPACTS = ("none", "low", "medium", "high")
REPO_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Signal:
    id: str
    source: str
    repo: str
    kind: str
    title: str
    summary: str
    dedupe_key: str
    severity: str = "medium"
    evidence: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now_iso)
    ack_url: str | None = None
    schema_version: int = 1

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Signal":
        if not isinstance(raw, dict):
            raise ValueError("Signal must be a JSON object")
        schema_version = raw.get("schemaVersion", 1)
        if schema_version != 1:
            raise ValueError(f"Unsupported signal schemaVersion: {schema_version}")

        repo = str(raw.get("repo", "")).strip()
        if not REPO_PATTERN.match(repo):
            raise ValueError(f"Invalid repo identifier: {repo!r}")

        kind = str(raw.get("kind", "")).strip()
        if kind not in VALID_KINDS:
            raise ValueError(f"Invalid kind {kind!r}; expected one of {VALID_KINDS}")

        severity = str(raw.get("severity", "medium")).strip()
        if severity not in VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity {severity!r}; expected one of {VALID_SEVERITIES}"
            )

        title = str(raw.get("title", "")).strip()
        if not title:
            raise ValueError("Signal title must not be empty")

        source = str(raw.get("source", "manual")).strip() or "manual"
        summary = str(raw.get("summary", "")).strip()
        dedupe_key = str(raw.get("dedupeKey", "")).strip()
        if not dedupe_key:
            digest = hashlib.sha256(f"{source}:{repo}:{kind}:{title}".encode()).hexdigest()[:12]
            dedupe_key = f"{source}:{repo}:{digest}"

        sig_id = str(raw.get("id", "")).strip()
        if not sig_id:
            digest = hashlib.sha256(f"{dedupe_key}:{utc_now_iso()}".encode()).hexdigest()[:10]
            sig_id = f"sig-{digest}"

        evidence = raw.get("evidence") or {}
        if not isinstance(evidence, dict):
            raise ValueError("Signal evidence must be a JSON object")

        ack_url = raw.get("ackUrl")
        if ack_url is not None:
            ack_url = str(ack_url).strip() or None

        created_at = str(raw.get("createdAt") or utc_now_iso())

        return cls(
            id=sig_id,
            source=source,
            repo=repo,
            kind=kind,
            title=title,
            summary=summary,
            dedupe_key=dedupe_key,
            severity=severity,
            evidence=evidence,
            created_at=created_at,
            ack_url=ack_url,
            schema_version=1,
        )

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "schemaVersion": self.schema_version,
            "id": self.id,
            "source": self.source,
            "repo": self.repo,
            "kind": self.kind,
            "severity": self.severity,
            "title": self.title,
            "summary": self.summary,
            "evidence": self.evidence,
            "dedupeKey": self.dedupe_key,
            "createdAt": self.created_at,
        }
        if self.ack_url:
            data["ackUrl"] = self.ack_url
        return data


@dataclass
class DiffStat:
    path: str
    additions: int
    deletions: int

    @property
    def changed_lines(self) -> int:
        return self.additions + self.deletions


@dataclass
class RiskReport:
    level: str  # "low" | "high"
    auto_merge_eligible: bool
    reasons: list[str]
    files_changed: int
    lines_added: int
    lines_deleted: int
    matched_denied_paths: list[str] = field(default_factory=list)
    touched_manifests: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "autoMergeEligible": self.auto_merge_eligible,
            "reasons": self.reasons,
            "filesChanged": self.files_changed,
            "linesAdded": self.lines_added,
            "linesDeleted": self.lines_deleted,
            "matchedDeniedPaths": self.matched_denied_paths,
            "touchedManifests": self.touched_manifests,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "RiskReport":
        return cls(
            level=str(raw["level"]),
            auto_merge_eligible=bool(raw["autoMergeEligible"]),
            reasons=list(raw.get("reasons", [])),
            files_changed=int(raw.get("filesChanged", 0)),
            lines_added=int(raw.get("linesAdded", 0)),
            lines_deleted=int(raw.get("linesDeleted", 0)),
            matched_denied_paths=list(raw.get("matchedDeniedPaths", [])),
            touched_manifests=list(raw.get("touchedManifests", [])),
        )


@dataclass
class ReviewVerdict:
    verdict: str
    behavior_impact: str
    summary: str
    findings: list[dict[str, Any]] = field(default_factory=list)
    schema_version: int = 1

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ReviewVerdict":
        if not isinstance(raw, dict):
            raise ValueError("Review verdict must be a JSON object")
        if raw.get("schemaVersion", 1) != 1:
            raise ValueError(f"Unsupported verdict schemaVersion: {raw.get('schemaVersion')}")
        verdict = str(raw.get("verdict", "")).strip()
        if verdict not in VALID_VERDICTS:
            raise ValueError(f"Invalid verdict {verdict!r}; expected {VALID_VERDICTS}")
        impact = str(raw.get("behaviorImpact", "")).strip()
        if impact not in VALID_IMPACTS:
            raise ValueError(f"Invalid behaviorImpact {impact!r}; expected {VALID_IMPACTS}")
        summary = str(raw.get("summary", "")).strip()
        if not summary:
            raise ValueError("Review summary must not be empty")
        findings = raw.get("findings", [])
        if not isinstance(findings, list):
            raise ValueError("Review findings must be an array")
        return cls(
            verdict=verdict,
            behavior_impact=impact,
            summary=summary,
            findings=findings,
            schema_version=1,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": self.schema_version,
            "verdict": self.verdict,
            "behaviorImpact": self.behavior_impact,
            "summary": self.summary,
            "findings": self.findings,
        }


@dataclass
class RunRecord:
    run_id: str
    repo: str
    branch: str
    base_branch: str
    workdir: str
    worker_agent: str
    worker_session: str
    signal: dict[str, Any]
    status: str = "running"  # running | reviewing | auto_merged | human_review | failed | closed
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)
    pr_number: int | None = None
    pr_url: str | None = None
    reviewer_agent: str | None = None
    reviewer_session: str | None = None
    verdict_path: str | None = None
    risk_report: dict[str, Any] | None = None
    review_verdict: dict[str, Any] | None = None
    decision_reason: str | None = None
    signal_acked: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "RunRecord":
        return cls(**raw)
