"""Reconciliation loop: PR detection, mechanical risk check, independent review, and gated auto-merge."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

from software_factory.config import choose_reviewer_agent, effective_repo_policy
from software_factory.models import ReviewVerdict, RiskReport, RunRecord
from software_factory.risk import evaluate_risk, parse_git_numstat
from software_factory.runner import (
    StateStore,
    hc_list_terminals,
    hc_terminal_state,
    is_terminal_working,
    launch_agent_session,
)
from software_factory.sensors import ack_cloudflare_signal


def _env_bin(env_name: str, default: str) -> str:
    return os.environ.get(env_name) or default


def find_open_pr(repo: str, branch: str) -> dict[str, Any] | None:
    gh_bin = _env_bin("SF_GH_BIN", "gh")
    proc = subprocess.run(
        [
            gh_bin,
            "pr",
            "list",
            "--repo",
            repo,
            "--head",
            branch,
            "--state",
            "open",
            "--json",
            "number,url,baseRefName,headRefName",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return None
    prs = json.loads(proc.stdout or "[]")
    return prs[0] if prs else None


def compute_run_risk(cfg: dict[str, Any], record: RunRecord) -> RiskReport:
    git_bin = _env_bin("SF_GIT_BIN", "git")
    policy = effective_repo_policy(cfg, record.repo)
    workdir = Path(record.workdir)
    subprocess.run(
        [git_bin, "-C", str(workdir), "fetch", "origin", record.base_branch, record.branch],
        capture_output=True,
        text=True,
        check=False,
    )
    diff_proc = subprocess.run(
        [
            git_bin,
            "-C",
            str(workdir),
            "diff",
            "--numstat",
            f"origin/{record.base_branch}...origin/{record.branch}",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if diff_proc.returncode != 0:
        diff_proc = subprocess.run(
            [
                git_bin,
                "-C",
                str(workdir),
                "diff",
                "--numstat",
                f"{record.base_branch}...HEAD",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
    stats = parse_git_numstat(diff_proc.stdout)
    return evaluate_risk(
        kind=str(record.signal.get("kind", "feature")),
        diff_stats=stats,
        auto_merge_policy=policy.get("autoMerge") or {},
    )


def build_reviewer_prompt(
    record: RunRecord,
    risk_report: RiskReport,
    verdict_path: Path,
) -> str:
    return f"""You are an independent, adversarial Software Factory reviewer for `{record.repo}` (PR #{record.pr_number}: {record.pr_url}).

Your role is strictly read-only verification. Do NOT edit tracked repository files, commit, push, or merge.
The worker agent was `{record.worker_agent}`; you are an independent reviewer running a separate check.

Original signal:
```json
{json.dumps(record.signal, indent=2, ensure_ascii=False)}
```

Mechanical risk pre-check:
```json
{json.dumps(risk_report.to_dict(), indent=2, ensure_ascii=False)}
```

Steps:
1. Inspect `git diff origin/{record.base_branch}...origin/{record.branch}` (or `{record.base_branch}...HEAD`) and verify tests, correctness, edge cases, regressions, security impact, and whether behavioral impact is genuinely `none` or `low`.
2. Write ONLY a valid JSON file to `{verdict_path}` matching this exact schema:
```json
{{
  "schemaVersion": 1,
  "verdict": "approve | request-changes | escalate-human",
  "behaviorImpact": "none | low | medium | high",
  "summary": "Concise review summary",
  "findings": [
    {{
      "severity": "info | warning | error",
      "path": "optional/file/path",
      "message": "Specific finding"
    }}
  ]
}}
```
3. Be conservative: if there is any ambiguity in behavioral impact, missing test coverage, or risk to production behavior, set `verdict` to `"escalate-human"` or `"request-changes"`.
"""


def start_independent_review(
    cfg: dict[str, Any],
    store: StateStore,
    record: RunRecord,
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
    policy = effective_repo_policy(cfg, record.repo)
    risk_report = compute_run_risk(cfg, record)
    reviewer_agent = choose_reviewer_agent(record.worker_agent, policy.get("reviewerAgent"))
    reviewer_session = f"sf-rev-{record.run_id}"
    verdict_path = store.runs_dir / f"{record.run_id}.verdict.json"

    if dry_run:
        return {
            "action": "dry-run-review",
            "runId": record.run_id,
            "reviewerAgent": reviewer_agent,
            "risk": risk_report.to_dict(),
        }

    prompt = build_reviewer_prompt(record, risk_report, verdict_path)
    launch_info = launch_agent_session(
        agent=reviewer_agent,
        session_name=reviewer_session,
        workdir=Path(record.workdir),
        prompt=prompt,
    )

    record.risk_report = risk_report.to_dict()
    record.reviewer_agent = reviewer_agent
    record.reviewer_session = reviewer_session
    record.verdict_path = str(verdict_path)
    record.status = "reviewing"
    store.save_run(record)
    return {
        "action": "review-started",
        "runId": record.run_id,
        "reviewerAgent": reviewer_agent,
        "reviewerSession": reviewer_session,
        "risk": risk_report.to_dict(),
        "launch": launch_info,
    }


def _gh_ensure_label(gh_bin: str, repo: str, label: str, color: str, desc: str) -> None:
    subprocess.run(
        [gh_bin, "label", "create", label, "--repo", repo, "--color", color, "--description", desc, "--force"],
        capture_output=True,
        text=True,
        check=False,
    )


def _format_decision_comment(
    record: RunRecord,
    risk_report: RiskReport,
    verdict: ReviewVerdict,
    auto_merged: bool,
) -> str:
    heading = "Software Factory: Auto-merge enabled" if auto_merged else "Software Factory: Human review required"
    lines = [
        f"## {heading}",
        "",
        f"- **Run ID**: `{record.run_id}`",
        f"- **Task Kind**: `{record.signal.get('kind')}` (source: `{record.signal.get('source')}`)",
        f"- **Worker / Reviewer**: `{record.worker_agent}` / `{record.reviewer_agent}`",
        f"- **Mechanical Risk**: `{risk_report.level}` (files: {risk_report.files_changed}, +{risk_report.lines_added}/-{risk_report.lines_deleted})",
        f"- **Independent Review**: verdict=`{verdict.verdict}`, behaviorImpact=`{verdict.behavior_impact}`",
        "",
        f"### Review Summary",
        verdict.summary,
    ]
    if risk_report.reasons:
        lines.extend(["", "### Mechanical Gate Reasons"])
        for reason in risk_report.reasons:
            lines.append(f"- {reason}")
    if verdict.findings:
        lines.extend(["", "### Reviewer Findings"])
        for finding in verdict.findings:
            sev = finding.get("severity", "info")
            path = finding.get("path")
            msg = finding.get("message", "")
            loc = f" (`{path}`)" if path else ""
            lines.append(f"- **[{sev}]**{loc}: {msg}")
    return "\n".join(lines) + "\n"


def apply_review_verdict(
    cfg: dict[str, Any],
    store: StateStore,
    record: RunRecord,
    verdict: ReviewVerdict,
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
    gh_bin = _env_bin("SF_GH_BIN", "gh")
    policy = effective_repo_policy(cfg, record.repo)
    risk_report = (
        RiskReport.from_dict(record.risk_report)
        if record.risk_report
        else compute_run_risk(cfg, record)
    )

    can_auto_merge = (
        risk_report.auto_merge_eligible
        and verdict.verdict == "approve"
        and verdict.behavior_impact in ("none", "low")
    )

    if dry_run:
        return {
            "action": "dry-run-decision",
            "runId": record.run_id,
            "decision": "auto_merged" if can_auto_merge else "human_review",
            "risk": risk_report.to_dict(),
            "verdict": verdict.to_dict(),
        }

    pr_num = str(record.pr_number)
    comment = _format_decision_comment(record, risk_report, verdict, auto_merged=can_auto_merge)

    if can_auto_merge:
        _gh_ensure_label(gh_bin, record.repo, "sf:auto-merge", "0e8a16", "Approved for Software Factory auto-merge")
        subprocess.run(
            [gh_bin, "pr", "edit", pr_num, "--repo", record.repo, "--add-label", "sf:auto-merge"],
            capture_output=True,
            text=True,
            check=False,
        )
        subprocess.run(
            [gh_bin, "pr", "comment", pr_num, "--repo", record.repo, "--body", comment],
            capture_output=True,
            text=True,
            check=False,
        )
        merge_method = str((policy.get("autoMerge") or {}).get("mergeMethod") or "squash")
        merge_flag = f"--{merge_method}" if merge_method in ("squash", "merge", "rebase") else "--squash"
        subprocess.run(
            [gh_bin, "pr", "merge", pr_num, "--repo", record.repo, "--auto", merge_flag],
            capture_output=True,
            text=True,
            check=True,
        )
        record.status = "auto_merged"
        record.decision_reason = "Passed mechanical low-risk check and independent review approval."
    else:
        _gh_ensure_label(gh_bin, record.repo, "sf:needs-human-review", "d93f0b", "Requires human approval")
        subprocess.run(
            [gh_bin, "pr", "edit", pr_num, "--repo", record.repo, "--add-label", "sf:needs-human-review"],
            capture_output=True,
            text=True,
            check=False,
        )
        subprocess.run(
            [gh_bin, "pr", "comment", pr_num, "--repo", record.repo, "--body", comment],
            capture_output=True,
            text=True,
            check=False,
        )
        record.status = "human_review"
        reasons = list(risk_report.reasons)
        if verdict.verdict != "approve":
            reasons.append(f"Reviewer verdict is '{verdict.verdict}'.")
        if verdict.behavior_impact not in ("none", "low"):
            reasons.append(f"Reviewer assessed behaviorImpact as '{verdict.behavior_impact}'.")
        record.decision_reason = "; ".join(reasons) or "Escalated to human review."

    record.risk_report = risk_report.to_dict()
    record.review_verdict = verdict.to_dict()

    if not record.signal_acked and record.signal.get("ackUrl"):
        try:
            record.signal_acked = ack_cloudflare_signal(
                cfg,
                record.signal,
                status=record.status,
                run_id=record.run_id,
                pr_url=record.pr_url,
                reason=record.decision_reason,
            )
        except Exception:
            record.signal_acked = False

    store.save_run(record)
    return {
        "action": record.status,
        "runId": record.run_id,
        "prNumber": record.pr_number,
        "prUrl": record.pr_url,
        "reason": record.decision_reason,
    }


def reconcile_runs(
    cfg: dict[str, Any],
    store: StateStore,
    *,
    dry_run: bool = False,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    terminals = hc_list_terminals()

    for record in store.list_runs():
        if record.status == "running":
            worker_entry = hc_terminal_state(record.worker_session, terminals)
            if is_terminal_working(worker_entry):
                continue
            pr = find_open_pr(record.repo, record.branch)
            if not pr:
                continue
            record.pr_number = int(pr["number"])
            record.pr_url = str(pr["url"])
            if not dry_run:
                store.save_run(record)
            results.append(start_independent_review(cfg, store, record, dry_run=dry_run))
        elif record.status == "reviewing":
            if not record.verdict_path:
                continue
            vpath = Path(record.verdict_path)
            if not vpath.exists():
                continue
            raw_verdict = json.loads(vpath.read_text(encoding="utf-8"))
            verdict = ReviewVerdict.from_dict(raw_verdict)
            results.append(apply_review_verdict(cfg, store, record, verdict, dry_run=dry_run))

    return results
