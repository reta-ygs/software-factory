"""Reconciliation loop: diagnosis challenge, PR review, gated auto-merge, PR comment wakeup, and post-deploy recovery check."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import subprocess
from pathlib import Path
from typing import Any

from software_factory.config import choose_reviewer_agent, effective_repo_policy
from software_factory.models import (
    DiagnosisChallenge,
    DiagnosisReport,
    ReviewVerdict,
    RiskReport,
    RunRecord,
    Signal,
    parse_utc_iso,
    utc_now_iso,
)
from software_factory.risk import evaluate_risk, parse_git_numstat
from software_factory.runner import (
    StateStore,
    build_worker_prompt,
    hc_list_terminals,
    hc_terminal_state,
    is_terminal_working,
    launch_agent_session,
)
from software_factory.sensors import ack_cloudflare_signal, fetch_recovery_status


def _env_bin(env_name: str, default: str) -> str:
    return os.environ.get(env_name) or default


def _maybe_ack(
    cfg: dict[str, Any],
    record: RunRecord,
    *,
    status: str,
    reason: str | None = None,
    force: bool = False,
) -> None:
    if not record.signal.get("ackUrl"):
        return
    if record.signal_acked and not force:
        return
    try:
        record.signal_acked = ack_cloudflare_signal(
            cfg,
            record.signal,
            status=status,
            run_id=record.run_id,
            pr_url=record.pr_url,
            reason=reason,
        )
    except Exception:
        if not force:
            record.signal_acked = False


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


def get_pr_merge_status(repo: str, pr_number: int) -> dict[str, Any] | None:
    gh_bin = _env_bin("SF_GH_BIN", "gh")
    proc = subprocess.run(
        [
            gh_bin,
            "pr",
            "view",
            str(pr_number),
            "--repo",
            repo,
            "--json",
            "state,mergedAt",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    data = json.loads(proc.stdout)
    return data if isinstance(data, dict) else None


def fetch_new_human_pr_comments(
    repo: str,
    pr_number: int,
    last_handled_id: str | None,
    *,
    allowed_associations: list[str] | None = None,
    allowed_authors: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Poll authorized maintainer comments on an open PR to wake up a sleeping worker."""
    gh_bin = _env_bin("SF_GH_BIN", "gh")
    permitted_assocs = {
        str(a).upper()
        for a in (allowed_associations if allowed_associations is not None else ["OWNER", "MEMBER", "COLLABORATOR"])
    }
    permitted_authors = {str(a).lower() for a in (allowed_authors or []) if str(a).strip()}

    collected: list[dict[str, Any]] = []
    for endpoint in (
        f"repos/{repo}/issues/{pr_number}/comments",
        f"repos/{repo}/pulls/{pr_number}/comments",
    ):
        proc = subprocess.run(
            [gh_bin, "api", endpoint],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            continue
        items = json.loads(proc.stdout)
        if not isinstance(items, list):
            continue
        for item in items:
            body = str(item.get("body") or "").strip()
            if not body or body.startswith("## Software Factory:"):
                continue
            user = item.get("user") or {}
            login = str(user.get("login") or "").strip()
            user_type = str(user.get("type") or "")
            if not login or user_type == "Bot" or login.endswith("[bot]"):
                continue
            assoc = str(item.get("author_association") or "").upper()
            if assoc not in permitted_assocs:
                continue
            if permitted_authors and login.lower() not in permitted_authors:
                continue
            cid = str(item.get("id") or "")
            if not cid:
                continue
            collected.append(
                {
                    "id": cid,
                    "author": login,
                    "authorAssociation": assoc,
                    "body": body,
                    "path": item.get("path"),
                    "createdAt": item.get("created_at") or "",
                }
            )

    collected.sort(key=lambda c: (c["createdAt"], c["id"]))
    if not last_handled_id:
        return collected
    for idx, c in enumerate(collected):
        if c["id"] == last_handled_id:
            return collected[idx + 1 :]
    return collected


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


def build_diagnosis_challenge_prompt(
    record: RunRecord,
    diagnosis: DiagnosisReport,
    challenge_path: Path,
) -> str:
    return f"""You are an independent adversarial challenger for `{record.repo}` (run `{record.run_id}`).

Your sole job is to TRY TO DISPROVE the primary investigator's root-cause diagnosis before any code is modified.
Do NOT edit repository files, commit, push, or open a PR.

Original signal:
```json
{json.dumps(record.signal, indent=2, ensure_ascii=False)}
```

Primary diagnosis to challenge:
```json
{json.dumps(diagnosis.to_dict(), indent=2, ensure_ascii=False)}
```

Steps:
1. Check whether the claimed root cause is actually supported by code paths, git history, and telemetry (`sf query <ref>` if available).
2. Actively look for confirmation bias: could this be a traffic mix shift, external dependency hiccup, caching effect, or a different code path?
3. Write ONLY a valid JSON file to `{challenge_path}` matching this exact schema:
```json
{{
  "schemaVersion": 1,
  "verdict": "confirmed | disproved | escalate-human",
  "summary": "Why the diagnosis survived scrutiny or was disproved",
  "counterArguments": ["Specific alternative hypotheses or counter-evidence checked"]
}}
```
"""


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


def _advance_investigating(
    cfg: dict[str, Any],
    store: StateStore,
    record: RunRecord,
    *,
    dry_run: bool = False,
) -> dict[str, Any] | None:
    if not record.diagnosis_path:
        return None
    dpath = Path(record.diagnosis_path)
    if not dpath.exists():
        return None
    diagnosis = DiagnosisReport.from_dict(json.loads(dpath.read_text(encoding="utf-8")))

    if diagnosis.status == "false-positive":
        if dry_run:
            return {"action": "dry-run-dismiss", "runId": record.run_id, "reason": diagnosis.backtest_summary}
        record.diagnosis_report = diagnosis.to_dict()
        record.status = "dismissed"
        record.decision_reason = f"False positive ruled out by backtest: {diagnosis.backtest_summary}"
        _maybe_ack(cfg, record, status="dismissed", reason=record.decision_reason)
        store.save_run(record)
        return {"action": "dismissed", "runId": record.run_id, "reason": record.decision_reason}

    if diagnosis.status == "inconclusive":
        if dry_run:
            return {"action": "dry-run-escalate-diagnosis", "runId": record.run_id}
        record.diagnosis_report = diagnosis.to_dict()
        record.status = "human_review"
        record.decision_reason = f"Diagnosis inconclusive: {diagnosis.root_cause}"
        _maybe_ack(cfg, record, status="human_review", reason=record.decision_reason)
        store.save_run(record)
        return {"action": "human_review", "runId": record.run_id, "reason": record.decision_reason}

    # Confirmed diagnosis -> launch independent adversarial challenger to try to disprove it
    policy = effective_repo_policy(cfg, record.repo)
    challenger_agent = choose_reviewer_agent(record.worker_agent, policy.get("reviewerAgent"))
    challenger_session = f"sf-chal-{record.run_id}"
    challenge_path = store.runs_dir / f"{record.run_id}.diagnosis-challenge.json"

    if dry_run:
        return {
            "action": "dry-run-diagnosis-challenge",
            "runId": record.run_id,
            "challengerAgent": challenger_agent,
        }

    prompt = build_diagnosis_challenge_prompt(record, diagnosis, challenge_path)
    launch_info = launch_agent_session(
        agent=challenger_agent,
        session_name=challenger_session,
        workdir=Path(record.workdir),
        prompt=prompt,
    )
    record.diagnosis_report = diagnosis.to_dict()
    record.reviewer_agent = challenger_agent
    record.diagnosis_reviewer_session = challenger_session
    record.diagnosis_challenge_path = str(challenge_path)
    record.status = "diagnosis_review"
    store.save_run(record)
    return {
        "action": "diagnosis-challenge-started",
        "runId": record.run_id,
        "challengerAgent": challenger_agent,
        "challengePath": str(challenge_path),
        "launch": launch_info,
    }


def _advance_diagnosis_review(
    cfg: dict[str, Any],
    store: StateStore,
    record: RunRecord,
    *,
    dry_run: bool = False,
) -> dict[str, Any] | None:
    if not record.diagnosis_challenge_path:
        return None
    cpath = Path(record.diagnosis_challenge_path)
    if not cpath.exists():
        return None
    challenge = DiagnosisChallenge.from_dict(json.loads(cpath.read_text(encoding="utf-8")))

    if challenge.verdict == "disproved":
        if dry_run:
            return {"action": "dry-run-disproved", "runId": record.run_id}
        record.diagnosis_challenge = challenge.to_dict()
        record.status = "dismissed"
        record.decision_reason = f"Diagnosis disproved by adversarial review: {challenge.summary}"
        _maybe_ack(cfg, record, status="dismissed", reason=record.decision_reason)
        store.save_run(record)
        return {"action": "dismissed", "runId": record.run_id, "reason": record.decision_reason}

    if challenge.verdict == "escalate-human":
        if dry_run:
            return {"action": "dry-run-escalate-human", "runId": record.run_id}
        record.diagnosis_challenge = challenge.to_dict()
        record.status = "human_review"
        record.decision_reason = f"Diagnosis challenge escalated to human: {challenge.summary}"
        _maybe_ack(cfg, record, status="human_review", reason=record.decision_reason)
        store.save_run(record)
        return {"action": "human_review", "runId": record.run_id, "reason": record.decision_reason}

    # Diagnosis survived adversarial scrutiny -> launch implementation worker!
    policy = effective_repo_policy(cfg, record.repo)
    signal = Signal.from_dict(record.signal)
    if dry_run:
        return {"action": "dry-run-implement", "runId": record.run_id}

    prompt = build_worker_prompt(
        signal,
        repo_policy=policy,
        branch=record.branch,
        base_branch=record.base_branch,
        diagnosis=record.diagnosis_report,
        challenge=challenge.to_dict(),
    )
    launch_info = launch_agent_session(
        agent=record.worker_agent,
        session_name=record.worker_session,
        workdir=Path(record.workdir),
        prompt=prompt,
    )
    record.diagnosis_challenge = challenge.to_dict()
    record.status = "running"
    store.save_run(record)
    return {
        "action": "implementation-started",
        "runId": record.run_id,
        "workerSession": record.worker_session,
        "launch": launch_info,
    }


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
    suffix = f"-{record.wakeup_count}" if record.wakeup_count else ""
    reviewer_session = f"sf-rev-{record.run_id}{suffix}"
    verdict_path = store.runs_dir / f"{record.run_id}{suffix}.verdict.json"

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
        "### Review Summary",
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
        next_state = "pending_merge" if can_auto_merge else "human_review"
        return {
            "action": "dry-run-decision",
            "runId": record.run_id,
            "decision": next_state,
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
        record.merged_at = None
        record.status = "pending_merge"
        record.decision_reason = "Passed mechanical low-risk check and independent review approval; waiting for GitHub merge."
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
    _maybe_ack(cfg, record, status=record.status, reason=record.decision_reason)
    store.save_run(record)
    return {
        "action": record.status,
        "runId": record.run_id,
        "prNumber": record.pr_number,
        "prUrl": record.pr_url,
        "reason": record.decision_reason,
    }


def _advance_pending_merge(
    cfg: dict[str, Any],
    store: StateStore,
    record: RunRecord,
    *,
    dry_run: bool = False,
) -> dict[str, Any] | None:
    if not record.pr_number:
        return None
    pr_status = get_pr_merge_status(record.repo, record.pr_number)
    if not pr_status:
        return None
    state = str(pr_status.get("state") or "").upper()
    if state == "OPEN":
        return None
    if state == "CLOSED":
        if dry_run:
            return {"action": "dry-run-closed", "runId": record.run_id}
        record.status = "closed"
        record.decision_reason = "PR was closed without merging."
        _maybe_ack(cfg, record, status="closed", reason=record.decision_reason, force=True)
        store.save_run(record)
        return {"action": "closed", "runId": record.run_id}
    if state != "MERGED":
        return None

    merged_at = str(pr_status.get("mergedAt") or "").strip() or utc_now_iso()
    has_recovery = bool((record.signal.get("recoveryCheck") or {}).get("queryUrl"))
    next_status = "verifying_recovery" if has_recovery else "auto_merged"
    if dry_run:
        return {"action": f"dry-run-{next_status}", "runId": record.run_id, "mergedAt": merged_at}

    record.merged_at = merged_at
    record.status = next_status
    record.decision_reason = "PR merged on GitHub."
    if not has_recovery:
        _maybe_ack(cfg, record, status="auto_merged", reason=record.decision_reason, force=True)
    store.save_run(record)
    return {"action": next_status, "runId": record.run_id, "mergedAt": merged_at}


def _advance_verifying_recovery(
    cfg: dict[str, Any],
    store: StateStore,
    record: RunRecord,
    *,
    dry_run: bool = False,
) -> dict[str, Any] | None:
    rc = record.signal.get("recoveryCheck") or {}
    query_url = rc.get("queryUrl")
    if not query_url:
        return None
    policy = effective_repo_policy(cfg, record.repo)
    wait_min = float(rc.get("waitMinutes", policy.get("recoveryWaitMinutes", 30)))
    if record.merged_at:
        elapsed_min = (datetime.now(timezone.utc) - parse_utc_iso(record.merged_at)).total_seconds() / 60.0
        if elapsed_min < wait_min:
            return None

    result = fetch_recovery_status(cfg, str(query_url))
    recovered = bool(result.get("recovered"))
    summary = str(result.get("summary") or ("Metrics returned to baseline." if recovered else "Metrics have not recovered."))

    if dry_run:
        return {"action": "dry-run-recovery", "runId": record.run_id, "recovered": recovered, "summary": summary}

    gh_bin = _env_bin("SF_GH_BIN", "gh")
    record.recovery_result = result
    if recovered:
        record.status = "resolved"
        record.decision_reason = f"Post-deploy recovery verified: {summary}"
        if record.pr_number:
            subprocess.run(
                [
                    gh_bin,
                    "pr",
                    "comment",
                    str(record.pr_number),
                    "--repo",
                    record.repo,
                    "--body",
                    f"## Software Factory: Post-deploy recovery verified\n\n{summary}\n",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
        _maybe_ack(cfg, record, status="resolved", reason=record.decision_reason, force=True)
    else:
        record.status = "human_review"
        record.decision_reason = f"Post-deploy recovery check failed: {summary}"
        if record.pr_number:
            _gh_ensure_label(gh_bin, record.repo, "sf:recovery-failed", "b60205", "Post-deploy recovery check failed")
            subprocess.run(
                [gh_bin, "pr", "edit", str(record.pr_number), "--repo", record.repo, "--add-label", "sf:recovery-failed"],
                capture_output=True,
                text=True,
                check=False,
            )
            subprocess.run(
                [
                    gh_bin,
                    "pr",
                    "comment",
                    str(record.pr_number),
                    "--repo",
                    record.repo,
                    "--body",
                    f"## Software Factory: Recovery verification failed\n\n{summary}\n",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
        _maybe_ack(cfg, record, status="recovery_failed", reason=record.decision_reason, force=True)

    store.save_run(record)
    return {"action": record.status, "runId": record.run_id, "recovered": recovered, "summary": summary}


def _maybe_wakeup_from_pr_comments(
    cfg: dict[str, Any],
    store: StateStore,
    record: RunRecord,
    *,
    dry_run: bool = False,
) -> dict[str, Any] | None:
    if not record.pr_number:
        return None
    policy = effective_repo_policy(cfg, record.repo)
    new_comments = fetch_new_human_pr_comments(
        record.repo,
        record.pr_number,
        record.last_handled_comment_id,
        allowed_associations=policy.get("allowedCommentAssociations"),
        allowed_authors=policy.get("allowedCommentAuthors"),
    )
    if not new_comments:
        return None
    latest_id = new_comments[-1]["id"]
    if dry_run:
        return {"action": "dry-run-wakeup", "runId": record.run_id, "commentCount": len(new_comments)}

    signal = Signal.from_dict(record.signal)
    record.wakeup_count += 1
    session_name = f"sf-fix-{record.run_id}-{record.wakeup_count}"
    prompt = build_worker_prompt(
        signal,
        repo_policy=policy,
        branch=record.branch,
        base_branch=record.base_branch,
        diagnosis=record.diagnosis_report,
        challenge=record.diagnosis_challenge,
        followup_comments=new_comments,
    )
    launch_info = launch_agent_session(
        agent=record.worker_agent,
        session_name=session_name,
        workdir=Path(record.workdir),
        prompt=prompt,
    )
    record.worker_session = session_name
    record.last_handled_comment_id = latest_id
    record.status = "running"
    store.save_run(record)
    return {
        "action": "wakeup-from-pr-comment",
        "runId": record.run_id,
        "commentCount": len(new_comments),
        "workerSession": session_name,
        "launch": launch_info,
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
        if record.status == "investigating":
            res = _advance_investigating(cfg, store, record, dry_run=dry_run)
            if res:
                results.append(res)
        elif record.status == "diagnosis_review":
            res = _advance_diagnosis_review(cfg, store, record, dry_run=dry_run)
            if res:
                results.append(res)
        elif record.status == "running":
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
        elif record.status == "pending_merge":
            res = _advance_pending_merge(cfg, store, record, dry_run=dry_run)
            if res:
                results.append(res)
        elif record.status == "verifying_recovery":
            res = _advance_verifying_recovery(cfg, store, record, dry_run=dry_run)
            if res:
                results.append(res)
        elif record.status == "human_review":
            res = _maybe_wakeup_from_pr_comments(cfg, store, record, dry_run=dry_run)
            if res:
                results.append(res)

    return results
