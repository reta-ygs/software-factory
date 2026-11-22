"""State persistence, isolated git checkouts, and herdr-core agent launcher."""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Iterator

from software_factory.config import effective_repo_policy, get_state_dir
from software_factory.models import RunRecord, Signal, utc_now_iso

ACTIVE_RUN_STATUSES = {
    "investigating",
    "diagnosis_review",
    "running",
    "reviewing",
    "pending_merge",
    "verifying_recovery",
    "human_review",
}
DIAGNOSIS_KINDS = {"bugfix", "efficiency"}


def _env_bin(env_name: str, default: str) -> str:
    return os.environ.get(env_name) or default


class StateStore:
    def __init__(self, state_dir: Path | None = None) -> None:
        self.root = (state_dir or get_state_dir()).expanduser()
        self.runs_dir = self.root / "runs"
        self.repos_dir = self.root / "repos"
        self.work_dir = self.root / "work"
        self.locks_dir = self.root / "locks"
        for d in (self.root, self.runs_dir, self.repos_dir, self.work_dir, self.locks_dir):
            d.mkdir(parents=True, exist_ok=True)

    @contextlib.contextmanager
    def lock(self, name: str) -> Iterator[bool]:
        lock_file = self.locks_dir / f"{name}.lock"
        fd = os.open(lock_file, os.O_CREAT | os.O_RDWR, 0o600)
        acquired = False
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
            except BlockingIOError:
                acquired = False
            yield acquired
        finally:
            if acquired:
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def run_path(self, run_id: str) -> Path:
        return self.runs_dir / f"{run_id}.json"

    def save_run(self, record: RunRecord) -> Path:
        record.updated_at = utc_now_iso()
        path = self.run_path(record.run_id)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(record.to_dict(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        tmp.replace(path)
        return path

    def load_run(self, run_id: str) -> RunRecord:
        path = self.run_path(run_id)
        if not path.exists():
            raise FileNotFoundError(f"Run not found: {run_id}")
        return RunRecord.from_dict(json.loads(path.read_text(encoding="utf-8")))

    def list_runs(self) -> list[RunRecord]:
        records: list[RunRecord] = []
        for path in sorted(self.runs_dir.glob("*.json")):
            if path.name.count(".") > 1:
                continue
            try:
                records.append(RunRecord.from_dict(json.loads(path.read_text(encoding="utf-8"))))
            except Exception:
                continue
        return records

    def find_active_by_dedupe(self, dedupe_key: str) -> RunRecord | None:
        for rec in self.list_runs():
            if rec.status in ACTIVE_RUN_STATUSES and rec.signal.get("dedupeKey") == dedupe_key:
                return rec
        return None

    def count_running(self) -> int:
        return sum(
            1
            for r in self.list_runs()
            if r.status in {"investigating", "diagnosis_review", "running", "reviewing"}
        )


def hc_list_terminals() -> list[dict[str, Any]]:
    hc_bin = _env_bin("SF_HC_BIN", "hc")
    proc = subprocess.run([hc_bin, "--json", "ls"], capture_output=True, text=True, check=True)
    raw = json.loads(proc.stdout or "[]")
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict) and isinstance(raw.get("terminals"), list):
        return raw["terminals"]
    raise ValueError("Unexpected hc --json ls output")


def hc_terminal_state(session_name: str, terminals: list[dict[str, Any]] | None = None) -> dict[str, Any] | None:
    entries = terminals if terminals is not None else hc_list_terminals()
    for entry in entries:
        if entry.get("name") == session_name:
            return entry
    return None


def is_terminal_working(entry: dict[str, Any] | None) -> bool:
    if not entry:
        return False
    if entry.get("state") != "live":
        return False
    status = entry.get("status")
    if isinstance(status, dict):
        status = status.get("state", "")
    return status in ("working", "blocked", "")


def sync_bare_mirror(store: StateStore, repo: str, git_url: str, branch: str) -> Path:
    git_bin = _env_bin("SF_GIT_BIN", "git")
    safe_repo = repo.replace("/", "__")
    mirror = store.repos_dir / f"{safe_repo}.git"
    if mirror.exists():
        subprocess.run([git_bin, "-C", str(mirror), "remote", "set-url", "origin", git_url], check=True)
        subprocess.run(
            [git_bin, "-C", str(mirror), "fetch", "--prune", "origin", f"+refs/heads/{branch}:refs/heads/{branch}"],
            check=True,
        )
    else:
        subprocess.run(
            [git_bin, "clone", "--bare", "--single-branch", "--branch", branch, git_url, str(mirror)],
            check=True,
        )
    return mirror


def prepare_isolated_workdir(
    store: StateStore,
    *,
    run_id: str,
    repo: str,
    git_url: str,
    base_branch: str,
    branch: str,
) -> Path:
    git_bin = _env_bin("SF_GIT_BIN", "git")
    mirror = sync_bare_mirror(store, repo, git_url, base_branch)
    run_root = store.work_dir / run_id
    if run_root.exists():
        shutil.rmtree(run_root)
    run_root.mkdir(parents=True, exist_ok=True)
    workdir = run_root / "repo"
    subprocess.run([git_bin, "clone", "--branch", base_branch, str(mirror), str(workdir)], check=True)
    subprocess.run([git_bin, "-C", str(workdir), "remote", "set-url", "origin", git_url], check=True)
    subprocess.run([git_bin, "-C", str(workdir), "checkout", "-B", branch], check=True)
    return workdir


def _query_refs_hint(evidence: dict[str, Any]) -> str:
    refs = evidence.get("queryRefs")
    if not isinstance(refs, list) or not refs:
        return ""
    lines = [
        "",
        "Telemetry Query References (use `sf query <id-or-url>` to fetch sanitized aggregates on demand):",
    ]
    for ref in refs:
        if isinstance(ref, dict) and ref.get("id"):
            label = f" - {ref.get('label')}" if ref.get("label") else ""
            url = ref.get("url") or ref.get("id")
            lines.append(f"- `{ref['id']}` (`{url}`){label}")
    return "\n".join(lines) + "\n"


def build_diagnosis_prompt(
    signal: Signal,
    *,
    diagnosis_path: Path,
    base_branch: str,
) -> str:
    evidence_json = json.dumps(signal.evidence, indent=2, ensure_ascii=False)
    qhint = _query_refs_hint(signal.evidence)
    return f"""You are a Software Factory forensic investigator for `{signal.repo}` (branch `{base_branch}`).

Your role in this phase is STRICTLY READ-ONLY investigation and false-positive backtesting.
Do NOT edit repository files, commit, push, or open a PR yet.

Signal metadata:
- ID: {signal.id}
- Source: {signal.source}
- Kind: {signal.kind}
- Severity: {signal.severity}
- Title: {signal.title}

Summary:
{signal.summary}

Evidence (sanitized):
```json
{evidence_json}
```
{qhint}
Steps:
1. Backtest the timeline against `git log` / recent commits and available telemetry (`sf query <ref>` if listed) to determine whether this is a genuine code regression/defect OR a false positive caused by traffic mix shifts, external outages, or transient noise.
2. Identify the concrete root cause and minimal fix scope if confirmed.
3. Write ONLY a valid JSON file to `{diagnosis_path}` matching this exact schema:
```json
{{
  "schemaVersion": 1,
  "status": "confirmed | false-positive | inconclusive",
  "rootCause": "Concrete root cause explanation or why it is a false positive",
  "backtestSummary": "How timeline/commits/metrics confirm or rule out a code regression",
  "suspectedCommit": "optional commit sha or null",
  "proposedFixScope": "Minimal files/changes needed if confirmed",
  "evidenceRefs": ["optional queryRef ids inspected"]
}}
```
"""


def build_worker_prompt(
    signal: Signal,
    *,
    repo_policy: dict[str, Any],
    branch: str,
    base_branch: str,
    diagnosis: dict[str, Any] | None = None,
    challenge: dict[str, Any] | None = None,
    followup_comments: list[dict[str, Any]] | None = None,
) -> str:
    test_hint = (
        f"Run the repository test command: `{repo_policy['testCommand']}`."
        if repo_policy.get("testCommand")
        else "Run the repository's existing test/lint/build verification commands."
    )
    merge_rule = (
        "This is a human-approval-required task. Do NOT merge the PR."
        if signal.kind in ("feature", "proposal")
        else "Do NOT merge the PR yourself; the Software Factory controller will run mechanical risk checks and an independent reviewer before any auto-merge."
    )
    evidence_json = json.dumps(signal.evidence, indent=2, ensure_ascii=False)
    qhint = _query_refs_hint(signal.evidence)
    diag_block = ""
    if diagnosis:
        diag_block += f"\nVerified Diagnosis:\n```json\n{json.dumps(diagnosis, indent=2, ensure_ascii=False)}\n```\n"
    if challenge:
        diag_block += f"\nAdversarial Diagnosis Review:\n```json\n{json.dumps(challenge, indent=2, ensure_ascii=False)}\n```\n"
    if followup_comments:
        diag_block += (
            "\nHuman PR Review Comments to Address:\n```json\n"
            + json.dumps(followup_comments, indent=2, ensure_ascii=False)
            + "\n```\n"
        )

    pr_step = (
        f"4. Commit your updates on branch `{branch}` and push to `origin` to update the existing PR."
        if followup_comments
        else f"4. Commit your changes on branch `{branch}`, push to `origin`, and open a Pull Request against `{base_branch}` using `gh pr create` with a clear summary of changes, verification results, and expected behavioral impact."
    )
    return f"""You are a Software Factory worker executing an isolated task on branch `{branch}` (base `{base_branch}`) for `{signal.repo}`.

Signal metadata:
- ID: {signal.id}
- Source: {signal.source}
- Kind: {signal.kind}
- Severity: {signal.severity}
- Dedupe Key: {signal.dedupe_key}
- Title: {signal.title}

Summary:
{signal.summary}

Evidence (sanitized):
```json
{evidence_json}
```
{qhint}{diag_block}
Instructions:
1. Investigate the codebase in this isolated checkout and implement the smallest clean, well-tested fix or feature addressing the signal.
2. Never read or touch checkouts outside this working directory. Never commit secrets, tokens, or credentials. Never run `nixos-rebuild switch` or restart host services.
3. {test_hint}
{pr_step}
5. {merge_rule}
"""


def launch_agent_session(
    *,
    agent: str,
    session_name: str,
    workdir: Path,
    prompt: str,
) -> dict[str, Any]:
    hc_bin = _env_bin("SF_HC_BIN", "hc")
    cmd = [
        hc_bin,
        "run",
        "--bg",
        "--no-parent",
        "--outlive-parent",
        "--name",
        session_name,
        "--cwd",
        str(workdir),
    ]
    if agent == "agy":
        agy_bin = _env_bin("SF_AGY_BIN", "agy")
        settings = json.dumps(
            {
                "agentMode": "auto",
                "toolPermission": "request-review",
                "allowNonWorkspaceAccess": False,
                "permissions": {"allow": [], "deny": [], "ask": []},
            },
            separators=(",", ":"),
        )
        cmd.extend([agy_bin, "--mode", "auto", "--settings", settings, "-i", prompt])
    elif agent == "codex":
        codex_bin = _env_bin("SF_CODEX_BIN", "codex")
        cmd.extend([codex_bin, prompt])
    elif agent == "pi":
        pi_bin = _env_bin("SF_PI_BIN", "pi")
        cmd.extend([pi_bin, prompt])
    else:
        raise ValueError(f"Unsupported agent: {agent}")

    proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
    try:
        return json.loads(proc.stdout) if proc.stdout.strip() else {"launched": True}
    except json.JSONDecodeError:
        return {"launched": True, "stdout": proc.stdout.strip()}


def _has_open_pr_for_dedupe(repo: str, dedupe_tag: str) -> bool:
    gh_bin = _env_bin("SF_GH_BIN", "gh")
    proc = subprocess.run(
        [gh_bin, "pr", "list", "--repo", repo, "--state", "open", "--json", "headRefName,title"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return False
    prs = json.loads(proc.stdout or "[]")
    for pr in prs:
        head = str(pr.get("headRefName") or "")
        if dedupe_tag in head:
            return True
    return False


def _sanitize_slug(text: str, max_len: int = 20) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return (slug[:max_len].strip("-")) or "task"


def dispatch_signal(
    cfg: dict[str, Any],
    store: StateStore,
    signal: Signal,
    *,
    dry_run: bool = False,
    skip_diagnosis: bool = False,
) -> dict[str, Any]:
    existing = store.find_active_by_dedupe(signal.dedupe_key)
    if existing:
        return {
            "action": "skipped",
            "reason": f"Active run {existing.run_id} already exists for dedupeKey={signal.dedupe_key}",
            "runId": existing.run_id,
        }

    max_concurrent = int((cfg.get("defaults") or {}).get("maxConcurrentRuns", 2))
    if store.count_running() >= max_concurrent:
        return {
            "action": "skipped",
            "reason": f"Concurrency limit reached ({max_concurrent})",
        }

    dedupe_tag = hashlib.sha256(signal.dedupe_key.encode()).hexdigest()[:10]
    if not dry_run and _has_open_pr_for_dedupe(signal.repo, dedupe_tag):
        return {
            "action": "skipped",
            "reason": f"Open PR already exists for dedupe tag {dedupe_tag}",
        }

    policy = effective_repo_policy(cfg, signal.repo)
    ts = time.strftime("%Y%m%d%H%M%S", time.gmtime())
    slug = _sanitize_slug(signal.title, 16)
    run_id = f"{ts}-{dedupe_tag[:8]}"
    branch = f"sf/{signal.kind}/{dedupe_tag}-{slug}"
    worker_agent = str(policy.get("workerAgent") or "agy")
    needs_diagnosis = (
        not skip_diagnosis
        and bool(policy.get("requireDiagnosis", True))
        and signal.kind in DIAGNOSIS_KINDS
    )
    session_name = f"sf-diag-{run_id}" if needs_diagnosis else f"sf-{run_id}"

    if dry_run:
        return {
            "action": "dry-run",
            "phase": "investigating" if needs_diagnosis else "running",
            "runId": run_id,
            "repo": signal.repo,
            "kind": signal.kind,
            "branch": branch,
            "workerAgent": worker_agent,
            "dedupeKey": signal.dedupe_key,
        }

    workdir = prepare_isolated_workdir(
        store,
        run_id=run_id,
        repo=signal.repo,
        git_url=policy["gitUrl"],
        base_branch=policy["defaultBranch"],
        branch=branch,
    )

    if needs_diagnosis:
        diagnosis_path = store.runs_dir / f"{run_id}.diagnosis.json"
        prompt = build_diagnosis_prompt(
            signal,
            diagnosis_path=diagnosis_path,
            base_branch=policy["defaultBranch"],
        )
        launch_info = launch_agent_session(
            agent=worker_agent,
            session_name=session_name,
            workdir=workdir,
            prompt=prompt,
        )
        record = RunRecord(
            run_id=run_id,
            repo=signal.repo,
            branch=branch,
            base_branch=policy["defaultBranch"],
            workdir=str(workdir),
            worker_agent=worker_agent,
            worker_session=f"sf-{run_id}",
            diagnosis_session=session_name,
            diagnosis_path=str(diagnosis_path),
            signal=signal.to_dict(),
            status="investigating",
        )
        store.save_run(record)
        return {
            "action": "investigating",
            "runId": run_id,
            "repo": signal.repo,
            "kind": signal.kind,
            "branch": branch,
            "workerAgent": worker_agent,
            "sessionName": session_name,
            "diagnosisPath": str(diagnosis_path),
            "launch": launch_info,
        }

    prompt = build_worker_prompt(
        signal,
        repo_policy=policy,
        branch=branch,
        base_branch=policy["defaultBranch"],
    )
    launch_info = launch_agent_session(
        agent=worker_agent,
        session_name=session_name,
        workdir=workdir,
        prompt=prompt,
    )

    record = RunRecord(
        run_id=run_id,
        repo=signal.repo,
        branch=branch,
        base_branch=policy["defaultBranch"],
        workdir=str(workdir),
        worker_agent=worker_agent,
        worker_session=session_name,
        signal=signal.to_dict(),
        status="running",
    )
    store.save_run(record)
    return {
        "action": "dispatched",
        "runId": run_id,
        "repo": signal.repo,
        "kind": signal.kind,
        "branch": branch,
        "workerAgent": worker_agent,
        "sessionName": session_name,
        "launch": launch_info,
    }
