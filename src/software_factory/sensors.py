"""Signal sensors for Software Factory (Cloudflare Signal Queue, GitHub, custom commands)."""

from __future__ import annotations

import json
import os
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from software_factory.config import load_cf_access_headers
from software_factory.models import Signal, utc_now_iso


def _env_bin(env_name: str, default: str) -> str:
    return os.environ.get(env_name) or default


def pull_cloudflare_signal_queue(cfg: dict[str, Any]) -> list[Signal]:
    """Pull pending sanitized signals from open-observability-framework on Cloudflare."""
    sq = cfg.get("signalQueue") or {}
    if not sq.get("enabled"):
        return []
    endpoint = str(sq.get("endpoint") or "").rstrip("/")
    if not endpoint:
        return []

    timeout = int(sq.get("timeoutSeconds") or 20)
    headers = load_cf_access_headers(sq.get("credentialsFile"))
    url = f"{endpoint}/v1/signals?status=pending"
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        payload = json.loads(resp.read().decode("utf-8"))

    raw_items = payload.get("signals", []) if isinstance(payload, dict) else payload
    if not isinstance(raw_items, list):
        raise ValueError("Cloudflare signal queue response must be an array or {signals: [...]}")

    signals: list[Signal] = []
    for item in raw_items:
        if not isinstance(item, dict):
            continue
        item = dict(item)
        if not item.get("source"):
            item["source"] = "open-observability-framework"
        if not item.get("ackUrl") and item.get("id"):
            sig_id = urllib.parse.quote(str(item["id"]), safe="")
            item["ackUrl"] = f"{endpoint}/v1/signals/{sig_id}/ack"
        signals.append(Signal.from_dict(item))
    return signals


def _resolve_same_origin_url(endpoint: str, ref_or_url: str, *, default_prefix: str = "/v1/queries/") -> str:
    base = endpoint.rstrip("/")
    if not base:
        raise ValueError("signalQueue.endpoint is not configured")
    parsed_base = urllib.parse.urlparse(base)
    if ref_or_url.startswith(("http://", "https://")):
        parsed_target = urllib.parse.urlparse(ref_or_url)
        if (parsed_target.scheme, parsed_target.netloc) != (parsed_base.scheme, parsed_base.netloc):
            raise ValueError(
                f"Refusing cross-origin request to {parsed_target.netloc}; expected {parsed_base.netloc}"
            )
        return ref_or_url
    if ref_or_url.startswith("/"):
        return f"{base}{ref_or_url}"
    encoded = urllib.parse.quote(ref_or_url, safe="")
    return f"{base}{default_prefix}{encoded}"


def fetch_cloudflare_query(cfg: dict[str, Any], ref_or_url: str) -> Any:
    """Fetch a read-only sanitized telemetry query reference from open-observability-framework."""
    sq = cfg.get("signalQueue") or {}
    endpoint = str(sq.get("endpoint") or "").rstrip("/")
    url = _resolve_same_origin_url(endpoint, ref_or_url, default_prefix="/v1/queries/")
    timeout = int(sq.get("timeoutSeconds") or 20)
    headers = load_cf_access_headers(sq.get("credentialsFile"))
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_recovery_status(cfg: dict[str, Any], query_url: str) -> dict[str, Any]:
    """Check post-deploy recovery metrics from open-observability-framework."""
    sq = cfg.get("signalQueue") or {}
    endpoint = str(sq.get("endpoint") or "").rstrip("/")
    url = _resolve_same_origin_url(endpoint, query_url, default_prefix="/v1/recovery/")
    timeout = int(sq.get("timeoutSeconds") or 20)
    headers = load_cf_access_headers(sq.get("credentialsFile"))
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Recovery check response must be a JSON object")
    return data


VALID_ACK_STATUSES = frozenset(
    {"dismissed", "auto_merged", "human_review", "resolved", "recovery_failed"}
)


def ack_cloudflare_signal(
    cfg: dict[str, Any],
    signal_dict: dict[str, Any],
    *,
    status: str,
    run_id: str,
    pr_url: str | None = None,
    reason: str | None = None,
) -> bool:
    """Send status acknowledgment back to the Cloudflare Signal Queue."""
    if status not in VALID_ACK_STATUSES:
        raise ValueError(f"Unsupported signal queue ack status: {status!r}")
    ack_url = signal_dict.get("ackUrl")
    if not ack_url:
        return False
    sq = cfg.get("signalQueue") or {}
    timeout = int(sq.get("timeoutSeconds") or 20)
    headers = load_cf_access_headers(sq.get("credentialsFile"))
    headers["Content-Type"] = "application/json"
    body = json.dumps(
        {
            "status": status,
            "runId": run_id,
            "prUrl": pr_url,
            "reason": reason,
            "updatedAt": utc_now_iso(),
        }
    ).encode("utf-8")
    req = urllib.request.Request(str(ack_url), data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return 200 <= resp.status < 300


def parse_signals_text(text: str, *, default_repo: str | None = None, default_source: str = "command") -> list[Signal]:
    """Parse JSON object, JSON array, or NDJSON text into Signal objects."""
    stripped = text.strip()
    if not stripped:
        return []

    raw_items: list[dict[str, Any]] = []
    try:
        parsed = json.loads(stripped)
        if isinstance(parsed, dict):
            if "signals" in parsed and isinstance(parsed["signals"], list):
                raw_items = parsed["signals"]
            else:
                raw_items = [parsed]
        elif isinstance(parsed, list):
            raw_items = parsed
        else:
            raise ValueError("Unsupported JSON root type for signals")
    except json.JSONDecodeError:
        for line in stripped.splitlines():
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if not isinstance(obj, dict):
                raise ValueError("Each NDJSON line must be a JSON object")
            raw_items.append(obj)

    result: list[Signal] = []
    for item in raw_items:
        item = dict(item)
        if default_repo and not item.get("repo"):
            item["repo"] = default_repo
        if not item.get("source"):
            item["source"] = default_source
        result.append(Signal.from_dict(item))
    return result


def _collect_ci_failures(repo_policy: dict[str, Any], sensor: dict[str, Any]) -> list[Signal]:
    gh_bin = _env_bin("SF_GH_BIN", "gh")
    repo = repo_policy["repo"]
    branch = sensor.get("branch") or repo_policy["defaultBranch"]
    limit = str(sensor.get("limit") or 5)
    proc = subprocess.run(
        [
            gh_bin,
            "run",
            "list",
            "--repo",
            repo,
            "--branch",
            branch,
            "--status",
            "failure",
            "--limit",
            limit,
            "--json",
            "databaseId,workflowName,headSha,url,displayTitle,createdAt",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    runs = json.loads(proc.stdout or "[]")
    signals: list[Signal] = []
    for run in runs:
        run_id = run.get("databaseId")
        wf = run.get("workflowName") or "CI"
        sha = str(run.get("headSha") or "")[:12]
        signals.append(
            Signal.from_dict(
                {
                    "schemaVersion": 1,
                    "id": f"ci-{run_id}",
                    "source": "ci-failure",
                    "repo": repo,
                    "kind": "bugfix",
                    "severity": "high",
                    "title": f"Fix failing CI workflow: {wf}",
                    "summary": f"Workflow '{wf}' failed on branch '{branch}' (commit {sha}): {run.get('displayTitle', '')}",
                    "evidence": {
                        "workflowName": wf,
                        "runId": run_id,
                        "headSha": run.get("headSha"),
                        "url": run.get("url"),
                    },
                    "dedupeKey": f"ci-failure:{repo}:{wf}:{sha}",
                }
            )
        )
    return signals


def _collect_security_alerts(repo_policy: dict[str, Any], sensor: dict[str, Any]) -> list[Signal]:
    gh_bin = _env_bin("SF_GH_BIN", "gh")
    repo = repo_policy["repo"]
    per_page = int(sensor.get("limit") or 10)
    proc = subprocess.run(
        [
            gh_bin,
            "api",
            f"repos/{repo}/dependabot/alerts?state=open&per_page={per_page}",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return []
    alerts = json.loads(proc.stdout or "[]")
    if not isinstance(alerts, list):
        return []
    signals: list[Signal] = []
    for alert in alerts:
        num = alert.get("number")
        adv = alert.get("security_advisory") or {}
        dep = (alert.get("dependency") or {}).get("package") or {}
        pkg_name = dep.get("name") or "dependency"
        sev = str(adv.get("severity") or "medium").lower()
        if sev not in ("low", "medium", "high", "critical"):
            sev = "medium"
        summary = adv.get("summary") or f"Dependabot alert #{num} in {pkg_name}"
        signals.append(
            Signal.from_dict(
                {
                    "schemaVersion": 1,
                    "id": f"sec-{num}",
                    "source": "security-alerts",
                    "repo": repo,
                    "kind": "security",
                    "severity": sev,
                    "title": f"Security fix: {pkg_name} ({adv.get('ghsa_id') or f'#{num}'})",
                    "summary": summary,
                    "evidence": {
                        "alertNumber": num,
                        "package": pkg_name,
                        "ghsaId": adv.get("ghsa_id"),
                        "cveId": adv.get("cve_id"),
                        "htmlUrl": alert.get("html_url"),
                    },
                    "dedupeKey": f"security:{repo}:dependabot:{num}",
                }
            )
        )
    return signals


def _collect_command_sensor(repo_policy: dict[str, Any], sensor: dict[str, Any]) -> list[Signal]:
    cmd = sensor.get("command")
    if not cmd:
        return []
    repo = repo_policy["repo"]
    name = sensor.get("name") or "command"
    kind = sensor.get("kind") or "bugfix"
    proc = subprocess.run(
        ["bash", "-lc", str(cmd)],
        capture_output=True,
        text=True,
        check=False,
    )
    stdout = (proc.stdout or "").strip()
    if stdout:
        try:
            return parse_signals_text(stdout, default_repo=repo, default_source=f"command:{name}")
        except (json.JSONDecodeError, ValueError):
            pass

    if proc.returncode != 0:
        excerpt = (proc.stderr or proc.stdout or "").strip()[-1500:]
        return [
            Signal.from_dict(
                {
                    "schemaVersion": 1,
                    "id": f"cmd-{name}-{int(time.time())}",
                    "source": f"command:{name}",
                    "repo": repo,
                    "kind": kind,
                    "severity": sensor.get("severity") or "high",
                    "title": f"Sensor '{name}' detected an issue",
                    "summary": f"Command sensor '{name}' exited with status {proc.returncode}.",
                    "evidence": {"exitCode": proc.returncode, "outputExcerpt": excerpt},
                    "dedupeKey": f"command:{repo}:{name}",
                }
            )
        ]
    return []


def _collect_efficiency_audit(
    repo_policy: dict[str, Any],
    sensor: dict[str, Any],
    state_dir: Path,
    *,
    dry_run: bool = False,
) -> list[Signal]:
    repo = repo_policy["repo"]
    interval_hours = float(sensor.get("intervalHours") or 168)  # default weekly
    marker_dir = state_dir / "sensor-state"
    safe_repo = repo.replace("/", "__")
    marker = marker_dir / f"efficiency-audit-{safe_repo}.ts"
    now = time.time()
    if marker.exists():
        try:
            last = float(marker.read_text(encoding="utf-8").strip())
            if (now - last) < interval_hours * 3600:
                return []
        except ValueError:
            pass
    if not dry_run:
        marker_dir.mkdir(parents=True, exist_ok=True)
        marker.write_text(str(now), encoding="utf-8")
    week_tag = time.strftime("%Y-W%W", time.gmtime(now))
    return [
        Signal.from_dict(
            {
                "schemaVersion": 1,
                "id": f"eff-{safe_repo}-{week_tag}",
                "source": "efficiency-audit",
                "repo": repo,
                "kind": sensor.get("kind") or "efficiency",
                "severity": "low",
                "title": f"Periodic efficiency & performance audit ({week_tag})",
                "summary": (
                    "Inspect hotspots, redundant work, slow tests, or clear low-risk efficiency "
                    "improvements. Keep changes small and behavior-preserving; if a larger redesign "
                    "is needed, open a proposal PR without risky edits."
                ),
                "evidence": {"period": week_tag},
                "dedupeKey": f"efficiency-audit:{repo}:{week_tag}",
            }
        )
    ]


def collect_repo_signals(
    repo_policy: dict[str, Any],
    state_dir: Path,
    *,
    dry_run: bool = False,
) -> list[Signal]:
    signals: list[Signal] = []
    for sensor in repo_policy.get("sensors", []):
        if not isinstance(sensor, dict) or sensor.get("enabled", True) is False:
            continue
        s_type = sensor.get("type")
        if s_type == "ci-failure":
            signals.extend(_collect_ci_failures(repo_policy, sensor))
        elif s_type == "security-alerts":
            signals.extend(_collect_security_alerts(repo_policy, sensor))
        elif s_type == "command":
            signals.extend(_collect_command_sensor(repo_policy, sensor))
        elif s_type == "efficiency-audit":
            signals.extend(_collect_efficiency_audit(repo_policy, sensor, state_dir, dry_run=dry_run))
    return signals
