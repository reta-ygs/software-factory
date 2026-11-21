"""CLI entrypoint for Software Factory (sf)."""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Any

from software_factory.config import (
    DEFAULT_CONFIG,
    effective_repo_policy,
    find_repo_config,
    get_config_path,
    load_config,
    save_config,
)
from software_factory.models import ReviewVerdict, Signal
from software_factory.reconcile import (
    apply_review_verdict,
    compute_run_risk,
    find_open_pr,
    reconcile_runs,
    start_independent_review,
)
from software_factory.runner import StateStore, dispatch_signal
from software_factory.sensors import (
    collect_repo_signals,
    parse_signals_text,
    pull_cloudflare_signal_queue,
)


def _print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False))


def cmd_init(args: argparse.Namespace) -> int:
    cfg_path = get_config_path()
    if cfg_path.exists() and not args.force:
        print(f"Config already exists at {cfg_path} (use --force to overwrite)", file=sys.stderr)
        return 1
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    if args.signal_queue_endpoint:
        cfg["signalQueue"]["enabled"] = True
        cfg["signalQueue"]["endpoint"] = args.signal_queue_endpoint
    if args.credentials_file:
        cfg["signalQueue"]["credentialsFile"] = args.credentials_file
    saved = save_config(cfg, cfg_path)
    _print_json({"status": "initialized", "configPath": str(saved)})
    return 0


def cmd_repo_add(args: argparse.Namespace) -> int:
    cfg = load_config()
    existing = find_repo_config(cfg, args.repo)
    sensors: list[dict[str, Any]] = []
    if args.ci_sensor:
        sensors.append({"type": "ci-failure", "enabled": True})
    if args.security_sensor:
        sensors.append({"type": "security-alerts", "enabled": True})
    if args.efficiency_sensor:
        sensors.append({"type": "efficiency-audit", "enabled": True, "intervalHours": 168})
    for cmd in args.command_sensor or []:
        sensors.append({"type": "command", "name": "custom", "command": cmd, "enabled": True})

    entry: dict[str, Any] = {
        "repo": args.repo,
        "defaultBranch": args.default_branch,
        "autoMerge": {"enabled": bool(args.auto_merge)},
        "sensors": sensors,
    }
    if args.git_url:
        entry["gitUrl"] = args.git_url
    if args.test_command:
        entry["testCommand"] = args.test_command

    if existing is not None:
        cfg["repos"] = [entry if r.get("repo") == args.repo else r for r in cfg["repos"]]
    else:
        cfg["repos"].append(entry)

    saved = save_config(cfg)
    _print_json({"status": "saved", "configPath": str(saved), "repo": entry})
    return 0


def cmd_repo_list(_args: argparse.Namespace) -> int:
    cfg = load_config()
    _print_json(cfg.get("repos", []))
    return 0


def cmd_submit(args: argparse.Namespace) -> int:
    cfg = load_config()
    store = StateStore()
    summary = args.prompt or ""
    evidence: dict[str, Any] = {}
    if args.spec:
        spec_path = Path(args.spec).expanduser()
        spec_text = spec_path.read_text(encoding="utf-8")
        summary = (summary + "\n\n" + spec_text).strip() if summary else spec_text
        evidence["specFile"] = str(spec_path)
    if not summary:
        summary = args.title

    signal = Signal.from_dict(
        {
            "schemaVersion": 1,
            "source": "manual",
            "repo": args.repo,
            "kind": args.kind,
            "severity": args.severity,
            "title": args.title,
            "summary": summary,
            "evidence": evidence,
            "dedupeKey": args.dedupe_key or "",
        }
    )
    with store.lock("dispatch") as acquired:
        if not acquired:
            _print_json({"action": "skipped", "reason": "dispatch lock held"})
            return 0
        res = dispatch_signal(cfg, store, signal, dry_run=args.dry_run)
    _print_json(res)
    return 0


def cmd_ingest(args: argparse.Namespace) -> int:
    cfg = load_config()
    store = StateStore()
    if args.file == "-" or args.file is None:
        raw_text = sys.stdin.read()
    else:
        raw_text = Path(args.file).expanduser().read_text(encoding="utf-8")

    signals = parse_signals_text(raw_text, default_source="ingest")
    results: list[dict[str, Any]] = []
    with store.lock("dispatch") as acquired:
        if not acquired:
            _print_json({"action": "skipped", "reason": "dispatch lock held"})
            return 0
        for sig in signals:
            results.append(dispatch_signal(cfg, store, sig, dry_run=args.dry_run))
    _print_json({"ingested": len(signals), "results": results})
    return 0


def cmd_patrol(args: argparse.Namespace) -> int:
    cfg = load_config()
    store = StateStore()
    with store.lock("patrol") as acquired:
        if not acquired:
            _print_json({"action": "skipped", "reason": "patrol lock held"})
            return 0

        signals: list[Signal] = []
        errors: list[str] = []

        if not args.repo:
            try:
                signals.extend(pull_cloudflare_signal_queue(cfg))
            except Exception as exc:
                errors.append(f"signalQueue: {exc}")

        repos = cfg.get("repos", [])
        for repo_entry in repos:
            repo_name = repo_entry.get("repo")
            if not repo_name:
                continue
            if args.repo and repo_name != args.repo:
                continue
            policy = effective_repo_policy(cfg, repo_name)
            try:
                signals.extend(collect_repo_signals(policy, store.root))
            except Exception as exc:
                errors.append(f"{repo_name}: {exc}")

        results: list[dict[str, Any]] = []
        for sig in signals:
            if args.repo and sig.repo != args.repo:
                continue
            results.append(dispatch_signal(cfg, store, sig, dry_run=args.dry_run))

    _print_json({"signalsFound": len(signals), "results": results, "errors": errors})
    return 1 if errors and not results else 0


def cmd_evaluate_risk(args: argparse.Namespace) -> int:
    cfg = load_config()
    store = StateStore()
    record = store.load_run(args.run_id)
    report = compute_run_risk(cfg, record)
    _print_json(report.to_dict())
    return 0


def cmd_review(args: argparse.Namespace) -> int:
    cfg = load_config()
    store = StateStore()
    record = store.load_run(args.run_id)
    if args.apply_verdict:
        verdict = ReviewVerdict.from_dict(
            json.loads(Path(args.apply_verdict).read_text(encoding="utf-8"))
        )
        res = apply_review_verdict(cfg, store, record, verdict, dry_run=args.dry_run)
        _print_json(res)
        return 0

    if not record.pr_number:
        pr = find_open_pr(record.repo, record.branch)
        if not pr:
            print(f"No open PR found for branch {record.branch} in {record.repo}", file=sys.stderr)
            return 1
        record.pr_number = int(pr["number"])
        record.pr_url = str(pr["url"])
        store.save_run(record)

    res = start_independent_review(cfg, store, record, dry_run=args.dry_run)
    _print_json(res)
    return 0


def cmd_reconcile(args: argparse.Namespace) -> int:
    cfg = load_config()
    store = StateStore()
    with store.lock("reconcile") as acquired:
        if not acquired:
            _print_json({"action": "skipped", "reason": "reconcile lock held"})
            return 0
        results = reconcile_runs(cfg, store, dry_run=args.dry_run)
    _print_json({"actions": results})
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    store = StateStore()
    if args.run_id:
        _print_json(store.load_run(args.run_id).to_dict())
        return 0
    runs = [
        {
            "runId": r.run_id,
            "repo": r.repo,
            "kind": r.signal.get("kind"),
            "status": r.status,
            "branch": r.branch,
            "prUrl": r.pr_url,
            "workerAgent": r.worker_agent,
            "reviewerAgent": r.reviewer_agent,
            "updatedAt": r.updated_at,
        }
        for r in store.list_runs()
    ]
    _print_json(runs)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sf",
        description="Software Factory CLI orchestrating herdr-core agents",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Initialize Software Factory config")
    p_init.add_argument("--force", action="store_true")
    p_init.add_argument("--signal-queue-endpoint", default="")
    p_init.add_argument("--credentials-file", default="")
    p_init.set_defaults(func=cmd_init)

    p_repo = sub.add_parser("repo", help="Manage registered repositories")
    repo_sub = p_repo.add_subparsers(dest="repo_cmd", required=True)
    p_repo_add = repo_sub.add_parser("add", help="Register or update a repository")
    p_repo_add.add_argument("repo", help="GitHub owner/repo")
    p_repo_add.add_argument("--default-branch", default="main")
    p_repo_add.add_argument("--git-url", default="")
    p_repo_add.add_argument("--auto-merge", action="store_true", help="Enable low-risk auto-merge")
    p_repo_add.add_argument("--test-command", default="")
    p_repo_add.add_argument("--ci-sensor", action="store_true")
    p_repo_add.add_argument("--security-sensor", action="store_true")
    p_repo_add.add_argument("--efficiency-sensor", action="store_true")
    p_repo_add.add_argument("--command-sensor", action="append", default=[])
    p_repo_add.set_defaults(func=cmd_repo_add)

    p_repo_list = repo_sub.add_parser("list", help="List registered repositories")
    p_repo_list.set_defaults(func=cmd_repo_list)

    p_submit = sub.add_parser("submit", help="Manually submit a task (e.g. new feature)")
    p_submit.add_argument("--repo", required=True)
    p_submit.add_argument("--kind", choices=["feature", "bugfix", "security", "efficiency", "proposal"], default="feature")
    p_submit.add_argument("--severity", choices=["low", "medium", "high", "critical"], default="medium")
    p_submit.add_argument("--title", required=True)
    p_submit.add_argument("--prompt", default="")
    p_submit.add_argument("--spec", default="", help="Path to a spec markdown file")
    p_submit.add_argument("--dedupe-key", default="")
    p_submit.add_argument("--dry-run", action="store_true")
    p_submit.set_defaults(func=cmd_submit)

    p_ingest = sub.add_parser("ingest", help="Ingest Signal JSON from file or stdin")
    p_ingest.add_argument("file", nargs="?", default="-")
    p_ingest.add_argument("--dry-run", action="store_true")
    p_ingest.set_defaults(func=cmd_ingest)

    p_patrol = sub.add_parser("patrol", help="Run configured sensors and Cloudflare Signal Queue pull")
    p_patrol.add_argument("--repo", default="")
    p_patrol.add_argument("--dry-run", action="store_true")
    p_patrol.set_defaults(func=cmd_patrol)

    p_risk = sub.add_parser("evaluate-risk", help="Run deterministic risk evaluation on a run")
    p_risk.add_argument("run_id")
    p_risk.set_defaults(func=cmd_evaluate_risk)

    p_review = sub.add_parser("review", help="Start independent review or apply a verdict JSON")
    p_review.add_argument("run_id")
    p_review.add_argument("--apply-verdict", default="")
    p_review.add_argument("--dry-run", action="store_true")
    p_review.set_defaults(func=cmd_review)

    p_rec = sub.add_parser("reconcile", help="Advance active runs through review and merge gates")
    p_rec.add_argument("--dry-run", action="store_true")
    p_rec.set_defaults(func=cmd_reconcile)

    p_status = sub.add_parser("status", help="Show run status")
    p_status.add_argument("run_id", nargs="?")
    p_status.set_defaults(func=cmd_status)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))
