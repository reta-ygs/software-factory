"""Configuration and path management for Software Factory."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Any

DEFAULT_DENIED_PATHS = [
    "*auth*",
    "*permission*",
    "*security*",
    "*secret*",
    "*.env*",
    "*migration*",
    "*schema*",
    "*.sql",
    ".github/workflows/*",
    "nix/nixos/*",
    "Dockerfile*",
    "terraform/*",
    "infra/*",
    "*openapi*",
    "*swagger*",
    "*.proto",
    "*.graphql",
]

DEFAULT_MANIFEST_FILES = [
    "package.json",
    "Cargo.toml",
    "pyproject.toml",
    "go.mod",
    "flake.nix",
    "Gemfile",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
]

DEFAULT_CONFIG: dict[str, Any] = {
    "schemaVersion": 1,
    "defaults": {
        "workerAgent": "agy",
        "reviewerAgent": "codex",
        "maxConcurrentRuns": 2,
        "requireDiagnosis": True,
        "recoveryWaitMinutes": 30,
        "allowedCommentAssociations": ["OWNER", "MEMBER", "COLLABORATOR"],
        "allowedCommentAuthors": [],
        "autoMerge": {
            "enabled": False,
            "mergeMethod": "squash",
            "maxFiles": 10,
            "maxChangedLines": 250,
            "allowManifestChanges": False,
            "deniedPaths": DEFAULT_DENIED_PATHS,
            "manifestFiles": DEFAULT_MANIFEST_FILES,
        },
    },
    "signalQueue": {
        "enabled": False,
        "endpoint": "",
        "credentialsFile": "",
        "timeoutSeconds": 20,
    },
    "repos": [],
}


def get_config_path() -> Path:
    override = os.environ.get("SF_CONFIG")
    if override:
        return Path(override).expanduser()
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".config"
    return base / "software-factory" / "config.json"


def get_state_dir() -> Path:
    override = os.environ.get("SF_STATE_DIR")
    if override:
        return Path(override).expanduser()
    xdg = os.environ.get("XDG_STATE_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".local" / "state"
    return base / "software-factory"


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def load_config(path: Path | None = None) -> dict[str, Any]:
    cfg_path = path or get_config_path()
    if not cfg_path.exists():
        return copy.deepcopy(DEFAULT_CONFIG)
    raw = json.loads(cfg_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"Config at {cfg_path} must be a JSON object")
    return deep_merge(DEFAULT_CONFIG, raw)


def save_config(cfg: dict[str, Any], path: Path | None = None) -> Path:
    cfg_path = path or get_config_path()
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = cfg_path.with_suffix(".tmp")
    tmp_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.chmod(tmp_path, 0o600)
    tmp_path.replace(cfg_path)
    return cfg_path


def find_repo_config(cfg: dict[str, Any], repo: str) -> dict[str, Any] | None:
    for entry in cfg.get("repos", []):
        if entry.get("repo") == repo:
            return entry
    return None


def effective_repo_policy(cfg: dict[str, Any], repo: str) -> dict[str, Any]:
    defaults = copy.deepcopy(cfg.get("defaults", DEFAULT_CONFIG["defaults"]))
    repo_cfg = find_repo_config(cfg, repo) or {}
    merged = deep_merge(
        defaults,
        {
            k: v
            for k, v in repo_cfg.items()
            if k
            in (
                "workerAgent",
                "reviewerAgent",
                "autoMerge",
                "requireDiagnosis",
                "recoveryWaitMinutes",
                "allowedCommentAssociations",
                "allowedCommentAuthors",
            )
        },
    )
    merged["repo"] = repo
    merged["gitUrl"] = repo_cfg.get("gitUrl") or f"git@github.com:{repo}.git"
    merged["defaultBranch"] = repo_cfg.get("defaultBranch") or "main"
    merged["sensors"] = list(repo_cfg.get("sensors", []))
    merged["testCommand"] = repo_cfg.get("testCommand")
    return merged


def choose_reviewer_agent(worker_agent: str, configured_reviewer: str | None) -> str:
    """Ensure the independent reviewer is a different agent from the worker."""
    if configured_reviewer and configured_reviewer != worker_agent:
        return configured_reviewer
    if worker_agent == "agy":
        return "codex"
    return "agy"


def load_cf_access_headers(credentials_file: str | None) -> dict[str, str]:
    """Load Cloudflare Access Service Token headers from a chmod-600 env file or environment."""
    client_id = ""
    client_secret = ""
    bearer = ""

    if credentials_file:
        cred_path = Path(credentials_file).expanduser()
        if not cred_path.exists():
            raise FileNotFoundError(f"Credentials file not found: {cred_path}")
        for raw_line in cred_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            if line.startswith("export "):
                line = line[len("export "):].strip()
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if key == "CF_ACCESS_CLIENT_ID":
                client_id = val
            elif key == "CF_ACCESS_CLIENT_SECRET":
                client_secret = val
            elif key == "SF_SIGNAL_QUEUE_TOKEN":
                bearer = val

    client_id = client_id or os.environ.get("CF_ACCESS_CLIENT_ID", "")
    client_secret = client_secret or os.environ.get("CF_ACCESS_CLIENT_SECRET", "")
    bearer = bearer or os.environ.get("SF_SIGNAL_QUEUE_TOKEN", "")

    headers: dict[str, str] = {"Accept": "application/json"}
    if client_id and client_secret:
        headers["CF-Access-Client-Id"] = client_id
        headers["CF-Access-Client-Secret"] = client_secret
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    return headers
