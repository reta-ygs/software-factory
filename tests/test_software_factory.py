"""Comprehensive offline unit and integration tests for Software Factory."""

from __future__ import annotations

import http.server
import io
import json
import os
import shutil
import stat
import subprocess
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from software_factory.cli import main
from software_factory.config import DEFAULT_CONFIG, choose_reviewer_agent, load_cf_access_headers
from software_factory.models import DiffStat, ReviewVerdict, Signal
from software_factory.risk import evaluate_risk, parse_git_numstat


class RiskEvaluationTests(unittest.TestCase):
    def _policy(self, **overrides):
        pol = dict(DEFAULT_CONFIG["defaults"]["autoMerge"])
        pol["enabled"] = True
        pol.update(overrides)
        return pol

    def test_low_risk_bugfix_is_eligible(self):
        stats = [DiffStat(path="src/math_utils.py", additions=8, deletions=3)]
        report = evaluate_risk(kind="bugfix", diff_stats=stats, auto_merge_policy=self._policy())
        self.assertEqual(report.level, "low")
        self.assertTrue(report.auto_merge_eligible)
        self.assertEqual(report.reasons, [])

    def test_feature_always_requires_human_review(self):
        stats = [DiffStat(path="src/math_utils.py", additions=2, deletions=0)]
        report = evaluate_risk(kind="feature", diff_stats=stats, auto_merge_policy=self._policy())
        self.assertEqual(report.level, "high")
        self.assertFalse(report.auto_merge_eligible)
        self.assertTrue(any("feature" in r for r in report.reasons))

    def test_disabled_auto_merge_blocks(self):
        stats = [DiffStat(path="src/math_utils.py", additions=2, deletions=0)]
        report = evaluate_risk(
            kind="bugfix",
            diff_stats=stats,
            auto_merge_policy=self._policy(enabled=False),
        )
        self.assertFalse(report.auto_merge_eligible)

    def test_denied_path_blocks(self):
        stats = [DiffStat(path="src/auth/jwt_verify.py", additions=4, deletions=2)]
        report = evaluate_risk(kind="bugfix", diff_stats=stats, auto_merge_policy=self._policy())
        self.assertFalse(report.auto_merge_eligible)
        self.assertEqual(report.matched_denied_paths, ["src/auth/jwt_verify.py"])

    def test_exceeding_line_limit_blocks(self):
        stats = [DiffStat(path="src/app.py", additions=200, deletions=60)]
        report = evaluate_risk(kind="efficiency", diff_stats=stats, auto_merge_policy=self._policy())
        self.assertFalse(report.auto_merge_eligible)
        self.assertTrue(any("maxChangedLines" in r for r in report.reasons))

    def test_manifest_change_blocked_for_non_security(self):
        stats = [DiffStat(path="package.json", additions=1, deletions=1)]
        report = evaluate_risk(kind="efficiency", diff_stats=stats, auto_merge_policy=self._policy())
        self.assertFalse(report.auto_merge_eligible)
        self.assertEqual(report.touched_manifests, ["package.json"])

        sec_report = evaluate_risk(kind="security", diff_stats=stats, auto_merge_policy=self._policy())
        self.assertTrue(sec_report.auto_merge_eligible)

    def test_parse_git_numstat_handles_binary(self):
        out = "10\t2\tsrc/a.py\n-\t-\tassets/logo.png\n"
        stats = parse_git_numstat(out)
        self.assertEqual(len(stats), 2)
        self.assertEqual(stats[0].changed_lines, 12)
        self.assertEqual(stats[1].changed_lines, 200)

    def test_choose_reviewer_agent_differs_from_worker(self):
        self.assertEqual(choose_reviewer_agent("agy", "codex"), "codex")
        self.assertEqual(choose_reviewer_agent("agy", "agy"), "codex")
        self.assertEqual(choose_reviewer_agent("codex", "codex"), "agy")


class CredentialsTests(unittest.TestCase):
    def test_load_cf_access_headers_from_file(self):
        with tempfile.TemporaryDirectory() as td:
            cred = Path(td) / "cf.env"
            cred.write_text(
                'export CF_ACCESS_CLIENT_ID="id-123"\nCF_ACCESS_CLIENT_SECRET=sec-456\n',
                encoding="utf-8",
            )
            headers = load_cf_access_headers(str(cred))
            self.assertEqual(headers["CF-Access-Client-Id"], "id-123")
            self.assertEqual(headers["CF-Access-Client-Secret"], "sec-456")


class EndToEndWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.root = Path(self.td.name)
        self.state_dir = self.root / "state"
        self.cfg_path = self.root / "config.json"
        self.bin_dir = self.root / "bin"
        self.bin_dir.mkdir(parents=True, exist_ok=True)
        self.hc_log = self.root / "hc.log"
        self.gh_log = self.root / "gh.log"

        # Create a real local bare git repo fixture
        self.src_repo = self.root / "src-repo"
        self.src_repo.mkdir()
        self._git(self.src_repo, "init", "-b", "main")
        self._git(self.src_repo, "config", "user.name", "Test")
        self._git(self.src_repo, "config", "user.email", "test@example.com")
        self._git(self.src_repo, "config", "commit.gpgsign", "false")
        (self.src_repo / "app.py").write_text("def add(a, b):\n    return a - b\n", encoding="utf-8")
        self._git(self.src_repo, "add", "app.py")
        self._git(self.src_repo, "commit", "-m", "initial")

        self.bare_repo = self.root / "origin.git"
        subprocess.run(["git", "init", "--bare", "-q", str(self.bare_repo)], check=True)
        self._git(self.src_repo, "push", "-q", str(self.bare_repo), "main")

        bash_bin = shutil.which("bash") or "/bin/sh"

        # Mock hc
        self.mock_hc = self.bin_dir / "mock-hc"
        self.mock_hc.write_text(
            f"""#!{bash_bin}
set -euo pipefail
printf '%s\\n' "$*" >> "{self.hc_log}"
if [[ "${{1:-}}" == "--json" && "${{2:-}}" == "ls" ]]; then
  printf '%s\\n' "${{MOCK_HC_LS:-[]}}"
  exit 0
fi
if [[ "${{1:-}}" == "run" ]]; then
  printf '{{"first_message":{{"sent":true}}}}\\n'
  exit 0
fi
exit 0
""",
            encoding="utf-8",
        )
        os.chmod(self.mock_hc, 0o755)

        # Mock gh
        self.mock_gh = self.bin_dir / "mock-gh"
        self.mock_gh.write_text(
            f"""#!{bash_bin}
set -euo pipefail
printf '%s\\n' "$*" >> "{self.gh_log}"
if [[ "${{1:-}}" == "pr" && "${{2:-}}" == "list" ]]; then
  printf '%s\\n' "${{MOCK_GH_PR_LIST:-[]}}"
  exit 0
fi
exit 0
""",
            encoding="utf-8",
        )
        os.chmod(self.mock_gh, 0o755)

        self.orig_env = dict(os.environ)
        os.environ["SF_CONFIG"] = str(self.cfg_path)
        os.environ["SF_STATE_DIR"] = str(self.state_dir)
        os.environ["SF_HC_BIN"] = str(self.mock_hc)
        os.environ["SF_GH_BIN"] = str(self.mock_gh)
        os.environ["MOCK_HC_LS"] = "[]"
        os.environ["MOCK_GH_PR_LIST"] = "[]"

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.orig_env)
        self.td.cleanup()

    def _git(self, cwd: Path, *args: str) -> None:
        subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True)

    def _run_cli(self, *args: str) -> dict | list:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(list(args))
        self.assertEqual(rc, 0)
        return json.loads(buf.getvalue())

    def test_cloudflare_pull_reconcile_auto_merge_and_ack(self):
        acks: list[dict] = []
        auth_headers_seen: list[tuple[str | None, str | None]] = []

        signal_payload = {
            "signals": [
                {
                    "schemaVersion": 1,
                    "id": "sig-cf-1",
                    "source": "open-observability-framework",
                    "repo": "reta-ygs/demo",
                    "kind": "bugfix",
                    "severity": "high",
                    "title": "Fix subtraction typo in add()",
                    "summary": "Error spike in /calc",
                    "evidence": {"errorRate": 0.05},
                    "dedupeKey": "oof:demo:add-bug",
                }
            ]
        }

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                return

            def do_GET(self):
                auth_headers_seen.append(
                    (self.headers.get("CF-Access-Client-Id"), self.headers.get("CF-Access-Client-Secret"))
                )
                body = json.dumps(signal_payload).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                acks.append(json.loads(self.rfile.read(length).decode()))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"ok":true}')

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            cred_file = self.root / "cf.env"
            cred_file.write_text("CF_ACCESS_CLIENT_ID=cid\nCF_ACCESS_CLIENT_SECRET=csec\n", encoding="utf-8")

            self._run_cli(
                "init",
                "--signal-queue-endpoint",
                f"http://127.0.0.1:{port}",
                "--credentials-file",
                str(cred_file),
            )
            self._run_cli(
                "repo",
                "add",
                "reta-ygs/demo",
                "--git-url",
                str(self.bare_repo),
                "--auto-merge",
            )

            # 1. Patrol pulls signal from Cloudflare Signal Queue and dispatches worker
            patrol_res = self._run_cli("patrol")
            self.assertEqual(patrol_res["signalsFound"], 1)
            self.assertEqual(patrol_res["results"][0]["action"], "dispatched")
            run_id = patrol_res["results"][0]["runId"]
            self.assertEqual(auth_headers_seen[0], ("cid", "csec"))

            # Second patrol deduplicates the active run
            patrol_res2 = self._run_cli("patrol")
            self.assertEqual(patrol_res2["results"][0]["action"], "skipped")

            # Simulate worker making a small bugfix commit and pushing branch
            run_detail = self._run_cli("status", run_id)
            workdir = Path(run_detail["workdir"])
            self._git(workdir, "config", "user.name", "Worker")
            self._git(workdir, "config", "user.email", "worker@example.com")
            self._git(workdir, "config", "commit.gpgsign", "false")
            (workdir / "app.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
            self._git(workdir, "add", "app.py")
            self._git(workdir, "commit", "-m", "fix add")
            self._git(workdir, "push", "-u", "origin", run_detail["branch"])

            # 2. Reconcile detects open PR and launches independent codex reviewer
            os.environ["MOCK_GH_PR_LIST"] = json.dumps(
                [
                    {
                        "number": 42,
                        "url": "https://github.com/reta-ygs/demo/pull/42",
                        "baseRefName": "main",
                        "headRefName": run_detail["branch"],
                    }
                ]
            )
            rec1 = self._run_cli("reconcile")
            self.assertEqual(rec1["actions"][0]["action"], "review-started")
            self.assertEqual(rec1["actions"][0]["reviewerAgent"], "codex")

            # 3. Independent reviewer writes approve + low impact verdict -> auto-merge & ack
            run_detail = self._run_cli("status", run_id)
            Path(run_detail["verdict_path"]).write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "verdict": "approve",
                        "behaviorImpact": "low",
                        "summary": "Clean 1-line bugfix with no regressions.",
                        "findings": [],
                    }
                ),
                encoding="utf-8",
            )
            rec2 = self._run_cli("reconcile")
            self.assertEqual(rec2["actions"][0]["action"], "auto_merged")

            gh_calls = self.gh_log.read_text(encoding="utf-8")
            self.assertIn("pr merge 42 --repo reta-ygs/demo --auto --squash", gh_calls)
            self.assertIn("--add-label sf:auto-merge", gh_calls)
            self.assertEqual(len(acks), 1)
            self.assertEqual(acks[0]["status"], "auto_merged")
            self.assertEqual(acks[0]["prUrl"], "https://github.com/reta-ygs/demo/pull/42")
        finally:
            server.shutdown()
            server.server_close()

    def test_feature_submit_always_escalates_to_human_review(self):
        self._run_cli("init")
        self._run_cli(
            "repo",
            "add",
            "reta-ygs/demo",
            "--git-url",
            str(self.bare_repo),
            "--auto-merge",
        )
        sub_res = self._run_cli(
            "submit",
            "--repo",
            "reta-ygs/demo",
            "--kind",
            "feature",
            "--title",
            "Add multiply function",
            "--prompt",
            "Implement multiply(a, b)",
        )
        self.assertEqual(sub_res["action"], "dispatched")
        run_id = sub_res["runId"]
        run_detail = self._run_cli("status", run_id)
        workdir = Path(run_detail["workdir"])
        self._git(workdir, "config", "user.name", "Worker")
        self._git(workdir, "config", "user.email", "worker@example.com")
        self._git(workdir, "config", "commit.gpgsign", "false")
        (workdir / "app.py").write_text(
            "def add(a, b):\n    return a - b\n\ndef mul(a, b):\n    return a * b\n",
            encoding="utf-8",
        )
        self._git(workdir, "add", "app.py")
        self._git(workdir, "commit", "-m", "add mul")
        self._git(workdir, "push", "-u", "origin", run_detail["branch"])

        os.environ["MOCK_GH_PR_LIST"] = json.dumps(
            [
                {
                    "number": 99,
                    "url": "https://github.com/reta-ygs/demo/pull/99",
                    "baseRefName": "main",
                    "headRefName": run_detail["branch"],
                }
            ]
        )
        self._run_cli("reconcile")
        run_detail = self._run_cli("status", run_id)
        # Even if reviewer approves with low impact, mechanical gate blocks feature auto-merge!
        Path(run_detail["verdict_path"]).write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "verdict": "approve",
                    "behaviorImpact": "low",
                    "summary": "Looks good.",
                    "findings": [],
                }
            ),
            encoding="utf-8",
        )
        rec = self._run_cli("reconcile")
        self.assertEqual(rec["actions"][0]["action"], "human_review")
        gh_calls = self.gh_log.read_text(encoding="utf-8")
        self.assertIn("--add-label sf:needs-human-review", gh_calls)
        self.assertNotIn("pr merge 99", gh_calls)


if __name__ == "__main__":
    unittest.main()
