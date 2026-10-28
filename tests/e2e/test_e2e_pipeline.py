"""E2E: the batch pipeline and operator tooling, run as real processes against an isolated store.

  analyze.py      five daily snapshots -> baseline seeding -> deviation findings on day five
  server.py       first-start seeding, role migration, console recovery commands, LLM-off start
  store.py        check / stats CLI
  scheduler.py    status CLI (next runs of the jobs)
  repo_guard.py   CLI exit codes (the ship.sh sensitive-data gate)
Every process gets its own temp state dir and NETMON_BACKUP_DIR, so live data and backups are never touched.
"""
import json
import os
import pty
import select
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _env  # noqa: E402
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness  # noqa: E402
import fixtures  # noqa: E402

PY = sys.executable
DAYS = ["2026-01-01T1200Z", "2026-01-02T1200Z", "2026-01-03T1200Z", "2026-01-04T1200Z", fixtures.SID]


class Sandbox:
    """A temp state dir + env for running netmon scripts as subprocesses."""

    def __init__(self, **extra):
        self.dir = tempfile.mkdtemp(prefix="netmon-pipe-", dir=_env.TMP)
        self.state = os.path.join(self.dir, "state")
        os.makedirs(self.state)
        self.env = harness.server_env(self.state, **extra)

    def run(self, args, timeout=120, input=None, cwd=None):
        return subprocess.run([PY] + args, env=self.env, capture_output=True, text=True, timeout=timeout, input=input,
                              cwd=cwd or _env.REPO)

    def py(self, code):
        pre = f"import sys; sys.path[:0] = [{_env.APP!r}, {_env.REPO!r}, {_env.TESTS!r}]\n"
        r = self.run(["-c", pre + code])
        if r.returncode:
            raise AssertionError(r.stderr[-3000:])
        return r.stdout


class AnalyzePipeline(unittest.TestCase):
    """analyze.py builds the baseline and then reports deviations."""

    @classmethod
    def setUpClass(cls):
        cls.sb = Sandbox()
        cls.sb.py(f"""
import fixtures, store
for s in {DAYS[:-1]!r}:
    fixtures.seed_snapshot(s, with_analysis=False)
r = fixtures.raw_snapshot(fixtures.SID)
d = r["devices"][fixtures.IPS["phone"]]
d.update(ext_out_bytes=900e6, total_sent=900e6, total_bytes=1e9)
store.jdump(r, "data/" + fixtures.SID + ".json")
""")
        cls.runs = [cls.sb.run(["analyze.py", f"data/{s}.json"]) for s in DAYS]
        cls.result = json.loads(cls.sb.py(f"import store, json; print(json.dumps(store.doc_get('data/{fixtures.SID}.analysis')))"))

    def test_every_run_succeeds(self):
        """analyze.py exits 0 for each of the five snapshots and reports writing an analysis.
        REQ: STO-01"""
        for s, r in zip(DAYS, self.runs):
            self.assertEqual(r.returncode, 0, r.stderr[-1500:])
            self.assertIn(f"data/{s}.analysis.json", r.stdout)

    def test_no_findings_while_seeding(self):
        """With fewer than MIN_DAYS (3) days of history, runs only seed the baseline and raise no deviation findings.
        REQ: ANA-01"""
        for r in self.runs[:3]:
            self.assertRegex(r.stdout, r"findings=0\b")

    def test_baseline_ready_after_history(self):
        """By day five the analysis records the baseline as ready with four days of history.
        REQ: STO-01"""
        self.assertTrue(self.result["baseline_ready"])
        self.assertEqual(self.result["baseline_days"], 4)

    def test_upload_spike_detected(self):
        """A device that suddenly uploads 900 MB gets a high 'upload-spike' finding keyed by its MAC.
        REQ: ANA-01, RISK-03"""
        f = [x for x in self.result["findings"] if x["kind"] == "upload-spike"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["severity"], "high")
        self.assertEqual(f[0]["device"], fixtures.mac(5))

    def test_steady_devices_not_flagged(self):
        """Devices whose traffic matches their baseline produce no findings.
        REQ: ANA-01"""
        flagged = {x["device"] for x in self.result["findings"]}
        self.assertEqual(flagged, {fixtures.mac(5)})

    def test_history_appended(self):
        """One history record per analysed snapshot is appended to the store.
        REQ: STO-01"""
        n = int(self.sb.py("import store; print(len(store.history_load()))"))
        self.assertEqual(n, len(DAYS))

    def test_backup_goes_to_sandbox(self):
        """The nightly store backup analyze.py takes lands in NETMON_BACKUP_DIR (never the live backup dir) and passes integrity.
        REQ: OPS-04"""
        bdir = self.sb.env["NETMON_BACKUP_DIR"]
        self.assertTrue(any(f.startswith("netmon-") for f in os.listdir(bdir)))
        self.assertIn("integrity: ok", self.runs[-1].stdout)

    def test_dashboard_serves_pipeline_output(self):
        """The dashboard started on the pipeline's store serves the analysis and its risk view.
        REQ: DASH-02, RISK-02"""
        env = {k: v for k, v in self.sb.env.items() if k in ("NETMON_DB",)}
        srv = harness.Server()
        srv.env.update(env, STATE_DIR=self.sb.state)
        srv.state = self.sb.state
        with srv:
            c = srv.login()
            snap = c.get("/api/snapshot?id=latest")[1]
            self.assertEqual(snap["id"], fixtures.SID)
            kinds = {f["kind"] for f in snap["analysis"]["findings"]}
            self.assertIn("upload-spike", kinds)
            self.assertEqual(c.get("/api/risk")[0], 200)


class ServerLifecycle(unittest.TestCase):
    """First start, upgrades and console recovery."""

    def test_first_start_seeds_admin_then_ignores_env(self):
        """The first start seeds an admin from DASH_USER/DASH_PASS; a restart with other values keeps the original account.
        REQ: AUTH-06, OPS-01"""
        srv = harness.Server()
        with srv:
            self.assertEqual(srv.login().get("/api/me")[1]["role"], "admin")
            self.assertIn("seeded users.json", srv.output())
        srv.env.update(DASH_USER="someone-else", DASH_PASS="another-password-1")
        with srv:
            self.assertEqual(srv.login().get("/api/me")[1]["user"], harness.ADMIN_USER)
            c = srv.client()
            self.assertEqual(c.post("/api/login", {"username": "someone-else", "password": "another-password-1"})[0], 401)

    def test_roleless_accounts_migrated_to_admin(self):
        """Accounts saved before roles existed become admins on the next start, and it is logged.
        REQ: AUTH-07"""
        srv = harness.Server()
        srv.run_py("""
import auth
auth.add("legacy-user", "legacy-password-1", "user")
u = auth.load(); u["legacy-user"].pop("role"); auth._save(u)
""")
        with srv:
            self.assertIn("existing accounts made admins: legacy-user", srv.output())
            self.assertEqual(srv.login("legacy-user", "legacy-password-1").get("/api/me")[1]["role"], "admin")

    def test_console_set_role(self):
        """server.py set-role changes a role from the console; the last admin cannot be demoted.
        REQ: OPS-01, AC-05"""
        sb = Sandbox()
        sb.py("import auth; auth.bootstrap('root-admin', 'root-admin-password'); auth.add('helper', 'helper-password-1', 'user')")
        r = sb.run([os.path.join(_env.APP, "server.py"), "set-role", "helper", "defender"], cwd=_env.APP)
        self.assertEqual((r.returncode, r.stdout.strip()), (0, "ok"), r.stderr)
        r = sb.run([os.path.join(_env.APP, "server.py"), "set-role", "root-admin", "user"], cwd=_env.APP)
        self.assertEqual(r.returncode, 1)
        roles = json.loads(sb.py("import auth, json; print(json.dumps({k: v['role'] for k, v in auth.load().items()}))"))
        self.assertEqual(roles, {"root-admin": "admin", "helper": "defender"})

    def test_console_add_user_prompts_for_password(self):
        """server.py add-user reads the password from the terminal (never argv) and creates a working account.
        REQ: OPS-01, AUTH-01"""
        sb = Sandbox()
        pid, fd = pty.fork()
        if pid == 0:
            os.chdir(_env.APP)
            os.execve(PY, [PY, os.path.join(_env.APP, "server.py"), "add-user", "console-admin"], sb.env)
        out, sent, end = b"", False, time.time() + 60
        while time.time() < end:
            r, _, _ = select.select([fd], [], [], 1)
            if r:
                try:
                    chunk = os.read(fd, 1024)
                except OSError:
                    break
                if not chunk:
                    break
                out += chunk
                if not sent and b"password" in out.lower():
                    os.write(fd, b"console-password-12\n")
                    sent = True
        _, status = os.waitpid(pid, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0, out[-500:])
        self.assertNotIn(b"console-password-12", out.split(b"\n", 1)[-1].replace(b"console-password-12\r\n", b""))
        ok = sb.py("import auth; c, e = auth.login('console-admin', 'console-password-12', '10.9.9.9'); print(bool(c), auth.role_of('console-admin'))")
        self.assertEqual(ok.split(), ["True", "admin"])

    def test_server_runs_with_llm_off(self):
        """With NETMON_LLM=off the server starts, says the reviewer is off, and makes no LLM calls.
        REQ: LLM-02"""
        with harness.Server() as srv:
            self.assertEqual(srv.login().get("/api/me")[0], 200)
            log = srv.output()
        self.assertIn("(off)", log)


class OperatorCli(unittest.TestCase):
    """Command-line tools an operator runs."""

    def test_store_check_and_stats(self):
        """store.py check reports ok and store.py stats lists the table row counts as JSON.
        REQ: OPS-04"""
        sb = Sandbox()
        sb.py("import fixtures; fixtures.seed_snapshot()")
        r = sb.run(["store.py", "check"])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("ok", r.stdout)
        r = sb.run(["store.py", "stats"])
        self.assertEqual(r.returncode, 0, r.stderr)
        body = r.stdout[r.stdout.index("{"):]
        stats = json.loads(body)
        self.assertGreaterEqual(stats.get("docs", 0), 2)

    def test_scheduler_status(self):
        """scheduler.py status prints the next run of the watcher, review, weekly and UniFi jobs without running them.
        REQ: OPS-03"""
        sb = Sandbox()
        r = sb.run(["scheduler.py", "status"], timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        for job in ("watch", "review", "weekly"):
            self.assertIn(job, r.stdout)

    def test_repo_guard_cli_blocks_forbidden_and_passes_clean(self):
        """repo_guard.py exits non-zero for a file that must never be committed and 0 for a clean file.
        REQ: SEC-04"""
        sb = Sandbox()
        d = tempfile.mkdtemp(dir=_env.TMP)
        clean = os.path.join(d, "clean.py")
        with open(clean, "w") as f:
            f.write("x = 1\n")
        mac_file = os.path.join(d, "leak.py")
        with open(mac_file, "w") as f:
            f.write("DEV = '" + fixtures.mac(7) + "'\n")
        self.assertEqual(sb.run(["repo_guard.py", clean]).returncode, 0)
        self.assertNotEqual(sb.run(["repo_guard.py", mac_file]).returncode, 0)
        self.assertNotEqual(sb.run(["repo_guard.py", "dashboard/state/netmon.db"]).returncode, 0)


if __name__ == "__main__":
    unittest.main()
