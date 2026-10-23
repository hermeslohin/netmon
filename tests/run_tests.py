#!/usr/bin/env python3
"""Run the netmon test suite and refresh the test docs.

Usage: python3 tests/run_tests.py [unit|e2e|all] [-v]     (default: all)

  - unit: fast, in-process, isolated temp DB (tests/_env.py)
  - e2e : starts the real dashboard over HTTPS + runs pipeline scripts as subprocesses, each in its own temp state;
          the deployed-container checks skip themselves when the container is not on this host
Writes tests/.last_results.json and regenerates docs/TEST_TRACEABILITY.md with pass/fail status.
Afterwards it verifies the run left the live state alone (tracked files outside tests/, live backups).
Exit code: 0 when every test passed (expected failures allowed).
"""
import glob
import json
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import _env  # noqa: E402,F401  isolate before anything imports netmon modules


def fingerprint():
    """Things a test must never change: tracked files outside tests/ and the live DB backups."""
    try:
        st = subprocess.run(["git", "status", "--porcelain", "--", ".", ":(exclude)tests"], cwd=REPO,
                            capture_output=True, text=True).stdout
        diff = subprocess.run(["git", "diff", "--", ".", ":(exclude)tests"], cwd=REPO, capture_output=True, text=True).stdout
    except OSError:
        st = diff = ""
    backups = {p: os.path.getmtime(p) for p in glob.glob(os.path.join(REPO, "baseline", "backup", "*"))}
    return st, hash(diff), backups


class Recorder(unittest.TextTestResult):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.status = {}

    def _set(self, test, s):
        self.status[test.id()] = s

    def addSuccess(self, t):
        super().addSuccess(t)
        self._set(t, "pass")

    def addFailure(self, t, e):
        super().addFailure(t, e)
        self._set(t, "FAIL")

    def addError(self, t, e):
        super().addError(t, e)
        self._set(t, "ERROR")

    def addSkip(self, t, r):
        super().addSkip(t, r)
        self._set(t, f"skipped ({r})")

    def addExpectedFailure(self, t, e):
        super().addExpectedFailure(t, e)
        self._set(t, "expected failure (known bug)")

    def addUnexpectedSuccess(self, t):
        super().addUnexpectedSuccess(t)
        self._set(t, "UNEXPECTED PASS (bug fixed? remove expectedFailure)")


def main():
    which = next((a for a in sys.argv[1:] if a in ("unit", "e2e", "all")), "all")
    verbosity = 2 if "-v" in sys.argv else 1
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for level in (("unit", "e2e") if which == "all" else (which,)):
        suite.addTests(loader.discover(os.path.join(HERE, level), pattern="test_*.py", top_level_dir=HERE))
    before = fingerprint()
    res = unittest.TextTestRunner(verbosity=verbosity, resultclass=Recorder).run(suite)
    after = fingerprint()
    out = os.path.join(HERE, ".last_results.json")
    prev = json.load(open(out)) if os.path.exists(out) and which != "all" else {}
    prev.update(res.status)
    with open(out, "w") as f:
        json.dump(prev, f, indent=1, sort_keys=True)
    subprocess.run([sys.executable, os.path.join(HERE, "gen_docs.py"), "--results", out], check=False)
    clean = before[:2] == after[:2] and all(after[2].get(p) == m for p, m in before[2].items())
    print("isolation check:", "OK - live files and backups untouched" if clean else "WARNING - files outside tests/ changed during the run")
    sys.exit(0 if res.wasSuccessful() and clean else 1)


if __name__ == "__main__":
    main()
