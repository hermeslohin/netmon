"""Settings coverage guard: every setting found in the code is in tests/settings_inventory.py and covered by a test."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E402

import ast  # noqa: E402
import re  # noqa: E402
import unittest  # noqa: E402

import gen_docs  # noqa: E402
import integrations  # noqa: E402
import settings_docs  # noqa: E402
import store  # noqa: E402
from requirements import REQUIREMENTS  # noqa: E402
from settings_inventory import ACTIONS, SETTINGS  # noqa: E402

REPO = _env.REPO if hasattr(_env, "REPO") else os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SERVER = os.path.join(REPO, "dashboard", "app", "server.py")
PREFIXES = ("/api/config/", "/api/llm/")
# modules whose set_* / put / save functions persist a setting
SETTER_MODULES = {"dashboard/app/corr_llm.py": "corr_llm", "dashboard/app/clef.py": "clef", "dashboard/app/autoclose.py": "autoclose",
                  "dashboard/app/notes_consolidate.py": "notes_consolidate", "integrations.py": "integrations",
                  "llm_providers.py": "llm_providers", "clef_server.py": "clef_server", "lookback.py": "lookback",
                  "review_cfg.py": "review_cfg", "research_cfg.py": "research_cfg"}
NOT_SETTERS = {"corr_llm.set_query_artifacts", "corr_llm.set_event_sources"}  # per-event data writers, not settings


def post_paths():
    """Settings POST paths handled by server.py do_POST (literal comparisons on u.path)."""
    src = open(SERVER).read()
    body = src[src.index("def do_POST"):]
    paths = set()
    for m in re.finditer(r'u\.path\s*(?:==\s*"([^"]+)"|in\s*\(([^)]*)\))', body):
        cands = [m.group(1)] if m.group(1) else re.findall(r'"([^"]+)"', m.group(2))
        paths.update(p for p in cands if p.startswith(PREFIXES))
    paths.add("/api/push/prefs")
    return paths


def setters():
    out = set()
    for rel, mod in SETTER_MODULES.items():
        tree = ast.parse(open(os.path.join(REPO, rel)).read())
        for fn in tree.body:
            if isinstance(fn, ast.FunctionDef) and (fn.name.startswith("set_") or fn.name in ("put", "save", "save_local")):
                out.add(f"{mod}.{fn.name}")
    return out - NOT_SETTERS


class SettingsInventoryTest(unittest.TestCase):
    """The settings inventory matches the code and every setting has tests."""

    def setUp(self):
        self.endpoints = {e for v in SETTINGS.values() for e in v[1]}
        self.setters = {s for v in SETTINGS.values() for s in v[2]}

    def test_every_settings_endpoint_listed(self):
        """Every settings POST endpoint in server.py is an inventory setting or a listed action.
        REQ: SET-90"""
        missing = sorted(p for p in post_paths() if p not in self.endpoints and p not in ACTIONS)
        self.assertEqual(missing, [], "add these endpoints to tests/settings_inventory.py")
        self.assertGreaterEqual(len(post_paths()), 20)

    def test_every_integrations_section_listed(self):
        """Every Integrations section shown on the Configuration page has its own inventory entry.
        REQ: SET-90"""
        secs = set(integrations.public())
        self.assertTrue({"elasticsearch", "unifi", "audit", "web", "opencti", "feeds"} <= secs)
        self.assertEqual(sorted(s for s in secs if "integrations." + s not in SETTINGS), [])
        for s in secs:
            self.assertIn(f"/api/config/integrations/{s}", SETTINGS["integrations." + s][1])

    def test_every_settings_document_listed(self):
        """Every Settings-page document (store.CFG_DOCS) and every documented settings section is inventoried.
        REQ: SET-90"""
        for d in store.CFG_DOCS:
            self.assertIn("cfg." + d, SETTINGS)
        self.assertEqual(sorted(d for d in settings_docs.DOCS if d not in store.CFG_DOCS), [])

    def test_every_setter_listed(self):
        """Every setter function that persists a setting is named by an inventory entry, and every named setter exists.
        REQ: SET-90"""
        found = setters()
        self.assertEqual(sorted(found - self.setters), [], "add these setters to tests/settings_inventory.py")
        self.assertEqual(sorted(self.setters - found), [], "inventory names setters that no longer exist")

    def test_every_setting_covered_by_tests(self):
        """Every inventoried setting names known requirements and each of them is verified by at least one test.
        REQ: SET-90"""
        tagged = {r for t in gen_docs.collect() for r in t["reqs"]}
        for sid, (_where, _eps, _set, reqs) in SETTINGS.items():
            with self.subTest(setting=sid):
                self.assertTrue(reqs, f"{sid} has no requirement")
                for r in reqs:
                    self.assertIn(r, REQUIREMENTS)
                    self.assertIn(r, tagged, f"{sid}: no test tagged {r}")


if __name__ == "__main__":
    unittest.main()
