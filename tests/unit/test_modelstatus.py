"""Unit tests for dashboard/app/modelstatus.py: AI pipeline monitoring > Models (each model role, its source, up/down)."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E402

import unittest  # noqa: E402
from unittest import mock  # noqa: E402

import clef  # noqa: E402
import corr_llm  # noqa: E402
import llm_providers  # noqa: E402
import modelstatus as MS  # noqa: E402

PROV = {"id": "abc", "name": "Cloud", "type": "openai", "base_url": "https://api.example.invalid/v1", "api_key": "sk-secret-123", "enabled": True, "models": ["m1"]}


def _get(pid):
    return dict(PROV) if pid == "api:abc" else None


class ModelStatus(unittest.TestCase):
    def setUp(self):
        MS._cache.update(at=0.0, v=None)

    def test_provider_up_warn_down_and_no_key_leak(self):
        """Listed model = up, missing model = warn, failing API = down; the endpoint is shown, the key never.
        REQ: COR-05
        """
        with mock.patch.object(llm_providers, "get", side_effect=_get), \
             mock.patch.object(llm_providers, "_http", return_value={"data": [{"id": "m1"}]}):
            up = MS._provider("chat", "Chat", "api:abc", "m1", "unset")
            warn = MS._provider("chat", "Chat", "api:abc", "m2", "unset")
        with mock.patch.object(llm_providers, "get", side_effect=_get), \
             mock.patch.object(llm_providers, "_http", side_effect=RuntimeError("Cloud: HTTP 401: bad key")):
            down = MS._provider("chat", "Chat", "api:abc", "m1", "unset")
        self.assertEqual((up["state"], warn["state"], down["state"]), ("up", "warn", "down"))
        self.assertEqual(up["source"], "Cloud")
        self.assertEqual(up["endpoint"], PROV["base_url"])
        for r in (up, warn, down):
            self.assertNotIn("sk-secret", repr(r))

    def test_unset_disabled_and_missing_provider(self):
        """No model chosen = off; a switched-off provider = off; a deleted provider = down.
        REQ: COR-05
        """
        self.assertEqual(MS._provider("chat", "Chat", "", "", "no model")["state"], "off")
        with mock.patch.object(llm_providers, "get", side_effect=lambda p: {**PROV, "enabled": False}):
            self.assertEqual(MS._provider("chat", "Chat", "api:abc", "m1", "x")["state"], "off")
        with mock.patch.object(llm_providers, "get", return_value=None):
            self.assertEqual(MS._provider("chat", "Chat", "api:gone", "m1", "x")["state"], "down")

    def test_decision_model_health_and_cache(self):
        """The decision model is up/down by its /health; status() returns all four roles and caches the result.
        REQ: COR-05
        """
        cfg = {"enabled": True, "url": "http://127.0.0.1:1", "model": "dm"}
        with mock.patch.object(clef, "config", return_value=cfg), mock.patch.object(clef, "healthy", return_value=False):
            self.assertEqual(MS._decision()["state"], "down")
        with mock.patch.object(clef, "config", return_value={**cfg, "enabled": False}):
            self.assertEqual(MS._decision()["state"], "off")
        with mock.patch.object(clef, "config", return_value=cfg), mock.patch.object(clef, "healthy", return_value=True), \
             mock.patch.object(corr_llm, "config", return_value={"correlation": {}, "chat": {}}), \
             mock.patch.object(MS, "_research", return_value=MS._row("research", "Event research")) as rs:
            a = MS.status()
            b = MS.status()
        self.assertEqual([r["role"] for r in a["roles"]], ["decision", "reviewer", "research", "chat"])
        self.assertEqual(a["roles"][0]["state"], "up")
        self.assertIs(a, b)
        self.assertEqual(rs.call_count, 1)


if __name__ == "__main__":
    unittest.main()
