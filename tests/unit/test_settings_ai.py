"""Unit tests for every AI-pipeline setting: corr_llm setters (notes, models, look-ups, review limits), the decision-model
settings (clef.py), AI providers (llm_providers.py) and the decision-model server settings (clef_server.py).
Each setting: its default, a valid value read back through the getter the pipeline uses, out-of-range values rejected,
updated_by stamped, and (where cheap) that the setting changes behaviour. No network, no model calls."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E402

import json  # noqa: E402
import unittest  # noqa: E402
from unittest import mock  # noqa: E402

import chat  # noqa: E402
import clef  # noqa: E402
import clef_server  # noqa: E402
import corr_llm  # noqa: E402
import llm_providers as LP  # noqa: E402

KEY = "x" * 16  # placeholder API key (never a real secret)
LOCAL_MODELS = [{"id": "local-a", "loaded": True}, {"id": "local-b", "loaded": False}]
T0 = 1_700_000_000


def _ev(t, label, sev="high", t0=T0):
    return {"type": t, "label": label, "sev": sev, "t0": t0, "ips": ["10.0.0.5"]}


def _raw():
    return corr_llm._raw_config()


class _Base(unittest.TestCase):
    """Common setup: empty isolated DB, no LM Studio (local_models stubbed)."""

    def setUp(self):
        _env.fresh_db()
        LP._cache["k"] = None
        for p in (mock.patch.object(LP, "local_models", return_value=list(LOCAL_MODELS)),
                  mock.patch("integrations.web", return_value={"provider": "duckduckgo"})):  # never read the host's integration secrets
            p.start()
            self.addCleanup(p.stop)


# ---------------------------------------------------------------- corr_llm: notes
class NotesLimit(_Base):
    """Event reviewer context notes: notes per event, note characters, notes per host / user."""

    def test_defaults(self):
        """With nothing saved the reviewer gets 7 notes per event, 6000 note characters and 40 notes per subject.
        REQ: SET-20"""
        self.assertEqual(corr_llm.notes_limit(), 7)
        self.assertEqual(corr_llm.notes_chars(), 6000)
        self.assertEqual(corr_llm.kb_per_subject(), 40)
        cn = corr_llm.config()["context_notes"]
        self.assertEqual((cn["limit"], cn["chars_min"], cn["chars_limit"], cn["per_subject_limit"]), (100, 1000, 100000, 500))
        self.assertIsNone(cn["by"])

    def test_valid_values_persist_each_field_separately(self):
        """Each field saved on its own keeps the others, is read back by the pipeline getters and stamps the user.
        REQ: SET-20"""
        corr_llm.set_notes_limit(12, "admin1")
        corr_llm.set_notes_limit(None, "admin2", chars=2500)
        res = corr_llm.set_notes_limit(None, "admin3", per_subject=99)
        self.assertEqual((corr_llm.notes_limit(), corr_llm.notes_chars(), corr_llm.kb_per_subject()), (12, 2500, 99))
        self.assertEqual((res["max"], res["chars"], res["per_subject"]), (12, 2500, 99))
        self.assertEqual(res["by"], "admin3")
        self.assertIsInstance(res["at"], float)
        corr_llm.set_notes_limit("100", "u", chars="100000", per_subject="500")  # the documented upper bounds, as strings
        self.assertEqual((corr_llm.notes_limit(), corr_llm.notes_chars(), corr_llm.kb_per_subject()), (100, 100000, 500))
        corr_llm.set_notes_limit(1, "u", chars=1000, per_subject=1)  # lower bounds
        self.assertEqual((corr_llm.notes_limit(), corr_llm.notes_chars(), corr_llm.kb_per_subject()), (1, 1000, 1))

    def test_out_of_range_rejected_and_nothing_saved(self):
        """Values outside 1-100 notes, 1000-100000 characters or 1-500 per subject are refused, and a refused call saves nothing.
        REQ: SET-20"""
        corr_llm.set_notes_limit(5, "u", chars=3000, per_subject=10)
        for kw in ({"mx": 0}, {"mx": 101}, {"mx": None, "chars": 999}, {"mx": None, "chars": 100001},
                   {"mx": None, "per_subject": 0}, {"mx": None, "per_subject": 501}, {"mx": "lots"}, {"mx": 9, "chars": 10}):
            with self.assertRaises(ValueError, msg=kw):
                corr_llm.set_notes_limit(user="evil", **kw)
        with self.assertRaises(ValueError):
            corr_llm.set_notes_limit(None, "u")  # nothing to set
        self.assertEqual((corr_llm.notes_limit(), corr_llm.notes_chars(), corr_llm.kb_per_subject()), (5, 3000, 10))
        self.assertEqual(corr_llm.config()["context_notes"]["by"], "u")

    def test_hand_edited_out_of_range_values_are_clamped(self):
        """Stored values outside the ranges (e.g. a hand-edited config) are clamped by the getters, garbage gives the default.
        REQ: SET-20"""
        corr_llm._save_config({"context_notes": {"max": 5000, "chars": 5, "per_subject": 9999}})
        self.assertEqual((corr_llm.notes_limit(), corr_llm.notes_chars(), corr_llm.kb_per_subject()), (100, 1000, 500))
        corr_llm._save_config({"context_notes": {"max": "x", "chars": "y", "per_subject": "z"}})
        self.assertEqual((corr_llm.notes_limit(), corr_llm.notes_chars(), corr_llm.kb_per_subject()), (7, 6000, 40))

    def _prompt_notes(self, n_notes=10):
        users = []

        def fake(target, system, user, max_tokens, purpose="", actor="", queries=False, schemas=None, fmts=None):
            users.append(user)
            return json.dumps({"decisions": []}), {}, 0
        notes = {"anchor": [f"note {i:02d} " + "y" * 280 for i in range(n_notes)]}  # ~288 characters each, distinct heads
        with mock.patch.object(corr_llm, "_complete", fake):
            corr_llm._ask_full({"provider": "lmstudio", "model": "m"}, {"type": "ids", "label": "x", "t0": None}, [], notes=notes)
        return users[0].count("<owner_note>")

    def test_notes_settings_cap_the_review_prompt(self):
        """Notes per event caps how many notes reach the prompt, and the character budget caps their total length.
        REQ: SET-21"""
        corr_llm.set_notes_limit(2, "u", chars=100000)
        self.assertEqual(self._prompt_notes(), 2)
        corr_llm.set_notes_limit(7, "u", chars=1000)  # 1000 characters hold 3 notes of ~288
        self.assertEqual(self._prompt_notes(), 3)
        corr_llm.set_notes_limit(100, "u", chars=100000)
        self.assertEqual(self._prompt_notes(), 10)


# ---------------------------------------------------------------- corr_llm: models and look-up switches
class Models(_Base):
    """Event reviewer and chat model choices, and the chat's Elasticsearch switch."""

    def _provider(self, models=("gpt-x",)):
        return LP.save({"type": "openai", "name": "Cloud one", "api_key": KEY, "models": "\n".join(models)}, "admin")

    def test_correlation_default_is_local_server(self):
        """With no choice saved the event reviewer uses the local server.
        REQ: SET-22"""
        self.assertEqual(corr_llm.config()["correlation"]["provider"], "lmstudio")
        with mock.patch.object(corr_llm, "_model", return_value="loaded-model"):
            self.assertEqual(corr_llm._target(), {"provider": "lmstudio", "model": corr_llm.MODEL or "loaded-model"})

    def test_correlation_choice_persists_and_is_used(self):
        """A chosen API-provider model is stored with the user, shown in STATUS and used by the event reviewer.
        REQ: SET-22"""
        p = self._provider()
        old = dict(corr_llm.STATUS)
        self.addCleanup(lambda: (corr_llm.STATUS.clear(), corr_llm.STATUS.update(old)))
        corr_llm.set_correlation(p["provider"], "gpt-x", "admin7")
        self.assertEqual(corr_llm.config()["correlation"], {"provider": p["provider"], "model": "gpt-x"})
        self.assertEqual(_raw()["correlation"]["by"], "admin7")
        self.assertEqual(corr_llm.STATUS["model"], "gpt-x")
        self.assertEqual(corr_llm._target(), {"provider": p["provider"], "model": "gpt-x"})

    def test_correlation_on_removed_provider_or_model_fails_loudly(self):
        """A reviewer model whose provider was deleted, whose model was dropped, or an unknown provider stops the review with an error.
        REQ: SET-22"""
        p = self._provider(("gpt-x", "gpt-y"))
        corr_llm.set_correlation(p["provider"], "gpt-y", "u")
        LP.save({"id": p["id"], "type": "openai", "name": "Cloud one", "models": "gpt-x"}, "u")  # gpt-y dropped
        with self.assertRaisesRegex(RuntimeError, "no longer available"):
            corr_llm._target()
        LP.delete(p["id"])
        with self.assertRaisesRegex(RuntimeError, "no longer available"):
            corr_llm._target()
        corr_llm.set_correlation("someother", "m", "u")
        with self.assertRaisesRegex(RuntimeError, "no longer available"):
            corr_llm._target()

    def test_server_only_allows_configured_models(self):
        """The model choice the UI posts is accepted only for an enabled provider with a key and that model (llm_allowed).
        REQ: SET-22"""
        p = self._provider()
        self.assertTrue(LP.allowed(p["provider"], "gpt-x"))
        self.assertFalse(LP.allowed(p["provider"], "not-listed"))
        self.assertFalse(LP.allowed("api:nope", "gpt-x"))
        self.assertTrue(LP.allowed("lmstudio", "local-a"))
        LP.save({"id": p["id"], "type": "openai", "name": "Cloud one", "models": "gpt-x", "enabled": False}, "u")
        self.assertFalse(LP.allowed(p["provider"], "gpt-x"))

    def test_chat_model_default_off_then_persists(self):
        """The chat is off until a model is chosen; the choice is stored with the user and used by the chat.
        REQ: SET-23"""
        self.assertFalse(chat.enabled())
        self.assertEqual(corr_llm.config()["chat"]["provider"], "")
        corr_llm.set_chat("lmstudio", "local-a", "admin2")
        c = corr_llm.config()["chat"]
        self.assertEqual((c["provider"], c["model"], c["by"]), ("lmstudio", "local-a", "admin2"))
        self.assertEqual(chat.default_model(), {"provider": "lmstudio", "model": "local-a"})

    def test_chat_es_switch(self):
        """Ask AI may search Elasticsearch by default; switching it off removes the search tool from the chat.
        REQ: SET-23"""
        self.assertTrue(corr_llm.config()["chat_es"]["enabled"])
        self.assertIn("elasticsearch_search", chat._tools(es=True))
        res = corr_llm.set_chat_es(False, "admin3")
        self.assertEqual((res["enabled"], res["by"]), (False, "admin3"))
        self.assertNotIn("elasticsearch_search", chat._tools(es=True))
        self.assertTrue(corr_llm.set_chat_es(True, "admin3")["enabled"])
        self.assertIn("elasticsearch_search", chat._tools(es=True))


class Lookups(_Base):
    """Look-ups first, web search and Elasticsearch look-up switches of the event reviewer."""

    def _users(self, es_max=1):
        users = []

        def fake(target, system, user, max_tokens, purpose="", actor="", queries=False, schemas=None, fmts=None):
            users.append(user)
            return json.dumps({"queries": [], "web": [], "decisions": []}), {}, 0
        with mock.patch.object(corr_llm, "_complete", fake), mock.patch.object(corr_llm, "broker") as b:
            corr_llm._ask_full({"provider": "lmstudio", "model": "m"}, {"type": "ids", "label": "x", "t0": None}, [], es_max=es_max)
        b.assert_not_called()
        return users

    def test_lookup_plan_default_on_and_switch(self):
        """Look-ups first is on by default (a planning call precedes the decision); switched off there is no planning call.
        REQ: SET-24"""
        self.assertTrue(corr_llm.lookup_plan())
        self.assertTrue(corr_llm.config()["lookup_plan"]["enabled"])
        self.assertIn("STEP 1 of 2", self._users()[0])
        res = corr_llm.set_lookup_plan(False, "admin4")
        self.assertEqual((res["enabled"], res["by"]), (False, "admin4"))
        self.assertFalse(corr_llm.lookup_plan())
        self.assertFalse(any("STEP 1 of 2" in u for u in self._users()))

    def test_web_search_default_valid_and_range(self):
        """Web look-ups are off by default with 2 per event; 1-10 are accepted and stored with the user, other values refused.
        REQ: SET-25"""
        w = corr_llm.config()["web_search"]
        self.assertEqual((w["enabled"], w["max"], w["limit"]), (False, 2, 10))
        for mx in (1, 10, "4"):
            res = corr_llm.set_web_search(True, mx, "admin5")
            self.assertEqual((res["enabled"], res["max"], res["by"]), (True, int(mx), "admin5"))
        for bad in (0, 11, -1, "many"):
            with self.assertRaises(ValueError):
                corr_llm.set_web_search(False, bad, "evil")
        with self.assertRaises(TypeError):  # the server turns this into a 400 as well
            corr_llm.set_web_search(False, None, "evil")
        self.assertEqual((corr_llm.config()["web_search"]["max"], corr_llm.config()["web_search"]["by"]), (4, "admin5"))
        self.assertTrue(corr_llm.config()["web_search"]["enabled"])

    def test_es_queries_default_valid_and_range(self):
        """Elasticsearch look-ups are off by default with 3 per event; 1-20 are accepted and stored with the user, other values refused.
        REQ: SET-25"""
        e = corr_llm.config()["es_queries"]
        self.assertEqual((e["enabled"], e["max"], e["limit"]), (False, 3, 20))
        res = corr_llm.set_es_queries(True, 20, "admin6")
        self.assertEqual((res["enabled"], res["max"], res["by"]), (True, 20, "admin6"))
        for bad in (0, 21, "x"):
            with self.assertRaises(ValueError):
                corr_llm.set_es_queries(False, bad, "evil")
        self.assertEqual(corr_llm.config()["es_queries"]["max"], 20)
        corr_llm._save_config({**_raw(), "es_queries": {"enabled": True, "max": 999}})  # hand-edited: clamped
        self.assertEqual(corr_llm.config()["es_queries"]["max"], 20)

    def test_es_max_is_the_lookup_budget_given_to_the_reviewer(self):
        """The event reviewer runs at most the set number of Elasticsearch look-ups per review.
        REQ: SET-25"""
        corr_llm.set_es_queries(True, 2, "u")
        corr_llm.set_lookup_plan(True, "u")
        qs = [{"source": "zeek", "match": {"source.ip": f"10.0.0.{i}"}} for i in range(5)]
        calls = []

        def fake(target, system, user, max_tokens, purpose="", actor="", queries=False, schemas=None, fmts=None):
            calls.append(user)
            return json.dumps({"queries": qs, "web": [], "decisions": []}), {}, 0
        es = corr_llm.config()["es_queries"]
        with mock.patch.object(corr_llm, "_complete", fake), mock.patch.object(corr_llm, "broker", return_value={"total": 0}) as b:
            corr_llm._ask_full({"provider": "lmstudio", "model": "m"}, {"type": "ids", "label": "x", "t0": None}, [],
                               es_max=es["max"] if es["enabled"] else 0)
        self.assertEqual(b.call_count, 2)


# ---------------------------------------------------------------- corr_llm: review limits
BASE = {"events": {"ids|a": _ev("ids", "sig a"), "vuln|b": _ev("vuln", "cve b", "low"), "vuln|c": _ev("vuln", "cve c", "low"),
                   "vuln|d": _ev("vuln", "cve d", "low"), "alarm|far": _ev("alarm", "far away", "medium", T0 + 7200)},
        "related": {"ids|a": [{"id": "vuln|b", "score": 5, "why": ["same host"]}, {"id": "vuln|c", "score": 4, "why": ["same host"]},
                              {"id": "vuln|d", "score": 3, "why": ["same host"]}, {"id": "alarm|far", "score": 2, "why": ["same host"]}]}}


def _event_window(m):
    """Set (or with None remove) the event window in the cfg table (lookback.py)."""
    import store
    d = store.cfg_load("site")
    if m is None:
        d.pop("event_window_minutes", None)
    else:
        d["event_window_minutes"] = m
    store.cfg_save("site", d)


def _pending(base=BASE):
    return {(x["a"], x["b"]) if x["a"] < x["b"] else (x["b"], x["a"]) for x in corr_llm.pending_list(base)["items"] if not x["testing"]}


class ReviewLimits(_Base):
    """Review limits: pair modes, max links, time window, retention, classify, view."""

    def setUp(self):
        super().setUp()
        corr_llm._save_config({"review_limits": {"pair_default": "review"}})
        _event_window(120)  # wide enough that alarm|far (2 h away) is a candidate, unless a test narrows it

    def tearDown(self):
        _event_window(None)
        super().tearDown()

    def test_pair_default_new_vs_existing_deployment(self):
        """A brand-new deployment skips every pair by default, an existing one (with verdicts) keeps reviewing everything.
        REQ: SET-26"""
        _env.fresh_db()
        with mock.patch.object(corr_llm, "_is_new_deployment", return_value=True):
            self.assertEqual(corr_llm.limits()["pair_default"], "skip")
        _env.fresh_db()
        with mock.patch.object(corr_llm, "_is_new_deployment", return_value=False):
            self.assertEqual(corr_llm.limits()["pair_default"], "review")
        with mock.patch.object(corr_llm, "_is_new_deployment", return_value=True):  # decided once, then kept
            self.assertEqual(corr_llm.limits()["pair_default"], "review")

    def test_defaults(self):
        """Without settings nothing is capped, the window is the default event window (10 min), verdicts kept forever and classification off.
        REQ: SET-26, EVW-01"""
        _event_window(None)
        L = corr_llm.limits()
        self.assertEqual((L["max_links"], L["window_minutes"], L["discard_days"], L["classify"], L["pair_modes"]), (0, 10, 0, False, {}))

    def test_pair_mode_skip_holds_links_back(self):
        """A pair type switched to skip is never sent to the event reviewer; switched back to review it is pending again.
        REQ: SET-26"""
        self.assertIn(("ids|a", "vuln|b"), _pending())
        L = corr_llm.set_limits("admin", pair_modes={"ids_high-vuln_low": "skip"})
        self.assertEqual(L["pair_modes"], {"ids_high-vuln_low": "skip"})
        self.assertEqual(L["skip_pairs"], ["ids_high-vuln_low"])
        self.assertEqual(_pending(), {("alarm|far", "ids|a")})
        corr_llm.set_limits("admin", pair_modes={"ids_high-vuln_low": "review"})
        self.assertIn(("ids|a", "vuln|b"), _pending())

    def test_pair_mode_validation(self):
        """Pair modes must map 'typeA-typeB' to review or skip, skip_pairs must be a list; bad input is refused and not saved.
        REQ: SET-26"""
        for kw in ({"pair_modes": {"ids-vuln": "maybe"}}, {"pair_modes": {"IDS-vuln": "skip"}}, {"pair_modes": ["ids-vuln"]},
                   {"skip_pairs": "ids-vuln"}, {"skip_pairs": ["ids vuln"]}):
            with self.assertRaises(ValueError, msg=kw):
                corr_llm.set_limits("evil", **kw)
        self.assertEqual(corr_llm.limits()["pair_modes"], {})

    def test_legacy_skip_pairs_and_test_mode(self):
        """Old-style skip_pairs lists and the retired 'test' mode still load as skip.
        REQ: SET-26"""
        corr_llm._save_config({"review_limits": {"pair_default": "test", "skip_pairs": ["alert-vuln"], "pair_modes": {"ids-host": "test", "a-b": "odd"}}})
        L = corr_llm.limits()
        self.assertEqual(L["pair_default"], "skip")
        self.assertEqual(L["pair_modes"], {"ids-host": "skip", "alert-vuln": "skip"})
        L = corr_llm.set_limits("u", skip_pairs=["ids-vuln"])  # skip_pairs replaces the skipped set
        self.assertEqual(L["skip_pairs"], ["ids-vuln"])
        self.assertEqual(L["pair_modes"]["alert-vuln"], "review")

    def test_max_links_range(self):
        """Max links per event accepts 0-200 (0 = no cap); other values are refused and nothing is saved.
        REQ: SET-27"""
        self.assertEqual(corr_llm.set_limits("u", max_links="200")["max_links"], 200)
        self.assertEqual(corr_llm.set_limits("u", max_links=0)["max_links"], 0)
        for bad in (-1, 201, "ten", 1.5e9):
            with self.assertRaises(ValueError, msg=bad):
                corr_llm.set_limits("evil", pair_modes={"ids-vuln": "skip"}, max_links=bad)
        L = corr_llm.limits()
        self.assertEqual((L["max_links"], L["pair_modes"]), (0, {}))  # the valid pair mode of a refused call is not saved either
        corr_llm._save_config({"review_limits": {"pair_default": "review", "max_links": 999}})
        self.assertEqual(corr_llm.limits()["max_links"], 200)  # hand-edited: clamped

    def test_max_links_caps_pending_links_best_score_first(self):
        """With a cap of 2 an event keeps only its two best-scoring undecided links; 0 removes the cap.
        REQ: SET-27"""
        self.assertEqual(len(_pending()), 4)
        corr_llm.set_limits("u", max_links=2)
        self.assertEqual(_pending(), {("ids|a", "vuln|b"), ("ids|a", "vuln|c")})
        corr_llm.set_limits("u", max_links=0)
        self.assertEqual(len(_pending()), 4)

    def test_window_range_and_effect(self):
        """The time window is the event window (Settings > Site, read live): links whose events are further apart are skipped;
        the review limits no longer set their own window.
        REQ: SET-28, EVW-02"""
        self.assertIn(("alarm|far", "ids|a"), _pending())
        _event_window(60)
        self.assertEqual(corr_llm.limits()["window_minutes"], 60)
        self.assertNotIn(("alarm|far", "ids|a"), _pending())
        self.assertIn(("ids|a", "vuln|b"), _pending())
        self.assertEqual(corr_llm.limits_view(BASE)["window_out"], {"links": 1})
        for v in (180, {"minutes": 5}):
            with self.assertRaises(ValueError):
                corr_llm.set_limits("u", window=v)
        self.assertEqual(corr_llm.limits()["window_minutes"], 60)

    def test_discard_days_and_classify(self):
        """Verdict retention accepts 0-3650 days, classification is an on/off switch; both persist.
        REQ: SET-28"""
        L = corr_llm.set_limits("u", discard_days={"days": 30}, classify=True)
        self.assertEqual((L["discard_days"], L["classify"]), (30, True))
        self.assertEqual(corr_llm.set_limits("u", discard_days=3650)["discard_days"], 3650)
        for bad in (-1, 3651, "week"):
            with self.assertRaises(ValueError):
                corr_llm.set_limits("evil", discard_days=bad)
        self.assertEqual(corr_llm.limits()["discard_days"], 3650)
        self.assertFalse(corr_llm.set_limits("u", classify=False)["classify"])
        self.assertEqual(corr_llm.limits()["discard_days"], 3650)  # other fields kept

    def test_exclusions_and_rules_are_ignored(self):
        """Exclusions and never-send rules were removed from the code: the arguments are accepted, nothing is stored or skipped.
        REQ: SET-29"""
        L = corr_llm.set_limits("u", exclude={"id": "vuln|b", "mode": "event"}, rule={"name": "cve", "scope": "both"}, unrule="rule|x", unexclude="event|x")
        self.assertEqual((L["excluded"], L["rules"]), ([], []))
        stored = _raw()["review_limits"]
        self.assertEqual((stored.get("excluded"), stored.get("rules")), ([], []))
        self.assertIn(("ids|a", "vuln|b"), _pending())

    def test_limits_view_counts_pairs(self):
        """The review-limits view lists every type pair with its candidate link count and mode, and the configured ranges.
        REQ: SET-29"""
        corr_llm.set_limits("u", pair_modes={"ids_high-vuln_low": "skip"})
        v = corr_llm.limits_view(BASE)
        P = {p["pair"]: p for p in v["pairs"]}
        self.assertEqual(v["total"], 4)
        self.assertEqual((P["ids_high-vuln_low"]["links"], P["ids_high-vuln_low"]["mode"]), (3, "skip"))
        self.assertEqual((P["alarm_medium-ids_high"]["links"], P["alarm_medium-ids_high"]["mode"]), (1, "review"))
        self.assertEqual(P["seg_low-vuln_high"]["links"], 0)  # every pair is listed, linked or not
        self.assertEqual((v["limit_range"], v["window_range"], v["discard_range"]), (200, 525600, 3650))


# ---------------------------------------------------------------- clef.py: decision model settings
class ClefSettings(_Base):
    """Decision-model stage settings: on/off and the related threshold (it decides links only)."""

    def test_defaults(self):
        """The decision model is on by default with the related threshold at 0.5; there is no event (suspicious) threshold.
        REQ: SET-30"""
        c = clef.config()
        self.assertEqual((c["enabled"], c["related_min"], c["by"]), (True, 0.5, None))
        self.assertNotIn("suspicious_min", c)

    def test_valid_values_persist_and_stamp(self):
        """On/off and thresholds are stored (rounded to 2 decimals) with the user; a partial save keeps the other fields.
        REQ: SET-30"""
        c = clef.set_config("admin8", enabled=False, related_min=0.333)
        self.assertEqual((c["enabled"], c["related_min"], c["by"]), (False, 0.33, "admin8"))
        c = clef.set_config("admin9", related_min="0.95")
        self.assertEqual((c["enabled"], c["related_min"], c["by"]), (False, 0.95, "admin9"))
        self.assertTrue(clef.set_config("admin9", enabled=True)["enabled"])

    def test_out_of_range_rejected(self):
        """Thresholds outside 0.05-0.95 or not numbers are refused and nothing changes.
        REQ: SET-30"""
        clef.set_config("u", related_min=0.6)
        for kw in ({"related_min": 0.04}, {"related_min": 0.96}, {"related_min": 0}, {"related_min": 1},
                   {"related_min": "half"}, {"related_min": float("nan")}, {"enabled": False, "related_min": 2}):
            with self.assertRaises((ValueError, TypeError), msg=kw):
                clef.set_config("evil", **kw)
        c = clef.config()
        self.assertEqual((c["enabled"], c["related_min"], c["by"]), (True, 0.6, "u"))

    def test_hand_edited_thresholds_clamped(self):
        """Stored thresholds outside the range are clamped to 0.05-0.95 by the config the pipeline reads; garbage gives 0.5.
        REQ: SET-30"""
        corr_llm._save_config({"clef": {"related_min": 3}})
        self.assertEqual(clef.config()["related_min"], 0.95)
        corr_llm._save_config({"clef": {"related_min": -1}})
        self.assertEqual(clef.config()["related_min"], 0.05)
        corr_llm._save_config({"clef": {"related_min": "x"}})
        self.assertEqual(clef.config()["related_min"], 0.5)

    def test_related_min_decides_links(self):
        """The related threshold is what turns the decision model's probability into a related / not related verdict.
        REQ: SET-31"""
        base = {"events": {"ids|ra": _ev("ids", "sig ra"), "vuln|rb": _ev("vuln", "cve rb"), "vuln|rc": _ev("vuln", "cve rc")}}
        with mock.patch.object(clef, "ask", return_value=({"related": 0.6}, 5)):
            clef.set_config("u", related_min=0.5)
            corr_llm.clef_pass(base, [("ids|ra", {"id": "vuln|rb", "score": 3, "why": []})])
            clef.set_config("u", related_min=0.7)
            corr_llm.clef_pass(base, [("ids|ra", {"id": "vuln|rc", "score": 3, "why": []})])
        V = corr_llm.verdicts([corr_llm.pair("ids|ra", "vuln|rb"), corr_llm.pair("ids|ra", "vuln|rc")])
        self.assertTrue(V[corr_llm.pair("ids|ra", "vuln|rb")]["related"])
        self.assertFalse(V[corr_llm.pair("ids|ra", "vuln|rc")]["related"])

    def test_enabled_switch_is_read_by_the_pipeline(self):
        """The on/off switch is what the review pass reads before using the decision model.
        REQ: SET-30"""
        clef.set_config("u", enabled=False)
        self.assertFalse(clef.config()["enabled"])
        with open(corr_llm.__file__, encoding="utf-8") as f:
            self.assertIn('use_clef = clef.config()["enabled"]', f.read())


# ---------------------------------------------------------------- llm_providers.py
class Providers(_Base):
    """Admin-added AI providers: validation, write-only keys, masking and removal."""

    def _body(self, **kw):
        b = {"type": "openai", "name": "Cloud one", "api_key": KEY, "models": "gpt-x 1.25 10 0.125\ngpt-y"}
        b.update(kw)
        return b

    def test_add_valid_provider_defaults(self):
        """A new provider gets an id, the official base URL, the parsed models and prices, 120 calls per hour and the user stamp.
        REQ: SET-32"""
        p = LP.save(self._body(), "admin1")
        self.assertEqual(p["provider"], "api:" + p["id"])
        self.assertEqual(p["base_url"], "https://api.openai.com/v1")
        self.assertEqual(p["models"], ["gpt-x", "gpt-y"])
        self.assertEqual(p["prices"], {"gpt-x": [1.25, 10.0, 0.125]})
        self.assertEqual((p["rate_per_hour"], p["reasoning_tokens"], p["enabled"], p["by"]), (120, 3000, True, "admin1"))
        self.assertEqual(LP.price(p["provider"], "gpt-x"), {"in": 1.25, "out": 10.0, "cache_read": 0.125})
        a = LP.save(self._body(type="anthropic", name="Other", models=["claude-x"]), "admin1")
        self.assertEqual((a["base_url"], a["reasoning_tokens"]), ("https://api.anthropic.com", 0))
        self.assertEqual([g["provider"] for g in LP.model_groups()], [p["provider"], a["provider"]])

    def test_validation_rejects_bad_input(self):
        """Wrong type, empty name, missing or malformed key, unsafe base URLs, bad model ids or prices and out-of-range numbers are refused.
        REQ: SET-32"""
        bad = [dict(type="google"), dict(name="  "), dict(name="<>"), dict(api_key=""), dict(api_key="has space"), dict(api_key="k" * 401),
               dict(base_url="http://api.example.com/v1"), dict(base_url="ftp://192.0.2.1/"), dict(base_url="https://u:p@api.example.com"),
               dict(base_url="https://api.example.com/v1?x=1"), dict(models="bad model!"), dict(models="m 1"), dict(models="m a b"),
               dict(models="m 1 1001"), dict(models="\n".join(f"m{i}" for i in range(61))), dict(rate_per_hour=0), dict(rate_per_hour=3001),
               dict(rate_per_hour="lots"), dict(reasoning_tokens=32001), dict(id="lmstudio"), dict(id="nosuch")]
        for kw in bad:
            with self.assertRaises(ValueError, msg=kw):
                LP.save(self._body(**kw), "evil")
        self.assertEqual(LP.public()[1:], [])

    def test_lan_http_allowed_and_names_unique(self):
        """Plain http is accepted for LAN / loopback base URLs; a second provider with the same name (any case) is refused.
        REQ: SET-32"""
        p = LP.save(self._body(base_url="http://10.0.0.20:8000/v1/"), "u")
        self.assertEqual(p["base_url"], "http://10.0.0.20:8000/v1")
        self.assertEqual(LP.save(self._body(name="Loop", base_url="http://127.0.0.1:9/v1"), "u")["base_url"], "http://127.0.0.1:9/v1")
        with self.assertRaisesRegex(ValueError, "already has that name"):
            LP.save(self._body(name="CLOUD ONE"), "u")
        self.assertEqual(len(LP.public()), 3)

    def test_key_is_masked_everywhere_the_browser_sees(self):
        """The API key never appears in what the admin page gets: only the last 4 characters, or 'set' for short keys.
        REQ: SET-33"""
        key = "k" * 12 + "WXYZ"
        p = LP.save(self._body(api_key=key), "u")
        self.assertEqual((p["key_set"], p["key_hint"]), (True, "…WXYZ"))
        self.assertNotIn(key, json.dumps(LP.public()))
        self.assertNotIn("api_key", p)
        s = LP.save(self._body(name="Short", api_key="shortkey"), "u")
        self.assertEqual(s["key_hint"], "set")
        self.assertEqual(LP.get(p["provider"])["api_key"], key)  # stored server-side

    def test_key_is_write_only_on_update(self):
        """An update without a key keeps the stored key, a new key replaces it, and a new type or base URL needs the key again.
        REQ: SET-33"""
        p = LP.save(self._body(), "u")
        LP.save({"id": p["id"], "type": "openai", "name": "Renamed", "models": "gpt-z", "rate_per_hour": 10}, "u2")
        g = LP.get(p["provider"])
        self.assertEqual((g["api_key"], g["name"], g["models"], g["rate_per_hour"], g["by"]), (KEY, "Renamed", ["gpt-z"], 10, "u2"))
        with self.assertRaisesRegex(ValueError, "API key again"):
            LP.save({"id": p["id"], "type": "openai", "name": "Renamed", "base_url": "https://other.example.com/v1"}, "u")
        with self.assertRaisesRegex(ValueError, "API key again"):
            LP.save({"id": p["id"], "type": "anthropic", "name": "Renamed"}, "u")
        self.assertEqual(LP.get(p["provider"])["base_url"], "https://api.openai.com/v1")
        LP.save({"id": p["id"], "type": "openai", "name": "Renamed", "base_url": "https://other.example.com/v1", "api_key": "y" * 16}, "u")
        g = LP.get(p["provider"])
        self.assertEqual((g["api_key"], g["base_url"]), ("y" * 16, "https://other.example.com/v1"))

    def test_delete_removes_provider_and_key(self):
        """Deleting a provider removes it and its key from storage; unknown ids and the local server can't be deleted.
        REQ: SET-33"""
        p = LP.save(self._body(), "u")
        LP.delete(p["id"])
        self.assertIsNone(LP.get(p["provider"]))
        self.assertNotIn(KEY, json.dumps(LP._load()))
        self.assertFalse(LP.allowed(p["provider"], "gpt-x"))
        with self.assertRaises(ValueError):
            LP.delete(p["id"])
        with self.assertRaises(ValueError):
            LP.delete("lmstudio")

    def test_local_server_defaults_and_save(self):
        """The local server row starts enabled with every model offered; save_local stores enabled, rate, picked models and prices with the user.
        REQ: SET-34"""
        loc = LP.public()[0]
        self.assertEqual((loc["id"], loc["enabled"], loc["rate_per_hour"], loc["models"]), ("lmstudio", True, LP.RATE_MAX, ["local-a", "local-b"]))
        res = LP.save_local({"id": "lmstudio", "enabled": True, "rate_per_hour": 50, "models": "local-b 0.1 0.2"}, "admin3")
        self.assertEqual((res["enabled"], res["rate_per_hour"], res["models"], res["by"]), (True, 50, ["local-b"], "admin3"))
        self.assertEqual(LP.price("lmstudio", "local-b"), {"in": 0.1, "out": 0.2, "cache_read": 0.1})
        self.assertFalse(LP.allowed("lmstudio", "local-a"))  # not picked any more
        self.assertEqual(LP.save_local({"enabled": True}, "u")["rate_per_hour"], LP.RATE_DEFAULT)  # an empty field saves the default 120

    def test_local_server_validation_and_disable(self):
        """Out-of-range rates are refused; switching the local server off stops the event reviewer from using it.
        REQ: SET-34"""
        for bad in (0, 3001, "x"):
            with self.assertRaises(ValueError):
                LP.save_local({"rate_per_hour": bad}, "evil")
        with self.assertRaises(ValueError):
            LP.save_local({"models": "bad id!"}, "evil")
        self.assertTrue(LP.local_enabled())
        p = LP.save({"type": "openai", "name": "Keep", "api_key": KEY, "models": "m1"}, "u")
        LP.save_local({"enabled": False, "rate_per_hour": 10}, "admin")
        self.assertFalse(LP.local_enabled())
        self.assertFalse(LP.allowed("lmstudio", "local-a"))
        self.assertIsNotNone(LP.get(p["provider"]))  # the API providers are kept
        corr_llm.set_correlation("lmstudio", "local-a", "u")
        with self.assertRaisesRegex(RuntimeError, "Local server is disabled"):
            corr_llm._target()


# ---------------------------------------------------------------- clef_server.py
class ClefServer(_Base):
    """Decision-model server settings (backend, model file, llama-server, port, context, slots, batch)."""

    def setUp(self):
        super().setUp()
        for name, val in (("models", [{"path": "/models/clef-q4.gguf", "name": "clef-q4.gguf", "gb": 1.0, "flash": False}]),
                          ("servers", ["/opt/llama/llama-server"])):
            p = mock.patch.object(clef_server, name, return_value=val)
            p.start()
            self.addCleanup(p.stop)

    def test_defaults(self):
        """With nothing saved the server is the Kubernetes backend on port 8091, 32768 context, 4 slots, batch 8192.
        REQ: SET-35"""
        s = clef_server.settings()
        self.assertEqual({k: s[k] for k in clef_server.DEFAULTS}, clef_server.DEFAULTS)
        self.assertIsNone(s["by"])
        self.assertEqual(clef_server.url(), "http://127.0.0.1:30891")

    def test_valid_save_persists_and_stamps(self):
        """Valid settings are stored in the database with the user, read back by settings(), url(), clef.sh's env and clef.config().
        REQ: SET-35"""
        s = clef_server.save({"backend": "host", "gguf": "/models/clef-q4.gguf", "server": "/opt/llama/llama-server", "port": "9001",
                              "ctx": 2048, "parallel": 16, "batch": 4096}, "admin5")
        self.assertEqual((s["backend"], s["gguf"], s["server"], s["port"], s["ctx"], s["parallel"], s["batch"], s["by"]),
                         ("host", "/models/clef-q4.gguf", "/opt/llama/llama-server", 9001, 2048, 16, 4096, "admin5"))
        self.assertEqual(clef_server.url(), "http://127.0.0.1:9001")
        self.assertIn('CLEF_PORT:=9001', clef_server.shell_env())
        with mock.patch.object(clef, "URL_DEFAULT", ""):
            self.assertEqual(clef.config()["url"], "http://127.0.0.1:9001")
        s = clef_server.save({"port": 9002, "backend": ""}, "admin6")  # partial: the rest is kept, empty backend = unchanged
        self.assertEqual((s["backend"], s["port"], s["gguf"], s["by"]), ("host", 9002, "/models/clef-q4.gguf", "admin6"))
        s = clef_server.save({"gguf": "", "server": None}, "u")  # empty = cleared
        self.assertEqual((s["gguf"], s["server"]), ("", ""))

    def test_invalid_rejected(self):
        """Unknown backends, model files or binaries, numbers outside their ranges and a batch below 4096 are refused; nothing changes.
        REQ: SET-35"""
        clef_server.save({"backend": "host", "port": 9001}, "u")
        for b in ({"backend": "cloud"}, {"gguf": "/etc/passwd"}, {"server": "/bin/sh"}, {"port": 80}, {"port": 65536},
                  {"ctx": 1024}, {"ctx": 262145}, {"parallel": 0}, {"parallel": 17}, {"batch": 32769}, {"batch": 2048},
                  {"port": "abc"}):
            with self.assertRaises(ValueError, msg=b):
                clef_server.save(b, "evil")
        s = clef_server.settings()
        self.assertEqual((s["backend"], s["port"], s["batch"], s["by"]), ("host", 9001, 8192, "u"))


if __name__ == "__main__":
    unittest.main()
