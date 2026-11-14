"""Every setting netmon has, where it is changed, and the requirement(s) whose tests cover it.

tests/unit/test_settings_inventory.py discovers settings from the code (settings POST endpoints in server.py, the
integrations sections, the Settings-page documents and their documented keys, and every setter function) and fails
when one is missing here, or when an entry's requirements have no test. tests/gen_docs.py renders this table as
"Settings coverage" in docs/TEST_TRACEABILITY.md and docs/TESTING.md.
"""

# id: (where in the UI, endpoint(s), setter(s) "module.function", requirement ids)
SETTINGS = {
    # ---- Configuration > Integrations ----
    "integrations.elasticsearch": ("Configuration > Integrations > Elasticsearch (URL, API key, index names)",
                                   ["/api/config/integrations/elasticsearch"], ["integrations.save"], ["SET-01", "SET-02", "SET-03", "SET-04", "SET-05", "SET-06", "SET-07", "SET-12", "SET-13", "SET-60", "SET-61", "SET-62"]),
    "integrations.unifi": ("Configuration > Integrations > UniFi (controller URL, API key)",
                           ["/api/config/integrations/unifi"], ["integrations.save"], ["SET-01", "SET-05", "SET-06", "SET-07", "SET-08", "SET-12", "SET-13", "SET-60", "SET-61", "SET-62"]),
    "integrations.audit": ("More > Audit log > Audit log storage (key, index, send event reviewer / researcher events)",
                           ["/api/config/integrations/audit"], ["integrations.save"], ["SET-05", "SET-06", "SET-09", "SET-10", "SET-11", "SET-13", "SET-14", "SET-15", "SET-63"]),
    "integrations.web": ("Configuration > Integrations > Web search (provider, Firecrawl URL, key, CA)",
                         ["/api/config/integrations/web"], ["integrations.save"], ["WEB-01", "WEB-02", "WEB-03", "WEB-04", "SET-60", "SET-61"]),
    "integrations.opencti": ("Configuration > Integrations > OpenCTI", ["/api/config/integrations/opencti"],
                             ["integrations.save"], ["OCTI-01", "OCTI-03", "SET-60", "SET-61"]),
    "integrations.kubernetes": ("Configuration > Integrations > Kubernetes API (URL(s), read-only token, CA, CIS on/off)",
                                ["/api/config/integrations/kubernetes"], ["integrations.save"], ["KUBE-05", "KUBE-06", "SET-60", "SET-61"]),
    "integrations.feeds": ("Configuration > Integrations > Threat-intel feeds", ["/api/config/integrations/feeds"],
                           ["integrations.save"], ["FEED-01", "FEED-02", "SET-60"]),
    # ---- Settings page documents (every documented key, settings_docs.DOCS) ----
    "cfg.policy": ("Settings > Network policy (zones, roles, device classes, ports, thresholds)", ["/api/config/cfg"], [], ["STO-02", "SET-40", "SET-41", "SET-42", "SET-43", "SET-44", "SET-45", "SET-46", "SET-47", "SET-49", "SET-50", "SET-67"]),
    "cfg.class_defs": ("Settings > Network policy > Device class definitions (add, rename, remove, behaves like, per-class alarm switches)",
                       ["/api/config/classes"], [], ["CLS-01", "CLS-02", "CLS-03", "CLS-04", "CLS-05", "ANA-30"]),
    "cfg.host_policy": ("Settings > Host policy", ["/api/config/cfg"], [], ["STO-02", "SET-40", "SET-41", "SET-42", "SET-43", "SET-48", "SET-49"]),
    "cfg.known_benign": ("Settings > Known benign", ["/api/config/cfg"], [], ["STO-02", "SET-40", "SET-41", "SET-42", "SET-43", "SET-48"]),
    "cfg.site": ("Settings > Site", ["/api/config/cfg"], [], ["STO-02", "CFG-01", "EVW-01", "SET-40", "SET-41", "SET-42", "SET-43", "SET-48"]),
    "cfg.class_scope": ("Settings > Network policy > upload_spike / volume_spike / scan_thresholds / beacon: classes (device class drop-down) and by_class overrides",
                        ["/api/config/cfg"], [], ["CLS-06", "CLS-07", "CLS-08", "VOL-03", "VOL-04"]),
    "cfg.volume_spike": ("Settings > Network policy > volume_spike: min_mb, times_normal, mad_factor, min_days, severity (volume-spike finding)",
                         ["/api/config/cfg"], [], ["VOL-01", "VOL-02", "VOL-05"]),
    "cfg.tune": ("Settings > Auto-tune thresholds (recommend, accept)", ["/api/config/tune-apply"], [], ["SET-51", "SET-52", "SET-67", "CLS-09", "VOL-05"]),
    "cfg.discover": ("Settings > Network policy > Discover from UniFi", ["/api/config/discover"], [], ["SET-53", "SET-54", "SET-55"]),
    # ---- review job / research / auto-close ----
    "review.lookback": ("More > Settings > Site > event_window_minutes: event window (correlation window, review coverage, settle wait)", ["/api/config/cfg"], ["lookback.put"], ["EVW-01", "EVW-02", "EVW-03", "EVW-04", "SET-64"]),
    "push.gate": ("More > Settings > Site > push_wait_for_ai / push_hold_max_minutes: wait for the AI verdict before phone alerts, longest hold", ["/api/config/cfg"], [], ["PSH-01", "PSH-05", "PSH-06"]),
    "users.trust": ("More > Settings > Site > min_indicators / few_indicators_max_confidence / user_alert_min_confidence / stop_device_min_confidence / baseline_alerts_to_users: who is told what", ["/api/config/cfg"], [], ["ALR-30", "ALR-31", "ALR-32"]),
    "review.schedule": ("AI pipeline configuration > Review job schedule", ["/api/config/review-schedule"], ["review_cfg.put"], ["CFG-01", "SET-64"]),
    "review.job": ("AI pipeline configuration > Review job: on/off, event modes", ["/api/llm/review"], ["review_cfg.put"], ["CFG-01", "OPS-06", "SET-64"]),
    "research.limits": ("AI pipeline configuration > Research job limits (model, cost caps, web)", ["/api/llm/research"], ["research_cfg.put"], ["CFG-01", "SET-64"]),
    "autoclose": ("Open events > Auto-close settings and guard rails", ["/api/config/triage", "/api/config/triage/reopen"],
                  ["autoclose.set_settings"], ["STO-08", "STO-12", "SET-64"]),
    "notes.consolidate": ("AI pipeline configuration > Nightly note consolidation", ["/api/llm/notes-consolidate"],
                          ["notes_consolidate.set_cfg"], ["STO-09", "SET-66"]),
    # ---- AI models and the event reviewer ----
    "llm.models": ("AI pipeline configuration > Models (event reviewer, research, chat model)", ["/api/llm/config"],
                   ["corr_llm.set_correlation", "corr_llm.set_chat"], ["SET-22", "SET-23", "SET-65"]),
    "llm.providers": ("AI pipeline configuration > AI providers (added APIs, local server)", ["/api/llm/providers"],
                      ["llm_providers.save", "llm_providers.save_local"], ["SET-32", "SET-33", "SET-34", "SET-65"]),
    "llm.clef": ("AI pipeline configuration > Decision model settings (on/off, thresholds)", ["/api/llm/clef"], ["clef.set_config"], ["SET-30", "SET-31", "SET-66"]),
    "llm.clef_server": ("AI pipeline configuration > Decision model server", ["/api/llm/clef-server"], ["clef_server.save"], ["SET-35"]),
    "llm.notes": ("AI pipeline configuration > Event reviewer context notes", ["/api/llm/notes"], ["corr_llm.set_notes_limit"], ["SET-20", "SET-21", "SET-16", "SET-66"]),
    "llm.review_limits": ("AI pipeline configuration > Review limits", ["/api/llm/review-limits"], ["corr_llm.set_limits"], ["STO-05", "SET-26", "SET-27", "SET-28", "SET-29", "SET-66", "SET-69"]),
    "llm.esqueries": ("AI pipeline configuration > Event reviewer look-ups: Elasticsearch", ["/api/llm/esqueries"], ["corr_llm.set_es_queries"], ["SET-25", "SET-66"]),
    "llm.websearch": ("AI pipeline configuration > Event reviewer look-ups: web search", ["/api/llm/websearch"], ["corr_llm.set_web_search"], ["SET-25", "SET-66"]),
    "llm.lookupplan": ("AI pipeline configuration > Event reviewer look-ups first", ["/api/llm/lookupplan"], ["corr_llm.set_lookup_plan"], ["SET-24", "SET-66"]),
    "llm.webcache": ("AI pipeline configuration > netmon web cache (on/off, days kept, clear)", ["/api/llm/webcache"], ["corr_llm.set_web_cache"], ["WEB-08", "SET-66"]),
    "llm.chat_es": ("Ask AI: may the chat search Elasticsearch", ["/api/llm/chat-es"], ["corr_llm.set_chat_es"], ["SET-23", "SET-66", "SET-69"]),
    # ---- per user ----
    "push.prefs": ("Account > Notifications (which devices alert me)", ["/api/push/prefs"], [], ["STO-07", "SET-68"]),
}

# POST endpoints under the settings prefixes that are actions, not settings (nothing persistent to cover)
ACTIONS = {
    "/api/config/triage/run": "runs auto-close now",
    "/api/config/triage/reopen-guard": "reopens closures a guard rail holds back today",
    "/api/config/integrations/<section>/test": "Test button: checks the connection, saves nothing",
}
