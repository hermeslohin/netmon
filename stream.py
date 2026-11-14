#!/usr/bin/python3
"""Event stream: tails Elasticsearch every few seconds for Suricata alerts, watched syslog patterns and host alerts
(Elastic Defend + Security Onion detections), so those events reach the dashboard and the event reviewer within about a
minute instead of at the next watcher pull (one event window, default 5 min).

How: Elasticsearch has no change feed, so this polls by ARRIVAL time (event.ingested, window.py) with its own bookmark
("arrival:stream"): every STREAM_S seconds it reads (bookmark, now - STREAM_MARGIN_S] - windows touch end to end, so every
document is read by exactly one tick however late it arrives; a tick with an Elasticsearch error keeps the bookmark and
the next tick re-reads the span. The checks are the watcher's own (streamchecks.py), with the same alert keys, so
store.mute_filter (12 h) drops whichever copy comes second. Alerts are stored with source "stream" (held: events for the
correlation and the AI review, never an alarm by themselves) and the event time, never posted to chat.

The watcher keeps running these checks once per window as a fallback (stream down / restarted).
The event reviewer (dashboard corr_llm.event_pass) settles a group made only of stream events against this bookmark
instead of the watcher's, so it is labelled about a minute after its newest event is one event window old.

Run by the scheduler (job "stream", restarted within 20 s when it exits; it exits every RUN_FOR_S to pick up code changes).
Usage: stream.py            run (loop)
       stream.py once       one tick, print what it found
       stream.py status     bookmark + last tick
"""
import json
import os
import sys
import time

sys.argv = [sys.argv[0], "1"] + sys.argv[1:]  # collect.py reads argv at import (hours = 1, unused: every query is windowed)
NM = os.environ.get("NETMON_DIR") or os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from collect import q, inventory  # noqa: E402
import store  # noqa: E402
import streamchecks  # noqa: E402
import window  # noqa: E402

JOB = "stream"
STREAM_S = float(os.environ.get("NETMON_STREAM_S", 15))   # seconds between ticks
RUN_FOR_S = 3600                                           # exit after this long; the scheduler starts a fresh process
SUPPRESS_H = 12                                            # same mute as the watcher
STATUS_DOC = "state/stream"
CHECKS = (("suricata", "ids"), ("syslog", "syslog"), ("host", "host_alerts"))


class Ctx:
    """Names, benign signatures and the per-class alarm policy, re-read every 10 minutes."""
    def __init__(self):
        self.at = 0

    def refresh(self):
        if time.time() - self.at < 600:
            return
        self.at = time.time()
        self.benign = store.jload(os.path.join(NM, "known_benign.json")) or {}
        self.registry = store.registry_load()
        inv, _ = inventory()
        self.names = {v["ip"]: v["name"] for v in inv.values()}
        self.names.update(self.benign.get("names", {}))
        try:
            self.pol = store.cfg_load("policy") or {}
        except Exception:  # noqa: BLE001 - no policy = every alarm on
            self.pol = {}

    def nm(self, ip):
        return f"{self.names.get(ip, ip)} ({ip})" if self.names.get(ip) else ip

    def benign_sig(self, sig):
        return any(k.lower() in sig.lower() for k in self.benign.get("signatures", {}))

    def alarm_on(self, kind, ip=None, mac=None):
        import classdefs
        if ip and not mac:
            mac = next((m for m, r in self.registry.items() if ip in (r.get("ips") or [])), None)
        return classdefs.device_alarm(self.pol, kind, ip, mac)


def tick(ctx, now=None):
    """One arrival window: run every check, store new alerts, move the bookmark when no check failed.
    Returns {"window": ..., "found": {check: n}, "new": [keys], "failed": [checks]}."""
    import lookback
    ctx.refresh()
    aw = window.arrival(JOB, lookback.minutes(), now=now, margin=window.STREAM_MARGIN_S)  # first run: the last event window
    R = window.since(aw["nominal_minutes"])
    alerts, ets, found, failed = [], {}, {}, []

    def alert(key, text, at=None, kind=None, ip=None, mac=None):
        if kind and (ip or mac) and not ctx.alarm_on(kind, ip, mac):
            return
        alerts.append((key, text))
        if at:
            ets.setdefault(key, float(at))

    for name, fn in CHECKS:
        try:
            f = getattr(streamchecks, fn)
            found[name] = f(q, R, alert, ctx.benign_sig, ctx.nm) if fn == "ids" else f(q, R, alert)
        except Exception as e:  # noqa: BLE001 - keep the bookmark; the next tick re-reads this span
            failed.append(name)
            print(f"stream {name} check failed: {type(e).__name__}: {str(e)[:300]}", file=sys.stderr, flush=True)
    fresh = store.mute_filter(alerts, SUPPRESS_H) if alerts else []
    if fresh:
        store.alerts_add([(k, t.replace("**", ""), "investigate" if ("ALERT" in t or t.startswith("**IDS")) else "urgent", None, ets.get(k))
                          for k, t in fresh], source="stream")
    if not failed:
        window.commit()
    st = {"at": time.time(), "from": aw["from"], "to": aw["to"], "span_s": round(aw["span_minutes"] * 60), "found": found,
          "new": len(fresh), "failed": failed}
    try:
        old = store.doc_get(STATUS_DOC, {}) or {}
        st["ticks"] = int(old.get("ticks") or 0) + 1
        st["new_total"] = int(old.get("new_total") or 0) + len(fresh)
        st["last_new"] = time.time() if fresh else old.get("last_new")
        st["errors"] = int(old.get("errors") or 0) + (1 if failed else 0)
        store.doc_put(STATUS_DOC, st)
    except Exception as e:  # noqa: BLE001 - status is informational
        print(f"stream status write failed: {e}", file=sys.stderr)
    for k, t in fresh:
        print(f"new {k}: {t.replace('**', '')[:200]}", flush=True)
    return {"window": aw, "found": found, "new": [k for k, _ in fresh], "failed": failed}


def status():
    return {"bookmark": window.bookmark(JOB), "last": store.doc_get(STATUS_DOC, {}), "every_s": STREAM_S, "margin_s": window.STREAM_MARGIN_S}


def main():
    cmd = sys.argv[2:3]
    if cmd == ["status"]:
        print(json.dumps(status(), indent=1, default=str))
        return 0
    ctx = Ctx()
    if cmd == ["once"]:
        print(json.dumps(tick(ctx), indent=1, default=str))
        return 0
    import fcntl
    os.makedirs(os.path.join(NM, "logs"), exist_ok=True)
    lk = open(os.path.join(NM, "logs", "stream.lock"), "w")  # one stream at a time (a scheduler restart leaves its children running)
    try:
        fcntl.flock(lk, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print("another stream is running; exiting", file=sys.stderr)
        return 3
    t_end = time.time() + RUN_FOR_S
    print(f"stream started: every {STREAM_S:g} s, margin {window.STREAM_MARGIN_S} s", flush=True)
    while time.time() < t_end:
        t0 = time.time()
        try:
            tick(ctx)
        except Exception as e:  # noqa: BLE001 - store / config trouble: log, wait, retry
            print(f"stream tick error: {type(e).__name__}: {str(e)[:300]}", file=sys.stderr, flush=True)
        time.sleep(max(1.0, STREAM_S - (time.time() - t0)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
