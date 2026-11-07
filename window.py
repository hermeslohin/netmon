"""Time window shared by every collector.

Two kinds of window:

* Event time (@timestamp) - a dashboard time range (collect.py --start/--end, started by the host LLM broker for the
  range picker) sets NETMON_WINDOW_END, and every query covers [end - N minutes, end]: what HAPPENED in that range.
  Without an end and without arrival mode it is [now - N minutes, now].

* Arrival time (event.ingested) - the watcher and the review job (`collect.py auto`) select by when Elasticsearch
  STORED an event, not when it happened. When Logstash / the SO ingest pipeline is backed up, events reach ES hours
  late; an event-time window of "the last 20 minutes" would never see them. Arrival mode keeps one bookmark per job
  (store meta "arrival:<job>" = the end of the last successful run's window):

      window = (from, to]      to   = now - ARRIVAL_MARGIN_S (newest arrivals may not be searchable yet: refresh 30 s)
                               from = the bookmark (watcher: exactly, no overlap)
                                      / min(bookmark, to - lookback) (review job: keeps its lookback overlap)
                                      / to - nominal minutes on the first run; never older than MAX_CATCHUP_H

  Windows touch end to end, so every event is selected by exactly one watcher run, however late it arrives - no
  event ids need to be kept. The bookmark only moves on commit() after a run that did not fail, so a failed run is
  covered by the next one. Documents without event.ingested fall back to @timestamp over the same span.
  Aggregations (hourly charts, baselines) still bucket on @timestamp, so a late event lands in the hour it happened.
"""
import datetime as dt
import json
import os
import time

ARRIVAL_MARGIN_S = 120     # > index refresh (30 s on the SO data streams) + bulk latency; single-node cluster, no clock skew
MAX_CATCHUP_H = 7 * 24     # a scheduler outage longer than this restarts from now - MAX_CATCHUP_H
LATE_S = 30 * 60           # an event that arrives more than this after it happened is "late" (lag stats, alert notes)
_ARR = {}                  # active arrival window: job, frm, to (epoch s), nominal (minutes)


def _iso(t):
    return dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _bm_key(job):
    return "arrival:" + job


def bookmark(job):
    """End (epoch s) of the last committed window of `job`, or None."""
    try:
        import store
        with store.connect() as c:
            r = c.execute("SELECT v FROM meta WHERE k=?", (_bm_key(job),)).fetchone()
        return float(json.loads(r[0])["to"]) if r else None
    except Exception:  # noqa: BLE001 - no store / bad row: first run
        return None


def arrival(job, minutes, overlap=False, now=None):
    """Switch every since() of this process to arrival time. Returns the window {job, from, to, nominal, first}.
    job None = a manual run: arrival window of `minutes`, no bookmark read or written."""
    to = (time.time() if now is None else now) - ARRIVAL_MARGIN_S
    nominal = max(1.0, float(minutes))
    prev = bookmark(job) if job else None
    if prev is None or prev >= to:
        frm = to - nominal * 60
    else:
        frm = min(prev, to - nominal * 60) if overlap else prev
    frm = max(frm, to - MAX_CATCHUP_H * 3600)
    _ARR.clear()
    _ARR.update(job=job, frm=frm, to=to, nominal=nominal, first=prev is None)
    return info()


def info():
    """The active arrival window (ISO from/to, span minutes), or None in event-time mode."""
    if not _ARR:
        return None
    return {"job": _ARR["job"], "from": _iso(_ARR["frm"]), "to": _iso(_ARR["to"]), "span_minutes": round((_ARR["to"] - _ARR["frm"]) / 60, 1),
            "nominal_minutes": _ARR["nominal"], "first_run": _ARR["first"], "field": "event.ingested"}


def commit():
    """Move the bookmark to the end of this window (call after a run that did not fail)."""
    if not _ARR or not _ARR.get("job"):
        return False
    import store
    with store.connect() as c:
        c.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)",
                  (_bm_key(_ARR["job"]), json.dumps({"to": _ARR["to"], "from": _ARR["frm"], "at": time.time()})))
    return True


def off():
    _ARR.clear()


def arrival_filter(frm, to):
    """(frm, to] on event.ingested; documents without event.ingested by @timestamp over the same span."""
    r = {"gt": _iso(frm), "lte": _iso(to)}
    return {"bool": {"should": [{"range": {"event.ingested": r}},
                                {"bool": {"must_not": [{"exists": {"field": "event.ingested"}}], "filter": [{"range": {"@timestamp": r}}]}}],
                     "minimum_should_match": 1}}


def end():
    """ISO end of the window (UTC, 'Z'), or None for now."""
    return os.environ.get("NETMON_WINDOW_END") or None


def end_dt():
    e = end()
    return dt.datetime.fromisoformat(e.replace("Z", "+00:00")) if e else dt.datetime.now(dt.timezone.utc)


def end_ms():
    return int(end_dt().timestamp() * 1000)


def since(minutes):
    """Elasticsearch range filter for the last `minutes` of the window. In arrival mode the job's own span
    (minutes == nominal) is exactly the bookmark window; any other span is [to - minutes, to] but never starts after
    the bookmark window does, so every range covers at least the job window."""
    if _ARR and not end():
        if abs(float(minutes) - _ARR["nominal"]) < 1e-6:
            return arrival_filter(_ARR["frm"], _ARR["to"])
        return arrival_filter(min(_ARR["frm"], _ARR["to"] - max(1.0, float(minutes)) * 60), _ARR["to"])
    m = max(1, int(round(minutes)))
    e = end()
    if e:
        return {"range": {"@timestamp": {"gte": f"{e}||-{m}m", "lte": e}}}
    return {"range": {"@timestamp": {"gte": f"now-{m}m"}}}


def since_h(hours):
    return since(float(hours) * 60)


def is_range():
    return bool(end())


# per-source ingest lag (how far behind Logstash / the ingest pipeline is), measured over the arrival window
LAG_SOURCES = {"zeek": "logs-zeek-so", "suricata": "logs-suricata.alerts-so", "endpoint": "logs-endpoint.events.*",
               "system": "logs-system.*", "osquery": "logs-osquery_manager.*", "detections": "logs-detections.alerts-so"}
_LAG_SCRIPT = ("if (doc.containsKey('event.ingested') && doc['event.ingested'].size() > 0 && doc['@timestamp'].size() > 0) "
               "return (doc['event.ingested'].value.toInstant().toEpochMilli() - doc['@timestamp'].value.toInstant().toEpochMilli()) / 1000.0; "
               "return null;")


def lag_stats(q, frm=None, to=None):
    """{source: {n, late, p50_s, p99_s, max_s, newest_event}} for events that arrived in (frm, to] (default: the
    active arrival window). q = collect.q. A failing source is reported with an error, never raised."""
    if frm is None:
        if not _ARR:
            return {}
        frm, to = _ARR["frm"], _ARR["to"]
    out = {}
    for name, ix in LAG_SOURCES.items():
        try:
            r = q(ix, {"size": 0, "track_total_hits": True, "query": {"range": {"event.ingested": {"gt": _iso(frm), "lte": _iso(to)}}},
                       "aggs": {"lag": {"percentiles": {"script": {"source": _LAG_SCRIPT}, "percents": [50, 99]}},
                                "mx": {"max": {"script": {"source": _LAG_SCRIPT}}},
                                "late": {"filter": {"script": {"script": {"source": "def v = doc['event.ingested']; def t = doc['@timestamp']; "
                                                                          "return v.size() > 0 && t.size() > 0 && v.value.toInstant().toEpochMilli() - "
                                                                          "t.value.toInstant().toEpochMilli() > params.l", "params": {"l": LATE_S * 1000}}}}},
                                "newest": {"max": {"field": "@timestamp"}}}})
            a, n = r["aggregations"], r["hits"]["total"]["value"]
            v = a["lag"]["values"]
            out[name] = {"n": n, "late": a["late"]["doc_count"], "p50_s": v.get("50.0"), "p99_s": v.get("99.0"),
                         "max_s": a["mx"]["value"], "newest_event": a["newest"].get("value_as_string")}
        except Exception as e:  # noqa: BLE001 - missing index / no permission
            out[name] = {"error": f"{type(e).__name__}: {str(e)[:120]}"}
    return out


def save_lag(stats):
    try:
        import store
        with store.connect() as c:
            c.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", ("ingest_lag", json.dumps({"at": time.time(), "window": info(), "sources": stats})))
    except Exception as e:  # noqa: BLE001 - informational only
        print(f"(ingest lag not saved: {e})", file=__import__("sys").stderr)


def load_lag():
    try:
        import store
        with store.connect() as c:
            r = c.execute("SELECT v FROM meta WHERE k='ingest_lag'").fetchone()
        return json.loads(r[0]) if r else None
    except Exception:  # noqa: BLE001
        return None
