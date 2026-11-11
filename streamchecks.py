"""Checks shared by the watcher (watch.py, once per event window) and the stream (stream.py, every few seconds).

Each check takes the Elasticsearch search function q(index, body), the arrival-window filter R (window.since) and an
alert(key, text, at=None, kind=None, ip=None, mac=None) callback, and raises on an Elasticsearch error (the caller
keeps its arrival bookmark). Alert keys are the same whichever process raises them, so the watcher's 12-hour mute
(store.mute_filter) drops the second copy of an event both saw.

  ids(q, R, alert, benign_sig, nm)     Suricata severity-1 alerts or malware / C2 / exploit categories
  syslog(q, R, alert)                  watched syslog patterns (host_policy syslog_patterns with "watch": true)
  host_alerts(q, R, alert)             Elastic Defend alerts + Security Onion detection (Sigma) alerts
"""
import collections
import re
import sys

IDS_CATEGORIES = ["A Network Trojan was detected", "Malware Command and Control Activity Detected",
                  "Exploit Kit Activity Detected", "Successful Administrator Privilege Gain",
                  "Successful User Privilege Gain", "Targeted Malicious Activity was Detected",
                  "Domain Observed Used for C2 Detected", "Crypto Currency Mining Activity Detected"]
LATE_S = 30 * 60
_IFACE = re.compile(r"\b(eno\d+|enp\w+|eth\d+|ens\w+|vnet\d+|sd[a-z]\d*|nvme\w+|dm-\d+)\b")


def _b(agg):
    return (agg or {}).get("buckets", []) if isinstance(agg, dict) else []


def bucket_time(b):
    """Epoch of a bucket's first event (its "t0" min @timestamp aggregation), or None."""
    try:
        v = (b.get("t0") or {}).get("value")
        return float(v) / 1000 if v else None
    except (TypeError, ValueError, AttributeError):
        return None


def late_note(b):
    """' (happened <time>, arrived N h late)' when the first event of a bucket reached ES more than LATE_S late."""
    try:
        t0, t1 = (b.get("t0") or {}).get("value"), (b.get("in") or {}).get("value")
        if t0 and t1 and (t1 - t0) / 1000 > LATE_S:
            return f" (happened {(b['t0'].get('value_as_string') or '')[:16].replace('T', ' ')} UTC, arrived {(t1 - t0) / 3.6e6:.1f} h late)"
    except (TypeError, ValueError, AttributeError) as e:
        print(f"(late note: {e})", file=sys.stderr)
    return ""


def _mitre_tags(ids):
    try:
        import mitre
        return " [ATT&CK " + ", ".join(f"{i} {mitre.tech(i).get('name', '')}" for i in ids) + "]" if ids else ""
    except Exception:  # noqa: BLE001 - tags are decoration
        return ""


def ids(q, R, alert, benign_sig=lambda s: False, nm=str):
    """Suricata: severity 1 or a malware / C2 / exploit category, signatures not on the known-benign list."""
    r = q("logs-suricata.alerts-so", {"size": 0, "query": {"bool": {"filter": [R], "should": [
        {"term": {"rule.severity": 1}}, {"terms": {"rule.category": IDS_CATEGORIES}}], "minimum_should_match": 1}},
        "aggs": {"s": {"terms": {"field": "rule.name", "size": 20},
                       "aggs": {"src": {"terms": {"field": "source.ip", "size": 2}}, "dst": {"terms": {"field": "destination.ip", "size": 2}},
                                "mt": {"terms": {"field": "rule.metadata.mitre_technique_id", "size": 2}},
                                "t0": {"min": {"field": "@timestamp"}}, "in": {"max": {"field": "event.ingested"}}}}}})
    n = 0
    for b in _b(r["aggregations"]["s"]):
        if benign_sig(b["key"]):
            continue
        src = [x["key"] for x in _b(b["src"])]
        dst = [x["key"] for x in _b(b["dst"])]
        mt = _mitre_tags([x["key"] for x in _b(b.get("mt"))])
        alert(f"ids|{b['key']}|{src[:1]}", f"**IDS:** {b['key']} x{b['doc_count']} - {', '.join(map(nm, src))} -> {', '.join(map(nm, dst))}{mt}{late_note(b)}",
              at=bucket_time(b), kind="ids", ip=(src or [None])[0])
        n += 1
    return n


def _host_alert(alert, k, pri, t, at=None):
    try:
        import mitre
        t += mitre.tags_for("host", f"{k}|{t}")
    except Exception as e:  # noqa: BLE001 - tags are decoration
        print(f"(mitre tags: {e})", file=sys.stderr)
    alert(f"host|{k}", f"**Host {'ALERT' if pri == 'Investigate' else 'notice'}:** {t}", at=at)


def _acks():
    try:
        import hosts_ack
        return hosts_ack.load()
    except Exception:  # noqa: BLE001 - no acks: every finding counts
        return {}


def syslog_data(q, R, patterns):
    """hosts.syslog() output for the watched patterns, in ONE search (a filters aggregation per pattern) instead of
    one per pattern, so a tail every few seconds stays cheap: {host: {pattern: {count, first, last, sev, devices, sample}}}."""
    import hosts
    flt = {}
    for name, spec in patterns.items():
        f = [{"wildcard": {"message": {"value": spec["q"], "case_insensitive": True}}}]
        if spec.get("process"):
            f.append({"term": {"process.name": spec["process"]}})
        flt[name] = {"bool": {"filter": f}}
    if not flt:
        return {}
    r = q("logs-system.syslog-default", {"size": 0, "query": {"bool": {"filter": [R], "should": list(flt.values()), "minimum_should_match": 1}},
                                         "aggs": {"p": {"filters": {"filters": flt}, "aggs": {"h": {"terms": {"field": "host.name", "size": 20}, "aggs": {
                                             "first": {"min": {"field": "@timestamp"}}, "last": {"max": {"field": "@timestamp"}},
                                             "s": {"top_hits": {"size": 5, "sort": [{"@timestamp": "desc"}], "_source": ["message"]}}}}}}}})
    out = {}
    for name, pb in ((r.get("aggregations") or {}).get("p") or {}).get("buckets", {}).items():
        for b in _b(pb.get("h")):
            samples = [(x.get("_source") or {}).get("message") or "" for x in ((b.get("s") or {}).get("hits") or {}).get("hits", [])]
            ifs = collections.Counter(m for s in samples for m in _IFACE.findall(s)[:1])
            out.setdefault(hosts.hn(b["key"]), {})[name] = {
                "count": b["doc_count"], "first": b["first"].get("value_as_string") or "", "last": b["last"].get("value_as_string") or "",
                "sev": patterns[name].get("sev", "Review"), "devices": dict(ifs.most_common(5)), "sample": samples[0][:220] if samples else "",
                "t0": (b["first"].get("value") or 0) / 1000 or None}
    return out


def syslog(q, R, alert):
    """Watched syslog patterns (the same findings and keys as the watcher's host check: host|syslog|<host>|<pattern>)."""
    import hosts
    watched = {k: v for k, v in hosts.SYSLOG_PATTERNS.items() if v.get("watch")}
    data = syslog_data(q, R, watched)
    acks, n = _acks(), 0
    for k, pri, t in hosts.findings({"syslog": data}, {}, nightly=False):
        if not k.startswith("syslog|") or k in acks:
            continue
        _, host, name = k.split("|", 2)
        _host_alert(alert, k, pri, t, at=(data.get(host) or {}).get(name, {}).get("t0"))
        n += 1
    return n


def _ts(v):
    import datetime as dt
    try:
        return dt.datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def host_alerts(q, R, alert):
    """Elastic Defend alerts (keys host|defend|..., as the watcher) and Security Onion detection alerts (Sigma rules on host
    and application logs: host|detect|<host>|<rule>; high / critical = ALERT, lower = notice)."""
    import hosts
    acks, n = _acks(), 0
    r = q("logs-endpoint.alerts-*", {"size": 50, "sort": [{"@timestamp": "desc"}], "query": {"bool": {"filter": [R]}},
                                     "_source": ["@timestamp", "host.name", "event.code", "event.action", "event.outcome", "rule.name", "message",
                                                 "file.path", "process.executable", "process.command_line", "user.name"]})
    ea = [h["_source"] for h in (r.get("hits") or {}).get("hits", [])]
    first = {}  # finding key -> earliest @timestamp of the alerts behind it (the key itself carries only the hour)
    for a in ea:
        k1 = hosts.findings({"endpoint_alerts": [a]}, {}, nightly=False)
        if k1 and _ts(a.get("@timestamp")):
            first[k1[0][0]] = min(first.get(k1[0][0], 1e12), _ts(a["@timestamp"]))
    for k, pri, t in hosts.findings({"endpoint_alerts": ea}, {}, nightly=False):
        if k.startswith("defend|") and k not in acks:
            _host_alert(alert, k, pri, t, at=first.get(k))
            n += 1
    r = q("logs-detections.alerts-so", {"size": 100, "sort": [{"@timestamp": "asc"}], "query": {"bool": {"filter": [R]}},
                                        "_source": ["@timestamp", "rule.name", "event.severity_label", "event_data.host.name", "event_data.user.name",
                                                    "event_data.source.ip", "host.name", "user.name", "source.ip", "message"]})
    seen = {}
    for h in (r.get("hits") or {}).get("hits", []):
        s = h["_source"]
        ed = s.get("event_data") or {}
        rule = (s.get("rule") or {}).get("name") or "detection"
        host = hosts.hn((ed.get("host") or {}).get("name") or (s.get("host") or {}).get("name") or "?")
        key = f"detect|{host}|{rule}"
        v = seen.setdefault(key, {"n": 0, "t0": _ts(s.get("@timestamp")), "sev": str((s.get("event") or {}).get("severity_label") or "").lower(),
                                  "user": (ed.get("user") or {}).get("name") or (s.get("user") or {}).get("name"),
                                  "src": (ed.get("source") or {}).get("ip") or (s.get("source") or {}).get("ip")})
        v["n"] += 1
    for key, v in seen.items():
        if key in acks:
            continue
        _, host, rule = key.split("|", 2)
        pri = "Investigate" if v["sev"] in ("high", "critical") else "Review"
        extra = ", ".join(x for x in (f"user {v['user']}" if v["user"] else "", f"from {v['src']}" if v["src"] else "") if x)
        _host_alert(alert, key, pri, f"Security Onion detection on {host}: {rule} x{v['n']}{' (' + extra + ')' if extra else ''}"
                                     f"{' [' + v['sev'] + ']' if v['sev'] else ''}", at=v["t0"])
        n += 1
    return n
