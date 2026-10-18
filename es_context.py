#!/usr/bin/python3
"""Read-only Elasticsearch look-ups for the correlation reviewer (host_broker.py POST /esquery).

The reviewer model may ask for extra context before it decides a link (AI review > Models > "Elasticsearch
queries"). It never sends Elasticsearch DSL: it sends a small structured request, this module validates it and
builds the query itself, so the model can only run bounded `_search` requests on the Security Onion indices.

  {"source": "zeek" | "suricata" | "detections" | "endpoint" | "auth",
   "match":  {"<field>": "<value>" | [values], ...}     up to 6 exact (term/terms) filters
   "text":   "<simple_query_string>"                     optional, 200 chars, no leading wildcards
   "start":  ISO time, "end": ISO time                   default: anchor time -2 h .. +2 h; span <= 7 days
   "group_by": "<field>"                                 optional: top 10 values with counts instead of documents
   "size":   1..10                                       documents returned (default 5)
   "why":    "<one line: what the model wants to learn>"}

Results are trimmed (selected flat fields, 400 chars per document) and returned as data; the caller wraps them
in <es_result> tags and the reviewer's system prompt says never to follow instructions inside them.
CLI: es_context.py '<request json>' [anchor_epoch]
"""
import json, os, re, ssl, sys, urllib.request
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import integrations as INTEG  # noqa: E402

SOURCES = {  # name -> (index pattern, what it holds) - shown to the model
    "zeek": ("logs-zeek-so", "Zeek network logs: conn, dns, ssl, http, ssh, rdp, smb, ntlm, kerberos, notice, dhcp (event.dataset tells which)"),
    "suricata": ("logs-suricata.alerts-so", "Suricata IDS alerts (rule.name, rule.category)"),
    "detections": ("logs-detections.alerts-so", "Security Onion detection rule hits (rule.name)"),
    "endpoint": ("logs-endpoint.events.*", "Elastic Agent endpoint events: process, network, file (host.name, process.*, user.name)"),
    "auth": ("logs-system.auth-*", "Linux auth logs from Elastic Agent (sshd/sudo: event.outcome, user.name, source.ip)"),
}
FIELD = re.compile(r"^[A-Za-z0-9_@][A-Za-z0-9_.@-]{0,80}$")
KEEP = ("@timestamp", "event.dataset", "event.action", "event.outcome", "source.ip", "source.port", "destination.ip",
        "destination.port", "network.transport", "network.protocol", "connection.state", "rule.name", "rule.category",
        "dns.query.name", "dns.answers.name", "ssl.server_name", "tls.client.server_name", "http.request.method",
        "url.original", "http.virtual_host", "user.name", "host.name", "process.name", "process.command_line",
        "process.parent.name", "file.path", "ssh.auth_success", "client.bytes", "server.bytes", "message")
MAX_SPAN = timedelta(days=7)
DOC_CHARS, TEXT_CHARS = 400, 200


def _flat(d, p=""):
    for k, v in (d or {}).items():
        key = f"{p}{k}"
        if isinstance(v, dict):
            yield from _flat(v, key + ".")
        else:
            yield key, v


def _t(v, default):
    if not v:
        return default
    s = str(v).strip().replace("Z", "+00:00")
    try:
        t = datetime.fromisoformat(s)
    except ValueError:
        raise ValueError(f"bad time {str(v)[:40]!r} (use ISO 8601, UTC)") from None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def build(req, anchor=None):
    """Validate the model's request -> (index, ES body, normalised request). Raises ValueError on anything odd."""
    if not isinstance(req, dict):
        raise ValueError("query must be an object")
    src = str(req.get("source") or "")
    if src not in SOURCES:
        raise ValueError(f"source must be one of {', '.join(SOURCES)}")
    now = datetime.now(timezone.utc)
    a = datetime.fromtimestamp(float(anchor), timezone.utc) if anchor else now
    start, end = _t(req.get("start"), a - timedelta(hours=2)), _t(req.get("end"), min(now, a + timedelta(hours=2)))
    if end <= start:
        raise ValueError("end must be after start")
    if end - start > MAX_SPAN:
        start = end - MAX_SPAN
    filt: list = [{"range": {"@timestamp": {"gte": start.isoformat(), "lte": end.isoformat()}}}]
    match = req.get("match") or {}
    if not isinstance(match, dict) or len(match) > 6:
        raise ValueError("match: an object with at most 6 fields")
    for f, v in match.items():
        if not FIELD.match(str(f)):
            raise ValueError(f"bad field name {str(f)[:40]!r}")
        vals = v if isinstance(v, list) else [v]
        vals = [x for x in vals if isinstance(x, (str, int, float, bool))][:20]
        if not vals:
            raise ValueError(f"match.{f}: give a value or a list of values")
        vals = [str(x)[:200] if isinstance(x, str) else x for x in vals]
        filt.append({"terms": {f: vals}} if len(vals) > 1 else {"term": {f: vals[0]}})
    must = []
    text = str(req.get("text") or "").strip()[:TEXT_CHARS]
    if text:
        if re.search(r"(^|\s)[*?]", text):
            raise ValueError("text: no leading wildcards")
        must.append({"simple_query_string": {"query": text, "default_operator": "and", "lenient": True,
                                             "flags": "AND|OR|NOT|PHRASE|PREFIX|PRECEDENCE|ESCAPE|WHITESPACE"}})
    body = {"query": {"bool": {"filter": filt, "must": must}}, "track_total_hits": 100000, "timeout": "20s",
            "sort": [{"@timestamp": "desc"}]}
    gb = str(req.get("group_by") or "")
    if gb:
        if not FIELD.match(gb):
            raise ValueError("bad group_by field")
        body.update(size=0, aggs={"top": {"terms": {"field": gb, "size": 10}}})
        body.pop("sort")
    else:
        body["size"] = max(1, min(int(req.get("size") or 5), 10))
        body["_source"] = list(KEEP)
    norm = {"source": src, "match": match, "text": text, "start": start.isoformat(timespec="seconds"),
            "end": end.isoformat(timespec="seconds"), "group_by": gb, "size": body.get("size", 0), "why": str(req.get("why") or "")[:200]}
    return INTEG.map_index(SOURCES[src][0]), body, norm


def run(req, anchor=None):
    index, body, norm = build(req, anchor)
    url, key = INTEG.es_url(), INTEG.es_key()
    if not (url and key):
        raise ValueError("Elasticsearch is not configured (Configuration > Integrations)")
    r = urllib.request.Request(f"{url}/{index}/_search", data=json.dumps(body).encode(),  # noqa: S310 - https ES URL from settings
                               headers={"Authorization": f"ApiKey {key}", "Content-Type": "application/json"})
    # Security Onion's ES uses its own CA (same as collect.py)
    d = json.load(urllib.request.urlopen(r, context=ssl._create_unverified_context(), timeout=30))  # noqa: S310, S323
    total = (d.get("hits") or {}).get("total") or {}
    out = {"query": norm, "total": total.get("value", 0) if isinstance(total, dict) else total}
    if norm["group_by"]:
        out["top"] = [{"value": b.get("key_as_string", b.get("key")), "count": b.get("doc_count")}
                      for b in (d.get("aggregations") or {}).get("top", {}).get("buckets", [])]
    else:
        docs = []
        for h in d["hits"]["hits"]:
            src = dict(_flat(h.get("_source")))
            flat = {k: src[k] for k in KEEP if src.get(k) not in (None, "", [])}  # fixed order: time and 5-tuple first
            if "message" in flat:  # Zeek's message is the raw JSON log line (duplicates the fields): drop it
                m = str(flat.pop("message"))
                if not m.lstrip().startswith("{"):
                    flat["message"] = m[:150]
            docs.append(json.dumps(flat, default=str, separators=(",", ":"))[:DOC_CHARS])
        out["docs"] = docs
    return out


def describe():
    """The query help text placed in the reviewer's system prompt."""
    return "\n".join(f"  - {k}: {v[1]}" for k, v in SOURCES.items())


if __name__ == "__main__":
    print(json.dumps(run(json.loads(sys.argv[1]), float(sys.argv[2]) if len(sys.argv) > 2 else None), indent=1))
