"""Elasticsearch searches of the AIs -> Kibana Discover "artifact" descriptors (stdlib only; used by the dashboard and review.py).

An artifact of kind "query" keeps what Discover needs to reproduce a search the reviewer or the research AI ran:
  {"kql": ..., "from": ..., "to": ..., "index": ..., "total": ..., "why": ..., "approx": bool, "by": "reviewer"|"research"}
`approx` is true when part of the search (aggregations, scripts, odd clauses) cannot be written as KQL: the link then
opens a broader search than the one the AI ran. The page builds the URL from site.json (kibana_url, kibana_data_view).
"""
import json
import re

_SAFE_FIELD = re.compile(r"^[A-Za-z0-9_@][A-Za-z0-9_.@-]{0,80}$")


def q(v):
    return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _scalar(v):
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) else q(v)


def _vals(f, vals):
    vals = [v for v in vals if isinstance(v, (str, int, float, bool))][:20]
    if not vals:
        return None
    return f"{f}:{_scalar(vals[0])}" if len(vals) == 1 else f"{f}:({' or '.join(str(_scalar(v)) for v in vals)})"


def _index_kql(index):
    """Index name/pattern -> KQL on the _index metadata field (Discover's data view usually spans logs-*)."""
    parts = [p for p in re.split(r"[,\s]+", str(index or "")) if p and p not in ("*", "logs-*")]
    if not parts:
        return None
    one = [f"_index:*{p.strip('*')}*" if not p.startswith("*") else f"_index:{p}" for p in parts]
    return one[0] if len(one) == 1 else "(" + " or ".join(one) + ")"


def _text_kql(text):
    """simple_query_string text -> KQL: each word must appear (quoted phrases kept)."""
    toks = re.findall(r'"[^"]+"|[^\s()|+\-]+', str(text or ""))
    toks = [t for t in toks if t.lower() not in ("and", "or", "not")][:12]
    return " and ".join(t if t.startswith('"') else q(t.rstrip("*")) for t in toks) or None


def from_norm(norm, total=None, by="reviewer"):
    """Reviewer's normalised request (es_context.build) -> descriptor."""
    parts = [_index_kql(norm.get("es_index")) or None]
    for f, v in (norm.get("match") or {}).items():
        if _SAFE_FIELD.match(str(f)):
            parts.append(_vals(f, v if isinstance(v, list) else [v]))
    parts.append(_text_kql(norm.get("text")))
    kql = " and ".join(p for p in parts if p)
    return {"kql": kql, "from": norm.get("start"), "to": norm.get("end"), "index": norm.get("source"), "total": total,
            "why": str(norm.get("why") or "")[:200], "group_by": norm.get("group_by") or "", "approx": False, "by": by}


class _Approx(Exception):
    pass


def _lst(x):
    return x if isinstance(x, list) else [x] if x else []


def _clause(c, ctx):
    """One query-DSL clause -> KQL string (None = matches everything / dropped). Sets ctx['approx'] on anything lost."""
    if not isinstance(c, dict) or not c:
        return None
    (k, v), = list(c.items())[:1]
    if k == "match_all":
        return None
    if k == "bool":
        out = []
        for key in ("filter", "must"):
            for x in _lst(v.get(key)):
                s = _clause(x, ctx)
                if s:
                    out.append(s)
        sh = [_clause(x, ctx) for x in _lst(v.get("should"))]
        sh = [s for s in sh if s]
        if sh:
            out.append("(" + " or ".join(sh) + ")" if len(sh) > 1 else sh[0])
        for x in _lst(v.get("must_not")):
            s = _clause(x, ctx)
            if s:
                out.append(f"not ({s})")
        return " and ".join(out) if out else None
    if k in ("term", "match", "match_phrase", "terms", "prefix", "wildcard") and isinstance(v, dict) and v:
        f, val = next(iter(v.items()))
        if not _SAFE_FIELD.match(str(f)):
            ctx["approx"] = True
            return None
        if k == "terms":
            return _vals(f, val if isinstance(val, list) else [val])
        if isinstance(val, dict):
            val = val.get("value", val.get("query"))
        if not isinstance(val, (str, int, float, bool)):
            ctx["approx"] = True
            return None
        if k == "prefix":
            return f"{f}:{str(val)}*" if re.fullmatch(r"[\w.:-]+", str(val)) else f"{f}:{q(val)}"
        if k == "wildcard":
            return f"{f}:{val}" if re.fullmatch(r"[\w.:*?-]+", str(val)) else f"{f}:{q(val)}"
        return f"{f}:{_scalar(val)}"
    if k == "exists" and isinstance(v, dict) and _SAFE_FIELD.match(str(v.get("field", ""))):
        return f"{v['field']}:*"
    if k == "range" and isinstance(v, dict) and v:
        f, r = next(iter(v.items()))
        if f == "@timestamp":
            ctx["from"] = r.get("gte", r.get("gt", ctx.get("from")))
            ctx["to"] = r.get("lte", r.get("lt", ctx.get("to")))
            return None
        if not _SAFE_FIELD.match(str(f)) or not isinstance(r, dict):
            ctx["approx"] = True
            return None
        ops = {"gte": ">=", "gt": ">", "lte": "<=", "lt": "<"}
        s = [f"{f} {ops[o]} {_scalar(x)}" for o, x in r.items() if o in ops and isinstance(x, (str, int, float))]
        return " and ".join(s) or None
    if k in ("query_string", "simple_query_string") and isinstance(v, dict) and isinstance(v.get("query"), str):
        ctx["approx"] = True  # Lucene / simple syntax, shown as KQL: close but not identical
        return _text_kql(v["query"]) if k == "simple_query_string" else v["query"][:300]
    ctx["approx"] = True
    return None


def _time(t, default):
    """ES date-math ("now-24h") and ISO strings are valid in Discover's _g time; epoch ms become ISO."""
    if isinstance(t, (int, float)):
        from datetime import datetime, timezone
        return datetime.fromtimestamp(t / 1000, timezone.utc).isoformat(timespec="seconds")
    s = str(t or "").strip()
    return s if re.fullmatch(r"now([+-]\d+[smhdwMy])?(/[dhmwMy])?|\d{4}-\d\d-\d\d[T ][\d:.]+(Z|[+-]\d\d:?\d\d)?|\d{4}-\d\d-\d\d", s) else default


def from_dsl(index, body, total=None, by="research"):
    """Research AI's raw search body -> descriptor."""
    body = body if isinstance(body, dict) else {}
    ctx = {"approx": False}
    try:
        kql = _clause(body.get("query"), ctx) or ""
    except Exception:  # noqa: BLE001 - odd shapes: fall back to the index only
        kql, ctx["approx"] = "", True
    if body.get("aggs") or body.get("aggregations"):
        ctx["approx"] = True
    ix = _index_kql(index)
    kql = " and ".join(p for p in (ix, f"({kql})" if kql and " or " in kql and ix else kql) if p)
    return {"kql": kql, "from": _time(ctx.get("from"), "now-24h"), "to": _time(ctx.get("to"), "now"), "index": str(index)[:100],
            "total": total, "why": "", "group_by": "", "approx": bool(ctx["approx"]), "by": by}


def label(d):
    """One-line description for lists."""
    return (d.get("kql") or d.get("index") or "search")[:300]


def clean(d):
    """Validate a descriptor read from storage/an AI-facing path -> trimmed copy or None."""
    if not isinstance(d, dict) or not isinstance(d.get("kql"), str):
        return None
    out: dict = {k: d.get(k) for k in ("kql", "from", "to", "index", "total", "why", "group_by", "approx", "by")}
    out["kql"] = str(out["kql"])[:1000]
    return out


def dumps(d):
    return json.dumps(clean(d), separators=(",", ":"))
