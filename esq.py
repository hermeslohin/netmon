#!/usr/bin/python3
"""Ad-hoc read-only ES query: esq.py <index> '<json body>'  -> prints JSON (aggs or trimmed hits)."""
import json, os, ssl, sys, urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import site_cfg as SITE  # noqa: E402  network-specific values live in site.json (git-ignored)
HOME = os.environ.get("HERMES_HOME") or os.path.expanduser("~/.hermes")
KEY = next(l.split("=", 1)[1].strip().strip("'\"") for l in open(f"{HOME}/.env")
           if l.startswith("MCP_SO_ELASTICSEARCH_API_KEY="))


def q(index, body):
    req = urllib.request.Request(f"{SITE.get('es_url')}/{index}/_search", data=json.dumps(body).encode(),
                                 headers={"Authorization": f"ApiKey {KEY}", "Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req, context=ssl._create_unverified_context(), timeout=180))


if __name__ == "__main__":
    r = q(sys.argv[1], json.loads(sys.argv[2]))
    if "aggregations" in r:
        print(json.dumps(r["aggregations"], indent=1))
    for h in r["hits"]["hits"]:
        print(json.dumps(h["_source"])[:int(os.environ.get("W", 600))])
