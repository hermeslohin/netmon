#!/usr/bin/python3
"""Read-only Kubernetes API client for netmon (stdlib only).

Settings come from the dashboard integration "kubernetes" (integrations.kubernetes(): enabled, url, api_key = a
ServiceAccount bearer token, ca_pem). The account is expected to be read-only (get/list/watch, no secrets,
no pods/log, no exec, no nodes/proxy); this client only sends GET, plus SelfSubjectAccessReview (asks the API
server what this account itself may do - changes nothing). TLS is always verified - with the pasted CA,
else the system store. url may list several API servers separated by commas (control-plane nodes): the first one
that answers is used, so a rebooting control-plane node doesn't stop the checks.

Used by kube_cis.py (CIS benchmark) and kube_map.py (the Kubernetes map). Container logs and events are NOT read
here: they come from Security Onion (k8s.py).
"""
import json, os, ssl, sys, urllib.error, urllib.parse, urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import integrations as INTEG  # noqa: E402

MAX_ITEMS = 20000


class NotConfigured(RuntimeError):
    pass


class Client:
    def __init__(self, cfg=None, timeout=20):
        c = cfg if cfg is not None else INTEG.kubernetes()
        if not (c.get("url") and c.get("api_key")):
            raise NotConfigured("Kubernetes API not configured (Configuration > Integrations > Kubernetes)")
        if cfg is None and not c.get("enabled"):
            raise NotConfigured("Kubernetes API integration is turned off (Configuration > Integrations > Kubernetes)")
        self.urls = [u.strip().rstrip("/") for u in str(c["url"]).split(",") if u.strip()]
        for u in self.urls:
            if not u.startswith("https://"):
                raise ValueError("Kubernetes API URL must start with https://")
        self.token, self.timeout = c["api_key"], timeout
        self.ctx = ssl.create_default_context(cadata=c["ca_pem"]) if c.get("ca_pem") else ssl.create_default_context()
        self.used = None

    def get(self, path, params=None):
        q = ("?" + urllib.parse.urlencode(params)) if params else ""
        last = None
        for u in ([self.used] if self.used else []) + [x for x in self.urls if x != self.used]:
            req = urllib.request.Request(u + path + q, headers={"Authorization": "Bearer " + self.token, "Accept": "application/json"})
            try:
                with urllib.request.urlopen(req, context=self.ctx, timeout=self.timeout) as r:  # noqa: S310 - https only (checked above)
                    self.used = u
                    return json.load(r)
            except urllib.error.HTTPError as e:  # the server answered: no failover, report it
                try:
                    msg = json.load(e).get("message", "")
                except Exception:  # noqa: BLE001
                    msg = ""
                raise PermissionError(f"HTTP {e.code} {path}: {msg[:200]}") if e.code in (401, 403) else RuntimeError(f"HTTP {e.code} {path}: {msg[:200]}") from None
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                last = e
        raise ConnectionError(f"no Kubernetes API server reachable ({', '.join(self.urls)}): {getattr(last, 'reason', last)}")

    def items(self, path):
        """All items of a list endpoint (paged)."""
        out, cont = [], None
        while True:
            r = self.get(path, {"limit": 500, **({"continue": cont} if cont else {})})
            out += r.get("items") or []
            cont = (r.get("metadata") or {}).get("continue")
            if not cont or len(out) >= MAX_ITEMS:
                return out

    def try_items(self, path):
        """items() or [] when the resource type does not exist (404) or is not granted (403) - optional CRDs."""
        try:
            return self.items(path)
        except (PermissionError, RuntimeError) as e:
            if "HTTP 404" in str(e) or "HTTP 403" in str(e):
                return []
            raise

    def version(self):
        return self.get("/version")

    def can_i(self, verb, resource, group="", namespace="", subresource=""):
        """SelfSubjectAccessReview is a create, which the read-only account may do for itself (system:basic-user)."""
        body = json.dumps({"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectAccessReview",
                           "spec": {"resourceAttributes": {"verb": verb, "resource": resource, "group": group,
                                                           "namespace": namespace, "subresource": subresource}}}).encode()
        for u in ([self.used] if self.used else []) + self.urls:
            req = urllib.request.Request(u + "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", data=body, method="POST",
                                         headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, context=self.ctx, timeout=self.timeout) as r:  # noqa: S310
                    return bool((json.load(r).get("status") or {}).get("allowed"))
            except (urllib.error.URLError, OSError):
                continue
        return None


def check(cfg):
    """Integration test: version, identity checks (must be read-only)."""
    c = Client(cfg)
    v = c.version()
    nodes = len(c.items("/api/v1/nodes"))
    risky = {f"{verb} {res}{'/' + sub if sub else ''}": c.can_i(verb, res, subresource=sub)
             for verb, res, sub in (("list", "secrets", ""), ("create", "pods", ""), ("create", "pods", "exec"),
                                    ("get", "nodes", "proxy"), ("delete", "pods", ""), ("update", "deployments", ""))}
    return {"url": c.used, "version": v.get("gitVersion"), "nodes": nodes, "read_only": not any(risky.values()),
            "too_much": [k for k, x in risky.items() if x]}


if __name__ == "__main__":
    print(json.dumps(check(INTEG.kubernetes()), indent=1))
