#!/usr/bin/python3
"""Container image updates and CVEs for the Kubernetes clusters (Devices > Kubernetes > Container images).

For every image running in a cluster (read through the read-only Kubernetes API, kube_map.py):
  1. Update check: list the image's tags in its registry (OCI distribution API, anonymous pull token - public images)
     and pick the newest tag of the same shape (7.261030.1 -> #.#.#, 4.1.2-debian-12-r1 -> #.#.#-debian-#-r#; release
     tags only, no rc/beta/alpha unless the running tag is one) - overall and within the running major version.
     Images pinned by digest only are compared with the digest of their :latest tag.
  2. CVEs: Trivy (container aquasec/trivy, --image-src remote, vulnerability scanner) on the exact running digest and
     on the newest tag. Result per image: CVEs by severity, those FIXED by updating (in the running image, gone in the
     newest), those that remain, and CVEs with a fixed version available in the package (fix by rebuilding the image).
Results are cached per digest (store doc "k8s/images_scan"); a digest is rescanned after RESCAN_H (the Trivy DB
changes daily). Runs from the scheduler once a day (job "k8simages") and on demand (broker /k8s action images_run).

Findings (kube_images.findings -> k8s findings / nightly host findings):
  k8s-imgcve|<repo>  Investigate: a CRITICAL CVE fixed by an available update; Review: HIGH CVEs fixed by an update.
"""
import concurrent.futures as cf
import json, os, re, ssl, subprocess, sys, time, urllib.error, urllib.parse, urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pwd  # noqa: E402
# Fixed values (not environment variables): they end up in a docker command line.
TRIVY_IMAGE = "aquasec/trivy:latest"
TRIVY_CACHE = os.path.join(pwd.getpwuid(os.getuid()).pw_dir, "netmon-trivy-cache")
PLATFORM = ""  # "" = the node architecture reported by Kubernetes
RESCAN_H = 24
MAX_TAG_PAGES = 15
SEV = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
PRE = re.compile(r"(?i)(alpha|beta|rc|dev|nightly|snapshot|preview|canary|test|debug)")
DOC = "k8s/images_scan"


# ---------------------------------------------------------------- image reference parsing
def parse_ref(ref):
    """'quay.io/calico/node:v3.33.0' -> (registry, repo, tag, digest). Docker Hub short names get docker.io/library/."""
    digest = ""
    if "@" in ref:
        ref, digest = ref.split("@", 1)
    tag = ""
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        ref, tag = ref.rsplit(":", 1)
    parts = ref.split("/")
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        reg, repo = parts[0], "/".join(parts[1:])
    else:
        reg, repo = "docker.io", ref
    if reg == "docker.io" and "/" not in repo:
        repo = "library/" + repo
    return reg, repo, tag, digest


def shape(tag):
    return re.sub(r"\d+", "#", tag)


def nums(tag):
    return tuple(int(x) for x in re.findall(r"\d+", tag))


def newer_tags(cur, tags):
    """(newest overall, newest within the running major) of the tags shaped like `cur`, or (None, None)."""
    if not cur or not re.search(r"\d", cur) or cur == "latest":
        return None, None
    sh, n, pre = shape(cur), nums(cur), bool(PRE.search(cur))
    cands = [t for t in tags if shape(t) == sh and (pre or not PRE.search(t)) and nums(t) > n]
    if not cands:
        return None, None
    best = max(cands, key=nums)
    same = [t for t in cands if nums(t)[:1] == n[:1]]
    return best, (max(same, key=nums) if same else None)


# ---------------------------------------------------------------- registry API (anonymous)
_ctx = ssl.create_default_context()
_tokens = {}


def _reg_host(reg):
    return "registry-1.docker.io" if reg == "docker.io" else reg


def _req(url, headers=None, method="GET"):
    req = urllib.request.Request(url, headers=headers or {}, method=method)
    return urllib.request.urlopen(req, context=_ctx, timeout=30)  # noqa: S310 - https registry URLs built here


def _auth(reg, repo, www):
    m = dict(re.findall(r'(\w+)="([^"]*)"', www or ""))
    if not m.get("realm", "").startswith("https://"):
        raise RuntimeError(f"registry {reg}: unsupported auth {www[:80]}")
    q = {"service": m.get("service", ""), "scope": m.get("scope") or f"repository:{repo}:pull"}
    with _req(m["realm"] + "?" + urllib.parse.urlencode({k: v for k, v in q.items() if v})) as r:
        j = json.load(r)
    return j.get("token") or j.get("access_token")


def _get(reg, repo, path, accept=None, method="GET"):
    url = f"https://{_reg_host(reg)}/v2/{repo}/{path}"
    hdr = {"Accept": accept} if accept else {}
    tok = _tokens.get((reg, repo))
    if tok:
        hdr["Authorization"] = "Bearer " + tok
    try:
        return _req(url, hdr, method)
    except urllib.error.HTTPError as e:
        if e.code != 401:
            raise
        tok = _tokens[(reg, repo)] = _auth(reg, repo, e.headers.get("WWW-Authenticate"))
        hdr["Authorization"] = "Bearer " + tok
        return _req(url, hdr, method)


def list_tags(reg, repo):
    tags, path = [], "tags/list?n=1000"
    for _ in range(MAX_TAG_PAGES):
        with _get(reg, repo, path) as r:
            tags += json.load(r).get("tags") or []
            link = r.headers.get("Link", "")
        m = re.search(r"<([^>]+)>", link)
        if not m:
            break
        nxt = m.group(1)
        path = nxt.split(f"/v2/{repo}/", 1)[1] if f"/v2/{repo}/" in nxt else None
        if not path:
            break
    return tags


def tag_digest(reg, repo, tag):
    acc = ",".join(["application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json",
                    "application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"])
    with _get(reg, repo, f"manifests/{tag}", accept=acc, method="HEAD") as r:
        return r.headers.get("Docker-Content-Digest", "")


# ---------------------------------------------------------------- Trivy
def update_db():
    """Download / refresh Trivy's vulnerability databases once, before the parallel scans (which skip the update)."""
    os.makedirs(TRIVY_CACHE, exist_ok=True)
    for flag in ("--download-db-only", "--download-java-db-only"):
        p = subprocess.run(["docker", "run", "--rm", "-v", f"{TRIVY_CACHE}:/root/.cache/trivy", TRIVY_IMAGE, "image", "--quiet", flag],  # noqa: S603,S607 - fixed argv
                           capture_output=True, text=True, timeout=1800)
        if p.returncode != 0:
            raise RuntimeError("trivy database update failed: " + (p.stderr.strip().splitlines() or ["?"])[-1][:300])


REF_RE = re.compile(r"^[a-z0-9][a-z0-9._:/@-]{0,250}$", re.I)   # registry/repo[:tag][@sha256:...]; never starts with "-"
PLAT_RE = re.compile(r"^(linux/[a-z0-9]{1,16}(/[a-z0-9]{1,8})?)?$")
TRIVY_IMAGE_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]*(:[A-Za-z0-9._-]+)?(@sha256:[a-f0-9]{64})?$")


def trivy(ref, platform):
    """{severity counts, vulns[{id, pkg, installed, fixed, severity, title}]} for one image reference.
    ref comes from a cluster (a pod's image) - validated so it can never be read as a docker / trivy option."""
    if not REF_RE.match(ref or "") or not PLAT_RE.match(platform or "") or not TRIVY_IMAGE_RE.match(TRIVY_IMAGE) \
            or not os.path.isabs(TRIVY_CACHE) or ":" in TRIVY_CACHE:
        raise ValueError(f"refusing to scan unexpected image reference {str(ref)[:80]!r}")
    os.makedirs(TRIVY_CACHE, exist_ok=True)
    cmd = ["docker", "run", "--rm", "-v", f"{TRIVY_CACHE}:/root/.cache/trivy", TRIVY_IMAGE, "image", "--quiet", "--scanners", "vuln",
           "--image-src", "remote", "--format", "json", "--timeout", "15m",
           # parallel scans: the vulnerability databases are refreshed once beforehand (update_db) and only read here;
           # the per-scan layer cache stays in memory (a shared on-disk one is locked by the first scan -> "cache may be in use")
           "--skip-db-update", "--skip-java-db-update", "--cache-backend", "memory"] + (["--platform", platform] if platform else []) + ["--", ref]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=1200)  # noqa: S603 - fixed argv, ref from the cluster
    if p.returncode != 0:
        raise RuntimeError((p.stderr.strip().splitlines() or ["trivy failed"])[-1][:300])
    d = json.loads(p.stdout or "{}")
    vulns = {}
    for res in d.get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            k = (v["VulnerabilityID"], v.get("PkgName", ""))
            vulns[k] = {"id": v["VulnerabilityID"], "pkg": v.get("PkgName", ""), "installed": v.get("InstalledVersion", ""),
                        "fixed": v.get("FixedVersion", ""), "severity": v.get("Severity", "UNKNOWN"), "title": (v.get("Title") or "")[:160],
                        "target": res.get("Target", "")[:80]}
    vl = sorted(vulns.values(), key=lambda v: (SEV.index(v["severity"]) if v["severity"] in SEV else 9, v["id"]))
    return {"counts": {s: sum(1 for v in vl if v["severity"] == s) for s in SEV}, "vulns": vl,
            "os": ((d.get("Metadata") or {}).get("OS") or {}).get("Name", "") and f"{d['Metadata']['OS'].get('Family', '')} {d['Metadata']['OS'].get('Name', '')}",
            "scanned": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


# ---------------------------------------------------------------- one image
def check_image(image, image_id, platform, cache):
    reg, repo, tag, dig = parse_ref(image)
    run_dig = dig or (image_id.split("@", 1)[1] if "@" in (image_id or "") else "")
    out = {"image": image, "registry": reg, "repo": repo, "tag": tag, "digest": run_dig, "update": None, "update_major": None, "errors": []}
    tags = []
    try:
        tags = list_tags(reg, repo)
        out["update"], out["update_major"] = newer_tags(tag, tags)
        if not tag or tag == "latest":  # digest-pinned or :latest: is the latest tag a different build?
            ld = tag_digest(reg, repo, "latest") if "latest" in tags else ""
            if ld and run_dig and ld != run_dig:
                out["latest_digest"], out["update"] = ld, "latest"
    except Exception as e:  # noqa: BLE001 - private registry, rate limit: CVEs still scanned
        out["errors"].append(f"tags: {type(e).__name__}: {str(e)[:160]}")
    ref = f"{reg}/{repo}@{run_dig}" if run_dig else image
    key = ref + "|" + platform
    hit = cache.get(key)
    if hit and time.time() - time.mktime(time.strptime(hit["scanned"][:19], "%Y-%m-%dT%H:%M:%S")) + time.timezone < RESCAN_H * 3600:
        out["current"] = hit
    else:
        try:
            out["current"] = cache[key] = trivy(ref, platform)
        except Exception as e:  # noqa: BLE001
            out["errors"].append(f"scan: {str(e)[:200]}")
    if out["update"] and out.get("current"):
        nref = f"{reg}/{repo}:{out['update']}"
        nkey = nref + "|" + platform
        hit = cache.get(nkey)
        try:
            new = hit if hit and time.time() - time.mktime(time.strptime(hit["scanned"][:19], "%Y-%m-%dT%H:%M:%S")) + time.timezone < RESCAN_H * 3600 \
                else trivy(nref, platform)
            cache[nkey] = new
            have = {v["id"] for v in new["vulns"]}
            fixed = [v for v in out["current"]["vulns"] if v["id"] not in have]
            out["newest"] = {"tag": out["update"], "counts": new["counts"]}
            out["fixed_by_update"] = {"counts": {s: sum(1 for v in fixed if v["severity"] == s) for s in SEV}, "ids": [v["id"] for v in fixed][:400]}
        except Exception as e:  # noqa: BLE001
            out["errors"].append(f"scan {out['update']}: {str(e)[:200]}")
    if out.get("current"):
        out["fixable_in_place"] = sum(1 for v in out["current"]["vulns"] if v["fixed"] and v["severity"] in ("CRITICAL", "HIGH"))
    return out


def scan(clusters=None, workers=3):
    """clusters: [(name, kube_api.Client)]; default: every configured cluster. Saves and returns the doc."""
    import store
    import kube_api
    import kube_map
    clusters = clusters if clusters is not None else kube_api.clusters()
    prev = store.doc_get(DOC, {}) or {}
    cache = prev.get("cache") or {}
    t0 = time.time()
    images = {}  # (image, image_id, platform) -> {clusters, namespaces, pods}
    errors = {}
    for name, cli in clusters:
        try:
            m = kube_map.build(cli)
        except Exception as e:  # noqa: BLE001
            errors[name] = f"{type(e).__name__}: {str(e)[:200]}"
            continue
        arch = {n["name"]: n.get("arch", "") for n in m["nodes"]}
        for p in m["pods"]:
            plat = PLATFORM or (f"linux/{arch.get(p['node'])}" if arch.get(p["node"]) else "")
            for c in p["containers"]:
                k = (c["image"], c.get("image_id", ""), plat)
                e = images.setdefault(k, {"clusters": set(), "namespaces": set(), "pods": set()})
                e["clusters"].add(name)
                e["namespaces"].add(f"{name}/{p['ns']}")
                e["pods"].add(f"{p['ns']}/{p['name']}")
    # the same image tag on several pods/digests: check each running digest once
    uniq = {}
    for (img, iid, plat), use in images.items():
        dig = iid.split("@", 1)[1] if "@" in iid else ""
        u = uniq.setdefault((img, dig, plat), {"image_id": iid, "clusters": set(), "namespaces": set(), "pods": set()})
        for k in ("clusters", "namespaces", "pods"):
            u[k] |= use[k]
    update_db()
    res = []
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(check_image, img, u["image_id"], plat, cache): (img, plat, u) for (img, dig, plat), u in uniq.items()}
        for f in cf.as_completed(futs):
            img, plat, u = futs[f]
            try:
                r = f.result()
            except Exception as e:  # noqa: BLE001
                r = {"image": img, "errors": [f"{type(e).__name__}: {str(e)[:200]}"]}
            r.update(platform=plat, clusters=sorted(u["clusters"]), namespaces=sorted(u["namespaces"]), pods=len(u["pods"]))
            res.append(r)
    keep = {r.get("digest") for r in res}  # prune the cache to what is still running (+ newest tags)
    cache = {k: v for k, v in cache.items() if k.split("@")[-1].split("|")[0] in keep or "@" not in k}
    if len(cache) > 400:
        cache = dict(sorted(cache.items(), key=lambda kv: kv[1].get("scanned", ""))[-400:])
    doc = {"generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "seconds": round(time.time() - t0),
           "images": sorted(res, key=lambda r: r["image"]), "errors": errors, "cache": cache}
    store.doc_put(DOC, doc)
    return doc


def latest(with_vulns=False):
    import store
    d = store.doc_get(DOC, {}) or {}
    d.pop("cache", None)
    if not with_vulns:
        for r in d.get("images") or []:
            if r.get("current"):
                r["current"] = {k: v for k, v in r["current"].items() if k != "vulns"}
    return d


def image_detail(image, digest=""):
    """One image with its full CVE list (the details panel)."""
    import store
    d = store.doc_get(DOC, {}) or {}
    for r in d.get("images") or []:
        if r["image"] == image and (not digest or r.get("digest") == digest):
            fixed = set((r.get("fixed_by_update") or {}).get("ids") or [])
            for v in (r.get("current") or {}).get("vulns") or []:
                v["fixed_by_update"] = v["id"] in fixed
            return r
    raise ValueError("image not in the last scan")


def findings(d=None):
    d = d if d is not None else latest()
    out = []
    for r in d.get("images") or []:
        fx = (r.get("fixed_by_update") or {}).get("counts") or {}
        cur = (r.get("current") or {}).get("counts") or {}
        where = ", ".join(r.get("namespaces") or [])[:120]
        if fx.get("CRITICAL"):
            out.append((f"k8s-imgcve|{r['repo']}", "Investigate", f"Container image {r['image']} ({where}) has {fx['CRITICAL']} critical and {fx.get('HIGH', 0)} high "
                                                                   f"CVE(s) fixed in {r['update']} - update it ({cur.get('CRITICAL', 0)} critical / {cur.get('HIGH', 0)} high in the running image)"))
        elif fx.get("HIGH"):
            out.append((f"k8s-imgcve|{r['repo']}", "Review", f"Container image {r['image']} ({where}) has {fx['HIGH']} high CVE(s) fixed in {r['update']} - update it"))
    return out


if __name__ == "__main__":
    d = scan()
    print(json.dumps({"seconds": d["seconds"], "errors": d["errors"], "images": [
        (r["image"][-60:], r.get("update"), (r.get("current") or {}).get("counts", {}).get("CRITICAL"), (r.get("current") or {}).get("counts", {}).get("HIGH"),
         (r.get("fixed_by_update") or {}).get("counts", {}).get("HIGH"), r.get("errors")) for r in d["images"]]}, indent=0, default=str))
