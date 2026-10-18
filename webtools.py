"""Web search + page fetch for the AI research job and the dashboard chat (stdlib only).

search(query, n)  -> [{title, url, snippet}]  via the backend set in Configuration > Integrations > Web search
                     (integrations.web()): DuckDuckGo (no key), Firecrawl, Brave or Tavily.
fetch(url, chars) -> {url, title, text}       public http(s) pages only: every redirect hop is resolved and refused if it
                     points at a loopback / private / link-local / reserved address (the model must not reach the LAN or the
                     local AI / broker endpoints through this). With Firecrawl configured, pages are fetched through it.
Results are untrusted text; callers wrap them as data in the prompt.
"""
import html, ipaddress, json, re, socket, urllib.error, urllib.parse, urllib.request

UA = "Mozilla/5.0 (X11; Linux x86_64) netmon-research/1.0"
MAX_BYTES = 3_000_000


def _cfg():
    import integrations
    return integrations.web()


def _post(url, body, headers, timeout=30):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json", **headers})
    return json.load(urllib.request.urlopen(req, timeout=timeout))  # noqa: S310 - fixed https API URLs


def _get(url, headers, timeout=30):
    return json.load(urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=timeout))  # noqa: S310


def _txt(s):
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", s or ""))).strip()


def search(query, n=6, cfg=None):
    cfg = cfg or _cfg()
    q, n = str(query)[:300], max(1, min(int(n or 6), 10))
    p, k = cfg.get("provider"), cfg.get("api_key") or ""
    if p == "firecrawl":
        d = _post("https://api.firecrawl.dev/v1/search", {"query": q, "limit": n}, {"Authorization": f"Bearer {k}"})
        rows = d.get("data") or []
        rows = rows.get("web", []) if isinstance(rows, dict) else rows
        return [{"title": r.get("title") or "", "url": r.get("url") or "", "snippet": (r.get("description") or "")[:400]} for r in rows][:n]
    if p == "brave":
        d = _get("https://api.search.brave.com/res/v1/web/search?" + urllib.parse.urlencode({"q": q, "count": n}),
                 {"X-Subscription-Token": k, "Accept": "application/json"})
        return [{"title": _txt(r.get("title")), "url": r.get("url") or "", "snippet": _txt(r.get("description"))[:400]}
                for r in (d.get("web") or {}).get("results") or []][:n]
    if p == "tavily":
        d = _post("https://api.tavily.com/search", {"query": q, "max_results": n}, {"Authorization": f"Bearer {k}"})
        return [{"title": r.get("title") or "", "url": r.get("url") or "", "snippet": (r.get("content") or "")[:400]} for r in d.get("results") or []][:n]
    # DuckDuckGo HTML endpoint (no key)
    req = urllib.request.Request("https://html.duckduckgo.com/html/", data=urllib.parse.urlencode({"q": q}).encode(), headers={"User-Agent": UA})
    page = urllib.request.urlopen(req, timeout=20).read().decode("utf-8", "replace")  # noqa: S310 - fixed https URL
    out = []
    for m in re.finditer(r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>(.*?)(?=<a[^>]+class="result__a"|$)', page, re.S):
        href = html.unescape(m.group(1))
        if "uddg=" in href:
            href = urllib.parse.unquote(urllib.parse.parse_qs(urllib.parse.urlparse(href).query).get("uddg", [""])[0])
        if not href.startswith("http") or "duckduckgo.com/y.js" in href:
            continue
        sn = re.search(r'class="result__snippet"[^>]*>(.*?)</a>', m.group(3), re.S)
        out.append({"title": _txt(m.group(2)), "url": href, "snippet": _txt(sn.group(1) if sn else "")[:400]})
        if len(out) >= n:
            break
    return out


def _public(url):
    u = urllib.parse.urlparse(url)
    if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password:
        raise ValueError("only public http(s) URLs")
    for fam, _, _, _, sa in socket.getaddrinfo(u.hostname, u.port or (443 if u.scheme == "https" else 80), proto=socket.IPPROTO_TCP):
        ip = ipaddress.ip_address(sa[0])
        if not ip.is_global or ip.is_multicast:
            raise ValueError(f"{u.hostname} resolves to a non-public address - not fetched")
    return url


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _html_text(raw):
    title = _txt((re.search(r"<title[^>]*>(.*?)</title>", raw, re.S | re.I) or [None, ""])[1])[:200]
    raw = re.sub(r"(?is)<(script|style|noscript|svg|nav|footer|header|form)[^>]*>.*?</\1>", " ", raw)
    raw = re.sub(r"(?i)<(br|/p|/div|/li|/h[1-6]|/tr)[^>]*>", "\n", raw)
    text = html.unescape(re.sub(r"<[^>]+>", " ", raw))
    text = re.sub(r"[ \t\r\f\v]+", " ", text)
    return title, re.sub(r"\n\s*\n+", "\n\n", text).strip()


def fetch(url, chars=8000, cfg=None):
    cfg = cfg or _cfg()
    chars = max(500, min(int(chars or 8000), 20000))
    _public(url)
    if cfg.get("provider") == "firecrawl" and cfg.get("api_key"):
        d = _post("https://api.firecrawl.dev/v1/scrape", {"url": url, "formats": ["markdown"], "onlyMainContent": True},
                  {"Authorization": f"Bearer {cfg['api_key']}"}, timeout=60)
        dd = d.get("data") or {}
        return {"url": url, "title": (dd.get("metadata") or {}).get("title") or "", "text": (dd.get("markdown") or "")[:chars]}
    op = urllib.request.build_opener(_NoRedirect)
    cur = url
    for _ in range(5):
        _public(cur)
        try:
            r = op.open(urllib.request.Request(cur, headers={"User-Agent": UA, "Accept": "text/html,text/plain,application/json"}), timeout=25)
        except urllib.error.HTTPError as e:
            if e.code in (301, 302, 303, 307, 308) and e.headers.get("Location"):
                cur = urllib.parse.urljoin(cur, e.headers["Location"])
                continue
            raise RuntimeError(f"HTTP {e.code} from {urllib.parse.urlparse(cur).hostname}") from None
        ct = r.headers.get("Content-Type", "")
        if not re.search(r"text/|json|xml", ct):
            return {"url": cur, "title": "", "text": f"(not a text page: {ct[:60]})"}
        raw = r.read(MAX_BYTES).decode(r.headers.get_content_charset() or "utf-8", "replace")
        title, text = _html_text(raw) if "html" in ct else ("", raw)
        return {"url": cur, "title": title, "text": text[:chars]}
    raise RuntimeError("too many redirects")
