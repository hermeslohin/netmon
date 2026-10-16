#!/usr/bin/python3
"""Pre-push guard: refuse to commit anything that identifies this network.

  repo_guard.py <file>...    exit 1 and list offending lines if any staged file contains
     - an IP inside internal_cidr, the home WAN IP, or any IP that appears anywhere in site.json
     - a MAC address
     - a sensitive term from site.json "sensitive_terms" (host names, account names, domains)
     - a file that must never be committed (site.json, policy/inventory/accepted-findings JSON, data, state)
Values come from site.json (git-ignored), so the guard itself contains nothing sensitive.
"""
import ipaddress, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import site_cfg as SITE  # noqa: E402

FORBIDDEN_FILES = re.compile(r"(^|/)(site\.json|policy\.json|host_policy\.json|known_benign\.json|sec_accepted\.json|"
                             r"\.env|.*\.(db|pem|key|pdf|jsonl))$|^(data|baseline|dashboard/state|dashboard/certs|intel/(?!attack_enterprise))")
IP_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
MAC_RE = re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b")
SKIP_CONTENT = re.compile(r"(^|/)(chart\.umd\.min\.js|attack_enterprise\.json|.*\.png)$")


def _site_values():
    s = json.load(open(os.path.join(HERE, "site.json"))) if os.path.exists(os.path.join(HERE, "site.json")) else {}
    ips = set(IP_RE.findall(json.dumps(s)))
    terms = [t for t in s.get("sensitive_terms", []) if len(t) >= 4]
    for k in ("site_name", "self_host", "gateway_name", "github_user"):
        if isinstance(s.get(k), str) and len(s[k]) >= 4:
            terms.append(s[k])
    terms += [d for d in s.get("own_domains", []) if len(d) >= 4]
    try:
        net = ipaddress.ip_network(s.get("internal_cidr"))
    except Exception:
        net = None
    return ips, sorted(set(terms), key=len, reverse=True), net


def scan(paths):
    ips, terms, net = _site_values()
    # whole-word-ish: a term must not continue into a longer word (a two-word term must not hit a longer phrase)
    term_re = re.compile("|".join(r"(?<![A-Za-z0-9])" + re.escape(t) + (r"(?![A-Za-z0-9])" if t[-1].isalnum() else "") for t in terms), re.I) if terms else None
    bad = []
    for p in paths:
        rel = os.path.relpath(p, HERE) if os.path.isabs(p) else p
        if FORBIDDEN_FILES.search(rel):
            bad.append((rel, 0, "file must never be committed"))
            continue
        if SKIP_CONTENT.search(rel) or not os.path.isfile(p):
            continue
        try:
            lines = open(p, errors="replace").read().splitlines()
        except OSError as e:  # unreadable file: fail closed
            bad.append((rel, 0, f"unreadable ({e.__class__.__name__}) - cannot verify"))
            continue
        for n, line in enumerate(lines, 1):
            why = []
            for ip in IP_RE.findall(line):
                try:
                    a = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                if ip in ips or (net and a in net):
                    why.append(f"site IP {ip}")
            if MAC_RE.search(line):
                why.append("MAC address")
            if term_re:
                m = term_re.search(line)
                if m:
                    why.append(f"site term '{m.group(0)}'")
            if why:
                bad.append((rel, n, ", ".join(why)))
    return bad


if __name__ == "__main__":
    bad = scan(sys.argv[1:])
    for f, n, why in bad[:60]:
        print(f"   {f}:{n}: {why}")
    if len(bad) > 60:
        print(f"   ...and {len(bad) - 60} more")
    sys.exit(1 if bad else 0)
