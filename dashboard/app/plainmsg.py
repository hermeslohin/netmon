"""Plain-language alert lines for the User role (family members): what happened, on which device, in a few words.

Admins and defenders keep the full alert text (signature names, IPs, AI reason). Users get one short sentence such as
"Kitchen tablet: possible phishing or scam website visited - look out." on their phone push and on the Alerts page.
Deterministic (no model call) so it is ready the moment an alarm fires. No IPs, MACs, ports, rule names or hashes.
"""
import re

import store

# (pattern over "key text", plain message) - first match wins; order matters (specific before generic).
_RULES = (
    (r"phish", "possible phishing website visited"),
    (r"malware|trojan|\bcnc\b|command.and.control|ransom|botnet|coinminer|cryptominer|\bmining\b|tifile|threat-intel file|hash hit",
     "possible malware activity"),
    (r"suspicious \.\w+ domain|dns query for \.\w+ tld|newly-registered-domain|ti-domain|tidom|listed domain|threat-intel domain|"
     r"lookalike|look-alike|typosquat", "possible phishing or scam website visited"),
    (r"external ip address lookup|ip check|whatismyip", "an app checked this device's internet address (malware sometimes does this)"),
    (r"scan outbound|outbound scan", "this device is scanning other computers (possible infection)"),
    (r"nxdomain-spike|dns-long|dga|long random", "unusual website lookups (a bad app may be running)"),
    (r"upload-spike", "unusually large upload from this device"),
    (r"volume-spike", "unusually heavy internet use"),
    (r"ti-ip-in|probed|et scan|\bscan\b|brute|failed login|answered .* inbound", "someone on the internet is probing this device"),
    (r"ti-ip|outbound to listed ip|listed ip|threat-intel ip", "this device talked to a known-bad internet address"),
    (r"inport|new internet-facing port|new-listening-port", "this device is now reachable from the internet"),
    (r"newmac|newip|new device", "a new device joined your network"),
    (r"cleartext", "a password or PIN was sent without encryption"),
    (r"exploit|attack|shellcode", "possible attack on this device"),
    (r"login|account change|ssh", "unusual sign-in activity"),
    (r"stopped sending|not checking in|not reaching", "a monitoring problem (the security team will look)"),
)
_GENERIC = "suspicious activity"
_CALL = {"investigate": "Stop and check - tap for what to do.", "urgent": "Look out - tap for what to do."}


def kind(alert):
    """The plain message for an alert's category (no device, no punctuation)."""
    s = f"{alert.get('key') or ''} {alert.get('text') or ''}".lower()
    for pat, msg in _RULES:
        if re.search(pat, s):
            return msg
    return _GENERIC


def device_name(alert, reg=None):
    """Friendly name of the first device the alert targets (registry name), else ''. Never an IP or MAC."""
    tg = list(alert.get("targets") or [])
    if not tg:
        return ""
    try:
        reg = reg if reg is not None else store.registry_load()
    except Exception:  # noqa: BLE001 - a name is a nicety
        return ""
    for t in tg:
        for d in reg.values():
            if t in store.device_ids(d):
                n = (d.get("name") or "").strip()
                if n and not re.fullmatch(r"[\d.]+|([0-9a-f]{2}:){5}[0-9a-f]{2}", n, re.I):
                    return n
    for t in tg:  # endpoint host alerts: host:<label>
        if t.startswith("host:"):
            return t[5:]
    return ""


def line(alert, reg=None):
    """One short sentence for a User: '<Device>: <what happened>.' (capitalised)."""
    k = kind(alert)
    d = device_name(alert, reg)
    return f"{d}: {k}." if d else k[0].upper() + k[1:] + "."


def push_payload(rows, reg=None):
    """Web Push payload for a User: plain lines, no signature text."""
    inv = any(r.get("severity") == "investigate" for r in rows)
    call = _CALL["investigate" if inv else "urgent"]
    lines = []
    for r in rows:
        x = line(r, reg)
        if x not in lines:
            lines.append(x)
    if len(rows) == 1:
        r = rows[0]
        return {"title": "Syn: security alert" if inv else "Syn: heads up", "body": f"{lines[0]} {call}",
                "tag": "netmon-" + str(r["id"]), "url": "/#/reports" if r.get("source") == "report" else "/#/alerts",
                "severity": r["severity"]}
    body = "\n".join("• " + x for x in lines[:4]) + (f"\n…and {len(lines) - 4} more" if len(lines) > 4 else "") + "\n" + call
    return {"title": f"Syn: {len(rows)} security alerts", "body": body, "tag": "netmon-batch-" + str(rows[-1]["id"]),
            "url": "/#/alerts", "severity": "investigate" if inv else "urgent"}
