"""Device class definitions and per-class alarm switches (policy.class_defs, Settings > Network policy).

class_defs = [{"name": "iot", "like": "iot", "off": ["dns-volume", ...]}, ...]
  name  a device class used by policy.device_classes (MAC/IP -> class). Users can add, rename and remove classes.
  like  which built-in class's rules it follows ("behaves like"): protected-zone and admin-port segmentation rules
        (iot, camera), IoT executable / new TLS client rules (iot, camera, media, game) and risk impact by class.
        A built-in class behaves like itself; a user-added class picks one.
  off   alarm kinds (ALARMS ids) that devices of this class never raise.
The fixed row "unclassified" holds the switches for devices with no class.

Compatibility: until class_defs is saved, the defaults are built from the older policy keys new_domain_classes /
new_tls_classes (default ["iot"]), so behaviour is unchanged. The first class-definition edit stores class_defs and
drops those keys (migrate(); see server POST /api/config/classes).

alarm_enabled(pol, cls, kind) / device_alarm(pol, kind, ip, mac) is the one check every raiser uses
(analyze.py findings, watch.py live alerts, hosts.py endpoint findings).
"""
import re

BUILTIN = ("iot", "camera", "media", "game", "personal", "work", "server", "k8s", "infra")
UNCLASSIFIED = "unclassified"
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")

# (id, label, group). Ids are the finding kinds of analyze.py; live alerts (watch.py) reuse the id of the same
# baseline finding where there is one; endpoint findings (hosts.py) are "host-<kind>".
ALARMS = [
    # threat intel
    ("ti-ip-out", "Threat-intel IP contacted (serious list)", "Threat intel"),
    ("ti-ip-out-reputation", "Threat-intel IP contacted (reputation list)", "Threat intel"),
    ("ti-ip-in", "Probed by threat-intel listed attackers", "Threat intel"),
    ("ti-domain", "Threat-intel domain looked up", "Threat intel"),
    ("newly-registered-domain", "Newly registered domain", "Threat intel"),
    ("malware-hash", "Malware download (MHR hash)", "Threat intel"),
    ("malicious-ja3", "TLS fingerprint on a malware JA3 list", "Threat intel"),
    ("ids", "IDS alert (live)", "Threat intel"),
    ("new-signature", "New IDS signature", "Threat intel"),
    ("signature-spike", "IDS signature spike", "Threat intel"),
    # beaconing
    ("beacon-new", "New beaconing", "Beaconing"),
    ("beacon-suspicious", "Suspicious beaconing", "Beaconing"),
    ("beacon-unlabelled", "Unlabelled beaconing", "Beaconing"),
    # new destinations (learned allowlists)
    ("iot-new-domain", "New domain (outside learned list)", "New destinations"),
    ("iot-new-network", "New network (ASN) with data sent", "New destinations"),
    ("iot-raw-ip", "IP with no ASN/geo", "New destinations"),
    ("new-tls-server", "New TLS server name (certificate)", "New destinations"),
    ("new-asn", "New ASN", "New destinations"),
    ("new-country", "New country", "New destinations"),
    ("new-port", "New destination port", "New destinations"),
    ("new-service", "New service", "New destinations"),
    ("new-internal-peer", "New internal peer", "New destinations"),
    # traffic
    ("upload-spike", "Upload spike", "Traffic"),
    ("volume-spike", "Volume spike", "Traffic"),
    ("port-spike", "Port spike", "Traffic"),
    ("fan-out", "Fan-out (many peers)", "Traffic"),
    ("failed-conns", "Failed connections", "Traffic"),
    ("odd-hours", "Activity at odd hours", "Traffic"),
    ("service-mix", "Service mix changed", "Traffic"),
    ("silent", "Device went silent", "Traffic"),
    # lateral / exposure
    ("segmentation", "Segmentation violation", "Lateral & exposure"),
    ("internal-scan", "Internal scan", "Lateral & exposure"),
    ("admin-access", "Admin protocol access (live)", "Lateral & exposure"),
    ("inbound-exposure", "Internet-facing service", "Lateral & exposure"),
    ("inbound-port", "New Internet-facing port (live)", "Lateral & exposure"),
    ("new-listening-port", "New listening port", "Lateral & exposure"),
    # devices
    ("new-device", "New device", "Devices"),
    ("new-device-dhcp", "New device joined (DHCP)", "Devices"),
    # DNS
    ("dns-tunnel", "DNS tunnel", "DNS"),
    ("dns-tunnel-watch", "DNS tunnel (watch)", "DNS"),
    ("dns-doh", "DNS over HTTPS", "DNS"),
    ("dns-dot", "DNS over TLS", "DNS"),
    ("dns-new-resolver", "New DNS resolver", "DNS"),
    ("dns-volume", "DNS volume", "DNS"),
    ("dns-unique-names", "Many unique DNS names", "DNS"),
    ("dns-long-names", "Long DNS names", "DNS"),
    ("dns-subdomain-explosion", "Subdomain explosion", "DNS"),
    ("dns-new-heavy-domain", "New heavy domain", "DNS"),
    ("dns-new-tld", "New TLD", "DNS"),
    ("dns-new-qtype", "New query type", "DNS"),
    ("dns-qtype-mix", "Query type mix changed", "DNS"),
    ("nxdomain-spike", "NXDOMAIN spike", "DNS"),
    # TLS & software
    ("new-tls-client", "New TLS client fingerprint (JA4)", "TLS & software"),
    ("legacy-tls", "Legacy TLS", "TLS & software"),
    ("expired-cert", "Expired certificate", "TLS & software"),
    ("iot-executable", "Executable downloaded by a device", "TLS & software"),
    ("outdated-software", "Outdated software", "TLS & software"),
    ("new-software", "New software", "TLS & software"),
    # endpoint agents (hosts.py; the host is matched to a device by its learned host name)
    ("host-defend", "Elastic Defend alert", "Endpoint"),
    ("host-login-src", "Login from unexpected source", "Endpoint"),
    ("host-login-new", "First-seen login", "Endpoint"),
    ("host-authfail", "Authentication failures", "Endpoint"),
    ("host-acct", "Account change", "Endpoint"),
    ("host-sudo-err", "sudo refused", "Endpoint"),
    ("host-sudo-susp", "Suspicious sudo", "Endpoint"),
    ("host-proc", "Suspicious process", "Endpoint"),
    ("host-exec-new", "New executable", "Endpoint"),
    ("host-exec-sha", "Executable hash changed", "Endpoint"),
    ("host-exec-mhr", "Executable in MHR", "Endpoint"),
    ("host-file", "Sensitive file change", "Endpoint"),
    ("host-syslog", "Syslog finding", "Endpoint"),
    ("host-agent-off", "Agent not checking in", "Endpoint"),
    ("host-agent-deg", "Agent degraded", "Endpoint"),
    ("host-defend-pol", "Defend not protecting", "Endpoint"),
    ("host-silent", "Host stopped sending syslog", "Endpoint"),
]
ALARM_IDS = frozenset(a[0] for a in ALARMS)
# the switches that replaced policy.new_domain_classes / new_tls_classes (default: on for iot only)
LEGACY = {"new_domain_classes": ("iot-new-domain", "iot-new-network", "iot-raw-ip"), "new_tls_classes": ("new-tls-server",)}
LEGACY_DEFAULT = ("iot",)
NEW_DEST_KINDS = ("iot-new-domain", "iot-new-network", "iot-raw-ip", "new-tls-server")


def _legacy(pol, key):
    v = (pol or {}).get(key)
    if not isinstance(v, list) or any(not isinstance(x, str) for x in v):
        return set(LEGACY_DEFAULT)
    return {x.strip() for x in v if x.strip()}


def _default_off(pol, like):
    off = []
    for key, kinds in LEGACY.items():
        s = _legacy(pol, key)
        if "*" not in s and like not in s:
            off += kinds
    return off


def default_defs(pol=None):
    """The definitions before any edit: the built-in classes plus unclassified, with today's switches."""
    return [{"name": n, "like": n, "off": _default_off(pol, n)} for n in (*BUILTIN, UNCLASSIFIED)]


def valid_defs(v):
    """Error text for a class_defs value, or None."""
    if not isinstance(v, list):
        return "class_defs must be a list of {name, like, off}"
    seen = set()
    for d in v:
        if not isinstance(d, dict) or not isinstance(d.get("name"), str):
            return "every class_defs entry needs a name"
        n, lk, off = d["name"], d.get("like"), d.get("off", [])
        if not NAME_RE.match(n):
            return f"class name '{n}' must be 1-32 lower-case letters, digits, - or _"
        if n in seen:
            return f"class '{n}' is defined twice"
        seen.add(n)
        if n == UNCLASSIFIED and lk not in (None, UNCLASSIFIED):
            return "unclassified cannot behave like another class"
        if n != UNCLASSIFIED and lk not in BUILTIN:
            return f"class '{n}' must behave like one of {', '.join(BUILTIN)}"
        if n in BUILTIN and lk != n:
            return f"built-in class '{n}' behaves like itself"
        if not isinstance(off, list) or any(k not in ALARM_IDS for k in off):
            return f"class '{n}': off must be a list of alarm kinds"
    return None


def defs(pol):
    """class_defs as stored (unclassified row added when missing), else default_defs from the legacy keys."""
    v = (pol or {}).get("class_defs")
    if v is None or valid_defs(v):
        return default_defs(pol)
    out = [{"name": d["name"], "like": d.get("like") or d["name"], "off": list(d.get("off") or [])} for d in v]
    if not any(d["name"] == UNCLASSIFIED for d in out):
        out.append({"name": UNCLASSIFIED, "like": UNCLASSIFIED, "off": _default_off(pol, UNCLASSIFIED)})
    return out


def names(pol):
    """Classes a device can be given (everything except unclassified)."""
    return [d["name"] for d in defs(pol) if d["name"] != UNCLASSIFIED]


def _index(pol):
    return {d["name"]: d for d in defs(pol)}


def like(pol, cls):
    """The built-in class whose rules `cls` follows ('' / None -> unclassified; an unknown name -> itself)."""
    cls = cls or UNCLASSIFIED
    d = _index(pol).get(cls)
    return d["like"] if d else cls


def class_of(pol, ip=None, mac=None):
    dc = (pol or {}).get("device_classes") or {}
    m = str(mac or "")
    return dc.get(m) or dc.get(m.lower()) or (dc.get(ip) if ip else None) or UNCLASSIFIED


def alarm_enabled(pol, cls, kind):
    """False when devices of class `cls` must never raise alarm `kind` (an undefined class uses unclassified)."""
    idx = _index(pol)
    d = idx.get(cls or UNCLASSIFIED) or idx.get(UNCLASSIFIED)
    return not d or kind not in d["off"]


def device_alarm(pol, kind, ip=None, mac=None):
    return alarm_enabled(pol, class_of(pol, ip, mac), kind)


def host_class(pol, host, registry):
    """Class of an endpoint-agent host: the device whose learned host name (registry hostname / name) matches."""
    h = str(host or "").lower().split(".")[0]
    if not h:
        return UNCLASSIFIED
    for k, d in (registry or {}).items():
        if not isinstance(d, dict):
            continue
        for n in (d.get("hostname"), d.get("name")):
            if n and str(n).lower().split(".")[0] == h:
                for ip in [None, *(d.get("ips") or [])]:
                    c = class_of(pol, ip, d.get("mac") or k)
                    if c != UNCLASSIFIED:
                        return c
    return UNCLASSIFIED


def in_use(pol, name):
    dc = (pol or {}).get("device_classes") or {}
    return sorted(k for k, v in dc.items() if not str(k).startswith("_") and v == name)


# ---- edits (return a new policy; raise ValueError with a user-facing text) ----
def _done(pol, ds):
    out = dict(pol)
    out["class_defs"] = ds
    for k in LEGACY:  # migrated: the switches now hold these
        out.pop(k, None)
        out.pop("_doc_" + k, None)
    return out


def add(pol, name, like_):
    name = str(name or "").strip().lower()
    ds = defs(pol)
    if not NAME_RE.match(name) or name == UNCLASSIFIED:
        raise ValueError("a class name is 1-32 lower-case letters, digits, - or _ (not 'unclassified')")
    if any(d["name"] == name for d in ds):
        raise ValueError(f"class '{name}' already exists")
    if like_ not in BUILTIN:
        raise ValueError(f"behaves like must be one of {', '.join(BUILTIN)}")
    if name in BUILTIN and like_ != name:
        raise ValueError(f"built-in class '{name}' behaves like itself")
    base = next((d for d in ds if d["name"] == like_), None)
    off = list(base["off"]) if base else _default_off(pol, like_)
    ds.insert(len(ds) - 1 if ds[-1]["name"] == UNCLASSIFIED else len(ds), {"name": name, "like": like_, "off": off})
    return _done(pol, ds)


def rename(pol, old, new):
    new = str(new or "").strip().lower()
    ds = defs(pol)
    if old == UNCLASSIFIED or not any(d["name"] == old for d in ds):
        raise ValueError(f"no class '{old}' to rename")
    if not NAME_RE.match(new) or new == UNCLASSIFIED:
        raise ValueError("a class name is 1-32 lower-case letters, digits, - or _ (not 'unclassified')")
    if new != old and any(d["name"] == new for d in ds):
        raise ValueError(f"class '{new}' already exists")
    for d in ds:
        if d["name"] == old:
            d["name"] = new  # 'like' stays: a renamed built-in keeps its rules
            if new in BUILTIN and d["like"] != new:
                raise ValueError(f"'{new}' is a built-in class name: only a class that behaves like {new} can take it")
    out = _done(pol, ds)
    dc = dict(out.get("device_classes") or {})
    out["device_classes"] = {k: (new if v == old and not str(k).startswith("_") else v) for k, v in dc.items()}
    out["allow"] = [{**a, **{s: new for s in ("src", "dst") if a.get(s) == old}} if isinstance(a, dict) else a
                    for a in out.get("allow") or []]
    return _rescope(out, old, new)


SCOPED = ("upload_spike", "volume_spike", "scan_thresholds", "beacon")  # threshold sections with a device-class scope (extras.SCOPED)


def _rescope(pol, old, new, removed=False):
    """Follow a class rename or removal in the threshold sections' classes / by_class. On removal the class filter
    follows the devices to the class they moved to (never turning a narrowed rule into 'every device'); the removed
    class's overrides go away unless the target class has none."""
    for sname in SCOPED:
        sec = pol.get(sname)
        if not isinstance(sec, dict):
            continue
        sec = dict(sec)
        if isinstance(sec.get("classes"), list) and old in sec["classes"]:
            sec["classes"] = list(dict.fromkeys(new if c == old else c for c in sec["classes"]))
        bc = sec.get("by_class")
        if isinstance(bc, dict) and old in bc:
            if removed and new in bc:
                sec["by_class"] = {c: v for c, v in bc.items() if c != old}
            else:
                sec["by_class"] = {(new if c == old else c): v for c, v in bc.items()}
        pol[sname] = sec
    return pol


def remove(pol, name, move_to=None):
    """Remove a class. Devices that use it must be moved: move_to = another class, or "" to make them unclassified."""
    ds = defs(pol)
    if name == UNCLASSIFIED or not any(d["name"] == name for d in ds):
        raise ValueError(f"no class '{name}' to remove")
    used = in_use(pol, name)
    if used and move_to is None:
        raise ValueError(f"{len(used)} device(s) use class '{name}': choose a class to move them to (or unclassified)")
    if move_to and (move_to == name or move_to not in [d["name"] for d in ds] or move_to == UNCLASSIFIED):
        raise ValueError(f"cannot move devices to '{move_to}'")
    out = _done(pol, [d for d in ds if d["name"] != name])
    dc = {}
    for k, v in (out.get("device_classes") or {}).items():
        if v == name and not str(k).startswith("_"):
            if move_to:
                dc[k] = move_to
            continue
        dc[k] = v
    out["device_classes"] = dc
    return _rescope(out, name, move_to or UNCLASSIFIED, removed=True)


def update(pol, name, like_=None, off=None):
    """Change a class's behaves-like and/or its switched-off alarm kinds."""
    ds = defs(pol)
    d = next((x for x in ds if x["name"] == name), None)
    if not d:
        raise ValueError(f"no class '{name}'")
    if like_ is not None:
        if name == UNCLASSIFIED or like_ not in BUILTIN:
            raise ValueError(f"behaves like must be one of {', '.join(BUILTIN)}")
        if name in BUILTIN and like_ != name:
            raise ValueError(f"built-in class '{name}' behaves like itself")
        d["like"] = like_
    if off is not None:
        if not isinstance(off, list) or any(k not in ALARM_IDS for k in off):
            raise ValueError("off must be a list of alarm kinds")
        d["off"] = [a[0] for a in ALARMS if a[0] in set(off)]
    return _done(pol, ds)


def catalogue():
    return [{"id": i, "label": lbl, "group": g} for i, lbl, g in ALARMS]
