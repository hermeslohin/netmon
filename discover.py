#!/usr/bin/python3
"""Auto-discover the network model from UniFi: zones (one per routed network), zone roles, device classes.

build()  -> proposal dict (nothing is written):
    zones          {name: cidr}                      one per UniFi network that has a subnet
    zone_roles     {zone: dmz|protected|mgmt|user|iot}
    device_classes {mac: class}                      class = iot camera media game personal work server k8s infra
    site_prefixes  [prefix, ...]                     internal_prefixes needed to cover every subnet
    detail         per-zone / per-device reasons for the preview table
apply(prop, overwrite=False) -> merges the proposal into the policy + site settings documents. Existing entries are
kept unless overwrite=True. Never removes anything.

Sources: UniFi rest/networkconf (networks), stat/sta + rest/user (clients and their fingerprinted device category),
stat/device (UniFi gear = infra) and UniFi's fingerprint database (device-category names).
"""
import ipaddress, os, re, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import unifi  # noqa: E402
import store  # noqa: E402

ROLES = ("dmz", "protected", "mgmt", "user", "iot")

# ---- zone role: from the network's name / UniFi purpose, refined by what lives in it
_NAME_ROLE = [
    (re.compile(r"dmz|untrust|public|exposed|perimeter", re.I), "dmz"),
    (re.compile(r"ipmi|bmc|mgmt|manage|oob|infra", re.I), "mgmt"),
    (re.compile(r"server|kube|k8s|cluster|\bai\b|gpu|lab|datacenter|prod|storage|nas", re.I), "protected"),
    (re.compile(r"iot|camera|cctv|surveil|smart|sensor|guest|visitor|cam\b|media|tv", re.I), "iot"),
]

# ---- device class: UniFi fingerprint category name -> class (first match wins)
_CAT_CLASS = [
    (re.compile(r"camera|video recorder|baby monitor|doorbell", re.I), "camera"),
    (re.compile(r"game|console", re.I), "game"),
    (re.compile(r"\btv\b|set-top|speaker|audio|theater|receiver|streaming|media|picture frame|soundbar|projector", re.I), "media"),
    (re.compile(r"handheld|phone|tablet|wearable|watch|e-?reader|headphone|earphone", re.I), "personal"),
    (re.compile(r"virtual machine|server|hypervisor|nas\b|storage|single.?board|hosting", re.I), "server"),
    (re.compile(r"router|switch|access point|gateway|firewall|bridge|network (device|infrastructure)|^network$", re.I), "infra"),
    (re.compile(r"desktop|laptop|computer|workstation|notebook", re.I), "personal"),
]
_NAME_CLASS = [  # hostname hints beat the category
    (re.compile(r"kube|k8s|talos|k3s|rke|microk8s", re.I), "k8s"),
    (re.compile(r"ipmi|idrac|\bilo\b|bmc|\bpdu\b|\bups\b", re.I), "infra"),
    (re.compile(r"(^|[^a-z])(cam|camera|doorbell|nvr)([^a-z]|$)", re.I), "camera"),
    (re.compile(r"(^|[^a-z])work([^a-z]|$)|corp|office", re.I), "work"),
]
_GEAR = {"ugw": "gateway", "udm": "gateway", "uxg": "gateway", "uap": "access point", "usw": "switch", "uph": "phone",
         "ubb": "bridge", "uci": "bridge", "uck": "controller"}


def _slug(name, vlan):
    s = re.sub(r"[^a-z0-9]+", "-", re.sub(r"[^\x00-\x7f]", "", str(name or "")).lower()).strip("-")
    return s or (f"vlan{vlan}" if vlan else "lan")


def _norm_mac(m):
    return str(m or "").strip().lower().replace("-", ":")


def _fingerprint_names():
    try:
        r = unifi._req(unifi.base() + "/v2/api/fingerprint_devices/0")
        return {int(k): v for k, v in (r.get("dev_type_ids") or {}).items()}
    except Exception:  # noqa: BLE001 - fall back to hostname/vendor hints only
        return {}


def _class_for(cat, name, vendor, zone_role):
    """(class, reason) or (None, reason)."""
    n = name or ""
    for rx, cls in _NAME_CLASS:
        if rx.search(n):
            return cls, f"hostname '{n}'"
    for rx, cls in _CAT_CLASS:
        if cat and rx.search(cat):
            if cls == "personal" and re.search(r"desktop|laptop|computer|notebook|workstation", cat, re.I):
                if zone_role == "protected":
                    return "server", f"{cat} in a protected zone"
                if zone_role == "iot":
                    return "iot", f"{cat} in an IoT zone"
            return cls, f"UniFi category '{cat}'"
    if cat:  # fingerprinted as something else (smart device, appliance, lighting, printer, ...)
        return "iot", f"UniFi category '{cat}'"
    if zone_role == "protected":
        return "server", "unfingerprinted host in a protected zone"
    if zone_role == "iot":
        return "iot", "unfingerprinted host in an IoT zone"
    if zone_role == "mgmt":
        return "infra", "unfingerprinted host in a management zone"
    return None, "no fingerprint"


def _zone_of(ip, nets):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    best = None
    for z, n in nets.items():
        if a in n and (best is None or n.prefixlen > nets[best].prefixlen):
            best = z
    return best


def build(existing_policy=None):
    pol = existing_policy if existing_policy is not None else store.cfg_load("policy")
    have_zones = {str(c): z for z, c in (pol.get("zones") or {}).items()}
    nets_raw = unifi._legacy_raw("rest/networkconf")
    zones, roles, detail_z, purpose = {}, {}, [], {}
    for n in nets_raw:
        if n.get("purpose") not in ("corporate", "guest") or not n.get("ip_subnet") or n.get("enabled") is False:
            continue
        try:
            cidr = str(ipaddress.ip_interface(n["ip_subnet"]).network)
        except ValueError:
            continue
        name = have_zones.get(cidr) or _slug(n.get("name"), n.get("vlan"))
        base, i = name, 2
        while name in zones and zones[name] != cidr:
            name, i = f"{base}-{i}", i + 1
        zones[name] = cidr
        purpose[name] = (n.get("purpose"), n.get("name") or "")
        role = None
        if n.get("purpose") == "guest":
            role = "iot"
        else:
            for rx, rr in _NAME_ROLE:
                if rx.search(f"{n.get('name') or ''} {name}"):
                    role = rr
                    break
        roles[name] = role  # None -> decided below from the members
    nets = {z: ipaddress.ip_network(c) for z, c in zones.items()}

    # ---- clients: merge stat/sta (online now) with rest/user (everything UniFi has ever seen)
    fp = _fingerprint_names()
    clients = {}
    for src in ("rest/user", "stat/sta"):
        try:
            rows = unifi._legacy_raw(src)
        except Exception:  # noqa: BLE001
            rows = []
        for c in rows:
            mac = _norm_mac(c.get("mac"))
            if not mac:
                continue
            cur = clients.setdefault(mac, {})
            for k, v in c.items():
                if v not in (None, "", []) and (k not in cur or src == "stat/sta"):
                    cur[k] = v
    gear = {}
    try:
        for d in unifi._legacy_raw("stat/device"):
            mac = _norm_mac(d.get("mac"))
            if mac:
                gear[mac] = {"name": d.get("name") or d.get("model") or mac, "kind": _GEAR.get(str(d.get("type") or "")[:3], d.get("type") or "device"),
                             "ip": d.get("ip")}
    except Exception:  # noqa: BLE001
        pass

    def cip(c):
        return c.get("ip") or c.get("last_ip") or c.get("fixed_ip") or ""

    # roles left undecided: look at what the members are
    by_zone = {}
    for mac, c in clients.items():
        z = _zone_of(cip(c), nets)
        if z:
            by_zone.setdefault(z, []).append(c)
    for z, role in list(roles.items()):
        if role:
            continue
        members = by_zone.get(z, [])
        classes = []
        for c in members:
            cls, _ = _class_for(fp.get(c.get("dev_cat")), c.get("name") or c.get("hostname"), c.get("oui"), None)
            if cls:
                classes.append(cls)
        if len(classes) >= 2:
            share = lambda *k, classes=classes: sum(1 for x in classes if x in k) / len(classes)  # noqa: E731
            if share("server", "k8s") >= 0.5:
                role = "protected"
        roles[z] = role or "user"
    for z, c in zones.items():
        detail_z.append({"zone": z, "cidr": c, "role": roles[z], "network": purpose[z][1], "purpose": purpose[z][0],
                         "members": len(by_zone.get(z, [])), "existing": have_zones.get(c) == z})

    # ---- device classes
    classes, detail_d = {}, []
    for mac, g in gear.items():
        classes[mac] = "infra"
        detail_d.append({"key": mac, "name": g["name"], "ip": g.get("ip") or "", "zone": _zone_of(g.get("ip") or "", nets) or "", "class": "infra",
                         "why": f"UniFi {g['kind']}"})
    for mac, c in clients.items():
        if mac in classes:
            continue
        z = _zone_of(cip(c), nets)
        name = c.get("name") or c.get("hostname") or ""
        cat = fp.get(c.get("dev_cat"))
        cls, why = _class_for(cat, name, c.get("oui"), roles.get(z))
        if not cls:
            continue
        classes[mac] = cls
        detail_d.append({"key": mac, "name": name or c.get("oui") or "", "ip": cip(c), "zone": z or "", "class": cls, "why": why})

    # ---- internal prefixes covering all subnets (so is_internal() works on non-10.x networks)
    prefixes = set()
    for n in nets.values():
        o = str(n.network_address).split(".")
        prefixes.add(".".join(o[:2]) + "." if n.prefixlen >= 16 else o[0] + ".")
    return {"zones": zones, "zone_roles": roles, "device_classes": classes, "site_prefixes": sorted(prefixes),
            "detail": {"zones": detail_z, "devices": sorted(detail_d, key=lambda d: (d["class"], d["name"]))}}


def apply(prop, overwrite=False, user="system"):
    """Merge a proposal into policy + site. Returns counts. Existing keys survive unless overwrite=True."""
    pol = store.cfg_load("policy")
    zones = pol.setdefault("zones", {})
    roles = pol.setdefault("zone_roles", {})
    cls = pol.setdefault("device_classes", {})
    have_cidr = {str(c): z for z, c in zones.items()}
    n = {"zones": 0, "roles": 0, "classes": 0, "changed": 0}
    for z, c in prop["zones"].items():
        if c in have_cidr:  # same subnet already has a zone name: keep that name
            z_existing = have_cidr[c]
            if z != z_existing and prop["zone_roles"].get(z) and (overwrite or z_existing not in roles):
                roles[z_existing] = prop["zone_roles"][z]
                n["roles"] += 1
            elif z_existing not in roles and prop["zone_roles"].get(z):
                roles[z_existing] = prop["zone_roles"][z]
                n["roles"] += 1
            elif z == z_existing and overwrite and roles.get(z) != prop["zone_roles"].get(z):
                roles[z] = prop["zone_roles"][z]
                n["roles"] += 1
            continue
        if z in zones:
            continue
        zones[z] = c
        n["zones"] += 1
        if prop["zone_roles"].get(z):
            roles[z] = prop["zone_roles"][z]
            n["roles"] += 1
    ip2mac_known = {k.lower() for k in cls}
    for mac, c in prop["device_classes"].items():
        if mac in cls:
            if overwrite and cls[mac] != c:
                cls[mac] = c
                n["changed"] += 1
            continue
        d = next((x for x in prop["detail"]["devices"] if x["key"] == mac), {})
        if d.get("ip") and d["ip"] in cls:  # already classified by IP
            if overwrite and cls[d["ip"]] != c:
                cls[d["ip"]] = c
                n["changed"] += 1
            continue
        cls[mac] = c
        n["classes"] += 1
    store.cfg_save("policy", pol)
    site = store.cfg_load("site")
    have = list(site.get("internal_prefixes") or [])
    add = [p for p in prop["site_prefixes"] if not any(p.startswith(h) for h in have)]
    # an untouched example default (10.) is replaced rather than kept next to the real prefixes
    if add and have == ["10."] and not any(p.startswith("10.") for p in prop["site_prefixes"]):
        have = []
    if add or have != list(site.get("internal_prefixes") or []):
        site["internal_prefixes"] = have + add
        store.cfg_save("site", site)
        n["prefixes"] = len(add)
    return n


if __name__ == "__main__":
    import json
    p = build()
    if "--apply" in sys.argv:
        print(json.dumps(apply(p, "--overwrite" in sys.argv)))
    else:
        print(json.dumps({k: v for k, v in p.items() if k != "detail"}, indent=1))
        print(json.dumps(p["detail"]["zones"], indent=1))
