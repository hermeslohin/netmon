"""Admin / lateral-movement protocols: what an administrator (or an attacker moving laterally) uses to
reach another machine. Shared by the collector (extras.admin_access) and the dashboard (lateral.py, risk.py).

Each entry: port -> (protocol label, category, transport).
  category  shell    - interactive remote shell / desktop (SSH, RDP, VNC, WinRM, telnet, r-services, remote support)
            exec     - remote execution / management APIs (SMB+RPC = PsExec/WMI/admin shares, Docker, k8s, IPMI...)
            database - database logins (successful app traffic is normal; failures still count)
"""

ADMIN_PORTS = {
    22: ("SSH", "shell", "tcp"),
    23: ("Telnet", "shell", "tcp"),
    3389: ("RDP", "shell", "tcp"),
    5985: ("WinRM / PowerShell remoting", "shell", "tcp"),
    5986: ("WinRM / PowerShell remoting (TLS)", "shell", "tcp"),
    5900: ("VNC", "shell", "tcp"), 5901: ("VNC", "shell", "tcp"), 5902: ("VNC", "shell", "tcp"), 5903: ("VNC", "shell", "tcp"),
    512: ("rexec", "shell", "tcp"), 513: ("rlogin", "shell", "tcp"), 514: ("rsh", "shell", "tcp"),
    5938: ("TeamViewer", "shell", "tcp"), 7070: ("AnyDesk", "shell", "tcp"),
    21115: ("RustDesk", "shell", "tcp"), 21116: ("RustDesk", "shell", "tcp"), 21118: ("RustDesk", "shell", "tcp"),
    445: ("SMB (PsExec / admin shares)", "exec", "tcp"),
    139: ("NetBIOS SMB", "exec", "tcp"),
    135: ("RPC / DCOM (WMI, PsExec service)", "exec", "tcp"),
    2375: ("Docker API", "exec", "tcp"), 2376: ("Docker API (TLS)", "exec", "tcp"),
    6443: ("Kubernetes API", "exec", "tcp"), 10250: ("kubelet", "exec", "tcp"),
    8291: ("MikroTik Winbox", "exec", "tcp"), 8006: ("Proxmox", "exec", "tcp"), 902: ("VMware ESXi", "exec", "tcp"),
    623: ("IPMI / BMC", "exec", "udp"), 9090: ("Cockpit", "exec", "tcp"), 10000: ("Webmin", "exec", "tcp"),
    1433: ("MSSQL", "database", "tcp"), 3306: ("MySQL", "database", "tcp"), 5432: ("PostgreSQL", "database", "tcp"),
    6379: ("Redis", "database", "tcp"), 27017: ("MongoDB", "database", "tcp"),
}

# Zeek conn states that mean the connection never got through (the port was refused, filtered or ignored).
# OTH (midstream, no SYN seen) is deliberately NOT a failure - it is usually a long-lived session.
CONN_FAILED = ["S0", "REJ", "RSTOS0", "RSTRH", "SH", "SHR"]

# admin client tools seen in endpoint process telemetry (Elastic Defend exec events)
ADMIN_TOOLS = {
    "ssh": "SSH", "scp": "SSH", "sftp": "SSH", "sshpass": "SSH", "mosh": "SSH", "rsync": "SSH",
    "xfreerdp": "RDP", "xfreerdp3": "RDP", "rdesktop": "RDP", "remmina": "RDP", "mstsc.exe": "RDP",
    "psexec": "SMB (PsExec / admin shares)", "psexec.exe": "SMB (PsExec / admin shares)", "psexec64.exe": "SMB (PsExec / admin shares)",
    "paexec.exe": "SMB (PsExec / admin shares)", "impacket-psexec": "SMB (PsExec / admin shares)", "psexec.py": "SMB (PsExec / admin shares)",
    "impacket-smbexec": "SMB (PsExec / admin shares)", "smbexec.py": "SMB (PsExec / admin shares)", "smbclient": "SMB (PsExec / admin shares)",
    "impacket-wmiexec": "RPC / DCOM (WMI, PsExec service)", "wmiexec.py": "RPC / DCOM (WMI, PsExec service)", "wmic.exe": "RPC / DCOM (WMI, PsExec service)",
    "impacket-dcomexec": "RPC / DCOM (WMI, PsExec service)",
    "winrs.exe": "WinRM / PowerShell remoting", "evil-winrm": "WinRM / PowerShell remoting",
    "nxc": "SMB (PsExec / admin shares)", "netexec": "SMB (PsExec / admin shares)", "crackmapexec": "SMB (PsExec / admin shares)",
    "telnet": "Telnet", "vncviewer": "VNC",
}
# PowerShell is only an admin tool when it is remoting
PS_NAMES = {"pwsh", "pwsh.exe", "powershell.exe"}
PS_REMOTING = ("enter-pssession", "invoke-command", "new-pssession", "-computername", "-cn ")

# Windows logon types that mean "someone came in over the network"
WIN_LOGON = {"3": "network (SMB / PsExec / WinRM / WMI)", "10": "RDP", "8": "network cleartext"}


def label(port, transport="tcp"):
    p = ADMIN_PORTS.get(int(port))
    return p if p and p[2] == transport else None


def tcp_admin_ports():
    return sorted(p for p, (_, _, t) in ADMIN_PORTS.items() if t == "tcp")


def udp_admin_ports():
    return sorted(p for p, (_, _, t) in ADMIN_PORTS.items() if t == "udp")


# protocol labels from login sources -> the conn-level protocol they belong to (so evidence merges onto one session)
_LOGIN_PROTO = {"Windows network logon": "SMB (PsExec / admin shares)", "NTLM auth": "SMB (PsExec / admin shares)"}


def sessions(admin, resolve):
    """Merge network, login and tool evidence into one row per (src, dst, protocol).
    admin   - raw["admin_access"] from the collector
    resolve - fn(name_or_ip) -> internal IP or "" (maps endpoint host names / tool targets to IPs)
    Rows carry counts only; lateral.py decides the risk level."""
    rows = {}

    def row(s, d, proto, port=None, category=None):
        k = (s, d, proto)
        r = rows.get(k)
        if not r:
            cat = category or next((c for _, (p, c, _) in ADMIN_PORTS.items() if p == proto), "shell")
            r = rows[k] = {"src": s, "dst": d, "protocol": proto, "category": cat, "ports": set(), "attempts": 0, "connected": 0,
                           "conn_failed": 0, "bytes": 0, "auth_ok": 0, "auth_fail": 0, "invalid_user": 0, "users": {}, "methods": set(),
                           "details": set(), "sources": set(), "tools": [], "first": None, "last": None}
        if port:
            r["ports"].add(port)
        return r

    def when(r, a, b):
        for t in (a, b):
            if t:
                r["first"] = min(filter(None, [r["first"], t]))
                r["last"] = max(filter(None, [r["last"], t]))

    for c in admin.get("conns") or []:
        r = row(c["src"], c["dst"], c["protocol"], c["port"], c["category"])
        r["attempts"] += c["attempts"]; r["connected"] += c["connected"]; r["conn_failed"] += c["failed"]; r["bytes"] += c["bytes"]
        r["sources"].add("Zeek conn"); when(r, c.get("first"), c.get("last"))
    for l in admin.get("logins") or []:
        d = l.get("dst") or resolve(l.get("dst_host") or "")
        s = l.get("src") or ""
        if not s or not d:
            continue
        r = row(s, d, _LOGIN_PROTO.get(l["protocol"], l["protocol"]))
        n = l.get("count", 1)
        if l.get("ok"):
            r["auth_ok"] += n
        else:
            r["auth_fail"] += n
            if "invalid" in str(l.get("detail", "")).lower():
                r["invalid_user"] += n
        u = l.get("user") or ""
        if u:
            uu = r["users"].setdefault(u, {"ok": 0, "fail": 0}); uu["ok" if l.get("ok") else "fail"] += n
        for f, dst in (("method", r["methods"]), ("detail", r["details"])):
            for x in str(l.get(f) or "").split(","):
                if x.strip():
                    dst.add(x.strip())
        r["sources"].add(l.get("source") or "login log"); when(r, l.get("first"), l.get("last"))
    for t in admin.get("tools") or []:
        s, d = resolve(t.get("host") or ""), resolve(t.get("target") or "")
        if not s or not d or s == d:
            continue
        r = row(s, d, t["protocol"])
        r["tools"].append({"tool": t["tool"], "user": t.get("user", ""), "count": t["count"], "example": t.get("example", "")})
        r["sources"].add("endpoint process"); when(r, None, t.get("last"))
    out = []
    for r in rows.values():
        r["ports"] = sorted(r["ports"]); r["methods"] = sorted(r["methods"]); r["details"] = sorted(r["details"]); r["sources"] = sorted(r["sources"])
        out.append(r)
    return out
