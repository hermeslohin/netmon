#!/usr/bin/python3
"""Plain-language definitions for every Settings section. They are stored in each settings document as `_doc_<key>`
and shown by the Settings page as an (i) bubble next to the section / setting. `python3 settings_docs.py` writes them
into the live settings (existing text is replaced) and into the *.example.json templates."""
import json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

DOCS = {
    "policy": {
        "zones": "Your network segments: zone name -> subnet (CIDR). Every internal IP is placed in the most specific matching zone; "
                 "traffic between zones is what segmentation checks, the zone matrix and the lateral-movement graph are built on. "
                 "An internal IP in no zone is 'internal-other'. 'Discover from UniFi' fills this from your UniFi networks.",
        "zone_roles": "What each zone is for, which drives the rules: dmz = internet-exposed (any flow from it into another zone is a high-severity violation; risk x1.3), "
                      "protected = servers/clusters/AI (IoT or camera access and unexpected cross-zone access are flagged; impact 5; risk x1.15), "
                      "mgmt = IPMI / infrastructure (impact 4), user = PCs and phones (impact 3), iot = IoT, cameras, guests (impact 2, and not allowed to reach protected zones). "
                      "Zone names are free-form; the role is what counts.",
        "device_classes": "What kind of device each one is: MAC address (preferred, survives DHCP changes) or IP -> class. Classes: iot, camera, media, game, personal, work, server, k8s, infra. "
                          "The class sets a device's risk impact (infra/server 5, k8s/work 4, personal 3, camera/media/game/iot 2) and drives rules: iot and camera devices must not reach protected zones or use admin ports. "
                          "A device with no class is 'unclassified' and takes its zone's impact. 'Discover from UniFi' guesses classes from UniFi fingerprints; review them.",
        "sensitive_ports": "Admin / remote-control / lateral-movement ports (SSH 22, SMB 445, RDP 3389, databases, Docker and Kubernetes APIs...). "
                           "A successful internal connection to one of these that is not covered by an allow rule is a segmentation violation, and its severity is HIGH. "
                           "Add a port here to treat it as administrative; netmon also has a built-in list of admin ports that is always included.",
        "discovery_ports": "Ports used by normal network discovery and housekeeping (DNS 53, DHCP 67/68, NTP 123, NetBIOS 137/138, mDNS 5353, SSDP 1900, UPnP...). "
                           "Connections on these are treated as ordinary (LOW severity) and traffic from a device to its gateway (.1) on them is ignored. Add noisy discovery protocols to cut false positives.",
        "gateway_ports": "Ports clients are expected to use towards the gateway (the .1 address of a subnet): DNS, DHCP, NTP, the web UI, Tailscale/STUN. "
                         "Flows to a gateway on these ports are skipped by the segmentation check. Remove a port to start checking it.",
        "scan_thresholds": "Flags an internal device as a scanner. Within the time range being analysed (24 h for the nightly analysis), netmon counts each internal source's FAILED connections to other internal hosts "
                           "(Zeek states S0 = no reply, REJ = refused, RSTOS0, SH, OTH). A source is reported as scanning when EITHER number is reached: "
                           "hosts = distinct destination IPs it failed to reach (a sweep across many machines), or ports = distinct destination ports it failed on (a port scan of few machines). "
                           "Defaults hosts 20, ports 40. Lower = more sensitive and more false positives (discovery apps such as Sonos/Cast/printers probe many hosts); raise it if known devices keep appearing. "
                           "Gateway addresses ending in .1 are ignored. Successful connections do not count. Findings show under Posture > Scans and Network > Lateral movement.",
        "allow": "Expected internal flows that are NOT violations, checked top to bottom. Each rule has src and dst (an IP, a zone name, a device class, or * for any), "
                 "optional ports (numbers or 'port/proto' such as 41641/udp; empty = any port) and a 'why'. "
                 "Anything on a sensitive port, from a dmz zone, from IoT/camera to a protected zone, or across zones into a protected zone that no rule allows is reported. "
                 "Add a rule when a flagged flow is legitimate; keep rules narrow (specific host and ports).",
    },
    "host_policy": {
        "admin_sources": "Machines (IP or IP prefix -> label) that are expected to log in to your hosts and administer them. "
                         "A first-seen login or failed login from a source in this list is Review; from an unlisted internal or external source it is Investigate. Put your admin workstations and jump hosts here.",
        "failure_threshold": "Number of failed logins from one internal source on one host, within the analysed window, before it is reported (default 8). "
                             "Failures from an internet address are always reported regardless of this number. Lower = more sensitive.",
        "agent_stale_minutes": "Minutes without a check-in before an Elastic Agent is reported as not checking in (default 30). "
                               "Raise it for laptops that sleep; lower it for servers you want to know about quickly.",
        "silent_min_prev": "A host is reported as 'stopped sending syslog' when it sent 0 events in this window but at least this many in the previous one (default 50). "
                           "The minimum stops hosts that are normally quiet from alerting.",
        "ack_days": "How many days an acknowledged host finding stays quiet (default 14). After that the finding comes back if the condition still exists, so accepted risks are re-reviewed.",
        "package_processes": "Process names of package managers and system updaters (apt, dnf, buildah, podman...). Executables or file changes they cause are treated as expected software installs, not suspicious activity.",
        "exec_allow_prefixes": "Path prefixes of programs that may run for the first time without a 'new executable' finding (for example your own deploy directory). Empty by default.",
        "memfd_allow": "Programs allowed to run code from anonymous memory (memfd_create), which malware uses to avoid touching disk. Browsers and some runtimes do it legitimately; list their path prefixes here.",
        "suspicious_exec_dirs": "Directories where a running program is suspicious because normal software is not installed there (/tmp, /var/tmp, /dev/shm...). Executing from one is reported as Investigate.",
        "suspicious_cmdline": "Regular expressions (case-insensitive) matched against process command lines to catch reverse shells and download-and-run one-liners (/dev/tcp/, bash -i, nc -e, base64 -d | sh...). A match is Investigate. Invalid regexes are rejected when saving.",
        "sensitive_paths": "Files whose modification should be reported (SSH authorized_keys, sudoers, passwd/shadow, cron...). Wildcard patterns, case-insensitive; * matches any characters. Changes by package managers are marked as such.",
        "syslog_patterns": "Kernel and system log messages worth alerting on. Each entry: name -> q (an Elasticsearch wildcard matched against the message, * = anything), sev (Investigate or Review) and watch (true = also checked by the 15-minute watcher, not only the nightly run). Add a pattern to catch a message you care about.",
        "net_suspicious_ports": "Outbound connections to the internet on these ports (common backdoor, IRC, Tor and C2 ports such as 4444, 6667, 9001, 31337) are reported as Investigate.",
        "net_quiet_procs": "Programs whose connections to new destinations are not reported (browsers and updaters talk to constantly changing CDN addresses). Path prefixes. Shells, interpreters and temp-path binaries reaching the internet are still always reported.",
        "net_interpreter_ok": "Per host: interpreter programs (python, node...) whose internet web traffic is expected on that host, so 'interpreter opened an internet connection' is not raised. Format: host -> list of executable path prefixes. Empty = none expected.",
        "trusted_tool_paths": "Glob patterns for known tools installed in hidden directories (Hermes, LM Studio...). They skip the temp/hidden-path and interpreter-to-internet rules but are still covered by command-line, new-executable, hash-change and threat-feed rules.",
        "trusted_script_dirs": "Glob patterns for working directories / script paths of your own automation. Network events from processes running there are dropped from host network analysis, so netmon's own collectors do not raise alerts.",
        "service_parents": "Regular expressions for executables of network or AI services (web servers, databases, inference APIs). If such a program starts a shell or downloader (see service_child_suspicious), that is Investigate: the main sign of an exploited service.",
        "service_child_suspicious": "One regular expression naming child programs that a service should never start: shells, curl/wget, netcat, socat, telnet, base64... Used with service_parents.",
        "package_managed_prefixes": "Directories whose contents are owned by the OS package manager (/usr/bin, /usr/sbin, /lib...). An executable outside them is 'unmanaged'; a changed file inside them without a package update is suspicious.",
        "osquery": "Rules for the osquery host-posture pack: package_managed_prefixes, max_uptime_days (flag hosts that have not rebooted for kernel updates, default 45), risky_exposed_ports (port -> why it is risky when listening on the LAN), sysctl_expect (kernel setting -> accepted values, severity and reason), host_exceptions (host -> {posture item: reason} to accept a known risk) and the ld_preload_allow / nopasswd_allow / deleted_allow lists of accepted items.",
        "endpoint_ips": "Maps an endpoint (Elastic Agent) host name to its LAN IP so host findings are tied to the right device for per-device alert subscriptions, risk scoring and the network map.",
    },
    "known_benign": {
        "signatures": "Suricata alert names (substring match) you have judged harmless in your network, with the reason. They are shown as noise, not signal, in reports and the AI review. Only add a signature after you know exactly what generates it.",
        "names": "Labels for IP addresses that are not in your DHCP inventory (gateways, VIPs, appliances), so they show a name instead of a bare address.",
        "dns_domains": "Registered domains cleared of DNS-tunnelling suspicion (high-volume, high-entropy lookups that are legitimate, such as security products and reverse DNS). They are excluded from tunnel alarms.",
        "beacon_domains": "Registered domains whose regular check-ins are expected (NTP, Apple, cloud IoT vendors, DNS-over-HTTPS). They are excluded from beaconing / C2 alarms. Subdomains match.",
    },
    "site": {
        "site_name": "Display name for this network, used in titles and reports.",
        "own_domains": "Domains you own (home.lan, example.com). Used to recognise your own names in DNS and certificates and by the push guard that blocks publishing them.",
        "internal_cidr": "Your whole internal address range (a CIDR such as a /16 or /8 private range). Used in Elasticsearch queries to select internal-to-internal traffic. It must contain every zone.",
        "internal_prefixes": "Address prefixes that count as internal (for example the first two octets plus a dot). Any IP starting with one is internal; others are internet. 'Discover from UniFi' fills them from your subnets. Wrong prefixes make internal traffic look external.",
        "es_url": "Elasticsearch (Security Onion) URL that netmon queries, for example https://sensor.example.lan:9200. Credentials are set under More > Configuration.",
        "sensor_ip": "IP of the Security Onion / network sensor. It sees all traffic, so it is treated as infrastructure and excluded from some detections.",
        "self_ip": "IP of the machine running netmon. Its own traffic (feeds, API calls) is expected and not reported.",
        "self_host": "Host name of the machine running netmon. Used to recognise its own events.",
        "gateway_name": "Display name of your router/firewall gateway.",
        "gateway_dns_ip": "The gateway's DNS address. DNS that bypasses it (clients using a public resolver directly) is flagged, and the fix text names this address.",
        "unifi_console_ip": "LAN IP of the UniFi console. Netmon reaches UniFi through the cloud API; this is for display and pivot links.",
        "home_wan": "Your home public IP. UniFi admin access from it, from internal addresses and from the VPN is expected; any other source is an alert.",
        "vpn_prefixes": "Address prefixes handed to VPN clients (for example '192.168.2.'). Admin access from them counts as expected.",
        "honeypot_ips": "IPs of decoy hosts. Any connection to one is suspicious because nothing legitimate uses it.",
        "admin_workstations": "Free text naming your admin machines. It is inserted into advice such as 'restrict SSH to <these> with a firewall rule'.",
        "host_ips": "Endpoint host name -> IP, so Elastic Agent hosts without a device IP are tied to the right address for risk scoring. Changes need a dashboard restart.",
        "display_names": "IP -> friendly name shown instead of the DHCP name or the bare address (IP -> kube-1).",
        "crown_jewels": "IP -> reason for your most important systems. They get the maximum impact (5) in risk scoring, so any weakness on them ranks highest. Changes need a dashboard restart.",
        "game_ports": "Port -> name of game servers you run (25565 -> minecraft). Used to label that traffic as expected rather than unknown.",
        "vapid_contact": "Contact (mailto:you@example.com) sent to browser push services with web-push notifications. Not shown to anyone else.",
        "github_user": "GitHub user that ship.sh pushes to, and that the push guard refuses to leak into other places. Only needed if you publish a fork.",
        "github_repo": "GitHub repository (user/name) that ship.sh pushes to. Only needed if you publish a fork.",
        "image_repo": "Container registry path for the dashboard image (ghcr.io/user/netmon-dashboard). Only needed if you publish images.",
        "sensitive_terms": "Words that must never appear in the public repository (your names, hosts, domains). repo_guard.py blocks a commit or push that contains one.",
        "kibana_url": "Kibana base URL. When set, the dashboard shows a magnifier button that opens the matching search in Kibana. Empty hides the buttons.",
        "kibana_data_view": "Kibana Discover data view id used by those links (default logs-*).",
        "unifi_web_url": "Base URL of the UniFi Network web app, for pivot links from a client or event straight into UniFi.",
        "unifi_paths": "Label -> page path under unifi_web_url for the UniFi pivot links (for example 'Flows' -> 'insights/flows').",
    },
}


def write_all():
    import store
    out = {}
    for doc, m in DOCS.items():
        d = store.cfg_load(doc)
        n = 0
        for k, t in m.items():
            if k in d:  # only document settings that exist, so the page never shows an orphan note
                d["_doc_" + k] = t
                n += 1
        store.cfg_save(doc, d)
        out[doc] = n
        ex = os.path.join(HERE, {"policy": "policy.example.json", "host_policy": "host_policy.example.json",
                                 "known_benign": "known_benign.example.json", "site": "site.example.json"}[doc])
        if os.path.exists(ex):
            e = json.load(open(ex))
            for k, t in m.items():
                if k in e:
                    e["_doc_" + k] = t
            json.dump(e, open(ex, "w"), indent=1)
    return out


if __name__ == "__main__":
    print(write_all())
