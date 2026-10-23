#!/usr/bin/python3
"""Investigation check-off for host (endpoint) findings.

  hosts_ack.py list [hours]            open + investigated findings (default last 24h)
  hosts_ack.py ack <key> [note...]     mark investigated (muted in watcher, shown as checked in report/widget)
  hosts_ack.py unack <key>             reopen
  hosts_ack.py widget [hours] [out]    write the desktop checklist widget HTML (default <netmon>/host_findings.html)

Acks live in the SQLite store (store.py, acks table, type "host") - shared with the dashboard.
An ack expires after ACK_DAYS (host_policy.json "ack_days", default 14) so a recurring condition re-surfaces.
"""
import html, json, os, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hosts  # noqa: E402

# Check-offs live in the SQLite store (store.py, table acks, type "host") - shared with the dashboard.
import store  # noqa: E402
ACK_DAYS = hosts.POLICY.get("ack_days", 14)
WIDGET = os.path.join(os.path.dirname(os.path.abspath(__file__)), "host_findings.html")


def _ts(at):
    try:
        return time.mktime(time.strptime(at[:19], "%Y-%m-%dT%H:%M:%S")) - time.timezone
    except Exception:
        return time.time()


def load():
    """{key: {at, note, label, ts}} for live (non-expired) host acks."""
    a = store.acks_load().get("host", {})
    now = time.time()
    return {k: dict(v, ts=_ts(v.get("at", ""))) for k, v in a.items() if now - _ts(v.get("at", "")) < ACK_DAYS * 86400}


def current(hours=24):
    d = hosts.gather(hours * 60, nightly=True)
    return [{"key": k, "priority": p, "text": t} for k, p, t in hosts.findings(d, hosts.load_base(), nightly=True)]


def ack(key, note="", finding=None):
    f = finding or {}
    old = store.acks_load().get("host", {}).get(key, {})
    store.ack_set("host", key, True, note, (f.get("text") or old.get("label") or key)[:300])


def unack(key):
    store.ack_set("host", key, False)


def widget(hours=24, out=WIDGET):
    F = current(hours)
    acks = load()
    keys = {f["key"] for f in F}
    open_ = [f for f in F if f["key"] not in acks]
    done = [dict(key=k, text=v.get("label"), **v) for k, v in acks.items()]
    done.sort(key=lambda x: x.get("ts", 0), reverse=True)
    col = {"Investigate": "#c0392b", "Review": "#d68910", "Info": "#2e86c1"}

    def row(f, checked):
        k = html.escape(f["key"], quote=True)
        cmd = (f"Reopen host finding: {f['key']}" if checked else f"Ack host finding: {f['key']}")
        meta = (f"investigated {html.escape(f.get('at', ''))}" + (f" — {html.escape(f['note'])}" if f.get("note") else "")
                + ("" if f["key"] in keys else " · not seen in current window")) if checked else ""
        return (f'<label class="r{" done" if checked else ""}" data-send="{html.escape(cmd, quote=True)}" title="{k}">'
                f'<input type="checkbox" {"checked" if checked else ""} onclick="return false">'
                f'<span class="p" style="color:{col.get(f.get("priority"), "inherit")}">{html.escape(f.get("priority") or "")}</span>'
                f'<span class="t">{html.escape(f.get("text") or f["key"])}'
                + (f'<span class="m">{meta}</span>' if meta else "") + "</span></label>")

    body = "".join(row(f, False) for f in open_) or '<div class="e">No open host findings.</div>'
    body2 = "".join(row(f, True) for f in done) or '<div class="e">Nothing checked off yet.</div>'
    page = f"""<style>
.h{{font-weight:600;margin:6px 0 4px}} .s{{color:var(--muted-foreground);font-size:12px;margin-bottom:6px}}
.r{{display:flex;gap:8px;align-items:flex-start;padding:6px 4px;border-bottom:1px solid var(--border);cursor:pointer;font-size:13px;max-width:860px}}
.r:hover{{background:var(--card)}} .r input{{margin-top:2px;pointer-events:none}}
.p{{min-width:72px;font-weight:600;font-size:12px}} .t{{flex:1;word-break:break-word}}
.done .t{{text-decoration:line-through;color:var(--muted-foreground)}} .m{{display:block;font-size:11px;text-decoration:none;margin-top:2px}}
.e{{color:var(--muted-foreground);font-size:13px;padding:4px}}
</style>
<div class="h">Host findings — open ({len(open_)})</div>
<div class="s">Last {hours}h · generated {time.strftime('%Y-%m-%d %H:%MZ', time.gmtime())} · click a row to check it off (muted in the 15-min watcher; re-opens after {ACK_DAYS} days)</div>
{body}
<div class="h" style="margin-top:14px">Investigated ({len(done)})</div>
<div class="s">Click to reopen.</div>
{body2}"""
    open(out, "w").write(page)
    return out, len(open_), len(done)


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "list"
    if cmd == "list":
        hrs = int(sys.argv[2]) if len(sys.argv) > 2 else 24
        acks = load()
        for f in current(hrs):
            print(f"[{'x' if f['key'] in acks else ' '}] {f['priority']:<11} {f['key']}\n      {f['text'][:200]}")
    elif cmd == "ack":
        key, note = sys.argv[2], " ".join(sys.argv[3:])
        f = next((x for x in current(24) if x["key"] == key), None)
        ack(key, note, f)
        print(f"checked off: {key}" + ("" if f else " (not in current findings - stored anyway)"))
    elif cmd == "unack":
        unack(sys.argv[2])
        print(f"reopened: {sys.argv[2]}")
    elif cmd == "widget":
        hrs = int(sys.argv[2]) if len(sys.argv) > 2 else 24
        print(*widget(hrs, sys.argv[3] if len(sys.argv) > 3 else WIDGET))
