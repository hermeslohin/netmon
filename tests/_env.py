"""Test isolation for netmon. Import this FIRST in every test module (before any netmon module).

Every netmon module reads its locations from the environment at import time, so this module points them at a
throw-away directory before anything else is imported:

  STATE_DIR / NETMON_DB   -> <tmp>/state, <tmp>/state/netmon.db   (never the live dashboard/state DB)
  NETMON_DIR              -> the repository checkout (code only; data comes from the temp DB)
  NETMON_LLM=off          -> no local-LLM worker threads, no network calls to LM Studio
  NETMON_INTEGRATIONS     -> <tmp>/state/integrations.json (no Elasticsearch / UniFi credentials)
  NETMON_BACKUP_DIR       -> <tmp>/backup (analyze.py calls store.backup(); never overwrite the live daily backups)

It also puts the repo root and dashboard/app on sys.path, exactly as the dashboard container does (/netmon + /app).
Nothing here touches the network, the live database, the running container or git.
"""
import atexit
import os
import shutil
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(REPO, "dashboard", "app")
TESTS = os.path.join(REPO, "tests")

if not os.environ.get("NETMON_TEST_TMP"):
    _tmp = tempfile.mkdtemp(prefix="netmon-test-")
    os.environ["NETMON_TEST_TMP"] = _tmp
    if not os.environ.get("NETMON_TEST_KEEP"):
        atexit.register(shutil.rmtree, _tmp, True)
TMP = os.environ["NETMON_TEST_TMP"]
STATE = os.path.join(TMP, "state")
os.makedirs(STATE, exist_ok=True)

os.environ["STATE_DIR"] = STATE
os.environ["NETMON_DB"] = os.path.join(STATE, "netmon.db")
os.environ["NETMON_DIR"] = REPO
os.environ["NETMON_LLM"] = "off"
os.environ["NETMON_INTEGRATIONS"] = os.path.join(STATE, "integrations.json")
os.environ["NETMON_BACKUP_DIR"] = os.path.join(TMP, "backup")  # store.backup() default is <repo>/baseline/backup (live backups!)
os.environ.pop("NETMON_WINDOW_END", None)
os.environ.pop("NETMON_BROKER_URL", None)
os.environ.pop("NETMON_BROKER_KEY", None)

for p in (APP, REPO, TESTS):
    if p not in sys.path:
        sys.path.insert(0, p)


def fresh_db():
    """Empty every table of the isolated DB except meta, and drop store/site_cfg caches (call from setUp)."""
    import store
    old = getattr(store._dl, "c", None)
    if old is not None:
        try:
            old.close()
        except Exception:  # noqa: BLE001
            pass
        store._dl.c = None
    c = store.connect()
    for (t,) in c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall():
        if t != "meta":
            c.execute(f'DELETE FROM "{t}"')
    c.close()
    if hasattr(store, "_cfg_cache"):
        try:
            store._cfg_cache.clear()
        except Exception:  # noqa: BLE001
            pass
    m = sys.modules.get("site_cfg")
    if m is not None:
        setattr(m, "_cache", None)
