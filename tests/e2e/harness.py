"""End-to-end harness: runs the REAL dashboard (dashboard/app/server.py) as a separate process over HTTPS.

The server gets its own throw-away state directory, a freshly generated self-signed certificate, a free port, the LLM
switched off and no Elasticsearch/UniFi credentials. Tests talk to it only over the network, like a browser would.
"""
import http.client
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import time

import _env

ADMIN_USER, ADMIN_PASS = "e2e-admin", "e2e-admin-password-1"
PY = sys.executable


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def make_cert(d):
    crt, key = os.path.join(d, "dashboard.crt"), os.path.join(d, "dashboard.key")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost",
                    "-keyout", key, "-out", crt], check=True, capture_output=True)
    return crt, key


def server_env(state, crt=None, key=None, port=None, **extra):
    env = {k: v for k, v in os.environ.items() if not k.startswith(("NETMON_", "DASH_"))}
    env.update(NETMON_DIR=_env.REPO, STATE_DIR=state, NETMON_DB=os.path.join(state, "netmon.db"), NETMON_LLM="off",
               NETMON_INTEGRATIONS=os.path.join(state, "integrations.json"), PYTHONDONTWRITEBYTECODE="1",
               NETMON_BACKUP_DIR=os.path.join(state, "backup"),
               DASH_USER=ADMIN_USER, DASH_PASS=ADMIN_PASS)
    if crt:
        env.update(CERT=crt, KEY=key, PORT=str(port))
    env.update(extra)
    return env


class Server:
    """Context manager: start server.py, wait for /healthz, stop it (and keep its log for assertions)."""

    def __init__(self, seed=None, **extra_env):
        self.dir = tempfile.mkdtemp(prefix="netmon-e2e-", dir=_env.TMP)
        self.state = os.path.join(self.dir, "state")
        os.makedirs(self.state)
        self.crt, self.key = make_cert(self.dir)
        self.port = free_port()
        self.env = server_env(self.state, self.crt, self.key, self.port, **extra_env)
        self.seed = seed
        self.log_path = os.path.join(self.dir, "server.log")

    def run_py(self, code, timeout=60):
        """Run Python inside the server's environment (e.g. to seed its store) and return stdout."""
        pre = (f"import sys; sys.path[:0] = [{_env.APP!r}, {_env.REPO!r}, {_env.TESTS!r}]\n")
        r = subprocess.run([PY, "-c", pre + code], env=self.env, capture_output=True, text=True, timeout=timeout)
        if r.returncode:
            raise RuntimeError(f"seed failed: {r.stderr[-2000:]}")
        return r.stdout

    def __enter__(self):
        if self.seed:
            self.run_py(self.seed)
        self.log = open(self.log_path, "w")
        self.proc = subprocess.Popen([PY, "-u", os.path.join(_env.APP, "server.py")], env=self.env, cwd=_env.APP,
                                     stdout=self.log, stderr=subprocess.STDOUT)
        deadline = time.time() + 30
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError("server exited early:\n" + self.output())
            try:
                if self.client().get("/healthz")[0] == 200:
                    return self
            except OSError:
                pass
            time.sleep(0.25)
        raise RuntimeError("server did not become healthy:\n" + self.output())

    def __exit__(self, *a):
        self.proc.terminate()
        try:
            self.proc.wait(10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.log.close()

    def output(self):
        if not self.log.closed:
            self.log.flush()
        with open(self.log_path) as f:
            return f.read()

    def client(self):
        return Client("127.0.0.1", self.port)

    def login(self, user=ADMIN_USER, pw=ADMIN_PASS):
        c = self.client()
        code, body, _ = c.post("/api/login", {"username": user, "password": pw})
        if code != 200:
            raise AssertionError(f"login {user} -> {code} {body}")
        return c


class Client:
    """Tiny HTTPS client with a cookie jar (one cookie: the session) and the dashboard's CSRF header."""

    def __init__(self, host, port):
        self.host, self.port, self.cookie = host, port, None
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

    def request(self, method, path, body=None, headers=None, raw=False):
        conn = http.client.HTTPSConnection(self.host, self.port, context=self.ctx, timeout=30)
        h = dict(headers or {})
        if self.cookie:
            h["Cookie"] = f"netmon_session={self.cookie}"
        data = None
        if body is not None:
            data = body if isinstance(body, (bytes, str)) else json.dumps(body)
            h.setdefault("Content-Type", "application/json")
            h.setdefault("X-Netmon", "1")
        conn.request(method, path, body=data, headers=h)
        r = conn.getresponse()
        payload = r.read()
        hdrs = {k.lower(): v for k, v in r.getheaders()}
        for k, v in r.getheaders():
            if k.lower() == "set-cookie" and v.startswith("netmon_session="):
                val = v.split(";", 1)[0].split("=", 1)[1]
                self.cookie = val or None
        hdrs["_set_cookie"] = [v for k, v in r.getheaders() if k.lower() == "set-cookie"]
        conn.close()
        if raw:
            return r.status, payload, hdrs
        try:
            return r.status, json.loads(payload), hdrs
        except ValueError:
            return r.status, payload.decode(errors="replace"), hdrs

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, body=None, **kw):
        return self.request("POST", path, body if body is not None else {}, **kw)
