"""Host-side harness for the credential proxy tests (P3, R3): a per-test CA and certificates (host
openssl), the real deep/credproxy.js and deep/fake-upstream.js under the host's node, free ports,
and a synthetic CANARY credential of each family's shape. No Docker, no network beyond 127.0.0.1."""
import base64
import json
import os
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

DEEP = Path(__file__).resolve().parent.parent / "deep"
NODE = shutil.which("node")
OPENSSL = shutil.which("openssl")


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def canary(family: str) -> dict:
    """Synthetic credentials of the admitted shapes, marked CANARY (never valid anywhere)."""
    if family == "claude":
        tok = "sk-ant-oat01-CANARY" + secrets.token_urlsafe(64)[:83] + "AA"
        return {"set": {"authorization": f"Bearer {tok}"}, "values": [tok, f"Bearer {tok}"]}
    seg = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()
    jwt = seg({"alg": "RS256", "typ": "JWT"}) + "." + seg({"sub": "CANARY", "exp": 4102444800}) + ".CANARY" + secrets.token_urlsafe(48)
    acct = "canary-" + secrets.token_hex(12)
    return {"set": {"authorization": f"Bearer {jwt}", "chatgpt-account-id": acct}, "values": [jwt, f"Bearer {jwt}", acct]}


class CA:
    def __init__(self, d: Path, name: str):
        self.d = d
        self.key, self.pem = d / f"{name}-ca.key", d / f"{name}-ca.pem"
        subprocess.run([OPENSSL, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", self.key, "-out", self.pem,
                        "-days", "2", "-subj", f"/CN=scout test CA {name}"], check=True, capture_output=True)

    def leaf(self, cn: str, name: str) -> tuple[Path, Path]:
        key, csr, pem, ext = (self.d / f"{name}.key", self.d / f"{name}.csr", self.d / f"{name}.pem", self.d / f"{name}.ext")
        ext.write_text(f"subjectAltName=DNS:{cn}\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n")
        subprocess.run([OPENSSL, "req", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", csr, "-subj", f"/CN={cn}"],
                       check=True, capture_output=True)
        subprocess.run([OPENSSL, "x509", "-req", "-in", csr, "-CA", self.pem, "-CAkey", self.key, "-CAcreateserial",
                        "-out", pem, "-days", "2", "-extfile", ext], check=True, capture_output=True)
        return key, pem


class Proc:
    def __init__(self, argv, env, log: Path, ready: str, timeout=15):
        self.log = log
        self.f = open(log, "wb")
        self.p = subprocess.Popen(argv, env=env, stdout=self.f, stderr=subprocess.STDOUT)
        t0 = time.monotonic()
        while time.monotonic() - t0 < timeout:
            if ready in log.read_text(errors="replace") or self.p.poll() is not None:
                break
            time.sleep(0.05)

    def events(self):
        out = []
        for l in self.log.read_text(errors="replace").splitlines():
            try:
                out.append(json.loads(l))
            except json.JSONDecodeError:
                pass
        return out

    def stop(self):
        if self.p.poll() is None:
            self.p.terminate()
            try:
                self.p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.p.kill()
        self.f.close()


class Rig:
    """One fake upstream (TLS, test CA) and one credential proxy in front of it, both on 127.0.0.1.
    `upstream_ca`: which CA the PROXY trusts ('good' or 'rogue'); `leaf_cn`: the name in the
    upstream's certificate; the proxy's allowlisted host is always 'localhost'."""

    def __init__(self, family="claude", upstream_ca="good", leaf_cn="localhost", drip=False, allow_hosts=("localhost",),
                 put=True):
        self.t = tempfile.TemporaryDirectory()
        d = self.d = Path(self.t.name)
        self.family = family
        good, rogue = CA(d, "good"), CA(d, "rogue")
        key, pem = good.leaf(leaf_cn, "leaf")
        self.up_port, self.px_port = free_port(), free_port()
        env = {**os.environ, "FAKE_KEY": str(key), "FAKE_CERT": str(pem), "FAKE_PORT": str(self.up_port)}
        if drip:
            env["DRIP"] = "1"
        self.up = Proc([NODE, str(DEEP / "fake-upstream.js")], env, d / "upstream.log", '"listening"')
        conf = json.loads((DEEP / f"credproxy-{family}.json").read_text())
        conf.update(listen_port=self.px_port, upstream_port=self.up_port,
                    ca_file=str((good if upstream_ca == "good" else rogue).pem))
        (d / "config.json").write_text(json.dumps(conf))
        (d / "allow.txt").write_text("".join(h + "\n" for h in allow_hosts))
        self.penv = {**os.environ, "CREDPROXY_CONFIG": str(d / "config.json"), "CREDPROXY_ALLOWLIST": str(d / "allow.txt"),
                     "CREDPROXY_CRED": str(d / "cred.json")}
        self.px = Proc([NODE, str(DEEP / "credproxy.js")], self.penv, d / "proxy.log", '"listening"')
        self.canary = canary(family)
        self.dummy = self._dummy()
        if put:
            self.put({"set": self.canary["set"], "box": self.dummy})

    def _dummy(self):
        import sys
        sys.path.insert(0, str(DEEP))
        import deeplib
        return deeplib.box_dummy(self.family)["headers"]

    def put(self, payload):
        subprocess.run([NODE, str(DEEP / "credproxy.js"), "put"], input=json.dumps(payload).encode(), env=self.penv,
                       check=True, capture_output=True)

    def raw(self, data: bytes, timeout=10) -> bytes:
        s = socket.create_connection(("127.0.0.1", self.px_port), timeout=timeout)
        s.sendall(data)
        buf = b""
        try:
            while True:
                c = s.recv(65536)
                if not c:
                    break
                buf += c
        except socket.timeout:
            pass
        s.close()
        return buf

    def request(self, method, path, headers=(), body=b"", host="egress-proxy:8080"):
        h = [f"{method} {path} HTTP/1.1", f"Host: {host}", "Connection: close", f"Content-Length: {len(body)}"]
        h += [f"{k}: {v}" for k, v in headers]
        return self.raw(("\r\n".join(h) + "\r\n\r\n").encode() + body)

    def marked(self):
        return list(self.dummy.items())

    def close(self):
        self.up.stop()
        self.px.stop()
        self.t.cleanup()
