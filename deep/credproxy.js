#!/usr/bin/env node
// scout deep review, P3 (R3): the credential boundary. Stdlib only.
//
// This is the ONLY process that holds a real model credential, and it runs in the one container
// that is dual-homed: the box's --internal network on one side, an egress network on the other.
// The box holds a DUMMY credential of the right shape, so its CLI starts and sends requests; it
// talks plain HTTP to this proxy (ANTHROPIC_BASE_URL / codex provider base_url). For each request:
//
//   1. refuse anything that is not an origin-form request to an allowlisted (method, path) route:
//      CONNECT, absolute-form targets (forward-proxy use), upgrades (websocket), other paths;
//   2. refuse unless every box-marker header carries EXACTLY the dummy value this run issued;
//   3. strip every auth-bearing header the box sent (Authorization, x-api-key, cookies, account and
//      organization ids, proxy auth) and every hop-by-hop header; never merge: the real values are
//      SET afterwards, once each;
//   4. forward over TLS to the exact host in the mounted allowlist (one host, port 443), certificate
//      verification on (Node's bundled roots, or a CA file in a test config), SNI = that host, the
//      box's Host header ignored;
//   5. scrub the real credential values out of the response headers and body before the box sees
//      them (identity encoding is forced upstream so the body can be scanned; set-cookie is dropped);
//   6. log one JSON line per request to stdout: decision, reason, route, status, bytes, TLS facts.
//      The first line states the sha256 of this file, the config and the allowlist AS THIS PROCESS
//      READ THEM, so the host can compare the proxy's own view with the frozen contract.
//
// The credential arrives after start over `docker exec -i <proxy> node /opt/credproxy/credproxy.js
// put` (stdin, never an env var, so never in `docker inspect`), lands in a 0600 file on this
// container's tmpfs, is read once into memory and the file is unlinked.
"use strict";
const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const https = require("https");
const { Transform } = require("stream");

const CONFIG = process.env.CREDPROXY_CONFIG || "/etc/credproxy/config.json";
const ALLOW = process.env.CREDPROXY_ALLOWLIST || "/etc/credproxy/allowlist.txt";
const CRED_FILE = process.env.CREDPROXY_CRED || "/run/credproxy/cred.json";

const sha256 = (b) => crypto.createHash("sha256").update(b).digest("hex");
const out = (o) => process.stdout.write(JSON.stringify({ ts: new Date().toISOString(), ...o }) + "\n");

if (process.argv[2] === "put") {
  // stdin = {"set": {header: real value}, "box": {header: dummy value}}; written 0600, read once.
  const chunks = [];
  process.stdin.on("data", (c) => chunks.push(c));
  process.stdin.on("end", () => {
    const body = Buffer.concat(chunks);
    JSON.parse(body.toString("utf8")); // refuse garbage before writing anything
    fs.writeFileSync(CRED_FILE + ".tmp", body, { mode: 0o600 });
    fs.renameSync(CRED_FILE + ".tmp", CRED_FILE);
  });
  return;
}

const codeBytes = fs.readFileSync(__filename);
const confBytes = fs.readFileSync(CONFIG);
const allowBytes = fs.readFileSync(ALLOW);
const conf = JSON.parse(confBytes.toString("utf8"));
const hosts = allowBytes.toString("utf8").split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
if (hosts.length !== 1 || !/^[a-z0-9.-]+$/.test(hosts[0])) {
  out({ event: "fatal", reason: "allowlist must hold exactly one host name" });
  process.exit(2);
}
const UPSTREAM = hosts[0];
const PORT = conf.upstream_port || 443;
const ROUTES = new Set((conf.routes || []).map(([m, p]) => `${m} ${p}`));
// Auxiliary client requests the contract pins as expected but not needed: answered 404 HERE, never
// forwarded, and logged as "declined" (distinct from "denied", which is anything unexpected).
const DECLINE = new Set((conf.decline_routes || []).map(([m, p]) => `${m} ${p}`));
const MAX_BODY = conf.max_request_bytes || 32 * 1024 * 1024;
// Every request header that can carry auth or identity, plus hop-by-hop headers. Prefix entries end with '*'.
const STRIP = (conf.strip_headers || []).map((h) => h.toLowerCase());
const HOP = ["connection", "keep-alive", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade",
             "host", "content-length", "accept-encoding", "expect"];
const stripped = (name) => HOP.includes(name) || STRIP.some((s) => (s.endsWith("*") ? name.startsWith(s.slice(0, -1)) : name === s));
const caFile = conf.ca_file ? fs.readFileSync(conf.ca_file) : undefined;
const agent = new https.Agent({ keepAlive: true, maxSockets: 8, ca: caFile, servername: UPSTREAM, rejectUnauthorized: true });

out({ event: "start", code_sha256: sha256(codeBytes), config_sha256: sha256(confBytes), allowlist_sha256: sha256(allowBytes),
      family: conf.family, upstream: `${UPSTREAM}:${PORT}`, routes: [...ROUTES].sort(), declined: [...DECLINE].sort(), test_ca: Boolean(caFile),
      tls_verify: true, node: process.version });

let cred = null; // {set: {...}, box: {...}}
function loadCred() {
  if (cred) return true;
  try {
    const c = JSON.parse(fs.readFileSync(CRED_FILE, "utf8"));
    fs.unlinkSync(CRED_FILE);
    if (!c.set || !c.box || !Object.keys(c.set).length || !Object.keys(c.box).length) return false;
    cred = { set: lower(c.set), box: lower(c.box) };
    cred.secrets = Object.values(cred.set).map((v) => String(v)).filter((v) => v.length >= 16);
    // also each bare token value after a scheme ("Bearer X" -> X), so a reflected bare token is scrubbed too
    for (const v of [...cred.secrets]) { const m = /^\S+\s+(\S{16,})$/.exec(v); if (m) cred.secrets.push(m[1]); }
    cred.secrets.sort((a, b) => b.length - a.length);
    out({ event: "credential_loaded", set_headers: Object.keys(cred.set).sort(), box_marker_headers: Object.keys(cred.box).sort() });
    return true;
  } catch (e) {
    return false;
  }
}
const lower = (o) => Object.fromEntries(Object.entries(o).map(([k, v]) => [k.toLowerCase(), String(v)]));

function scrubString(s, counter) {
  let r = s;
  for (const v of cred.secrets) {
    if (r.includes(v)) { counter.n += r.split(v).length - 1; r = r.split(v).join("[scrubbed]"); }
  }
  return r;
}

// Streaming scrub: holds back (longest secret - 1) bytes so a value split across chunks is still caught.
class Scrub extends Transform {
  constructor(counter) { super(); this.counter = counter; this.carry = ""; this.keep = Math.max(0, ...cred.secrets.map((s) => s.length)) - 1; }
  _transform(chunk, _enc, cb) {
    const s = scrubString(this.carry + chunk.toString("latin1"), this.counter);
    const cut = Math.max(0, s.length - this.keep);
    this.carry = s.slice(cut);
    cb(null, Buffer.from(s.slice(0, cut), "latin1"));
  }
  _flush(cb) { cb(null, Buffer.from(scrubString(this.carry, this.counter), "latin1")); }
}

function deny(req, res, status, reason, extra = {}) {
  out({ event: "request", decision: "denied", reason, client: req.socket.remoteAddress, method: req.method,
        path: String(req.url).slice(0, 200), status, ...extra });
  res.writeHead(status, { "content-type": "application/json", connection: "close" });
  res.end(JSON.stringify({ error: { type: "scout_credproxy_denied", reason } }));
}

const server = http.createServer((req, res) => {
  if (req.method === "CONNECT") return deny(req, res, 405, "connect_refused");
  if (!String(req.url).startsWith("/")) return deny(req, res, 400, "absolute_form_refused");
  const path = String(req.url).split("?")[0];
  if (DECLINE.has(`${req.method} ${path}`)) {
    out({ event: "request", decision: "declined", reason: "pinned_auxiliary_route", client: req.socket.remoteAddress,
          method: req.method, path: path.slice(0, 200), status: 404 });
    res.writeHead(404, { "content-type": "application/json" });
    return res.end(JSON.stringify({ error: { type: "scout_credproxy_declined" } }));
  }
  if (!ROUTES.has(`${req.method} ${path}`)) return deny(req, res, 403, "route_not_allowlisted");
  if (!loadCred()) return deny(req, res, 503, "credential_not_loaded");
  for (const [h, v] of Object.entries(cred.box)) {
    const got = req.headers[h];
    if (typeof got !== "string" || got.length !== v.length ||
        !crypto.timingSafeEqual(Buffer.from(got), Buffer.from(v))) return deny(req, res, 403, "box_marker_mismatch", { header: h });
  }
  const chunks = [];
  let n = 0, tooBig = false;
  req.on("data", (c) => { n += c.length; if (n > MAX_BODY) { tooBig = true; req.destroy(); } else chunks.push(c); });
  req.on("end", () => {
    if (tooBig) return;
    const body = Buffer.concat(chunks);
    const headers = {};
    const strippedNames = [];
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      const name = req.rawHeaders[i].toLowerCase();
      if (stripped(name) || Object.prototype.hasOwnProperty.call(cred.set, name)) { strippedNames.push(name); continue; }
      headers[name] = headers[name] === undefined ? req.rawHeaders[i + 1] : `${headers[name]}, ${req.rawHeaders[i + 1]}`;
    }
    for (const [h, v] of Object.entries(cred.set)) headers[h] = v; // set once, after the strip: never merged
    headers["host"] = UPSTREAM;
    headers["accept-encoding"] = "identity";
    headers["content-length"] = String(body.length);
    const counter = { n: 0 };
    const t0 = Date.now();
    const up = https.request({ host: UPSTREAM, port: PORT, method: req.method, path: req.url, headers, agent,
                               servername: UPSTREAM, ca: caFile, rejectUnauthorized: true }, (ur) => {
      const sock = ur.socket;
      const peer = sock.getPeerCertificate ? sock.getPeerCertificate() : {};
      const rh = {};
      for (let i = 0; i < ur.rawHeaders.length; i += 2) {
        const name = ur.rawHeaders[i].toLowerCase();
        if (HOP.includes(name) || name === "set-cookie" || name === "content-length" || name === "content-encoding") continue;
        rh[name] = scrubString(ur.rawHeaders[i + 1], counter);
      }
      res.writeHead(ur.statusCode, rh);
      ur.pipe(new Scrub(counter)).pipe(res);
      ur.on("end", () => out({ event: "request", decision: "forwarded", client: req.socket.remoteAddress, method: req.method,
                               path: path.slice(0, 200), upstream: `${UPSTREAM}:${PORT}`, status: ur.statusCode,
                               req_bytes: body.length, ms: Date.now() - t0, stripped_headers: [...new Set(strippedNames)].sort(),
                               set_headers: Object.keys(cred.set).sort(), scrubbed: counter.n,
                               tls: { authorized: sock.authorized === true, servername: UPSTREAM,
                                      peer_cn: peer && peer.subject ? peer.subject.CN : null,
                                      peer_fingerprint256: peer ? peer.fingerprint256 : null } }));
    });
    up.on("error", (e) => {
      out({ event: "request", decision: "upstream_error", client: req.socket.remoteAddress, method: req.method,
            path: path.slice(0, 200), upstream: `${UPSTREAM}:${PORT}`, error: e.code || e.name });
      if (!res.headersSent) { res.writeHead(502, { "content-type": "application/json" }); }
      res.end(JSON.stringify({ error: { type: "scout_credproxy_upstream_error", code: e.code || e.name } }));
    });
    up.end(body);
  });
});
server.on("upgrade", (req, sock) => {
  out({ event: "request", decision: "denied", reason: "upgrade_refused", client: sock.remoteAddress, method: req.method,
        path: String(req.url).slice(0, 200), status: 403 });
  sock.end("HTTP/1.1 403 Forbidden\r\nconnection: close\r\ncontent-length: 0\r\n\r\n");
});
server.on("connect", (req, sock) => {
  out({ event: "request", decision: "denied", reason: "connect_refused", client: sock.remoteAddress, method: "CONNECT",
        path: String(req.url).slice(0, 200), status: 405 });
  sock.end("HTTP/1.1 405 Method Not Allowed\r\nconnection: close\r\ncontent-length: 0\r\n\r\n");
});
server.requestTimeout = 0;
server.timeout = 0;
server.keepAliveTimeout = 5000;
server.listen(conf.listen_port || 8080, "0.0.0.0", () => out({ event: "listening", port: conf.listen_port || 8080 }));
process.on("SIGTERM", () => process.exit(0));
