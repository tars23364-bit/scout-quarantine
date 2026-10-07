#!/usr/bin/env node
// scout deep review, P3 (R3): a FAKE model API for netcheck and canarycheck. Never used by a pair.
// A TLS server (key/cert from /etc/fake, issued by a per-check test CA) that plays just enough of the
// Anthropic Messages API and the ChatGPT codex Responses API for each CLI to finish a turn, and that
// is HOSTILE on purpose: it REFLECTS every auth-bearing header it received into a response header,
// the response body and error bodies, so the check can prove the proxy scrubs the credential before
// the box sees it. It logs, per request, the method, path, Host, header NAMES, and the sha256 (never
// the value) of every auth-bearing header. HOLD_MS delays the first model response so the host can
// scan box and proxy memory while a request is in flight (it logs {"event":"holding"} then).
"use strict";
const crypto = require("crypto");
const fs = require("fs");
const https = require("https");

const HOLD_MS = Number(process.env.HOLD_MS || 0);
let held = false;
const sha = (v) => crypto.createHash("sha256").update(String(v)).digest("hex");
const out = (o) => process.stdout.write(JSON.stringify({ ts: new Date().toISOString(), ...o }) + "\n");
const AUTHY = /^(authorization|proxy-authorization|x-api-key|api-key|cookie|cookie2|chatgpt-account-id|openai-organization|openai-project)$/;

// DRIP=1: write every body 5 bytes at a time with a pause, so a reflected value is split across
// many TCP segments and the proxy's streaming scrub is tested at chunk boundaries.
const DRIP = process.env.DRIP === "1";
function send(res, body) {
  if (!DRIP) return res.end(body);
  const b = Buffer.from(body);
  let i = 0;
  const step = () => { if (i >= b.length) return res.end(); res.write(b.subarray(i, i + 5)); i += 5; setTimeout(step, 1); };
  step();
}
function sse(res, events) {
  res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
  send(res, events.map(([ev, data]) => `event: ${ev}\ndata: ${JSON.stringify(data)}\n\n`).join(""));
}

const KEY = process.env.FAKE_KEY || "/etc/fake/key.pem";
const CERT = process.env.FAKE_CERT || "/etc/fake/cert.pem";
const srv = https.createServer({ key: fs.readFileSync(KEY), cert: fs.readFileSync(CERT) }, (req, res) => {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    const authy = {};
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      const n = req.rawHeaders[i].toLowerCase();
      if (AUTHY.test(n)) (authy[n] = authy[n] || []).push(sha(req.rawHeaders[i + 1]));
    }
    const reflected = Object.entries(req.headers).filter(([k]) => AUTHY.test(k)).map(([k, v]) => `${k}=${v}`).join(" ; ");
    const path = req.url.split("?")[0];
    out({ event: "request", method: req.method, path, host: req.headers.host, header_names: Object.keys(req.headers).sort(),
          auth_sha256: authy, bytes: Buffer.concat(chunks).length });
    const go = () => {
      res.setHeader("x-reflect-auth", reflected);
      if (req.method === "POST" && path === "/v1/messages") {
        const text = `OK. reflected: ${reflected}`;
        return sse(res, [
          ["message_start", { type: "message_start", message: { id: "msg_fake", type: "message", role: "assistant", model: "claude-fake",
            content: [], stop_reason: null, stop_sequence: null, usage: { input_tokens: 1, output_tokens: 1 } } }],
          ["content_block_start", { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } }],
          ["content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text } }],
          ["content_block_stop", { type: "content_block_stop", index: 0 }],
          ["message_delta", { type: "message_delta", delta: { stop_reason: "end_turn", stop_sequence: null }, usage: { output_tokens: 5 } }],
          ["message_stop", { type: "message_stop" }]]);
      }
      if (req.method === "POST" && path === "/backend-api/codex/responses") {
        const text = `OK. reflected: ${reflected}`;
        const usage = { input_tokens: 1, input_tokens_details: { cached_tokens: 0 }, output_tokens: 1,
                        output_tokens_details: { reasoning_tokens: 0 }, total_tokens: 2 };
        return sse(res, [
          ["response.created", { type: "response.created", response: { id: "resp_fake", object: "response", status: "in_progress", output: [] } }],
          ["response.output_item.added", { type: "response.output_item.added", output_index: 0,
            item: { type: "message", id: "msg_fake", role: "assistant", status: "in_progress", content: [] } }],
          ["response.output_text.delta", { type: "response.output_text.delta", item_id: "msg_fake", output_index: 0, content_index: 0, delta: text }],
          ["response.output_item.done", { type: "response.output_item.done", output_index: 0,
            item: { type: "message", id: "msg_fake", role: "assistant", status: "completed",
                    content: [{ type: "output_text", text, annotations: [] }] } }],
          ["response.completed", { type: "response.completed", response: { id: "resp_fake", object: "response", status: "completed",
            output: [], usage } }]]);
      }
      if (req.method === "GET" && path === "/backend-api/codex/models") {
        res.writeHead(200, { "content-type": "application/json" });
        return send(res, JSON.stringify({ models: [], note: `reflected: ${reflected}` }));
      }
      res.writeHead(400, { "content-type": "application/json" });
      send(res, JSON.stringify({ error: { type: "invalid_request_error", message: `unknown path; reflected: ${reflected}` } }));
    };
    const model = path === "/v1/messages" || path === "/backend-api/codex/responses";
    if (HOLD_MS && model && !held) {
      held = true;
      out({ event: "holding", ms: HOLD_MS });
      setTimeout(go, HOLD_MS);
    } else go();
  });
});
srv.listen(Number(process.env.FAKE_PORT || 443), "0.0.0.0", () => out({ event: "listening" }));
process.on("SIGTERM", () => process.exit(0));
