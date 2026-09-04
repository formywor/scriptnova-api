"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const mount = require("../lib/project-z-routes");
const z = require("../lib/project-z");
function harness() {
  const hmac = (value) => crypto.createHash("sha256").update(String(value)).digest("hex");
  const data = {accounts: {alice: {username: "alice", accountStatus: "ACTIVE", fraudStatus: "CLEAR", registeredDeviceId: "pc", pointBalance: 2}},
    devices: {pc: {accountId: "alice", status: "ACTIVE", deviceHash: hmac("computer-proof")}}};
  z.purchase(data, {accountId: "alice", tokenId: "tok", tokenHash: hmac("Z-TOKEN"), rawToken: "Z-TOKEN", product: "z",
    option: {hours: 1, minutes: 60, points: 2}, ledgerId: "ledger", now: Date.now()});
  const routes = new Map();
  const read = async (path) => path.split("/").reduce((v, key) => v?.[key], data);
  const child = (path) => ({transaction: async (fn) => {
    const parts = path.split("/"); const key = parts.pop(); let parent = data;
    for (const part of parts) parent = parent[part] ||= {};
    const value = fn(parent[key]); if (value === undefined) return {committed: false};
    parent[key] = value; return {committed: true};
  }});
  const fail = (message, statusCode) => { throw Object.assign(new Error(message), {statusCode}); };
  mount({get: (path, fn) => routes.set("GET " + path, fn), post: (path, fn) => routes.set("POST " + path, fn)}, {
    route: fn => fn, root: {child}, read, hmac, fail, rateLimit: async () => {},
    atomic: async (fn) => fn(data),
    requireVersion: req => { if (req.headers["x-project-z-version"] !== z.VERSION) fail("Update required", 426); },
    requireAccount: async req => {
      if (req.headers.authorization !== "Bearer valid") fail("Authentication required", 401);
      return {id: "alice", data: data.accounts.alice};
    },
  });
  async function call(path, body, headers = {}) {
    const req = {body: body || {}, headers: {authorization: "Bearer valid", "x-project-z-version": z.VERSION, ...headers}};
    let status = 200, response;
    const res = {status: value => { status = value; return res; }, json: value => { response = value; return res; }};
    await routes.get(path)(req, res); return {status, response};
  }
  return {call, data};
}
test("mounted Z routes complete paired start / heartbeat / end without real Firebase", async () => {
  const {call, data} = harness();
  const status = await call("POST /api/z/status", {deviceProof: "computer-proof"}); assert.equal(status.response.username, "alice");
  const body = {token: "Z-TOKEN", deviceProof: "computer-proof", requestId: "f".repeat(32), mode: "privacy", searchEngine: "bing", connection: "direct"};
  const started = (await call("POST /api/z/session/activate", body)).response;
  assert.equal(started.ok, true); assert.equal(started.sessionSecret.length, 64);
  assert.match(started.webAccess, /^z_[a-f0-9]{40}\.[a-f0-9]{64}$/);
  assert.equal((await call("POST /api/z/session/activate", body)).response.sessionId, started.sessionId);
  const credentials = {sessionId: started.sessionId, sessionSecret: started.sessionSecret, deviceProof: "computer-proof"};
  assert.equal((await call("POST /api/z/session/heartbeat", credentials)).response.ok, true);
  await call("POST /api/z/session/end", {...credentials, reason: "USER_ENDED"});
  assert.equal(data.tokens.tok.status, "COMPLETED");
  assert.equal((await call("POST /api/z/session/heartbeat", credentials)).status, 409);
});
test("mounted routes reject old versions, missing auth, and foreign computers", async () => {
  const {call} = harness();
  await assert.rejects(call("GET /api/z/config", null, {"x-project-z-version": "old"}), /Update/);
  await assert.rejects(call("POST /api/z/status", {deviceProof: "computer-proof"}, {authorization: ""}), /Authentication/);
  await assert.rejects(call("POST /api/z/status", {deviceProof: "wrong"}), /computer/);
});
