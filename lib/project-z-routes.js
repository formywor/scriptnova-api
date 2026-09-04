"use strict";
const z = require("./project-z");

module.exports = function mountProjectZ(app, deps) {
  const {route, requireAccount, root, read, atomic, hmac, rateLimit, fail, requireVersion} = deps;
  async function paired(req) {
    requireVersion(req);
    const account = await requireAccount(req);
    const device = await read(`devices/${account.data.registeredDeviceId || "missing"}`);
    if (!device || device.status !== "ACTIVE" || device.accountId !== account.id ||
        device.deviceHash !== hmac(req.body.deviceProof || "")) {
      fail("Connect this computer to your account first.", 403, "Z_DEVICE_REQUIRED");
    }
    return account;
  }
  function timing(session, now) {
    return {sessionId: session.id, expiresAt: new Date(session.expiresAt).toISOString(),
      remainingSeconds: Math.max(0, Math.floor((session.expiresAt - now) / 1000)),
      leaseSeconds: Math.max(0, Math.floor((session.leaseExpiresAt - now) / 1000)),
      heartbeatSeconds: 10};
  }
  app.get("/api/z/config", route(async (req, res) => {
    requireVersion(req);
    res.json({ok: true, configuration: z.configuration()});
  }));
  app.post("/api/z/status", route(async (req, res) => {
    const account = await paired(req);
    res.json({ok: true, connected: true, accountId: account.id, username: account.data.username,
      configuration: z.configuration()});
  }));
  app.post("/api/z/session/activate", route(async (req, res) => {
    const account = await paired(req);
    await rateLimit(account.id, "Z_START", 20, 3600);
    const requestId = String(req.body.requestId || "");
    if (!/^[a-f0-9]{32}$/.test(requestId)) fail("Invalid start request.");
    const sessionId = "z_" + hmac(`${account.id}:${requestId}`).slice(0, 40);
    const secret = hmac(`z-session:${account.id}:${requestId}`);
    const webAccessSecret = hmac(`z-web:${account.id}:${requestId}`);
    const webAccess = `${sessionId}.${webAccessSecret}`;
    const lockedAt = Date.now();
    // Same lock as Share Browser: concurrent launches across products cannot win together.
    const lockRef = root.child(`sessionActivationLocks/${account.id}`);
    const lock = await lockRef.transaction((current) => {
      if (current && Number(current.lockedAt || 0) > lockedAt - 30000) return;
      return {activationId: sessionId, lockedAt};
    }, undefined, false);
    if (!lock.committed) fail("A browser session is already starting.", 409);
    let result;
    try {
      result = await atomic((data) => z.activate(data, {
        accountId: account.id, deviceHash: hmac(req.body.deviceProof), tokenHash: hmac(req.body.token || ""),
        sessionId, secretHash: hmac(secret), webAccessHash: hmac(webAccessSecret), requestId, now: Date.now(),
        mode: req.body.mode, searchEngine: req.body.searchEngine, connection: req.body.connection,
      }));
    } finally {
      await lockRef.transaction((current) => current?.activationId === sessionId ? null : current);
    }
    const session = result.sessions[sessionId];
    res.json({ok: true, ...timing({id: sessionId, ...session}, Date.now()), sessionSecret: secret,
      webAccess});
  }));
  // Heartbeats require BOTH the paired account credential and session secret.
  app.post("/api/z/session/heartbeat", route(async (req, res) => {
    const account = await paired(req);
    const sessionId = String(req.body.sessionId || "");
    if (!/^z_[a-f0-9]{40}$/.test(sessionId)) fail("Invalid session.", 401);
    const result = await atomic((data) => z.heartbeat(data, {sessionId, accountId: account.id,
      secretHash: hmac(req.body.sessionSecret || ""), deviceHash: hmac(req.body.deviceProof), now: Date.now()}));
    const session = result.sessions[sessionId];
    if (session.status !== "ACTIVE") return res.status(409).json({ok: false,
      error: "This Project Z session has finished. Enter another Z token.", reason: session.endReason});
    res.json({ok: true, ...timing({id: sessionId, ...session}, Date.now())});
  }));
  app.post("/api/z/session/end", route(async (req, res) => {
    // Permit end after version changes or restrictions; never permit further browsing.
    const account = await requireAccount(req, {allowRestricted: true, allowRecoveryPending: true});
    const sessionId = String(req.body.sessionId || "");
    if (!/^z_[a-f0-9]{40}$/.test(sessionId)) fail("Invalid session.", 401);
    const reasons = new Set(["USER_ENDED", "WINDOW_CLOSED", "TIME_EXPIRED", "HEARTBEAT_FAILED", "BROWSER_FAILED", "LAUNCH_FAILED"]);
    await atomic((data) => {
      const session = data.sessions?.[sessionId];
      if (!session || session.product !== "z" || session.accountId !== account.id ||
          session.sessionSecretHash !== hmac(req.body.sessionSecret || "")) fail("Session authentication failed.", 401);
      return z.finish(data, sessionId, reasons.has(req.body.reason) ? req.body.reason : "USER_ENDED", Date.now());
    });
    res.json({ok: true});
  }));
};
