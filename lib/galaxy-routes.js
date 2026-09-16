"use strict";

const galaxy = require("./galaxy");

module.exports = function mountGalaxy(app, deps) {
  const {route, requireAccount, root, read, atomic, hmac, rateLimit, fail, requireVersion} = deps;

  async function paired(req) {
    requireVersion(req);
    const account = await requireAccount(req);
    const device = await read(`devices/${account.data.registeredDeviceId || "missing"}`);
    if (!device || device.status !== "ACTIVE" || device.accountId !== account.id ||
        device.deviceHash !== hmac(req.body.deviceProof || "")) {
      fail("Connect this computer to your account first.", 403, "GALAXY_DEVICE_REQUIRED");
    }
    return account;
  }

  function timing(id, session, now) {
    return {sessionId: id, expiresAt: new Date(session.expiresAt).toISOString(),
      remainingSeconds: Math.max(0, Math.floor((session.expiresAt - now) / 1000)),
      heartbeatSeconds: 10, accessMode: session.accessMode};
  }

  app.get("/api/galaxy/config", route(async (req, res) => {
    requireVersion(req);
    res.json({ok: true, configuration: galaxy.configuration()});
  }));

  app.post("/api/galaxy/status", route(async (req, res) => {
    const account = await paired(req);
    res.json({ok: true, connected: true, accountId: account.id,
      username: account.data.username, configuration: galaxy.configuration()});
  }));

  app.post("/api/galaxy/session/activate", route(async (req, res) => {
    const account = await paired(req);
    await rateLimit(account.id, "GALAXY_START", 20, 3600);
    const requestId = String(req.body.requestId || "");
    if (!/^[a-f0-9]{32}$/.test(requestId)) fail("Invalid start request.");
    const sessionId = "galaxy_" + hmac(`${account.id}:${requestId}`).slice(0, 40);
    const secret = hmac(`galaxy-session:${account.id}:${requestId}`);
    const webSecret = hmac(`galaxy-web:${account.id}:${requestId}`);
    const webAccess = `${sessionId}.${webSecret}`;
    const lockedAt = Date.now();
    const lockRef = root.child(`sessionActivationLocks/${account.id}`);
    const lock = await lockRef.transaction((current) => {
      if (current && Number(current.lockedAt || 0) > lockedAt - 30000) return;
      return {activationId: sessionId, lockedAt};
    }, undefined, false);
    if (!lock.committed) fail("A browser session is already starting.", 409);
    let result;
    try {
      result = await atomic((data) => galaxy.activate(data, {
        accountId: account.id,
        deviceHash: hmac(req.body.deviceProof),
        tokenHash: hmac(req.body.token || ""),
        sessionId,
        secretHash: hmac(secret),
        webAccessHash: hmac(webSecret),
        requestId,
        now: Date.now(),
        experience: req.body.experience,
        searchEngine: req.body.searchEngine,
        browser: req.body.browser,
        dataMode: req.body.dataMode,
      }));
    } finally {
      await lockRef.transaction((current) => current?.activationId === sessionId ? null : current);
    }
    const session = result.sessions[sessionId];
    res.json({ok: true, ...timing(sessionId, session, Date.now()),
      sessionSecret: secret, webAccess, configuration: galaxy.configuration(),
      launch: galaxy.launchConfiguration(req.body.searchEngine === "google" ? "https://www.google.com/" :
          req.body.searchEngine === "bing" ? "https://www.bing.com/" :
          `https://api.scriptnovaa.com/search?access=${encodeURIComponent(webAccess)}`)});
  }));

  async function authorize(req, refreshLease = true) {
    const account = await paired(req);
    const sessionId = String(req.body.sessionId || "");
    if (!/^galaxy_[a-f0-9]{40}$/.test(sessionId)) fail("Invalid Galaxy session.", 401);
    const result = await atomic((data) => galaxy.authorize(data, {
      sessionId, accountId: account.id, secretHash: hmac(req.body.sessionSecret || ""),
      deviceHash: hmac(req.body.deviceProof), now: Date.now(), refreshLease,
    }));
    return {account, sessionId, result, session: result.sessions[sessionId]};
  }

  app.post("/api/galaxy/session/heartbeat", route(async (req, res) => {
    const checked = await authorize(req);
    if (checked.session.status !== "ACTIVE") return res.status(409).json({ok: false,
      error: "This Galaxy session has finished. Enter another Galaxy token.",
      reason: checked.session.endReason});
    res.json({ok: true, ...timing(checked.sessionId, checked.session, Date.now())});
  }));

  app.post("/api/galaxy/session/resume", route(async (req, res) => {
    const checked = await authorize(req);
    if (checked.session.status !== "ACTIVE" || checked.session.accessMode !== "multi") {
      fail("This Galaxy session cannot be resumed.", 409);
    }
    const webAccess = String(req.body.webAccess || "");
    const separator = webAccess.indexOf(".");
    const webSessionId = separator > 0 ? webAccess.slice(0, separator) : "";
    const webSecret = separator > 0 ? webAccess.slice(separator + 1) : "";
    if (webSessionId !== checked.sessionId || checked.session.webAccessHash !== hmac(webSecret)) {
      fail("Galaxy web access could not be restored.", 401);
    }
    const startUrl = checked.session.searchEngine === "google" ? "https://www.google.com/" :
      checked.session.searchEngine === "bing" ? "https://www.bing.com/" :
      `https://api.scriptnovaa.com/search?access=${encodeURIComponent(webAccess)}`;
    res.json({ok: true, ...timing(checked.sessionId, checked.session, Date.now()),
      webAccess,
      session: {experience: checked.session.experience, searchEngine: checked.session.searchEngine,
        browser: checked.session.browser, dataMode: checked.session.dataMode},
      launch: galaxy.launchConfiguration(startUrl)});
  }));

  app.post("/api/galaxy/session/end", route(async (req, res) => {
    const account = await requireAccount(req, {allowRestricted: true, allowRecoveryPending: true});
    const sessionId = String(req.body.sessionId || "");
    if (!/^galaxy_[a-f0-9]{40}$/.test(sessionId)) fail("Invalid Galaxy session.", 401);
    const allowedReasons = new Set(["USER_ENDED", "WINDOW_CLOSED", "TIME_EXPIRED",
      "HEARTBEAT_FAILED", "BROWSER_CLOSED", "LAUNCH_FAILED", "AUTHORIZATION_REVOKED"]);
    await atomic((data) => {
      const session = data.sessions?.[sessionId];
      if (!session || session.product !== "galaxy" || session.accountId !== account.id ||
          session.sessionSecretHash !== hmac(req.body.sessionSecret || "")) {
        fail("Session authentication failed.", 401);
      }
      const reason = allowedReasons.has(req.body.reason) ? req.body.reason : "USER_ENDED";
      return galaxy.finish(data, sessionId, reason, Date.now());
    });
    res.json({ok: true});
  }));
};
