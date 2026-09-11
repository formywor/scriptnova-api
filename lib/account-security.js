"use strict";

function safeClient(value) {
  const text = String(value || "Unknown browser").slice(0, 250);
  const browser = /Edg\//.test(text) ? "Microsoft Edge" :
    /Chrome\//.test(text) ? "Google Chrome" :
      /Firefox\//.test(text) ? "Firefox" : /Safari\//.test(text) ? "Safari" : "Browser";
  const system = /Windows/i.test(text) ? "Windows" : /Android/i.test(text) ? "Android" :
    /iPhone|iPad/i.test(text) ? "iPhone or iPad" : /Macintosh/i.test(text) ? "Mac" :
      /Linux/i.test(text) ? "Linux" : "device";
  return `${browser} on ${system}`;
}

function maskNetwork(value) {
  const text = String(value || "unknown");
  if (text === "unknown") return text;
  return text.includes(":") ? `${text}:…` : `${text}.…`;
}

function mountAccountSecurity(app, dependencies) {
  const {route, root, read, id, requireAccount, rateLimit, verifies, credential,
    code, fail, hmac} = dependencies;

  function requirePin(account, pin) {
    if (!verifies(pin, account.data.pinCredential, "PIN_PEPPER")) {
      fail("Enter your current PIN to continue.", 401, "PIN_REAUTH_REQUIRED");
    }
  }

  async function activity(accountId, type, detail = {}) {
    const activityId = id(`accountActivity/${accountId}`);
    await root.child(`accountActivity/${accountId}/${activityId}`).set({
      type, detail, createdAt: Date.now(),
    });
  }

  app.get("/api/account/security", route(async (req, res) => {
    const account = await requireAccount(req);
    const [sessionsValue, activityValue, alertsValue, device] = await Promise.all([
      read("loginSessions"), read(`accountActivity/${account.id}`),
      read(`securityAlerts/${account.id}`), account.data.registeredDeviceId ?
        read(`devices/${account.data.registeredDeviceId}`) : Promise.resolve(null),
    ]);
    const sessions = Object.entries(sessionsValue || {})
        .filter(([, session]) => session.accountId === account.id && session.revoked !== true)
        .map(([sessionId, session]) => ({
          sessionId, current: sessionId === account.loginId,
          client: safeClient(session.clientDescription),
          network: maskNetwork(session.networkPrefix),
          createdAt: Number(session.createdAt || 0),
          lastUsedAt: Number(session.lastUsedAt || 0),
        })).sort((a, b) => b.lastUsedAt - a.lastUsedAt);
    const recentActivity = Object.entries(activityValue || {})
        .map(([activityId, item]) => ({activityId, ...item}))
        .sort((a, b) => Number(b.createdAt || 0) - Number(a.createdAt || 0)).slice(0, 30);
    const alerts = Object.entries(alertsValue || {})
        .map(([alertId, item]) => ({alertId, ...item}))
        .sort((a, b) => Number(b.createdAt || 0) - Number(a.createdAt || 0)).slice(0, 10);
    res.json({ok: true, sessions, recentActivity, alerts,
      device: device ? {deviceId: account.data.registeredDeviceId,
        status: device.status || "UNKNOWN", registeredAt: Number(device.registeredAt || 0),
        lastSeenAt: Number(device.lastSeenAt || 0)} : null});
  }));

  app.post("/api/account/security/signout-all", route(async (req, res) => {
    const account = await requireAccount(req);
    await rateLimit(account.id, "SECURITY_SIGNOUT_ALL", 5, 60 * 60);
    requirePin(account, req.body.pin);
    const sessions = await read("loginSessions") || {};
    const updates = {};
    const now = Date.now();
    Object.entries(sessions).forEach(([sessionId, session]) => {
      if (session.accountId === account.id && session.revoked !== true) {
        updates[`loginSessions/${sessionId}/revoked`] = true;
        updates[`loginSessions/${sessionId}/revokedAt`] = now;
      }
    });
    if (Object.keys(updates).length) await root.update(updates);
    await activity(account.id, "SIGNED_OUT_EVERYWHERE");
    res.json({ok: true});
  }));

  app.post("/api/account/security/sessions/:sessionId/revoke", route(async (req, res) => {
    const account = await requireAccount(req);
    requirePin(account, req.body.pin);
    const sessionId = String(req.params.sessionId || "");
    if (!/^[a-f0-9]{64}$/i.test(sessionId)) fail("Signed-in device not found.", 404);
    const session = await read(`loginSessions/${sessionId}`);
    if (!session || session.accountId !== account.id) fail("Signed-in device not found.", 404);
    await root.child(`loginSessions/${sessionId}`).update({revoked: true, revokedAt: Date.now()});
    await activity(account.id, "SESSION_REVOKED", {client: safeClient(session.clientDescription)});
    res.json({ok: true, currentSessionRevoked: sessionId === account.loginId});
  }));

  app.post("/api/account/security/device/remove", route(async (req, res) => {
    const account = await requireAccount(req);
    await rateLimit(account.id, "SECURITY_DEVICE_REMOVE", 3, 24 * 60 * 60);
    requirePin(account, req.body.pin);
    if (account.data.activeSessionId) fail("End the active browser session before removing this computer.", 409);
    const deviceId = account.data.registeredDeviceId;
    if (!deviceId) return res.json({ok: true, alreadyRemoved: true});
    await root.update({
      [`devices/${deviceId}/status`]: "REVOKED",
      [`devices/${deviceId}/revokedAt`]: Date.now(),
      [`accounts/${account.id}/registeredDeviceId`]: null,
      [`accounts/${account.id}/persistentLauncherPairedAt`]: null,
      [`accounts/${account.id}/updatedAt`]: Date.now(),
    });
    await activity(account.id, "COMPUTER_REMOVED");
    res.json({ok: true});
  }));

  app.post("/api/account/security/recovery/rotate", route(async (req, res) => {
    const account = await requireAccount(req);
    await rateLimit(account.id, "SECURITY_RECOVERY_ROTATE", 3, 24 * 60 * 60);
    requirePin(account, req.body.pin);
    const replacement = code("RCVY", 12);
    await root.child(`accounts/${account.id}`).update({
      recoveryCredential: credential(replacement, "RECOVERY_PEPPER"),
      recoveryPromptRequired: true, recoveryAcknowledgedAt: null,
      recoveryRegeneratedAt: Date.now(), updatedAt: Date.now(),
    });
    await activity(account.id, "RECOVERY_CODE_CHANGED");
    res.json({ok: true, recoveryCode: replacement,
      warning: "The old recovery code no longer works. Save this code now."});
  }));

  app.post("/api/account/security/alerts/:alertId/read", route(async (req, res) => {
    const account = await requireAccount(req);
    const alert = await read(`securityAlerts/${account.id}/${req.params.alertId}`);
    if (!alert) fail("Security alert not found.", 404);
    await root.child(`securityAlerts/${account.id}/${req.params.alertId}`).update({readAt: Date.now()});
    res.json({ok: true});
  }));
}

module.exports = {mountAccountSecurity, safeClient, maskNetwork};
