"use strict";
const crypto = require("node:crypto");
const dns = require("node:dns/promises");
const devices = require("./account-devices");
const {validateUsername} = require("./policy");
const RESERVED = new Set(["www", "api", "admin", "mail", "hosting", "support", "status", "cdn", "assets", "ns1", "ns2"]);
function reject(message, statusCode = 400) { throw Object.assign(new Error(message), {statusCode}); }
function slug(value) {
  const text = String(value || "").toLowerCase();
  if (!/^[a-z0-9][a-z0-9-]{1,18}[a-z0-9]$/.test(text) || RESERVED.has(text)) reject("Choose a unique 3–20 character address: letters, numbers and internal hyphens.");
  validateUsername(text.replace(/-/g, "_"));
  return text;
}
function automaticApproval(accountId, customDomain, hmac) {
  // Stable per account, not per submission: retries cannot reroll the review sample.
  return !customDomain && parseInt(hmac(`hosting-review-v1:${accountId}`).slice(0,8),16) / 0x100000000 < 0.9;
}
function domain(value) {
  const text = String(value || "").trim().toLowerCase();
  if (!text) return "";
  if (text.length > 253 || !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(text) || text === "scriptnovaa.com" || text.endsWith(".scriptnovaa.com")) reject("Enter a public custom hostname you own, without https:// or a path. Use a subdomain such as play.example.com.");
  return text;
}
function activeSession(session, account, device, token, sessionId, now) {
  return Boolean(session?.product === "galaxy" && session.status === "ACTIVE" && session.expiresAt > now && session.leaseExpiresAt > now &&
    account && (account.accountStatus || "ACTIVE") === "ACTIVE" && account.activeSessionId === sessionId && devices.ids(account).includes(session.deviceId) &&
    device?.status === "ACTIVE" && device.accountId === session.accountId && token?.status === "ACTIVE" && token.sessionId === sessionId && token.ownerAccountId === session.accountId);
}
module.exports = function mount(app, deps) {
  const {route, requireAccount, requireAdmin, root, read, atomic, rateLimit, adminAudit, hmac} = deps;
  const enabled = () => process.env.HOSTING_ENABLED === "true" && String(process.env.HOSTING_GATEWAY_SECRET || "").length >= 32 && Boolean(process.env.HOSTING_TARGET_DOMAIN);
  function records(site) {
    return site.customDomain ? [
      {type: "TXT", name: `_scriptnovaa.${site.customDomain}`, value: `scriptnovaa-verification=${site.verificationToken}`},
      {type: "CNAME", name: site.customDomain, value: process.env.HOSTING_TARGET_DOMAIN || "Not configured by ScriptNovaa yet"},
    ] : [];
  }
  app.get("/api/developer/portal", route(async (req, res) => {
    const user = await requireAccount(req);
    const [requests, site, admin] = await Promise.all([read(`programRequests/${user.id}`), read(`hostingSites/${user.id}`), read(`administrators/${user.id}`)]);
    res.json({ok: true, username: user.data.username, requests: requests || {}, site: site ? {...site, dns: records(site)} : null,
      hostingEnabled: enabled(), administrator: admin?.active === true && String(admin.role).toUpperCase() === "ADMIN"});
  }));
  app.post("/api/developer/requests", route(async (req, res) => {
    const user = await requireAccount(req); await rateLimit(user.id, "program-request", 6, 86400);
    const type = String(req.body.type || "").toUpperCase();
    const message = String(req.body.message || "").trim();
    if (!["BETA", "DEVELOPER", "SPONSORSHIP"].includes(type) || message.length < 30 || message.length > 3000) reject("Choose a request type and describe your proposal in 30–3000 characters.");
    await atomic(data => {
      data.programRequests ||= {}; data.programRequests[user.id] ||= {};
      const old = data.programRequests[user.id][type];
      if (old?.status === "PENDING" || old?.status === "APPROVED") reject("You already have a pending or approved request of this type.", 409);
      data.programRequests[user.id][type] = {type, accountId: user.id, username: user.data.username, message, status: "PENDING", createdAt: Date.now()};
      return data;
    });
    res.json({ok: true});
  }));
  app.get("/api/admin/program-requests", route(async (req, res) => {
    await requireAdmin(req, "ADMIN");
    const [requests, sites] = await Promise.all([read("programRequests"), read("hostingSites")]);
    res.json({ok: true, requests: Object.values(requests || {}).flatMap(x => Object.values(x)).sort((a,b) => b.createdAt-a.createdAt).slice(0, 200), sites: Object.values(sites || {}).slice(0, 200)});
  }));
  app.post("/api/admin/program-review", route(async (req, res) => {
    const admin = await requireAdmin(req, "ADMIN");
    const {accountId, type, decision} = req.body;
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(String(accountId || "")) || !["BETA", "DEVELOPER", "SPONSORSHIP"].includes(type)) reject("Invalid review target.");
    const reason = String(req.body.reason || "").trim();
    if (!["APPROVED", "DECLINED"].includes(decision) || reason.length < 8 || reason.length > 500) reject("Give an approval or decline decision and an 8–500 character reason.");
    await atomic(data => {
      const item = data.programRequests?.[accountId]?.[type];
      const account = data.accounts?.[accountId];
      if (!item || !account || item.status !== "PENDING") reject("This pending application no longer exists.", 409);
      Object.assign(item, {status: decision, reason, reviewedBy: admin.id, reviewedAt: Date.now()});
      if (decision === "APPROVED" && type === "BETA") account.betaProgramStatus = "ACTIVE";
      if (decision === "APPROVED" && type === "DEVELOPER") {account.developerProgramStatus = "APPROVED"; account.betaProgramStatus = "ACTIVE";}
      data.adminAuditLog ||= {}; data.adminAuditLog[crypto.randomBytes(16).toString("hex")] = {administratorAccountId: admin.id, action: "PROGRAM_REVIEW", targetAccountId: accountId, detail: {type, decision, reason}, createdAt: Date.now()};
      return data;
    }); res.json({ok: true});
  }));
  app.post("/api/developer/site", route(async (req, res) => {
    const user = await requireAccount(req); await rateLimit(user.id, "hosting-site", 5, 86400);
    const name = slug(req.body.slug), customDomain = domain(req.body.customDomain);
    const verificationToken = crypto.randomBytes(24).toString("hex");
    await atomic(data => {
      const approved = data.programRequests?.[user.id];
      if (approved?.DEVELOPER?.status !== "APPROVED" && approved?.SPONSORSHIP?.status !== "APPROVED" && user.data.developerProgramStatus !== "APPROVED") reject("Developer or sponsorship approval is required first.", 403);
      data.hostingSites ||= {};
      if (data.hostingSites[user.id]) reject("A site is already reserved. Contact support to change its domain.", 409);
      if (Object.values(data.hostingSites).some(s => s.slug === name || (customDomain && s.customDomain === customDomain))) reject("That address is already reserved.", 409);
      const autoApproved = automaticApproval(user.id, customDomain, hmac);
      const ready = enabled() && process.env.HOSTING_FIRST_PARTY_READY === "true";
      data.hostingSites[user.id] = {accountId: user.id, username: user.data.username, slug: name, customDomain, verificationToken, domainVerifiedAt: 0,
        status: autoApproved ? (ready ? "ACTIVE" : "APPROVED") : "PENDING", autoApproved,
        reviewReason: autoApproved ? "Automatically approved after name-policy checks. Activation requires configured first-party hosting." : "Selected for administrator review.",
        template: "scriptnovaa-demo", createdAt: Date.now()};
      return data;
    }); res.json({ok: true});
  }));
  app.post("/api/developer/domain/verify", route(async (req, res) => {
    const user = await requireAccount(req); await rateLimit(user.id, "hosting-dns", 10, 3600);
    const site = await read(`hostingSites/${user.id}`);
    if (!site?.customDomain || !process.env.HOSTING_TARGET_DOMAIN) reject("A custom domain and configured hosting target are required.");
    const [txt, names] = await Promise.all([dns.resolveTxt(`_scriptnovaa.${site.customDomain}`).catch(() => []), dns.resolveCname(site.customDomain).catch(() => [])]);
    if (!txt.some(x => x.join("") === `scriptnovaa-verification=${site.verificationToken}`) || !names.some(x => x.toLowerCase().replace(/\.$/, "") === process.env.HOSTING_TARGET_DOMAIN.toLowerCase().replace(/\.$/, ""))) reject("DNS does not match yet. Add both records and allow time for DNS propagation.");
    await root.child(`hostingSites/${user.id}/domainVerifiedAt`).set(Date.now());
    res.json({ok: true});
  }));
  app.post("/api/admin/hosting-review", route(async (req, res) => {
    const admin = await requireAdmin(req, "ADMIN");
    const {accountId, decision} = req.body; const reason = String(req.body.reason || "").trim();
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(String(accountId || ""))) reject("Invalid review target.");
    if (!["ACTIVE", "DECLINED", "SUSPENDED"].includes(decision) || reason.length < 8 || reason.length > 500) reject("Choose a hosting decision and include an 8–500 character reason.");
    await atomic(data => {
      const site = data.hostingSites?.[accountId]; if (!site) reject("Site not found.", 404);
      if (decision === "ACTIVE" && (!enabled() || (site.customDomain && (!site.domainVerifiedAt || Date.now()-site.domainVerifiedAt > 86400000)) || req.body.tlsReady !== true)) reject("Configure hosting, verify custom DNS within the last 24 hours and confirm that this site's HTTPS certificate and routing are ready before activation.");
      Object.assign(site, {status: decision, reviewReason: reason, reviewedAt: Date.now(), reviewedBy: admin.id});
      return data;
    });
    await adminAudit(admin, "HOSTING_REVIEW", accountId, {decision, reason}); res.json({ok: true});
  }));
  async function sessionCheck(sessionId) {
    const session = await read(`sessions/${sessionId}`);
    if (!session) reject("Start an active Galaxy session first.", 403);
    const [account, device, token] = await Promise.all([read(`accounts/${session.accountId}`), read(`devices/${session.deviceId}`), read(`tokens/${session.tokenId}`)]);
    if (!activeSession(session, account, device, token, sessionId, Date.now())) reject("Galaxy access expired, ended, or was revoked.", 403);
    return session;
  }
  app.post("/api/hosting/launch", route(async (req, res) => {
    const user = await requireAccount(req); await rateLimit(user.id, "hosting-launch", 30, 3600);
    if (!enabled()) reject("Managed hosting is awaiting deployment.", 503);
    const name = slug(req.body.slug); const sites = await read("hostingSites");
    const site = Object.values(sites || {}).find(x => x.slug === name && x.status === "ACTIVE");
    if (!site) reject("This site is not available.", 404);
    const sessionId = user.data.activeSessionId;
    if (!sessionId) reject("Start an active Galaxy session first.", 403);
    const session = await sessionCheck(sessionId);
    if (session.accountId !== user.id) reject("Session ownership mismatch.", 403);
    const host = site.customDomain || `${site.slug}.scriptnovaa.com`;
    const payload = Buffer.from(JSON.stringify({sessionId, siteId: site.accountId, host, expiresAt: session.expiresAt})).toString("base64url");
    res.json({ok: true, url: `https://${host}/#access=${payload}.${hmac(`hosting:${payload}`)}`});
  }));
  app.post("/api/hosting/render", route(async (req, res) => {
    const supplied = String(req.headers["x-hosting-key"] || ""), expected = process.env.HOSTING_GATEWAY_SECRET || "";
    if (!enabled() || !expected || supplied.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(supplied), Buffer.from(expected))) reject("Hosting gateway authorization required.", 403);
    const raw = String(req.body.access || ""); if (raw.length > 2000) reject("Invalid access.", 403);
    const [payload, signature, extra] = raw.split(".");
    if (extra || !signature || signature !== hmac(`hosting:${payload}`)) reject("Invalid access.", 403);
    let grant; try {grant = JSON.parse(Buffer.from(payload, "base64url").toString());} catch {reject("Invalid access.", 403);}
    if (grant.expiresAt <= Date.now() || grant.host !== req.body.host) reject("Access expired or belongs to another domain.", 403);
    await rateLimit(grant.sessionId, "hosting-render", 120, 60);
    const site = await read(`hostingSites/${grant.siteId}`);
    const owner = site && await read(`accounts/${site.accountId}`);
    if (!site || site.status !== "ACTIVE" || !owner || (owner.accountStatus || "ACTIVE") !== "ACTIVE" || grant.host !== (site.customDomain || `${site.slug}.scriptnovaa.com`)) reject("Site is unavailable.", 403);
    const session = await sessionCheck(grant.sessionId);
    res.json({ok: true, site: {slug: site.slug, username: site.username}, startedAt: session.startedAt, expiresAt: session.expiresAt, serverNow: Date.now()});
  }));
};
module.exports.slug = slug;
module.exports.domain = domain;
module.exports.activeSession = activeSession;
module.exports.automaticApproval = automaticApproval;
