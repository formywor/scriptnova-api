import crypto from "crypto";
import { getRedis } from "./_redis.js";

function cors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
}

function b64urlEncodeUtf8(str) {
  return Buffer.from(String(str), "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function signToken(payloadObj, secret) {
  const payloadJson = JSON.stringify(payloadObj);
  const payloadB64 = b64urlEncodeUtf8(payloadJson);
  const sig = crypto.createHmac("sha256", secret).update(payloadB64).digest();
  const sigB64 = sig
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
  return payloadB64 + "." + sigB64;
}

function getLicenseList() {
  return (process.env.LICENSES || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function getJsonBody(req) {
  try {
    if (!req.body) return {};
    if (typeof req.body === "string") return JSON.parse(req.body);
    return req.body;
  } catch {
    return {};
  }
}

function readLicense(req) {
  if (req.method === "GET") return (req.query.license || "").toString().trim();
  const b = getJsonBody(req);
  return (b.license || "").toString().trim();
}

function planForLicense(license) {
  return license.startsWith("PRO-") ? "pro" : "basic";
}

function sessionLimitForPlan(plan) {
  return plan === "pro" ? 4 : 2;
}

function ttlSecondsForPlan(plan) {
  return plan === "pro" ? (118 * 60 * 60) : (32 * 60);
}

function makeSessionId() {
  return crypto.randomBytes(18).toString("hex");
}

async function cleanupExpiredSessions(redis, key, nowSec) {
  const map = await redis.hgetall(key);
  if (!map) return;

  const entries = Object.entries(map);
  for (const [sid, expStr] of entries) {
    const exp = parseInt(expStr, 10) || 0;
    if (exp <= nowSec) {
      await redis.hdel(key, sid);
    }
  }
}

async function countActiveSessions(redis, key, nowSec) {
  const map = await redis.hgetall(key);
  if (!map) return 0;

  let count = 0;
  const entries = Object.entries(map);
  for (const [, expStr] of entries) {
    const exp = parseInt(expStr, 10) || 0;
    if (exp > nowSec) count++;
  }
  return count;
}

export default async function handler(req, res) {
  cors(res);
  if (req.method === "OPTIONS") return res.status(204).end();

  const secret = (process.env.SECRET_SALT || "").toString();
  if (!secret || secret.length < 16) {
    return res.status(500).json({ ok: false, error: "server_misconfigured_secret" });
  }

  const license = readLicense(req);
  const list = getLicenseList();
  if (!license || !list.includes(license)) {
    return res.status(200).json({ ok: false, plan: "none" });
  }

  let redis;
  try {
    redis = getRedis();
  } catch {
    return res.status(500).json({ ok: false, error: "redis_not_configured" });
  }

  const plan = planForLicense(license);
  const limit = sessionLimitForPlan(plan);
  const ttl = ttlSecondsForPlan(plan);

  const now = Math.floor(Date.now() / 1000);
  const exp = now + ttl;

  const sessionKey = `sn:sessions:${license}`;

  await cleanupExpiredSessions(redis, sessionKey, now);

  const active = await countActiveSessions(redis, sessionKey, now);
  if (active >= limit) {
    return res.status(429).json({
      ok: false,
      plan,
      error: "too_many_sessions",
      active,
      limit
    });
  }

  const sessionId = makeSessionId();

  await redis.hset(sessionKey, { [sessionId]: String(exp) });
  // keep the hash alive a bit longer than TTL
  await redis.expire(sessionKey, ttl + 120);

  const token = signToken({ lic: license, plan, exp, sid: sessionId }, secret);

  return res.status(200).json({
    ok: true,
    plan,
    token,
    exp,
    sessionId,
    ttlSeconds: ttl
  });
}