const { getRedis } = require("./_redis");
const { rateLimit } = require("./_rate");

const BUILD = "sn-hard-2026-03-09-admin1";

function cors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
}

function getLicenseList() {
  return (process.env.LICENSES || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function freeKeyRedisKey(freeKey) {
  return "sn:freekey:" + String(freeKey);
}

function customKeyRedisKey(license) {
  return "sn:custom:" + String(license);
}

function disabledKeyRedisKey(license) {
  return "sn:disabled:" + String(license);
}

function globalKey(name) {
  return "sn:global:" + String(name);
}

function safeJsonParse(v, fallback) {
  try {
    if (v == null) return fallback;
    if (typeof v === "object") return v;
    return JSON.parse(String(v));
  } catch {
    return fallback;
  }
}

function toInt(v, dflt) {
  const n = parseInt(v, 10);
  return Number.isFinite(n) ? n : dflt;
}

function inferPlan(lic) {
  lic = String(lic || "").trim().toUpperCase();
  if (lic.indexOf("FREE-") === 0) return "free";
  if (lic.indexOf("PRO-") === 0) return "pro";
  return "basic";
}

function defaultTtlForPlan(plan) {
  if (plan === "free") return 15 * 60;
  if (plan === "pro") return 118 * 60 * 60;
  return 32 * 60;
}

module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "GET") {
    return res.status(405).json({ ok: false, error: "method_not_allowed", build: BUILD });
  }

  const rl = await rateLimit(req, "check", 120, 60);
  if (!rl.ok) {
    res.setHeader("Retry-After", String(rl.retryAfter));
    return res.status(429).json({
      ok: false,
      error: "rate_limited",
      retryAfter: rl.retryAfter,
      build: BUILD
    });
  }

  const lic = String(req.query.license || "").trim();
  if (!lic) {
    return res.status(200).json({ ok: false, plan: "none", build: BUILD });
  }

  let redis;
  try {
    redis = getRedis();
  } catch {
    return res.status(500).json({ ok: false, error: "redis_not_configured", build: BUILD });
  }

  // Global disable-all switch
  try {
    const disableAll = await redis.get(globalKey("disable_all"));
    if (disableAll) {
      return res.status(200).json({
        ok: false,
        error: "all_keys_disabled",
        plan: "none",
        build: BUILD
      });
    }
  } catch {}

  // Per-key disable
  try {
    const disabled = await redis.get(disabledKeyRedisKey(lic));
    if (disabled) {
      return res.status(200).json({
        ok: false,
        error: "key_disabled",
        plan: "none",
        build: BUILD
      });
    }
  } catch {}

  // Custom keys first
  try {
    const customRaw = await redis.get(customKeyRedisKey(lic));
    if (customRaw) {
      const custom = safeJsonParse(customRaw, null);
      if (custom && typeof custom === "object") {
        const plan = String(custom.plan || inferPlan(lic)).trim().toLowerCase();
        const ttlSeconds = toInt(custom.ttlSeconds, defaultTtlForPlan(plan));
        const exp = toInt(custom.exp, 0);

        if (exp > 0) {
          const now = Math.floor(Date.now() / 1000);
          if (exp <= now) {
            return res.status(200).json({
              ok: false,
              error: "key_expired",
              plan: "none",
              build: BUILD
            });
          }
        }

        return res.status(200).json({
          ok: true,
          plan,
          ttlSeconds,
          source: "custom",
          build: BUILD
        });
      }
    }
  } catch {}

  // FREE keys: stored in Redis only
  if (lic.indexOf("FREE-") === 0) {
    const raw = await redis.get(freeKeyRedisKey(lic));
    if (!raw) {
      return res.status(200).json({ ok: false, plan: "none", build: BUILD });
    }

    return res.status(200).json({
      ok: true,
      plan: "free",
      ttlSeconds: 900,
      source: "free",
      build: BUILD
    });
  }

  // BASIC/PRO keys: env LICENSES list
  const list = getLicenseList();
  if (!list.includes(lic)) {
    return res.status(200).json({ ok: false, plan: "none", build: BUILD });
  }

  const plan = lic.indexOf("PRO-") === 0 ? "pro" : "basic";
  const ttlSeconds = plan === "pro" ? (118 * 60 * 60) : (32 * 60);

  return res.status(200).json({
    ok: true,
    plan,
    ttlSeconds,
    source: "env",
    build: BUILD
  });
};