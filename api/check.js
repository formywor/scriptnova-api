const { getRedis } = require("./_redis");
const { rateLimit } = require("./_rate");

const BUILD = "sn-hard-2026-03-20-balance-c";

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
  if (lic.indexOf("BLACKEXP-") === 0 || lic.indexOf("BLACK_EXPRESS-") === 0) return "black_express";
  if (lic.indexOf("EXPRESS-") === 0) return "express";
  if (lic.indexOf("ELITE-") === 0) return "elite";
  if (lic.indexOf("PRO-") === 0) return "pro";
  if (lic.indexOf("BASIC-") === 0) return "basic";

  return "basic";
}

function defaultTtlForPlan(plan) {
  if (plan === "free") return 15 * 60;
  if (plan === "basic") return 6 * 60 * 60;
  if (plan === "pro") return 48 * 60 * 60;
  if (plan === "elite") return 168 * 60 * 60;
  if (plan === "express") return 720 * 60 * 60;
  if (plan === "black_express") return 1800 * 60 * 60;
  return 6 * 60 * 60;
}

function defaultLimitForPlan(plan) {
  if (plan === "free") return 1;
  if (plan === "basic") return 3;
  if (plan === "pro") return 10;
  if (plan === "elite") return 10;
  if (plan === "express") return 725;
  if (plan === "black_express") return 1500;
  return 3;
}

function defaultMaxDevicesForPlan(plan) {
  if (plan === "free") return 1;
  if (plan === "basic") return 2;
  if (plan === "pro") return 10;
  if (plan === "elite") return 6;
  if (plan === "express") return 2;
  if (plan === "black_express") return 12;
  return 2;
}

async function resolveLicense(redis, lic) {
  if (!lic) {
    return { ok: false, error: "invalid_key" };
  }

  try {
    const disableAll = await redis.get(globalKey("disable_all"));
    if (disableAll) {
      return { ok: false, error: "all_keys_disabled" };
    }
  } catch {}

  try {
    const disabled = await redis.get(disabledKeyRedisKey(lic));
    if (disabled) {
      return { ok: false, error: "key_disabled" };
    }
  } catch {}

  try {
    const customRaw = await redis.get(customKeyRedisKey(lic));
    if (customRaw) {
      const custom = safeJsonParse(customRaw, null);
      if (!custom || typeof custom !== "object") {
        return { ok: false, error: "custom_key_invalid" };
      }

      const now = Math.floor(Date.now() / 1000);
      const plan = String(custom.plan || inferPlan(lic)).trim().toLowerCase();
      const configuredTtl = Math.max(1, toInt(custom.ttlSeconds, defaultTtlForPlan(plan)));
      const limit = Math.max(1, toInt(custom.sessionLimit, defaultLimitForPlan(plan)));
      const maxDevices = Math.max(1, toInt(custom.maxDevices, defaultMaxDevicesForPlan(plan)));
      const exp = toInt(custom.exp, 0);

      if (exp > 0 && exp <= now) {
        return { ok: false, error: "key_expired" };
      }

      let ttlSeconds = configuredTtl;
      if (exp > 0) {
        ttlSeconds = Math.max(1, Math.min(configuredTtl, exp - now));
      }

      return {
        ok: true,
        source: "custom",
        kind: "custom",
        plan,
        tier: String(custom.tier || ""),
        ttlSeconds,
        configuredTtlSeconds: configuredTtl,
        limit,
        maxDevices,
        exp
      };
    }
  } catch {}

  if (String(lic).toUpperCase().indexOf("FREE-") === 0) {
    return { ok: false, error: "invalid_key" };
  }

  const allowedKeys = ["PRO-Z", "PRO-SNOVAPROKEY", "PRO-SENG1", "PRO-MH1", "PRO-MH2", "PRO-KOFS"];
  if (!allowedKeys.includes(lic.toUpperCase())) {
    return { ok: false, error: "invalid_key" };
  }

  const plan = inferPlan(lic);
  const ttlSeconds = defaultTtlForPlan(plan);

  return {
    ok: true,
    source: "env",
    kind: "env",
    plan,
    tier: "",
    ttlSeconds,
    configuredTtlSeconds: ttlSeconds,
    limit: defaultLimitForPlan(plan),
    maxDevices: defaultMaxDevicesForPlan(plan),
    exp: 0
  };
}

module.exports = async function handler(req, res) {
  cors(res);

  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }

  if (req.method !== "GET") {
    return res.status(405).json({
      ok: false,
      error: "method_not_allowed",
      build: BUILD
    });
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
    return res.status(200).json({
      ok: false,
      plan: "none",
      build: BUILD
    });
  }

  let redis;
  try {
    redis = getRedis();
  } catch {
    return res.status(500).json({
      ok: false,
      error: "redis_not_configured",
      build: BUILD
    });
  }

  const info = await resolveLicense(redis, lic);
  if (!info.ok) {
    return res.status(200).json({
      ok: false,
      plan: "none",
      error: info.error,
      build: BUILD
    });
  }

  return res.status(200).json({
    ok: true,
    plan: info.plan,
    tier: info.tier || "",
    ttlSeconds: info.ttlSeconds,
    configuredTtlSeconds: info.configuredTtlSeconds,
    limit: info.limit,
    maxDevices: info.maxDevices,
    source: info.source,
    kind: info.kind,
    exp: info.exp || 0,
    build: BUILD
  });
};