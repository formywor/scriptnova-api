import { Redis } from "@upstash/redis/cloudflare";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // ---- CORS for HTA ----
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders() });
    }

    // Health check
    if (url.pathname === "/" && request.method === "GET") {
      return json({ ok: true, service: "scriptnova-api" }, 200);
    }

    // Support chat endpoints
    if (url.pathname.startsWith("/support/") || url.pathname.startsWith("/admin/")) {
      return handleSupportChat(request, env);
    }

    // Only allow POST for other API
    if (request.method !== "POST") {
      return json({ ok: false, error: "method_not_allowed" }, 405);
    }

    // Parse JSON body
    const body = await request.json().catch(() => ({}));
    const license = String(body.license || "");
    const action = String(body.action || "");

    // Routes
    if (url.pathname === "/verify") {
      const plan = getPlanFromLicense(license, env);
      return json({ ok: !!plan, plan: plan || "none" }, 200);
    }

    if (url.pathname === "/ui") {
      const plan = getPlanFromLicense(license, env);
      if (!plan) return json({ ok: false, error: "invalid_license" }, 403);

      // 🔒 SECRET UI RULES LIVE HERE (server-side)
      const ui = buildUiForPlan(plan);

      // also send recommended defaults + chrome flags policy
      const config = buildConfigForPlan(plan);

      return json({ ok: true, plan, ui, config }, 200);
    }

    if (url.pathname === "/doThing") {
      const plan = getPlanFromLicense(license, env);
      if (!plan) return json({ ok: false, error: "invalid_license" }, 403);

      // Allowed actions
      if (action === "chrome_flags") {
        const cfg = buildConfigForPlan(plan);
        return json({ ok: true, plan, chromeFlags: cfg.chromeFlags }, 200);
      }

      return json({ ok: false, error: "unknown_action" }, 400);
    }

    return json({ ok: false, error: "not_found" }, 404);
  }
};

async function handleSupportChat(request, env) {
  const url = new URL(request.url);
  const redis = getRedis(env);

  if (url.pathname === "/support/start" && request.method === "POST") {
    const body = await request.json().catch(() => ({}));
    const name = String(body.name || "").trim();
    const hwid = String(body.hwid || "").trim();
    if (!name || !hwid) return json({ ok: false, error: "missing_name_or_hwid" }, 400);

    // Check if banned
    const banned = await redis.sismember("support:banned_hwids", hwid);
    if (banned) return json({ ok: false, error: "banned" }, 403);

    const sessionId = crypto.randomUUID();
    const session = { sessionId, name, hwid, status: "queued", messages: [], created: Date.now() };
    await redis.set(`support:session:${sessionId}`, JSON.stringify(session));
    await redis.rpush("support:queue", sessionId);

    const queueLength = await redis.llen("support:queue");
    return json({ ok: true, sessionId, queuePosition: queueLength }, 200);
  }

  if (url.pathname === "/support/message" && request.method === "POST") {
    const body = await request.json().catch(() => ({}));
    const sessionId = String(body.sessionId || "");
    const message = String(body.message || "").trim();
    if (!sessionId || !message) return json({ ok: false, error: "missing_sessionId_or_message" }, 400);

    const sessionKey = `support:session:${sessionId}`;
    const sessionStr = await redis.get(sessionKey);
    if (!sessionStr) return json({ ok: false, error: "invalid_session" }, 404);

    const session = JSON.parse(sessionStr);
    session.messages.push({ role: "user", text: message, timestamp: Date.now() });
    await redis.set(sessionKey, JSON.stringify(session));
    return json({ ok: true }, 200);
  }

  if (url.pathname === "/support/poll" && request.method === "GET") {
    const sessionId = url.searchParams.get("sessionId");
    if (!sessionId) return json({ ok: false, error: "missing_sessionId" }, 400);

    const sessionKey = `support:session:${sessionId}`;
    const sessionStr = await redis.get(sessionKey);
    if (!sessionStr) return json({ ok: false, error: "invalid_session" }, 404);

    const session = JSON.parse(sessionStr);
    let queuePosition = null;
    if (session.status === "queued") {
      const queue = await redis.lrange("support:queue", 0, -1);
      queuePosition = queue.indexOf(sessionId) + 1;
    }

    const newMessages = session.messages.filter(m => m.timestamp > (session.lastPoll || 0));
    session.lastPoll = Date.now();
    await redis.set(sessionKey, JSON.stringify(session));

    return json({ ok: true, status: session.status, queuePosition, messages: session.messages }, 200);
  }

  if (url.pathname === "/admin/login" && request.method === "POST") {
    const body = await request.json().catch(() => ({}));
    const username = String(body.username || "");
    const password = String(body.password || "");
    if (username !== "SNOVAOWNER" || password !== "4444") return json({ ok: false, error: "invalid_credentials" }, 401);

    const token = crypto.randomUUID();
    await redis.set(`admin:token:${token}`, "active", { ex: 3600 }); // 1 hour
    return json({ ok: true, token }, 200);
  }

  if (url.pathname === "/admin/queue" && request.method === "GET") {
    const token = url.searchParams.get("token");
    if (!token || !(await redis.get(`admin:token:${token}`))) return json({ ok: false, error: "invalid_token" }, 401);

    const queue = await redis.lrange("support:queue", 0, -1);
    const sessions = [];
    for (const sid of queue) {
      const s = await redis.get(`support:session:${sid}`);
      if (s) {
        const session = JSON.parse(s);
        sessions.push({ sessionId: sid, name: session.name, hwid: session.hwid });
      }
    }
    return json({ ok: true, tickets: sessions }, 200);
  }

  if (url.pathname === "/admin/ticket" && request.method === "GET") {
    const token = url.searchParams.get("token");
    const sessionId = url.searchParams.get("sessionId");
    if (!token || !(await redis.get(`admin:token:${token}`))) return json({ ok: false, error: "invalid_token" }, 401);
    if (!sessionId) return json({ ok: false, error: "missing_sessionId" }, 400);

    const sessionStr = await redis.get(`support:session:${sessionId}`);
    if (!sessionStr) return json({ ok: false, error: "invalid_session" }, 404);

    const session = JSON.parse(sessionStr);
    return json({ ok: true, session: { sessionId, name: session.name, hwid: session.hwid, messages: session.messages } }, 200);
  }

  if (url.pathname === "/admin/command" && request.method === "POST") {
    const body = await request.json().catch(() => ({}));
    const token = String(body.token || "");
    const command = String(body.command || "").trim();
    const args = String(body.args || "").trim();
    if (!token || !(await redis.get(`admin:token:${token}`))) return json({ ok: false, error: "invalid_token" }, 401);
    if (!command) return json({ ok: false, error: "missing_command" }, 400);

    if (command === "/ban" && args) {
      await redis.sadd("support:banned_hwids", args);
      return json({ ok: true, message: `Banned HWID: ${args}` }, 200);
    }
    if (command === "/unban" && args) {
      await redis.srem("support:banned_hwids", args);
      return json({ ok: true, message: `Unbanned HWID: ${args}` }, 200);
    }
    if (command === "/close" && args) {
      const sessionKey = `support:session:${args}`;
      const sessionStr = await redis.get(sessionKey);
      if (sessionStr) {
        const session = JSON.parse(sessionStr);
        session.status = "closed";
        await redis.set(sessionKey, JSON.stringify(session));
        await redis.lrem("support:queue", 0, args);
      }
      return json({ ok: true, message: `Closed session: ${args}` }, 200);
    }
    if (command === "/info" && args) {
      const sessionStr = await redis.get(`support:session:${args}`);
      if (!sessionStr) return json({ ok: false, error: "session_not_found" }, 404);
      const session = JSON.parse(sessionStr);
      return json({ ok: true, info: { name: session.name, hwid: session.hwid, status: session.status } }, 200);
    }
    if (command === "/list") {
      const queue = await redis.lrange("support:queue", 0, -1);
      return json({ ok: true, list: queue }, 200);
    }
    if (command === "/help") {
      return json({ ok: true, help: "/ban HWID, /unban HWID, /close SESSION_ID, /info SESSION_ID, /list, /help" }, 200);
    }
    return json({ ok: false, error: "unknown_command" }, 400);
  }

  if (url.pathname === "/admin/message" && request.method === "POST") {
    const body = await request.json().catch(() => ({}));
    const token = String(body.token || "");
    const sessionId = String(body.sessionId || "");
    const message = String(body.message || "").trim();
    if (!token || !(await redis.get(`admin:token:${token}`))) return json({ ok: false, error: "invalid_token" }, 401);
    if (!sessionId || !message) return json({ ok: false, error: "missing_sessionId_or_message" }, 400);

    const sessionKey = `support:session:${sessionId}`;
    const sessionStr = await redis.get(sessionKey);
    if (!sessionStr) return json({ ok: false, error: "invalid_session" }, 404);

    const session = JSON.parse(sessionStr);
    session.messages.push({ role: "admin", text: message, timestamp: Date.now() });
    if (session.status === "queued") {
      session.status = "active";
      await redis.lrem("support:queue", 0, sessionId);
    }
    await redis.set(sessionKey, JSON.stringify(session));
    return json({ ok: true }, 200);
  }

  return json({ ok: false, error: "not_found" }, 404);
}

function getRedis(env) {
  const url = env.UPSTASH_REDIS_REST_URL || env.KV_REST_API_URL;
  const token = env.UPSTASH_REDIS_REST_TOKEN || env.KV_REST_API_TOKEN;
  if (!url || !token) throw new Error("missing_redis_env");
  return new Redis({ url, token });
}

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS, GET",
    "Access-Control-Allow-Headers": "Content-Type"
  };
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj, null, 2), {
    status,
    headers: { ...corsHeaders(), "Content-Type": "application/json; charset=utf-8" }
  });
}

/**
 * License storage (simple, dashboard-only):
 * Put your keys in an env var named LICENSES:
 *   LICENSES="BASIC-AAA111,PRO-BBB222,PRO-CCC333"
 *
 * Put a second env var SECRET_SALT too (anything random).
 */
function getPlanFromLicense(license, env) {
  if (!license || license.length < 8) return null;

  const list = String(env.LICENSES || "")
    .split(",")
    .map(s => s.trim())
    .filter(Boolean);

  if (!list.includes(license)) return null;

  // Simple plan rule:
  // PRO-... => pro
  // BASIC-... => basic
  if (license.startsWith("PRO-")) return "pro";
  if (license.startsWith("BASIC-")) return "basic";

  // fallback (still valid)
  return "basic";
}

/**
 * 🔒 SECRET UI (what panels/buttons/features appear)
 * You can change this any time without updating the HTA.
 */
function buildUiForPlan(plan) {
  const base = {
    showProModeToggle: false,
    showMediaModeToggle: true,
    showToolsKillApps: true,
    showToolsRamOptimize: true,
    showToolsClearCache: true,
    showEdgeDrmButton: true,
    showThemePicker: true
  };

  if (plan === "pro") {
    return {
      ...base,
      showProModeToggle: true,
      // example: unlock extra pro-only switches
      showAdvancedSwitches: true
    };
  }

  return {
    ...base,
    showAdvancedSwitches: false
  };
}

/**
 * 🔒 SECRET CONFIG (recommended defaults + chrome flags)
 * HTA only receives the results.
 */
function buildConfigForPlan(plan) {
  // Defaults the HTA should apply
  const defaults = {
    t_kill: false,
    t_temp: false,
    t_incog: false,
    t_kiosk: false,
    t_gpu: true,
    t_ext: false,
    t_proxy: true,
    t_fps: false,
    t_mute: false
  };

  if (plan === "pro") {
    return {
      defaults: {
        ...defaults,
        t_kill: true
      },
      chromeFlags: [
        "--no-first-run",
        "--force-dark-mode",

        // 🔒 Put your “real” pro flags here
        // (HTA never stores these permanently; it asks the API each time)
        "--disable-background-timer-throttling",
        "--disable-renderer-backgrounding"
      ]
    };
  }

  // basic
  return {
    defaults,
    chromeFlags: [
      "--no-first-run",
      "--force-dark-mode"
    ]
  };
}