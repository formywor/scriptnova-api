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

    // Only allow POST for API
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