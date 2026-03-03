export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Basic CORS so your HTA can call it
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders() });
    }

    try {
      if (url.pathname === "/verify" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const key = String(body.license || "");

        const ok = await isValidLicense(key, env);
        return json({ ok }, 200);
      }

      if (url.pathname === "/doThing" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const key = String(body.license || "");
        const action = String(body.action || "");

        const ok = await isValidLicense(key, env);
        if (!ok) return json({ ok: false, error: "invalid_license" }, 403);

        // 🔒 SECRET LOGIC LIVES HERE:
        // Return server-approved settings instead of shipping them in HTA.
        // Example: return Chrome flags, feature unlocks, etc.
        const plan = await getPlanForLicense(key, env);

        const payload = buildActionPayload(action, plan);
        return json({ ok: true, plan, ...payload }, 200);
      }

      return json({ ok: false, error: "not_found" }, 404);
    } catch (e) {
      return json({ ok: false, error: "server_error" }, 500);
    }
  }
};

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type"
  };
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj, null, 2), {
    status,
    headers: {
      ...corsHeaders(),
      "Content-Type": "application/json; charset=utf-8"
    }
  });
}

// --- License storage option A (simple): single secret list in env ---
// env.LICENSES = "KEY1,KEY2,KEY3"
async function isValidLicense(key, env) {
  if (!key || key.length < 6) return false;
  const list = (env.LICENSES || "")
    .split(",")
    .map(s => s.trim())
    .filter(Boolean);

  return list.includes(key);
}

// Example: map license → plan
async function getPlanForLicense(key, env) {
  // You can make this smarter later (KV/D1 database).
  // For now: keys starting with PRO- => pro
  if (key.startsWith("PRO-")) return "pro";
  return "basic";
}

function buildActionPayload(action, plan) {
  // Define “actions” your HTA can ask for.
  // Return ONLY what you want the client to know.
  if (action === "chrome_launch_flags") {
    if (plan === "pro") {
      return {
        chromeFlags: [
          "--no-first-run",
          "--force-dark-mode"
          // keep your real secret sauce here, not in HTA
        ],
        features: { proMode: true, mediaMode: true }
      };
    }
    return {
      chromeFlags: ["--no-first-run"],
      features: { proMode: false, mediaMode: true }
    };
  }

  return { message: "unknown_action" };
}