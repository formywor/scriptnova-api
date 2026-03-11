const { getRedis } = require("./_redis");
const { rateLimit } = require("./_rate");

const BUILD = "sn-bootstrap-2026-03-10a";

function cors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}

function toInt(v, dflt) {
  const n = parseInt(v, 10);
  return Number.isFinite(n) ? n : dflt;
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

function globalKey(name) {
  return "sn:global:" + String(name);
}

function boolFromRedis(v) {
  return !!v && String(v).trim() !== "";
}

async function getGlobalString(redis, name, fallback) {
  try {
    const v = await redis.get(globalKey(name));
    if (v == null || String(v).trim() === "") return fallback;
    return String(v);
  } catch {
    return fallback;
  }
}

async function getGlobalBool(redis, name) {
  try {
    const v = await redis.get(globalKey(name));
    return boolFromRedis(v);
  } catch {
    return false;
  }
}

async function getGlobalInt(redis, name, fallback) {
  try {
    const v = await redis.get(globalKey(name));
    return toInt(v, fallback);
  } catch {
    return fallback;
  }
}

module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "GET") {
    return res.status(405).json({ ok: false, error: "method_not_allowed", build: BUILD });
  }

  const rl = await rateLimit(req, "bootstrap", 120, 60);
  if (!rl.ok) {
    res.setHeader("Retry-After", String(rl.retryAfter));
    return res.status(429).json({
      ok: false,
      error: "rate_limited",
      retryAfter: rl.retryAfter,
      build: BUILD
    });
  }

  let redis;
  try {
    redis = getRedis();
  } catch {
    return res.status(500).json({ ok: false, error: "redis_not_configured", build: BUILD });
  }

  const requiredVersion =
    (await getGlobalString(redis, "min_version", "")) ||
    "v13.13.15";

  const pauseEnabled = await getGlobalBool(redis, "paused");
  const pauseReason = await getGlobalString(redis, "paused_reason", "");
  const maintenanceMode = await getGlobalBool(redis, "maintenance_mode");
  const maintenanceMessage = await getGlobalString(redis, "maintenance_message", "");
  const disableAll = await getGlobalBool(redis, "disable_all");

  const cleanupPromptEnabled = await getGlobalBool(redis, "cleanup_old_prompt_enabled");
  const cleanupPromptMessage = await getGlobalString(
    redis,
    "cleanup_old_prompt_message",
    "Owner recommends removing outdated ScriptNova launcher copies from Desktop and Downloads."
  );
  const cleanupPromptForceOnce = await getGlobalInt(redis, "cleanup_old_prompt_force_once", 0);
  const cleanupScanPaths = safeJsonParse(
    await getGlobalString(redis, "cleanup_old_scan_paths_json", "[]"),
    []
  );
  const cleanupNameHints = safeJsonParse(
    await getGlobalString(redis, "cleanup_old_name_hints_json", "[]"),
    []
  );

  const supportEmail =
    (await getGlobalString(redis, "launcher_support_email", "")) ||
    "gomegaassist@gmail.com";

  const discordUrl =
    (await getGlobalString(redis, "launcher_discord_url", "")) ||
    "https://discord.gg/gscGTMVsWE";

  const defaultStartUrl =
    (await getGlobalString(redis, "launcher_default_start_url", "")) ||
    "https://www.guns.lol/iii_dev";

  const bannerEnabled = await getGlobalBool(redis, "public_banner_enabled");
  const bannerId = await getGlobalString(redis, "public_banner_id", "");
  const bannerTitle = await getGlobalString(redis, "public_banner_title", "");
  const bannerText = await getGlobalString(redis, "public_banner_text", "");
  const bannerMode = await getGlobalString(redis, "public_banner_mode", "info");
  const bannerDismissable = await getGlobalBool(redis, "public_banner_dismissable");

  const modalEnabled = await getGlobalBool(redis, "public_modal_enabled");
  const modalId = await getGlobalString(redis, "public_modal_id", "");
  const modalTitle = await getGlobalString(redis, "public_modal_title", "");
  const modalText = await getGlobalString(redis, "public_modal_text", "");
  const modalButtons = safeJsonParse(await getGlobalString(redis, "public_modal_buttons_json", "[]"), []);

  const pollEnabled = await getGlobalBool(redis, "public_poll_enabled");
  const pollId = await getGlobalString(redis, "public_poll_id", "");
  const pollQuestion = await getGlobalString(redis, "public_poll_question", "");
  const pollOptions = safeJsonParse(await getGlobalString(redis, "public_poll_options_json", "[]"), []);

  const quickLinks = safeJsonParse(await getGlobalString(redis, "launcher_quick_links_json", "[]"), []);
  const submitUrl = await getGlobalString(redis, "launcher_submit_url", "/api/ui");

  return res.status(200).json({
    ok: true,
    build: BUILD,
    version: {
      required: requiredVersion,
      downloadUrl: "https://scriptnovaa.com/download"
    },
    support: {
      email: supportEmail,
      discordUrl
    },
    launcher: {
      defaultStartUrl,
      pauseEnabled,
      pauseReason,
      maintenanceMode,
      maintenanceMessage,
      disableAll
    },
    endpoints: {
      check: "/api/check",
      verify: "/api/verify",
      ui: "/api/ui",
      launch: "/api/launch",
      ping: "/api/ping",
      end: "/api/end"
    },
    ui: {
      banner: {
        enabled: bannerEnabled,
        id: bannerId,
        title: bannerTitle,
        text: bannerText,
        mode: bannerMode,
        dismissable: bannerDismissable
      },
      modal: {
        enabled: modalEnabled,
        id: modalId,
        title: modalTitle,
        text: modalText,
        buttons: Array.isArray(modalButtons) ? modalButtons : []
      },
      poll: {
        enabled: pollEnabled,
        id: pollId,
        question: pollQuestion,
        options: Array.isArray(pollOptions) ? pollOptions : []
      },
      cleanupPrompt: {
        enabled: cleanupPromptEnabled,
        message: cleanupPromptMessage,
        forceOnce: cleanupPromptForceOnce,
        scanPaths: Array.isArray(cleanupScanPaths) ? cleanupScanPaths : [],
        nameHints: Array.isArray(cleanupNameHints) ? cleanupNameHints : []
      },
      quickLinks: Array.isArray(quickLinks) ? quickLinks : [],
      submitUrl: submitUrl || ""
    }
  });
};