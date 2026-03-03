module.exports = function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.status(204).end();

  const license =
    (req.method === "GET" ? req.query.license : (req.body && req.body.license)) || "";

  const list = (process.env.LICENSES || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  const ok = list.includes(String(license));
  if (!ok) return res.status(403).json({ ok: false, error: "invalid_license" });

  const plan = String(license).startsWith("PRO-")
    ? "pro"
    : String(license).startsWith("BASIC-")
      ? "basic"
      : "basic";

  const ui = {
    showProModeToggle: plan === "pro",
    showMediaModeToggle: true,
    showToolsKillApps: true,
    showToolsRamOptimize: true,
    showToolsClearCache: true,
    showEdgeDrmButton: true,
    showThemePicker: true
  };

  const config = {
    defaults: {
      t_kill: plan === "pro",
      t_temp: false,
      t_incog: false,
      t_kiosk: false,
      t_gpu: true,
      t_ext: false,
      t_proxy: true,
      t_fps: false,
      t_mute: false
    },
    chromeFlags: plan === "pro"
      ? ["--no-first-run", "--force-dark-mode", "--disable-renderer-backgrounding"]
      : ["--no-first-run", "--force-dark-mode"]
  };

  return res.status(200).json({ ok: true, plan, ui, config });
};