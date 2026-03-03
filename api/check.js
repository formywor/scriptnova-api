function cors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
}

function getLicenseList() {
  return (process.env.LICENSES || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function readLicense(req) {
  if (req.method === "GET") return String(req.query.license || "").trim();
  const b = req.body;
  if (!b) return "";
  if (typeof b === "string") {
    try { return String(JSON.parse(b).license || "").trim(); } catch { return ""; }
  }
  return String(b.license || "").trim();
}

function planForLicense(lic) {
  return lic.indexOf("PRO-") === 0 ? "pro" : "basic";
}
function limitForPlan(plan) {
  return plan === "pro" ? 4 : 2;
}
function ttlForPlan(plan) {
  return plan === "pro" ? (118 * 60 * 60) : (32 * 60);
}

module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === "OPTIONS") return res.status(204).end();

  const lic = readLicense(req);
  const list = getLicenseList();

  if (!lic || !list.includes(lic)) {
    return res.status(200).json({ ok: false, plan: "none" });
  }

  const plan = planForLicense(lic);
  return res.status(200).json({
    ok: true,
    plan,
    limit: limitForPlan(plan),
    ttlSeconds: ttlForPlan(plan)
  });
};