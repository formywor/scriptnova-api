module.exports = function handler(req, res) {
  // CORS
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") return res.status(204).end();

  // Allow GET for easy testing in a browser:
  // /api/verify?license=PRO-TEST1234
  const license =
    (req.method === "GET" ? req.query.license : (req.body && req.body.license)) || "";

  const list = (process.env.LICENSES || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  const ok = list.includes(String(license));
  const plan = ok
    ? String(license).startsWith("PRO-")
      ? "pro"
      : String(license).startsWith("BASIC-")
        ? "basic"
        : "basic"
    : "none";

  return res.status(200).json({ ok, plan });
};