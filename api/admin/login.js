const { BUILD, cors, getJsonBody, loginAdmin } = require('../_admin');

module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return res.status(405).json({ ok: false, error: 'method_not_allowed', build: BUILD });

  const body = await getJsonBody(req);
  const role = String(body.role || '').trim().toLowerCase();
  const password = String(body.password || '');
  if (!['owner', 'ulises', 'other'].includes(role)) {
    return res.status(400).json({ ok: false, error: 'bad_role', build: BUILD });
  }

  const out = await loginAdmin(req, role, password);
  if (!out.ok) return res.status(403).json({ ok: false, error: out.error, build: BUILD });

  return res.status(200).json({ ok: true, token: out.token, role: out.role, exp: out.exp, build: BUILD });
};