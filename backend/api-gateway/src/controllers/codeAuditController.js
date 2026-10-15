const axios = require("axios");
const { query } = require("../config/database");
const { c4BaseUrl } = require("../config/env");
const AppError = require("../utils/AppError");
const { assertCanAccess, listsAll } = require("../utils/ownership");

// Cloning + Semgrep + AST analysis of a repository can take several minutes.
const ANALYZE_TIMEOUT_MS = 15 * 60 * 1000;
const READ_TIMEOUT_MS = 30000;
const C4_UNAVAILABLE = "Code audit service is unavailable. Please make sure the C4 service is running.";

/** Forward C4's own status and error body; never expose network error internals. */
function forwardC4Error(error, res) {
  if (error.response) {
    return res.status(error.response.status).json(error.response.data);
  }
  return res.status(502).json({ message: C4_UNAVAILABLE, detail: C4_UNAVAILABLE });
}

/** POST /api/code-audit — { "repository_url": "https://github.com/owner/repo" } */
async function submitRepository(req, res) {
  const repositoryUrl = req.body?.repository_url;
  if (typeof repositoryUrl !== "string" || !repositoryUrl.trim() || repositoryUrl.length > 500) {
    throw new AppError(400, "repository_url is required.");
  }

  let data;
  try {
    ({ data } = await axios.post(
      `${c4BaseUrl}/api/v1/repositories/analyze`,
      { repository_url: repositoryUrl.trim() },
      { timeout: ANALYZE_TIMEOUT_MS }
    ));
  } catch (error) {
    return forwardC4Error(error, res);
  }

  if (data?.scan_id) {
    await query(
      `INSERT INTO code_audit_scans (scan_id, user_id, repository_url, status)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (scan_id) DO NOTHING`,
      [data.scan_id, req.user.id, data.repository?.url || repositoryUrl.trim(), String(data.status || "unknown")]
    );
  }
  return res.json(data);
}

/** GET /api/code-audit — own scans; ADMIN may add ?all=true. */
async function listScans(req, res) {
  const all = listsAll(req);
  const { rows } = await query(
    `SELECT s.scan_id, s.user_id, s.repository_url, s.status, s.created_at,
            u.name AS owner_name, u.email AS owner_email
       FROM code_audit_scans s JOIN users u ON u.id = s.user_id
      WHERE $1::boolean OR s.user_id = $2
      ORDER BY s.created_at DESC
      LIMIT 200`,
    [all, req.user.id]
  );
  res.json({ scope: all ? "all" : "own", scans: rows });
}

/** GET /api/code-audit/:scanId — owner or ADMIN; includes C4's finding summary when reachable. */
async function getScan(req, res) {
  const { rows } = await query(
    `SELECT s.scan_id, s.user_id, s.repository_url, s.status, s.created_at,
            u.name AS owner_name, u.email AS owner_email
       FROM code_audit_scans s JOIN users u ON u.id = s.user_id
      WHERE s.scan_id = $1`,
    [req.params.scanId]
  );
  assertCanAccess(req.user, rows[0], "Repository scan");

  let findings = null;
  try {
    ({ data: findings } = await axios.get(
      `${c4BaseUrl}/api/v1/scans/${encodeURIComponent(req.params.scanId)}/findings`,
      { timeout: READ_TIMEOUT_MS }
    ));
  } catch {
    findings = null;
  }
  res.json({ scan: rows[0], findings, c4_available: findings !== null });
}

module.exports = { submitRepository, listScans, getScan };
