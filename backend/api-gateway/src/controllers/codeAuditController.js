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

/**
 * GET /api/code-audit/projects — the caller's own repositories, one entry per repository URL,
 * each with its scan history (newest first).
 */
async function listProjects(req, res) {
  const { rows } = await query(
    `SELECT scan_id, repository_url, status, created_at
       FROM code_audit_scans
      WHERE user_id = $1
      ORDER BY created_at DESC
      LIMIT 500`,
    [req.user.id]
  );

  const projects = new Map();
  for (const row of rows) {
    const url = row.repository_url.replace(/\.git$|\/+$/g, "");
    const key = url.toLowerCase();
    if (!projects.has(key)) {
      const [owner = "", name = ""] = url.replace(/^https?:\/\/github\.com\//i, "").split("/");
      projects.set(key, {
        repository_url: row.repository_url,
        owner,
        name: name || row.repository_url,
        last_scanned_at: row.created_at,
        latest_scan_id: row.scan_id,
        latest_status: row.status,
        scans: [],
      });
    }
    projects.get(key).scans.push({ scan_id: row.scan_id, status: row.status, created_at: row.created_at });
  }

  res.json({ projects: [...projects.values()] });
}

/**
 * DELETE /api/code-audit/projects/:scanId — removes the caller's project that contains this scan,
 * i.e. all of the caller's scan records for the same repository. Other users' records are untouched.
 */
async function deleteProject(req, res) {
  const { rows } = await query(
    "SELECT scan_id, user_id, repository_url FROM code_audit_scans WHERE scan_id = $1",
    [req.params.scanId]
  );
  const scan = rows[0];
  if (!scan || scan.user_id !== req.user.id) {
    throw new AppError(404, "Project not found.");
  }

  const key = scan.repository_url.replace(/\.git$|\/+$/g, "").toLowerCase();
  const result = await query(
    `DELETE FROM code_audit_scans
      WHERE user_id = $1
        AND lower(regexp_replace(repository_url, '(\\.git|/+)$', '')) = $2`,
    [req.user.id, key]
  );

  // C4 keeps one clone per repository; remove it only when no user still has this project.
  const { rows: remaining } = await query(
    `SELECT 1 FROM code_audit_scans
      WHERE lower(regexp_replace(repository_url, '(\\.git|/+)$', '')) = $1
      LIMIT 1`,
    [key]
  );
  let cloneDeleted = false;
  if (remaining.length === 0) {
    try {
      const { data } = await axios.delete(`${c4BaseUrl}/api/v1/projects/clone`, {
        params: { repository_url: scan.repository_url.replace(/\.git$|\/+$/g, "") },
        timeout: READ_TIMEOUT_MS,
      });
      cloneDeleted = Boolean(data?.deleted);
    } catch {
      cloneDeleted = false;
    }
  }

  res.json({ deleted_scans: result.rowCount, repository_url: scan.repository_url, clone_deleted: cloneDeleted });
}

async function fetchFromC4(path) {
  try {
    const { data } = await axios.get(`${c4BaseUrl}/api/v1${path}`, { timeout: READ_TIMEOUT_MS });
    return data;
  } catch {
    return null;
  }
}

/** GET /api/code-audit/:scanId — owner or ADMIN; includes C4's stored summary and findings when reachable. */
async function getScan(req, res) {
  const { rows } = await query(
    `SELECT s.scan_id, s.user_id, s.repository_url, s.status, s.created_at,
            u.name AS owner_name, u.email AS owner_email
       FROM code_audit_scans s JOIN users u ON u.id = s.user_id
      WHERE s.scan_id = $1`,
    [req.params.scanId]
  );
  assertCanAccess(req.user, rows[0], "Repository scan");

  const scanPath = `/scans/${encodeURIComponent(req.params.scanId)}`;
  const [summary, findings] = await Promise.all([fetchFromC4(scanPath), fetchFromC4(`${scanPath}/findings`)]);
  res.json({ scan: rows[0], summary, findings, c4_available: findings !== null });
}

module.exports = { submitRepository, listScans, listProjects, deleteProject, getScan };
