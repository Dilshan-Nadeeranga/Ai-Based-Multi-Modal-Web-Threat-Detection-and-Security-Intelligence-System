const crypto = require("crypto");
const axios = require("axios");
const { query } = require("../config/database");
const AppError = require("../utils/AppError");
const { assertCanAccess, listsAll } = require("../utils/ownership");

const SERVICE_TIMEOUT_MS = 30000;
const MAX_INPUT_LENGTH = 5000;

function notConnected(component) {
  return { component, status: "service_not_connected", score: 0 };
}

async function callService(url, body, component) {
  if (!url) return notConnected(component);
  try {
    const response = await axios.post(url, body, { timeout: SERVICE_TIMEOUT_MS });
    return response.data;
  } catch {
    return notConnected(component);
  }
}

function readInput(body = {}) {
  const input = {};
  for (const key of ["url", "socialText", "repoUrl"]) {
    if (body[key] === undefined || body[key] === null || body[key] === "") continue;
    if (typeof body[key] !== "string" || body[key].length > MAX_INPUT_LENGTH) {
      throw new AppError(400, `${key} must be a string of at most ${MAX_INPUT_LENGTH} characters.`);
    }
    input[key] = body[key].trim();
  }
  if (!Object.keys(input).length) throw new AppError(400, "Provide a url, socialText or repoUrl to analyze.");
  return input;
}

/** POST /api/analysis (also the legacy POST /api/analyze) — runs C1–C4 and stores the result for req.user. */
async function analyze(req, res) {
  const { url, socialText, repoUrl } = readInput(req.body);
  const { C1_URL, C2_URL, C3_URL, C4_URL } = process.env;

  const [c1, c2, c3, c4] = await Promise.all([
    callService(C1_URL && `${C1_URL}/analyze-url`, { url }, "C1_URL_DOMAIN"),
    callService(C2_URL && `${C2_URL}/analyze-html`, { url }, "C2_HTML_CONTENT"),
    callService(C3_URL && `${C3_URL}/analyze-visual`, { url, socialText }, "C3_SOCIAL_VISUAL"),
    callService(C4_URL && `${C4_URL}/analyze-code`, { repoUrl }, "C4_CODE_AUDIT"),
  ]);
  const results = { c1_url_domain: c1, c2_html_content: c2, c3_social_visual: c3, c4_code_audit: c4 };

  const scores = Object.values(results).map((item) => Number(item?.score) || 0);
  const overallScore = Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);
  let finalLabel = "Low Risk";
  if (overallScore >= 75) finalLabel = "High Risk Scam";
  else if (overallScore >= 50) finalLabel = "Medium Risk";
  else if (overallScore >= 25) finalLabel = "Suspicious";

  const analysis = {
    analysis_id: `SCAM-${Date.now()}-${crypto.randomBytes(3).toString("hex").toUpperCase()}`,
    input: { url, socialText, repoUrl },
    overall_score: overallScore,
    final_label: finalLabel,
    component_results: results,
  };

  await query(
    `INSERT INTO analysis_records (analysis_id, user_id, input, overall_score, final_label, result)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [analysis.analysis_id, req.user.id, analysis.input, overallScore, finalLabel, results]
  );
  res.status(201).json(analysis);
}

const SUMMARY_COLUMNS = `a.analysis_id, a.user_id, a.input, a.overall_score, a.final_label, a.created_at,
                         u.name AS owner_name, u.email AS owner_email`;

/** GET /api/analysis/history — own records; ADMIN may add ?all=true. */
async function history(req, res) {
  const all = listsAll(req);
  const { rows } = await query(
    `SELECT ${SUMMARY_COLUMNS}
       FROM analysis_records a JOIN users u ON u.id = a.user_id
      WHERE $1::boolean OR a.user_id = $2
      ORDER BY a.created_at DESC
      LIMIT 200`,
    [all, req.user.id]
  );
  res.json({ scope: all ? "all" : "own", analyses: rows });
}

/** GET /api/analysis/:analysisId — owner or ADMIN. */
async function getAnalysis(req, res) {
  const { rows } = await query(
    `SELECT ${SUMMARY_COLUMNS}, a.result
       FROM analysis_records a JOIN users u ON u.id = a.user_id
      WHERE a.analysis_id = $1`,
    [req.params.analysisId]
  );
  assertCanAccess(req.user, rows[0], "Analysis");
  res.json({ analysis: rows[0] });
}

module.exports = { analyze, history, getAnalysis };
