import { execFile } from "child_process";
import path from "path";
import { Router } from "express";
import { ensurePythonDeps, getPython, SCRAPER_DIR } from "../pythonEnv.js";
import {
  hasSessionFile,
  readSessionB64,
  restartScraperAfterLogin,
  stopScraper,
} from "../scraperProcess.js";

export const authRouter = Router();

const AUTH_SCRIPT = path.join(SCRAPER_DIR, "auth.py");

async function runAuth(args) {
  await ensurePythonDeps();

  return new Promise((resolve) => {
    const python = getPython();
    execFile(
      python,
      [AUTH_SCRIPT, ...args],
      {
        cwd: SCRAPER_DIR,
        env: { ...process.env },
        timeout: 25_000,
      },
      (err, stdout, stderr) => {
        const lines = (stdout || "").trim().split("\n").filter(Boolean);
        const raw = lines[lines.length - 1] || "";

        try {
          resolve(JSON.parse(raw));
          return;
        } catch {
          const detail = stderr?.trim() || err?.message || "Auth script failed";
          resolve({
            success: false,
            step: "error",
            message: detail,
          });
        }
      }
    );
  });
}

async function handleAuth(req, res, args, { onSuccess } = {}) {
  try {
    const result = await runAuth(args);
    if (result.success && result.step === "done" && onSuccess) {
      onSuccess();
    }
    res.json(result);
  } catch (e) {
    res.json({ success: false, step: "error", message: String(e) });
  }
}

authRouter.get("/status", async (req, res) => {
  await handleAuth(req, res, ["status"]);
});

authRouter.post("/request-code", async (req, res) => {
  const phone = String(req.body?.phone ?? "").trim();
  if (!phone) {
    return res.status(400).json({ success: false, message: "phone is required" });
  }
  stopScraper();
  await handleAuth(req, res, ["request-code", phone]);
});

authRouter.post("/verify-code", async (req, res) => {
  const code = String(req.body?.code ?? "").trim();
  if (!code) {
    return res.status(400).json({ success: false, message: "code is required" });
  }
  await handleAuth(req, res, ["verify-code", code], {
    onSuccess: () => restartScraperAfterLogin(),
  });
});

authRouter.post("/verify-password", async (req, res) => {
  const password = String(req.body?.password ?? "").trim();
  if (!password) {
    return res.status(400).json({ success: false, message: "password is required" });
  }
  await handleAuth(req, res, ["verify-password", password], {
    onSuccess: () => restartScraperAfterLogin(),
  });
});

authRouter.post("/logout", async (req, res) => {
  stopScraper();
  await handleAuth(req, res, ["logout"]);
});

/** Export session as base64 for Render redeploy persistence (optional). */
authRouter.get("/export-session", async (_req, res) => {
  if (!hasSessionFile()) {
    return res.json({ success: false, message: "Not logged in" });
  }
  const b64 = readSessionB64();
  res.json({
    success: true,
    message:
      "Copy sessionB64 to Render as TELEGRAM_SESSION_B64 and set TELEGRAM_RESTORE_SESSION_B64=true only if you need login to survive redeploys.",
    sessionB64: b64,
  });
});
