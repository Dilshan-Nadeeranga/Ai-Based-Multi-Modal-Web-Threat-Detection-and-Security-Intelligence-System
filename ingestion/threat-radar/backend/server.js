import cors from "cors";
import express from "express";
import { config } from "./config.js";
import { startKeepAlive } from "./keepAlive.js";
import { ensurePythonDeps } from "./pythonEnv.js";
import { apiRouter } from "./routes/api.js";
import { authRouter } from "./routes/auth.js";
import { domainFilterRouter } from "./routes/domainFilter.js";
import { keywordsRouter } from "./routes/keywords.js";
import { redditAuthRouter } from "./routes/redditAuth.js";
import { redditRouter } from "./routes/reddit.js";
import { scraperRouter } from "./routes/scraper.js";
import { playwrightReady } from "./redditAuth/capabilities.js";
import { restoreSessionFromEnv } from "./redditAuth/session.js";
import { startRedditScraper } from "./redditScraperProcess.js";
import { startScheduler } from "./scheduler.js";
import { startScraper } from "./scraperProcess.js";
import { ensurePlaywrightBrowsers } from "./scripts/ensure-playwright.js";
import { seedKeywordsFromEnv } from "./keywordsStore.js";

const app = express();

app.use(cors({ origin: true }));
app.use(express.json());

app.use("/api", apiRouter);
app.use("/api/auth", authRouter);
app.use("/api/domain-filter", domainFilterRouter);
app.use("/api/keywords", keywordsRouter);
app.use("/api/scraper", scraperRouter);
app.use("/api/reddit", redditRouter);
app.use("/api/reddit-auth", redditAuthRouter);

function maybeEnsurePythonDeps() {
  if (process.env.SCRAPER_ALLOW_LOCAL === "true") {
    ensurePythonDeps();
  }
}



// test10



const server = app.listen(config.port, () => {
  console.log(`ThreatRadar backend http://localhost:${config.port}`);
  console.log(`Downloads -> ${config.downloadDir}`);
  void bootstrap();
});

async function bootstrap() {
  restoreSessionFromEnv();
  await seedKeywordsFromEnv();

  const rssOnly =
    process.env.REDDIT_USE_RSS_ONLY === "true" ||
    process.env.REDDIT_SCRAPER_ENGINE === "rss";

  if (!rssOnly) {
    const pwOk = await ensurePlaywrightBrowsers();
    console.log(
      `[playwright] Chromium ready: ${playwrightReady()} (dir: ${process.env.PLAYWRIGHT_BROWSERS_PATH})`
    );
    if (!pwOk) {
      console.warn(
        "[playwright] Browser scrape unavailable — Reddit will use Python RSS if auto-scrape is on"
      );
    }
  } else {
    console.log("[reddit] Skipping Playwright (REDDIT_USE_RSS_ONLY=true)");
  }

  maybeEnsurePythonDeps();
  startScheduler();
  startScraper();
  startRedditScraper();
  startKeepAlive();
}

server.on("error", (err) => {
  if (err.code === "EADDRINUSE") {
    console.error(
      `\nERROR: Port ${config.port} is already in use.\n` +
        "  Another backend is probably already running.\n" +
        "  - Use it: http://localhost:" + config.port + "/api/health\n" +
        "  - Or stop it (PowerShell):\n" +
        `      Get-NetTCPConnection -LocalPort ${config.port} | ` +
        "ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }\n"
    );
    process.exit(1);
  }
  throw err;
});
