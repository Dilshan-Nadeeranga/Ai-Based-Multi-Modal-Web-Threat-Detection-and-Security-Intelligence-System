/**
 * Print REDDIT_SESSION_B64 for cloud deploy (Render).
 * Run after: npm run reddit:login
 */
import fs from "fs";
import { SESSION_FILE } from "../redditAuth/session.js";

if (!fs.existsSync(SESSION_FILE)) {
  console.error("ERROR: No session file found.");
  console.error("Run first: npm run reddit:login");
  process.exit(1);
}

const b64 = Buffer.from(fs.readFileSync(SESSION_FILE, "utf-8")).toString("base64");

console.log("\n" + "=".repeat(60));
console.log("Copy into Render → Environment variables");
console.log("Key:   REDDIT_SESSION_B64");
console.log("=".repeat(60));
console.log(b64);
console.log("=".repeat(60) + "\n");
console.log(`(Source: ${SESSION_FILE})`);
