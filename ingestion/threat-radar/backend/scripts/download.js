import { config } from "../config.js";
import { runDownload } from "../downloadJob.js";

const zone = process.argv[2] ?? "dailyupdate";
const format = process.argv[3] ?? "text";
const useFeed = process.argv.includes("--feed");
const dated = process.argv.includes("--dated");
const outDir = process.argv.includes("--out")
  ? process.argv[process.argv.indexOf("--out") + 1]
  : config.downloadDir;

const result = await runDownload({ zone, format, useFeed, outDir, dated });

if (result.lineCount != null) {
  console.log(
    `Saved ${result.lineCount.toLocaleString()} domains -> ${result.path}`
  );
} else if (result.domainCount != null) {
  console.log(
    `Saved ${result.domainCount.toLocaleString()} domains -> ${result.path}`
  );
} else {
  console.log(`Saved ${result.bytes} bytes -> ${result.path}`);
}
