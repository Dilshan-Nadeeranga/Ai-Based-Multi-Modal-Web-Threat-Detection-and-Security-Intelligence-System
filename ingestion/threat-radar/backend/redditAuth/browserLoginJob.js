import { loginWithBrowser } from "./login.js";

/** @type {{ status: 'idle'|'waiting'|'done'|'error', message?: string, startedAt?: number }} */
let job = { status: "idle" };

export function getBrowserLoginJob() {
  return { ...job };
}

export function startBrowserLoginJob() {
  if (job.status === "waiting") {
    return { started: false, message: "Browser login already in progress" };
  }

  job = { status: "waiting", message: "Browser window opened — log in to Reddit", startedAt: Date.now() };

  loginWithBrowser()
    .then((result) => {
      job = { status: "done", message: result.message };
    })
    .catch((err) => {
      job = { status: "error", message: err.message };
    });

  return { started: true, message: job.message };
}

export function resetBrowserLoginJob() {
  if (job.status !== "waiting") {
    job = { status: "idle" };
  }
}
