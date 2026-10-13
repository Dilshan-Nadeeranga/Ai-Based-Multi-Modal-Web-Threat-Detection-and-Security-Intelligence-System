/**
 * Open a visible browser to log in to Reddit manually (CAPTCHA / 2FA safe).
 * Usage: node scripts/reddit-browser-login.js
 */
import { loginWithBrowser } from "../redditAuth/login.js";

loginWithBrowser()
  .then((r) => {
    console.log(JSON.stringify(r, null, 2));
    process.exit(0);
  })
  .catch((err) => {
    console.error(err.message);
    process.exit(1);
  });
