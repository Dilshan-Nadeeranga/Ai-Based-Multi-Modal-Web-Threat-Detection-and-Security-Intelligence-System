const express = require("express");
const rateLimit = require("express-rate-limit");
const { authRateLimit } = require("../config/env");
const authController = require("../controllers/authController");
const { requireAuth } = require("../middleware/authMiddleware");

const router = express.Router();

function limiter(limit, message) {
  return rateLimit({
    windowMs: authRateLimit.windowMs,
    limit,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: { message },
  });
}

const loginLimiter = limiter(authRateLimit.loginMax, "Too many login attempts. Please try again later.");
const registerLimiter = limiter(authRateLimit.registerMax, "Too many registration attempts. Please try again later.");

router.post("/register", registerLimiter, authController.register);
router.post("/login", loginLimiter, authController.login);
router.post("/logout", authController.logout);
router.get("/me", requireAuth, authController.me);

module.exports = router;
