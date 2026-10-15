const isProduction = process.env.NODE_ENV === "production";

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  throw new Error("JWT_SECRET must be set to a random value of at least 32 characters.");
}

module.exports = {
  isProduction,
  port: Number(process.env.PORT) || 5000,
  jwtSecret: JWT_SECRET,
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || "1h",
  frontendOrigins: (process.env.FRONTEND_URL || "http://localhost:5173")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean),
  c4BaseUrl: (process.env.C4_URL || "http://localhost:8000").replace(/\/+$/, ""),
  authRateLimit: {
    windowMs: Number(process.env.AUTH_RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
    loginMax: Number(process.env.LOGIN_RATE_LIMIT_MAX) || 10,
    registerMax: Number(process.env.REGISTER_RATE_LIMIT_MAX) || 5,
  },
};
