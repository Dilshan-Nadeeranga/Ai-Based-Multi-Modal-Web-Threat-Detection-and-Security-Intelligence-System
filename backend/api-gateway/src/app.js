require("dotenv").config({ quiet: true });

const express = require("express");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const helmet = require("helmet");

const { frontendOrigins, isProduction } = require("./config/env");
const { ping } = require("./config/database");
const analysisController = require("./controllers/analysisController");
const { requireAuth } = require("./middleware/authMiddleware");
const { errorHandler, notFound } = require("./middleware/errorMiddleware");
const adminRoutes = require("./routes/adminRoutes");
const analysisRoutes = require("./routes/analysisRoutes");
const authRoutes = require("./routes/authRoutes");
const codeAuditRoutes = require("./routes/codeAuditRoutes");
const userRoutes = require("./routes/userRoutes");

const app = express();

app.disable("x-powered-by");
// Behind a reverse proxy in production, so rate limiting sees the real client IP.
if (isProduction) app.set("trust proxy", 1);

app.use(helmet());
// Vite moves to 5174+ when 5173 is busy, so dev also accepts any localhost port.
const DEV_LOCALHOST_ORIGIN = /^http:\/\/(localhost|127\.0\.0\.1):\d+$/;
const allowedOrigins = isProduction ? frontendOrigins : [...frontendOrigins, DEV_LOCALHOST_ORIGIN];

app.use(cors({ origin: allowedOrigins, credentials: true }));
app.use(express.json({ limit: "100kb" }));
app.use(cookieParser());

app.get("/", (req, res) => {
  res.json({ message: "ScamTrace API Gateway Running", project: "J26-SE-316" });
});

app.get("/api/health", async (req, res) => {
  res.json({ status: "ok", database_connected: await ping() });
});

app.use("/api/auth", authRoutes);
app.use("/api/users", userRoutes);
app.use("/api/admin", adminRoutes);
app.use("/api/analysis", analysisRoutes);
app.use("/api/code-audit", codeAuditRoutes);

// Legacy multi-component endpoint, now authenticated and stored like POST /api/analysis.
app.post("/api/analyze", requireAuth, analysisController.analyze);

app.use(notFound);
app.use(errorHandler);

module.exports = app;
