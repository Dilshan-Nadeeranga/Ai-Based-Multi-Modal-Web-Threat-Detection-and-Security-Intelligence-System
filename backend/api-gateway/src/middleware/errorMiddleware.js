const { isProduction } = require("../config/env");

function notFound(req, res) {
  res.status(404).json({ message: "Route not found." });
}

// Express recognizes error handlers by their four arguments.
// eslint-disable-next-line no-unused-vars
function errorHandler(error, req, res, next) {
  if (error.isOperational) {
    const body = { message: error.message };
    if (error.details) body.errors = error.details;
    return res.status(error.statusCode).json(body);
  }
  if (error.type === "entity.parse.failed") {
    return res.status(400).json({ message: "Request body must be valid JSON." });
  }
  if (error.type === "entity.too.large") {
    return res.status(413).json({ message: "Request body is too large." });
  }
  if (error.code === "23505") {
    return res.status(409).json({ message: "A record with this value already exists." });
  }

  // Log the method/path and error only — never request bodies, cookies or tokens.
  console.error(`Unhandled error on ${req.method} ${req.originalUrl}:`, isProduction ? error.message : error);
  const body = { message: "Internal server error." };
  if (!isProduction) body.error = error.message;
  return res.status(500).json(body);
}

module.exports = { notFound, errorHandler };
