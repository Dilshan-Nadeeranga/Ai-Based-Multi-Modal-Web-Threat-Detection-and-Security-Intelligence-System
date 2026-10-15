const AppError = require("./AppError");

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ROLES = Object.freeze(["USER", "ADMIN"]);

const PASSWORD_MIN = 8;
// bcrypt only uses the first 72 bytes; longer passwords are rejected instead of silently truncated.
const PASSWORD_MAX_BYTES = 72;

function normalizeEmail(email) {
  return typeof email === "string" ? email.trim().toLowerCase() : "";
}

function validateName(name) {
  const value = typeof name === "string" ? name.trim().replace(/\s+/g, " ") : "";
  if (value.length < 2 || value.length > 100) {
    return { error: "Name must be between 2 and 100 characters." };
  }
  return { value };
}

function validateEmail(email) {
  const value = normalizeEmail(email);
  if (!value || value.length > 255 || !EMAIL_PATTERN.test(value)) {
    return { error: "A valid email address is required." };
  }
  return { value };
}

function validatePassword(password, field = "Password") {
  if (typeof password !== "string" || password.length < PASSWORD_MIN) {
    return { error: `${field} must be at least ${PASSWORD_MIN} characters.` };
  }
  if (Buffer.byteLength(password, "utf8") > PASSWORD_MAX_BYTES) {
    return { error: `${field} must be at most ${PASSWORD_MAX_BYTES} bytes.` };
  }
  return { value: password };
}

/** Throw a 400 with per-field messages when any validation failed. */
function assertValid(results) {
  const errors = Object.fromEntries(
    Object.entries(results).filter(([, result]) => result.error).map(([field, result]) => [field, result.error])
  );
  if (Object.keys(errors).length) {
    throw new AppError(400, Object.values(errors)[0], errors);
  }
  return Object.fromEntries(Object.entries(results).map(([field, result]) => [field, result.value]));
}

function isUuid(value) {
  return typeof value === "string" && UUID_PATTERN.test(value);
}

module.exports = {
  ROLES,
  normalizeEmail,
  validateName,
  validateEmail,
  validatePassword,
  assertValid,
  isUuid,
};
