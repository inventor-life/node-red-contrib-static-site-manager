const crypto = require("crypto");

function sanitizeAppName(value) {
  const name = String(value || "").trim().toLowerCase();
  if (!name) throw new Error("app es obligatorio");
  if (!/^[a-z0-9_-]+$/.test(name)) {
    throw new Error("app invalida. Usa solo a-z, 0-9, _ y -");
  }
  return name;
}

function sanitizeRoute(value) {
  let route = String(value || "").trim();
  if (!route) throw new Error("route es obligatoria");
  if (!route.startsWith("/")) route = `/${route}`;
  route = route.replace(/\/+$/, "");
  if (!route) route = "/";
  if (route === "/") {
    throw new Error("No se permite usar '/' como route de app");
  }
  if (!/^\/[A-Za-z0-9_\-\/]*$/.test(route)) {
    throw new Error("route invalida");
  }
  return route;
}

function sanitizeRelativeFile(rel) {
  const normalized = String(rel || "")
    .replace(/\\/g, "/")
    .replace(/^\/+/, "")
    .trim();
  if (!normalized) throw new Error("filePath es obligatorio");
  if (normalized.includes("..")) throw new Error("Ruta no permitida");
  if (normalized.includes("\0")) throw new Error("Ruta invalida");
  return normalized;
}

function sanitizeRootSubpath(rel) {
  const normalized = String(rel || "")
    .replace(/\\/g, "/")
    .replace(/^\/+/, "")
    .trim();
  if (!normalized) return "";
  if (normalized.includes("..")) throw new Error("rootSubpath invalido");
  if (normalized.includes("\0")) throw new Error("rootSubpath invalido");
  return normalized;
}

function splitCsvToList(value) {
  return String(value || "")
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);
}

function normalizeStringList(value) {
  if (Array.isArray(value)) {
    return value.map((x) => String(x || "").trim()).filter(Boolean);
  }
  return splitCsvToList(value);
}

function wildcardToRegExp(pattern) {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  return new RegExp(`^${escaped}$`);
}

function matchesAnyPattern(value, patterns) {
  const testValue = String(value || "");
  if (!patterns || !patterns.length) return true;
  return patterns.some((rawPattern) => {
    const pattern = String(rawPattern || "").trim();
    if (!pattern) return false;
    if (pattern === testValue) return true;
    if (pattern.includes("*")) {
      return wildcardToRegExp(pattern).test(testValue);
    }
    return false;
  });
}

function safeTimingEqual(expected, actual) {
  const a = Buffer.from(String(expected || ""));
  const b = Buffer.from(String(actual || ""));
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function hmacSha256Hex(secret, payloadBuffer) {
  return crypto.createHmac("sha256", String(secret || "")).update(payloadBuffer).digest("hex");
}

module.exports = {
  sanitizeAppName,
  sanitizeRoute,
  sanitizeRelativeFile,
  sanitizeRootSubpath,
  normalizeStringList,
  matchesAnyPattern,
  safeTimingEqual,
  hmacSha256Hex
};
