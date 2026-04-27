const fs = require("fs");
const tls = require("tls");

function buildFetchOptions(options = {}) {
  const next = { ...options };
  delete next.insecureTls;
  return next;
}

async function fetchWithOptionalInsecureTls(url, options = {}) {
  const insecureTls = Boolean(options.insecureTls);
  const fetchOptions = buildFetchOptions(options);
  if (!insecureTls) {
    return fetch(url, fetchOptions);
  }

  // Fallback compatible with Node runtimes where fetch does not expose custom dispatcher modules.
  const previous = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  const previousGlobal = tls.DEFAULT_REJECT_UNAUTHORIZED;
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
  tls.DEFAULT_REJECT_UNAUTHORIZED = false;
  try {
    return await fetch(url, fetchOptions);
  } finally {
    if (typeof previous === "undefined") {
      delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    } else {
      process.env.NODE_TLS_REJECT_UNAUTHORIZED = previous;
    }
    tls.DEFAULT_REJECT_UNAUTHORIZED = previousGlobal;
  }
}

function buildAuthHeaders(secrets = {}) {
  const token = String(secrets.token || "").trim();
  if (!token) return {};

  const authType = String(secrets.authType || "bearer").toLowerCase();
  if (authType === "header") {
    const headerName = String(secrets.authHeaderName || "Authorization").trim();
    return { [headerName]: token };
  }
  if (authType === "token") {
    return { Authorization: `token ${token}` };
  }
  return { Authorization: `Bearer ${token}` };
}

async function fetchJson(url, options = {}) {
  const res = await fetchWithOptionalInsecureTls(url, options);
  const text = await res.text();
  let payload = null;
  try {
    payload = text ? JSON.parse(text) : null;
  } catch (err) {
    payload = null;
  }

  if (!res.ok) {
    const message = payload && payload.message ? payload.message : `HTTP ${res.status}`;
    const error = new Error(message);
    error.status = res.status;
    error.payload = payload;
    throw error;
  }
  return payload;
}

async function downloadToFile(url, options = {}, targetFile, maxBytes) {
  const res = await fetchWithOptionalInsecureTls(url, options);
  if (!res.ok) {
    const bodyText = await res.text();
    throw new Error(`Error descargando artefacto: HTTP ${res.status} ${bodyText.slice(0, 200)}`);
  }

  const contentLength = Number(res.headers.get("content-length") || 0);
  if (maxBytes && contentLength && contentLength > maxBytes) {
    throw new Error(`Artefacto excede maximo permitido (${maxBytes} bytes)`);
  }

  const arr = await res.arrayBuffer();
  const buffer = Buffer.from(arr);
  const downloaded = buffer.length;
  if (maxBytes && downloaded > maxBytes) {
    throw new Error(`Artefacto excede maximo permitido (${maxBytes} bytes)`);
  }
  fs.mkdirSync(require("path").dirname(targetFile), { recursive: true });
  fs.writeFileSync(targetFile, buffer, { mode: 0o600 });

  return { downloaded };
}

module.exports = {
  buildAuthHeaders,
  fetchJson,
  downloadToFile
};
