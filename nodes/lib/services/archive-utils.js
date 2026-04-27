const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const unzipper = require("unzipper");
const { sanitizeRelativeFile } = require("./security-utils");

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function removeDirRecursive(target) {
  if (fs.existsSync(target)) {
    fs.rmSync(target, { recursive: true, force: true });
  }
}

function secureJoin(baseDir, relativePath) {
  const rel = sanitizeRelativeFile(relativePath);
  const resolved = path.resolve(baseDir, rel);
  const root = path.resolve(baseDir);
  if (!resolved.startsWith(root + path.sep) && resolved !== root) {
    throw new Error("Ruta fuera de app");
  }
  return { resolved, rel };
}

function findIndexFiles(baseDir, currentDir = "") {
  const scan = path.join(baseDir, currentDir);
  if (!fs.existsSync(scan)) return [];
  const entries = fs.readdirSync(scan, { withFileTypes: true });
  const found = [];
  for (const entry of entries) {
    const rel = path.join(currentDir, entry.name);
    if (entry.isDirectory()) {
      found.push(...findIndexFiles(baseDir, rel));
      continue;
    }
    if (entry.isFile() && entry.name.toLowerCase() === "index.html") {
      found.push(rel.replace(/\\/g, "/"));
    }
  }
  return found;
}

function detectAppRoot(baseDir) {
  const rootIndex = path.join(baseDir, "index.html");
  if (fs.existsSync(rootIndex)) {
    return { rootSubpath: "", indexPath: rootIndex };
  }

  const candidates = findIndexFiles(baseDir);
  if (candidates.length === 1) {
    const relIndex = candidates[0];
    const relDir = path.dirname(relIndex).replace(/\\/g, "/");
    const rootSubpath = relDir === "." ? "" : relDir;
    return {
      rootSubpath,
      indexPath: path.join(baseDir, relIndex)
    };
  }
  return null;
}

function renderIndexWithBase(indexPath, routePrefix) {
  const routeBase = routePrefix.endsWith("/") ? routePrefix : `${routePrefix}/`;
  const html = fs.readFileSync(indexPath, "utf8");
  const baseTagRegex = /<base\s+href\s*=\s*["'][^"']*["']\s*\/?>/i;
  if (baseTagRegex.test(html)) {
    return html.replace(baseTagRegex, `<base href="${routeBase}">`);
  }
  const headCloseRegex = /<\/head>/i;
  if (headCloseRegex.test(html)) {
    return html.replace(headCloseRegex, `  <base href="${routeBase}">\n</head>`);
  }
  return `<base href="${routeBase}">\n${html}`;
}

async function extractZipSecure(zipPath, destinationDir, options = {}) {
  const maxFiles = Number(options.maxFiles || 4000);
  const maxUncompressedBytes = Number(options.maxUncompressedBytes || 1024 * 1024 * 512);

  ensureDir(destinationDir);
  const directory = await unzipper.Open.file(zipPath);

  let totalFiles = 0;
  let totalSize = 0;

  for (const entry of directory.files) {
    const entryPath = String(entry.path || "").replace(/\\/g, "/");
    if (!entryPath || entry.type === "Directory") {
      continue;
    }

    totalFiles += 1;
    if (totalFiles > maxFiles) {
      throw new Error(`ZIP excede maximo de archivos (${maxFiles})`);
    }

    totalSize += Number(entry.uncompressedSize || 0);
    if (totalSize > maxUncompressedBytes) {
      throw new Error(`ZIP excede tamano descomprimido permitido (${maxUncompressedBytes} bytes)`);
    }

    const safePath = sanitizeRelativeFile(entryPath);
    const target = path.resolve(destinationDir, safePath);
    const root = path.resolve(destinationDir);
    if (!target.startsWith(root + path.sep) && target !== root) {
      throw new Error("ZIP contiene rutas fuera del destino (zip slip)");
    }

    ensureDir(path.dirname(target));
    await new Promise((resolve, reject) => {
      let streamOrPromise;
      try {
        streamOrPromise = entry.stream();
      } catch (err) {
        reject(err);
        return;
      }

      const handleReadable = (readable) => {
        const writable = fs.createWriteStream(target, { mode: 0o600 });
        readable.on("error", reject);
        writable.on("error", reject);
        writable.on("finish", resolve);
        readable.pipe(writable);
      };

      if (streamOrPromise && typeof streamOrPromise.then === "function") {
        streamOrPromise.then(handleReadable).catch(reject);
      } else {
        handleReadable(streamOrPromise);
      }
    });
  }

  return { files: totalFiles, uncompressedBytes: totalSize };
}

function sha256File(filePath) {
  const hash = crypto.createHash("sha256");
  const data = fs.readFileSync(filePath);
  hash.update(data);
  return hash.digest("hex");
}

function copyDirRecursive(src, dst) {
  fs.cpSync(src, dst, { recursive: true, force: true });
}

module.exports = {
  ensureDir,
  removeDirRecursive,
  secureJoin,
  findIndexFiles,
  detectAppRoot,
  renderIndexWithBase,
  extractZipSecure,
  sha256File,
  copyDirRecursive
};
