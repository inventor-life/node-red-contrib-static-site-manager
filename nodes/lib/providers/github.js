const { buildAuthHeaders, fetchJson, downloadToFile } = require("./http-utils");
const { hmacSha256Hex, safeTimingEqual } = require("../services/security-utils");

function apiBase(config) {
  return String(config.baseUrl || "https://api.github.com").replace(/\/+$/, "");
}

function pickAsset(release, artifactName) {
  const assets = Array.isArray(release.assets) ? release.assets : [];
  if (!assets.length) return null;
  if (artifactName) {
    const exact = assets.find((a) => a && a.name === artifactName);
    if (exact) return exact;
  }
  const zipAsset = assets.find((a) => a && /\.zip$/i.test(String(a.name || "")));
  return zipAsset || assets[0];
}

class GitHubProvider {
  name() {
    return "github";
  }

  validateConfig(config) {
    if (!config.owner || !config.repo) {
      throw new Error("Config GitHub incompleta: owner y repo son obligatorios");
    }
    if (config.sourceType && config.sourceType !== "release_asset") {
      throw new Error("Por ahora GitHub soporta sourceType=release_asset");
    }
  }

  async testConnection(config, secrets) {
    this.validateConfig(config);
    const headers = {
      Accept: "application/vnd.github+json",
      "User-Agent": "static-site-manager",
      ...buildAuthHeaders(secrets)
    };
    const repo = await fetchJson(`${apiBase(config)}/repos/${config.owner}/${config.repo}`, {
      headers,
      insecureTls: Boolean(config.insecureTls)
    });
    return {
      ok: true,
      repository: repo.full_name,
      private: Boolean(repo.private),
      defaultBranch: repo.default_branch || ""
    };
  }

  async listVersions(config, secrets) {
    this.validateConfig(config);
    const headers = {
      Accept: "application/vnd.github+json",
      "User-Agent": "static-site-manager",
      ...buildAuthHeaders(secrets)
    };

    const releases = await fetchJson(
      `${apiBase(config)}/repos/${config.owner}/${config.repo}/releases?per_page=30`,
      {
        headers,
        insecureTls: Boolean(config.insecureTls)
      }
    );

    const result = [];
    for (const release of Array.isArray(releases) ? releases : []) {
      if (!release || release.draft) continue;
      const asset = pickAsset(release, config.artifactName);
      if (!asset) continue;

      result.push({
        id: `gh-release-${release.id}-${asset.id}`,
        version: release.tag_name || release.name || String(release.id),
        releaseId: release.id,
        assetId: asset.id,
        assetName: asset.name,
        tag: release.tag_name || "",
        createdAt: release.published_at || release.created_at || "",
        commitSha: release.target_commitish || "",
        notes: release.name || "",
        sourceRef: {
          releaseApiUrl: release.url,
          assetApiUrl: asset.url,
          browserDownloadUrl: asset.browser_download_url
        }
      });
    }

    result.sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
    return result;
  }

  async resolveLatest(config, secrets) {
    const versions = await this.listVersions(config, secrets);
    if (!versions.length) {
      throw new Error("No hay versiones publicadas en GitHub Release");
    }
    return versions[0];
  }

  async downloadVersion(config, secrets, version, targetFile, limits = {}) {
    const headers = {
      Accept: "application/octet-stream",
      "User-Agent": "static-site-manager",
      ...buildAuthHeaders(secrets)
    };

    const sourceUrl =
      (version && version.sourceRef && version.sourceRef.assetApiUrl) ||
      (version && version.sourceRef && version.sourceRef.browserDownloadUrl);

    if (!sourceUrl) {
      throw new Error("Version GitHub sin URL de descarga");
    }

    return downloadToFile(
      sourceUrl,
      { headers, redirect: "follow", insecureTls: Boolean(config.insecureTls) },
      targetFile,
      limits.maxZipBytes
    );
  }

  verifyWebhook(headers, rawBodyBuffer, appConfig, secrets) {
    const eventType = String(headers["x-github-event"] || "").toLowerCase();
    const deliveryId = String(headers["x-github-delivery"] || "");
    const signatureHeader = String(headers["x-hub-signature-256"] || "");
    const webhookSecret = String((secrets && secrets.webhookSecret) || "");

    if (!webhookSecret) {
      throw new Error("App sin webhookSecret configurado");
    }
    if (!signatureHeader.startsWith("sha256=")) {
      throw new Error("Firma GitHub ausente");
    }

    const provided = signatureHeader.slice("sha256=".length);
    const expected = hmacSha256Hex(webhookSecret, rawBodyBuffer);
    if (!safeTimingEqual(expected, provided)) {
      throw new Error("Firma GitHub invalida");
    }

    let payload;
    try {
      payload = JSON.parse(rawBodyBuffer.toString("utf8"));
    } catch (err) {
      throw new Error("Payload JSON invalido");
    }

    const repo = payload && payload.repository ? payload.repository : {};
    const repoFullName = String(repo.full_name || "").toLowerCase();
    const expectedRepo = `${String(appConfig.owner || "").toLowerCase()}/${String(appConfig.repo || "").toLowerCase()}`;
    if (!repoFullName || repoFullName !== expectedRepo) {
      throw new Error("Evento no pertenece al repo configurado");
    }

    let tag = "";
    let branch = "";
    if (eventType === "release") {
      tag = String(payload.release && payload.release.tag_name ? payload.release.tag_name : "");
    }
    if (eventType === "push") {
      const ref = String(payload.ref || "");
      branch = ref.replace(/^refs\/heads\//, "");
    }

    return {
      ok: true,
      provider: "github",
      eventType,
      action: String(payload.action || ""),
      deliveryId,
      repoFullName,
      branch,
      tag,
      payload
    };
  }
}

module.exports = {
  GitHubProvider
};
