const { buildAuthHeaders, fetchJson, downloadToFile } = require("./http-utils");
const { hmacSha256Hex, safeTimingEqual } = require("../services/security-utils");

function apiBase(config) {
  return String(config.baseUrl || "https://gitea.com/api/v1").replace(/\/+$/, "");
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

class GiteaProvider {
  name() {
    return "gitea";
  }

  validateConfig(config) {
    if (!config.owner || !config.repo) {
      throw new Error("Config Gitea incompleta: owner y repo son obligatorios");
    }
    if (config.sourceType && config.sourceType !== "release_asset") {
      throw new Error("Por ahora Gitea soporta sourceType=release_asset");
    }
  }

  async testConnection(config, secrets) {
    this.validateConfig(config);
    const headers = {
      Accept: "application/json",
      ...buildAuthHeaders(secrets)
    };
    const repo = await fetchJson(`${apiBase(config)}/repos/${config.owner}/${config.repo}`, {
      headers,
      insecureTls: Boolean(config.insecureTls)
    });
    return {
      ok: true,
      repository: repo.full_name || `${config.owner}/${config.repo}`,
      private: Boolean(repo.private),
      defaultBranch: repo.default_branch || ""
    };
  }

  async listVersions(config, secrets) {
    this.validateConfig(config);
    const headers = {
      Accept: "application/json",
      ...buildAuthHeaders(secrets)
    };

    const releases = await fetchJson(`${apiBase(config)}/repos/${config.owner}/${config.repo}/releases?page=1&limit=30`, {
      headers,
      insecureTls: Boolean(config.insecureTls)
    });

    const result = [];
    for (const release of Array.isArray(releases) ? releases : []) {
      if (!release || release.draft) continue;
      const asset = pickAsset(release, config.artifactName);
      if (!asset) continue;

      result.push({
        id: `gitea-release-${release.id}-${asset.id}`,
        version: release.tag_name || release.name || String(release.id),
        releaseId: release.id,
        assetId: asset.id,
        assetName: asset.name,
        tag: release.tag_name || "",
        createdAt: release.published_at || release.created_at || "",
        commitSha: release.target_commitish || "",
        notes: release.name || "",
        sourceRef: {
          browserDownloadUrl: asset.browser_download_url,
          assetApiUrl: asset.url
        }
      });
    }

    result.sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
    return result;
  }

  async resolveLatest(config, secrets) {
    const versions = await this.listVersions(config, secrets);
    if (!versions.length) {
      throw new Error("No hay versiones publicadas en Gitea Release");
    }
    return versions[0];
  }

  async downloadVersion(config, secrets, version, targetFile, limits = {}) {
    const headers = {
      Accept: "application/octet-stream",
      ...buildAuthHeaders(secrets)
    };

    const sourceUrl =
      (version && version.sourceRef && version.sourceRef.browserDownloadUrl) ||
      (version && version.sourceRef && version.sourceRef.assetApiUrl);

    if (!sourceUrl) {
      throw new Error("Version Gitea sin URL de descarga");
    }

    return downloadToFile(
      sourceUrl,
      { headers, redirect: "follow", insecureTls: Boolean(config.insecureTls) },
      targetFile,
      limits.maxZipBytes
    );
  }

  verifyWebhook(headers, rawBodyBuffer, appConfig, secrets) {
    const eventType = String(headers["x-gitea-event"] || "").toLowerCase();
    const deliveryId = String(headers["x-gitea-delivery"] || "");
    const signature = String(headers["x-gitea-signature"] || "");
    const webhookSecret = String((secrets && secrets.webhookSecret) || "");

    if (!webhookSecret) {
      throw new Error("App sin webhookSecret configurado");
    }
    if (!signature) {
      throw new Error("Firma Gitea ausente");
    }

    const expected = hmacSha256Hex(webhookSecret, rawBodyBuffer);
    if (!safeTimingEqual(expected, signature)) {
      throw new Error("Firma Gitea invalida");
    }

    let payload;
    try {
      payload = JSON.parse(rawBodyBuffer.toString("utf8"));
    } catch (err) {
      throw new Error("Payload JSON invalido");
    }

    const repo = payload && payload.repository ? payload.repository : {};
    const repoFullName = String(repo.full_name || `${repo.owner && repo.owner.username ? repo.owner.username : ""}/${repo.name || ""}`)
      .toLowerCase();
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
      provider: "gitea",
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
  GiteaProvider
};
