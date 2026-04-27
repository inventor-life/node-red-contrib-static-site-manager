const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const {
  ensureDir,
  removeDirRecursive,
  extractZipSecure,
  detectAppRoot,
  sha256File,
  copyDirRecursive
} = require("./archive-utils");
const { sanitizeAppName } = require("./security-utils");

function nowIso() {
  return new Date().toISOString();
}

function versionFromNow(prefix = "r") {
  const d = new Date();
  const stamp = `${d.getUTCFullYear()}${String(d.getUTCMonth() + 1).padStart(2, "0")}${String(d.getUTCDate()).padStart(2, "0")}-${String(
    d.getUTCHours()
  ).padStart(2, "0")}${String(d.getUTCMinutes()).padStart(2, "0")}${String(d.getUTCSeconds()).padStart(2, "0")}`;
  const rand = crypto.randomBytes(3).toString("hex");
  return `${prefix}-${stamp}-${rand}`;
}

class DeployManager {
  constructor(store, providers) {
    this.store = store;
    this.providers = providers || {};
  }

  providerForMode(mode) {
    if (!mode || mode === "manual") return null;
    const provider = this.providers[mode];
    if (!provider) {
      throw new Error(`Proveedor no soportado: ${mode}`);
    }
    return provider;
  }

  async listRemoteVersions(app) {
    const name = sanitizeAppName(app);
    const { config, secrets } = this.store.getAppWithSecrets(name);
    const provider = this.providerForMode(config.mode);
    if (!provider) {
      throw new Error("La app esta en modo manual");
    }
    provider.validateConfig(config.providerConfig);
    return provider.listVersions(config.providerConfig, secrets);
  }

  async testConnection(app) {
    const name = sanitizeAppName(app);
    const { config, secrets } = this.store.getAppWithSecrets(name);
    const provider = this.providerForMode(config.mode);
    if (!provider) {
      throw new Error("La app esta en modo manual");
    }
    provider.validateConfig(config.providerConfig);
    return provider.testConnection(config.providerConfig, secrets);
  }

  async checkUpdate(app) {
    const versions = await this.listRemoteVersions(app);
    const config = this.store.getConfig(app);
    const active = this.store.getDeployments(app).items.find((x) => x.version === config.activeRelease);
    const latest = versions[0] || null;
    const needsUpdate = !!(latest && (!active || active.sourceVersion !== latest.version));
    return {
      latest,
      active,
      needsUpdate,
      count: versions.length
    };
  }

  async deployLatest(app, options = {}) {
    const name = sanitizeAppName(app);
    const { config, secrets } = this.store.getAppWithSecrets(name);
    const provider = this.providerForMode(config.mode);
    if (!provider) {
      throw new Error("La app esta en modo manual");
    }

    provider.validateConfig(config.providerConfig);
    const latest = await provider.resolveLatest(config.providerConfig, secrets);
    return this.deployRemoteResolved(name, latest, options);
  }

  async deploySpecific(app, versionIdOrTag, options = {}) {
    const name = sanitizeAppName(app);
    const versions = await this.listRemoteVersions(name);
    const needle = String(versionIdOrTag || "").trim();
    if (!needle) {
      throw new Error("version es obligatoria");
    }

    const selected = versions.find((x) => x.id === needle || x.version === needle || x.tag === needle);
    if (!selected) {
      throw new Error("Version no encontrada en proveedor remoto");
    }

    return this.deployRemoteResolved(name, selected, options);
  }

  async deployRemoteResolved(app, remoteVersion, options = {}) {
    const name = sanitizeAppName(app);
    const { config, secrets } = this.store.getAppWithSecrets(name);
    const provider = this.providerForMode(config.mode);
    if (!provider) {
      throw new Error("La app esta en modo manual");
    }

    const tmpRoot = path.join(this.store.appDir(name), ".tmp", `remote-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`);
    const zipPath = path.join(tmpRoot, "artifact.zip");
    const extractedPath = path.join(tmpRoot, "extracted");

    ensureDir(tmpRoot);
    let deployment = null;

    try {
      this.store.appendLog(name, "info", "Descargando artefacto remoto", {
        sourceVersion: remoteVersion.version,
        provider: config.mode
      });

      await provider.downloadVersion(config.providerConfig, secrets, remoteVersion, zipPath, {
        maxZipBytes: config.security.maxZipBytes
      });

      const checksum = sha256File(zipPath);

      await extractZipSecure(zipPath, extractedPath, {
        maxFiles: config.security.maxFiles,
        maxUncompressedBytes: config.security.maxZipBytes * 6
      });

      deployment = this.finalizeExtractedDeployment(name, extractedPath, {
        provider: config.mode,
        sourceType: config.providerConfig.sourceType,
        sourceVersion: remoteVersion.version,
        commitSha: remoteVersion.commitSha || "",
        artifactName: remoteVersion.assetName || "",
        checksum,
        deployedBy: options.deployedBy || "api",
        notes: options.notes || "",
        eventId: options.eventId || "",
        branch: options.branch || config.providerConfig.branch || "",
        tag: remoteVersion.tag || options.tag || "",
        repo: `${config.providerConfig.owner}/${config.providerConfig.repo}`,
        route: options.route || config.route || ""
      });

      this.store.appendLog(name, "info", "Deploy remoto exitoso", {
        version: deployment.version,
        sourceVersion: deployment.sourceVersion
      });

      return deployment;
    } catch (err) {
      this.store.appendLog(name, "error", "Deploy remoto fallido", {
        message: err.message,
        sourceVersion: remoteVersion && remoteVersion.version ? remoteVersion.version : ""
      });
      throw err;
    } finally {
      removeDirRecursive(tmpRoot);
    }
  }

  deployManual(app, route, options = {}) {
    const name = sanitizeAppName(app);
    const manualState = this.store.getManualUploadState(name);
    if (!manualState.hasContent) {
      throw new Error("No hay archivos en staging manual. Ejecuta prepare-upload y upload-file primero.");
    }

    const tmpRoot = path.join(this.store.appDir(name), ".tmp", `manual-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`);
    const extractedPath = path.join(tmpRoot, "manual-files");
    ensureDir(tmpRoot);

    try {
      copyDirRecursive(manualState.manualDir, extractedPath);
      const deployment = this.finalizeExtractedDeployment(name, extractedPath, {
        provider: "manual",
        sourceType: "manual_upload",
        sourceVersion: options.sourceVersion || "manual",
        commitSha: "",
        artifactName: "manual-upload",
        checksum: "",
        deployedBy: options.deployedBy || "panel",
        notes: options.notes || "",
        eventId: options.eventId || "",
        branch: "",
        tag: "",
        repo: "",
        route
      });
      this.store.appendLog(name, "info", "Deploy manual exitoso", {
        version: deployment.version,
        route: deployment.route
      });
      return deployment;
    } finally {
      removeDirRecursive(tmpRoot);
    }
  }

  rollback(app, version, options = {}) {
    const name = sanitizeAppName(app);
    const deployments = this.store.getDeployments(name);
    const selected = deployments.items.find((x) => x.version === String(version || ""));
    if (!selected) {
      throw new Error("Version no encontrada para rollback");
    }

    const releaseDir = this.store.releaseDir(name, selected.version);
    if (!fs.existsSync(releaseDir)) {
      throw new Error("Release no existe en disco");
    }

    const cfg = this.store.getConfig(name);
    const targetRoute = options.route || cfg.route;
    if (!targetRoute) {
      throw new Error("La app no tiene route configurada");
    }

    this.store.setActiveRelease(name, selected.version, selected.rootSubpath || "");
    this.store.updateRoute(name, targetRoute);

    const rollbackEvent = {
      version: versionFromNow("rollback"),
      provider: "manual",
      sourceType: "rollback",
      sourceVersion: selected.sourceVersion || selected.version,
      commitSha: selected.commitSha || "",
      artifactName: selected.artifactName || "",
      checksum: selected.checksum || "",
      deployedAt: nowIso(),
      deployedBy: options.deployedBy || "api",
      status: "success",
      rootSubpath: selected.rootSubpath || "",
      notes: `Rollback a ${selected.version}`,
      eventId: options.eventId || "",
      route: targetRoute,
      repo: selected.repo || "",
      branch: selected.branch || "",
      tag: selected.tag || ""
    };

    this.store.appendDeployment(name, rollbackEvent);
    this.store.appendLog(name, "warn", "Rollback aplicado", {
      toVersion: selected.version,
      rollbackEvent: rollbackEvent.version
    });

    return {
      ok: true,
      activeRelease: selected.version,
      deployment: rollbackEvent
    };
  }

  finalizeExtractedDeployment(app, extractedPath, meta) {
    const name = sanitizeAppName(app);
    const detected = detectAppRoot(extractedPath);
    if (!detected) {
      const details = "La app no tiene index.html unico en root/subcarpeta";
      throw new Error(details);
    }

    const route = meta.route || this.store.getConfig(name).route;
    if (!route) {
      throw new Error("route es obligatoria para activar deployment");
    }

    const version = versionFromNow(meta.provider === "manual" ? "manual" : meta.provider);
    const releaseDir = this.store.releaseDir(name, version);

    if (fs.existsSync(releaseDir)) {
      throw new Error(`Release ya existe: ${version}`);
    }

    ensureDir(path.dirname(releaseDir));
    fs.renameSync(extractedPath, releaseDir);

    const deployment = {
      version,
      provider: String(meta.provider || "manual"),
      sourceType: String(meta.sourceType || "manual_upload"),
      sourceVersion: String(meta.sourceVersion || version),
      commitSha: String(meta.commitSha || ""),
      artifactName: String(meta.artifactName || ""),
      checksum: String(meta.checksum || ""),
      deployedAt: nowIso(),
      deployedBy: String(meta.deployedBy || "api"),
      status: "success",
      rootSubpath: detected.rootSubpath,
      notes: String(meta.notes || ""),
      eventId: String(meta.eventId || ""),
      route: String(route || ""),
      repo: String(meta.repo || ""),
      branch: String(meta.branch || ""),
      tag: String(meta.tag || "")
    };

    this.store.appendDeployment(name, deployment);
    this.store.setActiveRelease(name, version, detected.rootSubpath);
    this.store.updateRoute(name, route);
    return deployment;
  }
}

module.exports = {
  DeployManager
};
