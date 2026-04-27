const fs = require("fs");
const path = require("path");
const {
  sanitizeAppName,
  sanitizeRoute,
  sanitizeRelativeFile,
  sanitizeRootSubpath,
  normalizeStringList
} = require("./security-utils");
const { ensureDir, removeDirRecursive, secureJoin, detectAppRoot, copyDirRecursive } = require("./archive-utils");

function nowIso() {
  return new Date().toISOString();
}

class ReleaseStore {
  constructor(storageRoot, options = {}) {
    this.storageRoot = storageRoot;
    this.legacyRoutesFile = path.join(storageRoot, "routes.json");
    this.defaults = {
      maxZipBytes: Number(options.maxZipBytes || process.env.ANGULAR_PANEL_MAX_ZIP_BYTES || 250 * 1024 * 1024),
      maxFiles: Number(options.maxFiles || process.env.ANGULAR_PANEL_MAX_FILES || 12000)
    };
    ensureDir(this.storageRoot);
  }

  appDir(app) {
    return path.join(this.storageRoot, sanitizeAppName(app));
  }

  releasesDir(app) {
    return path.join(this.appDir(app), "releases");
  }

  stagingDir(app) {
    return path.join(this.appDir(app), "staging");
  }

  manualStagingDir(app) {
    return path.join(this.stagingDir(app), "manual");
  }

  configPath(app) {
    return path.join(this.appDir(app), "config.json");
  }

  secretsPath(app) {
    return path.join(this.appDir(app), "credentials.json");
  }

  deploymentsPath(app) {
    return path.join(this.appDir(app), "deployments.json");
  }

  logsPath(app) {
    return path.join(this.appDir(app), "logs.json");
  }

  webhookStatePath(app) {
    return path.join(this.appDir(app), "webhook_state.json");
  }

  currentPath(app) {
    return path.join(this.appDir(app), "current");
  }

  ensureApp(app) {
    const name = sanitizeAppName(app);
    ensureDir(this.appDir(name));
    ensureDir(this.releasesDir(name));
    ensureDir(this.stagingDir(name));
    this.getConfig(name);
    this.getSecrets(name);
    this.getDeployments(name);
    this.getLogs(name);
    this.getWebhookState(name);
    return name;
  }

  defaultConfig(app) {
    return {
      app,
      enabled: true,
      route: "",
      mode: "manual",
      activeRelease: "",
      activeRootSubpath: "",
      providerConfig: {
        provider: "",
        sourceType: "release_asset",
        owner: "",
        repo: "",
        baseUrl: "",
        insecureTls: false,
        artifactName: "",
        branch: "",
        tag: ""
      },
      webhooks: {
        enabled: false,
        autoDeploy: false,
        allowedBranches: [],
        allowedTags: []
      },
      security: {
        maxZipBytes: this.defaults.maxZipBytes,
        maxFiles: this.defaults.maxFiles
      },
      createdAt: nowIso(),
      updatedAt: nowIso(),
      lastDeployAt: ""
    };
  }

  defaultSecrets() {
    return {
      token: "",
      authType: "bearer",
      authHeaderName: "Authorization",
      webhookSecret: ""
    };
  }

  defaultDeployments() {
    return {
      activeVersion: "",
      items: []
    };
  }

  defaultLogs() {
    return {
      items: []
    };
  }

  defaultWebhookState() {
    return {
      deliveries: {}
    };
  }

  readJson(filePath, fallback) {
    if (!fs.existsSync(filePath)) {
      this.writeJson(filePath, fallback);
      return JSON.parse(JSON.stringify(fallback));
    }
    try {
      return JSON.parse(fs.readFileSync(filePath, "utf8"));
    } catch (err) {
      return JSON.parse(JSON.stringify(fallback));
    }
  }

  writeJson(filePath, value) {
    ensureDir(path.dirname(filePath));
    fs.writeFileSync(filePath, JSON.stringify(value, null, 2), { encoding: "utf8", mode: 0o600 });
  }

  getConfig(app) {
    const name = this.ensureAppBare(app);
    const raw = this.readJson(this.configPath(name), this.defaultConfig(name));
    return this.normalizeConfig(name, raw);
  }

  saveConfig(app, inputPatch = {}) {
    const name = this.ensureAppBare(app);
    const existing = this.getConfig(name);

    const routeInput = Object.prototype.hasOwnProperty.call(inputPatch, "route") ? inputPatch.route : existing.route;
    let route = "";
    if (routeInput) {
      route = sanitizeRoute(routeInput);
    }

    const modeInput = String(inputPatch.mode || existing.mode || "manual").toLowerCase();
    const mode = ["manual", "github", "gitea"].includes(modeInput) ? modeInput : "manual";

    const provider = Object.assign({}, existing.providerConfig, inputPatch.providerConfig || {});
    const normalizedProvider = {
      provider: String(provider.provider || (mode === "manual" ? "" : mode)).toLowerCase(),
      sourceType: String(provider.sourceType || "release_asset").toLowerCase(),
      owner: String(provider.owner || "").trim(),
      repo: String(provider.repo || "").trim(),
      baseUrl: String(provider.baseUrl || "").trim(),
      insecureTls: Boolean(provider.insecureTls),
      artifactName: String(provider.artifactName || "").trim(),
      branch: String(provider.branch || "").trim(),
      tag: String(provider.tag || "").trim()
    };

    const webhooks = Object.assign({}, existing.webhooks, inputPatch.webhooks || {});
    const security = Object.assign({}, existing.security, inputPatch.security || {});

    const next = {
      ...existing,
      app: name,
      enabled: Object.prototype.hasOwnProperty.call(inputPatch, "enabled") ? Boolean(inputPatch.enabled) : Boolean(existing.enabled),
      route,
      mode,
      providerConfig: normalizedProvider,
      webhooks: {
        enabled: Boolean(webhooks.enabled),
        autoDeploy: Boolean(webhooks.autoDeploy),
        allowedBranches: normalizeStringList(webhooks.allowedBranches),
        allowedTags: normalizeStringList(webhooks.allowedTags)
      },
      security: {
        maxZipBytes: Number(security.maxZipBytes || this.defaults.maxZipBytes),
        maxFiles: Number(security.maxFiles || this.defaults.maxFiles)
      },
      updatedAt: nowIso()
    };

    this.writeJson(this.configPath(name), next);
    this.writeLegacyRoutesFromConfigs();
    return next;
  }

  getSecrets(app) {
    const name = this.ensureAppBare(app);
    const raw = this.readJson(this.secretsPath(name), this.defaultSecrets());
    return {
      token: String(raw.token || ""),
      authType: String(raw.authType || "bearer"),
      authHeaderName: String(raw.authHeaderName || "Authorization"),
      webhookSecret: String(raw.webhookSecret || "")
    };
  }

  saveSecrets(app, patch = {}) {
    const name = this.ensureAppBare(app);
    const current = this.getSecrets(name);
    const next = {
      token: Object.prototype.hasOwnProperty.call(patch, "token") ? String(patch.token || "") : current.token,
      authType: Object.prototype.hasOwnProperty.call(patch, "authType") ? String(patch.authType || "bearer") : current.authType,
      authHeaderName: Object.prototype.hasOwnProperty.call(patch, "authHeaderName") ? String(patch.authHeaderName || "Authorization") : current.authHeaderName,
      webhookSecret: Object.prototype.hasOwnProperty.call(patch, "webhookSecret") ? String(patch.webhookSecret || "") : current.webhookSecret
    };
    this.writeJson(this.secretsPath(name), next);
    return next;
  }

  getDeployments(app) {
    const name = this.ensureAppBare(app);
    const data = this.readJson(this.deploymentsPath(name), this.defaultDeployments());
    if (!Array.isArray(data.items)) data.items = [];
    data.activeVersion = String(data.activeVersion || "");
    return data;
  }

  saveDeployments(app, value) {
    const name = this.ensureAppBare(app);
    const next = {
      activeVersion: String(value.activeVersion || ""),
      items: Array.isArray(value.items) ? value.items : []
    };
    this.writeJson(this.deploymentsPath(name), next);
    return next;
  }

  appendDeployment(app, deployment) {
    const name = this.ensureAppBare(app);
    const deployments = this.getDeployments(name);
    deployments.items.unshift(deployment);
    deployments.items = deployments.items.slice(0, 300);
    if (deployment.status === "success") {
      deployments.activeVersion = String(deployment.version || "");
    }
    this.saveDeployments(name, deployments);
    return deployments;
  }

  getLogs(app) {
    const name = this.ensureAppBare(app);
    const logs = this.readJson(this.logsPath(name), this.defaultLogs());
    if (!Array.isArray(logs.items)) logs.items = [];
    return logs;
  }

  appendLog(app, level, message, meta = {}) {
    const name = this.ensureAppBare(app);
    const logs = this.getLogs(name);
    logs.items.unshift({
      at: nowIso(),
      level,
      message,
      meta
    });
    logs.items = logs.items.slice(0, 500);
    this.writeJson(this.logsPath(name), logs);
    return logs.items[0];
  }

  getWebhookState(app) {
    const name = this.ensureAppBare(app);
    const state = this.readJson(this.webhookStatePath(name), this.defaultWebhookState());
    if (!state.deliveries || typeof state.deliveries !== "object") {
      state.deliveries = {};
    }
    return state;
  }

  isDeliveryProcessed(app, deliveryId) {
    if (!deliveryId) return false;
    const state = this.getWebhookState(app);
    return Boolean(state.deliveries[String(deliveryId)]);
  }

  markDeliveryProcessed(app, deliveryId) {
    if (!deliveryId) return;
    const name = this.ensureAppBare(app);
    const state = this.getWebhookState(name);
    state.deliveries[String(deliveryId)] = nowIso();
    const keys = Object.keys(state.deliveries);
    if (keys.length > 300) {
      const sorted = keys
        .map((id) => ({ id, at: state.deliveries[id] }))
        .sort((a, b) => String(b.at).localeCompare(String(a.at)));
      const trimmed = sorted.slice(0, 250);
      state.deliveries = {};
      for (const entry of trimmed) {
        state.deliveries[entry.id] = entry.at;
      }
    }
    this.writeJson(this.webhookStatePath(name), state);
  }

  ensureAppBare(app) {
    const name = sanitizeAppName(app);
    ensureDir(this.appDir(name));
    return name;
  }

  normalizeConfig(app, raw) {
    const base = this.defaultConfig(app);
    const cfg = Object.assign({}, base, raw || {});
    cfg.app = app;
    cfg.enabled = cfg.enabled !== false;
    cfg.route = cfg.route ? sanitizeRoute(cfg.route) : "";
    cfg.mode = ["manual", "github", "gitea"].includes(cfg.mode) ? cfg.mode : "manual";
    cfg.activeRelease = String(cfg.activeRelease || "");
    cfg.activeRootSubpath = sanitizeRootSubpath(cfg.activeRootSubpath || "");

    cfg.providerConfig = Object.assign({}, base.providerConfig, cfg.providerConfig || {});
    cfg.providerConfig.provider = String(cfg.providerConfig.provider || "").toLowerCase();
    cfg.providerConfig.sourceType = String(cfg.providerConfig.sourceType || "release_asset").toLowerCase();

    cfg.webhooks = Object.assign({}, base.webhooks, cfg.webhooks || {});
    cfg.webhooks.enabled = Boolean(cfg.webhooks.enabled);
    cfg.webhooks.autoDeploy = Boolean(cfg.webhooks.autoDeploy);
    cfg.webhooks.allowedBranches = normalizeStringList(cfg.webhooks.allowedBranches);
    cfg.webhooks.allowedTags = normalizeStringList(cfg.webhooks.allowedTags);

    cfg.security = Object.assign({}, base.security, cfg.security || {});
    cfg.security.maxZipBytes = Number(cfg.security.maxZipBytes || this.defaults.maxZipBytes);
    cfg.security.maxFiles = Number(cfg.security.maxFiles || this.defaults.maxFiles);

    return cfg;
  }

  getAppWithSecrets(app) {
    const config = this.getConfig(app);
    const secrets = this.getSecrets(app);
    return { config, secrets };
  }

  listAppNames() {
    ensureDir(this.storageRoot);
    return fs
      .readdirSync(this.storageRoot, { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name)
      .filter((name) => !name.startsWith("."))
      .filter((name) => /^[a-z0-9_-]+$/.test(name))
      .sort((a, b) => a.localeCompare(b));
  }

  listAppsSummary() {
    const names = this.listAppNames();
    return names.map((name) => this.getAppSummary(name));
  }

  getAppSummary(app) {
    const name = sanitizeAppName(app);
    const config = this.getConfig(name);
    const deployments = this.getDeployments(name);
    const activeDeployment = deployments.items.find((x) => x.version === config.activeRelease) || null;

    return {
      app: name,
      enabled: config.enabled !== false,
      route: config.route,
      mode: config.mode,
      provider: config.providerConfig.provider,
      sourceType: config.providerConfig.sourceType,
      activeRelease: config.activeRelease,
      activeRootSubpath: config.activeRootSubpath,
      lastDeployAt: config.lastDeployAt || "",
      updatedAt: config.updatedAt,
      releaseCount: deployments.items.length,
      activeStatus: activeDeployment ? activeDeployment.status : "unknown"
    };
  }

  getRoutesForRuntime() {
    const all = [];
    for (const app of this.listAppNames()) {
      const cfg = this.getConfig(app);
      if (cfg.enabled === false) continue;
      if (!cfg.route) continue;
      if (!cfg.activeRelease) continue;
      all.push({
        app,
        route: cfg.route,
        rootSubpath: cfg.activeRootSubpath || "",
        activeRelease: cfg.activeRelease
      });
    }
    all.sort((a, b) => b.route.length - a.route.length);
    return all;
  }

  writeLegacyRoutesFromConfigs() {
    const routes = this.getRoutesForRuntime().map((x) => ({
      app: x.app,
      route: x.route,
      rootSubpath: x.rootSubpath
    }));
    this.writeJson(this.legacyRoutesFile, routes);
    return routes;
  }

  readLegacyRoutes() {
    const parsed = this.readJson(this.legacyRoutesFile, []);
    if (!Array.isArray(parsed)) return [];
    return parsed
      .filter((x) => x && typeof x === "object" && x.app && x.route)
      .map((x) => ({
        app: sanitizeAppName(x.app),
        route: sanitizeRoute(x.route),
        rootSubpath: sanitizeRootSubpath(x.rootSubpath || "")
      }));
  }

  setActiveRelease(app, version, rootSubpath) {
    const name = sanitizeAppName(app);
    const cfg = this.getConfig(name);
    cfg.activeRelease = String(version || "");
    cfg.activeRootSubpath = sanitizeRootSubpath(rootSubpath || "");
    cfg.lastDeployAt = nowIso();
    cfg.updatedAt = nowIso();
    this.writeJson(this.configPath(name), cfg);

    const deployments = this.getDeployments(name);
    deployments.activeVersion = cfg.activeRelease;
    this.writeJson(this.deploymentsPath(name), deployments);

    this.updateCurrentPointer(name, cfg.activeRelease);
    this.writeLegacyRoutesFromConfigs();
    return cfg;
  }

  updateCurrentPointer(app, version) {
    const name = sanitizeAppName(app);
    const currentPath = this.currentPath(name);
    const releasePath = path.join(this.releasesDir(name), String(version || ""));
    if (!version || !fs.existsSync(releasePath)) {
      return;
    }

    const tmpLink = `${currentPath}.next`;
    try {
      if (fs.existsSync(tmpLink)) {
        fs.rmSync(tmpLink, { recursive: true, force: true });
      }
      const relativeTarget = path.relative(path.dirname(currentPath), releasePath);
      fs.symlinkSync(relativeTarget, tmpLink, "dir");
      fs.renameSync(tmpLink, currentPath);
    } catch (err) {
      if (fs.existsSync(tmpLink)) {
        fs.rmSync(tmpLink, { recursive: true, force: true });
      }
      removeDirRecursive(currentPath);
      copyDirRecursive(releasePath, currentPath);
    }
  }

  resolveAppFile(app, relFile) {
    const base = this.manualStagingDir(app);
    const rel = sanitizeRelativeFile(relFile);
    const target = secureJoin(base, rel);
    return { base, rel, full: target.resolved };
  }

  prepareManualUpload(app, clear = true) {
    const name = this.ensureApp(app);
    const manualDir = this.manualStagingDir(name);
    if (clear) {
      removeDirRecursive(manualDir);
    }
    ensureDir(manualDir);
    return manualDir;
  }

  writeManualFile(app, relFile, buffer) {
    const name = this.ensureApp(app);
    const target = this.resolveAppFile(name, relFile);
    ensureDir(path.dirname(target.full));
    fs.writeFileSync(target.full, buffer || Buffer.alloc(0));
    return target;
  }

  getManualUploadState(app) {
    const name = sanitizeAppName(app);
    const manualDir = this.manualStagingDir(name);
    const hasContent = fs.existsSync(manualDir) && fs.readdirSync(manualDir).length > 0;
    return {
      manualDir,
      hasContent
    };
  }

  releaseDir(app, version) {
    return path.join(this.releasesDir(app), String(version || ""));
  }

  releaseRootDir(app, version, rootSubpath) {
    return path.join(this.releaseDir(app, version), sanitizeRootSubpath(rootSubpath || ""));
  }

  updateRoute(app, route) {
    const name = sanitizeAppName(app);
    const cfg = this.getConfig(name);
    cfg.route = route ? sanitizeRoute(route) : "";
    cfg.updatedAt = nowIso();
    this.writeJson(this.configPath(name), cfg);
    this.writeLegacyRoutesFromConfigs();
    return cfg;
  }

  deleteRoute(route) {
    const target = sanitizeRoute(route);
    let changed = false;
    for (const app of this.listAppNames()) {
      const cfg = this.getConfig(app);
      if (cfg.route === target) {
        cfg.route = "";
        cfg.updatedAt = nowIso();
        this.writeJson(this.configPath(app), cfg);
        changed = true;
      }
    }
    if (changed) {
      this.writeLegacyRoutesFromConfigs();
    }
  }

  deleteApp(app) {
    const name = sanitizeAppName(app);
    removeDirRecursive(this.appDir(name));
    this.writeLegacyRoutesFromConfigs();
  }

  migrateLegacyCurrentIfNeeded(app, routeHint = "") {
    const name = sanitizeAppName(app);
    const cfg = this.getConfig(name);
    if (cfg.activeRelease) return;

    const currentDir = this.currentPath(name);
    if (!fs.existsSync(currentDir) || !fs.statSync(currentDir).isDirectory()) return;

    const detected = detectAppRoot(currentDir);
    if (!detected) return;

    const version = `legacy-${Date.now()}`;
    const releaseDir = this.releaseDir(name, version);
    if (!fs.existsSync(releaseDir)) {
      copyDirRecursive(currentDir, releaseDir);
    }

    const deployments = this.getDeployments(name);
    deployments.items.unshift({
      version,
      provider: "manual",
      sourceType: "legacy_current",
      status: "success",
      rootSubpath: detected.rootSubpath,
      deployedAt: nowIso(),
      deployedBy: "migration",
      notes: "Migrated from legacy current directory"
    });
    deployments.activeVersion = version;
    this.saveDeployments(name, deployments);
    this.setActiveRelease(name, version, detected.rootSubpath);
    if (routeHint) {
      this.updateRoute(name, routeHint);
    }
    this.appendLog(name, "info", "Legacy current migrated to releases", { version });
  }
}

module.exports = {
  ReleaseStore
};
