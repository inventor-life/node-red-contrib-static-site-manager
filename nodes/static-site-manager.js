const fs = require("fs");
const path = require("path");
const express = require("express");
const { ReleaseStore } = require("./lib/services/release-store");
const { DeployManager } = require("./lib/services/deploy-manager");
const { WebhookHandler } = require("./lib/services/webhook-handler");
const { GitHubProvider } = require("./lib/providers/github");
const { GiteaProvider } = require("./lib/providers/gitea");
const {
  sanitizeAppName,
  sanitizeRoute,
  sanitizeRootSubpath,
  sanitizeRelativeFile
} = require("./lib/services/security-utils");
const { renderIndexWithBase } = require("./lib/services/archive-utils");

module.exports = function(RED) {
  const adminApp = RED.httpAdmin;
  const httpNodeApp = RED.httpNode;
  const authConfigured = !!(RED.settings && RED.settings.adminAuth);

  const needsPermission = (permission) => {
    if (authConfigured && RED.auth && RED.auth.needsPermission) {
      return RED.auth.needsPermission(permission);
    }
    return (req, res, next) => next();
  };

  const storageRoot = path.join(RED.settings.userDir || process.cwd(), "static_sites");
  const adminUiPath = path.join(__dirname, "lib", "admin");
  const panelSettingsPath = path.join(storageRoot, "panel_settings.json");

  const store = new ReleaseStore(storageRoot);
  const providers = {
    github: new GitHubProvider(),
    gitea: new GiteaProvider()
  };
  const deployManager = new DeployManager(store, providers);
  const webhookHandler = new WebhookHandler(store, providers, deployManager);
  const panelNodeEnabledById = new Map();

  function readPanelSettings() {
    const fallback = { language: "es", panelEnabled: true };
    try {
      if (!fs.existsSync(panelSettingsPath)) {
        fs.writeFileSync(panelSettingsPath, JSON.stringify(fallback, null, 2), { encoding: "utf8", mode: 0o600 });
        return fallback;
      }
      const raw = JSON.parse(fs.readFileSync(panelSettingsPath, "utf8"));
      const language = String(raw.language || "es").toLowerCase();
      const panelEnabled = raw.panelEnabled !== false;
      return { language: language === "en" ? "en" : "es", panelEnabled };
    } catch (err) {
      return fallback;
    }
  }

  function savePanelSettings(input = {}) {
    const language = String(input.language || "es").toLowerCase() === "en" ? "en" : "es";
    const panelEnabled = input.panelEnabled !== false;
    const next = { language, panelEnabled };
    fs.writeFileSync(panelSettingsPath, JSON.stringify(next, null, 2), { encoding: "utf8", mode: 0o600 });
    return next;
  }

  function isPanelEnabled() {
    const byConfigNode = getConfigNodePanelEnabled();
    if (byConfigNode !== null) return byConfigNode;
    return readPanelSettings().panelEnabled !== false;
  }

  function getConfigNodePanelEnabled() {
    if (!panelNodeEnabledById.size) return null;
    const values = Array.from(panelNodeEnabledById.values());
    return values.some((v) => v === true);
  }

  adminApp.use("/static-site-manager", (req, res, next) => {
    const routePath = String(req.path || "");
    const uiSettingsPath = routePath === "/api/ui-settings" || routePath.startsWith("/api/ui-settings/");
    if (uiSettingsPath) return next();
    if (isPanelEnabled()) return next();
    if (routePath.startsWith("/api/")) {
      return res.status(403).json({ ok: false, error: "Static Site Manager is disabled" });
    }
    return res.status(403).send("Static Site Manager is disabled");
  });

  const legacyRouteMap = {};
  for (const entry of store.readLegacyRoutes()) {
    legacyRouteMap[entry.app] = entry.route;
  }

  for (const app of store.listAppNames()) {
    try {
      store.migrateLegacyCurrentIfNeeded(app, legacyRouteMap[app] || "");
    } catch (err) {
      store.appendLog(app, "error", "Error migrando estructura legacy", { message: err.message });
    }
  }

  function routeEntries() {
    return store.getRoutesForRuntime();
  }

  function chooseRoute(pathname, routes) {
    const sorted = [...routes].sort((a, b) => b.route.length - a.route.length);
    return sorted.find((entry) => pathname === entry.route || pathname.startsWith(entry.route + "/")) || null;
  }

  function appReleaseBase(routeEntry) {
    return path.join(
      store.releaseDir(routeEntry.app, routeEntry.activeRelease),
      sanitizeRootSubpath(routeEntry.rootSubpath || "")
    );
  }

  function readAppDetails(app) {
    const summary = store.getAppSummary(app);
    const config = store.getConfig(app);
    const deployments = store.getDeployments(app);
    const secrets = store.getSecrets(app);
    return {
      summary,
      config,
      deployments: deployments.items,
      activeVersion: deployments.activeVersion,
      logs: store.getLogs(app).items.slice(0, 50),
      secretsConfigured: {
        token: !!secrets.token,
        webhookSecret: !!secrets.webhookSecret
      },
      secretSettings: {
        authType: secrets.authType || "bearer",
        authHeaderName: secrets.authHeaderName || "Authorization"
      }
    };
  }

  adminApp.get("/static-site-manager/api/status", needsPermission("flows.read"), (req, res) => {
    const appSummaries = store.listAppsSummary();
    const routes = routeEntries();
    res.json({
      ok: true,
      storageRoot,
      routes,
      apps: appSummaries.map((x) => ({
        app: x.app,
        route: x.route,
        mode: x.mode,
        provider: x.provider,
        activeRelease: x.activeRelease,
        ready: !!x.activeRelease,
        currentDir: path.join(store.appDir(x.app), "current")
      }))
    });
  });

  adminApp.get("/static-site-manager/api/apps", needsPermission("flows.read"), (req, res) => {
    res.json({
      ok: true,
      items: store.listAppsSummary()
    });
  });

  adminApp.get("/static-site-manager/api/ui-settings", needsPermission("flows.read"), (req, res) => {
    const settings = readPanelSettings();
    const byConfigNode = getConfigNodePanelEnabled();
    res.json({
      ok: true,
      settings,
      effectivePanelEnabled: isPanelEnabled(),
      controlledByConfigNode: byConfigNode !== null,
      configNodePanelEnabled: byConfigNode
    });
  });

  adminApp.post("/static-site-manager/api/ui-settings", needsPermission("flows.write"), express.json({ limit: "1mb" }), (req, res) => {
    try {
      const body = req.body || {};
      const settings = savePanelSettings(body);
      res.json({ ok: true, settings });
    } catch (err) {
      res.status(400).json({ ok: false, error: err.message });
    }
  });

  adminApp.get("/static-site-manager/api/app/:app", needsPermission("flows.read"), (req, res) => {
    try {
      const app = sanitizeAppName(req.params.app);
      res.json({ ok: true, ...readAppDetails(app) });
    } catch (err) {
      res.status(400).json({ ok: false, error: err.message });
    }
  });

  adminApp.post("/static-site-manager/api/app", needsPermission("flows.write"), express.json({ limit: "2mb" }), (req, res) => {
    try {
      const body = req.body || {};
      const app = sanitizeAppName(body.app);
      store.ensureApp(app);

      const configPatch = {
        enabled: body.enabled,
        route: body.route || "",
        mode: body.mode || "manual",
        providerConfig: body.providerConfig || {},
        webhooks: body.webhooks || {},
        security: body.security || {}
      };
      const secretPatch = body.secrets || {};

      const config = store.saveConfig(app, configPatch);
      if (secretPatch && typeof secretPatch === "object") {
        store.saveSecrets(app, secretPatch);
      }

      store.appendLog(app, "info", "Configuracion actualizada", {
        mode: config.mode,
        route: config.route
      });

      res.json({ ok: true, config, summary: store.getAppSummary(app) });
    } catch (err) {
      res.status(400).json({ ok: false, error: err.message });
    }
  });

  adminApp.post("/static-site-manager/api/app/:app/test-connection", needsPermission("flows.write"), async (req, res) => {
    try {
      const app = sanitizeAppName(req.params.app);
      const result = await deployManager.testConnection(app);
      store.appendLog(app, "info", "Test de conexion exitoso", result);
      res.json({ ok: true, result });
    } catch (err) {
      res.status(400).json({ ok: false, error: err.message });
    }
  });

  adminApp.get("/static-site-manager/api/app/:app/versions", needsPermission("flows.read"), async (req, res) => {
    try {
      const app = sanitizeAppName(req.params.app);
      const versions = await deployManager.listRemoteVersions(app);
      res.json({ ok: true, versions });
    } catch (err) {
      res.status(400).json({ ok: false, error: err.message });
    }
  });

  adminApp.post("/static-site-manager/api/app/:app/check-update", needsPermission("flows.read"), async (req, res) => {
    try {
      const app = sanitizeAppName(req.params.app);
      const result = await deployManager.checkUpdate(app);
      res.json({ ok: true, result });
    } catch (err) {
      res.status(400).json({ ok: false, error: err.message });
    }
  });

  adminApp.post("/static-site-manager/api/app/:app/deploy-latest", needsPermission("flows.write"), express.json({ limit: "1mb" }), async (req, res) => {
    try {
      const app = sanitizeAppName(req.params.app);
      const body = req.body || {};
      const deployment = await deployManager.deployLatest(app, {
        deployedBy: "panel",
        notes: body.notes || "Deploy latest"
      });
      res.json({ ok: true, deployment, summary: store.getAppSummary(app) });
    } catch (err) {
      res.status(400).json({ ok: false, error: err.message });
    }
  });

  adminApp.post("/static-site-manager/api/app/:app/deploy-version", needsPermission("flows.write"), express.json({ limit: "1mb" }), async (req, res) => {
    try {
      const app = sanitizeAppName(req.params.app);
      const body = req.body || {};
      const version = String(body.version || "").trim();
      const deployment = await deployManager.deploySpecific(app, version, {
        deployedBy: "panel",
        notes: body.notes || `Deploy version ${version}`
      });
      res.json({ ok: true, deployment, summary: store.getAppSummary(app) });
    } catch (err) {
      res.status(400).json({ ok: false, error: err.message });
    }
  });

  adminApp.post("/static-site-manager/api/app/:app/rollback", needsPermission("flows.write"), express.json({ limit: "1mb" }), (req, res) => {
    try {
      const app = sanitizeAppName(req.params.app);
      const body = req.body || {};
      const version = String(body.version || "").trim();
      const result = deployManager.rollback(app, version, {
        deployedBy: "panel"
      });
      res.json({ ok: true, result, summary: store.getAppSummary(app) });
    } catch (err) {
      res.status(400).json({ ok: false, error: err.message });
    }
  });

  adminApp.get("/static-site-manager/api/app/:app/releases", needsPermission("flows.read"), (req, res) => {
    try {
      const app = sanitizeAppName(req.params.app);
      res.json({ ok: true, releases: store.getDeployments(app).items, activeVersion: store.getConfig(app).activeRelease });
    } catch (err) {
      res.status(400).json({ ok: false, error: err.message });
    }
  });

  adminApp.get("/static-site-manager/api/app/:app/logs", needsPermission("flows.read"), (req, res) => {
    try {
      const app = sanitizeAppName(req.params.app);
      const limit = Math.max(1, Math.min(200, Number(req.query.limit || 50)));
      res.json({ ok: true, logs: store.getLogs(app).items.slice(0, limit) });
    } catch (err) {
      res.status(400).json({ ok: false, error: err.message });
    }
  });

  // Legacy manual flow (compatible): prepare-upload -> upload-file -> set-route
  adminApp.post("/static-site-manager/api/prepare-upload", needsPermission("flows.write"), express.json({ limit: "1mb" }), (req, res) => {
    try {
      const body = req.body || {};
      const app = sanitizeAppName(body.app);
      const staging = store.prepareManualUpload(app, body.clear !== false);
      res.json({ ok: true, app, currentDir: staging });
    } catch (err) {
      res.status(400).json({ ok: false, error: err.message });
    }
  });

  adminApp.post("/static-site-manager/api/upload-file", needsPermission("flows.write"), express.raw({ type: "*/*", limit: "80mb" }), (req, res) => {
    try {
      const app = sanitizeAppName(req.query.app);
      const filePath = sanitizeRelativeFile(req.query.filePath);
      const target = store.writeManualFile(app, filePath, req.body || Buffer.alloc(0));
      res.json({ ok: true, app, filePath: target.rel, fullPath: target.full });
    } catch (err) {
      res.status(400).json({ ok: false, error: err.message });
    }
  });

  adminApp.post("/static-site-manager/api/set-route", needsPermission("flows.write"), express.json({ limit: "1mb" }), (req, res) => {
    try {
      const body = req.body || {};
      const app = sanitizeAppName(body.app);
      const route = sanitizeRoute(body.route);
      const deployment = deployManager.deployManual(app, route, {
        deployedBy: "panel",
        notes: "Manual upload publish"
      });

      const routes = routeEntries();
      res.json({ ok: true, deployment, routes });
    } catch (err) {
      res.status(400).json({ ok: false, error: err.message });
    }
  });

  adminApp.delete("/static-site-manager/api/route", needsPermission("flows.write"), express.json({ limit: "1mb" }), (req, res) => {
    try {
      const route = sanitizeRoute(req.body && req.body.route);
      store.deleteRoute(route);
      res.json({ ok: true, routes: routeEntries() });
    } catch (err) {
      res.status(400).json({ ok: false, error: err.message });
    }
  });

  adminApp.delete("/static-site-manager/api/app", needsPermission("flows.write"), express.json({ limit: "1mb" }), (req, res) => {
    try {
      const app = sanitizeAppName(req.body && req.body.app);
      store.deleteApp(app);
      res.json({ ok: true, deleted: app, routes: routeEntries() });
    } catch (err) {
      res.status(400).json({ ok: false, error: err.message });
    }
  });

  adminApp.post(
    "/static-site-manager/api/webhook/:provider",
    express.raw({ type: "*/*", limit: "5mb" }),
    async (req, res) => {
      try {
        const provider = String(req.params.provider || "").toLowerCase();
        const payloadBuffer = Buffer.isBuffer(req.body) ? req.body : Buffer.from(req.body || "");
        const result = await webhookHandler.handle(provider, req.headers || {}, payloadBuffer);
        res.json({ ok: true, result });
      } catch (err) {
        res.status(400).json({ ok: false, error: err.message });
      }
    }
  );

  adminApp.use("/static-site-manager", needsPermission("flows.read"), express.static(adminUiPath));
  adminApp.get("/static-site-manager", needsPermission("flows.read"), (req, res) => {
    res.sendFile(path.join(adminUiPath, "index.html"));
  });

  // Runtime static hosting by app route + active release.
  httpNodeApp.use((req, res, next) => {
    try {
      const entry = chooseRoute(req.path, routeEntries());
      if (!entry) return next();

      const base = appReleaseBase(entry);
      const routePrefix = entry.route;
      const relative = req.path === routePrefix ? "/" : req.path.slice(routePrefix.length) || "/";
      const cleanRel = relative.replace(/^\/+/, "");
      const target = path.resolve(base, cleanRel || "index.html");
      const root = path.resolve(base);

      if (!target.startsWith(root + path.sep) && target !== root) {
        return res.status(400).send("Invalid path");
      }

      const indexPath = path.join(base, "index.html");
      if (!fs.existsSync(indexPath)) {
        return res.status(503).send("App not ready: missing index.html");
      }

      if (cleanRel && fs.existsSync(target) && fs.statSync(target).isFile()) {
        return res.sendFile(target);
      }

      const renderedIndex = renderIndexWithBase(indexPath, routePrefix);
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      return res.send(renderedIndex);
    } catch (err) {
      return next(err);
    }
  });

  function StaticSiteManagerNode(config) {
    RED.nodes.createNode(this, config);
    const node = this;

    node.name = config.name;
    node.sitePath = config.sitePath;
    node.route = config.route;

    node.on("input", function(msg, send, done) {
      send = send || function() { node.send.apply(node, arguments); };

      try {
        msg.staticSiteManager = msg.staticSiteManager || {};
        msg.staticSiteManager.name = node.name || "";
        msg.staticSiteManager.sitePath = node.sitePath || "";
        msg.staticSiteManager.route = node.route || "/static";
        send(msg);

        if (done) {
          done();
        }
      } catch (err) {
        if (done) {
          done(err);
        } else {
          node.error(err, msg);
        }
      }
    });
  }

  function StaticSiteManagerConfigNode(config) {
    RED.nodes.createNode(this, config);
    this.name = config.name || "static-site-manager";
    this.panelEnabled = config.panelEnabled !== false;
    panelNodeEnabledById.set(this.id, this.panelEnabled);

    this.on("close", (removed, done) => {
      panelNodeEnabledById.delete(this.id);
      done();
    });
  }

  RED.nodes.registerType("static-site-manager", StaticSiteManagerNode);
  RED.nodes.registerType("static-site-manager-config", StaticSiteManagerConfigNode);
};
