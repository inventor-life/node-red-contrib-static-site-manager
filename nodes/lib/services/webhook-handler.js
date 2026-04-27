const { matchesAnyPattern } = require("./security-utils");

class WebhookHandler {
  constructor(store, providers, deployManager) {
    this.store = store;
    this.providers = providers;
    this.deployManager = deployManager;
  }

  appCandidates(providerName) {
    return this.store
      .listAppNames()
      .map((app) => this.store.getAppWithSecrets(app))
      .filter(({ config }) => config.mode === providerName)
      .filter(({ config }) => Boolean(config.webhooks && config.webhooks.enabled));
  }

  async handle(providerName, headers, rawBodyBuffer) {
    const provider = this.providers[providerName];
    if (!provider) {
      throw new Error(`Proveedor webhook no soportado: ${providerName}`);
    }

    const candidates = this.appCandidates(providerName);
    if (!candidates.length) {
      return { ok: true, matched: false, message: "No hay apps en modo webhook para este proveedor" };
    }

    let selected = null;
    let verified = null;
    let verifyError = null;

    for (const candidate of candidates) {
      try {
        const info = provider.verifyWebhook(headers, rawBodyBuffer, candidate.config.providerConfig, candidate.secrets);
        selected = candidate;
        verified = info;
        break;
      } catch (err) {
        verifyError = err;
      }
    }

    if (!selected || !verified) {
      throw verifyError || new Error("Webhook no corresponde a ninguna app configurada");
    }

    const app = selected.config.app;
    const deliveryId = verified.deliveryId || "";
    if (deliveryId && this.store.isDeliveryProcessed(app, deliveryId)) {
      this.store.appendLog(app, "warn", "Webhook duplicado ignorado", { deliveryId });
      return {
        ok: true,
        matched: true,
        app,
        duplicate: true,
        deliveryId
      };
    }

    const allowedBranches = selected.config.webhooks.allowedBranches || [];
    const allowedTags = selected.config.webhooks.allowedTags || [];

    if (verified.branch && !matchesAnyPattern(verified.branch, allowedBranches)) {
      this.store.appendLog(app, "warn", "Webhook ignorado por branch no permitido", {
        branch: verified.branch,
        allowedBranches
      });
      this.store.markDeliveryProcessed(app, deliveryId);
      return {
        ok: true,
        matched: true,
        app,
        ignored: true,
        reason: "branch_not_allowed"
      };
    }

    if (verified.tag && !matchesAnyPattern(verified.tag, allowedTags)) {
      this.store.appendLog(app, "warn", "Webhook ignorado por tag no permitido", {
        tag: verified.tag,
        allowedTags
      });
      this.store.markDeliveryProcessed(app, deliveryId);
      return {
        ok: true,
        matched: true,
        app,
        ignored: true,
        reason: "tag_not_allowed"
      };
    }

    this.store.markDeliveryProcessed(app, deliveryId);

    if (!selected.config.webhooks.autoDeploy) {
      this.store.appendLog(app, "info", "Webhook validado sin auto deploy", {
        eventType: verified.eventType,
        action: verified.action,
        deliveryId
      });
      return {
        ok: true,
        matched: true,
        app,
        autoDeploy: false,
        eventType: verified.eventType
      };
    }

    let deployment = null;
    if (verified.tag) {
      deployment = await this.deployManager.deploySpecific(app, verified.tag, {
        deployedBy: "webhook",
        eventId: deliveryId,
        notes: `${providerName} webhook ${verified.eventType}:${verified.action}`,
        branch: verified.branch,
        tag: verified.tag
      });
    } else {
      deployment = await this.deployManager.deployLatest(app, {
        deployedBy: "webhook",
        eventId: deliveryId,
        notes: `${providerName} webhook ${verified.eventType}:${verified.action}`,
        branch: verified.branch,
        tag: verified.tag
      });
    }

    return {
      ok: true,
      matched: true,
      app,
      autoDeploy: true,
      deployment,
      eventType: verified.eventType,
      deliveryId
    };
  }
}

module.exports = {
  WebhookHandler
};
