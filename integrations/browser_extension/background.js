// Calls the AI-EDR gateway from the service worker (host_permissions avoid page CORS limits).
const DEFAULTS = { gateway: "http://localhost:8080", tenant: "default", enabled: true };

async function settings() {
  return { ...DEFAULTS, ...(await chrome.storage.local.get(Object.keys(DEFAULTS))) };
}

async function inspect(body) {
  const s = await settings();
  if (!s.enabled) return { verdict: "ALLOWED", reason: "AI-EDR Guard disabled", disabled: true };
  const r = await fetch(`${s.gateway}/v1/ai-edr/inspect/simple`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ tenant_id: s.tenant, user_id: "browser-user", ...body }),
  });
  if (!r.ok) throw new Error(`gateway HTTP ${r.status}`);
  return r.json();
}

chrome.runtime.onMessage.addListener((msg, _sender, reply) => {
  if (msg.type !== "ai-edr-inspect") return;
  inspect(msg.body)
    .then(v => reply({ ok: true, verdict: v }))
    .catch(e => reply({ ok: false, error: String(e) }));
  return true; // async reply
});
