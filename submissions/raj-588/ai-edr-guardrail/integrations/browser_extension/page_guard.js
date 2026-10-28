// AI-EDR network backstop. Runs in the page's MAIN world (manifest "world": "MAIN").
// Holds the chat-send request itself (Gemini StreamGenerate, Claude completion) until the content
// script returns a verdict, so a prompt cannot leave the browser no matter which key, button or
// shortcut the site uses to send it. Also drops an identical duplicate send within a few seconds.
(() => {
  const ENDPOINTS = [/StreamGenerate/i, /\/completion(\?|$)/i, /\/retry_completion/i];
  const isChat = url => ENDPOINTS.some(rx => rx.test(String(url || "")));
  const pending = new Map();
  let seq = 0;

  window.addEventListener("message", e => {
    if (e.source !== window || e.data?.type !== "ai-edr-net-verdict") return;
    const resolve = pending.get(e.data.id);
    if (resolve) { pending.delete(e.data.id); resolve(e.data.allow); }
  });

  function askContentScript(text) {
    return new Promise(resolve => {
      const id = ++seq;
      pending.set(id, resolve);
      window.postMessage({ type: "ai-edr-net-check", id, text }, "*");
      setTimeout(() => { if (pending.has(id)) { pending.delete(id); resolve(true); } }, 15000);  // fail-open
    });
  }

  // Pull the user's prompt out of the provider request body (best effort; content script falls back
  // to the composer text it captured when the user pressed send).
  function promptFrom(body) {
    try {
      let s = typeof body === "string" ? body : body instanceof URLSearchParams ? body.toString() : "";
      if (!s && body instanceof FormData) s = new URLSearchParams([...body].filter(([, v]) => typeof v === "string")).toString();
      if (!s) return "";
      if (s.trim().startsWith("{")) {                       // Claude: JSON body with "prompt"
        const j = JSON.parse(s);
        return typeof j.prompt === "string" ? j.prompt : "";
      }
      const freq = new URLSearchParams(s).get("f.req");    // Gemini: f.req=[null,"[[\"prompt\",...]]"]
      if (freq) {
        const outer = JSON.parse(freq);
        const inner = JSON.parse(outer[1]);
        return typeof inner?.[0]?.[0] === "string" ? inner[0][0] : "";
      }
    } catch (_) { /* fall through */ }
    return "";
  }

  const origFetch = window.fetch;
  window.fetch = async function (input, init) {
    const url = typeof input === "string" ? input : input?.url;
    if (isChat(url)) {
      const allow = await askContentScript(promptFrom(init?.body));
      if (!allow) return new Response(JSON.stringify({ error: "Blocked by AI-EDR" }), { status: 403, headers: { "content-type": "application/json" } });
    }
    return origFetch.apply(this, arguments);
  };

  const origOpen = XMLHttpRequest.prototype.open;
  const origSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (method, url) {
    this.__aiEdrChat = isChat(url);
    return origOpen.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function (body) {
    if (!this.__aiEdrChat) return origSend.apply(this, arguments);
    const xhr = this, args = arguments;
    askContentScript(promptFrom(body)).then(allow => {
      if (allow) origSend.apply(xhr, args);
      else { xhr.abort(); xhr.dispatchEvent(new ProgressEvent("error")); }
    });
  };
})();
