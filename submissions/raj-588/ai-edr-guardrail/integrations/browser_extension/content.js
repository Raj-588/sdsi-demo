// AI-EDR Guard content script for Claude.ai and Gemini (and the local test page).
// Prompts: Enter / Send is held until the gateway returns a verdict; BLOCKED prompts are never sent.
// Files: uploads (picker, drag & drop, paste) are scanned first; poisoned files are replaced by a
// sanitized .txt copy (STRIP mode) or dropped (BLOCK mode).
(() => {
  const BYPASS = new WeakSet();
  const host = location.hostname;
  const PLATFORM = host.includes("gemini") ? "GEMINI" : "CLAUDE_IDE";
  const CLIENT = `browser:${host || "local"}`;
  let approvedText = null;
  let pending = false;

  // ------------------------------------------------------------------ gateway
  function ask(body) {
    return new Promise(resolve => {
      try {
        chrome.runtime.sendMessage({ type: "ai-edr-inspect", body: { platform: PLATFORM, client: CLIENT, ...body } },
          r => resolve(r || { ok: false, error: chrome.runtime.lastError?.message || "no response" }));
      } catch (e) { resolve({ ok: false, error: String(e) }); }
    });
  }
  const cats = v => [...new Set((v.findings || []).filter(f => ["MEDIUM", "HIGH", "CRITICAL"].includes(f.severity)).map(f => f.category))].slice(0, 3).join(", ");

  // ------------------------------------------------------------------ toasts
  function toast(kind, title, msg, removed = []) {
    let box = document.getElementById("ai-edr-toasts");
    if (!box) { box = document.createElement("div"); box.id = "ai-edr-toasts"; document.documentElement.appendChild(box); }
    const el = document.createElement("div");
    el.className = `ai-edr-toast ${kind}`;
    const icon = { BLOCKED: "⛔", ALLOWED_SANITIZED: "✂️", AUDIT_FLAGGED: "◉", PENDING: "⏳", ERROR: "⚠️", ALLOWED: "✅" }[kind] || "🛡️";
    el.innerHTML = `<b>${icon} ${esc(title)}</b><div class="m">${esc(msg)}</div>` +
      (removed.length ? `<div class="rm">${removed.slice(0, 4).map(esc).join("<br>")}</div>` : "") +
      (kind !== "PENDING" ? `<div class="m" style="margin-top:6px">AI-EDR Guard · <a href="http://localhost:8080/console#feed" target="_blank">open console</a></div>` : "");
    box.appendChild(el);
    if (kind !== "PENDING") setTimeout(() => el.remove(), kind === "ALLOWED" ? 3000 : 12000);
    return el;
  }
  const esc = s => String(s ?? "").replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

  // ------------------------------------------------------------------ prompts
  const COMPOSER = 'div.ProseMirror[contenteditable="true"], rich-textarea [contenteditable="true"], .ql-editor[contenteditable="true"], [contenteditable="true"][role="textbox"], textarea';
  const SEND = 'button[aria-label="Send message"], button[aria-label="Send Message"], button[aria-label*="Send" i], button.send-button, button[data-testid="send-button"]';
  const findComposer = () => document.querySelector(COMPOSER);
  const textOf = c => (c ? (c.value ?? c.innerText ?? "") : "").trim();
  const sendButton = () => [...document.querySelectorAll(SEND)].find(b => !b.disabled && b.offsetParent !== null) || document.querySelector(SEND);

  // One verdict per prompt text, shared by the keyboard/click gate and the network backstop.
  const verdicts = new Map();
  let lastText = "";
  let netSeen = 0;
  function verdictFor(text) {
    if (!verdicts.has(text)) {
      const p = ask({ stage: "PRE_LLM_DIRECT", prompt: text }).then(r => {
        if (!r.ok) toast("ERROR", "AI-EDR gateway unreachable", `${r.error}. Sent without inspection (fail-open).`);
        else if (r.verdict.verdict === "BLOCKED")
          toast("BLOCKED", "Prompt blocked — not sent to the AI", `${r.verdict.reason} · ${cats(r.verdict)} · vault ${r.verdict.quarantine_id || ""}`);
        else if (r.verdict.verdict === "AUDIT_FLAGGED") toast("AUDIT_FLAGGED", "Sent and flagged for audit", r.verdict.reason);
        return r;
      });
      verdicts.set(text, p);
      setTimeout(() => verdicts.delete(text), 60000);
    }
    return verdicts.get(text);
  }
  const allowed = r => !r.ok || r.verdict.verdict !== "BLOCKED";

  async function gate(ev, send) {
    const text = textOf(findComposer());
    if (!text) return;
    if (approvedText !== null && approvedText === text) { approvedText = null; return; }   // our own re-send
    ev.preventDefault();
    ev.stopImmediatePropagation();
    if (pending) return;
    pending = true;
    lastText = text;
    const started = Date.now();
    const wait = toast("PENDING", "AI-EDR is inspecting your prompt…", "");
    const r = await verdictFor(text);
    pending = false;
    wait.remove();
    if (!allowed(r)) return;
    // Some sites (e.g. Gemini) send through another event anyway; the network backstop held that
    // request and has now released it, so re-sending would duplicate the message.
    if (netSeen >= started) return;
    approvedText = text;
    send();
  }

  // Network backstop (page_guard.js, MAIN world) asks before the chat request leaves the browser.
  window.addEventListener("message", async e => {
    if (e.source !== window || e.data?.type !== "ai-edr-net-check") return;
    netSeen = Date.now();
    const text = (e.data.text || lastText || textOf(findComposer())).trim();
    const allow = text ? allowed(await verdictFor(text)) : true;
    window.postMessage({ type: "ai-edr-net-verdict", id: e.data.id, allow }, "*");
  });

  window.addEventListener("keydown", e => {
    if (e.key !== "Enter" || e.shiftKey || e.isComposing || !e.target?.closest?.(COMPOSER)) return;
    gate(e, () => { const b = sendButton(); if (b) b.click(); });
  }, true);

  window.addEventListener("click", e => {
    const b = e.target?.closest?.("button");
    if (!b || !b.matches(SEND)) return;
    gate(e, () => b.click());
  }, true);

  // ------------------------------------------------------------------ files
  function b64(buf) {
    const bytes = new Uint8Array(buf);
    let s = "";
    for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    return btoa(s);
  }

  async function screen(files) {
    const out = [];
    for (const f of files) {
      if (f.size > 20 * 1024 * 1024 || f.type.startsWith("image/")) { out.push(f); continue; }
      const wait = toast("PENDING", `AI-EDR is scanning ${f.name}…`, "Checking for hidden text, metadata and injected instructions");
      const r = await ask({ stage: "PRE_LLM_INDIRECT_FILE",
                            attachments: [{ filename: f.name, content_base64: b64(await f.arrayBuffer()), mime_type: f.type || null }] });
      wait.remove();
      if (!r.ok) { toast("ERROR", "AI-EDR gateway unreachable", `${r.error}. ${f.name} uploaded without inspection.`); out.push(f); continue; }
      const v = r.verdict;
      const removed = (v.sanitization || []).flatMap(s => s.removed_spans || []);
      if (v.verdict === "BLOCKED") {
        toast("BLOCKED", `${f.name} blocked — not uploaded`, `${v.reason} · ${cats(v)} · vault ${v.quarantine_id || ""}`);
      } else if (v.verdict === "ALLOWED_SANITIZED") {
        const clean = Object.values(v.sanitized_attachments || {})[0] || "";
        const name = f.name.replace(/\.[^.]+$/, "") + ".sanitized.txt";
        out.push(new File([clean], name, { type: "text/plain" }));
        toast("ALLOWED_SANITIZED", `Hidden instructions removed from ${f.name}`,
              `Uploading clean copy "${name}" instead. Hidden tricks: ${(v.anomalies || []).join(", ") || "—"}`, removed);
      } else {
        if (v.verdict === "AUDIT_FLAGGED") toast("AUDIT_FLAGGED", `${f.name} flagged for audit`, v.reason);
        else toast("ALLOWED", `${f.name} is clean`, "No hidden instructions found");
        out.push(f);
      }
    }
    return out;
  }

  const toDT = files => { const dt = new DataTransfer(); files.forEach(f => dt.items.add(f)); return dt; };

  // file picker
  const held = new WeakMap();
  for (const type of ["input", "change"]) {
    window.addEventListener(type, e => {
      const input = e.target;
      if (BYPASS.has(e) || !(input instanceof HTMLInputElement) || input.type !== "file" || !input.files?.length) return;
      e.stopImmediatePropagation();
      if (type === "input" || held.get(input) === input.files) return;   // one scan per selection
      held.set(input, input.files);
      screen([...input.files]).then(files => {
        input.files = toDT(files).files;
        held.set(input, input.files);
        if (!files.length) { input.value = ""; return; }
        for (const t of ["input", "change"]) { const ev = new Event(t, { bubbles: true }); BYPASS.add(ev); input.dispatchEvent(ev); }
      });
    }, true);
  }

  // drag & drop
  window.addEventListener("drop", e => {
    if (BYPASS.has(e) || !e.dataTransfer?.files?.length) return;
    e.preventDefault(); e.stopImmediatePropagation();
    const target = e.target, x = e.clientX, y = e.clientY;
    screen([...e.dataTransfer.files]).then(files => {
      if (!files.length) return;
      const ev = new DragEvent("drop", { bubbles: true, cancelable: true, clientX: x, clientY: y, dataTransfer: toDT(files) });
      BYPASS.add(ev); target.dispatchEvent(ev);
    });
  }, true);

  // paste of files
  window.addEventListener("paste", e => {
    if (BYPASS.has(e) || !e.clipboardData?.files?.length) return;
    e.preventDefault(); e.stopImmediatePropagation();
    const target = e.target;
    screen([...e.clipboardData.files]).then(files => {
      if (!files.length) return;
      const ev = new ClipboardEvent("paste", { bubbles: true, cancelable: true, clipboardData: toDT(files) });
      BYPASS.add(ev); target.dispatchEvent(ev);
    });
  }, true);
})();
