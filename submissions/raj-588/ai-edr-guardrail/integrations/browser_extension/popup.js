const KEYS = { gateway: "http://localhost:8080", tenant: "default", enabled: true };
chrome.storage.local.get(Object.keys(KEYS)).then(s => {
  const v = { ...KEYS, ...s };
  document.getElementById("gateway").value = v.gateway;
  document.getElementById("tenant").value = v.tenant;
  document.getElementById("enabled").checked = v.enabled;
});
document.getElementById("save").onclick = async () => {
  await chrome.storage.local.set({
    gateway: document.getElementById("gateway").value.replace(/\/$/, ""),
    tenant: document.getElementById("tenant").value,
    enabled: document.getElementById("enabled").checked,
  });
  window.close();
};
