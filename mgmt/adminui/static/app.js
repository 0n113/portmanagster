// Passkey login and setup. No inline scripts: the CSP allows only this file.
"use strict";

(function () {
  function b64urlToBuf(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    const bin = atob(s);
    const buf = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
    return buf.buffer;
  }

  function bufToB64url(buf) {
    const bytes = new Uint8Array(buf);
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function decodeIDs(list) {
    return (list || []).map(function (c) { return Object.assign({}, c, { id: b64urlToBuf(c.id) }); });
  }

  function credentialJSON(cred) {
    if (typeof cred.toJSON === "function") return cred.toJSON();
    const r = cred.response;
    const out = { id: cred.id, rawId: bufToB64url(cred.rawId), type: cred.type, response: {
      clientDataJSON: bufToB64url(r.clientDataJSON) },
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {} };
    if (cred.authenticatorAttachment) out.authenticatorAttachment = cred.authenticatorAttachment;
    if (r.attestationObject) {
      out.response.attestationObject = bufToB64url(r.attestationObject);
      if (r.getTransports) out.response.transports = r.getTransports();
    } else {
      out.response.authenticatorData = bufToB64url(r.authenticatorData);
      out.response.signature = bufToB64url(r.signature);
      if (r.userHandle) out.response.userHandle = bufToB64url(r.userHandle);
    }
    return out;
  }

  async function post(url, body) {
    const res = await fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
    });
    const data = await res.json().catch(function () { return {}; });
    if (!res.ok) throw new Error(data.error || ("Request failed (" + res.status + ")"));
    return data;
  }

  function showError(err) {
    const el = document.getElementById("passkey-error");
    if (!el) return;
    el.textContent = err && err.name === "NotAllowedError" ? "The passkey prompt was cancelled or timed out." : String(err.message || err);
    el.hidden = false;
  }

  function supported() {
    if (window.PublicKeyCredential) return true;
    showError(new Error("This browser does not support passkeys."));
    return false;
  }

  async function login(btn) {
    btn.disabled = true;
    try {
      const begin = await post("/api/login/begin");
      const pk = begin.options.publicKey;
      pk.challenge = b64urlToBuf(pk.challenge);
      pk.allowCredentials = decodeIDs(pk.allowCredentials);
      const cred = await navigator.credentials.get({ publicKey: pk, mediation: begin.options.mediation || undefined });
      const done = await post("/api/login/finish?id=" + encodeURIComponent(begin.id), credentialJSON(cred));
      window.location.assign(done.next || "/");
    } catch (err) {
      showError(err);
    } finally {
      btn.disabled = false;
    }
  }

  async function setup(btn) {
    btn.disabled = true;
    try {
      const begin = await post("/api/setup/passkey/begin", { token: btn.dataset.token });
      const pk = begin.options.publicKey;
      pk.challenge = b64urlToBuf(pk.challenge);
      pk.user.id = b64urlToBuf(pk.user.id);
      pk.excludeCredentials = decodeIDs(pk.excludeCredentials);
      const cred = await navigator.credentials.create({ publicKey: pk });
      const done = await post("/api/setup/passkey/finish?id=" + encodeURIComponent(begin.id), credentialJSON(cred));
      window.location.assign(done.next || "/login");
    } catch (err) {
      showError(err);
    } finally {
      btn.disabled = false;
    }
  }

  document.addEventListener("DOMContentLoaded", function () {
    const loginBtn = document.getElementById("passkey-login");
    if (loginBtn) loginBtn.addEventListener("click", function () { if (supported()) login(loginBtn); });
    const setupBtn = document.getElementById("passkey-setup");
    if (setupBtn) setupBtn.addEventListener("click", function () { if (supported()) setup(setupBtn); });
  });
})();

// Forms with data-confirm ask before they are sent.
document.addEventListener("submit", function (ev) {
  const msg = ev.target.dataset && ev.target.dataset.confirm;
  if (msg && !window.confirm(msg)) ev.preventDefault();
});
