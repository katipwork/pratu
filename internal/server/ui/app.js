// Pratu reference login UI. Zero dependencies; drives the browser flow
// API with cookies + CSRF. Reads ?login_challenge= (OAuth2 handshake) and
// the social-callback parameters (?mfa_flow, ?methods, ?mfa_csrf, ?error).
"use strict";

const app = document.getElementById("app");
const params = new URLSearchParams(location.search);

// An OAuth2 challenge survives the whole multi-screen journey.
if (params.get("login_challenge")) {
  sessionStorage.setItem("pratu_challenge", params.get("login_challenge"));
}
const challenge = () => sessionStorage.getItem("pratu_challenge");

async function api(method, path, body, headers) {
  const opts = { method, credentials: "same-origin", headers: { ...(headers || {}) } };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  let json = null;
  try { json = await res.json(); } catch { /* empty body */ }
  return { status: res.status, ok: res.ok, body: json };
}

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
}[c]));

function screen(title, inner) {
  app.innerHTML = `<h1>${esc(title)}</h1><div id="msg"></div>${inner}`;
}
function say(kind, text) {
  document.getElementById("msg").innerHTML =
    text ? `<div class="msg ${kind}">${esc(text)}</div>` : "";
}
function errOf(resp) {
  const e = resp.body && resp.body.error;
  if (!e) return `request failed (${resp.status})`;
  return e.message + (e.details ? ": " + e.details.join("; ") : "");
}
function busy(form, on) {
  form.querySelectorAll("button").forEach((b) => (b.disabled = on));
}
function onSubmit(id, fn) {
  const form = document.getElementById(id);
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    busy(form, true);
    try { await fn(new FormData(form)); }
    catch (e) { say("error", e.message || String(e)); }
    finally { busy(form, false); }
  });
}

// ---- screens ---------------------------------------------------------

async function loginScreen(notice) {
  const flow = (await api("GET", "/self-service/login/browser")).body;
  const social = (await api("GET", "/self-service/social")).body || [];
  screen("Sign in", `
    <form id="f">
      <div><label for="identifier">Email</label>
        <input id="identifier" name="identifier" autocomplete="username" required></div>
      <div><label for="password">Password</label>
        <input id="password" name="password" type="password" autocomplete="current-password" required></div>
      <button>Sign in</button>
    </form>
    ${social.length ? `<div class="divider">or</div><div class="stack">` +
      social.map((p) => `<button class="secondary" data-social="${esc(p.id)}">Continue with ${esc(p.label)}</button>`).join("") +
      `</div>` : ""}
    <div class="links"><a href="#" id="to-register">Create account</a><a href="#" id="to-recovery">Forgot password?</a></div>`);
  if (notice) say(notice.kind, notice.text);
  document.getElementById("to-register").onclick = (e) => { e.preventDefault(); registerScreen(); };
  document.getElementById("to-recovery").onclick = (e) => { e.preventDefault(); recoveryScreen(); };
  app.querySelectorAll("[data-social]").forEach((b) =>
    (b.onclick = () => (location.href = `/self-service/social/${b.dataset.social}/browser`)));
  onSubmit("f", async (fd) => {
    const resp = await api("POST", `/self-service/login?flow=${flow.id}`, {
      method: "password", identifier: fd.get("identifier"),
      password: fd.get("password"), csrf_token: flow.csrf_token,
    });
    if (resp.ok) return afterAuth();
    const st = resp.body && resp.body.state;
    if (resp.status === 403 && st === "verification_required") return verifyScreen(resp.body.verification);
    if (resp.status === 403 && st === "mfa_required") return mfaScreen(flow.id, flow.csrf_token, resp.body.methods);
    say("error", errOf(resp));
  });
}

async function registerScreen() {
  const resp = await api("GET", "/self-service/registration/browser");
  if (!resp.ok) return say("error", errOf(resp));
  const flow = resp.body;
  const traits = flow.ui.fields.filter((f) => f.name !== "password");
  screen("Create account", `
    <form id="f">
      ${traits.map((f) => `<div><label for="t-${esc(f.name)}">${esc(f.title || f.name)}</label>
        <input id="t-${esc(f.name)}" name="${esc(f.name)}" ${f.name === "email" ? 'type="email" autocomplete="email"' : ""} ${f.required ? "required" : ""}></div>`).join("")}
      <div><label for="password">Password</label>
        <input id="password" name="password" type="password" autocomplete="new-password" required></div>
      <button>Create account</button>
    </form>
    <div class="links"><a href="#" id="to-login">Back to sign in</a><span></span></div>`);
  document.getElementById("to-login").onclick = (e) => { e.preventDefault(); loginScreen(); };
  onSubmit("f", async (fd) => {
    const t = {};
    traits.forEach((f) => { const v = fd.get(f.name); if (v) t[f.name] = v; });
    const r = await api("POST", `/self-service/registration?flow=${flow.id}`, {
      method: "password", traits: t, password: fd.get("password"), csrf_token: flow.csrf_token,
    });
    if (!r.ok) return say("error", errOf(r));
    if (r.body.state === "verification_required") return verifyScreen(r.body.verification);
    afterAuth();
  });
}

function verifyScreen(v) {
  screen("Check your " + (v.channel === "sms" ? "phone" : "email"), `
    <p class="muted">We sent a code to ${esc(v.address)}.</p>
    <form id="f">
      <div><label for="code">Code</label>
        <input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" required></div>
      <button>Verify</button>
      <button class="secondary" type="button" id="resend">Resend code</button>
    </form>`);
  document.getElementById("resend").onclick = async () => {
    const r = await api("POST", `/self-service/verification/resend?flow=${v.flow_id}`, { csrf_token: v.csrf_token });
    say(r.ok ? "ok" : "error", r.ok ? "Code re-sent." : errOf(r));
  };
  onSubmit("f", async (fd) => {
    const r = await api("POST", `/self-service/verification?flow=${v.flow_id}`, {
      code: fd.get("code"), csrf_token: v.csrf_token,
    });
    if (!r.ok) return say("error", errOf(r));
    r.body.session ? afterAuth() : loginScreen({ kind: "ok", text: "Address verified — sign in to continue." });
  });
}

function mfaScreen(flowId, csrf, methods) {
  const hasTotp = methods.includes("totp"), hasSms = methods.includes("sms");
  screen("Second factor", `
    <form id="f">
      <div><label for="code">${hasTotp ? "Authenticator code" : "SMS code"}</label>
        <input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" required></div>
      <button>Continue</button>
      ${hasSms ? `<button class="secondary" type="button" id="send-sms">${hasTotp ? "Use SMS instead — send code" : "Send code"}</button>` : ""}
    </form>`);
  let via = hasTotp ? "totp" : "sms";
  if (hasSms) document.getElementById("send-sms").onclick = async () => {
    const r = await api("POST", `/self-service/login/sms/send?flow=${flowId}`, { csrf_token: csrf });
    if (r.ok) { via = "sms"; say("ok", `Code sent to ${r.body.address}.`); }
    else say("error", errOf(r));
  };
  onSubmit("f", async (fd) => {
    const r = await api("POST", `/self-service/login/${via}?flow=${flowId}`, {
      code: fd.get("code"), csrf_token: csrf,
    });
    r.ok ? afterAuth() : say("error", errOf(r));
  });
}

async function recoveryScreen() {
  const resp = await api("GET", "/self-service/recovery/browser");
  if (!resp.ok) return say("error", errOf(resp));
  const flow = resp.body;
  screen("Recover your account", `
    <form id="f">
      <div><label for="address">Email or phone</label>
        <input id="address" name="address" required></div>
      <button>Send recovery code</button>
    </form>
    <div class="links"><a href="#" id="to-login">Back to sign in</a><span></span></div>`);
  document.getElementById("to-login").onclick = (e) => { e.preventDefault(); loginScreen(); };
  onSubmit("f", async (fd) => {
    const r = await api("POST", `/self-service/recovery?flow=${flow.id}`, {
      address: fd.get("address"), csrf_token: flow.csrf_token,
    });
    r.ok ? recoveryCodeScreen(flow) : say("error", errOf(r));
  });
}

function recoveryCodeScreen(flow) {
  screen("Enter the recovery code", `
    <p class="muted">If the address exists, a code was sent to it.</p>
    <form id="f">
      <div><label for="code">Code</label>
        <input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" required></div>
      <button>Continue</button>
    </form>`);
  onSubmit("f", async (fd) => {
    const r = await api("POST", `/self-service/recovery/code?flow=${flow.id}`, {
      code: fd.get("code"), csrf_token: flow.csrf_token,
    });
    if (!r.ok) return say("error", errOf(r));
    r.body.state === "second_factor_required"
      ? recoveryFactorScreen(flow, r.body.methods || [])
      : recoveryPasswordScreen(flow);
  });
}

function recoveryFactorScreen(flow, methods) {
  const hasTotp = methods.includes("totp"), hasSms = methods.includes("sms");
  screen("Second factor", `
    <form id="f">
      <div><label for="code">${hasTotp ? "Authenticator code" : "SMS code"}</label>
        <input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" required></div>
      <button>Continue</button>
      ${hasSms ? `<button class="secondary" type="button" id="send-sms">${hasTotp ? "Use SMS instead — send code" : "Send code"}</button>` : ""}
    </form>`);
  let via = hasTotp ? "totp" : "sms";
  if (hasSms) document.getElementById("send-sms").onclick = async () => {
    const r = await api("POST", `/self-service/recovery/sms/send?flow=${flow.id}`, { csrf_token: flow.csrf_token });
    if (r.ok) { via = "sms"; say("ok", `Code sent to ${r.body.address}.`); }
    else say("error", errOf(r));
  };
  onSubmit("f", async (fd) => {
    const r = await api("POST", `/self-service/recovery/${via}?flow=${flow.id}`, {
      code: fd.get("code"), csrf_token: flow.csrf_token,
    });
    r.ok ? recoveryPasswordScreen(flow) : say("error", errOf(r));
  });
}

function recoveryPasswordScreen(flow) {
  screen("Set a new password", `
    <form id="f">
      <div><label for="password">New password</label>
        <input id="password" name="password" type="password" autocomplete="new-password" required></div>
      <button>Save and sign in</button>
    </form>`);
  onSubmit("f", async (fd) => {
    const r = await api("POST", `/self-service/recovery/password?flow=${flow.id}`, {
      password: fd.get("password"), csrf_token: flow.csrf_token,
    });
    r.ok ? afterAuth() : say("error", errOf(r));
  });
}

async function homeScreen(who) {
  const s = who.session, i = who.identity;
  screen("Signed in", `
    <dl>
      <dt>Identity</dt><dd>${esc((i.traits && i.traits.email) || i.id)}</dd>
      <dt>Assurance</dt><dd>${esc(s.aal)}</dd>
      <dt>Session expires</dt><dd>${esc(new Date(s.expires_at).toLocaleString())}</dd>
    </dl>
    <form id="f"><button class="secondary">Sign out</button></form>`);
  onSubmit("f", async () => {
    await api("POST", "/self-service/logout", undefined, { "X-CSRF-Token": who.csrf_token });
    loginScreen({ kind: "ok", text: "Signed out." });
  });
}

// ---- OAuth2 login/consent handshake ---------------------------------

async function consentScreen(who) {
  const ch = challenge();
  const info = await api("GET", `/oauth2/auth/requests/${ch}`);
  if (!info.ok) {
    sessionStorage.removeItem("pratu_challenge");
    return say("error", errOf(info));
  }
  const accept = async (grantScopes) => {
    const r = await api("POST", `/oauth2/auth/accept?challenge=${ch}`,
      grantScopes ? { grant_scopes: grantScopes } : {},
      { "X-CSRF-Token": who.csrf_token });
    if (!r.ok) return say("error", errOf(r));
    sessionStorage.removeItem("pratu_challenge");
    location.href = r.body.redirect_to;
  };
  if (info.body.first_party) return accept(null);
  screen(`Authorize ${info.body.client_name}`, `
    <p class="muted">${esc(info.body.client_name)} is asking for access:</p>
    <form id="f">
      <div class="stack">
        ${info.body.requested_scopes.map((s) => `<label class="scope">
          <input type="checkbox" name="scope" value="${esc(s)}" checked> ${esc(s)}</label>`).join("")}
      </div>
      <button>Allow</button>
      <button class="secondary" type="button" id="deny">Deny</button>
    </form>`);
  document.getElementById("deny").onclick = async () => {
    const r = await api("POST", `/oauth2/auth/reject?challenge=${ch}`);
    if (!r.ok) return say("error", errOf(r));
    sessionStorage.removeItem("pratu_challenge");
    location.href = r.body.redirect_to;
  };
  onSubmit("f", async (fd) => accept(fd.getAll("scope")));
}

async function afterAuth() {
  const who = await api("GET", "/sessions/whoami");
  if (!who.ok) return loginScreen();
  challenge() ? consentScreen(who.body) : homeScreen(who.body);
}

// ---- entry -----------------------------------------------------------

(async function init() {
  // Social callback handovers land here with query parameters.
  if (params.get("mfa_flow")) {
    return mfaScreen(params.get("mfa_flow"), params.get("mfa_csrf") || "", params.getAll("methods"));
  }
  const notice = params.get("error")
    ? { kind: "error", text: `Sign-in failed: ${params.get("error")}` } : null;
  const who = await api("GET", "/sessions/whoami");
  if (who.ok && !notice) {
    return challenge() ? consentScreen(who.body) : homeScreen(who.body);
  }
  loginScreen(notice);
})();
