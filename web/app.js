/* Sentinel 3.0 dashboard — static SPA. All authorization is enforced server-side (RLS + Edge Functions);
   nothing here is trusted. Only the project URL and publishable key are present in the browser. */
(() => {
const cfg = window.SENTINEL_CONFIG || {};
const app = document.getElementById("app");
if (!cfg.SUPABASE_URL || /YOUR_/.test(cfg.SUPABASE_URL)) { app.innerHTML = '<p class="boot">config.js is not configured (SUPABASE_URL / SUPABASE_PUBLISHABLE_KEY).</p>'; return; }
const sb = supabase.createClient(cfg.SUPABASE_URL, cfg.SUPABASE_PUBLISHABLE_KEY, { auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: false } });

// ── helpers ─────────────────────────────────────────────────────────────────
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmt = t => t ? new Date(t).toLocaleString() : "—";
const ago = t => { if (!t) return "never"; const s = (Date.now() - new Date(t)) / 1000; return s < 60 ? `${Math.floor(s)}s ago` : s < 3600 ? `${Math.floor(s / 60)}m ago` : s < 86400 ? `${Math.floor(s / 3600)}h ago` : `${Math.floor(s / 86400)}d ago`; };
const sev = s => `<span class="badge b-${{ critical: "crit", high: "high", medium: "med", low: "low" }[s] || "low"}">${esc(s)}</span>`;
const badge = (txt, cls) => `<span class="badge b-${cls}">${esc(txt)}</span>`;
const lines = v => (v || []).join("\n");
const toList = t => t.split("\n").map(s => s.trim()).filter(Boolean);
function toast(msg, kind = "") { const d = document.createElement("div"); d.className = "toast " + kind; d.textContent = msg; document.getElementById("toasts").append(d); setTimeout(() => d.remove(), 5000); }
const ERR = { mfa_required: "MFA verification required", insufficient_role: "Your role does not allow this", confirmation_required: "Confirmation required", device_revoked: "Device is revoked", not_an_admin: "Not an authorized administrator", rate_limited: "Too many requests, slow down" };
const errText = e => ERR[e.message] || e.message;

async function api(action, payload = {}) {
  const { data: { session } } = await sb.auth.getSession();
  if (!session) throw new Error("unauthenticated");
  const r = await fetch(`${cfg.SUPABASE_URL}/functions/v1/admin-api`, { method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${session.access_token}`, apikey: cfg.SUPABASE_PUBLISHABLE_KEY },
    body: JSON.stringify({ action, ...payload }) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || `http_${r.status}`);
  return j;
}
function confirmDialog(title, bodyHtml, { okText = "Confirm", danger = false, needText = null } = {}) {
  return new Promise(res => {
    const m = document.createElement("div"); m.className = "modal";
    m.innerHTML = `<div class="card"><h3>${esc(title)}</h3><div>${bodyHtml}</div>${needText ? `<label>Type <b>${esc(needText)}</b> to confirm</label><input id="cf-t" style="width:100%">` : ""}<div class="row"><button id="cf-no">Cancel</button><button id="cf-ok" class="${danger ? "danger" : "pri"}">${esc(okText)}</button></div></div>`;
    document.body.append(m);
    const done = v => { m.remove(); res(v); };
    m.querySelector("#cf-no").onclick = () => done(null);
    m.querySelector("#cf-ok").onclick = () => { const t = m.querySelector("#cf-t"); if (needText && t.value !== needText) return toast("Text does not match", "bad"); done({ text: t ? t.value : null, el: m }); };
  });
}

// ── auth ────────────────────────────────────────────────────────────────────
let me = null, idleTimer = null;
function resetIdle() { clearTimeout(idleTimer); idleTimer = setTimeout(() => logout("Signed out after 30 minutes of inactivity."), 30 * 60_000); }
["click", "keydown", "touchstart"].forEach(ev => document.addEventListener(ev, () => me && resetIdle(), { passive: true }));
async function logout(msg) { clearTimeout(idleTimer); me = null; await sb.auth.signOut(); loginView(msg); }

function loginView(msg = "") {
  app.innerHTML = `<div class="login"><h2>🛡️ Sentinel</h2><div class="card"><form id="lf"><label>Email</label><input id="em" type="email" autocomplete="username" required><label>Password</label><input id="pw" type="password" autocomplete="current-password" required><div class="err" id="le">${esc(msg)}</div><button class="pri" style="width:100%">Sign in</button></form></div></div>`;
  app.querySelector("#lf").onsubmit = async e => {
    e.preventDefault(); const le = app.querySelector("#le"); le.textContent = "";
    const { error } = await sb.auth.signInWithPassword({ email: app.querySelector("#em").value.trim(), password: app.querySelector("#pw").value });
    if (error) { le.textContent = "Invalid email or password."; return; }   // generic on purpose
    await afterPassword();
  };
}
async function afterPassword() {
  const { data: aal } = await sb.auth.mfa.getAuthenticatorAssuranceLevel();
  if (aal?.nextLevel === "aal2" && aal.currentLevel !== "aal2") return mfaView();
  await enter();
}
async function mfaView() {
  const { data: f } = await sb.auth.mfa.listFactors(); const factor = f?.totp?.[0];
  app.innerHTML = `<div class="login"><h2>Two-factor code</h2><div class="card"><form id="mf"><label>6-digit code from your authenticator</label><input id="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required><div class="err" id="me"></div><button class="pri" style="width:100%">Verify</button></form><p class="mu sm" style="margin-top:.8rem"><a href="#" id="mo">Cancel</a></p></div></div>`;
  app.querySelector("#mo").onclick = e => { e.preventDefault(); logout(); };
  app.querySelector("#mf").onsubmit = async e => {
    e.preventDefault();
    const { data: ch, error: e1 } = await sb.auth.mfa.challenge({ factorId: factor.id });
    const { error: e2 } = e1 ? { error: e1 } : await sb.auth.mfa.verify({ factorId: factor.id, challengeId: ch.id, code: app.querySelector("#code").value.trim() });
    if (e2) return (app.querySelector("#me").textContent = "Invalid code.");
    await enter();
  };
}
async function enter() {
  const { data: { user } } = await sb.auth.getUser();
  const { data: p } = await sb.from("admin_profiles").select("*").eq("id", user.id).maybeSingle();
  if (!p || !p.is_active) { await sb.auth.signOut(); return loginView("This account is not an authorized Sentinel administrator."); }
  me = p;
  try { await api("record_login"); } catch { /* non-fatal */ }
  resetIdle(); subscribeRealtime(); shell(); route();
}
sb.auth.onAuthStateChange(ev => { if (ev === "SIGNED_OUT" && me) { me = null; loginView("Session ended. Please sign in again."); } });

// ── shell + router ──────────────────────────────────────────────────────────
const NAV = [["overview", "Overview"], ["devices", "Devices"], ["logs", "Logs"], ["commands", "Commands"], ["settings", "Settings"]];
function shell() {
  app.innerHTML = `<div class="shell"><nav class="side"><h1>🛡️ Sentinel</h1>${NAV.map(([k, l]) => `<a href="#/${k}" data-nav="${k}">${l}</a>`).join("")}<div class="who">${esc(me.email)}<br>${esc(me.role)} · <a href="#" id="lo">Sign out</a></div></nav><main class="main" id="view"></main></div>`;
  app.querySelector("#lo").onclick = e => { e.preventDefault(); logout(); };
}
window.addEventListener("hashchange", () => me && route());
let rt = null; function subscribeRealtime() {
  sb.channel("live").on("postgres_changes", { event: "*", schema: "public" }, () => { clearTimeout(rt); rt = setTimeout(() => { const h = location.hash; if (document.activeElement?.closest("form,.modal,input,textarea,select") || document.querySelector(".modal")) return;
    if (!(h === "" || h === "#/overview" || h === "#/devices" || /^#\/device\/[^/]+\/?(overview)?$/.test(h))) return;   // never wipe filters/forms
    route(true); }, 1500); }).subscribe();
}
async function route(silent) {
  if (!me) return;
  const parts = (location.hash.replace(/^#\/?/, "") || "overview").split("/");
  document.querySelectorAll("[data-nav]").forEach(a => a.classList.toggle("on", a.dataset.nav === (parts[0] === "device" ? "devices" : parts[0])));
  const v = document.getElementById("view"); if (!silent) v.innerHTML = '<p class="mu">Loading…</p>';
  try {
    if (parts[0] === "devices") await devicesView(v);
    else if (parts[0] === "device") await deviceView(v, parts[1], parts[2] || "overview");
    else if (parts[0] === "logs") await eventsView(v, { title: "Security & operational logs", showDevice: true });
    else if (parts[0] === "commands") await commandsView(v);
    else if (parts[0] === "settings") await settingsView(v);
    else await overviewView(v);
  } catch (e) { v.innerHTML = `<div class="card err">Error: ${esc(errText(e))}</div>`; }
}

// ── device state & security score (transparent rules) ───────────────────────
const DEV_COLS = "id,device_name,hostname,operating_system,os_version,agent_version,registered_at,last_heartbeat,last_seen_at,current_mode,status,is_active,is_compromised,revoked_at,revoked_reason,system_status,integrity_status,baselines";
let THRESH = 120;
function devState(d) {
  const s = (Date.now() - new Date(d.last_seen_at || 0)) / 1000;
  if (!d.is_active || d.revoked_at) return ["Revoked", "bad"];
  if (d.status === "pending" && !d.last_seen_at) return ["Never connected", "mu"];
  if (d.status === "agent_stopped" && s < 86400) return ["Agent stopped", "warn"];
  if (s < THRESH) return ["Online", "ok"];
  if (s < 900) return ["Unresponsive", "warn"];
  return ["Offline", "mu"];
}
const stBadge = d => { const [t, c] = devState(d); return badge(t, c) + (d.is_compromised ? " " + badge("compromised", "bad") : ""); };
function scoreOf(d, unresolvedHigh) {
  const ss = d.system_status || {}, [st] = devState(d), r = [];
  const add = (pts, ok, label, warn) => r.push({ pts: ok ? pts : warn ? Math.round(pts / 2) : 0, max: pts, ok, warn: !ok && warn, label });
  add(25, st === "Online", "Sentinel service running & reporting", st === "Unresponsive");
  add(20, d.integrity_status === "verified", `Agent integrity ${d.integrity_status}`, d.integrity_status === "unknown");
  add(15, ((Date.now() - new Date(d.last_heartbeat || 0)) / 1000) < THRESH, `Last heartbeat ${ago(d.last_heartbeat)}`, false);
  add(15, ss.defender?.realtime === true, ss.defender ? "Defender real-time protection " + (ss.defender.realtime ? "on" : "OFF") : "Defender status unknown", !ss.defender);
  const fw = ss.firewall; add(15, Array.isArray(fw) && fw.length > 0 && fw.every(p => p.enabled), fw ? "Firewall profiles " + (fw.every(p => p.enabled) ? "all enabled" : "NOT all enabled") : "Firewall status unknown", !fw);
  add(10, unresolvedHigh === 0, `${unresolvedHigh} unresolved high/critical alert(s)`, false);
  return { total: r.reduce((a, x) => a + x.pts, 0), r };
}

// ── overview ────────────────────────────────────────────────────────────────
async function overviewView(v) {
  const [dv, ev, au, hc, rel, ap] = await Promise.all([
    sb.from("devices").select(DEV_COLS), sb.from("security_events").select("id,device_id,severity,message,event_type,event_timestamp").eq("resolved", false).in("severity", ["high", "critical"]).order("event_timestamp", { ascending: false }).limit(500),
    sb.from("admin_audit_logs").select("action,created_at,target_device_id,admin_id").order("created_at", { ascending: false }).limit(8),
    sb.from("system_health_checks").select("*").order("checked_at", { ascending: false }).limit(1),
    sb.from("agent_releases").select("version").eq("is_latest", true).maybeSingle(), sb.from("app_settings").select("*").eq("key", "offline_threshold_seconds").maybeSingle()]);
  const err = dv.error || ev.error; if (err) throw new Error(err.message);
  THRESH = Number(ap.data?.value) || 120;
  const devs = dv.data, names = Object.fromEntries(devs.map(d => [d.id, d.device_name]));
  const active = devs.filter(d => d.is_active);
  const crit = new Set(ev.data.filter(e => e.severity === "critical").map(e => e.device_id)), high = new Set(ev.data.filter(e => e.severity === "high").map(e => e.device_id));
  const latest = rel.data?.version;
  const last = hc.data?.[0], staleHc = !last || (Date.now() - new Date(last.checked_at)) > 36 * 3600e3 || !last.success;
  v.innerHTML = `<h2>Overview</h2>
  ${staleHc ? `<div class="banner">⚠️ Supabase keep-alive: ${last ? `last check ${ago(last.checked_at)} (${last.success ? "ok" : "FAILED"})` : "no check recorded yet"}. Verify the GitHub Action — a paused project stops all monitoring.</div>` : ""}
  <div class="grid">
  <div class="card stat"><b>${devs.length}</b><span>Registered</span></div>
  <div class="card stat good"><b>${active.filter(d => devState(d)[0] === "Online").length}</b><span>Online</span></div>
  <div class="card stat"><b>${active.filter(d => ["Offline", "Unresponsive", "Agent stopped"].includes(devState(d)[0])).length}</b><span>Offline / stopped</span></div>
  <div class="card stat crit"><b>${crit.size}</b><span>Critical alerts</span></div>
  <div class="card stat high"><b>${high.size}</b><span>High alerts</span></div>
  <div class="card stat"><b>${latest ? active.filter(d => d.agent_version && d.agent_version !== latest).length : "—"}</b><span>Outdated agents</span></div>
  <div class="card stat crit"><b>${active.filter(d => d.integrity_status === "mismatch").length}</b><span>Integrity problems</span></div></div>
  <div class="two"><div class="card"><h3>Recent incidents (unresolved high/critical)</h3>${ev.data.slice(0, 12).map(e => `<div class="sm" style="margin-bottom:.5rem">${sev(e.severity)} <a href="#/device/${e.device_id}/security">${esc(names[e.device_id] || "?")}</a> — ${esc(e.message.slice(0, 120))}<br><span class="mu">${fmt(e.event_timestamp)}</span></div>`).join("") || '<p class="mu">None 🎉</p>'}</div>
  <div class="card"><h3>Recent administrator actions</h3>${au.data.map(a => `<div class="sm" style="margin-bottom:.4rem"><b>${esc(a.action)}</b> ${a.target_device_id ? "· " + esc(names[a.target_device_id] || "") : ""}<br><span class="mu">${fmt(a.created_at)}</span></div>`).join("") || '<p class="mu">No actions yet</p>'}</div></div>`;
}

// ── devices list ────────────────────────────────────────────────────────────
async function devicesView(v) {
  const { data, error } = await sb.from("devices").select(DEV_COLS).order("device_name"); if (error) throw new Error(error.message);
  v.innerHTML = `<h2>Devices</h2><div class="card tw"><table><thead><tr><th>Name</th><th>Status</th><th>Mode</th><th>Agent</th><th>Integrity</th><th>Last seen</th></tr></thead><tbody>${data.map(d => `<tr class="click" data-go="#/device/${d.id}"><td><b>${esc(d.device_name)}</b><br><span class="mu sm">${esc(d.hostname || "")}</span></td><td>${stBadge(d)}</td><td>${badge(d.current_mode, d.current_mode === "secure" ? "sec" : "open")}</td><td>${esc(d.agent_version || "—")}</td><td>${badge(d.integrity_status, d.integrity_status === "verified" ? "ok" : d.integrity_status === "mismatch" ? "bad" : "mu")}</td><td>${ago(d.last_seen_at)}</td></tr>`).join("") || '<tr><td colspan="6" class="mu">No devices yet. Create an enrollment token in Settings.</td></tr>'}</tbody></table></div>`;
  v.querySelectorAll("[data-go]").forEach(r => r.onclick = () => location.hash = r.dataset.go);
}

// ── device page ─────────────────────────────────────────────────────────────
const TABS = [["overview", "Overview"], ["security", "Security Events"], ["logins", "Windows Logins"], ["files", "File & Folder"], ["apps", "Applications"], ["usb", "USB"], ["health", "Agent Health"], ["commands", "Commands"], ["settings", "Settings"]];
const TAB_CATS = { security: ["security", "defender", "firewall", "network", "auth"], logins: ["login"], files: ["file"], apps: ["application"], usb: ["usb"], health: ["agent", "system_health", "integrity", "service"] };
async function deviceView(v, id, tab) {
  const { data: d, error } = await sb.from("devices").select(DEV_COLS).eq("id", id).maybeSingle(); if (error || !d) throw new Error("device_not_found");
  v.innerHTML = `<h2>${esc(d.device_name)} ${stBadge(d)} ${badge(d.current_mode, d.current_mode === "secure" ? "sec" : "open")}</h2><div class="tabs">${TABS.map(([k, l]) => `<a href="#/device/${id}/${k}" class="${k === tab ? "on" : ""}">${l}</a>`).join("")}</div><div id="tabbody"></div>`;
  const tb = v.querySelector("#tabbody");
  if (tab === "overview") await deviceOverview(tb, d);
  else if (TAB_CATS[tab]) { if (tab === "health") await healthTab(tb, d); await eventsView(tb.appendChild(Object.assign(document.createElement("div"), { })), { deviceId: id, cats: TAB_CATS[tab], title: TABS.find(t => t[0] === tab)[1] }); }
  else if (tab === "commands") await commandsTab(tb, d);
  else if (tab === "settings") await deviceSettings(tb, d);
}
async function deviceOverview(el, d) {
  const [ev, tl] = await Promise.all([
    sb.from("security_events").select("severity").eq("device_id", d.id).eq("resolved", false).in("severity", ["high", "critical"]),
    sb.from("security_events").select("*").eq("device_id", d.id).order("event_timestamp", { ascending: false }).limit(25)]);
  const sc = scoreOf(d, ev.data?.length || 0), ss = d.system_status || {};
  const fails = (await sb.from("security_events").select("id", { count: "exact", head: true }).eq("device_id", d.id).eq("event_type", "logon_failed").gte("event_timestamp", new Date(Date.now() - 86400e3).toISOString())).count;
  el.innerHTML = `<div class="two"><div class="card"><h3>Device information</h3><dl class="kv"><dt>Device ID</dt><dd>${d.id}</dd><dt>Hostname</dt><dd>${esc(d.hostname || "—")}</dd><dt>OS</dt><dd>${esc(d.operating_system || "")} ${esc(d.os_version || "")}</dd><dt>Agent version</dt><dd>${esc(d.agent_version || "—")}</dd><dt>Registered</dt><dd>${fmt(d.registered_at)}</dd><dt>Last heartbeat</dt><dd>${fmt(d.last_heartbeat)} (${ago(d.last_heartbeat)})</dd><dt>Last seen</dt><dd>${fmt(d.last_seen_at)}</dd></dl></div>
  <div class="card"><h3>Security status</h3><dl class="kv"><dt>Protection mode</dt><dd>${esc(d.current_mode)}</dd><dt>Agent integrity</dt><dd>${esc(d.integrity_status)}</dd><dt>Defender</dt><dd>${ss.defender ? `AV ${ss.defender.antivirus ? "on" : "OFF"} · RTP ${ss.defender.realtime ? "on" : "OFF"} · Tamper ${ss.defender.tamper ? "on" : "off"} · sigs ${ss.defender.sig_age_hours ?? "?"}h old` : "unknown"}</dd><dt>Firewall</dt><dd>${Array.isArray(ss.firewall) ? ss.firewall.map(p => `${esc(p.name)}: ${p.enabled ? "on" : "OFF"}`).join(" · ") : "unknown"}</dd><dt>Failed logons 24h</dt><dd>${fails ?? 0}</dd><dt>Agent buffer</dt><dd>${ss.buffer ? `${ss.buffer.rows} queued (${ss.buffer.pct}%)` : "—"}</dd></dl></div></div>
  <div class="two"><div class="card"><h3>Security health score <span class="score">${sc.total}</span>/100</h3><ul class="reasons">${sc.r.map(x => `<li>${x.ok ? "✅" : x.warn ? "⚠️" : "❌"} ${esc(x.label)} <span class="mu">(${x.pts}/${x.max})</span></li>`).join("")}</ul><p class="mu sm">Simple rules, not proof of security.</p></div>
  <div class="card"><h3>🚨 Emergency response</h3><p class="sm mu" style="margin-bottom:.6rem">Commands are only <b>completed</b> once the laptop acknowledges and runs them. Offline devices receive them on reconnect (until they expire).</p><div id="emg" style="display:flex;gap:.4rem;flex-wrap:wrap"></div></div></div>
  <div class="card"><h3>Recent activity</h3><div class="tl">${tl.data.map(e => `<div class="it s-${e.severity}"><span class="mu sm">${fmt(e.event_timestamp)}</span> ${sev(e.severity)} <b>${esc(e.event_type)}</b><br>${esc(e.message)}</div>`).join("") || '<p class="mu">No events yet</p>'}</div></div>`;
  emergencyButtons(el.querySelector("#emg"), d);
}
const CMDS = { secure_mode_on: "Activate Secure Mode", secure_mode_off: "Deactivate Secure Mode", lock_workstation: "Lock workstation", security_scan: "Quick scan", health_report: "Health report", integrity_check: "Integrity check", refresh_config: "Refresh config", restrict_apps: "Restrict apps…", rotate_credentials: "Rotate credentials", network_isolate: "Isolate network…", network_restore: "Restore network" };
const SENSITIVE = ["lock_workstation", "restrict_apps", "rotate_credentials", "network_isolate"];
function emergencyButtons(el, d) {
  const dead = !d.is_active;
  el.innerHTML = Object.entries(CMDS).map(([k, l]) => `<button data-c="${k}" ${dead ? "disabled" : ""}>${l}</button>`).join("") +
    `<button class="danger" data-x="compromise" ${dead ? "disabled" : ""}>${d.is_compromised ? "Clear compromised" : "Mark compromised"}</button><button class="danger" data-x="revoke" ${dead ? "disabled" : ""}>Revoke device</button>`;
  el.onclick = async e => {
    const b = e.target.closest("button"); if (!b) return;
    try {
      if (b.dataset.c) {
        const c = b.dataset.c; let payload = {}, ok;
        if (c === "restrict_apps") { ok = await confirmDialog("Restrict applications", `<label>Executables (one per line)</label><textarea id="ra"></textarea><label>Minutes</label><input id="rm" type="number" value="60" min="1" max="1440">`); if (!ok) return; payload = { apps: toList(ok.el.querySelector("#ra").value), minutes: +ok.el.querySelector("#rm").value }; }
        else if (c === "network_isolate") { ok = await confirmDialog("Isolate network", `<p>Blocks outbound traffic except to Sentinel's cloud endpoint. Auto-restores after the timeout. The agent must have <code>allow_network_isolation</code> enabled locally.</p><label>Auto-restore (minutes)</label><input id="ar" type="number" value="30" min="5" max="240">`, { danger: true }); if (!ok) return; payload = { auto_restore_minutes: +ok.el.querySelector("#ar").value }; }
        else if (SENSITIVE.includes(c) || c === "secure_mode_off") { ok = await confirmDialog(CMDS[c], `<p>Send <b>${esc(CMDS[c])}</b> to <b>${esc(d.device_name)}</b>?</p>`, { danger: c === "lock_workstation" || c === "rotate_credentials" }); if (!ok) return; }
        const r = await api("create_command", { device_id: d.id, command_type: c, payload, confirm: true });
        toast(`Queued (${r.status}). Waiting for the device to acknowledge.`, "ok");
      } else if (b.dataset.x === "compromise") {
        const on = !d.is_compromised; if (!await confirmDialog(on ? "Mark compromised" : "Clear flag", `<p>${on ? "Marks the device compromised and queues Secure Mode." : "Clears the compromised flag."}</p>`, { danger: on })) return;
        await api(on ? "mark_compromised" : "clear_compromised", { device_id: d.id, confirm: true }); toast("Done", "ok");
      } else if (b.dataset.x === "revoke") {
        const r = await confirmDialog("Revoke device credentials", `<p>The device will no longer be able to send logs or receive commands. Re-enrolment needs a new token.</p><label>Reason</label><input id="rr" style="width:100%">`, { danger: true, needText: d.device_name, okText: "Revoke" }); if (!r) return;
        await api("revoke_device", { device_id: d.id, confirm_name: r.text, reason: r.el.querySelector("#rr").value }); toast("Device revoked", "ok");
      }
      route(true);
    } catch (err) { toast(errText(err), "bad"); }
  };
}

// ── agent health tab extras ─────────────────────────────────────────────────
async function healthTab(el, d) {
  const [hb, ig] = await Promise.all([sb.from("device_heartbeats").select("*").eq("device_id", d.id).order("timestamp", { ascending: false }).limit(15), sb.from("agent_integrity_events").select("*").eq("device_id", d.id).order("created_at", { ascending: false }).limit(15)]);
  el.insertAdjacentHTML("beforeend", `<div class="two"><div class="card tw"><h3>Heartbeat samples</h3><table><tbody>${(hb.data || []).map(h => `<tr><td>${fmt(h.timestamp)}</td><td>${esc(h.agent_version || "")}</td><td>${esc(h.service_status || "")}</td></tr>`).join("")}</tbody></table></div><div class="card tw"><h3>Integrity findings ${d.integrity_status === "mismatch" ? `<button data-ab class="danger" style="float:right">Accept current as baseline</button>` : ""}</h3><table><tbody>${(ig.data || []).map(i => `<tr><td>${sev(i.severity)}</td><td>${esc(i.check_type)}</td><td class="sm">${fmt(i.created_at)}</td></tr>`).join("") || '<tr><td class="mu">None</td></tr>'}</tbody></table></div></div>`);
  const b = el.querySelector("[data-ab]"); if (b) b.onclick = async () => { if (!await confirmDialog("Accept baseline", "<p>Only do this if you made the change yourself (e.g. upgraded the agent).</p>", { danger: true })) return; try { await api("accept_baseline", { device_id: d.id }); toast("Baseline reset", "ok"); route(); } catch (e) { toast(errText(e), "bad"); } };
}

// ── events table (filters, search, pagination, export) ──────────────────────
const CATS = ["security", "login", "usb", "file", "application", "integrity", "defender", "firewall", "service", "network", "system_health", "agent", "command", "auth"];
async function eventsView(host, { deviceId = null, cats = null, title = "Events", showDevice = false }) {
  const devs = showDevice ? (await sb.from("devices").select("id,device_name")).data || [] : [], names = Object.fromEntries(devs.map(d => [d.id, d.device_name]));
  const st = { page: 0, size: 50 };
  const box = document.createElement("div"); host.append(box);
  box.innerHTML = `<h3>${esc(title)}</h3><div class="card"><div class="bar">
   ${showDevice ? `<div><label>Device</label><select id="f-dev"><option value="">All</option>${devs.map(d => `<option value="${d.id}">${esc(d.device_name)}</option>`).join("")}</select></div>` : ""}
   <div><label>From</label><input id="f-from" type="datetime-local"></div><div><label>To</label><input id="f-to" type="datetime-local"></div>
   <div><label>Severity</label><select id="f-sev"><option value="">Any</option><option>critical</option><option>high</option><option>medium</option><option>low</option></select></div>
   <div><label>Category</label><select id="f-cat"><option value="">Any</option>${(cats || CATS).map(c => `<option>${c}</option>`).join("")}</select></div>
   <div><label>Source</label><input id="f-src" size="8"></div><div><label>Event type</label><input id="f-type" size="12"></div>
   <div><label>Status</label><select id="f-res"><option value="">Any</option><option value="open">Unresolved</option><option value="done">Resolved</option></select></div>
   <div><label>Search</label><input id="f-q" placeholder="message text"></div><button id="f-go" class="pri">Apply</button>
   <button id="x-csv">CSV</button><button id="x-json">JSON</button></div><div class="tw"><table><thead><tr>${showDevice ? "<th>Device</th>" : ""}<th>Time</th><th>Sev</th><th>Category</th><th>Type</th><th>Message</th><th></th></tr></thead><tbody id="rows"></tbody></table></div>
   <div class="bar" style="margin-top:.8rem"><button id="pg-p">‹ Prev</button><span id="pg-i" class="mu"></span><button id="pg-n">Next ›</button></div></div>`;
  const $ = s => box.querySelector(s);
  const build = () => {
    let q = sb.from("security_events").select("*", { count: "exact" }).order("event_timestamp", { ascending: false });
    const dv = deviceId || ($("#f-dev")?.value); if (dv) q = q.eq("device_id", dv);
    const c = $("#f-cat").value; if (c) q = q.eq("category", c); else if (cats) q = q.in("category", cats);
    if ($("#f-sev").value) q = q.eq("severity", $("#f-sev").value);
    if ($("#f-from").value) q = q.gte("event_timestamp", new Date($("#f-from").value).toISOString());
    if ($("#f-to").value) q = q.lte("event_timestamp", new Date($("#f-to").value).toISOString());
    if ($("#f-src").value.trim()) q = q.eq("source", $("#f-src").value.trim());
    if ($("#f-type").value.trim()) q = q.eq("event_type", $("#f-type").value.trim());
    if ($("#f-res").value) q = q.eq("resolved", $("#f-res").value === "done");
    const s = $("#f-q").value.replace(/[%,()*]/g, " ").trim(); if (s) q = q.ilike("message", `%${s}%`);
    return q;
  };
  async function load() {
    const { data, count, error } = await build().range(st.page * st.size, st.page * st.size + st.size - 1);
    if (error) return ($("#rows").innerHTML = `<tr><td class="err">${esc(error.message)}</td></tr>`);
    $("#rows").innerHTML = data.map(e => `<tr>${showDevice ? `<td><a href="#/device/${e.device_id}">${esc(names[e.device_id] || "")}</a></td>` : ""}<td class="sm">${fmt(e.event_timestamp)}</td><td>${sev(e.severity)}</td><td>${esc(e.category)}</td><td>${esc(e.event_type)}</td><td>${esc(e.message)}${Object.keys(e.details || {}).length ? `<details><summary class="mu sm">details</summary><pre>${esc(JSON.stringify(e.details, null, 2))}</pre></details>` : ""}</td><td>${e.resolved ? badge("resolved", "ok") : (["high", "critical"].includes(e.severity) ? `<button data-r="${e.id}">Resolve</button>` : "")}</td></tr>`).join("") || `<tr><td colspan="7" class="mu">No events match.</td></tr>`;
    const pages = Math.max(1, Math.ceil((count || 0) / st.size)); $("#pg-i").textContent = `Page ${st.page + 1} / ${pages} · ${count ?? 0} events`;
    $("#pg-p").disabled = st.page === 0; $("#pg-n").disabled = st.page + 1 >= pages;
  }
  $("#f-go").onclick = () => { st.page = 0; load(); }; $("#pg-p").onclick = () => { st.page--; load(); }; $("#pg-n").onclick = () => { st.page++; load(); };
  $("#rows").onclick = async e => { const id = e.target.dataset.r; if (!id) return; const r = await confirmDialog("Resolve event", `<label>Note</label><input id="rn" style="width:100%">`); if (!r) return; try { await api("resolve_event", { event_ids: [id], note: r.el.querySelector("#rn").value }); load(); } catch (er) { toast(errText(er), "bad"); } };
  async function exportAll(kind) {
    toast("Exporting…"); let all = [], from = 0; const step = 1000;
    for (;;) { const { data, error } = await build().range(from, from + step - 1); if (error) return toast(error.message, "bad"); all = all.concat(data); if (data.length < step || all.length >= 100000) break; from += step; }
    let blob, name = `sentinel-events-${new Date().toISOString().slice(0, 10)}`;
    if (kind === "json") { blob = new Blob([JSON.stringify(all, null, 1)], { type: "application/json" }); name += ".json"; }
    else { const cols = ["event_timestamp", "device_id", "severity", "category", "event_type", "source", "message", "resolved", "deduplication_id"]; const q = x => `"${String(x ?? "").replace(/"/g, '""').replace(/^([=+\-@])/, "'$1")}"`; blob = new Blob([cols.join(",") + "\n" + all.map(r => cols.map(c => q(r[c])).join(",")).join("\n")], { type: "text/csv" }); name += ".csv"; }
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = name; a.click(); URL.revokeObjectURL(a.href); toast(`Exported ${all.length} events`, "ok");
  }
  $("#x-csv").onclick = () => exportAll("csv"); $("#x-json").onclick = () => exportAll("json");
  await load();
}

// ── commands ────────────────────────────────────────────────────────────────
const CST = { pending: "warn", delivered: "warn", acknowledged: "warn", executing: "warn", completed: "ok", failed: "bad", expired: "mu", cancelled: "mu" };
function cmdTable(rows, names) {
  return `<div class="card tw"><table><thead><tr>${names ? "<th>Device</th>" : ""}<th>Command</th><th>Status</th><th>Created</th><th>Expires</th><th>Result</th><th></th></tr></thead><tbody>${rows.map(c => `<tr>${names ? `<td>${esc(names[c.device_id] || "")}</td>` : ""}<td>${esc(c.command_type)}</td><td>${badge(c.status, CST[c.status])}${c.status === "pending" ? '<div class="mu sm">waiting for device</div>' : ""}</td><td class="sm">${fmt(c.created_at)}</td><td class="sm">${fmt(c.expires_at)}</td><td class="sm">${c.result ? `<details><summary>view</summary><pre>${esc(JSON.stringify(c.result, null, 1))}</pre></details>` : ""}</td><td>${["pending", "delivered"].includes(c.status) ? `<button data-cx="${c.id}">Cancel</button>` : ""}</td></tr>`).join("") || '<tr><td class="mu">No commands</td></tr>'}</tbody></table></div>`;
}
function bindCancel(el) { el.querySelectorAll("[data-cx]").forEach(b => b.onclick = async () => { try { await api("cancel_command", { command_id: b.dataset.cx }); route(true); } catch (e) { toast(errText(e), "bad"); } }); }
async function commandsView(v) {
  const [c, d] = await Promise.all([sb.from("device_commands").select("*").order("created_at", { ascending: false }).limit(100), sb.from("devices").select("id,device_name")]);
  v.innerHTML = `<h2>Command history</h2>${cmdTable(c.data || [], Object.fromEntries((d.data || []).map(x => [x.id, x.device_name])))}`; bindCancel(v);
}
async function commandsTab(el, d) { const { data } = await sb.from("device_commands").select("*").eq("device_id", d.id).order("created_at", { ascending: false }).limit(100); el.innerHTML = cmdTable(data || [], null); bindCancel(el); }

// ── device settings ─────────────────────────────────────────────────────────
async function deviceSettings(el, d) {
  const { data: s } = await sb.from("device_settings").select("*").eq("device_id", d.id).maybeSingle(); if (!s) { el.innerHTML = "<p class='mu'>No settings</p>"; return; }
  const ec = s.event_categories || {};
  el.innerHTML = `<div class="two"><div class="card"><h3>Blocked applications <span class="mu sm">(enforced in Secure Mode)</span></h3><textarea id="s-apps" placeholder="chrome.exe">${esc(lines(s.blocked_applications))}</textarea><h3 style="margin-top:.8rem">Watch-list processes <span class="mu sm">(always alert)</span></h3><textarea id="s-watch">${esc(lines(s.watch_processes))}</textarea></div>
  <div class="card"><h3>Protected folders</h3><textarea id="s-fold" placeholder="C:\\Users\\me\\Documents\\Private">${esc(lines(s.protected_folders))}</textarea><p class="mu sm">Only paths, event types and times are logged — never file contents.</p><label><input type="checkbox" id="s-mon" ${s.monitoring_enabled ? "checked" : ""} style="width:auto"> Monitoring enabled</label><label>Heartbeat interval (seconds, 15–600)</label><input id="s-hb" type="number" min="15" max="600" value="${s.heartbeat_interval}"></div></div>
  <div class="card"><h3>Event categories <span class="mu sm">(critical events are always sent)</span></h3>${["login", "usb", "file", "application", "defender", "firewall", "service", "network", "integrity"].map(k => `<label style="display:inline-block;margin-right:1rem"><input type="checkbox" data-ec="${k}" ${ec[k] !== false ? "checked" : ""} style="width:auto"> ${k}</label>`).join("")}</div>
  <button class="pri" id="s-save">Save settings</button> <span class="mu sm">Secure Mode is changed with commands so it is acknowledged by the device. Current: <b>${s.secure_mode ? "secure" : "open"}</b> · version ${s.settings_version}</span>`;
  el.querySelector("#s-save").onclick = async () => {
    const event_categories = {}; el.querySelectorAll("[data-ec]").forEach(c => event_categories[c.dataset.ec] = c.checked);
    try { await api("update_settings", { device_id: d.id, settings: { blocked_applications: toList(el.querySelector("#s-apps").value), watch_processes: toList(el.querySelector("#s-watch").value), protected_folders: toList(el.querySelector("#s-fold").value), monitoring_enabled: el.querySelector("#s-mon").checked, heartbeat_interval: +el.querySelector("#s-hb").value, event_categories } }); toast("Saved — device picks it up on its next heartbeat", "ok"); }
    catch (e) { toast(errText(e), "bad"); }
  };
}

// ── settings (tokens, releases, MFA, retention, audit) ──────────────────────
async function settingsView(v) {
  const [tk, rl, au, hc, ret] = await Promise.all([
    sb.from("device_enrollment_tokens").select("id,label,created_at,expires_at,used_at").order("created_at", { ascending: false }).limit(10),
    sb.from("agent_releases").select("*").order("created_at", { ascending: false }).limit(10),
    sb.from("admin_audit_logs").select("*").order("created_at", { ascending: false }).limit(30),
    sb.from("system_health_checks").select("*").order("checked_at", { ascending: false }).limit(8),
    sb.from("app_settings").select("*").eq("key", "heartbeat_retention_days").maybeSingle()]);
  const owner = me.role === "owner";
  v.innerHTML = `<h2>Settings</h2>
  <div class="two"><div class="card"><h3>Enroll a new laptop</h3><label>Label</label><input id="t-l" placeholder="Johns-Laptop"><label>Valid for (minutes)</label><input id="t-m" type="number" value="60" min="5" max="1440"><br><br><button class="pri" id="t-new">Create one-time token</button><div id="t-out"></div>
  <table style="margin-top:.8rem"><tbody>${(tk.data || []).map(t => `<tr><td>${esc(t.label || "—")}</td><td>${t.used_at ? badge("used", "ok") : new Date(t.expires_at) < new Date() ? badge("expired", "mu") : badge("active", "warn")}</td><td class="sm">${fmt(t.created_at)}</td></tr>`).join("")}</tbody></table></div>
  <div class="card"><h3>Two-factor authentication (TOTP)</h3><p class="sm mu">Once enrolled, only MFA-verified sessions can read or change data.</p><div id="mfa"></div></div></div>
  <div class="two"><div class="card"><h3>Agent releases (integrity baseline)</h3><p class="sm mu">Run <code>python tools/make_manifest.py</code> on the build machine and paste the JSON.</p>${owner ? `<label>Version</label><input id="r-v" placeholder="3.0.0"><label>file_hashes JSON</label><textarea id="r-h" placeholder='{"SentinelAgent.exe":"<sha256>"}'></textarea><label><input id="r-l" type="checkbox" checked style="width:auto"> Mark as latest</label><button id="r-pub" class="pri">Publish</button>` : '<p class="mu sm">Owner only.</p>'}<table style="margin-top:.6rem"><tbody>${(rl.data || []).map(r => `<tr><td>${esc(r.version)} ${r.is_latest ? badge("latest", "ok") : ""}</td><td class="sm">${Object.keys(r.file_hashes).length} files</td></tr>`).join("")}</tbody></table></div>
  <div class="card"><h3>Retention</h3><p class="sm mu">Security events are never deleted. Only heartbeat samples can be pruned (daily).</p><p>Heartbeat retention: <b>${ret.data?.value ?? "keep forever"}</b> ${owner ? `<br><input id="rt" type="number" min="7" placeholder="days (blank = forever)"> <button id="rt-s">Save</button>` : ""}</p>
  <h3 style="margin-top:1rem">Keep-alive history</h3>${(hc.data || []).map(h => `<div class="sm">${h.success ? "✅" : "❌"} ${fmt(h.checked_at)} · ${esc(h.source)} · ${h.duration_ms}ms</div>`).join("") || '<p class="mu sm">No checks yet</p>'}</div></div>
  <div class="card tw"><h3>Administrator audit log</h3><table><tbody>${(au.data || []).map(a => `<tr><td class="sm">${fmt(a.created_at)}</td><td><b>${esc(a.action)}</b></td><td class="sm mu">${esc(JSON.stringify(a.details).slice(0, 120))}</td></tr>`).join("")}</tbody></table></div>`;
  v.querySelector("#t-new").onclick = async () => { try { const r = await api("create_enrollment_token", { label: v.querySelector("#t-l").value, ttl_minutes: +v.querySelector("#t-m").value }); v.querySelector("#t-out").innerHTML = `<p class="sm">Copy now — shown only once (expires ${fmt(r.expires_at)}):</p><pre>${esc(r.token)}</pre>`; } catch (e) { toast(errText(e), "bad"); } };
  const pub = v.querySelector("#r-pub"); if (pub) pub.onclick = async () => { try { await api("publish_release", { version: v.querySelector("#r-v").value.trim(), file_hashes: JSON.parse(v.querySelector("#r-h").value), is_latest: v.querySelector("#r-l").checked }); toast("Published", "ok"); route(); } catch (e) { toast(errText(e), "bad"); } };
  const rs = v.querySelector("#rt-s"); if (rs) rs.onclick = async () => { const x = v.querySelector("#rt").value; try { await api("set_retention", { heartbeat_retention_days: x === "" ? null : +x }); toast("Saved", "ok"); route(); } catch (e) { toast(errText(e), "bad"); } };
  mfaPanel(v.querySelector("#mfa"));
}
async function mfaPanel(el) {
  const { data } = await sb.auth.mfa.listFactors(); const f = data?.totp?.[0];
  if (f) { el.innerHTML = `<p>✅ TOTP enrolled.</p><button class="danger" id="m-rm">Remove</button>`; el.querySelector("#m-rm").onclick = async () => { const { data: a } = await sb.auth.mfa.getAuthenticatorAssuranceLevel(); if (a.currentLevel !== "aal2") return toast("Sign in with MFA first", "bad"); await sb.auth.mfa.unenroll({ factorId: f.id }); toast("Removed", "ok"); route(); }; return; }
  el.innerHTML = '<button id="m-go" class="pri">Set up authenticator app</button>';
  el.querySelector("#m-go").onclick = async () => {
    const { data: en, error } = await sb.auth.mfa.enroll({ factorType: "totp" }); if (error) return toast(error.message, "bad");
    el.innerHTML = `<p class="sm">Scan with an authenticator app, then enter the code.</p><img src="${en.totp.qr_code}" alt="QR" width="180" height="180" style="background:#fff;padding:6px"><p class="sm mu">Manual key: <code>${esc(en.totp.secret)}</code></p><input id="m-c" maxlength="6" placeholder="123456"> <button id="m-v" class="pri">Verify & enable</button>`;
    el.querySelector("#m-v").onclick = async () => { const { data: ch } = await sb.auth.mfa.challenge({ factorId: en.id }); const { error: e2 } = await sb.auth.mfa.verify({ factorId: en.id, challengeId: ch.id, code: el.querySelector("#m-c").value.trim() }); if (e2) return toast("Invalid code", "bad"); toast("MFA enabled", "ok"); route(); };
  };
}

// ── boot ────────────────────────────────────────────────────────────────────
(async () => {
  const { data: { session } } = await sb.auth.getSession();
  if (session) await afterPassword(); else loginView();
})();
})();
