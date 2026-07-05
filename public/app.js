// public/app.js — dashboard frontend logic (talks to /admin/api/*)
const $ = (id) => document.getElementById(id);
const api = (url, opts) => fetch(url, { headers: { "Content-Type": "application/json" }, ...opts }).then(r => r.json());

// ── Tab switching ──
document.querySelectorAll("nav button").forEach(btn => {
  btn.onclick = () => {
    document.querySelectorAll("nav button").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".section").forEach(s => s.classList.remove("show"));
    btn.classList.add("active");
    $(btn.dataset.tab).classList.add("show");
    refresh();
  };
});

// ── Users & Keys ──
async function addUser() {
  await api("/admin/api/users", { method: "POST",
    body: JSON.stringify({ name: $("u_name").value, email: $("u_email").value, purpose: $("u_purpose").value }) });
  $("u_name").value = $("u_email").value = $("u_purpose").value = "";
  loadUsers();
}

async function loadUsers() {
  const users = await api("/admin/api/users");
  $("userList").innerHTML = users.map(u => `
    <div class="card">
      <div class="row">
        <b>${u.name}</b> <small class="mono">${u.email || ""}</small>
        <span class="badge ${u.disabled ? "off" : "on"}">${u.disabled ? "DISABLED" : "ACTIVE"}</span>
        <small>${u.purpose || ""}</small>
        <button class="act gray" onclick="toggleUser(${u.id})">${u.disabled ? "Enable" : "Disable"}</button>
        <button class="act danger" onclick="delUser(${u.id})">Delete</button>
      </div>

      <div class="row" style="margin-top:.6rem">
        <input id="ck_${u.id}" placeholder="Custom key (leave blank = auto-generate)" style="min-width:280px" />
        <input id="rl_${u.id}" type="number" value="60" title="requests" style="width:80px" />
        <span>reqs /</span>
        <input id="rw_${u.id}" type="number" value="60" title="seconds" style="width:80px" />
        <span>sec</span>
        <button class="act" onclick="createKey(${u.id})">Create Key</button>
      </div>

      <table>
        ${(u.keys || []).map(k => `
          <tr>
            <td><small class="mono">${k.api_key}</small></td>
            <td>${k.rate_limit}/${k.rate_window}s</td>
            <td>${k.override_on ? '<span class="badge on">OVR</span>' : ""}</td>
            <td class="${k.revoked ? "revoked" : "active"}">${k.revoked ? "REVOKED" : "ACTIVE"}</td>
            <td>
              <button class="act gray" onclick="regen(${k.id})">Regenerate</button>
              <button class="act gray" onclick="revoke(${k.id})">${k.revoked ? "Unrevoke" : "Revoke"}</button>
              <button class="act" onclick="editKey(${k.id}, ${k.rate_limit}, ${k.rate_window}, ${k.override_on}, ${JSON.stringify(k.override_body || "")})">Edit/Override</button>
              <button class="act danger" onclick="delKey(${k.id})">Delete</button>
            </td>
          </tr>`).join("")}
      </table>
    </div>`).join("");
}

async function createKey(uid) {
  const res = await api("/admin/api/keys", { method: "POST", body: JSON.stringify({
    user_id: uid, custom: $("ck_" + uid).value,
    rate_limit: +$("rl_" + uid).value, rate_window: +$("rw_" + uid).value }) });
  if (res.error) alert(res.error); else alert("Key created: " + res.api_key);
  loadUsers();
}
const toggleUser = (id) => api(`/admin/api/users/${id}/toggle`, { method: "POST" }).then(loadUsers);
const delUser = (id) => confirm("Delete user + keys?") && api(`/admin/api/users/${id}`, { method: "DELETE" }).then(loadUsers);
const regen = (id) => api(`/admin/api/keys/${id}/regenerate`, { method: "POST" }).then(r => { alert("New key: " + r.api_key); loadUsers(); });
const revoke = (id) => api(`/admin/api/keys/${id}/revoke`, { method: "POST" }).then(loadUsers);
const delKey = (id) => confirm("Delete key?") && api(`/admin/api/keys/${id}`, { method: "DELETE" }).then(loadUsers);

function editKey(id, rl, rw, ovOn, ovBody) {
  const newRl = prompt("Rate limit (requests):", rl); if (newRl === null) return;
  const newRw = prompt("Window (seconds):", rw); if (newRw === null) return;
  const on = confirm("Enable per-key override? OK = ON, Cancel = OFF");
  let body = ovBody;
  if (on) { body = prompt("Custom response (JSON or text):", ovBody || '{"message":"demo"}'); if (body === null) return; }
  api(`/admin/api/keys/${id}/update`, { method: "POST", body: JSON.stringify({
    rate_limit: +newRl, rate_window: +newRw, override_on: on, override_body: body }) }).then(loadUsers);
}

// ── Global override settings ──
async function loadSettings() {
  const s = await api("/admin/api/settings");
  $("ov_on").checked = !!s.override_on;
  $("ov_body").value = s.override_body || "";
  $("ov_status").textContent = s.override_on ? "ON" : "OFF";
  $("ov_status").className = "badge " + (s.override_on ? "on" : "off");
}
async function saveSettings() {
  await api("/admin/api/settings", { method: "POST", body: JSON.stringify({
    override_on: $("ov_on").checked, override_body: $("ov_body").value }) });
  loadSettings();
}

// ── Analytics ──
async function loadAnalytics() {
  const a = await api("/admin/api/analytics");
  $("stats").innerHTML = `
    <div class="stat"><b>${a.today}</b>Today</div>
    <div class="stat"><b>${a.week}</b>This Week</div>
    <div class="stat"><b>${a.allTime}</b>All Time</div>
    <div class="stat"><b>${a.activeKeys}</b>Active Keys</div>
    <div class="stat"><b>${a.revokedKeys}</b>Revoked Keys</div>`;
  $("topEndpoints").innerHTML = a.topEndpoints.map(e => `<div>${e.endpoint} — <b>${e.c}</b></div>`).join("") || "No data";
  $("topUsers").innerHTML = a.topUsers.map(u => `<div>${u.name} — <b>${u.c}</b></div>`).join("") || "No data";
  $("recent").innerHTML = logTable(a.recent);
}

// ── Logs ──
function logTable(rows) {
  return `<table><tr><th>Time</th><th>Endpoint</th><th>q</th><th>IP</th><th>Status</th><th>ms</th></tr>
    ${rows.map(l => `<tr>
      <td>${new Date(l.ts).toLocaleString()}</td>
      <td>${l.endpoint}</td><td><small class="mono">${l.query || ""}</small></td>
      <td>${l.ip}</td>
      <td class="${l.status === "success" ? "active" : "revoked"}">${l.status} (${l.status_code})</td>
      <td>${l.resp_ms}</td></tr>`).join("")}</table>`;
}
async function loadLogs() {
  const logs = await api("/admin/api/logs?limit=200");
  $("logList").innerHTML = logTable(logs);
}

// ── IPs ──
async function loadIps() {
  const ips = await api("/admin/api/blocked-ips");
  $("blockedList").innerHTML = `<table>${ips.map(i => `<tr>
    <td><small class="mono">${i.ip}</small></td>
    <td>${new Date(i.created).toLocaleString()}</td>
    <td><button class="act gray" onclick="unblockIp('${i.ip}')">Unblock</button></td>
  </tr>`).join("")}</table>`;
}
const blockIp = () => api("/admin/api/blocked-ips", { method: "POST", body: JSON.stringify({ ip: $("ip_input").value }) }).then(() => { $("ip_input").value = ""; loadIps(); });
const unblockIp = (ip) => api(`/admin/api/blocked-ips/${encodeURIComponent(ip)}`, { method: "DELETE" }).then(loadIps);

// ── Refresh active tab ──
function refresh() {
  const active = document.querySelector("nav button.active").dataset.tab;
  if (active === "overview") loadAnalytics();
  if (active === "users") loadUsers();
  if (active === "override") loadSettings();
  if (active === "logs") loadLogs();
  if (active === "ips") loadIps();
}
refresh();
setInterval(() => { if (document.querySelector("nav button.active").dataset.tab === "overview") loadAnalytics(); }, 15000);
