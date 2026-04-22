const express = require("express");
const cors    = require("cors");
const path    = require("path");

const app  = express();
const PORT = 3000;

// ── removed: unused OpenAI import (was crashing startup) ──

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// ── USERS ──────────────────────────────────────────────────
const USERS = {
  admin: { password: "admin123", role: "admin",    display: "ADMIN"   },
  emp1:  { password: "123",      role: "employee", display: "EMP-001" },
  emp2:  { password: "123",      role: "employee", display: "EMP-002" },
  emp3:  { password: "123",      role: "employee", display: "EMP-003" },
  emp4:  { password: "123",      role: "employee", display: "EMP-004" },
  emp5:  { password: "123",      role: "employee", display: "EMP-005" },
  emp6:  { password: "123",      role: "employee", display: "EMP-006" },
  emp7:  { password: "123",      role: "employee", display: "EMP-007" },
  emp8:  { password: "123",      role: "employee", display: "EMP-008" },
  emp9:  { password: "123",      role: "employee", display: "EMP-009" },
  emp10: { password: "123",      role: "employee", display: "EMP-010" },
};

// ── FILE CATEGORIES ────────────────────────────────────────
const CATEGORIES = {
  hr: {
    name: "HR Records", icon: "👥", sensitive: false, critical: false,
    files: [
      { name: "employee_list.pdf",           size: "1.2 MB", icon: "📄" },
      { name: "onboarding_guide.docx",       size: "860 KB", icon: "📝" },
      { name: "performance_reviews_Q1.xlsx", size: "2.1 MB", icon: "📊" },
      { name: "org_chart_2026.pdf",          size: "540 KB", icon: "📄" },
    ],
  },
  project: {
    name: "Project Documents", icon: "📋", sensitive: false, critical: false,
    files: [
      { name: "project_alpha.docx",       size: "3.4 MB", icon: "📝" },
      { name: "project_beta_specs.pdf",   size: "5.1 MB", icon: "📄" },
      { name: "roadmap_2026.xlsx",        size: "1.8 MB", icon: "📊" },
      { name: "sprint_backlog.txt",       size: "220 KB", icon: "📃" },
      { name: "architecture_diagram.pdf", size: "4.7 MB", icon: "📄" },
    ],
  },
  logs: {
    name: "System Logs", icon: "🖥", sensitive: false, critical: false,
    files: [
      { name: "access_log_april.txt", size: "12.4 MB", icon: "📃" },
      { name: "error_log_2026.txt",   size: "3.2 MB",  icon: "📃" },
      { name: "audit_trail.csv",      size: "6.8 MB",  icon: "📊" },
    ],
  },
  finance: {
    name: "Financial Reports", icon: "💰", sensitive: true, critical: false,
    files: [
      { name: "budget_2026.xlsx",         size: "4.2 MB", icon: "📊" },
      { name: "Q1_revenue_report.pdf",    size: "2.9 MB", icon: "📄" },
      { name: "payroll_summary.xlsx",     size: "1.6 MB", icon: "📊" },
      { name: "investment_portfolio.pdf", size: "3.8 MB", icon: "📄" },
    ],
  },
  client: {
    name: "Client Data", icon: "🏢", sensitive: true, critical: false,
    files: [
      { name: "client_database_2026.csv", size: "18.4 MB", icon: "📊" },
      { name: "contracts_signed.pdf",     size: "7.2 MB",  icon: "📄" },
      { name: "client_pii_records.xlsx",  size: "9.1 MB",  icon: "📊" },
      { name: "crm_export_april.csv",     size: "5.6 MB",  icon: "📊" },
    ],
  },
  confidential: {
    name: "Confidential Files", icon: "🔒", sensitive: true, critical: true,
    files: [
      { name: "board_meeting_minutes.pdf", size: "1.1 MB", icon: "📄" },
      { name: "acquisition_targets.docx",  size: "2.4 MB", icon: "📝" },
      { name: "security_master_keys.txt",  size: "44 KB",  icon: "🔑" },
      // ── removed: setTimeout() that was illegally placed inside this array ──
    ],
  },
};

// ── IN-MEMORY STORES ───────────────────────────────────────
let activityLogs  = [];
let alertLogs     = [];
let sessions      = {};   // username -> { riskScore, accessCount, downloadCount }
let logId         = 1;
let alertId       = 1;

function ts() {
  return new Date().toLocaleTimeString("en-US", { hour12: false });
}

function addLog(user, dotType, msg) {
  activityLogs.unshift({ id: logId++, ts: ts(), dotType, msg, user });
  if (activityLogs.length > 300) activityLogs.pop();
}

function addAlert(user, catKey, catName, filename) {
  const cat      = CATEGORIES[catKey];
  const severity = cat.critical ? "CRITICAL" : "HIGH";
  const action   = filename ? `downloaded ${filename}` : `accessed`;
  const entry    = {
    id: alertId++, ts: ts(),
    title: `🚨 ${severity} RISK — SENSITIVE DATA ${filename ? "DOWNLOAD" : "ACCESS"}`,
    desc:  `${user} ${action} from ${catName}`,
    severity, user,
  };
  alertLogs.unshift(entry);
  if (alertLogs.length > 200) alertLogs.pop();
  if (sessions[user]) {
    sessions[user].riskScore = Math.min(100, sessions[user].riskScore + (filename ? 20 : 30));
  }
  return entry;
}

// ── AUTH ───────────────────────────────────────────────────
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const u    = (username || "").toLowerCase().trim();
  const user = USERS[u];
  if (!user || user.password !== password) {
    return res.status(401).json({ success: false });
  }
  sessions[u] = { riskScore: u === "admin" ? 3 : 5, accessCount: 0, downloadCount: 0 };
  addLog(u, "login", `<strong>${u}</strong> authenticated and logged in`);
  res.json({ success: true, username: u, role: user.role, display: user.display });
});

app.post("/api/logout", (req, res) => {
  const u = (req.body.username || "").toLowerCase();
  if (sessions[u]) {
    addLog(u, "alert", `<strong>${u}</strong> session terminated`);
    delete sessions[u];
  }
  res.json({ success: true });
});

// ── CATEGORIES ─────────────────────────────────────────────
app.get("/api/categories", (req, res) => {
  res.json(
    Object.entries(CATEGORIES).map(([key, c]) => ({
      key, name: c.name, icon: c.icon,
      sensitive: c.sensitive, critical: c.critical,
      fileCount: c.files.length,
    }))
  );
});

app.get("/api/categories/:key", (req, res) => {
  const cat = CATEGORIES[req.params.key];
  if (!cat) return res.status(404).json({ error: "Not found" });
  const u = (req.query.username || "unknown").toLowerCase();

  addLog(u, "access", `<strong>${u}</strong> accessed <strong>${cat.name}</strong>`);
  if (sessions[u]) sessions[u].accessCount++;

  let alert = null;
  if (cat.sensitive) {
    alert = addAlert(u, req.params.key, cat.name, null);
    addLog(u, "alert", `⚠ ALERT: <strong>${u}</strong> accessed sensitive <strong>${cat.name}</strong>`);
  }
  res.json({ ...cat, key: req.params.key, alert });
});

app.post("/api/download", (req, res) => {
  const { username, catKey, filename } = req.body;
  const u   = (username || "unknown").toLowerCase();
  const cat = CATEGORIES[catKey];
  if (!cat) return res.status(404).json({ error: "Not found" });

  addLog(u, "download", `<strong>${u}</strong> downloaded <strong>${filename}</strong> from ${cat.name}`);
  if (sessions[u]) sessions[u].downloadCount++;

  let alert = null;
  if (cat.sensitive) {
    alert = addAlert(u, catKey, cat.name, filename);
    addLog(u, "alert", `⚠ ALERT: <strong>${u}</strong> downloaded sensitive file <strong>${filename}</strong>`);
  }
  res.json({ success: true, alert });
});

// ── LOGS & ALERTS ──────────────────────────────────────────
app.get("/api/logs", (req, res) => {
  const { role, username, limit } = req.query;
  const lim  = parseInt(limit) || 50;
  const logs = role === "admin"
    ? activityLogs.slice(0, lim)
    : activityLogs.filter(l => l.user === username).slice(0, lim);
  res.json({ logs, total: activityLogs.length });
});

app.get("/api/alerts", (req, res) => {
  const { role, username } = req.query;
  const list = role === "admin"
    ? alertLogs
    : alertLogs.filter(a => a.user === username);
  res.json({ alerts: list, total: list.length });
});

// ── SESSION & STATS ────────────────────────────────────────
app.get("/api/session/:username", (req, res) => {
  const s = sessions[req.params.username.toLowerCase()];
  if (!s) return res.status(404).json({ error: "No session" });
  res.json(s);
});
// ── removed: stray res.sendFile() that was outside any route handler ──

app.get("/api/stats", (req, res) => {
  res.json({
    totalEvents:  activityLogs.length,
    totalAlerts:  alertLogs.length,
    activeUsers:  Object.keys(sessions).length,
  });
});

app.get("/api/users", (req, res) => {
  res.json(
    Object.entries(USERS).map(([u, d]) => ({
      username: u, role: d.role, display: d.display, online: !!sessions[u],
    }))
  );
});

// ── CHATBOT ────────────────────────────────────────────────
app.post("/api/chat", (req, res) => {
  const { message, username, role } = req.body;
  const q    = (message || "").toLowerCase();
  const u    = (username || "").toLowerCase();
  const sess = sessions[u] || {};
  let reply  = "❓ Unknown query. Try: alerts, activity, users, threat, files, status, risk, help";

  if (q.includes("help"))          reply = "📋 Commands: alerts · activity · users · threat · files · status · risk · help";
  else if (q.includes("alert"))    reply = alertLogs.length === 0 ? "✅ No alerts on record." : `🚨 ${alertLogs.length} alert(s). Latest: "${alertLogs[0].desc}" at ${alertLogs[0].ts}`;
  else if (q.includes("activ"))    reply = `📊 Total events: ${activityLogs.length}. Active sessions: ${Object.keys(sessions).length}.`;
  else if (q.includes("user"))     reply = `👥 ${Object.keys(USERS).length} users registered. ${Object.keys(sessions).length} online.`;
  else if (q.includes("threat"))   reply = `🔍 Risk score: ${sess.riskScore || 0}%. Alerts: ${alertLogs.length}. Level: ${(sess.riskScore||0) >= 60 ? "🔴 HIGH" : (sess.riskScore||0) >= 30 ? "🟡 ELEVATED" : "🟢 LOW"}`;
  else if (q.includes("file"))     reply = "📁 6 categories: HR, Project, Logs (safe) · Finance, Client, Confidential (sensitive — triggers auto-logout)";
  else if (q.includes("status"))   reply = `⚙ SENTINEL v4.2 ONLINE. User: ${u.toUpperCase()} (${role}). Events this session: ${activityLogs.filter(l=>l.user===u).length}`;
  else if (q.includes("risk"))     reply = `📈 Risk: ${sess.riskScore || 0}%. Access: ${sess.accessCount || 0}. Downloads: ${sess.downloadCount || 0}.`;

  res.json({ reply });
  // ── removed: orphaned `if (q.includes("help")) ...` that was after res.json() ──
});

// ── SERVE FRONTEND ─────────────────────────────────────────
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));  // fixed: was "../frontend/index.html"
});

// ── removed: duplicate let activityLogs / alertLogs / sessions declarations ──

app.listen(PORT, () => {
  console.log("\n  ✅  SENTINEL running →  http://localhost:" + PORT);
  console.log("  Credentials:  admin/admin123   emp1-emp10/123\n");
});
