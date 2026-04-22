let CU   = null;   // current username
let CR   = null;   // current role
let CD   = null;   // current display name
let autoTimer  = null;
let liveTimer  = null;

const $  = id => document.getElementById(id);
const esc = s => String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");

$("btnLogin").onclick = doLogin;
$("inUser").onkeydown = $("inPass").onkeydown = e => { if(e.key==="Enter") doLogin(); };

async function doLogin() {
  const u = $("inUser").value.trim();
  const p = $("inPass").value;
  if (!u || !p) { showErr(); return; }
  try {
    const d = await API.login(u, p);
    if (d.success) {
      CU = d.username; CR = d.role; CD = d.display;
      $("loginErr").style.display = "none";
      $("loginScreen").style.display = "none";
      $("dashboard").style.display   = "flex";
      initDash();
    } else showErr();
  } catch(e) {
    showErr(e.message === "401"
      ? "⚠ INVALID CREDENTIALS — ACCESS DENIED"
      : "⚠ Cannot reach server. Is node server.js running?");
  }
}

function showErr(msg) {
  const el = $("loginErr");
  el.textContent = msg || "⚠ INVALID CREDENTIALS — ACCESS DENIED";
  el.style.display = "block";
  setTimeout(() => el.style.display = "none", 3500);
}

$("btnLogout").onclick = doLogout;

async function doLogout() {
  clearInterval(autoTimer);
  clearInterval(liveTimer);
  autoTimer = liveTimer = null;
  $("overlay").style.display = "none";
  if (CU) await API.logout(CU).catch(()=>{});
  CU = CR = CD = null;
  $("dashboard").style.display   = "none";
  $("loginScreen").style.display = "flex";
  $("inUser").value = $("inPass").value = "";
  $("threatBadge").textContent = "THREAT: LOW";
  $("threatBadge").className   = "threat-badge low";
}

async function initDash() {
  $("tbUser").textContent    = CU.toUpperCase();
  $("uName").textContent     = CD;
  $("avatarIcon").textContent = CR === "admin" ? "⭐" : "👤";

  const roleEl = $("uRole");
  if (CR === "admin") {
    roleEl.textContent = "ADMINISTRATOR";
    roleEl.className   = "u-role admin";
    $("alertPanel").style.display = "block";
    $("usersPanel").style.display = "block";
    loadUsers();
  } else {
    roleEl.textContent = "EMPLOYEE";
    roleEl.className   = "u-role employee";
    $("alertPanel").style.display = "none";
    $("usersPanel").style.display = "none";
  }

  setView("files");
  loadCats();
  await refresh();
  liveTimer = setInterval(refresh, 5000);
}

document.querySelectorAll(".nav-item").forEach(el =>
  el.addEventListener("click", () => setView(el.dataset.v))
);

function setView(v) {
  ["files","activity","alerts","chat"].forEach(n => {
    const id = "v"+n.charAt(0).toUpperCase()+n.slice(1);
    $(id).style.display = (n === v) ? "block" : "none";
  });
  document.querySelectorAll(".nav-item").forEach(el => {
    el.classList.toggle("active", el.dataset.v === v);
  });
  if (v === "activity") loadFullLog();
  if (v === "alerts")   loadFullAlerts();
}

async function loadCats() {
  try {
    const cats = await API.categories();
    const grid = $("catGrid");
    grid.innerHTML = cats.map(c => {
      const cls  = c.critical ? "critical" : c.sensitive ? "sensitive" : "normal";
      const tag  = c.critical
        ? `<span class="cat-tag tag-c">🚨 HIGHLY SENSITIVE</span>`
        : c.sensitive
          ? `<span class="cat-tag tag-s">⚠ SENSITIVE</span>`
          : `<span class="cat-tag tag-n">STANDARD</span>`;
      return `<div class="cat-card ${cls}" onclick="openCat('${c.key}')">
        <span class="cat-icon">${c.icon}</span>
        <div class="cat-name">${c.name}</div>
        <div class="cat-count">${c.fileCount} files</div>
        ${tag}
      </div>`;
    }).join("");
  } catch(e) {
    $("catGrid").innerHTML = `<div style="color:var(--red);font-family:Share Tech Mono,monospace;font-size:11px;padding:12px;">⚠ ${e.message||"Load error"}</div>`;
  }
}

async function openCat(key) {
  try {
    const d = await API.openCat(key, CU);

    $("fbTitle").textContent = "📂 " + d.name.toUpperCase();
    $("fileList").innerHTML  = d.files.map(f => `
      <div class="file-row">
        <div class="file-info">
          <span class="file-ico">${f.icon}</span>
          <div>
            <div class="file-name">${f.name}</div>
            <div class="file-size">${f.size}</div>
          </div>
        </div>
        <button class="btn-dl" onclick="dlFile('${esc(f.name)}','${key}')">⬇ DOWNLOAD</button>
      </div>`).join("");

    $("fileBrowser").style.display = "block";
    $("fileBrowser").scrollIntoView({behavior:"smooth", block:"nearest"});

    if (d.alert) { setThreatHigh(); showOverlay(d.alert); }

    const sess = await API.session(CU).catch(()=>null);
    if (sess) { $("sAccess").textContent = sess.accessCount; setRisk(sess.riskScore); }
    await refresh();
  } catch(e) { console.error("openCat:", e); }
}

$("fbClose").onclick = () => $("fileBrowser").style.display = "none";

async function dlFile(filename, catKey) {
  try {
    const d = await API.download(CU, catKey, filename);
    const sess = await API.session(CU).catch(()=>null);
    if (sess) { $("sDl").textContent = sess.downloadCount; $("sc3").textContent = sess.downloadCount; setRisk(sess.riskScore); }
    if (d.alert) { setThreatHigh(); showOverlay(d.alert); }
    await refresh();
  } catch(e) { console.error("dlFile:", e); }
}

async function refresh() {
  try {
    const [ld, ad, st] = await Promise.all([
      API.logs(CR, CU, 20),
      API.alerts(CR, CU),
      API.stats(),
    ]);
    renderLiveFeed(ld.logs);
    renderAlertFeed(ad.alerts);
    $("sc1").textContent = st.totalEvents;
    $("sc2").textContent = st.totalAlerts;
    $("sc4").textContent = st.activeUsers;

    const sess = await API.session(CU).catch(()=>null);
    if (sess) {
      $("sAccess").textContent = sess.accessCount;
      $("sDl").textContent     = sess.downloadCount;
      $("sc3").textContent     = sess.downloadCount;
      setRisk(sess.riskScore);
    }
  } catch {}
}

function renderLiveFeed(logs) {
  $("liveFeed").innerHTML = (!logs || !logs.length)
    ? `<div class="no-data">NO EVENTS YET</div>`
    : logs.map(l=>`
        <div class="log-row">
          <span class="log-ts">${l.ts}</span>
          <div class="log-dot ${l.dotType}"></div>
          <div class="log-msg">${l.msg}</div>
        </div>`).join("");
}

function renderAlertFeed(alerts) {
  $("alertFeed").innerHTML = (!alerts || !alerts.length)
    ? `<div class="no-data">NO ALERTS DETECTED</div>`
    : alerts.slice(0,5).map(a=>`
        <div class="a-item">
          <div class="a-title">${a.title}</div>
          <div class="a-desc">${a.desc}</div>
          <div class="a-ts">${a.ts}</div>
        </div>`).join("");
}

async function loadFullLog() {
  if (CR !== "admin") {
    $("fullLog").style.display        = "none";
    $("actRestrict").style.display    = "block";
    return;
  }
  $("actRestrict").style.display = "none";
  $("fullLog").style.display     = "block";
  try {
    const d = await API.logs("admin", CU, 100);
    $("actCount").textContent = d.total + " EVENTS";
    $("fullLog").innerHTML = d.logs.length
      ? d.logs.map(l=>`
          <div class="log-row">
            <span class="log-ts">${l.ts}</span>
            <div class="log-dot ${l.dotType}"></div>
            <div class="log-msg">${l.msg}</div>
          </div>`).join("")
      : `<div class="no-data">NO EVENTS</div>`;
  } catch {}
}

async function loadFullAlerts() {
  if (CR !== "admin") {
    $("fullAlerts").style.display  = "none";
    $("alRestrict").style.display  = "block";
    return;
  }
  $("alRestrict").style.display  = "none";
  $("fullAlerts").style.display  = "flex";
  try {
    const d = await API.alerts("admin", CU);
    $("alCount").textContent = d.total + " ALERTS";
    $("fullAlerts").innerHTML = d.alerts.length
      ? d.alerts.map(a=>`
          <div class="full-alert-card">
            <div class="full-alert-title">${a.title}</div>
            <div class="full-alert-desc">${a.desc}</div>
            <div class="full-alert-ts">${a.ts}</div>
          </div>`).join("")
      : `<div class="restrict-box"><p>NO SECURITY ALERTS ON RECORD</p></div>`;
  } catch {}
}

async function loadUsers() {
  try {
    const users = await API.users();
    $("usersList").innerHTML = users.map(u=>`
      <div class="user-row2">
        <span class="ur2-name">${u.role==="admin"?"⭐ ":""}${u.username.toUpperCase()}</span>
        <span class="ur2-status ${u.online?"ur2-on":"ur2-off"}">${u.online?"● ONLINE":"OFFLINE"}</span>
      </div>`).join("");
  } catch {}
}

function setRisk(v) {
  v = Math.max(0, Math.min(100, v||0));
  $("riskFill").style.width  = v + "%";
  $("riskPct").textContent   = v + "%";
  let color, label;
  if      (v < 30) { color="var(--green)";  label="NOMINAL";   }
  else if (v < 60) { color="var(--yellow)"; label="ELEVATED";  }
  else if (v < 85) { color="var(--orange)"; label="HIGH RISK"; }
  else             { color="var(--red)";    label="CRITICAL";  }
  $("riskPct").style.color   = color;
  $("riskLbl").textContent   = label;
}

function setThreatHigh() {
  $("threatBadge").textContent = "THREAT: HIGH";
  $("threatBadge").className   = "threat-badge high";
}

function showOverlay(alert) {
  const ov = $("overlay");
  $("ovMsg").textContent = `Unauthorized access to sensitive data.\n${alert.desc}\n\nIncident logged and flagged.`;
  ov.style.display = "flex";
  let n = 5;
  $("ovCount").textContent = n;
  clearInterval(autoTimer);
  autoTimer = setInterval(async () => {
    n--;
    $("ovCount").textContent = n;
    if (n <= 0) {
      clearInterval(autoTimer);
      ov.style.display = "none";
      await doLogout();
    }
  }, 1000);
}

// ── removed: stray app.use(express.static(...)) — server-side call has no place in browser JS ──

$("chatSend").onclick                = sendChat;
$("chatIn").onkeydown = e => { if(e.key==="Enter") sendChat(); };

async function sendChat() {
  const inp = $("chatIn");
  const q   = inp.value.trim();
  if (!q) return;
  const msgs = $("chatMsgs");
  msgs.innerHTML += `<div class="msg user">${esc(q)}</div>`;
  inp.value = "";
  msgs.scrollTop = msgs.scrollHeight;
  try {
    const d = await API.chat(q, CU, CR);
    setTimeout(() => {
      msgs.innerHTML += `<div class="msg bot">${d.reply}</div>`;
      msgs.scrollTop  = msgs.scrollHeight;
    }, 360);
  } catch {
    setTimeout(() => {
      msgs.innerHTML += `<div class="msg bot">⚠ Server unreachable.</div>`;
      msgs.scrollTop  = msgs.scrollHeight;
    }, 360);
  }
}
