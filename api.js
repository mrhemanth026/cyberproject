const BASE = "";  

const API = {
  login:        (u,p)         => post("/api/login",       {username:u, password:p}),
  logout:       (u)           => post("/api/logout",      {username:u}),
  categories:   ()            => get("/api/categories"),
  openCat:      (key,u)       => get(`/api/categories/${key}?username=${u}`),
  download:     (u,catKey,fn) => post("/api/download",    {username:u, catKey, filename:fn}),
  logs:         (role,u,lim)  => get(`/api/logs?role=${role}&username=${u}&limit=${lim||50}`),
  alerts:       (role,u)      => get(`/api/alerts?role=${role}&username=${u}`),
  session:      (u)           => get(`/api/session/${u}`),
  stats:        ()            => get("/api/stats"),
  users:        ()            => get("/api/users"),
  chat:         (msg,u,role)  => post("/api/chat",        {message:msg, username:u, role}),
};

async function get(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(r.status);
  return r.json();
}

async function post(url, body) {
  const r = await fetch(url, {
    method: "POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify(body),
  });
  if (!r.ok) {
    const err = await r.json().catch(()=>({}));
    throw Object.assign(new Error(r.status), err);
  }
  return r.json();
}
