const $ = (id) => document.getElementById(id);
let hashRecord = null;
let mfaToken = null;

async function api(path, method = "GET", payload = undefined) {
  const options = { method, headers: {} };
  if (payload !== undefined) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(payload);
  }
  const response = await fetch(path, options);
  const data = await response.json().catch(() => ({ error: "The server returned an unreadable response." }));
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}
function show(id, value) {
  const target = $(id);
  target.textContent = typeof value === "string" ? value : JSON.stringify(value, null, 2);
}
function showError(id, error) { show(id, error.message || String(error)); }
document.querySelectorAll("[data-tab]").forEach(button => button.addEventListener("click", () => {
  document.querySelectorAll(".nav-item").forEach(x => x.classList.toggle("active", x === button));
  document.querySelectorAll(".panel").forEach(x => x.classList.toggle("active", x.id === "panel-" + button.dataset.tab));
}));
$("analyze-url").addEventListener("click", async () => {
  try {
    const d = await api("/api/phishing/analyze", "POST", {url: $("url-input").value});
    show("url-result", `Risk indicator: ${d.risk}\nHostname: ${d.hostname || "not parsed"}\n\n• ${d.signals.join("\n• ")}`);
  } catch(e) { showError("url-result", e); }
});
async function loadNetwork() {
  try {
    const [n,t] = await Promise.all([api("/api/network/inventory"), api("/api/network/traffic")]);
    $("network-result").innerHTML = "";
    n.devices.forEach(device => {
      const card = document.createElement("div"); card.className = "device";
      const title = document.createElement("strong"); title.textContent = device.name;
      const address = document.createElement("code"); address.textContent = device.address;
      const role = document.createElement("small"); role.textContent = device.role + " · " + device.services.join(", ");
      card.append(title,address,document.createElement("br"),role); $("network-result").append(card);
    });
    show("traffic-result", `${t.scope}\nRecords: ${t.records.length}\nProtocol counts: ${JSON.stringify(t.protocol_counts)}\n\n${t.records.map(x => x.time+"  "+x.source+" → "+x.destination+"  "+x.protocol).join("\n")}`);
  } catch(e) { showError("traffic-result", e); }
}
$("load-network").addEventListener("click", loadNetwork);
$("db-search").addEventListener("click", async () => {
  try { const d = await api("/api/web/search","POST",{query:$("db-query").value}); show("db-result", `Query method: ${d.query_method}\n${d.lesson}\n\n${JSON.stringify(d.results,null,2)}`); }
  catch(e) { showError("db-result",e); }
});
async function session(action) {
  try { const d=await api("/api/web/session","POST",{action}); show("session-result",d.status+": "+d.explanation); }
  catch(e) { showError("session-result",e); }
}
$("session-create").addEventListener("click",()=>session("create"));
$("session-revoke").addEventListener("click",()=>session("revoke"));
$("password-analyze").addEventListener("click",async()=>{
  try { const d=await api("/api/password/analyze","POST",{password:$("password-input").value}); show("password-result",d); }
  catch(e){showError("password-result",e);}
});
$("make-hash").addEventListener("click",async()=>{
  try { hashRecord=await api("/api/password/hash","POST",{password:$("password-input").value}); show("hash-result",hashRecord); $("verify-hash").disabled=false; }
  catch(e){showError("hash-result",e);}
});
$("verify-hash").addEventListener("click",async()=>{
  if(!hashRecord)return;
  try { const d=await api("/api/password/verify","POST",{password:$("verify-input").value,salt:hashRecord.salt,digest:hashRecord.digest,iterations:hashRecord.iterations}); show("verify-result",d.verified?"Sample verified successfully.":"Sample did not match."); }
  catch(e){showError("verify-result",e);}
});
document.querySelectorAll("[data-benchmark]").forEach(button=>button.addEventListener("click",async()=>{
  try {const d=await api("/api/password/benchmark","POST",{iterations:Number(button.dataset.benchmark)});show("benchmark-result",d);}
  catch(e){showError("benchmark-result",e);}
}));
$("mfa-start").addEventListener("click",async()=>{
  try {const d=await api("/api/mfa/start","POST",{});mfaToken=d.token;show("mfa-code",`TRAINING CODE: ${d.demo_code}\n${d.notice}`);}
  catch(e){showError("mfa-code",e);}
});
$("mfa-verify").addEventListener("click",async()=>{
  try {const d=await api("/api/mfa/verify","POST",{code:$("mfa-input").value});show("mfa-result",d.message);}
  catch(e){showError("mfa-result",e);}
});
async function loadEvents() {
  try {
    const d=await api("/api/monitor/events");
    $("monitor-result").innerHTML="";
    d.events.forEach(event=>{
      const row=document.createElement("div");row.className="event";
      const time=document.createElement("time");time.textContent=event.timestamp;
      const source=document.createElement("span");source.className="source";source.textContent=event.source;
      const detail=document.createElement("span");detail.textContent=event.type.toUpperCase()+" · "+event.detail;
      detail.className="severity-"+event.severity;
      row.append(time,source,detail);$("monitor-result").append(row);
    });
  } catch(e) { showError("monitor-result",e); }
}
$("simulate-failure").addEventListener("click",async()=>{
  try {const d=await api("/api/monitor/simulate","POST",{});show("monitor-result",d.alert_triggered?"Detection alert triggered. Refreshing event timeline…":"Synthetic failed login recorded.");await loadEvents();}
  catch(e){showError("monitor-result",e);}
});
$("refresh-events").addEventListener("click",loadEvents);
loadNetwork();
loadEvents();
