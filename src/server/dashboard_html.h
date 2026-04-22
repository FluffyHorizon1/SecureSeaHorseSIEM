#ifndef DASHBOARD_HTML_H
#define DASHBOARD_HTML_H

// =============================================================================
// SecureSeaHorse SIEM -- Phase 7: Embedded Web Dashboard
// =============================================================================
// Single-page HTML/CSS/JS dashboard served at GET /
// Features: device grid, threat feed, IoC matches, FIM events, live stats
// Auto-refreshes every 15 seconds.
// =============================================================================

#include <string>

inline const std::string& get_dashboard_html() {
    static const std::string html = R"RAWHTML(
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SecureSeaHorse SIEM - Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0d1117;color:#c9d1d9;min-height:100vh}
.topbar{background:#161b22;border-bottom:1px solid #30363d;padding:12px 24px;display:flex;align-items:center;justify-content:space-between}
.topbar h1{font-size:18px;color:#58a6ff;font-weight:600}
.topbar h1 span{color:#8b949e;font-weight:400;font-size:13px;margin-left:8px}
.topbar .status{font-size:12px;color:#8b949e}
.topbar .status .dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:4px;vertical-align:middle}
.dot.green{background:#3fb950}.dot.red{background:#f85149}.dot.yellow{background:#d29922}
.container{max-width:1400px;margin:0 auto;padding:20px}
.stats-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:20px}
.stat-card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px}
.stat-card .label{font-size:11px;color:#8b949e;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:4px}
.stat-card .value{font-size:28px;font-weight:700;color:#e6edf3}
.stat-card .sub{font-size:11px;color:#8b949e;margin-top:2px}
.stat-card.critical .value{color:#f85149}
.stat-card.warn .value{color:#d29922}
.stat-card.ok .value{color:#3fb950}
.stat-card.info .value{color:#58a6ff}
.panels{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:20px}
@media(max-width:900px){.panels{grid-template-columns:1fr}}
.panel{background:#161b22;border:1px solid #30363d;border-radius:8px;overflow:hidden}
.panel-header{padding:12px 16px;border-bottom:1px solid #30363d;display:flex;align-items:center;justify-content:space-between}
.panel-header h2{font-size:14px;color:#e6edf3;font-weight:600}
.panel-header .badge{font-size:11px;background:#30363d;color:#8b949e;padding:2px 8px;border-radius:10px}
.panel-body{padding:0;max-height:360px;overflow-y:auto}
table{width:100%;border-collapse:collapse;font-size:12px}
th{background:#0d1117;color:#8b949e;font-weight:600;text-align:left;padding:8px 12px;position:sticky;top:0;text-transform:uppercase;font-size:10px;letter-spacing:0.5px}
td{padding:6px 12px;border-top:1px solid #21262d;color:#c9d1d9;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:200px}
tr:hover td{background:#1c2129}
.sev-critical{color:#f85149;font-weight:700}
.sev-high{color:#d29922;font-weight:600}
.sev-medium{color:#58a6ff}
.sev-low{color:#8b949e}
.change-added{color:#3fb950}.change-modified{color:#d29922}.change-deleted{color:#f85149}
.mitre{font-family:monospace;font-size:11px;color:#bc8cff}
.tag{display:inline-block;font-size:10px;background:#21262d;color:#8b949e;padding:1px 6px;border-radius:3px;margin-right:3px}
.empty{text-align:center;padding:40px;color:#484f58;font-size:13px}
.full-width{grid-column:1/-1}
.login-overlay{position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(13,17,23,0.95);display:flex;align-items:center;justify-content:center;z-index:1000}
.login-box{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:32px;width:340px}
.login-box h2{color:#e6edf3;margin-bottom:16px;font-size:18px}
.login-box input{width:100%;padding:10px 12px;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#e6edf3;font-size:14px;margin-bottom:12px;outline:none}
.login-box input:focus{border-color:#58a6ff}
.login-box button{width:100%;padding:10px;background:#238636;border:none;border-radius:6px;color:#fff;font-size:14px;cursor:pointer;font-weight:600}
.login-box button:hover{background:#2ea043}
.login-box .error{color:#f85149;font-size:12px;margin-top:8px;display:none}
#app{display:none}
</style>
</head>
<body>

<div id="login" class="login-overlay">
<div class="login-box">
<h2>SecureSeaHorse SIEM</h2>
<input type="password" id="token-input" placeholder="API Token" autofocus>
<button onclick="doLogin()">Sign In</button>
<div class="error" id="login-error">Invalid token</div>
</div>
</div>

<div id="app">
<div class="topbar">
<h1>SecureSeaHorse <span>SIEM Dashboard v2.0.0</span></h1>
<div class="status">
<span class="dot green" id="conn-dot"></span>
<span id="conn-text">Connected</span>
<span style="margin-left:16px;color:#484f58" id="refresh-text"></span>
</div>
</div>

<div class="container">
<div class="stats-row" id="stats-row"></div>

<div class="panels">
<div class="panel">
<div class="panel-header"><h2>Recent Threats</h2><span class="badge" id="threat-count">0</span></div>
<div class="panel-body"><table><thead><tr><th>Time</th><th>Device</th><th>Category</th><th>Severity</th><th>MITRE</th><th>Description</th></tr></thead><tbody id="threat-body"></tbody></table></div>
</div>
<div class="panel">
<div class="panel-header"><h2>IoC Matches</h2><span class="badge" id="ioc-count">0</span></div>
<div class="panel-body"><table><thead><tr><th>Time</th><th>Device</th><th>Type</th><th>Value</th><th>Severity</th><th>Feed</th></tr></thead><tbody id="ioc-body"></tbody></table></div>
</div>
<div class="panel">
<div class="panel-header"><h2>FIM Events</h2><span class="badge" id="fim-count">0</span></div>
<div class="panel-body"><table><thead><tr><th>Time</th><th>Device</th><th>Change</th><th>File Path</th><th>Severity</th><th>MITRE</th></tr></thead><tbody id="fim-body"></tbody></table></div>
</div>
<div class="panel">
<div class="panel-header"><h2>Security Events</h2><span class="badge" id="event-count">0</span></div>
<div class="panel-body"><table><thead><tr><th>Time</th><th>Device</th><th>Rule</th><th>Severity</th><th>Match</th></tr></thead><tbody id="event-body"></tbody></table></div>
</div>
</div>
</div>
</div>

<script>
let TOKEN='';
const API=window.location.origin;

function doLogin(){
  TOKEN=document.getElementById('token-input').value;
  fetch(API+'/api/stats',{headers:{'Authorization':'Bearer '+TOKEN}})
  .then(r=>{if(!r.ok)throw new Error();return r.json()})
  .then(()=>{
    document.getElementById('login').style.display='none';
    document.getElementById('app').style.display='block';
    refresh();
    setInterval(refresh,15000);
  })
  .catch(()=>{
    document.getElementById('login-error').style.display='block';
  });
}

document.getElementById('token-input').addEventListener('keypress',e=>{if(e.key==='Enter')doLogin()});

function api(path){
  return fetch(API+path,{headers:{'Authorization':'Bearer '+TOKEN}}).then(r=>r.json());
}

function sevClass(s){return 'sev-'+(s||'low').toLowerCase()}
function changeClass(c){return 'change-'+(c||'added').toLowerCase()}
function fmtTime(ms){if(!ms)return'-';const d=new Date(Number(ms));return d.toLocaleTimeString()}

async function refresh(){
  try{
    const[stats,threats,iocs,fims,events]=await Promise.all([
      api('/api/stats'),
      api('/api/threats?limit=50'),
      api('/api/ioc?limit=50'),
      api('/api/fim?limit=50'),
      api('/api/events?limit=50')
    ]);

    // Stats cards (no user input -- stats.* are all numeric)
    const sr=document.getElementById('stats-row');
    sr.innerHTML=`
      <div class="stat-card info"><div class="label">Fleet Online</div><div class="value">${stats.fleet_online||stats.devices_online||0}</div><div class="sub">of ${stats.fleet_total||0} devices</div></div>
      <div class="stat-card ${(stats.total_threats||0)>0?'critical':'ok'}"><div class="label">Threats</div><div class="value">${stats.total_threats||0}</div><div class="sub">detected</div></div>
      <div class="stat-card ${(stats.total_ioc_hits||0)>0?'warn':'ok'}"><div class="label">IoC Hits</div><div class="value">${stats.total_ioc_hits||0}</div><div class="sub">feed matches</div></div>
      <div class="stat-card ${(stats.total_fim_changes||0)>0?'warn':'ok'}"><div class="label">FIM Changes</div><div class="value">${stats.total_fim_changes||0}</div><div class="sub">file integrity</div></div>
      <div class="stat-card ${(stats.ir_blocked_ips||0)>0?'warn':'ok'}"><div class="label">Blocked IPs</div><div class="value">${stats.ir_blocked_ips||0}</div><div class="sub">${stats.ir_quarantined||0} quarantined</div></div>
      <div class="stat-card ${(stats.net_findings||0)>0?'warn':'ok'}"><div class="label">Net Findings</div><div class="value">${stats.net_findings||0}</div><div class="sub">deep inspection</div></div>
      <div class="stat-card info"><div class="label">IR Actions</div><div class="value">${stats.ir_actions_executed||0}</div><div class="sub">${stats.ir_incidents||0} incidents</div></div>
      <div class="stat-card info"><div class="label">Uptime</div><div class="value">${stats.uptime_hours||0}h</div><div class="sub">${stats.api_requests||0} API reqs</div></div>
    `;

    // XSS DEFENSE: Every field below comes from the database and may contain
    // attacker-controlled content (log lines, file paths, IoC values, etc.).
    // A compromised endpoint could send <script> tags in a raw log, which
    // would land in matched_text and execute in the admin's browser.
    // esc() strictly escapes HTML-special characters before interpolation.
    const esc=s=>String(s==null?'':s).replace(/[&<>"'`=\/]/g, c=>({
      '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',
      "'":'&#39;','`':'&#96;','=':'&#61;','/':'&#47;'
    })[c]);

    // Threats table
    const tb=document.getElementById('threat-body');
    document.getElementById('threat-count').textContent=threats.length||0;
    if(threats.length){
      tb.innerHTML=threats.map(t=>`<tr><td>${esc(fmtTime(t.timestamp_ms))}</td><td>${esc(t.device_id)}</td><td>${esc(t.category)}</td><td class="${sevClass(t.severity)}">${esc(t.severity)}</td><td class="mitre">${esc(t.mitre_id)}</td><td title="${esc(t.description)}">${esc((t.description||'').substring(0,60))}</td></tr>`).join('');
    } else tb.innerHTML='<tr><td colspan="6" class="empty">No threats detected</td></tr>';

    // IoC table
    const ib=document.getElementById('ioc-body');
    document.getElementById('ioc-count').textContent=iocs.length||0;
    if(iocs.length){
      ib.innerHTML=iocs.map(i=>`<tr><td>${esc(fmtTime(i.timestamp_ms))}</td><td>${esc(i.device_id)}</td><td><span class="tag">${esc(i.ioc_type)}</span></td><td title="${esc(i.ioc_value)}">${esc((i.ioc_value||'').substring(0,40))}</td><td class="${sevClass(i.severity)}">${esc(i.severity)}</td><td>${esc(i.feed_source)}</td></tr>`).join('');
    } else ib.innerHTML='<tr><td colspan="6" class="empty">No IoC matches</td></tr>';

    // FIM table
    const fb=document.getElementById('fim-body');
    document.getElementById('fim-count').textContent=fims.length||0;
    if(fims.length){
      fb.innerHTML=fims.map(f=>`<tr><td>${esc(fmtTime(f.timestamp_ms))}</td><td>${esc(f.device_id)}</td><td class="${changeClass(f.change_type)}">${esc(f.change_type)}</td><td title="${esc(f.file_path)}">${esc((f.file_path||'').substring(0,50))}</td><td class="${sevClass(f.severity)}">${esc(f.severity)}</td><td class="mitre">${esc(f.mitre_id)}</td></tr>`).join('');
    } else fb.innerHTML='<tr><td colspan="6" class="empty">No FIM events</td></tr>';

    // Events table
    const eb=document.getElementById('event-body');
    document.getElementById('event-count').textContent=events.length||0;
    if(events.length){
      eb.innerHTML=events.map(e=>`<tr><td>${esc(fmtTime(e.timestamp_ms))}</td><td>${esc(e.device_id)}</td><td>${esc(e.rule_name)}</td><td class="${sevClass(e.severity)}">${esc(e.severity)}</td><td title="${esc(e.matched_text)}">${esc((e.matched_text||'').substring(0,50))}</td></tr>`).join('');
    } else eb.innerHTML='<tr><td colspan="5" class="empty">No security events</td></tr>';

    document.getElementById('conn-dot').className='dot green';
    document.getElementById('conn-text').textContent='Connected';
    document.getElementById('refresh-text').textContent='Updated '+new Date().toLocaleTimeString();
  }catch(err){
    document.getElementById('conn-dot').className='dot red';
    document.getElementById('conn-text').textContent='Connection lost';
  }
}
</script>
</body>
</html>
)RAWHTML";
    return html;
}

#endif
