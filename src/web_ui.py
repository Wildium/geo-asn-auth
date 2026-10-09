"""
Thin web admin UI (issue #5) — a single self-contained page that talks
strictly to the token-authed admin API. No separate config-write path.

Serves at /admin/ui. The page prompts for the ADMIN_TOKEN once, stores it in
sessionStorage, and uses it as a Bearer token for all admin API calls.
"""

from flask import Response

UI_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Geo-ASN Auth — Admin</title>
<style>
  :root { color-scheme: dark; }
  body { font-family: system-ui, sans-serif; background:#101418; color:#e6e6e6; margin:0; }
  header { padding:1rem 1.5rem; background:#161b22; border-bottom:1px solid #2b3138;
           display:flex; align-items:center; gap:1rem; flex-wrap:wrap; }
  h1 { font-size:1.1rem; margin:0; }
  main { padding:1.5rem; max-width:1100px; margin:0 auto; }
  .grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(320px,1fr)); gap:1rem; }
  .card { background:#161b22; border:1px solid #2b3138; border-radius:8px; padding:1rem; }
  .card h2 { font-size:.95rem; margin:0 0 .5rem; color:#8ab4f8; }
  .mode { font-size:.8rem; color:#9aa0a6; margin-bottom:.5rem; }
  ul { list-style:none; padding:0; margin:.25rem 0 .75rem; }
  li { display:flex; justify-content:space-between; align-items:center;
       padding:.25rem .4rem; border-radius:4px; font-size:.85rem; }
  li:hover { background:#1d232b; }
  button { background:#2b3138; color:#e6e6e6; border:0; border-radius:4px;
           padding:.3rem .6rem; cursor:pointer; font-size:.8rem; }
  button:hover { background:#3a424c; }
  button.add { background:#21532a; }
  input[type=text], input[type=password] { background:#0d1117; color:#e6e6e6;
       border:1px solid #2b3138; border-radius:4px; padding:.35rem .5rem; font-size:.85rem; width:100%; box-sizing:border-box; }
  .row { display:flex; gap:.5rem; margin-top:.4rem; }
  .status { font-size:.8rem; padding:.4rem .6rem; border-radius:4px; margin-bottom:1rem; display:none; }
  .status.ok { background:#1c3324; display:block; }
  .status.err { background:#3a1d1d; display:block; }
  .warn { background:#33291a; border:1px solid #5c4a1f; border-radius:6px;
          padding:.5rem .75rem; font-size:.8rem; margin-bottom:1rem; }
  .pill { font-size:.7rem; background:#2b3138; border-radius:10px; padding:.1rem .5rem; }
  #tokenbar { margin-left:auto; display:flex; gap:.5rem; align-items:center; }
  #tokenbar input { width:16rem; }
</style>
</head>
<body>
<header>
  <h1>Geo-ASN Auth Admin</h1>
  <span class="pill" id="reloadinfo">—</span>
  <div id="tokenbar">
    <input type="password" id="token" placeholder="ADMIN_TOKEN">
    <button onclick="saveToken()">Save token</button>
    <button onclick="loadAll()">Refresh</button>
  </div>
</header>
<main>
  <div id="status" class="status"></div>
  <div id="warns"></div>
  <div class="grid" id="grid"></div>
</main>
<script>
const SECTIONS = [
  {key:'ip-whitelist',        title:'IP Whitelist',        modeKey:'ip_mode'},
  {key:'ip-blacklist',        title:'IP Blacklist',        modeKey:'ip_mode'},
  {key:'asn-whitelist',       title:'ASN Whitelist',       modeKey:'asn_mode'},
  {key:'asn-blacklist',       title:'ASN Blacklist',       modeKey:'asn_mode'},
  {key:'country-whitelist',   title:'Country Whitelist',   modeKey:'country_mode'},
  {key:'country-blacklist',   title:'Country Blacklist',   modeKey:'country_mode'},
  {key:'user-agent-whitelist',title:'User-Agent Whitelist',modeKey:'user_agent_mode'},
  {key:'user-agent-blacklist',title:'User-Agent Blacklist',modeKey:'user_agent_mode'},
];
let token = sessio…tem('gaa_token') || '';
document.getElementById('token').value = token;

function saveToken(){ token = document.getElementById('token').value.trim();
  sessionStorage.setItem('gaa_token', token); loadAll(); }
function msg(t, ok){ const el=document.getElementById('status');
  el.textContent=t; el.className='status '+(ok?'ok':'err');
  setTimeout(()=>{el.className='status';}, 4000); }

async function api(path, opts={}){
  opts.headers = Object.assign({'Authorization':'Bearer '+token,
                                'Content-Type':'application/json'}, opts.headers||{});
  const r = await fetch('/admin/'+path, opts);
  const body = await r.json().catch(()=>({}));
  if(!r.ok) throw new Error(body.error || ('HTTP '+r.status));
  return body;
}

function entryLabel(e){
  if(e && typeof e==='object' && 'asn' in e)
    return 'AS'+e.asn+(e.user_agents?(' (UA: '+e.user_agents.join(', ')+')'):'');
  return String(e);
}
function entryValue(e){ return (e && typeof e==='object' && 'asn' in e)? e.asn : e; }

async function loadAll(){
  if(!token){ msg('Enter your admin token first.', false); return; }
  try{
    const cfg = await api('config');
    document.getElementById('reloadinfo').textContent =
      'reloads: '+(cfg.reload.reload_count||0)+' · last: '+(cfg.reload.last_reload||'—');
    const warns = document.getElementById('warns');
    warns.innerHTML = (cfg.lint_warnings||[]).map(w=>'<div class="warn">⚠ '+w+'</div>').join('');
    const modes = {}; // modes come from /health/detail
    let detail = {};
    try{ detail = await (await fetch('/health/detail',{headers:{'Authorization':'Bearer '+token}})).json(); }catch(e){}
    const grid = document.getElementById('grid');
    grid.innerHTML = '';
    for(const s of SECTIONS){
      const data = await api(s.key);
      const card = document.createElement('div'); card.className='card';
      const mode = (detail.config||{})[s.modeKey] || '';
      card.innerHTML = '<h2>'+s.title+'</h2><div class="mode">mode: '+(mode||'?')+' · '+data.entries.length+' entries</div>';
      const ul = document.createElement('ul');
      for(const e of data.entries){
        const li = document.createElement('li');
        li.innerHTML = '<span>'+entryLabel(e)+'</span>';
        const del = document.createElement('button'); del.textContent='remove';
        del.onclick = ()=>edit(s.key, [], [entryValue(e)]);
        li.appendChild(del); ul.appendChild(li);
      }
      card.appendChild(ul);
      const row = document.createElement('div'); row.className='row';
      const inp = document.createElement('input'); inp.type='text';
      inp.placeholder = s.key.startsWith('asn')? 'ASN number' :
                        s.key.startsWith('ip')? 'IP, CIDR, or hostname' :
                        s.key.startsWith('country')? 'US' : 'user-agent';
      const add = document.createElement('button'); add.textContent='add'; add.className='add';
      add.onclick = ()=>{ if(inp.value.trim()) edit(s.key,[inp.value.trim()],[]); };
      row.appendChild(inp); row.appendChild(add); card.appendChild(row);
      grid.appendChild(card);
    }
  }catch(e){ msg('Error: '+e.message, false); }
}

async function edit(section, add, remove){
  try{
    await api(section, {method:'PUT', body: JSON.stringify({add, remove})});
    msg('Saved — hot-reloaded.', true); loadAll();
  }catch(e){ msg('Save failed: '+e.message, false); }
}
loadAll();
</script>
</body>
</html>
"""


def register_ui_routes(app):
    @app.route('/admin/ui')
    def admin_ui():
        return Response(UI_HTML, mimetype='text/html')
