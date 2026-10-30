#!/usr/bin/env python3
"""NetGraph: граф сетевой активности Mac в стиле Obsidian.
Запуск:  sudo python3 netgraph.py [--geo] [--menubar] [--install-agent]
(без sudo видны только ваши процессы)
Открыть: http://127.0.0.1:8765
Зависимости: только стандартная библиотека Python 3 (macOS: lsof, nettop).
"""
import subprocess, re, json, time, threading, socket, webbrowser, collections, ipaddress
import sqlite3, os, sys, argparse, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from concurrent.futures import ThreadPoolExecutor

PORT = 8765
LSOF = re.compile(r'^(\S+)\s+(\d+)\s+(\S+)\s+\S+\s+(IPv[46])\s+\S+\s+\S+\s+(TCP|UDP)\s+(.*)$')
lock = threading.Lock()
state = {"conns": [], "listen": [], "rates": {}}
events = collections.deque(maxlen=300)
dns = {}
pool = ThreadPoolExecutor(8)
ARGS = argparse.Namespace(geo=False, port=PORT)
alerts = collections.deque(maxlen=50)
geo, me_geo = {}, {}
os.makedirs(os.path.expanduser("~/.netgraph"), exist_ok=True)
DBL = threading.Lock()
D = sqlite3.connect(os.path.expanduser("~/.netgraph/history.db"), check_same_thread=False)
D.executescript("""CREATE TABLE IF NOT EXISTS pairs(proc TEXT,remote TEXT,first REAL,last REAL,n INT,PRIMARY KEY(proc,remote));
CREATE TABLE IF NOT EXISTS log(t REAL,s TEXT,proc TEXT,remote TEXT,port TEXT);
CREATE INDEX IF NOT EXISTS lt ON log(t);""")
D.execute("DELETE FROM log WHERE t<?", (time.time() - 14 * 86400,))
D.commit()
FRESH = D.execute("SELECT COUNT(*) FROM pairs").fetchone()[0] == 0
START = time.time()


def _resolve(ip):
    try:
        dns[ip] = socket.gethostbyaddr(ip)[0]
    except Exception:
        dns[ip] = ""


def host_of(ip):
    if ip not in dns:
        dns[ip] = None
        pool.submit(_resolve, ip)
    return dns.get(ip) or ""


def kind_of(ip):
    try:
        a = ipaddress.ip_address(ip.split('%')[0])
    except ValueError:
        return "wan"
    if a.is_loopback:
        return "local"
    if a.is_private or a.is_link_local:
        return "lan"
    return "wan"


def split_addr(s):
    s = s.strip()
    if s.startswith('['):
        h, _, p = s[1:].partition(']:')
        return h, p
    h, _, p = s.rpartition(':')
    return h, p


def collect():
    out = subprocess.run(["lsof", "-i", "-n", "-P"], capture_output=True, text=True, timeout=25).stdout
    conns, listen = [], []
    for line in out.splitlines()[1:]:
        m = LSOF.match(line)
        if not m:
            continue
        cmd, pid, _user, _fam, proto, rest = m.groups()
        cmd = cmd.replace("\\x20", " ")
        st = ""
        mm = re.search(r'\((\w+)\)\s*$', rest)
        if mm:
            st, rest = mm.group(1), rest[:mm.start()].strip()
        if "->" in rest:
            l, r = rest.split("->", 1)
            _lh, lp = split_addr(l)
            rh, rp = split_addr(r)
            conns.append(dict(proc=cmd, pid=int(pid), proto=proto, lport=lp, rip=rh, rport=rp, state=st or "UDP"))
        else:
            _lh, lp = split_addr(rest)
            listen.append(dict(proc=cmd, pid=int(pid), proto=proto, port=lp))
    return conns, listen


def poll_bytes():
    try:
        out = subprocess.run(["nettop", "-P", "-L", "1", "-x", "-J", "bytes_in,bytes_out"],
                             capture_output=True, text=True, timeout=20).stdout
    except Exception:
        return {}
    cur, hi, ho = {}, None, None
    for ln in out.splitlines():
        cells = ln.split(',')
        if 'bytes_in' in cells:
            hi, ho = cells.index('bytes_in'), cells.index('bytes_out')
            continue
        if hi is None or len(cells) <= max(hi, ho):
            continue
        pid = None
        for c in cells[:3]:
            if re.match(r'^\d+:\d+', c):
                continue
            m = re.match(r'^.+\.(\d+)$', c)
            if m:
                pid = int(m.group(1))
                break
        if pid is None:
            continue
        try:
            cur[pid] = (int(cells[hi]), int(cells[ho]))
        except ValueError:
            pass
    return cur


def label_of(ip):
    h = dns.get(ip)
    if h is None:
        host_of(ip)
        return None
    h = h or ip
    p = h.split('.')
    return '.'.join(p[-2:]) if h != ip and len(p) > 2 else h


def add_event(sign, c):
    r = host_of(c["rip"]) or c["rip"]
    events.appendleft(dict(t=time.strftime("%H:%M:%S"), s=sign, proc=c["proc"],
                           remote=r, port=c["rport"], proto=c["proto"]))
    with DBL:
        D.execute("INSERT INTO log VALUES(?,?,?,?,?)", (time.time(), sign, c["proc"], r, c["rport"]))
        D.commit()


def safe(s):
    return re.sub(r'[^\w .:\-]', '', s)


def check_pairs(conns):
    """Новая пара (процесс, домен) = тревога. Первые 10 минут на чистой базе идёт обучение."""
    now, new = time.time(), []
    with DBL:
        for c in conns:
            if kind_of(c["rip"]) != "wan":
                continue
            lab = label_of(c["rip"])
            if lab is None:
                continue
            row = D.execute("SELECT 1 FROM pairs WHERE proc=? AND remote=?", (c["proc"], lab)).fetchone()
            if row:
                D.execute("UPDATE pairs SET last=?,n=n+1 WHERE proc=? AND remote=?", (now, c["proc"], lab))
            else:
                D.execute("INSERT INTO pairs VALUES(?,?,?,?,1)", (c["proc"], lab, now, now))
                if not (FRESH and now - START < 600):
                    new.append((c["proc"], lab, c["rip"]))
        D.commit()
    for proc, lab, ip in new:
        alerts.appendleft(dict(t=time.strftime("%H:%M:%S"), proc=proc, remote=lab, ip=ip))
        subprocess.Popen(["osascript", "-e",
                          f'display notification "{safe(lab)}" with title "NetGraph: новое соединение" subtitle "{safe(proc)}"'])


def geo_loop():
    """Геолокация через ip-api.com (отправляет внешние IP ваших соединений этому сервису)."""
    F = "status,country,city,lat,lon,org,query"

    def post(url, body=None):
        req = urllib.request.Request(url, data=json.dumps(body).encode() if body else None,
                                     headers={"Content-Type": "application/json"})
        return json.load(urllib.request.urlopen(req, timeout=10))
    while True:
        try:
            if not me_geo:
                me_geo.update(post("http://ip-api.com/json/?fields=" + F))
            with lock:
                ips = {c["rip"] for c in state["conns"] if kind_of(c["rip"]) == "wan"}
            todo = [i for i in ips if i not in geo][:100]
            if todo:
                for r in post("http://ip-api.com/batch?fields=" + F, todo):
                    geo[r.get("query")] = r if r.get("status") == "success" else {}
        except Exception as e:
            print("geo error:", e)
        time.sleep(4)


def loop():
    prev, pb, pt = None, {}, time.time()
    while True:
        try:
            conns, listen = collect()
            now = time.time()
            b = poll_bytes()
            dt = max(now - pt, 0.1)
            rates = {p: [max(0, (v[0] - pb[p][0]) / dt), max(0, (v[1] - pb[p][1]) / dt)]
                     for p, v in b.items() if p in pb}
            pb, pt = b, now
            keys = {(c["proc"], c["rip"], c["rport"], c["lport"]): c for c in conns}
            if prev is not None:
                for k in keys.keys() - prev.keys():
                    add_event("+", keys[k])
                for k in prev.keys() - keys.keys():
                    add_event("-", prev[k])
            prev = keys
            with lock:
                state.update(conns=conns, listen=listen, rates=rates)
            check_pairs(conns)
        except Exception as e:
            print("collect error:", e)
        time.sleep(1.5)


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path.startswith("/history"):
            h = float((re.search(r'h=([\d.]+)', self.path) or [0, 24])[1])
            since = time.time() - h * 3600
            with DBL:
                top = D.execute("SELECT proc,remote,COUNT(*) FROM log WHERE s='+' AND t>? GROUP BY proc,remote ORDER BY 3 DESC LIMIT 25", (since,)).fetchall()
                new = D.execute("SELECT proc,remote,first FROM pairs WHERE first>? ORDER BY first DESC LIMIT 25", (since,)).fetchall()
            body, ctype = json.dumps(dict(top=top, new=new)).encode(), "application/json"
        elif self.path.startswith("/data"):
            with lock:
                conns = [dict(c, host=host_of(c["rip"]), kind=kind_of(c["rip"])) for c in state["conns"]]
                body = json.dumps(dict(conns=conns, listen=state["listen"], rates=state["rates"],
                                       events=list(events)[:120], alerts=list(alerts)[:15],
                                       geo={c["rip"]: geo.get(c["rip"], {}) for c in conns}, me=me_geo, geo_on=ARGS.geo)).encode()
            ctype = "application/json"
        else:
            body, ctype = PAGE.encode(), "text/html; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


PAGE = r"""<!doctype html><html lang="ru"><meta charset="utf-8"><title>NetGraph</title>
<style>
html,body{margin:0;height:100%;background:#1c1c1e;color:#d8d8dc;font:13px -apple-system,system-ui,sans-serif}
#app{display:flex;height:100%}
svg{flex:1;min-width:0;cursor:grab}
aside{width:330px;border-left:1px solid #333;background:#232326;display:flex;flex-direction:column;overflow-y:auto}
section{padding:10px 12px;border-bottom:1px solid #333}
h4{margin:0 0 6px;font-size:12px;font-weight:600;color:#9a9aa2}
input[type=text]{width:100%;box-sizing:border-box;background:#1c1c1e;color:inherit;border:1px solid #444;border-radius:4px;padding:6px}
label{display:block;margin-top:5px}
#det{max-height:200px;flex:none;overflow:auto;line-height:1.5}
#ev{height:220px;flex:none;overflow:auto;font:11px ui-monospace,Menlo,monospace;line-height:1.6}
button{background:#1c1c1e;color:inherit;border:1px solid #444;border-radius:4px;padding:5px 12px;margin-right:6px;cursor:pointer}button.on{background:#a78bfa;color:#111;border-color:#a78bfa}select{background:#1c1c1e;color:inherit;border:1px solid #444;border-radius:4px;padding:3px}.add{color:#7bd88f}.del{color:#ff7b72}.dim{color:#8a8a92}
.l{stroke:#555;stroke-opacity:.55}
.hot{stroke:#a78bfa;stroke-opacity:.9;stroke-dasharray:4 4;animation:f .8s linear infinite}
@keyframes f{to{stroke-dashoffset:-8}}
@media (prefers-reduced-motion:reduce){.hot{animation:none}}
text{fill:#c8c8d0;font-size:10px;pointer-events:none}
.leg span{display:inline-block;margin-right:10px}
.leg i{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:4px}
</style>
<div id="app"><svg id="g"></svg><svg id="m" style="display:none"></svg>
<aside>
<section><button id="vg" class="on">Граф</button><button id="vm">Карта</button></section>
<section><h4>Новые соединения (тревоги)</h4><div id="al" class="dim">Пока нет</div></section>
<section><h4>Фильтр</h4><input type="text" id="q" placeholder="процесс или хост">
<label><input type="checkbox" id="grp" checked> Группировать хосты по домену</label>
<label><input type="checkbox" id="loc"> Показывать localhost</label>
<div class="leg" style="margin-top:8px"><span><i style="background:#a78bfa"></i>процесс</span><span><i style="background:#4fd1c5"></i>интернет</span><span><i style="background:#7bd88f"></i>LAN</span><span><i style="background:#e0b050"></i>local</span></div></section>
<section id="det"><h4>Выбранный узел</h4><div class="dim">Нажмите на узел графа</div></section>
<section><h4>История</h4><select id="hr"><option value="1">1 час</option><option value="24" selected>24 часа</option><option value="168">7 дней</option></select><div id="hist" style="margin-top:6px"></div></section>
<section style="padding-bottom:0;border:0"><h4>Новые и закрытые соединения</h4></section>
<div id="ev" style="padding:0 12px 10px"></div>
</aside></div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.9.0/d3.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/topojson-client@3.0.2/dist/topojson-client.min.js"></script>
<script>
const $=id=>document.getElementById(id);
const svg=d3.select('#g'),root=svg.append('g'),linkG=root.append('g'),nodeG=root.append('g');
const zoom=d3.zoom().scaleExtent([.1,6]).on('zoom',e=>root.attr('transform',e.transform));
svg.call(zoom);
function center(){const r=$('g').getBoundingClientRect();svg.call(zoom.transform,d3.zoomIdentity.translate(r.width/2,r.height/2))}
center();
let nodes=[],links=[],sel=null,data=null;
const sim=d3.forceSimulation()
 .force('link',d3.forceLink().id(d=>d.id).distance(l=>l.source.type==='me'?100:55).strength(.6))
 .force('charge',d3.forceManyBody().strength(-140))
 .force('x',d3.forceX().strength(.03)).force('y',d3.forceY().strength(.03))
 .force('col',d3.forceCollide(12)).on('tick',tick);
const COL={me:'#fff',proc:'#a78bfa',wan:'#4fd1c5',lan:'#7bd88f',local:'#e0b050'};
const fmt=b=>b<1024?b.toFixed(0)+' Б/с':b<1048576?(b/1024).toFixed(1)+' КБ/с':(b/1048576).toFixed(1)+' МБ/с';
const rad=d=>d.type==='me'?11:d.type==='proc'?5+Math.min(12,Math.sqrt(d.rate/800))+Math.min(4,d.deg/4):3+Math.min(6,d.deg);

function build(d){
 const q=$('q').value.toLowerCase(),grp=$('grp').checked,showLoc=$('loc').checked;
 const nm=new Map(),lm=new Map(),pids={};
 const node=(id,o)=>{if(!nm.has(id))nm.set(id,{id,deg:0,rate:0,info:new Set(),...o});return nm.get(id)};
 const link=(s,t,hot,key)=>{const k=s+'>'+t;let l=lm.get(k);if(!l){l={source:s,target:t,key:k,hot:false};lm.set(k,l)}if(hot)l.hot=true;return l};
 node('me',{label:'Этот Mac',type:'me'});
 d.conns.forEach(c=>{
  if(c.kind==='local'&&!showLoc)return;
  let rl=c.host||c.rip;
  if(grp&&c.host){const p=c.host.split('.');rl=p.length>2?p.slice(-2).join('.'):c.host}
  if(q&&!c.proc.toLowerCase().includes(q)&&!rl.toLowerCase().includes(q))return;
  const p=node('p:'+c.proc,{label:c.proc,type:'proc',listen:new Set()});
  (pids[c.proc]=pids[c.proc]||new Set()).add(c.pid);
  const r=node('r:'+rl,{label:rl,type:c.kind});
  p.info.add(`${rl}:${c.rport} ${c.proto} ${c.state}`);
  r.info.add(`${c.proc} :${c.rport} ${c.proto} ${c.state}`);
  p.deg++;r.deg++;
  link('me','p:'+c.proc);
  link('p:'+c.proc,'r:'+rl);
 });
 d.listen.forEach(x=>{const p=nm.get('p:'+x.proc);if(p)p.listen.add(x.port+'/'+x.proto)});
 for(const[name,s]of Object.entries(pids)){
  const p=nm.get('p:'+name);let i=0,o=0;
  s.forEach(pid=>{const r=d.rates[pid];if(r){i+=r[0];o+=r[1]}});
  p.rin=i;p.rout=o;p.rate=i+o;
 }
 lm.forEach(l=>{if(l.source.startsWith('p:')){const p=nm.get(l.source);l.hot=p.rate>200}else{const p=nm.get(l.target);l.hot=p.rate>200}});
 const old=new Map(nodes.map(n=>[n.id,n]));
 nodes=[...nm.values()].map(n=>{const o=old.get(n.id);if(o){n.x=o.x;n.y=o.y;n.vx=o.vx;n.vy=o.vy;n.fx=o.fx;n.fy=o.fy}return n});
 links=[...lm.values()];
 render();
 sim.nodes(nodes);sim.force('link').links(links);sim.alpha(.25).restart();
 details();events(d.events);
}
function render(){
 linkG.selectAll('line').data(links,d=>d.key).join('line').attr('class',d=>d.hot?'l hot':'l').attr('stroke-width',1);
 const N=nodeG.selectAll('g').data(nodes,d=>d.id).join(e=>{
  const g=e.append('g').style('cursor','pointer').call(d3.drag()
   .on('start',(ev,d)=>{if(!ev.active)sim.alphaTarget(.3).restart();d.fx=d.x;d.fy=d.y})
   .on('drag',(ev,d)=>{d.fx=ev.x;d.fy=ev.y})
   .on('end',(ev,d)=>{if(!ev.active)sim.alphaTarget(0);d.fx=d.fy=null}));
  g.append('circle');g.append('text').attr('dy',-9).attr('text-anchor','middle');return g});
 N.select('circle').attr('r',rad).attr('fill',d=>COL[d.type]||COL.wan).attr('stroke',d=>d.id===sel?'#fff':'none').attr('stroke-width',2);
 N.select('text').text(d=>d.label).attr('opacity',d=>d.type==='proc'||d.type==='me'?1:.6);
 N.on('mouseover',(e,d)=>hl(d)).on('mouseout',()=>hl(null)).on('click',(e,d)=>{sel=d.id;render();details()});
}
function hl(d){
 const nb=new Set();if(d){nb.add(d.id);links.forEach(l=>{if(l.source.id===d.id)nb.add(l.target.id);if(l.target.id===d.id)nb.add(l.source.id)})}
 nodeG.selectAll('g').attr('opacity',n=>!d||nb.has(n.id)?1:.12);
 linkG.selectAll('line').attr('opacity',l=>!d||(nb.has(l.source.id)&&nb.has(l.target.id)&&(l.source.id===d.id||l.target.id===d.id))?1:.08);
}
function tick(){
 linkG.selectAll('line').attr('x1',d=>d.source.x).attr('y1',d=>d.source.y).attr('x2',d=>d.target.x).attr('y2',d=>d.target.y);
 nodeG.selectAll('g').attr('transform',d=>`translate(${d.x},${d.y})`);
}
function details(){
 const n=nodes.find(x=>x.id===sel),el=$('det');
 if(!n){el.innerHTML='<h4>Выбранный узел</h4><div class="dim">Нажмите на узел графа</div>';return}
 let h=`<h4>${esc(n.label)}</h4>`;
 if(n.type==='proc'){
  h+=`<div>↓ ${fmt(n.rin||0)} &nbsp; ↑ ${fmt(n.rout||0)}</div>`;
  if(n.listen&&n.listen.size)h+=`<div class="dim">слушает: ${[...n.listen].slice(0,12).join(', ')}</div>`;
 }
 h+=[...n.info].slice(0,60).map(s=>`<div class="dim">${esc(s)}</div>`).join('');
 el.innerHTML=h;
}
function events(ev){
 $('ev').innerHTML=ev.map(e=>`<div><span class="dim">${e.t}</span> <span class="${e.s==='+'?'add':'del'}">${e.s}</span> ${esc(e.proc)} → ${esc(e.remote)}:${e.port}</div>`).join('');
}
const esc=s=>String(s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
async function tickData(){try{data=await (await fetch('/data')).json();build(data);alertsUI(data.alerts);if(view==='m')drawMap(data)}catch(e){}}
['q','grp','loc'].forEach(i=>$(i).addEventListener('input',()=>data&&build(data)));
let view='g',world=null;
const setView=v=>{view=v;$('g').style.display=v==='g'?'':'none';$('m').style.display=v==='m'?'':'none';$('vg').className=v==='g'?'on':'';$('vm').className=v==='m'?'on':'';if(v==='m'){loadWorld();data&&drawMap(data)}};
$('vg').onclick=()=>setView('g');$('vm').onclick=()=>setView('m');
async function loadWorld(){if(world)return;try{world=await (await fetch('https://cdn.jsdelivr.net/npm/world-atlas@2.0.2/countries-110m.json')).json();data&&drawMap(data)}catch(e){}}
function drawMap(d){
 const el=$('m'),r=el.getBoundingClientRect(),m=d3.select(el);m.selectAll('*').remove();
 const pr=d3.geoNaturalEarth1().fitSize([r.width,r.height],{type:'Sphere'}),path=d3.geoPath(pr);
 m.append('path').datum({type:'Sphere'}).attr('d',path).attr('fill','#18181a');
 if(world)m.append('path').datum(topojson.feature(world,world.objects.countries)).attr('d',path).attr('fill','#2c2c30').attr('stroke','#1c1c1e');
 if(!d.geo_on){m.append('text').attr('x',20).attr('y',30).text('Геолокация выключена. Запустите: python3 netgraph.py --geo');return}
 const pts=new Map();
 d.conns.forEach(c=>{const g=d.geo[c.rip];if(!g||g.lat==null)return;const k=g.lat+','+g.lon,p=pts.get(k)||{g,n:0,names:new Set(),procs:new Set()};p.n++;p.names.add(c.host||c.rip);p.procs.add(c.proc);pts.set(k,p)});
 const me=d.me&&d.me.lat!=null?[d.me.lon,d.me.lat]:null;
 pts.forEach(p=>{
  if(me)m.append('path').datum({type:'LineString',coordinates:[me,[p.g.lon,p.g.lat]]}).attr('d',path).attr('fill','none').attr('stroke','#a78bfa').attr('stroke-opacity',.45);
  const xy=pr([p.g.lon,p.g.lat]);
  m.append('circle').attr('cx',xy[0]).attr('cy',xy[1]).attr('r',3+Math.sqrt(p.n)*1.5).attr('fill','#4fd1c5').append('title').text(`${[...p.names].slice(0,4).join(', ')}\n${p.g.city||''} ${p.g.country||''} ${p.g.org||''}\n${[...p.procs].join(', ')}`);
 });
 if(me){const xy=pr(me);m.append('circle').attr('cx',xy[0]).attr('cy',xy[1]).attr('r',6).attr('fill','#fff')}
}
function alertsUI(a){$('al').innerHTML=a&&a.length?a.map(x=>`<div class="del">${x.t} ${esc(x.proc)} → ${esc(x.remote)}</div>`).join(''):'Пока нет'}
async function hist(){try{const h=await (await fetch('/history?h='+$('hr').value)).json();
 $('hist').innerHTML='<div class="dim">Чаще всего</div>'+h.top.slice(0,12).map(r=>`<div>${esc(r[0])} → ${esc(r[1])} <span class="dim">×${r[2]}</span></div>`).join('')+'<div class="dim" style="margin-top:6px">Впервые за период</div>'+(h.new.slice(0,12).map(r=>`<div>${esc(r[0])} → ${esc(r[1])}</div>`).join('')||'<div class="dim">нет</div>')}catch(e){}}
$('hr').onchange=hist;hist();setInterval(hist,15000);
tickData();setInterval(tickData,2000);
</script></html>"""

def fmt(b):
    return f"{b:.0f} B/s" if b < 1024 else f"{b / 1024:.0f} KB/s" if b < 1048576 else f"{b / 1048576:.1f} MB/s"


def menubar(url):
    try:
        import rumps
    except ImportError:
        sys.exit("Для иконки в менюбаре: pip3 install rumps")
    app = rumps.App("NetGraph", "◉", quit_button="Выход")
    app.menu = [rumps.MenuItem("Открыть граф", callback=lambda _: webbrowser.open(url))]

    @rumps.timer(3)
    def upd(_):
        with lock:
            n = len(state["conns"])
            r = sum(sum(v) for v in state["rates"].values())
        app.title = f"◉ {n} {fmt(r)}" + (f" ⚠{len(alerts)}" if alerts else "")
    app.run()


def install_agent():
    import plistlib
    p = os.path.expanduser("~/Library/LaunchAgents/com.netgraph.plist")
    args = [sys.executable, os.path.abspath(__file__)] + [a for a in sys.argv[1:] if a != "--install-agent"]
    plistlib.dump({"Label": "com.netgraph", "ProgramArguments": args, "RunAtLoad": True, "KeepAlive": True},
                  open(p, "wb"))
    subprocess.run(["launchctl", "load", "-w", p])
    print("Автозапуск установлен:", p, "\nАргументы:", args)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="NetGraph")
    ap.add_argument("--geo", action="store_true", help="карта: геолокация IP через ip-api.com")
    ap.add_argument("--menubar", action="store_true", help="иконка в менюбаре (нужен rumps)")
    ap.add_argument("--install-agent", action="store_true", help="автозапуск при входе (launchd)")
    ap.add_argument("--port", type=int, default=PORT)
    a = ap.parse_args()
    ARGS.geo, ARGS.port = a.geo, a.port
    if a.install_agent:
        install_agent()
        sys.exit()
    threading.Thread(target=loop, daemon=True).start()
    if a.geo:
        threading.Thread(target=geo_loop, daemon=True).start()
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), H)
    url = f"http://127.0.0.1:{a.port}"
    print("NetGraph:", url, "(Ctrl+C для выхода)")
    if a.menubar:
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        menubar(url)
    else:
        webbrowser.open(url)
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            pass
