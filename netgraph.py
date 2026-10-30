#!/usr/bin/env python3
"""NetGraph: граф сетевой активности Mac в стиле Obsidian.
Запуск:  sudo python3 netgraph.py [--geo] [--menubar] [--install-agent] [--demo]
(без sudo видны только ваши процессы)
Открыть: http://127.0.0.1:8765
Зависимости: только стандартная библиотека Python 3 (macOS: lsof, nettop).
Интерфейс подгружает d3.js с CDN (cdnjs / jsDelivr / unpkg) — нужен интернет.

  --geo    включить геолокацию IP на карте (можно и кнопкой прямо на карте)
  --demo   демо-данные без lsof/nettop — удобно посмотреть интерфейс
"""
import subprocess, re, json, time, threading, socket, webbrowser, collections, ipaddress
import sqlite3, os, sys, argparse, urllib.request, urllib.parse, random, math
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from concurrent.futures import ThreadPoolExecutor

PORT = 8765
LSOF = re.compile(r'^(\S+)\s+(\d+)\s+(\S+)\s+\S+\s+(IPv[46])\s+\S+\s+\S+\s+(TCP|UDP)\s+(.*)$')
lock = threading.Lock()
state = {"conns": [], "listen": [], "rates": {}}
events = collections.deque(maxlen=300)
dns = {}
pool = ThreadPoolExecutor(8)
ARGS = argparse.Namespace(geo=False, port=PORT, demo=False)
alerts = collections.deque(maxlen=50)
geo, me_geo = {}, {}
geo_state = {"pending": 0, "err": ""}
HOME = os.path.expanduser("~/.netgraph")
GEO_FLAG = os.path.join(HOME, "geo-enabled")
WORLD_FILE = os.path.join(HOME, "world.json")
WORLD_URLS = ["https://cdn.jsdelivr.net/npm/world-atlas@2.0.2/countries-110m.json",
              "https://unpkg.com/world-atlas@2.0.2/countries-110m.json"]
os.makedirs(HOME, exist_ok=True)
DBL = threading.Lock()
D = sqlite3.connect(os.path.join(HOME, "history.db"), check_same_thread=False)
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
    """Геолокация через ip-api.com (отправляет внешние IP ваших соединений этому сервису).
    Работает только когда ARGS.geo включён (флаг --geo или кнопка на карте)."""
    F = "status,message,country,countryCode,city,lat,lon,org,query"

    def post(url, body=None):
        req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Content-Type": "application/json"})
        return json.load(urllib.request.urlopen(req, timeout=10))

    while True:
        if not ARGS.geo:
            time.sleep(1)
            continue
        wait = 4
        try:
            if not me_geo:
                r = post("http://ip-api.com/json/?fields=" + F)
                if r.get("status") == "success":
                    me_geo.update(r)
            with lock:
                ips = sorted({c["rip"] for c in state["conns"] if kind_of(c["rip"]) == "wan"})
            todo = [i for i in ips if i not in geo]
            geo_state["pending"] = len(todo)
            if todo:
                batch = todo[:100]
                # ответ приходит в том же порядке, что и запрос; сопоставляем по индексу,
                # потому что ip-api может вернуть IPv6 в другой записи, чем её выдал lsof
                for ip, r in zip(batch, post("http://ip-api.com/batch?fields=" + F, batch)):
                    geo[ip] = r if r.get("status") == "success" else {}
                geo_state["pending"] = max(0, len(todo) - len(batch))
            geo_state["err"] = ""
        except Exception as e:
            geo_state["err"] = str(e)[:140]
            print("geo error:", e)
            wait = 30  # не долбим сервис при лимитах (429) или отсутствии сети
        time.sleep(wait)


def set_geo(on):
    ARGS.geo = bool(on)
    try:
        if on:
            open(GEO_FLAG, "w").close()
        elif os.path.exists(GEO_FLAG):
            os.remove(GEO_FLAG)
    except OSError:
        pass


def world_json():
    """Контуры стран: кэшируем на диск, чтобы карта работала и без CDN в браузере."""
    try:
        with open(WORLD_FILE, "rb") as f:
            return f.read()
    except OSError:
        pass
    for u in WORLD_URLS:
        try:
            data = urllib.request.urlopen(u, timeout=12).read()
            json.loads(data)
            with open(WORLD_FILE, "wb") as f:
                f.write(data)
            return data
        except Exception:
            continue
    return None


def gateway_ip():
    """Адрес шлюза по умолчанию (обычно это и есть роутер)."""
    for cmd, rx in ((["route", "-n", "get", "default"], r'gateway:\s*(\S+)'),
                    (["ip", "route", "show", "default"], r'via\s+(\S+)')):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=3).stdout
            m = re.search(rx, out)
            if m:
                return str(ipaddress.ip_address(m.group(1).split('%')[0]))
        except Exception:
            continue
    return ""


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


# ───────────────────────────── демо-режим ─────────────────────────────
DEMO_HOSTS = [  # host, ip, city, country, cc, lat, lon, org
    ("youtube.com", "142.250.74.46", "Frankfurt", "Germany", "DE", 50.11, 8.68, "Google LLC"),
    ("googlevideo.com", "74.125.100.7", "Helsinki", "Finland", "FI", 60.17, 24.94, "Google LLC"),
    ("github.com", "140.82.121.4", "Frankfurt", "Germany", "DE", 50.11, 8.68, "GitHub, Inc."),
    ("githubusercontent.com", "185.199.108.133", "San Francisco", "United States", "US", 37.77, -122.42, "GitHub, Inc."),
    ("anthropic.com", "160.79.104.10", "San Francisco", "United States", "US", 37.77, -122.42, "Anthropic PBC"),
    ("cloudfront.net", "18.164.96.12", "Stockholm", "Sweden", "SE", 59.33, 18.07, "Amazon.com, Inc."),
    ("telegram.org", "149.154.167.51", "Amsterdam", "Netherlands", "NL", 52.37, 4.9, "Telegram Messenger"),
    ("spotify.com", "35.186.224.25", "Brussels", "Belgium", "BE", 50.85, 4.35, "Google LLC"),
    ("apple.com", "17.253.144.10", "Cupertino", "United States", "US", 37.32, -122.03, "Apple Inc."),
    ("icloud.com", "17.57.144.20", "Singapore", "Singapore", "SG", 1.35, 103.82, "Apple Inc."),
    ("slack.com", "3.120.45.8", "Frankfurt", "Germany", "DE", 50.11, 8.68, "Amazon.com, Inc."),
    ("notion.so", "104.18.12.33", "Tokyo", "Japan", "JP", 35.68, 139.69, "Cloudflare, Inc."),
    ("yandex.ru", "77.88.55.88", "Moscow", "Russia", "RU", 55.75, 37.62, "Yandex LLC"),
    ("vk.com", "87.240.137.164", "Saint Petersburg", "Russia", "RU", 59.93, 30.34, "VK LLC"),
    ("fastly.net", "151.101.1.69", "Sydney", "Australia", "AU", -33.87, 151.21, "Fastly, Inc."),
    ("cloudflare.com", "1.1.1.1", "Sao Paulo", "Brazil", "BR", -23.55, -46.63, "Cloudflare, Inc."),
]
DEMO_PROCS = {
    "Google Chrome": (4121, ["youtube.com", "googlevideo.com", "github.com", "githubusercontent.com", "notion.so", "yandex.ru", "cloudfront.net", "vk.com", "spotify.com"]),
    "Claude": (5230, ["anthropic.com", "cloudfront.net"]),
    "Telegram": (3310, ["telegram.org"]),
    "Slack": (2750, ["slack.com", "cloudfront.net"]),
    "Spotify": (6100, ["spotify.com", "fastly.net"]),
    "Code Helper": (7210, ["github.com", "githubusercontent.com"]),
    "cloudd": (880, ["apple.com", "icloud.com"]),
    "apsd": (640, ["apple.com"]),
    "mDNSResponder": (310, ["cloudflare.com"]),
}


def demo_loop():
    rnd = random.Random(7)
    ip_of = {h[0]: h[1] for h in DEMO_HOSTS}
    for h in DEMO_HOSTS:
        dns[h[1]] = "edge-%d.%s" % (rnd.randint(1, 99), h[0])
        geo[h[1]] = dict(status="success", country=h[3], countryCode=h[4], city=h[2], lat=h[5], lon=h[6], org=h[7], query=h[1])
    dns["192.168.1.1"] = "router.lan"
    dns["127.0.0.1"] = "localhost"
    me_geo.update(dict(status="success", country="Russia", countryCode="RU", city="Moscow", lat=55.75, lon=37.62, org="Home", query="0.0.0.0"))
    pool_c = []
    for name, (pid, hosts) in DEMO_PROCS.items():
        for hn in hosts:
            pool_c.append(dict(proc=name, pid=pid, proto="TCP", lport=str(50000 + rnd.randint(0, 9999)),
                               rip=ip_of[hn], rport="443", state="ESTABLISHED"))
    pool_c.append(dict(proc="Claude", pid=5230, proto="TCP", lport="53001", rip="192.168.1.1", rport="53", state="ESTABLISHED"))
    pool_c.append(dict(proc="Code Helper", pid=7210, proto="TCP", lport="53002", rip="127.0.0.1", rport="5173", state="ESTABLISHED"))
    listen = [dict(proc="Code Helper", pid=7210, proto="TCP", port="5173"), dict(proc="Telegram", pid=3310, proto="UDP", port="49152"),
              dict(proc="Spotify", pid=6100, proto="TCP", port="57621")]
    active = list(pool_c)
    alerts.appendleft(dict(t=time.strftime("%H:%M:%S"), proc="cloudd", remote="icloud.com", ip="17.57.144.20"))
    alerts.appendleft(dict(t=time.strftime("%H:%M:%S"), proc="Code Helper", remote="githubusercontent.com", ip="185.199.108.133"))
    t = 0
    while True:
        t += 1
        if rnd.random() < .5:
            if len(active) > len(pool_c) * .7 and rnd.random() < .6:
                c = active.pop(rnd.randrange(len(active)))
                events.appendleft(dict(t=time.strftime("%H:%M:%S"), s="-", proc=c["proc"], remote=dns.get(c["rip"]) or c["rip"], port=c["rport"], proto=c["proto"]))
            else:
                c = rnd.choice([x for x in pool_c if x not in active] or pool_c)
                if c not in active:
                    active.append(c)
                    events.appendleft(dict(t=time.strftime("%H:%M:%S"), s="+", proc=c["proc"], remote=dns.get(c["rip"]) or c["rip"], port=c["rport"], proto=c["proto"]))
        rates = {}
        for name, (pid, _h) in DEMO_PROCS.items():
            base = {"Google Chrome": 9e5, "Spotify": 3e5, "Telegram": 6e4, "Claude": 2.5e5}.get(name, 1.2e4)
            rates[pid] = [abs(math.sin(t / 4 + pid)) * base * rnd.random(), abs(math.cos(t / 6 + pid)) * base * .15 * rnd.random()]
        with lock:
            state.update(conns=list(active), listen=listen, rates=rates)
        time.sleep(1.5)


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body, ctype, code=200):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _allowed(self):
        """Защита от DNS-rebinding и чужих сайтов: принимаем только localhost."""
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]")
        if host not in ("127.0.0.1", "localhost", "::1"):
            return False
        origin = self.headers.get("Origin")
        return not origin or urllib.parse.urlparse(origin).hostname in ("127.0.0.1", "localhost", "::1")

    def do_POST(self):
        if not self._allowed():
            return self._send(b"forbidden", "text/plain", 403)
        if self.path.startswith("/geo"):
            try:
                n = int(self.headers.get("Content-Length") or 0)
                on = bool(json.loads(self.rfile.read(n) or b"{}").get("on"))
            except Exception:
                return self._send(b"bad request", "text/plain", 400)
            if not ARGS.demo:
                set_geo(on)
            return self._send(json.dumps(dict(ok=True, on=ARGS.geo)).encode(), "application/json")
        self._send(b"not found", "text/plain", 404)

    def do_GET(self):
        if not self._allowed():
            return self._send(b"forbidden", "text/plain", 403)
        path = self.path.split("?")[0]
        if path == "/history":
            h = float((re.search(r'h=([\d.]+)', self.path) or [0, 24])[1])
            since = time.time() - h * 3600
            if ARGS.demo:
                top = [[n, r, 40 - i * 3 - j] for i, (n, (_p, hs)) in enumerate(DEMO_PROCS.items()) for j, r in enumerate(hs[:2])][:14]
                new = [["cloudd", "icloud.com", time.time() - 600], ["Code Helper", "githubusercontent.com", time.time() - 3000]]
            else:
                with DBL:
                    top = D.execute("SELECT proc,remote,COUNT(*) FROM log WHERE s='+' AND t>? GROUP BY proc,remote ORDER BY 3 DESC LIMIT 25", (since,)).fetchall()
                    new = D.execute("SELECT proc,remote,first FROM pairs WHERE first>? ORDER BY first DESC LIMIT 25", (since,)).fetchall()
            self._send(json.dumps(dict(top=top, new=new)).encode(), "application/json")
        elif path == "/data":
            with lock:
                conns = [dict(c, host=host_of(c["rip"]), kind=kind_of(c["rip"])) for c in state["conns"]]
                body = json.dumps(dict(conns=conns, listen=state["listen"], rates=state["rates"],
                                       events=list(events)[:120], alerts=list(alerts)[:15],
                                       geo={c["rip"]: geo.get(c["rip"], {}) for c in conns}, me=me_geo,
                                       geo_on=ARGS.geo, geo_pending=geo_state["pending"], geo_err=geo_state["err"],
                                       demo=ARGS.demo)).encode()
            self._send(body, "application/json")
        elif path == "/gateway":
            self._send(json.dumps(dict(ip="192.168.1.1" if ARGS.demo else gateway_ip())).encode(), "application/json")
        elif path == "/world.json":
            data = world_json()
            if data is None:
                return self._send(b"unavailable", "text/plain", 404)
            self._send(data, "application/json")
        elif path in ("/", "/index.html"):
            self._send(PAGE.encode(), "text/html; charset=utf-8")
        else:
            self._send(b"not found", "text/plain", 404)


PAGE = r"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetGraph</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='8' fill='%230e1119'/%3E%3Cpath d='M9 22l7-12 7 12' stroke='%23a78bfa' stroke-width='2' fill='none'/%3E%3Ccircle cx='16' cy='10' r='3.5' fill='%23fff'/%3E%3Ccircle cx='9' cy='22' r='3' fill='%23a78bfa'/%3E%3Ccircle cx='23' cy='22' r='3' fill='%233ee0cb'/%3E%3C/svg%3E">
<style>
:root{
 --bg:#090b10;--panel:#0e1119;--glass:rgba(17,20,29,.74);
 --line:rgba(255,255,255,.07);--line2:rgba(255,255,255,.14);
 --tx:#e9ebf3;--tx2:#a2a9ba;--tx3:#687187;
 --acc:#a78bfa;--wan:#3ee0cb;--lan:#86e08f;--loc:#f5b94a;--me:#ffffff;
 --bad:#ff6b81;--warn:#f5b94a;--ok:#5be39a;--down:#3ee0cb;--up:#e879f9;
 --mono:ui-monospace,"SF Mono",Menlo,Consolas,monospace;--r:12px
}
*{box-sizing:border-box}
[hidden]{display:none!important}
html,body{margin:0;height:100%;background:var(--bg);color:var(--tx);overflow:hidden;
 font:13px/1.45 -apple-system,BlinkMacSystemFont,"SF Pro Text",Inter,system-ui,sans-serif;-webkit-font-smoothing:antialiased}
#app{display:flex;height:100%}
#stage{position:relative;flex:1;min-width:0;overflow:hidden;
 background:radial-gradient(1100px 720px at 50% 42%,#151b2a 0%,#0c0f17 58%,var(--bg) 100%)}
#stage::before{content:"";position:absolute;inset:0;pointer-events:none;transition:opacity .35s;
 background-image:radial-gradient(rgba(255,255,255,.075) 1px,transparent 1.3px);
 background-size:calc(26px*var(--gk,1)) calc(26px*var(--gk,1));background-position:var(--gx,0) var(--gy,0);
 -webkit-mask-image:radial-gradient(circle at 50% 48%,#000 15%,transparent 78%);mask-image:radial-gradient(circle at 50% 48%,#000 15%,transparent 78%)}
#stage.map::before{opacity:0}
svg.cv{position:absolute;inset:0;width:100%;height:100%;display:block;cursor:grab}
svg.cv:active{cursor:grabbing}

.glass{background:var(--glass);-webkit-backdrop-filter:blur(14px) saturate(1.3);backdrop-filter:blur(14px) saturate(1.3);
 border:1px solid var(--line);border-radius:var(--r);box-shadow:0 10px 34px rgba(0,0,0,.35),inset 0 1px 0 rgba(255,255,255,.04)}
svg.i{width:15px;height:15px;stroke:currentColor;fill:none;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round;flex:none}
kbd{font:600 10px/1 var(--mono);color:var(--tx3);border:1px solid var(--line2);border-radius:5px;padding:3px 5px}

/* верхняя панель */
#top{position:absolute;top:14px;left:14px;right:14px;display:flex;gap:10px;align-items:center;flex-wrap:wrap;z-index:5;pointer-events:none}
#top>*{pointer-events:auto}
.brand{display:flex;align-items:center;gap:9px;height:38px;padding:0 14px 0 11px;font-weight:650;letter-spacing:.2px}
.live{width:7px;height:7px;border-radius:50%;background:var(--ok);box-shadow:0 0 0 0 rgba(91,227,154,.6);animation:live 2s infinite}
.live.off{background:var(--bad);animation:none;box-shadow:none}
@keyframes live{70%{box-shadow:0 0 0 7px rgba(91,227,154,0)}100%{box-shadow:0 0 0 0 rgba(91,227,154,0)}}
.seg{display:flex;padding:3px;gap:2px;height:38px}
.seg button{display:flex;align-items:center;gap:7px;border:0;background:none;color:var(--tx2);font:inherit;font-weight:550;padding:0 13px;border-radius:9px;cursor:pointer;transition:.18s}
.seg button:hover{color:var(--tx)}
.seg button.on{background:rgba(167,139,250,.17);color:#fff;box-shadow:inset 0 0 0 1px rgba(167,139,250,.38)}
.search{display:flex;align-items:center;gap:8px;height:38px;padding:0 11px;flex:0 1 270px;min-width:170px;color:var(--tx3);transition:.18s}
.search:focus-within{border-color:rgba(167,139,250,.55);box-shadow:0 0 0 3px rgba(167,139,250,.15),0 10px 34px rgba(0,0,0,.35)}
.search input{flex:1;min-width:0;background:none;border:0;outline:0;color:var(--tx);font:inherit}
.search input::placeholder{color:var(--tx3)}
.chip{display:inline-flex;align-items:center;gap:7px;height:38px;padding:0 13px;color:var(--tx2);font:inherit;font-weight:550;cursor:pointer;user-select:none;transition:.18s}
.chip:hover{color:var(--tx)}
.chip.on{color:#fff;border-color:rgba(167,139,250,.45);background:rgba(167,139,250,.14)}

/* статистика */
#stats{position:absolute;top:64px;left:14px;display:flex;z-index:4;overflow:hidden;max-width:calc(100% - 28px)}
.stat{padding:9px 15px;min-width:86px}
.stat+.stat{border-left:1px solid var(--line)}
.stat b{display:block;font-size:18px;line-height:1.25;font-weight:650;font-variant-numeric:tabular-nums;white-space:nowrap}
.stat span{font-size:10px;color:var(--tx3);text-transform:uppercase;letter-spacing:.08em;white-space:nowrap}
.stat.d b{color:var(--down)}.stat.u b{color:var(--up)}
.stat.sp{padding:6px 12px;display:flex;align-items:center}
#spark{width:150px;height:34px;display:block;overflow:visible}
.sp-d{fill:none;stroke:var(--down);stroke-width:1.6}.sp-u{fill:none;stroke:var(--up);stroke-width:1.3;opacity:.9}
.sp-a{fill:url(#spg);opacity:.9}

/* легенда и зум */
.leg{position:absolute;left:14px;bottom:14px;display:flex;align-items:center;gap:14px;padding:9px 14px;color:var(--tx2);font-size:12px;z-index:4;flex-wrap:wrap;max-width:calc(100% - 90px)}
.leg span{display:inline-flex;align-items:center;gap:7px;white-space:nowrap}
.leg i{width:9px;height:9px;border-radius:50%;display:inline-block}
.leg button{background:none;border:0;color:var(--tx3);font:inherit;text-decoration:underline;text-underline-offset:3px;cursor:pointer;padding:0}
.leg button:hover{color:var(--tx)}
#zoomctl{position:absolute;right:14px;bottom:14px;display:flex;flex-direction:column;z-index:4;overflow:hidden}
#zoomctl button{width:36px;height:36px;display:grid;place-items:center;background:none;border:0;color:var(--tx2);cursor:pointer;transition:.15s}
#zoomctl button:hover{background:rgba(255,255,255,.07);color:#fff}
#zoomctl button+button{border-top:1px solid var(--line)}

/* карточки поверх сцены */
.card{position:absolute;left:50%;top:50%;transform:translate(-50%,-50%);width:min(390px,calc(100% - 40px));padding:24px 26px;text-align:center;z-index:6}
.card h3{margin:10px 0 6px;font-size:16px}
.card p{margin:0 0 16px;color:var(--tx2)}
.card .ic{width:44px;height:44px;margin:0 auto;border-radius:13px;display:grid;place-items:center;background:rgba(167,139,250,.14);color:var(--acc);box-shadow:inset 0 0 0 1px rgba(167,139,250,.3)}
.card .ic svg{width:22px;height:22px}
.btn{background:linear-gradient(180deg,#b9a0ff,#9a79f6);color:#150f2c;border:0;border-radius:10px;padding:10px 18px;font:inherit;font-weight:650;cursor:pointer;box-shadow:0 8px 24px rgba(167,139,250,.35);transition:.15s}
.btn:hover{transform:translateY(-1px);box-shadow:0 10px 28px rgba(167,139,250,.5)}
.btn.ghost{background:rgba(255,255,255,.06);color:var(--tx);box-shadow:inset 0 0 0 1px var(--line2)}
.spin{width:22px;height:22px;border-radius:50%;border:2.5px solid rgba(167,139,250,.25);border-top-color:var(--acc);animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.fine{font-size:11px;color:var(--tx3);margin-top:12px}
#tip{position:absolute;left:0;top:0;pointer-events:none;z-index:9;opacity:0;transition:opacity .12s;max-width:300px;padding:9px 12px;
 background:rgba(12,14,21,.94);border:1px solid var(--line2);border-radius:10px;box-shadow:0 12px 30px rgba(0,0,0,.5);font-size:12px;line-height:1.5}
#tip b{font-size:12.5px}

/* боковая панель */
aside{width:360px;flex:none;background:var(--panel);border-left:1px solid var(--line);display:flex;flex-direction:column;min-height:0}
.tabs{display:flex;padding:10px 10px 0;gap:2px;border-bottom:1px solid var(--line)}
.tab{flex:1;background:none;border:0;color:var(--tx3);font:inherit;font-size:12.5px;font-weight:560;padding:9px 0 12px;cursor:pointer;position:relative;white-space:nowrap;transition:color .15s}
.tab:hover{color:var(--tx2)}.tab.on{color:var(--tx)}
.tab.on::after{content:"";position:absolute;left:10px;right:10px;bottom:-1px;height:2px;border-radius:2px;background:var(--acc);box-shadow:0 0 12px var(--acc)}
.badge{display:inline-block;min-width:16px;padding:1px 5px;margin-left:4px;border-radius:9px;background:var(--bad);color:#fff;font-size:10px;font-weight:700;line-height:14px;text-align:center}
.pane{display:none;flex:1;min-height:0;overflow:auto;padding:16px 14px}
.pane.on{display:block}
.pane::-webkit-scrollbar{width:8px}.pane::-webkit-scrollbar-thumb{background:rgba(255,255,255,.1);border-radius:8px;border:2px solid var(--panel)}
.sec-t{font-size:10.5px;font-weight:650;letter-spacing:.09em;text-transform:uppercase;color:var(--tx3);margin:16px 0 8px}
.sec-t:first-child{margin-top:0}
.hint{color:var(--tx3);font-size:12px;margin:14px 2px 0}
.dim{color:var(--tx3)}.mono{font-family:var(--mono);font-size:11.5px}
.row{display:flex;align-items:center;gap:10px;padding:8px 9px;border-radius:9px}
.row.click{cursor:pointer}.row.click:hover{background:rgba(255,255,255,.055)}
.grow{flex:1;min-width:0}
.rw{display:flex;justify-content:space-between;gap:10px;align-items:baseline}
.nm{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dotc{width:9px;height:9px;border-radius:50%;flex:none;box-shadow:0 0 10px currentColor}
.dotc.big{width:13px;height:13px}
.bar{height:3px;border-radius:3px;background:rgba(255,255,255,.07);overflow:hidden;margin-top:5px}
.bar>i{display:block;height:100%;border-radius:3px;transition:width .5s}
.hd{display:flex;align-items:center;gap:12px;margin-bottom:14px}
.ttl{font-size:16px;font-weight:650;word-break:break-all;line-height:1.25}
.rates{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:6px}
.rate{padding:10px 12px;border-radius:10px;background:rgba(255,255,255,.04);border:1px solid var(--line)}
.rate span{font-size:10.5px;color:var(--tx3);text-transform:uppercase;letter-spacing:.07em}
.rate b{display:block;font-size:15px;font-weight:650;margin-top:1px;font-variant-numeric:tabular-nums}
.rate.d b{color:var(--down)}.rate.u b{color:var(--up)}
.chips{display:flex;flex-wrap:wrap;gap:5px}
.pill{font:600 10.5px/1 var(--mono);padding:4px 7px;border-radius:6px;background:rgba(255,255,255,.07);color:var(--tx2)}
.tag{font:600 9.5px/1 var(--mono);padding:3px 5px;border-radius:5px;background:rgba(255,255,255,.07);color:var(--tx2);flex:none}
.tag.ok{background:rgba(91,227,154,.13);color:var(--ok)}.tag.warn{background:rgba(245,185,74,.13);color:var(--warn)}
.conn{display:flex;align-items:center;gap:7px;padding:5px 4px;border-bottom:1px solid var(--line)}
.conn:last-child{border:0}.conn .mono{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.geo{padding:10px 12px;border-radius:10px;background:rgba(255,255,255,.04);border:1px solid var(--line);margin-bottom:10px}
.geo .big{font-size:14px;font-weight:600}
.ev{font:11.5px/1.7 var(--mono)}
.ev div{padding:1px 0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ev .p{display:inline-block;width:14px;text-align:center;font-weight:700}
.add{color:var(--ok)}.del{color:var(--bad)}
.alert{padding:10px 12px;border-radius:10px;background:rgba(255,107,129,.07);border:1px solid rgba(255,107,129,.2);border-left:3px solid var(--bad);margin-bottom:8px}
.alert b{font-weight:650}
.empty{text-align:center;color:var(--tx3);padding:38px 14px}
.empty .ic{width:42px;height:42px;margin:0 auto 10px;border-radius:50%;display:grid;place-items:center;background:rgba(255,255,255,.05)}
.empty .ic svg{width:20px;height:20px}
.pills{display:flex;gap:4px;margin-bottom:6px}
.pills button{flex:1;padding:7px;border:1px solid var(--line);background:none;color:var(--tx2);border-radius:8px;font:inherit;cursor:pointer;transition:.15s}
.pills button.on{background:rgba(167,139,250,.15);border-color:rgba(167,139,250,.4);color:#fff}

/* граф */
.n{cursor:pointer;transition:opacity .25s}
.n .halo{pointer-events:none}
.n .core{stroke:#0b0e15;stroke-width:1.5}
.n.sel .core{stroke:#fff;stroke-width:2.5}
.lbl{font-size:10.5px;fill:var(--tx2);text-anchor:middle;paint-order:stroke;stroke:#0a0d14;stroke-width:3.5px;stroke-linejoin:round;pointer-events:none}
.lbl.p{font-size:11.5px;font-weight:650;fill:var(--tx)}
.lbl.r{opacity:0;transition:opacity .2s}
.n.multi .lbl.r,.n:hover .lbl.r,.n.focus .lbl.r,.n.sel .lbl.r,svg.zoomed .lbl.r{opacity:.92}
.n.dim{opacity:.1}
.l{fill:none;stroke-opacity:.26;transition:opacity .25s,stroke-opacity .25s}
.l.me{stroke:var(--acc);stroke-opacity:.4}
.l.wan{stroke:var(--wan)}.l.lan{stroke:var(--lan)}.l.local{stroke:var(--loc)}
.l.hot{stroke-opacity:.95;stroke-dasharray:5 5;animation:flow .9s linear infinite}
.l.focus{stroke-opacity:.9}.l.dim{stroke-opacity:.04}
@keyframes flow{to{stroke-dashoffset:-10}}
.ring{fill:none;stroke:#fff;stroke-width:1;transform-box:fill-box;transform-origin:center;animation:ring 3.4s ease-out infinite;pointer-events:none}
.ring.r2{animation-delay:1.7s}
@keyframes ring{0%{transform:scale(.7);opacity:.7}100%{transform:scale(2.6);opacity:0}}

/* карта */
#m .ocean{fill:url(#ocean);stroke:rgba(255,255,255,.12);stroke-width:1;vector-effect:non-scaling-stroke}
#m .grat,#gl .grat{fill:none;stroke:rgba(255,255,255,.05);stroke-width:.7;vector-effect:non-scaling-stroke}
#m .land,#gl .land{fill:#222a40;stroke:#3a4766;stroke-width:.6;stroke-linejoin:round;vector-effect:non-scaling-stroke}
#m .arc,#gl .arc{fill:none;stroke:var(--acc);stroke-opacity:.6;stroke-width:1.2;stroke-dasharray:4 6;animation:flow 1.1s linear infinite;vector-effect:non-scaling-stroke}
#m .dot,#gl .dot{fill:var(--wan);stroke:#06141a;stroke-width:1.4;vector-effect:non-scaling-stroke;cursor:pointer}
#m .pulse,#gl .pulse{fill:var(--wan);transform-box:fill-box;transform-origin:center;animation:pulse 2.6s ease-out infinite;pointer-events:none}
@keyframes pulse{0%{transform:scale(.7);opacity:.55}100%{transform:scale(2.8);opacity:0}}
#m .me-dot,#gl .me-dot{fill:#fff;stroke:var(--acc);stroke-width:2;vector-effect:non-scaling-stroke}
#m .me-ring,#gl .me-ring{fill:none;stroke:#fff;stroke-width:1;vector-effect:non-scaling-stroke;transform-box:fill-box;transform-origin:center;animation:pulse 2.6s ease-out infinite}
#m text,#gl text{fill:#fff;font-weight:650;text-anchor:middle;paint-order:stroke;stroke:#0a0d14;stroke-width:3px;pointer-events:none}

#gl .land{fill:#2a3a60;stroke:#4d6193;stroke-width:.5}
#gl .grat{stroke:rgba(255,255,255,.07)}
svg.alllbl .lbl.r{opacity:.92}
#settings{position:absolute;top:64px;right:14px;width:340px;max-height:calc(100% - 90px);overflow:auto;z-index:8;padding:6px 0 12px}
.st-h{display:flex;justify-content:space-between;align-items:center;padding:12px 16px 2px;font-size:15px}
.st-h button{background:none;border:0;color:var(--tx3);font-size:22px;cursor:pointer;line-height:1}
.st-h button:hover{color:var(--tx)}
.st-s{font-size:10.5px;font-weight:650;letter-spacing:.09em;text-transform:uppercase;color:var(--tx3);padding:16px 16px 6px}
.st-r{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:7px 16px}
.st-r>span{color:var(--tx2)}
.sw{position:relative;width:38px;height:22px;flex:none}
.sw input{position:absolute;opacity:0;inset:0;width:100%;height:100%;margin:0;cursor:pointer;z-index:1}
.sw i{position:absolute;inset:0;border-radius:11px;background:rgba(255,255,255,.13);transition:.18s}
.sw i::after{content:"";position:absolute;left:3px;top:3px;width:16px;height:16px;border-radius:50%;background:#fff;transition:.18s}
.sw input:checked+i{background:var(--acc)}
.sw input:checked+i::after{transform:translateX(16px)}
.sw input:focus-visible+i{box-shadow:0 0 0 3px rgba(167,139,250,.35)}
.sw input:disabled+i{opacity:.4}
.seg.mini{height:30px;padding:2px;background:rgba(255,255,255,.05);border:1px solid var(--line);border-radius:10px}
.seg.mini button{padding:0 11px;font-size:12px;border-radius:8px}
.router{margin:4px 16px 0;padding:12px 14px;border-radius:10px;background:rgba(255,255,255,.04);border:1px solid var(--line);color:var(--tx2);font-size:12.5px}
.router b{color:var(--tx)}
.router p{margin:8px 0 0}
.router .btn{display:inline-block;margin-top:10px;text-decoration:none;font-size:12.5px;padding:8px 14px}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
@media (max-width:860px){#app{flex-direction:column}aside{width:auto;height:42%;border-left:0;border-top:1px solid var(--line)}#stats{top:112px}.stat.sp{display:none}}
</style></head>
<body>
<div id="app">
<main id="stage">
 <svg id="g" class="cv"></svg>
 <svg id="m" class="cv" style="display:none"></svg>
 <svg id="gl" class="cv" style="display:none"></svg>

 <div id="top">
  <div class="glass brand">
   <svg width="22" height="22" viewBox="0 0 32 32"><path d="M9 22l7-12 7 12" stroke="#a78bfa" stroke-width="2" fill="none"/><circle cx="16" cy="10" r="3.6" fill="#fff"/><circle cx="9" cy="22" r="3.1" fill="#a78bfa"/><circle cx="23" cy="22" r="3.1" fill="#3ee0cb"/></svg>
   NetGraph <i class="live" id="live" title="Данные поступают"></i>
  </div>
  <div class="glass seg">
   <button id="vg" class="on"><svg class="i" viewBox="0 0 24 24"><circle cx="6" cy="12" r="2.5"/><circle cx="18" cy="6" r="2.5"/><circle cx="18" cy="18" r="2.5"/><path d="M8.2 11l7.6-4M8.2 13l7.6 4"/></svg>Граф</button>
   <button id="vm"><svg class="i" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/></svg>Карта</button>
  </div>
  <label class="glass search"><svg class="i" viewBox="0 0 24 24"><circle cx="11" cy="11" r="7.5"/><path d="m21 21-4.3-4.3"/></svg>
   <input id="q" type="text" placeholder="Процесс или хост…" autocomplete="off" spellcheck="false"><kbd>/</kbd></label>
  <button class="glass chip on" id="grp" title="Объединять хосты по домену второго уровня">Домены</button>
  <button class="glass chip" id="loc" title="Показывать соединения через localhost">localhost</button>
  <button class="glass chip" id="pause" title="Заморозить обновление (P)"><svg class="i" id="pi" viewBox="0 0 24 24"><rect x="6" y="4.5" width="4" height="15" rx="1"/><rect x="14" y="4.5" width="4" height="15" rx="1"/></svg><span>Пауза</span></button>
  <button class="glass chip" id="cog" title="Настройки (S)"><svg class="i" viewBox="0 0 24 24"><path d="M4 6h9M19 6h1M4 12h3M13 12h7M4 18h11M21 18h-1"/><circle cx="16" cy="6" r="2.2"/><circle cx="10" cy="12" r="2.2"/><circle cx="18" cy="18" r="2.2"/></svg><span>Настройки</span></button>
 </div>

 <div id="stats" class="glass">
  <div class="stat"><b id="s-c">–</b><span>соединений</span></div>
  <div class="stat"><b id="s-p">–</b><span>процессов</span></div>
  <div class="stat"><b id="s-h">–</b><span>хостов</span></div>
  <div class="stat d"><b id="s-d">–</b><span>↓ приём</span></div>
  <div class="stat u"><b id="s-u">–</b><span>↑ отдача</span></div>
  <div class="stat sp"><svg id="spark" viewBox="0 0 150 34"><defs><linearGradient id="spg" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#3ee0cb" stop-opacity=".28"/><stop offset="1" stop-color="#3ee0cb" stop-opacity="0"/></linearGradient></defs><path class="sp-a"/><path class="sp-d"/><path class="sp-u"/></svg></div>
 </div>

 <div id="legend" class="glass leg">
  <span><i style="background:var(--me)"></i>Этот Mac</span><span><i style="background:var(--acc)"></i>процесс</span>
  <span><i style="background:var(--wan)"></i>интернет</span><span><i style="background:var(--lan)"></i>LAN</span><span><i style="background:var(--loc)"></i>localhost</span>
 </div>
 <div id="mapleg" class="glass leg" style="display:none">
  <span><i style="background:var(--me)"></i>Этот Mac</span><span><i style="background:var(--wan)"></i>серверы</span>
  <span id="mapstat" class="dim"></span><button id="mapmode">плоская карта</button><button id="geooff" hidden>выключить геолокацию</button>
 </div>

 <div id="zoomctl" class="glass">
  <button id="zin" title="Приблизить"><svg class="i" viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg></button>
  <button id="zout" title="Отдалить"><svg class="i" viewBox="0 0 24 24"><path d="M5 12h14"/></svg></button>
  <button id="zfit" title="Вписать (F)"><svg class="i" viewBox="0 0 24 24"><path d="M8 3H5a2 2 0 0 0-2 2v3m18 0V5a2 2 0 0 0-2-2h-3m0 18h3a2 2 0 0 0 2-2v-3M3 16v3a2 2 0 0 0 2 2h3"/></svg></button>
 </div>

 <div id="settings" class="glass" hidden>
  <div class="st-h"><b>Настройки</b><button id="st-x" title="Закрыть">×</button></div>
  <div class="st-s">Карта</div>
  <div class="st-r"><span>Вид</span><div class="seg mini"><button id="m-globe">3D глобус</button><button id="m-flat">Плоская</button></div></div>
  <div class="st-r"><span>Автовращение глобуса</span><label class="sw"><input type="checkbox" id="c-rot"><i></i></label></div>
  <div class="st-r"><span>Геолокация IP (ip-api.com)</span><label class="sw"><input type="checkbox" id="c-geo"><i></i></label></div>
  <div class="st-s">Граф</div>
  <div class="st-r"><span>Группировать хосты по домену</span><label class="sw"><input type="checkbox" id="c-grp" checked><i></i></label></div>
  <div class="st-r"><span>Показывать localhost</span><label class="sw"><input type="checkbox" id="c-loc"><i></i></label></div>
  <div class="st-r"><span>Подписи всех узлов</span><label class="sw"><input type="checkbox" id="c-lbl"><i></i></label></div>
  <div class="st-r"><span>Обновление данных</span><div class="seg mini"><button id="iv-1000">1 с</button><button id="iv-2000">2 с</button><button id="iv-5000">5 с</button></div></div>
  <div class="st-s">Wi-Fi роутера</div>
  <div class="router"><b>GPON-терминал MA670V3</b> (Photonspeak / Dragon Path GP700)<br>Адрес: <span class="mono" id="rt-ip">…</span>
   <p>Менять имя и пароль Wi-Fi из NetGraph пока нельзя: у этой модели нет документированного интерфейса, а запись вслепую может оставить вас без Wi-Fi и интернета. Откройте админку и поменяйте их в разделе WLAN / Wi-Fi.</p>
   <a class="btn" id="rt-open" target="_blank" rel="noopener" hidden>Открыть админку роутера</a></div>
 </div>
 <div id="mapcard" class="glass card" hidden></div>
 <div id="splash" class="glass card" hidden></div>
 <div id="tip"></div>
</main>

<aside>
 <nav class="tabs">
  <button class="tab on" data-t="node">Узел</button>
  <button class="tab" data-t="geo">Гео</button>
  <button class="tab" data-t="ev">Лог</button>
  <button class="tab" data-t="al">Тревоги<span class="badge" id="b-al" hidden>0</span></button>
  <button class="tab" data-t="hist">История</button>
 </nav>
 <section class="pane on" id="pane-node"></section>
 <section class="pane" id="pane-geo"></section>
 <section class="pane ev" id="pane-ev"></section>
 <section class="pane" id="pane-al"></section>
 <section class="pane" id="pane-hist"></section>
</aside>
</div>

<script>
(async function(){
const $=id=>document.getElementById(id);
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

/* ── загрузка d3 с запасными CDN ── */
function loadScript(urls){
 return urls.reduce((p,u)=>p.catch(()=>new Promise((res,rej)=>{
  const s=document.createElement('script');s.src=u;s.onload=res;s.onerror=()=>{s.remove();rej(new Error(u))};document.head.appendChild(s)})),Promise.reject());
}
try{
 await loadScript(['https://cdnjs.cloudflare.com/ajax/libs/d3/7.9.0/d3.min.js','https://cdn.jsdelivr.net/npm/d3@7.9.0/dist/d3.min.js','https://unpkg.com/d3@7.9.0/dist/d3.min.js']);
}catch(e){
 const s=$('splash');s.hidden=false;
 s.innerHTML='<div class="ic"><svg class="i" viewBox="0 0 24 24"><path d="M12 9v4M12 17h.01"/><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/></svg></div><h3>Не удалось загрузить d3.js</h3><p>Нужен интернет (cdnjs, jsDelivr или unpkg). Проверьте соединение и обновите страницу.</p>';
 return;
}

/* ── общие константы ── */
const css=getComputedStyle(document.documentElement),V=n=>css.getPropertyValue(n).trim();
const COL={me:V('--me'),proc:V('--acc'),wan:V('--wan'),lan:V('--lan'),local:V('--loc')};
const fmt=b=>b<1024?Math.round(b)+' Б/с':b<1048576?(b/1024).toFixed(1)+' КБ/с':(b/1048576).toFixed(1)+' МБ/с';
const flag=cc=>cc&&cc.length===2?String.fromCodePoint(...[...cc.toUpperCase()].map(c=>127397+c.charCodeAt(0))):'🌐';
const ICON={
 ok:'<svg class="i" viewBox="0 0 24 24"><path d="M20 6 9 17l-5-5"/></svg>',
 list:'<svg class="i" viewBox="0 0 24 24"><path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/></svg>',
 globe:'<svg class="i" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/></svg>',
 node:'<svg class="i" viewBox="0 0 24 24"><circle cx="6" cy="12" r="2.5"/><circle cx="18" cy="6" r="2.5"/><circle cx="18" cy="18" r="2.5"/><path d="M8.2 11l7.6-4M8.2 13l7.6 4"/></svg>',
 clock:'<svg class="i" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>'
};
const empty=(ic,t,s)=>`<div class="empty"><div class="ic">${ICON[ic]}</div><div style="color:var(--tx2);font-weight:600">${t}</div><div>${s||''}</div></div>`;
let data=null,view='g',tab='node',paused=false,sel=null,hov=null,firstFit=false;
const flt={grp:true,loc:false};
const tp=[];
const cfg=Object.assign({mode:'globe',rotate:true,labels:false,interval:2000},(()=>{try{return JSON.parse(localStorage.getItem('ng-cfg')||'{}')}catch(e){return{}}})());
const saveCfg=()=>{try{localStorage.setItem('ng-cfg',JSON.stringify(cfg))}catch(e){}};
function showMapSvg(){$('m').style.display=view==='m'&&cfg.mode==='flat'?'':'none';$('gl').style.display=view==='m'&&cfg.mode==='globe'?'':'none'}

/* ── тултип ── */
const tip=$('tip');
function showTip(e,html){tip.innerHTML=html;tip.style.opacity=1;moveTip(e)}
function moveTip(e){
 const r=$('stage').getBoundingClientRect();let x=e.clientX-r.left+16,y=e.clientY-r.top+16;
 const w=tip.offsetWidth,h=tip.offsetHeight;
 if(x+w>r.width-8)x=e.clientX-r.left-w-16;if(y+h>r.height-8)y=e.clientY-r.top-h-16;
 tip.style.transform=`translate(${Math.max(8,x)}px,${Math.max(8,y)}px)`}
const hideTip=()=>{tip.style.opacity=0};

/* ════════════ ГРАФ ════════════ */
const svg=d3.select('#g');
const defs=svg.append('defs');
Object.entries(COL).forEach(([k,c])=>{
 const g=defs.append('radialGradient').attr('id','glow-'+k);
 g.append('stop').attr('offset','0%').attr('stop-color',c).attr('stop-opacity',.55);
 g.append('stop').attr('offset','100%').attr('stop-color',c).attr('stop-opacity',0)});
const root=svg.append('g'),linkG=root.append('g'),nodeG=root.append('g');
let K=1;
const stage=$('stage');
const zoom=d3.zoom().scaleExtent([.15,5]).on('zoom',e=>{
 K=e.transform.k;root.attr('transform',e.transform);svg.classed('zoomed',K>1.5);
 stage.style.setProperty('--gx',e.transform.x+'px');stage.style.setProperty('--gy',e.transform.y+'px');
 stage.style.setProperty('--gk',Math.max(.6,Math.min(1.8,K)))});
svg.call(zoom);
function center(){const r=$('g').getBoundingClientRect();svg.call(zoom.transform,d3.zoomIdentity.translate(r.width/2,r.height/2))}
center();

let nodes=[],links=[],nodeSel=d3.selectAll(null),linkSel=d3.selectAll(null),sig='';
const rad=d=>d.type==='me'?12:d.type==='proc'?7+Math.min(14,Math.sqrt(d.rate/1500))+Math.min(5,d.deg/3):3.5+Math.min(6,Math.sqrt(d.deg)*1.6);
const sim=d3.forceSimulation().alphaDecay(.035)
 .force('link',d3.forceLink().id(d=>d.id).distance(l=>l.source.type==='me'?125:50+Math.min(30,l.target.deg*3)).strength(.7))
 .force('charge',d3.forceManyBody().strength(d=>d.type==='me'?-420:d.type==='proc'?-260:-60))
 .force('x',d3.forceX().strength(.03)).force('y',d3.forceY().strength(.03))
 .force('col',d3.forceCollide(d=>rad(d)+(d.type==='proc'?14:5))).on('tick',tick);

function build(d){
 const q=$('q').value.trim().toLowerCase(),grp=flt.grp,showLoc=flt.loc;
 const nm=new Map(),lm=new Map(),pids={};
 const node=(id,o)=>{let n=nm.get(id);if(!n){n={id,deg:0,rate:0,rin:0,rout:0,info:new Map(),...o};nm.set(id,n)}return n};
 const link=(s,t,kind)=>{const k=s+'>'+t;if(!lm.has(k))lm.set(k,{source:s,target:t,key:k,kind,hot:false})};
 node('me',{label:'Этот Mac',type:'me'});
 d.conns.forEach(c=>{
  if(c.kind==='local'&&!showLoc)return;
  let rl=c.host||c.rip;
  if(grp&&c.host){const p=c.host.split('.');rl=p.length>2?p.slice(-2).join('.'):c.host}
  if(q&&!c.proc.toLowerCase().includes(q)&&!rl.toLowerCase().includes(q))return;
  const p=node('p:'+c.proc,{label:c.proc,type:'proc',listen:new Set()});
  (pids[c.proc]=pids[c.proc]||new Set()).add(c.pid);
  const r=node('r:'+rl,{label:rl,type:c.kind,ips:new Set(),procs:new Set()});
  r.ips.add(c.rip);r.procs.add(c.proc);
  p.info.set(`${rl}|${c.rport}|${c.proto}|${c.state}`,{host:rl,port:c.rport,proto:c.proto,state:c.state});
  r.info.set(`${c.proc}|${c.rport}|${c.proto}|${c.state}`,{host:c.proc,port:c.rport,proto:c.proto,state:c.state});
  p.deg++;r.deg++;
  link('me','p:'+c.proc,'me');link('p:'+c.proc,'r:'+rl,c.kind);
 });
 d.listen.forEach(x=>{const p=nm.get('p:'+x.proc);if(p)p.listen.add(x.port+'/'+x.proto)});
 for(const[name,s]of Object.entries(pids)){
  const p=nm.get('p:'+name);let i=0,o=0;
  s.forEach(pid=>{const r=d.rates[pid];if(r){i+=r[0];o+=r[1]}});
  p.rin=i;p.rout=o;p.rate=i+o;p.pids=s;
 }
 lm.forEach(l=>{const p=nm.get(l.source.startsWith('p:')?l.source:l.target);l.hot=p.rate>200});
 const old=new Map(nodes.map(n=>[n.id,n]));
 nodes=[...nm.values()].map(n=>{const o=old.get(n.id);if(o){n.x=o.x;n.y=o.y;n.vx=o.vx;n.vy=o.vy;n.fx=o.fx;n.fy=o.fy}return n});
 links=[...lm.values()];
 for(let pass=0;pass<2;pass++)links.forEach(l=>{const s=nm.get(l.source),t=nm.get(l.target);
  if(t.x==null&&s.x!=null){t.x=s.x+(Math.random()-.5)*40;t.y=s.y+(Math.random()-.5)*40}});
 if(sel&&!nm.has(sel))sel=null;
 render();
 const ns=nodes.map(n=>n.id).join('|')+'#'+links.length;
 sim.nodes(nodes);sim.force('link').links(links);
 sim.alpha(ns!==sig?.5:.04).restart();sig=ns;
 details();
}

const drag=d3.drag()
 .on('start',(ev,d)=>{if(!ev.active)sim.alphaTarget(.3).restart();d.fx=d.x;d.fy=d.y;hideTip()})
 .on('drag',(ev,d)=>{d.fx=ev.x;d.fy=ev.y})
 .on('end',(ev,d)=>{if(!ev.active)sim.alphaTarget(0);d.fx=d.fy=null});

function tipHtml(n){
 let h=`<b>${esc(n.label)}</b><div class="dim">${n.type==='proc'?'процесс':n.type==='me'?'этот компьютер':n.type==='wan'?'интернет':n.type==='lan'?'локальная сеть':'localhost'}</div>`;
 if(n.type==='proc')h+=`<div>↓ ${fmt(n.rin)} &nbsp; ↑ ${fmt(n.rout)}</div><div class="dim">${n.deg} соед.</div>`;
 else if(n.type!=='me'){h+=`<div class="dim">${n.procs.size} проц. · ${n.deg} соед.</div>`;
  const g=data&&[...n.ips].map(ip=>data.geo[ip]).find(g=>g&&g.country);if(g)h+=`<div>${flag(g.countryCode)} ${esc(g.city||g.country)}</div>`}
 return h}

function render(){
 linkSel=linkG.selectAll('line').data(links,d=>d.key).join('line').attr('class',d=>`l ${d.kind}${d.hot?' hot':''}`).attr('stroke-width',d=>d.hot?1.7:1);
 nodeSel=nodeG.selectAll('g.n').data(nodes,d=>d.id).join(e=>{
  const g=e.append('g').attr('class',d=>'n '+d.type).call(drag);
  g.filter(d=>d.type==='me').each(function(){const s=d3.select(this);s.append('circle').attr('class','ring').attr('r',14);s.append('circle').attr('class','ring r2').attr('r',14)});
  g.append('circle').attr('class','halo');
  g.append('circle').attr('class','core').attr('r',0);
  g.append('text').attr('class','lbl');
  return g});
 nodeSel.classed('sel',d=>d.id===sel).classed('multi',d=>d.type!=='proc'&&d.type!=='me'&&d.procs&&d.procs.size>1);
 nodeSel.select('.halo').attr('r',d=>rad(d)*3).attr('fill',d=>`url(#glow-${d.type})`);
 nodeSel.select('.core').attr('fill',d=>COL[d.type]||COL.wan).transition().duration(450).attr('r',rad);
 nodeSel.select('.lbl').attr('dy',d=>-(rad(d)+6)).text(d=>d.label).attr('class',d=>'lbl '+(d.type==='proc'||d.type==='me'?'p':'r'));
 nodeSel.on('mouseover',(e,d)=>{hov=d.id;focus();showTip(e,tipHtml(d))}).on('mousemove',moveTip)
  .on('mouseout',()=>{hov=null;focus();hideTip()}).on('click',(e,d)=>{e.stopPropagation();select(d.id)});
 focus();
}
function focus(){
 const id=hov||sel;let nb=null;
 if(id){nb=new Set([id]);links.forEach(l=>{const s=l.source.id||l.source,t=l.target.id||l.target;if(s===id)nb.add(t);if(t===id)nb.add(s)})}
 nodeSel.classed('dim',n=>!!nb&&!nb.has(n.id)).classed('focus',n=>!!nb&&nb.has(n.id));
 linkSel.classed('dim',l=>{if(!nb)return false;const s=l.source.id||l.source,t=l.target.id||l.target;return s!==id&&t!==id})
  .classed('focus',l=>{if(!nb)return false;const s=l.source.id||l.source,t=l.target.id||l.target;return s===id||t===id});
}
function tick(){
 linkSel.attr('x1',d=>d.source.x).attr('y1',d=>d.source.y).attr('x2',d=>d.target.x).attr('y2',d=>d.target.y);
 nodeSel.attr('transform',d=>`translate(${d.x},${d.y})`);
}
function select(id){sel=id;nodeSel.classed('sel',d=>d.id===sel);focus();details();setTab('node')}
svg.on('click',()=>select(null));

function fit(animate=true){
 if(!nodes.length)return;const r=$('g').getBoundingClientRect();
 let x0=1e9,y0=1e9,x1=-1e9,y1=-1e9;
 nodes.forEach(n=>{if(n.x==null)return;x0=Math.min(x0,n.x);y0=Math.min(y0,n.y);x1=Math.max(x1,n.x);y1=Math.max(y1,n.y)});
 if(x0>x1)return;
 const w=x1-x0+140,h=y1-y0+190,k=Math.max(.2,Math.min(1.4,Math.min(r.width/w,r.height/h)));
 const t=d3.zoomIdentity.translate(r.width/2,r.height/2+30).scale(k).translate(-(x0+x1)/2,-(y0+y1)/2);
 (animate?svg.transition().duration(700):svg).call(zoom.transform,t);
}

/* ── панель «Узел» ── */
const conRow=(h,port,proto,st)=>{const cls=st==='ESTABLISHED'?'ok':/WAIT|CLOSE|SYN|FIN/.test(st)?'warn':'';
 return `<div class="conn"><span class="mono">${esc(h)}:${esc(port)}</span><span class="tag">${esc(proto)}</span><span class="tag ${cls}">${esc(st)}</span></div>`};
function topProcs(){
 const ps=nodes.filter(x=>x.type==='proc').sort((a,b)=>b.rate-a.rate||b.deg-a.deg).slice(0,10),mx=Math.max(1,...ps.map(p=>p.rate));
 return '<div class="sec-t">Топ процессов</div>'+(ps.length?ps.map(p=>`<div class="row click" data-id="${esc(p.id)}"><i class="dotc" style="color:${COL.proc};background:${COL.proc}"></i><div class="grow"><div class="rw"><span class="nm">${esc(p.label)}</span><span class="dim">${p.rate>1?fmt(p.rate):p.deg+' соед.'}</span></div><div class="bar"><i style="width:${Math.max(3,p.rate/mx*100)}%;background:${COL.proc}"></i></div></div></div>`).join(''):empty('node','Нет соединений','Попробуйте убрать фильтр или запустить с sudo'))}
function details(){
 const el=$('pane-node'),n=sel&&nodes.find(x=>x.id===sel);let h='';
 if(!n||n.type==='me'){h=topProcs()+'<p class="hint">Нажмите на узел графа, чтобы увидеть подробности. Колёсико — масштаб, перетаскивание — перемещение.</p>'}
 else{
  const c=COL[n.type]||COL.wan;
  const hd=sub=>`<div class="hd"><i class="dotc big" style="color:${c};background:${c}"></i><div><div class="ttl">${esc(n.label)}</div><div class="dim">${sub}</div></div></div>`;
  if(n.type==='proc'){
   h+=hd(`${n.pids?[...n.pids].map(p=>'PID '+p).slice(0,3).join(', '):''}${n.pids&&n.pids.size>3?' …':''}`);
   h+=`<div class="rates"><div class="rate d"><span>↓ приём</span><b>${fmt(n.rin||0)}</b></div><div class="rate u"><span>↑ отдача</span><b>${fmt(n.rout||0)}</b></div></div>`;
   if(n.listen&&n.listen.size)h+=`<div class="sec-t">Слушает</div><div class="chips">${[...n.listen].slice(0,14).map(x=>`<span class="pill">${esc(x)}</span>`).join('')}</div>`;
   h+=`<div class="sec-t">Соединения · ${n.info.size}</div>`+[...n.info.values()].slice(0,80).map(i=>conRow(i.host,i.port,i.proto,i.state)).join('');
  }else{
   h+=hd(n.type==='wan'?'интернет':n.type==='lan'?'локальная сеть':'localhost');
   const g=data&&[...n.ips].map(ip=>data.geo[ip]).find(g=>g&&g.country);
   if(g)h+=`<div class="geo"><div class="big">${flag(g.countryCode)} ${esc(g.city?g.city+', ':'')}${esc(g.country)}</div><div class="dim">${esc(g.org||'')}</div></div>`;
   h+=`<div class="chips" style="margin-bottom:6px">${[...n.ips].slice(0,6).map(x=>`<span class="pill">${esc(x)}</span>`).join('')}</div>`;
   h+=`<div class="sec-t">Процессы · ${n.procs.size}</div>`+[...n.procs].map(p=>`<div class="row click" data-id="${esc('p:'+p)}"><i class="dotc" style="color:${COL.proc};background:${COL.proc}"></i><span class="nm">${esc(p)}</span></div>`).join('');
   h+=`<div class="sec-t">Соединения</div>`+[...n.info.values()].slice(0,60).map(i=>conRow(i.host,i.port,i.proto,i.state)).join('');
  }
 }
 if(el._h!==h){const st=el.scrollTop;el.innerHTML=h;el.scrollTop=st;el._h=h}
}
$('pane-node').addEventListener('click',e=>{const r=e.target.closest('[data-id]');if(r&&nodes.some(n=>n.id===r.dataset.id))select(r.dataset.id)});

/* ════════════ КАРТА ════════════ */
const msvg=d3.select('#m'),md=msvg.append('defs');
const og=md.append('radialGradient').attr('id','ocean').attr('cx','50%').attr('cy','38%').attr('r','80%');
og.append('stop').attr('offset','0%').attr('stop-color','#16203a');og.append('stop').attr('offset','100%').attr('stop-color','#090c14');
const mroot=msvg.append('g');
const gOcean=mroot.append('path').attr('class','ocean'),gGrat=mroot.append('path').attr('class','grat'),gLand=mroot.append('path').attr('class','land');
const gArcs=mroot.append('g'),gPts=mroot.append('g'),gMe=mroot.append('g');
let mproj=null,mpath=null,mk=1,landFC=null,worldState='idle';
const mZoom=d3.zoom().scaleExtent([1,14]).on('zoom',e=>{mk=e.transform.k;mroot.attr('transform',e.transform);markScale()});
msvg.call(mZoom);
function markScale(){
 gPts.selectAll('.dot').attr('r',p=>p.r/mk);gPts.selectAll('.pulse').attr('r',p=>p.r/mk);
 gMe.selectAll('.me-dot').attr('r',6/mk);gMe.selectAll('.me-ring').attr('r',6/mk);
 gMe.selectAll('text').style('font-size',(11.5/mk)+'px').attr('dy',-13/mk);
}
/* TopoJSON → GeoJSON без внешних библиотек */
function topoFeature(t,obj){
 const [sx,sy]=t.transform?t.transform.scale:[1,1],[tx,ty]=t.transform?t.transform.translate:[0,0];
 const arcs=t.arcs.map(a=>{let x=0,y=0;return a.map(p=>{if(!t.transform)return p;x+=p[0];y+=p[1];return [x*sx+tx,y*sy+ty]})});
 const arc=i=>i<0?arcs[~i].slice().reverse():arcs[i];
 const ring=r=>{const out=[];r.forEach((i,k)=>{const a=arc(i);for(let j=k?1:0;j<a.length;j++)out.push(a[j])});return out};
 const geom=g=>g.type==='Polygon'?{type:'Polygon',coordinates:g.arcs.map(ring)}:{type:'MultiPolygon',coordinates:g.arcs.map(p=>p.map(ring))};
 return {type:'FeatureCollection',features:obj.geometries.filter(g=>g.arcs).map(g=>({type:'Feature',properties:g.properties||{},geometry:geom(g)}))};
}
async function loadWorld(force){
 if(landFC||(worldState==='loading'))return;worldState='loading';
 const srcs=['/world.json','https://cdn.jsdelivr.net/npm/world-atlas@2.0.2/countries-110m.json','https://unpkg.com/world-atlas@2.0.2/countries-110m.json'];
 for(const u of srcs){
  try{const r=await fetch(u);if(!r.ok)continue;const t=await r.json();
   landFC=topoFeature(t,t.objects.countries);worldState='ok';if(cfg.mode==='flat')mapLayout();data&&drawMap(data);return}catch(e){}
 }
 worldState='fail';data&&drawMap(data);
}
function mapLayout(){
 const r=$('m').getBoundingClientRect();if(r.width<50||r.height<50)return false;
 mproj=d3.geoNaturalEarth1().fitExtent([[18,92],[r.width-18,r.height-64]],{type:'Sphere'});
 mpath=d3.geoPath(mproj);
 gOcean.attr('d',mpath({type:'Sphere'}));gGrat.attr('d',mpath(d3.geoGraticule10()));
 if(landFC)gLand.attr('d',mpath(landFC));
 mZoom.extent([[0,0],[r.width,r.height]]).translateExtent([[0,0],[r.width,r.height]]);
 return true;
}
function setCard(html){const c=$('mapcard');if(!html){c.hidden=true;return}if(c._h!==html){c.innerHTML=html;c._h=html}c.hidden=false}
async function setGeo(on){try{await fetch('/geo',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({on})});poll()}catch(e){}}
$('geooff').onclick=()=>setGeo(false);
$('mapcard').addEventListener('click',e=>{if(e.target.closest('#geo-on'))setGeo(true);if(e.target.closest('#world-retry')){worldState='idle';loadWorld()}});

function geoModel(d){
 const q=$('q').value.trim().toLowerCase(),wan=new Set(),loc=new Set(),pts=new Map();
 d.conns.forEach(c=>{
  if(c.kind!=='wan')return;
  if(q&&!c.proc.toLowerCase().includes(q)&&!(c.host||c.rip).toLowerCase().includes(q))return;
  wan.add(c.rip);const g=d.geo[c.rip];if(!g||g.lat==null)return;
  loc.add(c.rip);const k=g.lat+','+g.lon;let p=pts.get(k);
  if(!p){p={key:k,g,n:0,names:new Set(),procs:new Set()};pts.set(k,p)}
  p.n++;p.names.add(c.host||c.rip);p.procs.add(c.proc)});
 const arr=[...pts.values()];arr.forEach(p=>p.r=4+Math.sqrt(p.n)*1.7);
 return {q,wan,loc,arr,me:d.me&&d.me.lat!=null?[d.me.lon,d.me.lat]:null};
}
const ptTip=(e,p)=>showTip(e,`<b>${flag(p.g.countryCode)} ${esc(p.g.city||p.g.country||'')}${p.g.city?', '+esc(p.g.country):''}</b><div class="dim">${esc(p.g.org||'')}</div><div>${[...p.names].slice(0,4).map(esc).join('<br>')}</div><div class="dim">${[...p.procs].slice(0,5).map(esc).join(', ')} · ${p.n} соед.</div>`);
const ptJoin=(layer,arr)=>{
 const P=layer.selectAll('g.pt').data(arr,p=>p.key).join(e=>{const g=e.append('g').attr('class','pt');g.append('circle').attr('class','pulse');g.append('circle').attr('class','dot');return g});
 P.select('.dot').on('mouseover',ptTip).on('mousemove',moveTip).on('mouseout',hideTip);return P};
const meJoin=(layer,me)=>layer.selectAll('g.me').data(me?[me]:[]).join(e=>{const g=e.append('g').attr('class','me');g.append('circle').attr('class','me-ring');g.append('circle').attr('class','me-dot');g.append('text').text('Вы');return g});

/* плоская карта */
function drawFlat(arr,me){
 gArcs.selectAll('path').data(me?arr:[],p=>p.key).join('path').attr('class','arc')
  .attr('d',p=>mpath({type:'LineString',coordinates:[me,[p.g.lon,p.g.lat]]}));
 ptJoin(gPts,arr).attr('transform',p=>{const xy=mproj([p.g.lon,p.g.lat]);return `translate(${xy[0]},${xy[1]})`});
 meJoin(gMe,me).attr('transform',m=>{const xy=mproj(m);return `translate(${xy[0]},${xy[1]})`});
 markScale();
}

/* 3D-глобус */
const gsvg=d3.select('#gl'),gd=gsvg.append('defs');
const gstop=(g,o,c,a)=>g.append('stop').attr('offset',o).attr('stop-color',c).attr('stop-opacity',a);
const sg=gd.append('radialGradient').attr('id','sphere').attr('cx','38%').attr('cy','30%').attr('r','85%');
gstop(sg,'0%','#24376a',1);gstop(sg,'55%','#0f1a36',1);gstop(sg,'100%','#050813',1);
const ag=gd.append('radialGradient').attr('id','atmo');
gstop(ag,'76%','#7aa2ff',0);gstop(ag,'86%','#7aa2ff',.38);gstop(ag,'100%','#7aa2ff',0);
const hg=gd.append('radialGradient').attr('id','shade').attr('cx','36%').attr('cy','28%').attr('r','82%');
gstop(hg,'0%','#fff',.14);gstop(hg,'42%','#fff',0);gstop(hg,'78%','#000',.28);gstop(hg,'100%','#000',.62);
const glSt=gsvg.append('g'),glAtmo=gsvg.append('circle').attr('fill','url(#atmo)').style('pointer-events','none'),
 glSph=gsvg.append('circle').attr('fill','url(#sphere)').attr('stroke','rgba(150,180,255,.3)'),
 glGr=gsvg.append('path').attr('class','grat').attr('fill','none'),glLd=gsvg.append('path').attr('class','land'),
 glSh=gsvg.append('circle').attr('fill','url(#shade)').style('pointer-events','none'),
 glA=gsvg.append('g'),glP=gsvg.append('g'),glM=gsvg.append('g');
const gproj=d3.geoOrthographic().clipAngle(90).precision(.5),grat10=d3.geoGraticule10();
let gk=1,rot=[-30,-20,0],rotInit=false,dragging=false,lastInt=0,glMe=null,glStFor='';
const homeRot=m=>[-m[0],-m[1]*.8-4,0];
function arcPath(a,b){
 const ip=d3.geoInterpolate(a,b),alt=Math.min(.42,.07+d3.geoDistance(a,b)*.2),c=gproj.translate(),ctr=[-rot[0],-rot[1]];
 let d='',pen=false;const N=44;
 for(let i=0;i<=N;i++){
  const t=i/N,pt=ip(t);
  if(d3.geoDistance(pt,ctr)>1.54){pen=false;continue}
  const xy=gproj(pt);if(!xy){pen=false;continue}
  const k=1+alt*Math.sin(Math.PI*t);
  d+=(pen?'L':'M')+(c[0]+(xy[0]-c[0])*k).toFixed(1)+','+(c[1]+(xy[1]-c[1])*k).toFixed(1);pen=true}
 return d||null}
function frameGlobe(){
 const r=$('gl').getBoundingClientRect();if(r.width<50||r.height<50)return;
 const R=Math.min(r.width-80,r.height-210)*.5*gk,cx=r.width/2,cy=r.height/2+42;
 gproj.translate([cx,cy]).scale(Math.max(R,40)).rotate(rot);
 const path=d3.geoPath(gproj),ctr=[-rot[0],-rot[1]],Rr=gproj.scale();
 const key=Math.round(r.width)+'x'+Math.round(r.height);
 if(glStFor!==key){glStFor=key;const rnd=d3.randomLcg(42);
  glSt.selectAll('circle').data(d3.range(130)).join('circle').attr('cx',()=>rnd()*r.width).attr('cy',()=>rnd()*r.height).attr('r',()=>.4+rnd()*1.1).attr('fill','#fff').attr('opacity',()=>.08+rnd()*.5)}
 glAtmo.attr('cx',cx).attr('cy',cy).attr('r',Rr*1.17);
 glSph.attr('cx',cx).attr('cy',cy).attr('r',Rr);glSh.attr('cx',cx).attr('cy',cy).attr('r',Rr);
 glGr.attr('d',path(grat10));if(landFC)glLd.attr('d',path(landFC));
 const place=function(lonlat){const sel=d3.select(this);
  const vis=d3.geoDistance(lonlat,ctr)<1.52,xy=vis&&gproj(lonlat);
  sel.attr('display',xy?null:'none');if(xy)sel.attr('transform',`translate(${xy[0]},${xy[1]})`)};
 glP.selectAll('g.pt').each(function(p){place.call(this,[p.g.lon,p.g.lat])});
 glM.selectAll('g.me').each(function(m){place.call(this,m)});
 glA.selectAll('path').attr('d',p=>glMe?arcPath(glMe,[p.g.lon,p.g.lat]):null);
}
function drawGlobe(arr,me){
 glMe=me;if(me&&!rotInit){rot=homeRot(me);rotInit=true}
 glA.selectAll('path').data(me?arr:[],p=>p.key).join('path').attr('class','arc');
 const P=ptJoin(glP,arr);P.select('.dot').attr('r',p=>p.r);P.select('.pulse').attr('r',p=>p.r);
 const M=meJoin(glM,me);M.select('.me-dot').attr('r',6);M.select('.me-ring').attr('r',6);M.select('text').attr('dy',-13).style('font-size','11.5px');
 frameGlobe();
}
gsvg.call(d3.drag().on('start',()=>{dragging=true;lastInt=Date.now();hideTip()})
 .on('drag',e=>{rot[0]+=e.dx*.3/gk;rot[1]=Math.max(-88,Math.min(88,rot[1]-e.dy*.3/gk));lastInt=Date.now();frameGlobe()})
 .on('end',()=>{dragging=false;lastInt=Date.now()}));
gsvg.on('wheel',e=>{e.preventDefault();gk=Math.max(.6,Math.min(3.2,gk*(e.deltaY<0?1.1:.91)));lastInt=Date.now();frameGlobe()},{passive:false});
(function spin(){
 if(view==='m'&&cfg.mode==='globe'&&cfg.rotate&&!dragging&&!paused&&!document.hidden&&Date.now()-lastInt>2500){rot[0]+=.07;frameGlobe()}
 requestAnimationFrame(spin)})();

function drawMap(d){
 try{
 const flat=cfg.mode==='flat';
 if(flat&&!mproj&&!mapLayout())return;
 const {q,wan,loc,arr,me}=geoModel(d);
 flat?drawFlat(arr,me):drawGlobe(arr,me);

 /* состояние и подсказки */
 const countries=new Set(arr.map(p=>p.g.country));
 $('mapstat').textContent=d.geo_on?`${arr.length} точек · ${countries.size} стран · ${loc.size}/${wan.size} IP`+(worldState==='fail'?' · контуры стран не загрузились':''):'';
 $('geooff').hidden=!d.geo_on||d.demo;
 let card='';
 if(!d.geo_on){
  card=`<div class="ic">${ICON.globe}</div><h3>Геолокация выключена</h3><p>Чтобы показать, где находятся серверы, внешние IP ваших соединений нужно отправить в сервис ip-api.com (по HTTP, без шифрования). Локальные адреса не отправляются.</p><button class="btn" id="geo-on">Включить геолокацию</button><div class="fine">Или запустите скрипт с флагом <b>--geo</b></div>`;
 }else if(!wan.size){
  card=`<div class="ic">${ICON.globe}</div><h3>Нет внешних соединений</h3><p>${q?'Под фильтр ничего не подходит.':'Как только появятся соединения с интернетом, они отобразятся на карте.'}</p>`;
 }else if(!arr.length&&d.geo_err){
  card=`<div class="ic">${ICON.globe}</div><h3>Не получается определить расположение</h3><p>ip-api.com не отвечает или ограничил запросы. Повторю попытку автоматически.</p><div class="fine mono">${esc(d.geo_err)}</div>`;
 }else if(!arr.length){
  card=`<div class="spin" style="margin:0 auto"></div><h3>Определяю расположение серверов…</h3><p>Осталось адресов: ${d.geo_pending||wan.size}</p>`;
 }else if(worldState==='fail'){
  card=`<h3>Контуры стран не загрузились</h3><p>Точки показаны, но без подложки. Проверьте интернет.</p><button class="btn ghost" id="world-retry">Повторить</button>`;
 }
 setCard(card);
 renderGeo(arr,d);
 }catch(e){console.error('drawMap',e)}
}
function renderGeo(arr,d){
 const el=$('pane-geo');let h='';
 if(!d.geo_on)h=empty('globe','Геолокация выключена','Включите её на вкладке «Карта»');
 else if(!arr.length)h=empty('globe','Пока нет данных','Адреса определяются…');
 else{
  const cm=new Map();arr.forEach(p=>{const k=p.g.country||'?';let c=cm.get(k);if(!c){c={name:k,cc:p.g.countryCode,n:0,cities:new Set()};cm.set(k,c)}c.n+=p.n;if(p.g.city)c.cities.add(p.g.city)});
  const cs=[...cm.values()].sort((a,b)=>b.n-a.n),mx=cs[0].n;
  h+='<div class="sec-t">Страны</div>'+cs.map(c=>`<div class="row"><span style="font-size:20px;line-height:1">${flag(c.cc)}</span><div class="grow"><div class="rw"><span class="nm">${esc(c.name)}</span><span class="dim">${c.n}</span></div><div class="bar"><i style="width:${c.n/mx*100}%;background:${COL.wan}"></i></div><div class="dim nm" style="font-size:11px;margin-top:3px">${[...c.cities].slice(0,4).map(esc).join(', ')}</div></div></div>`).join('');
  h+='<div class="sec-t">Серверы</div>'+[...arr].sort((a,b)=>b.n-a.n).slice(0,14).map(p=>`<div class="row"><i class="dotc" style="color:${COL.wan};background:${COL.wan}"></i><div class="grow"><div class="nm">${esc([...p.names][0])}${p.names.size>1?' <span class="dim">+'+(p.names.size-1)+'</span>':''}</div><div class="dim nm" style="font-size:11px">${esc(p.g.org||'')} · ${esc([...p.procs].slice(0,3).join(', '))}</div></div></div>`).join('');
 }
 const e2=$('pane-geo');if(e2._h!==h){e2.innerHTML=h;e2._h=h}
}

/* ════════════ ОБЩЕЕ: вкладки, HUD, опрос ════════════ */
function setTab(t){tab=t;document.querySelectorAll('.tab').forEach(b=>b.classList.toggle('on',b.dataset.t===t));
 document.querySelectorAll('.pane').forEach(p=>p.classList.toggle('on',p.id==='pane-'+t));if(t==='hist')loadHistory()}
document.querySelectorAll('.tab').forEach(b=>b.onclick=()=>setTab(b.dataset.t));

function setView(v){
 view=v;$('g').style.display=v==='g'?'':'none';showMapSvg();
 stage.classList.toggle('map',v==='m');$('vg').classList.toggle('on',v==='g');$('vm').classList.toggle('on',v==='m');
 $('legend').style.display=v==='g'?'':'none';$('mapleg').style.display=v==='m'?'':'none';
 hideTip();
 if(v==='m'){sim.stop();loadWorld();if(cfg.mode==='flat')mapLayout();data&&drawMap(data);setTab('geo')}
 else{setCard('');data&&build(data);if(tab==='geo')setTab('node')}
}
$('vg').onclick=()=>setView('g');$('vm').onclick=()=>setView('m');
const refresh=()=>{if(!data)return;view==='g'?build(data):drawMap(data)};
$('q').addEventListener('input',refresh);
const setFlag=(k,v)=>{flt[k]=v;$(k).classList.toggle('on',v);const c=$('c-'+k);if(c)c.checked=v;refresh()};
$('grp').onclick=()=>setFlag('grp',!flt.grp);$('loc').onclick=()=>setFlag('loc',!flt.loc);
$('pause').onclick=()=>{paused=!paused;$('pause').classList.toggle('on',paused);
 $('pause').querySelector('span').textContent=paused?'Продолжить':'Пауза';
 $('pi').innerHTML=paused?'<path d="M7 4.5l12 7.5-12 7.5z"/>':'<rect x="6" y="4.5" width="4" height="15" rx="1"/><rect x="14" y="4.5" width="4" height="15" rx="1"/>';
 if(!paused)refresh()};
const zbtn=f=>()=>{if(view==='g')svg.transition().duration(250).call(zoom.scaleBy,f);else if(cfg.mode==='flat')msvg.transition().duration(250).call(mZoom.scaleBy,f);else{gk=Math.max(.6,Math.min(3.2,gk*f));frameGlobe()}};
$('zin').onclick=zbtn(1.5);$('zout').onclick=zbtn(1/1.5);
$('zfit').onclick=()=>{if(view==='g')fit();else if(cfg.mode==='flat')msvg.transition().duration(500).call(mZoom.transform,d3.zoomIdentity);else{gk=1;if(glMe)rot=homeRot(glMe);frameGlobe()}};
document.addEventListener('keydown',e=>{
 if(e.target.tagName==='INPUT'){if(e.key==='Escape'){e.target.value='';e.target.blur();refresh()}return}
 if(e.metaKey||e.ctrlKey||e.altKey)return;
 if(e.key==='/'){e.preventDefault();$('q').focus()}
 else if(e.key==='g')setView('g');else if(e.key==='m')setView('m');
 else if(e.key==='p')$('pause').click();else if(e.key==='f')$('zfit').click();
 else if(e.key==='s')toggleSettings();else if(e.key==='Escape'){select(null);toggleSettings(false)}
});
new ResizeObserver(()=>{if(view!=='m')return;if(cfg.mode==='flat'){if(mapLayout()&&data)drawMap(data)}else frameGlobe()}).observe(stage);

/* HUD */
const sp=d3.select('#spark'),spA=sp.select('.sp-a'),spD=sp.select('.sp-d'),spU=sp.select('.sp-u');
function spark(){
 const W=150,H=34,n=tp.length,mx=Math.max(1,...tp.flat());
 const x=d3.scaleLinear([0,Math.max(1,n-1)],[0,W]),y=d3.scaleLinear([0,mx],[H-2,3]);
 const ln=k=>d3.line().curve(d3.curveMonotoneX).x((_,i)=>x(i)).y(h=>y(h[k]))(tp);
 spD.attr('d',ln(0));spU.attr('d',ln(1));
 spA.attr('d',d3.area().curve(d3.curveMonotoneX).x((_,i)=>x(i)).y0(H).y1(h=>y(h[0]))(tp));
}
function hud(d){
 let i=0,o=0;Object.values(d.rates).forEach(v=>{i+=v[0];o+=v[1]});
 tp.push([i,o]);if(tp.length>60)tp.shift();
 $('s-c').textContent=d.conns.length;$('s-p').textContent=new Set(d.conns.map(c=>c.proc)).size;
 $('s-h').textContent=new Set(d.conns.filter(c=>c.kind!=='local').map(c=>c.rip)).size;
 $('s-d').textContent=fmt(i);$('s-u').textContent=fmt(o);spark();
}
function setLive(ok){$('live').classList.toggle('off',!ok);$('live').title=ok?'Данные поступают':'Нет связи с сервером'}

/* Лог / тревоги / история */
function eventsUI(ev){
 const h=ev&&ev.length?ev.map(e=>`<div><span class="dim">${esc(e.t)}</span> <span class="p ${e.s==='+'?'add':'del'}">${e.s==='+'?'+':'−'}</span> ${esc(e.proc)} <span class="dim">→</span> ${esc(e.remote)}<span class="dim">:${esc(e.port)}</span></div>`).join(''):empty('list','Событий пока нет','Здесь будут появляться новые и закрытые соединения');
 const el=$('pane-ev');if(el._h!==h){el.innerHTML=h;el._h=h}
}
let lastAl=-1;
function alertsUI(a){
 a=a||[];const b=$('b-al');b.textContent=a.length;b.hidden=!a.length;
 const h=a.length?'<div class="hint" style="margin:0 2px 12px">Процесс впервые подключился к новому домену. Первые 10 минут на чистой базе — режим обучения.</div>'+a.map(x=>`<div class="alert"><div class="rw"><b>${esc(x.proc)}</b><span class="dim">${esc(x.t)}</span></div><div>→ ${esc(x.remote)}</div><div class="dim mono">${esc(x.ip)}</div></div>`).join(''):empty('ok','Всё спокойно','Новых соединений процессов с неизвестными доменами нет');
 const el=$('pane-al');if(el._h!==h){el.innerHTML=h;el._h=h}
}
let hrs=24;
async function loadHistory(){
 const el=$('pane-hist');
 try{
  const h=await (await fetch('/history?h='+hrs)).json(),mx=Math.max(1,...h.top.map(r=>r[2]));
  const ago=t=>{const m=Math.round((Date.now()/1000-t)/60);return m<60?m+' мин назад':m<1440?Math.round(m/60)+' ч назад':Math.round(m/1440)+' дн назад'};
  el.innerHTML=`<div class="pills">${[[1,'1 час'],[24,'24 часа'],[168,'7 дней']].map(([v,t])=>`<button data-h="${v}" class="${v===hrs?'on':''}">${t}</button>`).join('')}</div>`+
   '<div class="sec-t">Чаще всего</div>'+(h.top.length?h.top.slice(0,12).map(r=>`<div class="row"><div class="grow"><div class="rw"><span class="nm">${esc(r[0])} <span class="dim">→ ${esc(r[1])}</span></span><span class="dim">×${r[2]}</span></div><div class="bar"><i style="width:${r[2]/mx*100}%;background:${COL.proc}"></i></div></div></div>`).join(''):empty('clock','Нет данных','История накапливается по мере работы'))+
   '<div class="sec-t">Впервые за период</div>'+(h.new.length?h.new.slice(0,12).map(r=>`<div class="row"><i class="dotc" style="color:${COL.lan};background:${COL.lan}"></i><div class="grow nm">${esc(r[0])} <span class="dim">→ ${esc(r[1])}</span></div><span class="dim" style="font-size:11px">${ago(r[2])}</span></div>`).join(''):'<div class="dim" style="padding:6px 9px">нет</div>');
 }catch(e){}
}
$('pane-hist').addEventListener('click',e=>{const b=e.target.closest('[data-h]');if(b){hrs=+b.dataset.h;loadHistory()}});

async function poll(){
 try{
  data=await (await fetch('/data')).json();setLive(true);
  const cg=$('c-geo');if(document.activeElement!==cg)cg.checked=!!data.geo_on;cg.disabled=!!data.demo;
  hud(data);alertsUI(data.alerts);eventsUI(data.events);
  if(!paused){
   if(view==='g'){build(data);if(!firstFit&&nodes.length>1){firstFit=true;setTimeout(()=>fit(),1400)}}
   else drawMap(data);
  }
 }catch(e){setLive(false);console.error(e)}
}
details();eventsUI([]);alertsUI([]);
(async function pollLoop(){await poll();setTimeout(pollLoop,cfg.interval)})();setInterval(()=>{if(tab==='hist')loadHistory()},15000);
/* ── настройки ── */
const stp=$('settings');
function syncCfg(){
 $('m-globe').classList.toggle('on',cfg.mode==='globe');$('m-flat').classList.toggle('on',cfg.mode==='flat');
 $('c-rot').checked=cfg.rotate;$('c-lbl').checked=cfg.labels;svg.classed('alllbl',cfg.labels);
 [1000,2000,5000].forEach(v=>$('iv-'+v).classList.toggle('on',cfg.interval===v));
 $('mapmode').textContent=cfg.mode==='globe'?'плоская карта':'3D глобус';
}
function setMode(m){cfg.mode=m;saveCfg();syncCfg();showMapSvg();if(view==='m'){if(m==='flat')mapLayout();data&&drawMap(data)}}
$('m-globe').onclick=()=>setMode('globe');$('m-flat').onclick=()=>setMode('flat');
$('mapmode').onclick=()=>setMode(cfg.mode==='globe'?'flat':'globe');
$('c-rot').onchange=e=>{cfg.rotate=e.target.checked;saveCfg()};
$('c-lbl').onchange=e=>{cfg.labels=e.target.checked;saveCfg();syncCfg()};
$('c-grp').onchange=e=>setFlag('grp',e.target.checked);$('c-loc').onchange=e=>setFlag('loc',e.target.checked);
$('c-geo').onchange=e=>setGeo(e.target.checked);
[1000,2000,5000].forEach(v=>$('iv-'+v).onclick=()=>{cfg.interval=v;saveCfg();syncCfg()});
let gwLoaded=false;
async function loadGw(){try{const g=await (await fetch('/gateway')).json();gwLoaded=true;
 $('rt-ip').textContent=g.ip||'не определён';if(g.ip){$('rt-open').href='http://'+g.ip;$('rt-open').hidden=false}}catch(e){}}
function toggleSettings(on){stp.hidden=on===undefined?!stp.hidden:!on;$('cog').classList.toggle('on',!stp.hidden);if(!stp.hidden&&!gwLoaded)loadGw()}
$('cog').onclick=()=>toggleSettings();$('st-x').onclick=()=>toggleSettings(false);
syncCfg();
window.__ng={setView,select,setTab,fit,setMode,toggleSettings};
})();
</script></body></html>"""


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
    ap.add_argument("--demo", action="store_true", help="демо-данные (без lsof/nettop и без обращения в сеть)")
    ap.add_argument("--no-open", action="store_true", help="не открывать браузер")
    ap.add_argument("--port", type=int, default=PORT)
    a = ap.parse_args()
    ARGS.port, ARGS.demo = a.port, a.demo
    ARGS.geo = a.geo or a.demo or os.path.exists(GEO_FLAG)
    if a.install_agent:
        install_agent()
        sys.exit()
    if a.demo:
        threading.Thread(target=demo_loop, daemon=True).start()
    else:
        threading.Thread(target=loop, daemon=True).start()
        threading.Thread(target=geo_loop, daemon=True).start()
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), H)
    url = f"http://127.0.0.1:{a.port}"
    print("NetGraph:", url, "(Ctrl+C для выхода)")
    if a.menubar:
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        menubar(url)
    else:
        if not a.no_open:
            webbrowser.open(url)
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            pass
