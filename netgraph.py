#!/usr/bin/env python3
"""NetGraph: граф сетевой активности Mac в стиле Obsidian.
Запуск:  sudo python3 netgraph.py [--geo] [--menubar] [--install-agent] [--demo] [--rt-port N]
(без sudo видны только ваши процессы)
Открыть: http://127.0.0.1:8765
Зависимости: только стандартная библиотека Python 3 (macOS: lsof, nettop).
Интерфейс подгружает d3.js с CDN (cdnjs / jsDelivr / unpkg) — нужен интернет.

  --geo    включить геолокацию IP на карте (можно и кнопкой прямо на карте)
  --demo   демо-данные без lsof/nettop — удобно посмотреть интерфейс
"""
import subprocess, re, json, time, threading, socket, webbrowser, collections, ipaddress
import sqlite3, os, sys, argparse, urllib.request, urllib.parse, urllib.error, random, math, base64, http.cookiejar, csv, io
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from concurrent.futures import ThreadPoolExecutor

PORT = 8765
LSOF = re.compile(r'^(\S+)\s+(\d+)\s+(\S+)\s+\S+\s+(IPv[46])\s+\S+\s+\S+\s+(TCP|UDP)\s+(.*)$')
lock = threading.Lock()
state = {"conns": [], "listen": [], "rates": {}, "totals": {}}
events = collections.deque(maxlen=300)
dns = {}
pool = ThreadPoolExecutor(8)
ARGS = argparse.Namespace(geo=False, port=PORT, demo=False, rt_port=0)
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
CREATE INDEX IF NOT EXISTS lt ON log(t);
CREATE TABLE IF NOT EXISTS devices(mac TEXT PRIMARY KEY,ip TEXT,name TEXT,first REAL,last REAL);
CREATE TABLE IF NOT EXISTS outages(start REAL,end REAL);""")
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
        if proc in (CONFIG.get("trusted") or []):
            continue
        alerts.appendleft(dict(t=time.strftime("%H:%M:%S"), kind="conn", proc=proc, remote=lab, ip=ip))
        notify("NetGraph: новое соединение", proc, lab)


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
            for p, v in b.items():
                if p in pb:
                    sess["in"] += max(0, v[0] - pb[p][0])
                    sess["out"] += max(0, v[1] - pb[p][1])
            pb, pt = b, now
            keys = {(c["proc"], c["rip"], c["rport"], c["lport"]): c for c in conns}
            if prev is not None:
                for k in keys.keys() - prev.keys():
                    add_event("+", keys[k])
                for k in prev.keys() - keys.keys():
                    add_event("-", prev[k])
            prev = keys
            with lock:
                state.update(conns=conns, listen=listen, rates=rates, totals=dict(b))
            check_pairs(conns)
            check_rules(rates, conns)
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



def demo_net(t, rnd):
    now = time.time()
    if not lan:
        lan_state.update(ip="192.168.1.23", gw="192.168.1.1")
        for i, (ip, mac, name, host) in enumerate([
                ("192.168.1.1", "a4:2b:b0:11:22:33", "", "router.lan"), ("192.168.1.12", "3c:22:fb:aa:bb:01", "iPhone Ани", "anis-iphone.lan"),
                ("192.168.1.15", "f0:18:98:cc:dd:02", "MacBook Pro", "macbook-pro.lan"), ("192.168.1.20", "9a:5e:77:12:34:56", "", ""),
                ("192.168.1.31", "b8:27:eb:44:55:66", "Raspberry Pi", "raspberrypi.lan"), ("192.168.1.40", "7c:2e:bd:77:88:99", "Smart TV", "lg-webos.lan"),
                ("192.168.1.57", "d2:4f:91:0a:0b:0c", "", "")]):
            lan[mac] = dict(mac=mac, ip=ip, name=name, first=now - 86400 * (i + 1), last=now, flag_new=False)
            if host:
                dns[ip] = host
        lan["d2:4f:91:0a:0b:0c"].update(first=now - 120, flag_new=True)
        alerts.appendleft(dict(t=time.strftime("%H:%M:%S"), kind="device", proc="192.168.1.57", remote="d2:4f:91:0a:0b:0c", ip="192.168.1.57", mac="d2:4f:91:0a:0b:0c"))
    for i, d in enumerate(lan.values()):
        d["last"] = now - (rnd.randint(0, 20) if i % 3 else rnd.randint(30, 400))
    net_q["gw"].append(None if rnd.random() < .03 else 1.5 + abs(math.sin(t / 4)) * 3 + rnd.random() * 2)
    net_q["inet"].append(None if rnd.random() < .05 else 18 + abs(math.sin(t / 7)) * 30 + rnd.random() * 10 + (60 if 20 < t % 60 < 24 else 0))


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
    totals = {}
    alerts.appendleft(dict(t=time.strftime("%H:%M:%S"), proc="cloudd", remote="icloud.com", ip="17.57.144.20"))
    alerts.appendleft(dict(t=time.strftime("%H:%M:%S"), proc="Code Helper", remote="githubusercontent.com", ip="185.199.108.133"))
    alerts.appendleft(dict(t=time.strftime("%H:%M:%S"), kind="rate", proc="Google Chrome", remote="↓ 14.2 МБ/с  ↑ 0.4 МБ/с", ip=""))
    alerts.appendleft(dict(t=time.strftime("%H:%M:%S"), kind="net", proc="Интернет", remote="не было связи 2 мин 10 с", ip=""))
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
        for pid, rr in rates.items():
            tot = totals.setdefault(pid, [rnd.randint(1, 900) * 1e6, rnd.randint(1, 90) * 1e6])
            tot[0] += rr[0] * 1.5
            tot[1] += rr[1] * 1.5
            sess["in"] += rr[0] * 1.5
            sess["out"] += rr[1] * 1.5
        demo_net(t, rnd)
        with lock:
            state.update(conns=list(active), listen=listen, rates=rates, totals={k: list(v) for k, v in totals.items()})
        check_rules(rates, active)
        time.sleep(1.5)


# ───────────────────── сеть: устройства, задержка, трафик, экспорт ─────────────────────
CONFIG_FILE = os.path.join(HOME, "config.json")
CONFIG = {"notify": True, "rate_mb": 10, "outage": True, "trusted": []}
try:
    with open(CONFIG_FILE) as _f:
        CONFIG.update(json.load(_f))
except Exception:
    pass
sess = {"in": 0, "out": 0, "since": time.time()}
net_q = {"gw": collections.deque(maxlen=90), "inet": collections.deque(maxlen=90)}
lan = {}  # mac -> {mac, ip, name, first, last, flag_new}
lan_state = {"scanning": False, "last_scan": 0, "ip": "", "gw": ""}
LANL = threading.Lock()
FRESH_DEV = D.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 0


def save_config():
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(CONFIG, f)
    except OSError:
        pass


def notify(title, sub, body=""):
    """Системное уведомление macOS (можно отключить в настройках)."""
    if CONFIG.get("notify") and sys.platform == "darwin":
        subprocess.Popen(["osascript", "-e",
                          f'display notification "{safe(body)}" with title "{safe(title)}" subtitle "{safe(sub)}"'])


def tcp_rtt(host, port, timeout=1.5):
    """Задержка до хоста по времени TCP-рукопожатия (RST тоже считается ответом). None — нет ответа."""
    t = time.time()
    try:
        socket.create_connection((host, port), timeout).close()
    except ConnectionRefusedError:
        pass
    except OSError:
        return None
    return (time.time() - t) * 1000


def ping_loop():
    gw, t0 = "", 0
    while True:
        if time.time() - t0 > 60:
            gw, t0 = gateway_ip(), time.time()
            lan_state["gw"] = gw
        for key, host, port in (("gw", gw, 80), ("inet", "1.1.1.1", 443)):
            if host:
                v = tcp_rtt(host, port)
                net_q[key].append(v)
                if key == "inet":
                    track_outage(v)
        time.sleep(3)


def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return ""
    finally:
        s.close()


def parse_arp(text, ip_style=False):
    """Разбор вывода `arp -an` (macOS/Linux) или `ip neigh`. macOS печатает MAC без ведущих нулей — нормализуем."""
    rx = (r'^(\d+\.\d+\.\d+\.\d+)\s.*?lladdr\s+([0-9a-fA-F:]+)' if ip_style else r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)')
    res = []
    for m in re.finditer(rx, text, re.M):
        ip, parts = m.group(1), m.group(2).split(":")
        if len(parts) != 6:
            continue
        mac = ":".join(p.zfill(2) for p in parts).lower()
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if mac == "ff:ff:ff:ff:ff:ff" or mac.startswith("01:00:5e") or not a.is_private or ip.endswith(".255"):
            continue
        res.append((ip, mac))
    return res


def read_arp():
    for cmd, st in ((["arp", "-an"], False), (["ip", "neigh"], True)):
        try:
            rows = parse_arp(subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout, st)
            if rows:
                return rows
        except Exception:
            continue
    return []


def lan_update():
    now, new = time.time(), []
    rows = read_arp()
    lan_state["ip"] = lan_state["ip"] or local_ip()
    with LANL, DBL:
        for ip, mac in rows:
            d = lan.get(mac)
            if d is None:
                r = D.execute("SELECT name, first FROM devices WHERE mac=?", (mac,)).fetchone()
                d = lan[mac] = dict(mac=mac, name=r[0] if r else "", first=r[1] if r else now, flag_new=False)
                if not r:
                    D.execute("INSERT INTO devices VALUES(?,?,?,?,?)", (mac, ip, "", now, now))
                    if not (FRESH_DEV and now - START < 600):
                        d["flag_new"] = True
                        new.append((ip, mac))
            d.update(ip=ip, last=now)
            D.execute("UPDATE devices SET ip=?, last=? WHERE mac=?", (ip, now, mac))
        D.commit()
    for ip, mac in new:
        alerts.appendleft(dict(t=time.strftime("%H:%M:%S"), kind="device", proc=ip, remote=mac, ip=ip, mac=mac))
        notify("NetGraph: новое устройство в сети", ip, mac)


def lan_loop():
    while True:
        try:
            lan_update()
        except Exception as e:
            print("lan error:", e)
        time.sleep(15)


def start_scan():
    """Опрашивает подсеть /24 пингом, чтобы заполнить ARP-таблицу; возвращает False, если уже идёт."""
    if lan_state["scanning"] or time.time() - lan_state["last_scan"] < 10:
        return False
    lan_state["scanning"] = True

    def run():
        try:
            lip = local_ip()
            if not lip:
                return
            lan_state["ip"] = lip
            flag = ["-c", "1", "-t", "1"] if sys.platform == "darwin" else ["-c", "1", "-W", "1"]

            def ping(h):
                try:
                    subprocess.run(["ping", *flag, str(h)], capture_output=True, timeout=4)
                except Exception:
                    pass
            with ThreadPoolExecutor(48) as ex:
                list(ex.map(ping, [h for h in ipaddress.ip_network(lip + "/24", strict=False).hosts() if str(h) != lip]))
            lan_update()
        finally:
            lan_state["scanning"] = False
            lan_state["last_scan"] = time.time()
    threading.Thread(target=run, daemon=True).start()
    return True


def lan_rows():
    now, gw, lip, out = time.time(), lan_state["gw"], lan_state["ip"], []
    with LANL:
        items = [dict(d) for d in lan.values()]
    for d in items:
        out.append(dict(ip=d["ip"], mac=d["mac"], name=d.get("name", ""), host=host_of(d["ip"]), seen=now - d["last"],
                        first=d["first"], role="router" if d["ip"] == gw else "",
                        private=bool(int(d["mac"][:2], 16) & 2) and d["ip"] != gw,
                        new=bool(d.get("flag_new")) and now - d["first"] < 900))
    if lip and all(x["ip"] != lip for x in out):
        out.append(dict(ip=lip, mac="", name="", host=socket.gethostname(), seen=0, first=START, role="me", private=False, new=False))
    out.sort(key=lambda x: ipaddress.ip_address(x["ip"]))
    return out


def set_device_name(mac, name):
    name = (name or "").strip()[:40]
    with LANL:
        if mac in lan:
            lan[mac]["name"] = name
    if not ARGS.demo:
        with DBL:
            D.execute("UPDATE devices SET name=? WHERE mac=?", (name, mac))
            D.commit()


def dismiss_alerts(req):
    keep = [a for a in alerts if not (req.get("all") or (a.get("t") == req.get("t") and a.get("proc") == req.get("proc")
                                                       and a.get("remote") == req.get("remote")))]
    alerts.clear()
    alerts.extend(keep)


def export_data(what, fmt):
    if what == "devices":
        head = ["ip", "mac", "name", "hostname", "role", "private_mac", "first_seen"]
        rows = [[x["ip"], x["mac"], x["name"], x["host"], x["role"], x["private"], time.strftime("%F %T", time.localtime(x["first"]))] for x in lan_rows()]
    elif what == "log":
        head = ["time", "event", "process", "remote", "port"]
        with DBL:
            rows = [[time.strftime("%F %T", time.localtime(r[0])), r[1], r[2], r[3], r[4]]
                    for r in D.execute("SELECT t,s,proc,remote,port FROM log ORDER BY t DESC LIMIT 5000")]
    else:
        what = "connections"
        head = ["process", "pid", "proto", "local_port", "remote_ip", "remote_host", "remote_port", "state", "kind"]
        with lock:
            rows = [[c["proc"], c["pid"], c["proto"], c["lport"], c["rip"], dns.get(c["rip"]) or "", c["rport"], c["state"], kind_of(c["rip"])]
                    for c in state["conns"]]
    name = f"netgraph-{what}-{time.strftime('%Y%m%d-%H%M%S')}"
    if fmt == "json":
        return json.dumps([dict(zip(head, r)) for r in rows], ensure_ascii=False, indent=1).encode(), "application/json", name + ".json"
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(head)
    w.writerows(rows)
    return ("﻿" + buf.getvalue()).encode("utf-8"), "text/csv; charset=utf-8", name + ".csv"


# ───────────────────── управление Wi-Fi роутера (Realtek-админка) ─────────────────────
# Страницы и формы НЕ зашиты в код: клиент читает их с самого роутера, меняет только поле
# имени сети (SSID) или пароля (PSK), остальные поля отправляет как есть — так же, как браузер.
ROUTER_LOCK = threading.Lock()
# Эти страницы никогда не открываем при обходе: выход из админки, перезагрузка, сброс, прошивка и т.п.
UNSAFE_PAGE = re.compile(r"log_?(out|off)|reboot|restart|reset|factory|restore|upgrade|firmware|commit|default|backup|save_?(cfg|conf)|shutdown", re.I)


class _FormParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = []
        self.implicit = {"action": "", "method": "get", "fields": []}
        self.cur, self.sel, self.opt, self.ta = self.implicit, None, None, None
        self.script, self._js = [], False

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "script":
            self._js = True
        elif tag == "form":
            self.cur = {"action": a.get("action", ""), "method": a.get("method", "get").lower(), "fields": []}
            self.forms.append(self.cur)
        elif tag == "input":
            self.cur["fields"].append(dict(kind="input", type=a.get("type", "text").lower(), name=a.get("name", ""),
                                           value=a.get("value", ""), checked="checked" in a, disabled="disabled" in a))
        elif tag == "select":
            self.sel = dict(kind="select", name=a.get("name", ""), disabled="disabled" in a, options=[])
            self.cur["fields"].append(self.sel)
        elif tag == "option" and self.sel is not None:
            self.opt = {"value": a["value"] if "value" in a else None, "selected": "selected" in a, "text": ""}
            self.sel["options"].append(self.opt)
        elif tag == "textarea":
            self.ta = dict(kind="textarea", name=a.get("name", ""), disabled="disabled" in a, value="")
            self.cur["fields"].append(self.ta)

    def handle_endtag(self, tag):
        if tag == "script":
            self._js = False
        elif tag == "form":
            self.cur = self.implicit
        elif tag == "select":
            self.sel = self.opt = None
        elif tag == "option":
            self.opt = None
        elif tag == "textarea":
            self.ta = None

    def handle_data(self, d):
        if self._js:
            self.script.append(d)
        elif self.opt is not None:
            self.opt["text"] += d
        elif self.ta is not None:
            self.ta["value"] += d


_LIT = r"""(-?\d+|true|false|"[^"]*"|'[^']*')"""


def _lit(x):
    x = x.strip()
    return (x == "true") if x in ("true", "false") else x[1:-1] if x[0] in "\"'" else int(x)


def _apply_js(form, script):
    """Realtek выставляет выбранные пункты скриптом (form.method.selectedIndex = 4), а не в HTML.
    Без этого мы бы отправили первый пункт списка (например, шифрование «None») и сломали настройки."""
    by = {}
    for f in form["fields"]:
        if f.get("name"):
            by.setdefault(f["name"], []).append(f)
    for m in re.finditer(r"\.(?:elements\[['\"](\w+)['\"]\]|(\w+))\.(selectedIndex|value|checked)\s*=\s*" + _LIT + r"\s*[;\n]", script):
        name, prop, v = m.group(1) or m.group(2), m.group(3), _lit(m.group(4))
        fl = by.get(name)
        if not fl:
            continue
        f = fl[0]
        if f["kind"] == "select":
            opts = f["options"]
            idx = v if prop == "selectedIndex" else next((i for i, o in enumerate(opts) if (o["value"] if o["value"] is not None else o["text"].strip()) == str(v)), None)
            if isinstance(idx, int) and 0 <= idx < len(opts):
                for i, o in enumerate(opts):
                    o["selected"] = i == idx
        elif f["kind"] == "input" and f["type"] in ("text", "hidden", "password") and prop == "value":
            f["value"] = str(v)
        elif f["kind"] == "input" and f["type"] == "checkbox" and prop == "checked":
            f["checked"] = bool(v)
    for m in re.finditer(r"\.(\w+)\[(\d+)\]\.checked\s*=\s*true", script):
        grp = [f for f in by.get(m.group(1), []) if f["kind"] == "input" and f["type"] == "radio"]
        i = int(m.group(2))
        if i < len(grp):
            for j, f in enumerate(grp):
                f["checked"] = j == i


def parse_forms(html):
    p = _FormParser()
    p.feed(html)
    forms = list(p.forms)
    if p.implicit["fields"]:
        forms.append(p.implicit)
    script = "\n".join(p.script)
    for f in forms:
        _apply_js(f, script)
        for x in f["fields"]:
            x["in_js"] = bool(x.get("name")) and re.search(r"\b" + re.escape(x["name"]) + r"\b", script) is not None
    return forms


def ambiguous_fields(form):
    """Списки без выбранного пункта, которыми при этом управляет скрипт страницы: значение не определить."""
    return [x["name"] for x in form["fields"] if x["kind"] == "select" and x["name"] and x["options"]
            and not x["disabled"] and not any(o["selected"] for o in x["options"]) and x.get("in_js")]


def build_payload(form, overrides):
    """Собирает поля формы так же, как это сделал бы браузер; overrides подменяет значения по имени."""
    out, used, btn = [], set(), None
    for f in form["fields"]:
        n = f.get("name", "")
        if not n:
            continue
        k = f["kind"]
        if k == "input":
            t = f["type"]
            if t in ("submit", "button", "image"):
                if t != "image" and btn is None and re.search(r"apply|save|ok|submit|примен|сохран", f["value"], re.I):
                    btn = (n, f["value"])
                continue
            if t in ("reset", "file"):
                continue
            if t in ("radio", "checkbox"):
                if f["checked"]:  # отключённые, но отмеченные (напр. AES) сохраняем — это текущая настройка
                    out.append((n, f["value"] or "on"))
                continue
            if f["disabled"]:
                continue
            v = f["value"]
        elif k == "select":
            if f["disabled"] or not f["options"]:
                continue
            o = next((o for o in f["options"] if o["selected"]), f["options"][0])
            v = o["value"] if o["value"] is not None else o["text"].strip()
        else:
            if f["disabled"]:
                continue
            v = f["value"]
        if n in overrides and n not in used:
            v = overrides[n]
            used.add(n)
        out.append((n, v))
    if btn:
        out.append(btn)
    return out


def _field(form, pats, types=("text", "password"), skip=r"idx|type|num|enable"):
    cands = [x for x in form["fields"] if x["kind"] == "input" and x["type"] in types and x["name"]
             and not re.search(skip, x["name"], re.I)]
    for rx in pats:
        for x in cands:
            if re.search(rx, x["name"], re.I):
                return x
    return None


def _ssid_field(form):
    return _field(form, (r"^ssid$", r"ssid"), types=("text",))


def _psk_field(form):
    return _field(form, (r"^pskvalue$", r"psk", r"pass(phrase|word)?", r"wpa.*key"))


class RouterError(Exception):
    pass


class Router:
    def __init__(self, hostport, user, pw):
        self.host, _, port = hostport.partition(":")
        self.hostport = hostport
        self.base = f"http://{self.host}" + (f":{port}" if port else "")
        self.user, self.pw = user, pw
        self.log, self.pages, self.cur_band = [], {}, 0
        self.jar = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.px = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPCookieProcessor(self.jar))
        tok = base64.b64encode(f"{user}:{pw}".encode()).decode()
        self.hdr = {"Authorization": "Basic " + tok, "User-Agent": "Mozilla/5.0 (NetGraph)"}

    def note(self, m):
        self.log.append(m)

    def fetch(self, path, data=None, referer=None, method="post"):
        url = urllib.parse.urljoin(self.base + "/", path)
        if urllib.parse.urlparse(url).hostname != self.host:
            raise RouterError("запрос на чужой адрес отклонён")
        h, body = dict(self.hdr), None
        if referer:
            h["Referer"] = referer
        if data is not None:
            enc = urllib.parse.urlencode(data)
            if method == "get":
                url += ("&" if "?" in url else "?") + enc
            else:
                body, h["Content-Type"] = enc.encode(), "application/x-www-form-urlencoded"
        try:
            r = self.op.open(urllib.request.Request(url, data=body, headers=h), timeout=8)
            raw, final = r.read(), r.geturl()
        except urllib.error.HTTPError as e:
            if e.code == 401:
                raise RouterError("Неверный логин или пароль администратора")
            raise RouterError(f"HTTP {e.code} для {urllib.parse.urlparse(url).path}")
        if urllib.parse.urlparse(final).hostname != self.host:
            raise RouterError("роутер перенаправил на чужой адрес")
        try:
            return final, raw.decode("utf-8")
        except UnicodeDecodeError:
            return final, raw.decode("latin-1")

    @staticmethod
    def _login_form(html):
        return next((f for f in parse_forms(html) if any(x["kind"] == "input" and x["type"] == "password" for x in f["fields"])), None)

    def login(self):
        try:
            url, html = self.fetch("/")
        except urllib.error.URLError as e:
            raise RouterError(f"Роутер недоступен: {e.reason}")
        except OSError as e:
            raise RouterError(f"Роутер недоступен: {e}")
        lf = self._login_form(html)
        if lf:
            self.note("вход: найдена форма входа, отправляю логин и пароль")
            ov = {}
            for x in lf["fields"]:
                if x["kind"] == "input" and x["type"] == "password" and "p" not in ov:
                    ov[x["name"]] = self.pw
                    ov["p"] = 1
                elif x["kind"] == "input" and x["type"] == "text" and "u" not in ov and x["name"]:
                    ov[x["name"]] = self.user
                    ov["u"] = 1
            ov = {k: v for k, v in ov.items() if k not in ("p", "u")}
            self.fetch(urllib.parse.urljoin(url, lf["action"] or url), build_payload(lf, ov), referer=url)
            url, html = self.fetch("/")
            if self._login_form(html):
                raise RouterError("Не удалось войти: проверьте логин и пароль (или у роутера нестандартная форма входа)")
        else:
            self.note("вход: HTTP Basic")
        return url

    def connect(self):
        self.find_pages(self.login())

    def find_pages(self, root):
        seen, queue, found = set(), [root], {}
        rx = re.compile(r"[\w./\-]+\.(?:htm|html|asp)(?:\?[\w=&.\-]*)?", re.I)
        while queue and len(seen) < 30:
            p = queue.pop(0)
            if p in seen:
                continue
            seen.add(p)
            try:
                url, html = self.fetch(p)
            except Exception:
                continue
            for m in rx.findall(html):
                u = urllib.parse.urljoin(url, m)
                if urllib.parse.urlparse(u).hostname != self.host:
                    continue
                low = urllib.parse.urlparse(u).path.lower()
                if UNSAFE_PAGE.search(low):
                    continue
                if "wlbasic" in low:
                    found.setdefault("basic", u)
                if re.search(r"wl(wpa|security|encrypt)", low):
                    found.setdefault("sec", u)
                if u not in seen:
                    queue.append(u)
            if "basic" in found and "sec" in found:
                break
        for kind, cands, finder in (("basic", ("/admin/wlbasic.htm", "/wlbasic.htm"), _ssid_field),
                                    ("sec", ("/admin/wlwpa.htm", "/wlwpa.htm"), _psk_field)):
            if kind in found:
                continue
            for c in cands:
                try:
                    u, h = self.fetch(c)
                    if any(finder(f) for f in parse_forms(h)):
                        found[kind] = u
                        break
                except Exception:
                    pass
        self.pages = found
        self.note("страницы: " + ", ".join(f"{k}={urllib.parse.urlparse(v).path}" for k, v in found.items()) if found else "страницы Wi-Fi не найдены")
        if len(found) < 2:
            raise RouterError("Не нашёл страницы настроек Wi-Fi (" + ("нужны basic и security" if found else "ни одной") + "). Журнал ниже — пришлите его разработчику.")

    def select_band(self, idx):
        if idx == self.cur_band:
            return True
        try:
            page = urllib.parse.urlparse(self.pages["sec"]).path
            self.fetch("/boaform/admin/formWlanRedirect", [("redirect-url", page), ("wlan_idx", str(idx))], referer=self.pages["sec"])
            self.cur_band = idx
            return True
        except Exception as e:
            self.note(f"переключение диапазона {idx} не удалось: {e}")
            return False

    def _read(self, kind, finder, idx):
        url, html = self.fetch(self.pages[kind])
        forms = parse_forms(html)
        band_ids = {x["value"] for f in forms for x in f["fields"] if x.get("name", "").lower() == "wlan_idx"}
        confirmed = bool(band_ids)
        if band_ids and str(idx) not in band_ids:
            raise RouterError(f"роутер показал другой диапазон ({','.join(band_ids)})")
        for f in forms:
            x = finder(f)
            if x:
                return url, f, x, confirmed
        raise RouterError(f"на странице {urllib.parse.urlparse(url).path} нет нужного поля")

    def read_band(self, idx):
        res = {"idx": idx, "label": "2.4 ГГц" if idx == 0 else "5 ГГц", "ok": False}
        if not self.select_band(idx):
            res["error"] = "диапазон не переключается"
            return res
        try:
            _u, _f, x, c1 = self._read("basic", _ssid_field, idx)
            res["ssid"] = x["value"]
            _u, _f, y, c2 = self._read("sec", _psk_field, idx)
            res["psk"] = y["value"]
            res["confirmed"] = c1 and c2
            res["ok"] = True
        except RouterError as e:
            res["error"] = str(e)
        return res

    def update(self, kind, finder, value, idx):
        url, f, x, _c = self._read(kind, finder, idx)
        amb = ambiguous_fields(f)
        if amb:
            raise RouterError("Не могу однозначно определить текущие значения полей: " + ", ".join(amb) +
                              ". Чтобы случайно не поменять лишнее, запись отменена — пришлите технический журнал.")
        payload = build_payload(f, {x["name"]: value})
        try:
            bk = os.path.join(HOME, time.strftime(f"router-backup-%Y%m%d-%H%M%S-{kind}{idx}.json"))
            with open(bk, "w") as fh:
                json.dump(dict(url=url, band=idx, form=f["action"], fields=build_payload(f, {})), fh, ensure_ascii=False, indent=1)
            os.chmod(bk, 0o600)
            self.note("резервная копия формы: " + bk)
        except OSError as e:
            raise RouterError(f"Не удалось сохранить резервную копию ({e}) — запись отменена")
        action = urllib.parse.urljoin(url, f["action"] or url)
        self.note(f"{kind}: отправка формы {urllib.parse.urlparse(action).path}, полей: {len(payload)}")
        try:
            self.fetch(action, payload, referer=url, method=f["method"])
        except RouterError as e:
            self.note(f"ответ роутера: {e}")
        except OSError as e:
            self.note(f"связь оборвалась после отправки (роутер мог перезапустить Wi-Fi): {e}")
        for _ in range(5):  # проверяем, что значение действительно сохранилось
            time.sleep(2.5)
            try:
                _u, _f, y, _c2 = self._read(kind, finder, idx)
                return y["value"] == value
            except Exception:
                continue
        return None


def _router_args(req):
    host = str(req.get("host", "")).strip()
    h, _, port = host.partition(":")
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        raise RouterError("Укажите IP-адрес роутера, например 192.168.1.1")
    if not (ip.is_private or ip.is_loopback):
        raise RouterError("Разрешены только адреса локальной сети")
    if port and not port.isdigit():
        raise RouterError("Неверный порт")
    return host, str(req.get("user", "")), str(req.get("pass", ""))


def router_op(req, apply):
    if not ROUTER_LOCK.acquire(blocking=False):
        return dict(ok=False, error="Операция с роутером уже выполняется", log=[])
    r = None
    try:
        host, user, pw = _router_args(req)
        r = Router(host, user, pw)
        r.connect()
        if not apply:
            bands = [r.read_band(i) for i in (0, 1)]
            r.select_band(0)
            r.note("диапазонов найдено: %d" % sum(b["ok"] for b in bands))
            return dict(ok=any(b["ok"] for b in bands), bands=bands, log=r.log,
                        error=None if any(b["ok"] for b in bands) else "Не удалось прочитать настройки Wi-Fi")
        ssid, psk = req.get("ssid") or "", req.get("psk") or ""
        if not ssid and not psk:
            raise RouterError("Нечего менять")
        if ssid and not 1 <= len(ssid.encode()) <= 32:
            raise RouterError("Имя сети: от 1 до 32 байт")
        if psk and not (8 <= len(psk) <= 63 and all(32 <= ord(c) < 127 for c in psk) or re.fullmatch(r"[0-9a-fA-F]{64}", psk)):
            raise RouterError("Пароль: 8–63 символа (латиница, цифры, знаки)")
        bands = [int(b) for b in req.get("bands", [0]) if int(b) in (0, 1)]
        results = []
        for idx in bands:
            res = {"idx": idx}
            if not r.select_band(idx):
                res["error"] = "диапазон не переключается"
            else:
                try:
                    if ssid:
                        res["ssid"] = r.update("basic", _ssid_field, ssid, idx)
                        time.sleep(2)
                    if psk:
                        res["psk"] = r.update("sec", _psk_field, psk, idx)
                except RouterError as e:
                    res["error"] = str(e)
            results.append(res)
        r.select_band(0)
        return dict(ok=all("error" not in x and x.get("ssid", True) is not False and x.get("psk", True) is not False for x in results),
                    results=results, log=r.log)
    except RouterError as e:
        return dict(ok=False, error=str(e), log=r.log if r else [])
    except Exception as e:
        return dict(ok=False, error="Ошибка: %s" % e, log=r.log if r else [])
    finally:
        ROUTER_LOCK.release()


# ───────────── утилиты, WoL, сканер портов, правила тревог ─────────────
HOST_RX = re.compile(r"^(?!-)[A-Za-z0-9._:\-]{1,253}$")
SERVICES = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3", 139: "netbios", 143: "imap",
            443: "https", 445: "smb", 554: "rtsp", 631: "ipp", 1900: "upnp", 3306: "mysql", 3389: "rdp", 5000: "upnp/http",
            5900: "vnc", 8000: "http-alt", 8008: "http-alt", 8080: "http-proxy", 8443: "https-alt", 8888: "http-alt",
            9100: "printer", 32400: "plex", 62078: "iphone-sync"}
LAN_PORTS = [21, 22, 23, 53, 80, 139, 443, 445, 554, 631, 1900, 3389, 5000, 5900, 8000, 8008, 8080, 8443, 8888, 9100, 32400, 62078]


def _cmd(cmd, timeout):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return dict(ok=p.returncode == 0, out=(p.stdout + p.stderr).strip() or "(нет вывода)")
    except FileNotFoundError:
        return dict(ok=False, out="Команда «%s» не найдена в системе" % cmd[0])
    except subprocess.TimeoutExpired as e:
        o = e.stdout or ""
        o = o.decode("utf-8", "replace") if isinstance(o, bytes) else o
        return dict(ok=False, out=(o.strip() + "\n\n[прервано по таймауту]").strip())


def port_state(host, port, timeout=1.5):
    t = time.time()
    try:
        socket.create_connection((host, port), timeout).close()
        return "open", (time.time() - t) * 1000
    except ConnectionRefusedError:
        return "closed", (time.time() - t) * 1000
    except OSError:
        return "filtered", None


def scan_ports(host, ports, timeout=1.5):
    with ThreadPoolExecutor(16) as ex:
        return list(zip(ports, ex.map(lambda p: port_state(host, p, timeout), ports)))


def demo_tool(tool, host):
    if tool == "ping":
        r = random.Random(host)
        t = [r.uniform(8, 30) for _ in range(4)]
        return "PING %s: 56 data bytes\n" % host + "".join("64 bytes from %s: icmp_seq=%d ttl=57 time=%.3f ms\n" % (host, i, v) for i, v in enumerate(t)) + \
            "\n--- %s ping statistics ---\n4 packets transmitted, 4 received, 0.0%% packet loss\nround-trip min/avg/max = %.3f/%.3f/%.3f ms" % (host, min(t), sum(t) / 4, max(t))
    if tool == "trace":
        return "traceroute to %s, 20 hops max\n 1  router.lan (192.168.1.1)  1.2 ms\n 2  10.20.0.1  4.8 ms\n 3  core-gw.isp.example (95.31.0.5)  7.1 ms\n 4  * \n 5  ae-1.edge.example (62.115.1.9)  18.4 ms\n 6  %s  21.0 ms" % (host, host)
    if tool == "dns":
        return "%s\n  A     93.184.216.34   (example.net)\n  AAAA  2606:2800:220:1:248:1893:25c8:1946\nвремя ответа: 14 мс" % host
    return "22/tcp    closed\n53/tcp    open    14 мс  (dns)\n80/tcp    open    3 мс  (http)\n443/tcp   open    4 мс  (https)\n8080/tcp  filtered"


def _tool_ssl(host):
    import ssl
    h, port = (host.rsplit(":", 1) + ["443"])[:2] if host.count(":") == 1 else (host, "443")
    try:
        port = int(port)
    except ValueError:
        return dict(ok=False, out="Неверный порт")
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((h, port), 6) as raw, ctx.wrap_socket(raw, server_hostname=h) as s:
            c, ver, ciph = s.getpeercert(), s.version(), s.cipher()
    except ssl.SSLCertVerificationError as e:
        return dict(ok=False, out="Сертификат НЕ прошёл проверку:\n%s" % (e.verify_message or e))
    except (OSError, ssl.SSLError) as e:
        return dict(ok=False, out="Не удалось подключиться: %s" % e)
    nm = lambda t: ", ".join("%s=%s" % kv for rdn in t for kv in rdn)
    exp = ssl.cert_time_to_seconds(c["notAfter"])
    days = int((exp - time.time()) // 86400)
    san = [v for k, v in c.get("subjectAltName", ()) if k == "DNS"]
    out = ["%s:%d — сертификат действителен" % (h, port), "кому:      " + nm(c.get("subject", ())), "кем выдан: " + nm(c.get("issuer", ())),
           "с:         " + c["notBefore"], "до:        %s  (осталось %d дн.%s)" % (c["notAfter"], days, " — СКОРО ИСТЕКАЕТ" if days < 14 else ""),
           "TLS:       %s, %s" % (ver, ciph[0] if ciph else "?")]
    if san:
        out.append("имена:     " + ", ".join(san[:8]) + (" …" if len(san) > 8 else ""))
    return dict(ok=True, out="\n".join(out))


def _tool_http(host):
    import http.client
    out, ok = [], True
    scheme, h, path = "https", host, "/"
    for hop in range(6):
        t0 = time.time()
        try:
            cn = (http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection)(h, timeout=8)
            cn.request("GET", path, headers={"User-Agent": "NetGraph/1.0", "Accept-Encoding": "identity"})
            r = cn.getresponse()
        except (OSError, http.client.HTTPException) as e:
            if hop == 0 and scheme == "https":
                scheme = "http"
                out.append("HTTPS недоступен (%s), пробую HTTP" % (getattr(e, "reason", None) or e))
                continue
            return dict(ok=False, out="\n".join(out + ["Ошибка: %s" % e]))
        ms = (time.time() - t0) * 1000
        out.append("%s://%s%s\n  → %d %s  (%d мс)" % (scheme, h, path, r.status, r.reason, ms))
        for k in ("Server", "Content-Type", "Content-Length", "Strict-Transport-Security", "Cache-Control"):
            if r.getheader(k):
                out.append("    %s: %s" % (k, r.getheader(k)[:80]))
        loc = r.getheader("Location")
        r.close()
        cn.close()
        if r.status in (301, 302, 303, 307, 308) and loc:
            u = urllib.parse.urlparse(urllib.parse.urljoin("%s://%s%s" % (scheme, h, path), loc))
            if u.scheme not in ("http", "https") or not HOST_RX.match(u.netloc or ""):
                out.append("    редирект на неподдерживаемый адрес")
                break
            scheme, h, path = u.scheme, u.netloc, (u.path or "/") + ("?" + u.query if u.query else "")
            continue
        ok = r.status < 400
        break
    return dict(ok=ok, out="\n".join(out))


def _tool_ip(host):
    try:
        ip = socket.getaddrinfo(host, None)[0][4][0]
    except OSError as e:
        return dict(ok=False, out="Не удалось разрешить имя: %s" % e)
    a = ipaddress.ip_address(ip.split("%")[0])
    if a.is_private or a.is_loopback:
        return dict(ok=True, out="%s — адрес локальной сети, во внешних базах его нет" % ip)
    try:
        u = "http://ip-api.com/json/%s?lang=ru&fields=status,message,country,regionName,city,isp,org,as,reverse,proxy,hosting,mobile,timezone,query" % ip
        d = json.load(urllib.request.urlopen(u, timeout=8))
    except Exception as e:
        return dict(ok=False, out="Сервис геолокации недоступен: %s" % e)
    if d.get("status") != "success":
        return dict(ok=False, out=d.get("message", "нет данных"))
    rows = [("IP", d["query"]), ("Страна", d.get("country")), ("Регион", d.get("regionName")), ("Город", d.get("city")), ("Провайдер", d.get("isp")),
            ("Организация", d.get("org")), ("AS", d.get("as")), ("Обратный DNS", d.get("reverse")), ("Часовой пояс", d.get("timezone")),
            ("Хостинг/ЦОД", "да" if d.get("hosting") else "нет"), ("Прокси/VPN", "да" if d.get("proxy") else "нет"), ("Мобильная сеть", "да" if d.get("mobile") else "нет")]
    return dict(ok=True, out="\n".join("%-14s %s" % (k + ":", v) for k, v in rows if v))


def speedtest():
    if ARGS.demo:
        time.sleep(1.2)
        r = random.Random(time.time())
        return dict(ok=True, down=r.uniform(180, 320), up=r.uniform(60, 120), ping=r.uniform(8, 20), server="demo")
    try:
        t0 = time.time()
        urllib.request.urlopen("https://speed.cloudflare.com/__down?bytes=0", timeout=8).read()
        ping = (time.time() - t0) * 1000
        t0 = time.time()
        r = urllib.request.urlopen("https://speed.cloudflare.com/__down?bytes=30000000", timeout=10)
        got = 0
        while time.time() - t0 < 8:
            b = r.read(65536)
            if not b:
                break
            got += len(b)
        down = got * 8 / max(0.001, time.time() - t0) / 1e6
        r.close()
        up = 0
        try:
            body = os.urandom(6_000_000)
            t0 = time.time()
            urllib.request.urlopen(urllib.request.Request("https://speed.cloudflare.com/__up", data=body, method="POST"), timeout=15).read()
            up = len(body) * 8 / (time.time() - t0) / 1e6
        except Exception:
            pass
        return dict(ok=True, down=down, up=up, ping=ping, server="Cloudflare")
    except Exception as e:
        return dict(ok=False, error="Тест не удался: %s" % e)


def set_trusted(add=None, rem=None):
    t = list(CONFIG.get("trusted") or [])
    if add and add not in t and len(t) < 200:
        t.append(str(add)[:120])
    if rem in t:
        t.remove(rem)
    CONFIG["trusted"] = t
    save_config()


def run_tool(req):
    tool, host = str(req.get("tool", "")), str(req.get("host", "")).strip()
    if not HOST_RX.match(host):
        return dict(ok=False, out="Неверный адрес: допустимы имя хоста или IP")
    if tool not in ("ping", "trace", "dns", "ports", "ssl", "http", "ip", "wol"):
        return dict(ok=False, out="Неизвестная утилита")
    if tool == "wol":
        sent = wol(host)
        return dict(ok=sent, out="Magic packet отправлен на %s" % host if sent else "Неверный MAC-адрес (формат AA:BB:CC:DD:EE:FF)")
    if ARGS.demo and tool in ("ssl", "http", "ip"):
        return dict(ok=True, out={"ssl": "%s:443 — сертификат действителен\nкому:      commonName=%s\nкем выдан: organizationName=Let's Encrypt\nдо:        Jan 12 2027  (осталось 72 дн.)\nTLS:       TLSv1.3, TLS_AES_256_GCM_SHA384",
                                  "http": "https://%s/\n  → 200 OK  (84 мс)\n    Server: nginx\n    Content-Type: text/html\n    Strict-Transport-Security: max-age=31536000",
                                  "ip": "IP:            93.184.216.34\nСтрана:        США\nГород:         Los Angeles\nПровайдер:     Edgecast\nХостинг/ЦОД:   да"}[tool].replace("%s", host))
    if tool in ("ssl", "http", "ip"):
        return {"ssl": _tool_ssl, "http": _tool_http, "ip": _tool_ip}[tool](host)
    if ARGS.demo:
        return dict(ok=True, out=demo_tool(tool, host))
    if tool == "ping":
        return _cmd(["ping", "-c", "4"] + (["-W", "2000"] if sys.platform == "darwin" else ["-W", "2"]) + [host], 25)
    if tool == "trace":
        return _cmd(["traceroute", "-m", "20", "-w", "2", "-q", "1", host], 70)
    if tool == "dns":
        t0 = time.time()
        try:
            infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except OSError as e:
            return dict(ok=False, out="Не удалось разрешить имя: %s" % e)
        ms, lines, seen = (time.time() - t0) * 1000, [host], set()
        for fam, _t, _p, _c, sa in infos:
            ip = sa[0]
            if ip in seen:
                continue
            seen.add(ip)
            try:
                rev = socket.gethostbyaddr(ip)[0]
            except OSError:
                rev = ""
            lines.append("  %-5s %s%s" % ("AAAA" if fam == socket.AF_INET6 else "A", ip.ljust(18), ("(%s)" % rev) if rev else ""))
        lines.append("время ответа: %d мс" % ms)
        return dict(ok=True, out="\n".join(lines))
    ports = [int(x) for x in re.findall(r"\d+", str(req.get("ports") or "")) if 0 < int(x) < 65536][:30] or [22, 53, 80, 443, 8080]
    out = [("%d/tcp" % p).ljust(9) + ("%-9s" % st) + (("%d мс" % ms) if ms is not None else "") + (("  (%s)" % SERVICES[p]) if p in SERVICES and st == "open" else "")
           for p, (st, ms) in scan_ports(host, ports)]
    return dict(ok=True, out="\n".join(out))


def lan_ports(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return dict(ok=False, error="Неверный IP")
    if not a.is_private:
        return dict(ok=False, error="Сканируются только адреса локальной сети")
    if ARGS.demo:
        return dict(ok=True, open=[[53, "dns"], [80, "http"], [443, "https"]])
    res = scan_ports(ip, LAN_PORTS, 0.7)
    return dict(ok=True, open=[[p, SERVICES.get(p, "")] for p, (st, _ms) in res if st == "open"])


def wol(mac):
    if not re.fullmatch(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", mac or ""):
        return False
    if ARGS.demo:
        return True
    b = bytes.fromhex(re.sub(r"[:-]", "", mac))
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for port in (9, 7):
            s.sendto(b"\xff" * 6 + b * 16, ("255.255.255.255", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


RULE = {"hot": {}, "until": {}}


def _ru_rate(b):
    return "%.0f Б/с" % b if b < 1024 else "%.0f КБ/с" % (b / 1024) if b < 1048576 else "%.1f МБ/с" % (b / 1048576)


def check_rules(rates, conns):
    """Тревога, если процесс держит трафик выше порога 3 замера подряд."""
    lim = float(CONFIG.get("rate_mb") or 0) * 1048576
    if lim <= 0:
        RULE["hot"].clear()
        return
    names = {}
    for c in conns:
        names.setdefault(c["pid"], c["proc"])
    tot = {}
    for pid, v in rates.items():
        n = names.get(pid)
        if n:
            t = tot.setdefault(n, [0, 0])
            t[0] += v[0]
            t[1] += v[1]
    now = time.time()
    for n in list(RULE["hot"]):
        if n not in tot or sum(tot[n]) < lim:
            del RULE["hot"][n]
    for n, v in tot.items():
        if sum(v) < lim:
            continue
        RULE["hot"][n] = RULE["hot"].get(n, 0) + 1
        if RULE["hot"][n] >= 3 and now > RULE["until"].get(n, 0):
            RULE["until"][n] = now + 600
            txt = "↓ %s  ↑ %s" % (_ru_rate(v[0]), _ru_rate(v[1]))
            alerts.appendleft(dict(t=time.strftime("%H:%M:%S"), kind="rate", proc=n, remote=txt, ip=""))
            notify("NetGraph: всплеск трафика", n, txt)


outage = {"fails": 0, "t0": 0, "since": None, "seen_ok": False}


def dur_s(s):
    s = int(s)
    return "%d с" % s if s < 60 else "%d мин %d с" % (s // 60, s % 60) if s < 3600 else "%d ч %d мин" % (s // 3600, s % 3600 // 60)


def track_outage(rtt):
    """Обрыв интернета = 3 неудачных проверки подряд (после хотя бы одной удачной)."""
    if not CONFIG.get("outage", True):
        return
    if rtt is None:
        if not outage["seen_ok"]:
            return
        outage["fails"] += 1
        if outage["fails"] == 1:
            outage["t0"] = time.time()
        if outage["fails"] >= 3 and outage["since"] is None:
            outage["since"] = outage["t0"]
        return
    outage["seen_ok"] = True
    if outage["since"] is not None:
        a, b = outage["since"], time.time()
        with DBL:
            D.execute("INSERT INTO outages VALUES(?,?)", (a, b))
            D.commit()
        txt = "не было связи %s" % dur_s(b - a)
        alerts.appendleft(dict(t=time.strftime("%H:%M:%S"), kind="net", proc="Интернет", remote=txt, ip=""))
        notify("NetGraph", "Интернет вернулся", txt)
    outage.update(fails=0, since=None)


def outage_log():
    if ARGS.demo:
        n = time.time()
        return [[n - 7200, n - 7070], [n - 90000, n - 89700]]
    with DBL:
        return [list(r) for r in D.execute("SELECT start,end FROM outages ORDER BY start DESC LIMIT 8").fetchall()]


# ───────────── админка роутера внутри NetGraph: обратный прокси на отдельном порту ─────────────
import html as _htmlmod

RT = {"router": None, "server": None, "port": 0, "lock": threading.Lock()}
_BAD_LOGIN_FIELDS = re.compile(r"psk|wpa|wep|ssid|wlan|key|old|new|confirm|retype|repeat", re.I)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _is_login_page(raw):
    txt = raw.decode("utf-8", "replace")
    if "password" not in txt.lower():
        return False
    f = Router._login_form(txt)
    return bool(f) and not any(_BAD_LOGIN_FIELDS.search(x.get("name") or "") for x in f["fields"])


class RtProxy(BaseHTTPRequestHandler):
    """Прозрачный прокси: браузер ходит на 127.0.0.1:<порт>, NetGraph подставляет сессию роутера.
    Абсолютные пути вида /boaform/... продолжают работать, потому что проксируется весь origin."""
    DROP = {"connection", "transfer-encoding", "content-length", "content-encoding", "keep-alive", "set-cookie", "location",
            "content-security-policy", "content-security-policy-report-only", "x-frame-options", "strict-transport-security",
            "cache-control", "etag", "last-modified", "expires", "vary", "x-content-type-options", "server", "date"}

    def log_message(self, *a):
        pass

    def _fail(self, code, text):
        body = ("<meta charset=utf-8><body style='font:14px system-ui;padding:28px;color:#333'>%s</body>" % text).encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _guard(self):
        """Только с этого компьютера и только со страниц localhost: защита от CSRF и DNS-rebinding."""
        if (self.headers.get("Host") or "") not in ("127.0.0.1:%d" % RT["port"], "localhost:%d" % RT["port"]):
            return False
        sf = self.headers.get("Sec-Fetch-Site")
        if sf is not None and sf not in ("same-origin", "same-site", "none"):
            return False
        for h in ("Origin", "Referer"):
            v = self.headers.get(h)
            if v and urllib.parse.urlparse(v).hostname not in ("127.0.0.1", "localhost"):
                return False
        return not (sf is None and self.command == "POST" and not (self.headers.get("Origin") or self.headers.get("Referer")))

    def _forward(self, r, body):
        me = "http://" + self.headers["Host"]
        h = {"User-Agent": self.headers.get("User-Agent") or r.hdr["User-Agent"], "Authorization": r.hdr["Authorization"],
             "Accept": self.headers.get("Accept") or "*/*", "Accept-Encoding": "identity"}
        if self.headers.get("Accept-Language"):
            h["Accept-Language"] = self.headers["Accept-Language"]
        if body is not None:
            h["Content-Type"] = self.headers.get("Content-Type") or "application/x-www-form-urlencoded"
        for k in ("Referer", "Origin"):
            if self.headers.get(k):
                h[k] = self.headers[k].replace(me, r.base)
        url = r.base + self.path
        if urllib.parse.urlparse(url).hostname != r.host:
            raise RouterError("запрос на чужой адрес отклонён")
        try:
            resp = r.px.open(urllib.request.Request(url, data=body, headers=h, method=self.command), timeout=20)
        except urllib.error.HTTPError as e:
            resp = e
        data = resp.read(64 << 20)
        st = getattr(resp, "status", None) or resp.code
        ct = resp.headers.get("Content-Type", "")
        if re.search(r"text|javascript|json|xml", ct, re.I):
            data = data.replace(r.base.encode(), me.encode()).replace(("//" + r.hostport).encode(), ("//" + self.headers["Host"]).encode())
        hd = [(k, v) for k, v in resp.headers.items() if k.lower() not in self.DROP]
        loc = resp.headers.get("Location")
        if loc:
            hd.append(("Location", loc.replace(r.base, me)))
        return st, hd, data

    def _wants_login(self, st, hd, data):
        d = {k.lower(): v for k, v in hd}
        if st in (301, 302, 303, 307) and re.search(r"login|logon", d.get("location", ""), re.I):
            return True
        return st == 200 and "html" in d.get("content-type", "") and len(data) < 60000 and _is_login_page(data)

    def _handle(self):
        if not self._guard():
            return self._fail(403, "Запрещено")
        r = RT["router"]
        if r is None:
            return self._fail(503, "Роутер не подключён. Откройте вкладку «Роутер» в NetGraph и войдите.")
        if not self.path.startswith("/") or self.path.startswith("//"):
            return self._fail(400, "Неверный путь")
        body = None
        if self.command == "POST":
            n = int(self.headers.get("Content-Length") or 0)
            if n > 64 << 20:
                return self._fail(413, "Слишком большой запрос")
            body = self.rfile.read(n)
        try:
            st, hd, data = self._forward(r, body)
            if self.command == "GET" and (st == 401 or self._wants_login(st, hd, data)):
                with RT["lock"]:
                    r.login()
                st, hd, data = self._forward(r, body)
        except RouterError as e:
            return self._fail(502, _htmlmod.escape(str(e)))
        except OSError as e:
            return self._fail(502, "Роутер недоступен: " + _htmlmod.escape(str(e)))
        self.send_response(st)
        for k, v in hd:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    do_GET = do_POST = _handle


def rt_ensure_server():
    if RT["server"]:
        return
    port = ARGS.rt_port or ARGS.port + 1
    try:
        srv = ThreadingHTTPServer(("127.0.0.1", port), RtProxy)
    except OSError as e:
        raise RouterError("Не удалось занять порт %d для админки: %s. Задайте другой: --rt-port" % (port, e))
    RT.update(server=srv, port=srv.server_address[1])
    threading.Thread(target=srv.serve_forever, daemon=True).start()


def rt_open(req):
    try:
        host, user, pw = _router_args(req)
        r = Router(host, user, pw)
        r.login()
        rt_ensure_server()
        RT["router"] = r
        return dict(ok=True, host=r.hostport, port=RT["port"])
    except RouterError as e:
        return dict(ok=False, error=str(e))
    except Exception as e:
        return dict(ok=False, error="Ошибка: %s" % e)


def rt_info():
    r = RT["router"]
    return dict(active=bool(r), host=r.hostport if r else "", port=RT["port"] if r else 0)


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body, ctype, code=200, extra=()):
        self.send_response(code)
        for k, v in extra:
            self.send_header(k, v)
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
        if self.path in ("/rt/open", "/rt/close", "/tool", "/lan/wol", "/lan/ports", "/speedtest"):
            try:
                n = int(self.headers.get("Content-Length") or 0)
                req = json.loads(self.rfile.read(min(n, 5000)) or b"{}")
            except Exception:
                return self._send(b"bad request", "text/plain", 400)
            if self.path == "/rt/close":
                RT["router"] = None
                res = dict(ok=True)
            elif self.path == "/rt/open":
                res = dict(ok=False, error="В демо-режиме админка роутера не подключается") if ARGS.demo else rt_open(req)
            elif self.path == "/tool":
                res = run_tool(req)
            elif self.path == "/speedtest":
                res = speedtest()
            elif self.path == "/lan/wol":
                res = dict(ok=wol(str(req.get("mac", ""))))
            else:
                res = lan_ports(str(req.get("ip", "")))
            return self._send(json.dumps(res).encode(), "application/json")
        if self.path.startswith("/router/"):
            try:
                n = int(self.headers.get("Content-Length") or 0)
                req = json.loads(self.rfile.read(n) or b"{}")
            except Exception:
                return self._send(b"bad request", "text/plain", 400)
            if ARGS.demo:
                return self._send(json.dumps(dict(ok=False, error="В демо-режиме роутер не опрашивается", log=[])).encode(), "application/json")
            return self._send(json.dumps(router_op(req, self.path.startswith("/router/apply"))).encode(), "application/json")
        if self.path in ("/lan/scan", "/lan/name", "/alerts/dismiss", "/config"):
            try:
                n = int(self.headers.get("Content-Length") or 0)
                req = json.loads(self.rfile.read(min(n, 5000)) or b"{}")
            except Exception:
                return self._send(b"bad request", "text/plain", 400)
            if self.path == "/lan/scan":
                if ARGS.demo:
                    lan_state["scanning"] = True
                    threading.Timer(2.5, lambda: lan_state.update(scanning=False)).start()
                    ok = True
                else:
                    ok = start_scan()
                res = dict(ok=ok)
            elif self.path == "/lan/name":
                set_device_name(str(req.get("mac", "")), str(req.get("name", "")))
                res = dict(ok=True)
            elif self.path == "/alerts/dismiss":
                dismiss_alerts(req)
                res = dict(ok=True)
            else:
                if "notify" in req:
                    CONFIG["notify"] = bool(req["notify"])
                if "outage" in req:
                    CONFIG["outage"] = bool(req["outage"])
                if "rate_mb" in req:
                    try:
                        CONFIG["rate_mb"] = max(0, min(10000, float(req["rate_mb"])))
                    except (TypeError, ValueError):
                        pass
                if req.get("trust_add") or req.get("trust_del"):
                    set_trusted(req.get("trust_add"), req.get("trust_del"))
                save_config()
                res = dict(ok=True, notify=CONFIG["notify"])
            return self._send(json.dumps(res).encode(), "application/json")
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
            ol = outage_log()
            with lock:
                conns = [dict(c, host=host_of(c["rip"]), kind=kind_of(c["rip"])) for c in state["conns"]]
                body = json.dumps(dict(conns=conns, listen=state["listen"], rates=state["rates"],
                                       events=list(events)[:120], alerts=list(alerts)[:15],
                                       geo={c["rip"]: geo.get(c["rip"], {}) for c in conns}, me=me_geo,
                                       geo_on=ARGS.geo, geo_pending=geo_state["pending"], geo_err=geo_state["err"],
                                       demo=ARGS.demo, totals=state.get("totals", {}), lan=lan_rows(), lan_scanning=lan_state["scanning"],
                                       quality={k: list(v) for k, v in net_q.items()}, notify=CONFIG["notify"],
                                       session=dict(sess, now=time.time()), outages=ol, down_since=outage["since"],
                                       rules=dict(rate_mb=CONFIG.get("rate_mb", 0), outage=bool(CONFIG.get("outage", True)), trusted=CONFIG.get("trusted") or []),
                                       rt=rt_info())).encode()
            self._send(body, "application/json")
        elif path == "/export":
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            body, ctype, fname = export_data((q.get("what") or [""])[0], (q.get("fmt") or ["csv"])[0])
            self._send(body, ctype, extra=[("Content-Disposition", f'attachment; filename="{fname}"')])
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
aside{width:400px;flex:none;background:var(--panel);border-left:1px solid var(--line);display:flex;flex-direction:column;min-height:0}
.tabs{display:flex;padding:10px 6px 0;gap:0;border-bottom:1px solid var(--line)}
.tab{flex:1;background:none;border:0;color:var(--tx3);font:inherit;font-size:11px;font-weight:560;padding:9px 0 12px;cursor:pointer;position:relative;white-space:nowrap;transition:color .15s}
.tab:hover{color:var(--tx2)}.tab.on{color:var(--tx)}
.tab.on::after{content:"";position:absolute;left:10px;right:10px;bottom:-1px;height:2px;border-radius:2px;background:var(--acc);box-shadow:0 0 12px var(--acc)}
.badge{display:inline-block;min-width:16px;padding:1px 5px;margin-left:3px;border-radius:9px;background:var(--bad);color:#fff;font-size:10px;font-weight:700;line-height:14px;text-align:center}
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
.router .btn{display:inline-block;text-decoration:none;font-size:12.5px;padding:8px 14px}
.router label{display:block;font-size:11px;color:var(--tx3);margin:0 0 4px}
.in{width:100%;background:rgba(255,255,255,.05);border:1px solid var(--line2);border-radius:8px;color:var(--tx);font:inherit;padding:8px 10px;outline:0;transition:.15s}
.in:focus{border-color:rgba(167,139,250,.6);box-shadow:0 0 0 3px rgba(167,139,250,.15)}
.rt-f{margin-top:10px}.rt-two{display:grid;grid-template-columns:1fr 1.4fr;gap:8px;margin-top:10px}
.rt-msg{margin-top:10px;padding:9px 11px;border-radius:9px;font-size:12.5px;background:rgba(255,255,255,.05)}
.rt-msg.ok{background:rgba(91,227,154,.1);color:var(--ok)}.rt-msg.err{background:rgba(255,107,129,.1);color:var(--bad)}.rt-msg.warn{background:rgba(245,185,74,.1);color:var(--warn)}
.band{display:flex;gap:9px;align-items:flex-start;padding:7px 0;color:var(--tx);font-size:12.5px;cursor:pointer}
.band input{margin-top:3px;accent-color:#a78bfa}
.band .dim{display:block;font-size:11.5px}
.band a{color:var(--acc);cursor:pointer;text-decoration:underline;text-underline-offset:2px}
#rt-logw{margin-top:10px;font-size:11.5px;color:var(--tx3)}
#rt-log{white-space:pre-wrap;word-break:break-all;font:11px/1.5 var(--mono);margin:6px 0 0;max-height:160px;overflow:auto;user-select:text}
.qrow{display:flex;align-items:center;gap:12px;padding:8px 2px;border-bottom:1px solid var(--line)}
.qrow:last-of-type{border:0}
.qs{width:150px;height:30px;flex:none;overflow:visible}
.qrow b.bad{color:var(--bad)}
.al-a{margin-top:8px}
.alert.dev{border-color:rgba(245,185,74,.3);border-left-color:var(--warn);background:rgba(245,185,74,.07)}
.kbrow{display:flex;justify-content:space-between;align-items:center;padding:6px 0;color:var(--tx2)}
.kbrow kbd{margin-left:4px;font-size:11px;padding:3px 7px}
@media (max-width:1600px){#top .chip span{display:none}#top .chip{padding:0 12px}.search{flex-basis:210px}}
@media (max-width:1320px){.search{flex-basis:120px;min-width:100px}.brand{padding:0 10px 0 9px}.seg button{padding:0 10px}}
.btn.sm{padding:6px 11px;font-size:12px;border-radius:8px;box-shadow:none}
.btn.sm:hover{box-shadow:none}
.btn:disabled{opacity:.5;cursor:default;transform:none}
button.pill{border:0;cursor:pointer;font-family:var(--mono)}button.pill:hover{background:rgba(255,255,255,.14);color:#fff}
#rview{position:absolute;left:14px;right:14px;top:62px;bottom:14px;z-index:3;display:flex;flex-direction:column;overflow:hidden}
.rv-main{display:flex;flex-direction:column;flex:1;min-height:0}
.rv-bar{display:flex;align-items:center;gap:8px;padding:8px 10px;border-bottom:1px solid var(--line);flex-wrap:wrap}
.rv-bar b{margin-right:auto;font-weight:650;padding-left:4px}
.rv-bar .btn{display:inline-block;text-decoration:none}
#rv-frame{flex:1;width:100%;border:0;background:#fff;min-height:0}
.rv-login{margin:auto;width:min(390px,calc(100% - 40px));padding:26px;text-align:center}
.rv-login h3{margin:10px 0 6px;font-size:16px}.rv-login p{margin:0 0 14px;color:var(--tx2)}
.rv-login .ic{width:44px;height:44px;margin:0 auto;border-radius:13px;display:grid;place-items:center;background:rgba(167,139,250,.14);color:var(--acc);box-shadow:inset 0 0 0 1px rgba(167,139,250,.3)}
.rv-login .ic svg{width:22px;height:22px}
.rv-login label{display:block;font-size:11px;color:var(--tx3);margin:0 0 4px;text-align:left}
.tout{font:11.5px/1.55 var(--mono);white-space:pre-wrap;word-break:break-word;background:rgba(255,255,255,.04);border:1px solid var(--line);border-radius:10px;padding:10px 12px;margin:12px 0 0;user-select:text;max-height:none}
.tout.err{border-color:rgba(255,107,129,.3)}
.drow.open{background:rgba(255,255,255,.035);border-radius:10px;margin-bottom:4px}
.dacts{display:flex;flex-wrap:wrap;gap:6px;padding:2px 9px 10px 28px}
.dacts .btn{display:inline-block;text-decoration:none}
.dports{padding:0 9px 10px 28px;display:flex;gap:5px;flex-wrap:wrap;color:var(--tx2);font-size:12px}
.spk{width:64px;height:18px;flex:none;overflow:visible}
.alert.rate{border-color:rgba(245,185,74,.3);border-left-color:var(--warn);background:rgba(245,185,74,.07)}
.alert.net{border-color:rgba(62,224,203,.3);border-left-color:var(--wan);background:rgba(62,224,203,.06)}
.num{text-align:right;font-family:var(--mono)}
#app.focus aside{display:none}
#app.focus #top>:not(.brand):not(.seg):not(#pause){display:none}
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
   <button id="vr"><svg class="i" viewBox="0 0 24 24"><rect x="3" y="14" width="18" height="6" rx="2"/><path d="M7 17h.01M11 17h.01M8 11a5.5 5.5 0 0 1 8 0M5.5 8.5a9 9 0 0 1 13 0"/></svg>Роутер</button>
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
  <div class="stat"><b id="s-ping">–</b><span>пинг</span></div>
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
  <div class="st-r"><span>Устройства сети на графе</span><label class="sw"><input type="checkbox" id="c-devs"><i></i></label></div>
  <div class="st-s">Уведомления и данные</div>
  <div class="st-r"><span>Системные уведомления</span><label class="sw"><input type="checkbox" id="c-notify" checked><i></i></label></div>
  <div class="st-r"><span>Тревога при трафике процесса выше, МБ/с <span class="dim">(0 — выкл.)</span></span><input class="in num" id="c-rate" type="number" min="0" max="10000" step="1" style="width:74px"></div>
  <div class="st-r" style="align-items:flex-start"><span>Доверенные процессы <span class="dim">(без тревог о новых соединениях)</span></span></div>
  <div class="chips" id="c-trust" style="padding:0 16px 6px"></div>
  <div class="st-r"><span>Акцентный цвет</span><span id="c-acc" style="display:flex;gap:7px"></span></div>
  <div class="st-r"><span>Следить за обрывами интернета</span><label class="sw"><input type="checkbox" id="c-outage" checked><i></i></label></div>
  <div class="st-r"><span>Режим фокуса <kbd>H</kbd></span><button class="btn ghost sm" id="c-focus">Включить</button></div>
  <div class="st-r"><span>Экспорт (CSV)</span><div class="seg mini"><button id="ex-conns">Соединения</button><button id="ex-dev">Устройства</button><button id="ex-log">Лог</button></div></div>
  <div class="st-r"><span>Горячие клавиши</span><button class="btn ghost sm" id="st-help">Показать (?)</button></div>
  <div class="st-s">Wi-Fi роутера</div>
  <div class="router"><b>GPON-терминал MA670V3</b> (Photonspeak / Dragon Path GP700)
   <div class="rt-f"><label>Адрес роутера</label><input class="in mono" id="rt-host" value="192.168.1.1" spellcheck="false"></div>
   <div class="rt-two"><div><label>Логин</label><input class="in" id="rt-user" value="admin" autocomplete="off" spellcheck="false"></div>
   <div><label>Пароль админки</label><input class="in" id="rt-pass" type="password" autocomplete="off" placeholder="пароль админки"></div></div>
   <button class="btn" id="rt-connect" style="margin-top:10px">Подключиться</button>
   <a class="btn ghost" id="rt-open" target="_blank" rel="noopener" hidden>Открыть админку</a>
   <div class="rt-msg" id="rt-msg" hidden></div>
   <div id="rt-edit" hidden>
    <div class="rt-f"><label>Диапазоны</label><div id="rt-bands"></div></div>
    <div class="rt-f"><label>Новое имя сети (SSID)</label><input class="in" id="rt-ssid" maxlength="32" spellcheck="false"></div>
    <div class="rt-f"><label>Новый пароль Wi-Fi <span class="dim">(пусто — не менять)</span></label><input class="in" id="rt-psk" maxlength="63" autocomplete="off" spellcheck="false" placeholder="8–63 символа"></div>
    <button class="btn" id="rt-apply" style="margin-top:10px">Применить</button>
   </div>
   <details id="rt-logw" hidden><summary>Технический журнал</summary><pre id="rt-log"></pre></details>
  </div>
 </div>
 <div id="rview" class="glass" hidden>
  <div id="rv-main" class="rv-main" hidden>
   <div class="rv-bar"><b id="rv-title">Админка роутера</b>
    <button class="btn ghost sm" id="rv-home" title="Вернуться на стартовую страницу админки">В начало</button>
    <button class="btn ghost sm" id="rv-wifi" title="Быстро сменить имя и пароль Wi-Fi">Wi-Fi</button>
    <a class="btn ghost sm" id="rv-ext" target="_blank" rel="noopener">В новой вкладке</a>
    <button class="btn ghost sm" id="rv-off" title="Забыть сессию роутера">Отключить</button></div>
   <iframe id="rv-frame" title="Админка роутера" sandbox="allow-same-origin allow-scripts allow-forms allow-modals allow-popups allow-downloads"></iframe>
  </div>
  <div id="rv-login" class="rv-login glass" hidden>
   <div class="ic"><svg class="i" viewBox="0 0 24 24"><rect x="3" y="14" width="18" height="6" rx="2"/><path d="M7 17h.01M11 17h.01M8 11a5.5 5.5 0 0 1 8 0M5.5 8.5a9 9 0 0 1 13 0"/></svg></div>
   <h3>Админка роутера</h3>
   <p>Войдите один раз — NetGraph откроет панель управления роутера прямо здесь и будет держать сессию.</p>
   <div class="rt-f" style="text-align:left"><label>Адрес роутера</label><input class="in mono" id="rv-host" value="192.168.1.1" spellcheck="false"></div>
   <div class="rt-two" style="text-align:left"><div><label>Логин</label><input class="in" id="rv-user" value="admin" autocomplete="off" spellcheck="false"></div>
   <div><label>Пароль админки</label><input class="in" id="rv-pass" type="password" autocomplete="off" placeholder="пароль"></div></div>
   <button class="btn" id="rv-go" style="margin-top:14px;width:100%">Войти в админку</button>
   <div class="rt-msg" id="rv-msg" hidden style="text-align:left"></div>
   <div class="fine">Пароль хранится только в памяти запущенного NetGraph. Админка доступна только с этого компьютера.</div>
  </div>
 </div>
 <div id="mapcard" class="glass card" hidden></div>
 <div id="help" class="glass card" hidden style="text-align:left;width:min(360px,calc(100% - 30px));z-index:9">
  <div class="rw" style="margin-bottom:8px"><b style="font-size:15px">Горячие клавиши</b><span class="dim">Esc — закрыть</span></div>
  <div class="kbrow"><span>Поиск</span><span><kbd>/</kbd></span></div>
  <div class="kbrow"><span>Граф / Карта / Роутер</span><span><kbd>G</kbd><kbd>M</kbd><kbd>R</kbd></span></div>
  <div class="kbrow"><span>Вкладка «Сеть»</span><span><kbd>N</kbd></span></div>
  <div class="kbrow"><span>Вкладка «Утилиты»</span><span><kbd>U</kbd></span></div>
  <div class="kbrow"><span>Режим фокуса (без панели)</span><span><kbd>H</kbd></span></div>
  <div class="kbrow"><span>Пауза</span><span><kbd>P</kbd></span></div>
  <div class="kbrow"><span>Вписать в экран</span><span><kbd>F</kbd></span></div>
  <div class="kbrow"><span>Настройки</span><span><kbd>S</kbd></span></div>
  <div class="kbrow"><span>Эта подсказка</span><span><kbd>?</kbd></span></div>
 </div>
 <div id="splash" class="glass card" hidden></div>
 <div id="tip"></div>
</main>

<aside>
 <nav class="tabs">
  <button class="tab on" data-t="node">Узел</button>
  <button class="tab" data-t="geo">Гео</button>
  <button class="tab" data-t="net">Сеть</button>
  <button class="tab" data-t="ev">Лог</button>
  <button class="tab" data-t="al">Тревоги<span class="badge" id="b-al" hidden>0</span></button>
  <button class="tab" data-t="hist">История</button>
  <button class="tab" data-t="tools">Утилиты</button>
 </nav>
 <section class="pane on" id="pane-node"></section>
 <section class="pane" id="pane-geo"></section>
 <section class="pane" id="pane-net"></section>
 <section class="pane ev" id="pane-ev"></section>
 <section class="pane" id="pane-al"></section>
 <section class="pane" id="pane-hist"></section>
 <section class="pane" id="pane-tools">
  <div class="sec-t">Сетевые утилиты</div>
  <input class="in mono" id="t-host" placeholder="Хост или IP-адрес" spellcheck="false" autocomplete="off">
  <div class="chips" id="t-chips" style="margin:8px 0 12px">
   <button class="pill" data-q="gw">роутер</button><button class="pill" data-q="1.1.1.1">1.1.1.1</button><button class="pill" data-q="8.8.8.8">8.8.8.8</button><button class="pill" data-q="google.com">google.com</button><button class="pill" data-q="github.com">github.com</button>
  </div>
  <div class="pills" id="t-tools"><button data-tool="ping" class="on">Ping</button><button data-tool="trace">Трасса</button><button data-tool="dns">DNS</button><button data-tool="ports">Порты</button></div>
  <div class="pills" id="t-tools2"><button data-tool="http">HTTP</button><button data-tool="ssl">SSL</button><button data-tool="ip">Кто это</button><button data-tool="wol">WoL</button></div>
  <input class="in mono" id="t-ports" placeholder="Порты через запятую: 22,80,443" spellcheck="false" autocomplete="off" hidden style="margin-top:6px">
  <button class="btn" id="t-run" style="margin-top:10px;width:100%">Запустить</button>
  <pre id="t-out" class="tout" hidden></pre>
  <div class="hint">Ping и трассировка запускают системные ping/traceroute. «Кто это» отправляет IP в ip-api.com. WoL: вместо хоста введите MAC (AA:BB:CC:DD:EE:FF).</div>
  <div class="sec-t" style="margin-top:20px">Скорость интернета</div>
  <button class="btn" id="sp-run" style="width:100%">Запустить тест</button>
  <div id="sp-out" class="rates" hidden style="margin-top:10px"></div>
  <div class="hint" id="sp-note" hidden>Тест качает и отдаёт данные через speed.cloudflare.com (до ~35 МБ).</div>
  <div class="sec-t" style="margin-top:20px">Калькулятор подсети</div>
  <input class="in mono" id="sn-in" placeholder="192.168.1.0/24" spellcheck="false" autocomplete="off">
  <pre id="sn-out" class="tout" hidden></pre>
  <div class="sec-t" style="margin-top:20px">Генератор пароля Wi-Fi</div>
  <div style="display:flex;gap:6px"><input class="in mono" id="pw-out" readonly placeholder="нажмите «Создать»" style="flex:1"><input class="in num" id="pw-len" type="number" min="8" max="63" value="16" style="width:62px" title="Длина"></div>
  <div style="display:flex;gap:6px;margin-top:6px"><button class="btn ghost sm" id="pw-gen" style="flex:1">Создать</button><button class="btn ghost sm" id="pw-copy" style="flex:1">Копировать</button><button class="btn ghost sm" id="pw-set" style="flex:1">В поле роутера</button></div>
 </section>
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
const cfg=Object.assign({mode:'globe',rotate:true,labels:false,devs:false,interval:2000},(()=>{try{return JSON.parse(localStorage.getItem('ng-cfg')||'{}')}catch(e){return{}}})());
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
 if(cfg.devs&&d.lan)d.lan.forEach(v=>{
  if(v.role==='me')return;
  const nmv=v.name||v.host||(v.role==='router'?'Роутер':v.ip);
  if(q&&!(nmv+v.ip+v.mac).toLowerCase().includes(q))return;
  const id='d:'+(v.mac||v.ip);node(id,{label:nmv,type:'lan',dev:v,ips:new Set([v.ip]),procs:new Set()}).deg++;link('me',id,'lan')});
 d.listen.forEach(x=>{const p=nm.get('p:'+x.proc);if(p)p.listen.add(x.port+'/'+x.proto)});
 for(const[name,s]of Object.entries(pids)){
  const p=nm.get('p:'+name);let i=0,o=0;
  s.forEach(pid=>{const r=d.rates[pid];if(r){i+=r[0];o+=r[1]}});
  p.rin=i;p.rout=o;p.rate=i+o;p.pids=s;
  let ti=0,to=0;s.forEach(pid=>{const t=d.totals&&d.totals[pid];if(t){ti+=t[0];to+=t[1]}});p.tin=ti;p.tout=to;
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
 else if(n.dev){h+=`<div class="dim mono">${esc(n.dev.ip)}</div><div class="dim mono">${esc(n.dev.mac)}</div>`}
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
 if(!nodes.length||view!=='g')return;const r=$('g').getBoundingClientRect();if(r.width<50||r.height<50)return;
 let x0=1e9,y0=1e9,x1=-1e9,y1=-1e9;
 nodes.forEach(n=>{if(n.x==null)return;x0=Math.min(x0,n.x);y0=Math.min(y0,n.y);x1=Math.max(x1,n.x);y1=Math.max(y1,n.y)});
 if(x0>x1)return;
 const w=x1-x0+140,h=y1-y0+190,k=Math.max(.2,Math.min(1.4,Math.min(r.width/w,r.height/h)));
 const t=d3.zoomIdentity.translate(r.width/2,r.height/2+30).scale(k).translate(-(x0+x1)/2,-(y0+y1)/2);
 (animate?svg.transition().duration(700):svg).call(zoom.transform,t);
}

/* ── панель «Узел» ── */
const COMMON=new Set([20,21,22,25,53,80,110,123,143,443,465,587,853,993,995,1900,3478,5222,5228,5353,8080,8443]);
const odd=(port,proto)=>proto==='TCP'&&+port>0&&+port<49152&&!COMMON.has(+port)?'<span class="tag warn" title="Нестандартный порт">порт</span>':'';
const fmtB=b=>b<1024?Math.round(b)+' Б':b<1048576?(b/1024).toFixed(1)+' КБ':b<1073741824?(b/1048576).toFixed(1)+' МБ':(b/1073741824).toFixed(2)+' ГБ';
const ago=s=>s<90?'только что':s<5400?Math.round(s/60)+' мин назад':s<172800?Math.round(s/3600)+' ч назад':Math.round(s/86400)+' дн назад';
const post=(p,b)=>fetch(p,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b||{})}).then(r=>r.json()).catch(()=>({}));
function devInfo(v){return `<div class="geo"><div class="big">${esc(v.name||v.host||(v.role==='router'?'Роутер':'Неизвестное устройство'))}</div><div class="mono dim">${esc(v.ip)}${v.mac?' · '+esc(v.mac):''}</div><div class="dim">${v.role==='router'?'Роутер (шлюз по умолчанию)':'Виден '+ago(v.seen)}</div>${v.private?'<div class="dim" style="margin-top:6px">Приватный (случайный) MAC-адрес</div>':''}</div>`}
const conRow=(h,port,proto,st)=>{const cls=st==='ESTABLISHED'?'ok':/WAIT|CLOSE|SYN|FIN/.test(st)?'warn':'';
 return `<div class="conn"><span class="mono">${esc(h)}:${esc(port)}</span><span class="tag">${esc(proto)}</span>${odd(port,proto)}<span class="tag ${cls}">${esc(st)}</span></div>`};
const rateHist={};
function trackRates(d){
 const pn={},sum={};d.conns.forEach(c=>pn[c.pid]=c.proc);
 Object.entries(d.rates).forEach(([pid,v])=>{const n=pn[pid];if(n)sum[n]=(sum[n]||0)+v[0]+v[1]});
 Object.keys(sum).forEach(n=>{const a=rateHist[n]||(rateHist[n]=[]);a.push(sum[n]);if(a.length>30)a.shift()});
 Object.keys(rateHist).forEach(n=>{if(n in sum)return;const a=rateHist[n];a.push(0);if(a.length>30)a.shift();if(a.length>=30&&a.every(x=>x===0))delete rateHist[n]});
}
function pSpark(n,w=64,h=18){const a=rateHist[n];if(!a||a.length<2)return '';const mx=Math.max(1,...a);
 const pts=a.map((v,i)=>`${(i/(a.length-1)*w).toFixed(1)},${(h-1.5-v/mx*(h-3)).toFixed(1)}`).join(' ');
 return `<svg class="spk" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none"><polyline points="${pts}" fill="none" stroke="${COL.proc}" stroke-width="1.4" stroke-linejoin="round" vector-effect="non-scaling-stroke"/></svg>`}
function topProcs(){
 const ps=nodes.filter(x=>x.type==='proc').sort((a,b)=>b.rate-a.rate||b.deg-a.deg).slice(0,10),mx=Math.max(1,...ps.map(p=>p.rate));
 return '<div class="sec-t">Топ процессов</div>'+(ps.length?ps.map(p=>`<div class="row click" data-id="${esc(p.id)}"><i class="dotc" style="color:${COL.proc};background:${COL.proc}"></i><div class="grow"><div class="rw"><span class="nm">${esc(p.label)}</span><span class="dim">${p.rate>1?fmt(p.rate):p.deg+' соед.'}</span></div><div class="bar"><i style="width:${Math.max(3,p.rate/mx*100)}%;background:${COL.proc}"></i></div></div>${pSpark(p.label)}</div>`).join(''):empty('node','Нет соединений','Попробуйте убрать фильтр или запустить с sudo'))}
function details(){
 const el=$('pane-node'),n=sel&&nodes.find(x=>x.id===sel);let h='';
 if(!n||n.type==='me'){h=topProcs()+'<p class="hint">Нажмите на узел графа, чтобы увидеть подробности. Колёсико — масштаб, перетаскивание — перемещение.</p>'}
 else{
  const c=COL[n.type]||COL.wan;
  const hd=sub=>`<div class="hd"><i class="dotc big" style="color:${c};background:${c}"></i><div><div class="ttl">${esc(n.label)}</div><div class="dim">${sub}</div></div></div>`;
  if(n.type==='proc'){
   h+=hd(`${n.pids?[...n.pids].map(p=>'PID '+p).slice(0,3).join(', '):''}${n.pids&&n.pids.size>3?' …':''}`);
   h+=`<div class="rates"><div class="rate d"><span>↓ приём</span><b>${fmt(n.rin||0)}</b></div><div class="rate u"><span>↑ отдача</span><b>${fmt(n.rout||0)}</b></div></div>`+(rateHist[n.label]?'<div style="margin:2px 2px 8px">'+pSpark(n.label,340,38).replace('class="spk"','class="spk" style="width:100%;height:38px"')+'<div class="dim" style="font-size:11px">трафик за последнее время</div></div>':'')+(n.tin||n.tout?`<div class="dim" style="font-size:12px;margin:0 2px">с запуска процесса: ↓ ${fmtB(n.tin)} · ↑ ${fmtB(n.tout)}</div>`:'');
   if(n.listen&&n.listen.size)h+=`<div class="sec-t">Слушает</div><div class="chips">${[...n.listen].slice(0,14).map(x=>`<span class="pill">${esc(x)}</span>`).join('')}</div>`;
   h+=`<button class="btn ghost sm" data-trust="${esc(n.label)}" style="margin:8px 0 0">${trusted().includes(n.label)?'✓ Доверенный — убрать':'Доверять (без тревог)'}</button>`;
   h+=`<div class="sec-t">Соединения · ${n.info.size}</div>`+[...n.info.values()].slice(0,80).map(i=>conRow(i.host,i.port,i.proto,i.state)).join('');
  }else if(n.dev){
   h+=hd(n.dev.role==='router'?'роутер':'устройство в сети')+devInfo(n.dev);
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
 stage.classList.toggle('map',v==='m');$('vg').classList.toggle('on',v==='g');$('vm').classList.toggle('on',v==='m');$('vr').classList.toggle('on',v==='r');
 $('legend').style.display=v==='g'?'':'none';$('mapleg').style.display=v==='m'?'':'none';
 $('stats').style.display=$('zoomctl').style.display=v==='r'?'none':'';
 $('rview').hidden=v!=='r';
 hideTip();
 if(v==='m'){sim.stop();loadWorld();if(cfg.mode==='flat')mapLayout();data&&drawMap(data);setTab('geo')}
 else if(v==='r'){sim.stop();setCard('');if(tab==='geo')setTab('node');rvEnter()}
 else{setCard('');data&&build(data);if(tab==='geo')setTab('node')}
}
$('vg').onclick=()=>setView('g');$('vm').onclick=()=>setView('m');$('vr').onclick=()=>setView('r');
const refresh=()=>{if(!data)return;if(view==='g')build(data);else if(view==='m')drawMap(data)};
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
 if(e.target.tagName==='INPUT'&&e.target.type!=='checkbox'){if(e.key==='Escape'){e.target.value='';e.target.blur();refresh()}return}
 if(e.metaKey||e.ctrlKey||e.altKey)return;
 if(e.key==='/'){e.preventDefault();$('q').focus()}
 else if(e.key==='g')setView('g');else if(e.key==='m')setView('m');
 else if(e.key==='p')$('pause').click();else if(e.key==='f')$('zfit').click();
 else if(e.key==='s')toggleSettings();else if(e.key==='n')setTab('net');else if(e.key==='u')setTab('tools');else if(e.key==='r')setView('r');else if(e.key==='h')setFocus();else if(e.key==='?')$('help').hidden=!$('help').hidden;
 else if(e.key==='Escape'){select(null);toggleSettings(false);$('help').hidden=true;setFocus(false)}
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
 trackRates(d);
 let i=0,o=0;Object.values(d.rates).forEach(v=>{i+=v[0];o+=v[1]});
 tp.push([i,o]);if(tp.length>60)tp.shift();
 $('s-c').textContent=d.conns.length;$('s-p').textContent=new Set(d.conns.map(c=>c.proc)).size;
 $('s-h').textContent=new Set(d.conns.filter(c=>c.kind!=='local').map(c=>c.rip)).size;
 $('s-d').textContent=fmt(i);$('s-u').textContent=fmt(o);spark();
 const iq=(d.quality&&d.quality.inet)||[],lq=iq.length?iq[iq.length-1]:undefined,pe=$('s-ping');
 if(lq===undefined){pe.textContent='–';pe.style.color=''}else if(lq===null){pe.textContent='нет';pe.style.color='var(--bad)'}
 else{pe.textContent=Math.round(lq)+' мс';pe.style.color=lq<50?'var(--ok)':lq<150?'var(--warn)':'var(--bad)'}
}
function setLive(ok){$('live').classList.toggle('off',!ok);$('live').title=ok?'Данные поступают':'Нет связи с сервером'}

/* Лог / тревоги / история */
function eventsUI(ev){
 const h=ev&&ev.length?ev.map(e=>`<div><span class="dim">${esc(e.t)}</span> <span class="p ${e.s==='+'?'add':'del'}">${e.s==='+'?'+':'−'}</span> ${esc(e.proc)} <span class="dim">→</span> ${esc(e.remote)}<span class="dim">:${esc(e.port)}</span></div>`).join(''):empty('list','Событий пока нет','Здесь будут появляться новые и закрытые соединения');
 const el=$('pane-ev');if(el._h!==h){el.innerHTML=h;el._h=h}
}
let lastAl=-1;
let alertsList=[];
function alertsUI(a){
 a=a||[];alertsList=a;const b=$('b-al');b.textContent=a.length;b.hidden=!a.length;
 const card=(x,i)=>x.kind==='rate'
  ?`<div class="alert rate"><div class="rw"><b>Всплеск трафика</b><span class="dim">${esc(x.t)}</span></div><div>${esc(x.proc)}</div><div class="dim mono">${esc(x.remote)}</div><div class="al-a"><button class="btn ghost sm" data-ai="${i}">Понятно</button></div></div>`
  :x.kind==='net'
  ?`<div class="alert net"><div class="rw"><b>Интернет пропадал</b><span class="dim">${esc(x.t)}</span></div><div>${esc(x.remote)}</div><div class="al-a"><button class="btn ghost sm" data-ai="${i}">Понятно</button></div></div>`
  :x.kind==='device'
  ?`<div class="alert dev"><div class="rw"><b>Новое устройство в сети</b><span class="dim">${esc(x.t)}</span></div><div class="mono">${esc(x.ip)} · ${esc(x.mac||x.remote)}</div><div class="al-a"><button class="btn ghost sm" data-ai="${i}">Это моё</button></div></div>`
  :`<div class="alert"><div class="rw"><b>${esc(x.proc)}</b><span class="dim">${esc(x.t)}</span></div><div>→ ${esc(x.remote)}</div><div class="dim mono">${esc(x.ip)}</div><div class="al-a"><button class="btn ghost sm" data-ai="${i}">Доверять</button></div></div>`;
 const h=a.length?`<div class="rw" style="margin:0 2px 12px;align-items:center;gap:10px"><span class="hint" style="margin:0">Новые домены и устройства, всплески трафика и обрывы интернета.</span><button class="btn ghost sm" data-ai="all">Очистить</button></div>`+a.map(card).join(''):empty('ok','Всё спокойно','Тревог нет');
 const el=$('pane-al');if(el._h!==h){el.innerHTML=h;el._h=h}
}
$('pane-al').addEventListener('click',async e=>{
 const b=e.target.closest('[data-ai]');if(!b)return;
 const x=b.dataset.ai==='all'?{all:true}:(({t,proc,remote})=>({t,proc,remote}))(alertsList[+b.dataset.ai]);
 await post('/alerts/dismiss',x);poll()});
/* ── вкладка «Сеть» ── */
function qSpark(arr,color){
 const W=150,H=30,n=arr.length;if(n<2)return '<svg class="qs" viewBox="0 0 150 30"></svg>';
 const mx=Math.max(50,...arr.filter(v=>v!=null)),x=d3.scaleLinear([0,n-1],[0,W]),y=d3.scaleLinear([0,mx],[H-2,2]);
 const ln=d3.line().defined(v=>v!=null).curve(d3.curveMonotoneX).x((_,i)=>x(i)).y(v=>y(v));
 const miss=arr.map((v,i)=>v==null?`<rect x="${(x(i)-1).toFixed(1)}" y="0" width="2.5" height="${H}" fill="#ff6b81" opacity=".55"/>`:'').join('');
 return `<svg class="qs" viewBox="0 0 ${W} ${H}">${miss}<path d="${ln(arr)||''}" fill="none" stroke="${color}" stroke-width="1.6"/></svg>`}
function qRow(name,arr,color){
 const ok=arr.filter(v=>v!=null),loss=arr.length?Math.round((arr.length-ok.length)/arr.length*100):0,last=arr.length?arr[arr.length-1]:undefined;
 const avg=ok.length?Math.round(ok.reduce((p,c)=>p+c,0)/ok.length):null;
 return `<div class="qrow"><div class="grow"><div class="rw"><span>${name}</span><b class="${last==null&&last!==undefined?'bad':''}">${last===undefined?'–':last===null?'нет ответа':Math.round(last)+' мс'}</b></div><div class="dim" style="font-size:11px">среднее ${avg==null?'–':avg+' мс'} · потери ${loss}%</div></div>${qSpark(arr,color)}</div>`}
let devSel=null;const devPorts={};
function devRow(v){
 const tags=[v.role==='router'?'роутер':'',v.role==='me'?'этот Mac':'',v.new?'новое':'',v.private?'приватный MAC':''].filter(Boolean);
 const nmv=v.name||v.host||(v.role==='router'?'Роутер':v.role==='me'?'Этот Mac':'Неизвестное устройство');
 const c=v.role==='router'?COL.proc:v.role==='me'?'#fff':COL.lan,open=devSel===v.ip;
 const acts=open?`<div class="dacts">${v.mac?'<button class="btn ghost sm" data-act="name">Назвать</button><button class="btn ghost sm" data-act="wol" title="Wake-on-LAN">Разбудить</button>':''}<button class="btn ghost sm" data-act="ping">Пинг</button><button class="btn ghost sm" data-act="ports">Порты</button><a class="btn ghost sm" href="http://${esc(v.ip)}" target="_blank" rel="noopener">Открыть</a></div>${devPorts[v.ip]?`<div class="dports">${devPorts[v.ip]}</div>`:''}`:'';
 return `<div class="drow ${open?'open':''}"><div class="row click" data-ip="${esc(v.ip)}" data-mac="${esc(v.mac)}" data-name="${esc(v.name||'')}" title="Нажмите, чтобы показать действия"><i class="dotc" style="color:${c};background:${c}"></i><div class="grow"><div class="rw"><span class="nm">${esc(nmv)}</span><span class="dim" style="font-size:11px">${v.role==='me'?'':ago(v.seen)}</span></div><div class="mono dim nm">${esc(v.ip)}${v.mac?' · '+esc(v.mac):''}</div>${tags.length?`<div class="chips" style="margin-top:4px">${tags.map(t=>`<span class="pill${t==='новое'?' add':''}">${t}</span>`).join('')}</div>`:''}</div></div>${acts}</div>`}
const durS=s=>s<60?Math.round(s)+' с':s<3600?Math.round(s/60)+' мин':(s/3600).toFixed(1)+' ч';
function netUI(d){
 const el=$('pane-net');if(!d)return;
 const q=d.quality||{},s=d.session||{in:0,out:0,since:0,now:0},mins=Math.max(1,Math.round((s.now-s.since)/60)),devs=d.lan||[];
 let h='<div class="sec-t">Качество связи</div>'+qRow('Роутер',q.gw||[],COL.lan)+qRow('Интернет (1.1.1.1)',q.inet||[],COL.wan);
 h+='<div class="hint" style="margin:6px 2px 0">Задержка измеряется временем TCP-рукопожатия, каждые 3 с.</div>';
 const ol=d.outages||[];
 h+='<div class="sec-t">Обрывы интернета</div>';
 if(d.down_since)h+=`<div class="alert"><b>Сейчас нет связи</b> <span class="dim">с ${new Date(d.down_since*1000).toLocaleTimeString('ru-RU')}</span></div>`;
 h+=ol.length?ol.map(([a,b])=>`<div class="row"><i class="dotc" style="color:var(--bad);background:var(--bad)"></i><div class="grow"><div class="rw"><span>${new Date(a*1000).toLocaleString('ru-RU',{day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'})}</span><span class="dim">${durS(b-a)}</span></div></div></div>`).join(''):'<div class="dim" style="padding:2px 9px;font-size:12px">обрывов не зафиксировано</div>';
 h+=`<div class="sec-t">Трафик за сессию</div><div class="rates"><div class="rate d"><span>↓ получено</span><b>${fmtB(s.in)}</b></div><div class="rate u"><span>↑ отправлено</span><b>${fmtB(s.out)}</b></div></div><div class="dim" style="font-size:12px;margin:0 2px">за ${mins} мин работы NetGraph</div>`;
 h+=`<div class="rw" style="margin:18px 0 8px;align-items:center"><div class="sec-t" style="margin:0">Устройства в сети · ${devs.length}</div><button class="btn ghost sm" id="lan-scan" ${d.lan_scanning?'disabled':''}>${d.lan_scanning?'Сканирую…':'Сканировать'}</button></div>`;
 h+=devs.length?devs.map(devRow).join(''):empty('node','Устройств не найдено','Нажмите «Сканировать», чтобы опросить подсеть');
 if(el._h!==h){const st=el.scrollTop;el.innerHTML=h;el.scrollTop=st;el._h=h}
}
$('pane-net').addEventListener('click',async e=>{
 if(e.target.closest('#lan-scan')){await post('/lan/scan');poll();return}
 const a=e.target.closest('[data-act]');
 if(a){
  const r=a.closest('.drow').querySelector('.row'),ip=r.dataset.ip,mac=r.dataset.mac,act=a.dataset.act;
  if(act==='name'){const n=prompt('Название устройства (пусто — сбросить)',r.dataset.name);if(n!==null){await post('/lan/name',{mac,name:n});poll()}}
  else if(act==='wol'){a.disabled=true;const x=await post('/lan/wol',{mac});a.textContent=x.ok?'Отправлено ✓':'Не удалось';setTimeout(()=>{a.disabled=false},2500)}
  else if(act==='ping')toolFor('ping',ip);
  else if(act==='ports'){a.disabled=true;a.textContent='Сканирую…';const x=await post('/lan/ports',{ip});
   devPorts[ip]=x.ok?(x.open.length?x.open.map(([p,s])=>`<span class="pill">${p}${s?' · '+esc(s):''}</span>`).join(''):'Открытых портов не найдено'):esc(x.error||'Ошибка');netUI(data)}
  return}
 const r=e.target.closest('.row[data-ip]');if(!r)return;
 devSel=devSel===r.dataset.ip?null:r.dataset.ip;netUI(data)});
/* ── утилиты ── */
let tTool='ping',tGw='';
const toolBtns=()=>document.querySelectorAll('#t-tools button,#t-tools2 button');
toolBtns().forEach(b=>b.onclick=()=>{tTool=b.dataset.tool;toolBtns().forEach(x=>x.classList.toggle('on',x===b));$('t-ports').hidden=tTool!=='ports';$('t-host').placeholder=tTool==='wol'?'MAC-адрес AA:BB:CC:DD:EE:FF':'Хост или IP-адрес'});
$('t-chips').addEventListener('click',async e=>{const b=e.target.closest('[data-q]');if(!b)return;let v=b.dataset.q;
 if(v==='gw'){if(!tGw){try{tGw=(await (await fetch('/gateway')).json()).ip||''}catch(_){}}v=tGw}
 if(v)$('t-host').value=v});
async function runTool(){
 const host=$('t-host').value.trim();if(!host)return $('t-host').focus();
 const o=$('t-out'),b=$('t-run');o.hidden=false;o.className='tout';o.textContent='Выполняю…';b.disabled=true;
 try{const r=await post('/tool',{tool:tTool,host,ports:$('t-ports').value});o.textContent=r.out||r.error||'Нет ответа';o.className='tout'+(r.ok?'':' err')}
 finally{b.disabled=false}}
function toolFor(tool,host){setTab('tools');document.querySelector(`#t-tools [data-tool="${tool}"],#t-tools2 [data-tool="${tool}"]`).click();$('t-host').value=host;runTool()}
$('t-run').onclick=runTool;$('t-host').addEventListener('keydown',e=>{if(e.key==='Enter')runTool()});
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
  const cn=$('c-notify');if(document.activeElement!==cn)cn.checked=!!data.notify;
  if(data.rules){const cr=$('c-rate'),co=$('c-outage');if(document.activeElement!==cr)cr.value=data.rules.rate_mb;if(document.activeElement!==co)co.checked=data.rules.outage;trustUI()}
  hud(data);alertsUI(data.alerts);eventsUI(data.events);netUI(data);
  if(!paused){
   if(view==='g'){build(data);if(!firstFit&&nodes.length>1){firstFit=true;setTimeout(()=>fit(),1400)}}
   else if(view==='m')drawMap(data);
  }
 }catch(e){setLive(false);console.error(e)}
}
details();eventsUI([]);alertsUI([]);
(async function pollLoop(){await poll();setTimeout(pollLoop,cfg.interval)})();setInterval(()=>{if(tab==='hist')loadHistory()},15000);
/* ── настройки ── */
const stp=$('settings');
function syncCfg(){
 $('m-globe').classList.toggle('on',cfg.mode==='globe');$('m-flat').classList.toggle('on',cfg.mode==='flat');
 $('c-rot').checked=cfg.rotate;$('c-lbl').checked=cfg.labels;$('c-devs').checked=cfg.devs;svg.classed('alllbl',cfg.labels);
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
 if(g.ip){$('rt-host').value=g.ip;$('rt-open').href='http://'+g.ip;$('rt-open').hidden=false}}catch(e){}}
const rtMsg=(t,c)=>{const m=$('rt-msg');m.hidden=!t;m.className='rt-msg '+(c||'');m.textContent=t||''};
const rtLog=l=>{$('rt-logw').hidden=!(l&&l.length);$('rt-log').textContent=(l||[]).join('\n')};
const rtReq=()=>({host:$('rt-host').value.trim(),user:$('rt-user').value,pass:$('rt-pass').value});
async function rtCall(path,body){const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});return r.json()}
let rtBands=[];
$('rt-connect').onclick=async()=>{
 const b=$('rt-connect');b.disabled=true;b.textContent='Подключаюсь…';rtMsg('');$('rt-edit').hidden=true;
 try{
  const r=await rtCall('/router/probe',rtReq());rtLog(r.log);
  if(!r.ok){rtMsg(r.error||'Не удалось подключиться','err');return}
  rtBands=r.bands;
  $('rt-bands').innerHTML=r.bands.map(x=>x.ok?`<label class="band"><input type="checkbox" data-idx="${x.idx}" ${x.idx===0?'checked':''}><span><b>${esc(x.label)}</b> · ${esc(x.ssid)}<span class="dim">пароль: <span class="pw" data-pw="${esc(x.psk)}">•••••••</span> <a class="pwt">показать</a>${x.confirmed?'':' · диапазон не подтверждён роутером'}</span></span></label>`:`<div class="band dim"><span><b>${esc(x.label)}</b> — ${esc(x.error||'недоступен')}</span></div>`).join('');
  const b0=r.bands.find(x=>x.ok);$('rt-ssid').value=b0?b0.ssid:'';$('rt-psk').value='';
  $('rt-edit').hidden=false;rtMsg('Подключено. Измените имя и/или пароль и нажмите «Применить».','ok');
 }catch(e){rtMsg('Ошибка: '+e,'err')}
 finally{b.disabled=false;b.textContent='Подключиться'}
};
$('rt-bands').addEventListener('click',e=>{const a=e.target.closest('.pwt');if(!a)return;e.preventDefault();
 const pw=a.parentNode.querySelector('.pw'),shown=pw.dataset.shown==='1';pw.textContent=shown?'•••••••':pw.dataset.pw;pw.dataset.shown=shown?'0':'1';a.textContent=shown?'показать':'скрыть'});
$('rt-apply').onclick=async()=>{
 const bands=[...document.querySelectorAll('#rt-bands input:checked')].map(i=>+i.dataset.idx);
 const cur=rtBands.find(x=>x.ok&&bands.includes(x.idx)),ssid=$('rt-ssid').value.trim(),psk=$('rt-psk').value;
 const newSsid=cur&&ssid!==cur.ssid?ssid:'';
 if(!bands.length)return rtMsg('Выберите хотя бы один диапазон','warn');
 if(!newSsid&&!psk)return rtMsg('Нечего менять: введите новое имя или пароль','warn');
 if(psk&&(psk.length<8||psk.length>63))return rtMsg('Пароль: от 8 до 63 символов','warn');
 if(!confirm('Wi-Fi роутера перезапустится: устройства, подключённые по Wi-Fi (включая этот Mac, если он на Wi-Fi), на время отключатся, а затем потребуют новый пароль. Применить?'))return;
 const b=$('rt-apply');b.disabled=true;b.textContent='Применяю… (до 30 с)';rtMsg('Отправляю настройки в роутер…');
 try{
  const r=await rtCall('/router/apply',{...rtReq(),bands,ssid:newSsid,psk});rtLog(r.log);
  if(r.error)return rtMsg(r.error,'err');
  const lines=r.results.map(x=>{const n=x.idx===0?'2.4 ГГц':'5 ГГц',st=v=>v===true?'применено':v===false?'НЕ применилось':'не удалось подтвердить';
   return x.error?`${n}: ${x.error}`:`${n}:`+(x.ssid!==undefined?` имя — ${st(x.ssid)};`:'')+(x.psk!==undefined?` пароль — ${st(x.psk)};`:'')});
  rtMsg(lines.join('\n'),r.ok?'ok':'warn');$('rt-msg').style.whiteSpace='pre-line';
  if(r.ok)$('rt-psk').value='';
 }catch(e){rtMsg('Связь с роутером оборвалась — вероятно, Wi-Fi перезапускается. Подождите минуту и нажмите «Подключиться», чтобы проверить результат.','warn')}
 finally{b.disabled=false;b.textContent='Применить'}
};
/* ── админка роутера внутри NetGraph ── */
let rvPort=0;
function rvShow(port,host){
 rvPort=port;const url=location.protocol+'//'+location.hostname+':'+port+'/';
 $('rv-login').hidden=true;$('rv-main').hidden=false;$('rv-title').textContent='Админка роутера · '+host;$('rv-ext').href=url;
 const f=$('rv-frame');if(f.dataset.src!==url){f.dataset.src=url;f.src=url}}
function rvEnter(){
 const rt=data&&data.rt;
 if(rt&&rt.active){rvShow(rt.port,rt.host);return}
 $('rv-login').hidden=false;$('rv-main').hidden=true;
 if(!gwLoaded)loadGw().then(()=>{if(!$('rv-host').dataset.dirty)$('rv-host').value=$('rt-host').value});
}
$('rv-host').oninput=e=>{e.target.dataset.dirty=1};
$('rv-go').onclick=async()=>{
 const b=$('rv-go'),m=$('rv-msg');b.disabled=true;b.textContent='Подключаюсь…';m.hidden=true;
 try{const r=await post('/rt/open',{host:$('rv-host').value.trim(),user:$('rv-user').value,pass:$('rv-pass').value});
  if(!r.ok){m.hidden=false;m.className='rt-msg err';m.textContent=r.error||'Не удалось подключиться';return}
  $('rv-pass').value='';rvShow(r.port,r.host);poll()}
 finally{b.disabled=false;b.textContent='Войти в админку'}};
$('rv-pass').addEventListener('keydown',e=>{if(e.key==='Enter')$('rv-go').click()});
$('rv-home').onclick=()=>{const f=$('rv-frame');f.src=f.dataset.src};
$('rv-wifi').onclick=()=>toggleSettings(true);
$('rv-off').onclick=async()=>{await post('/rt/close');const f=$('rv-frame');f.removeAttribute('src');delete f.dataset.src;await poll();rvEnter()};
function toggleSettings(on){stp.hidden=on===undefined?!stp.hidden:!on;$('cog').classList.toggle('on',!stp.hidden);if(!stp.hidden&&!gwLoaded)loadGw()}
$('cog').onclick=()=>toggleSettings();$('st-x').onclick=()=>toggleSettings(false);
$('c-devs').onchange=e=>{cfg.devs=e.target.checked;saveCfg();if(data&&view==='g')build(data)};
$('c-notify').onchange=e=>post('/config',{notify:e.target.checked});

/* ── новые мини-инструменты ── */
$('sp-run').onclick=async()=>{const b=$('sp-run'),o=$('sp-out');b.disabled=true;b.textContent='Измеряю… (до 25 с)';o.hidden=false;o.innerHTML='<div class="dim" style="padding:6px">идёт тест…</div>';
 try{const r=await post('/speedtest',{});
  if(!r.ok)o.innerHTML='<div class="dim" style="padding:6px;color:var(--bad)">'+esc(r.error||'ошибка')+'</div>';
  else{o.innerHTML=`<div class="rate d"><span>↓ загрузка</span><b>${r.down.toFixed(1)} Мбит/с</b></div><div class="rate u"><span>↑ отдача</span><b>${r.up?r.up.toFixed(1)+' Мбит/с':'—'}</b></div><div class="rate"><span>задержка</span><b>${r.ping.toFixed(0)} мс</b></div>`;$('sp-note').hidden=false}
 }catch(e){o.innerHTML='<div class="dim" style="padding:6px">ошибка</div>'}
 b.disabled=false;b.textContent='Запустить тест'};
function subnet(v){
 const m=v.trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2})|\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))?$/);if(!m)return null;
 const o=[1,2,3,4].map(i=>+m[i]);if(o.some(x=>x>255))return null;
 let pre=m[5]!==undefined?+m[5]:24;
 if(m[6]){const mm=m[6].split('.').map(Number);const bits=mm.map(x=>x.toString(2).padStart(8,'0')).join('');if(!/^1*0*$/.test(bits)||mm.some(x=>x>255))return null;pre=bits.indexOf('0')<0?32:bits.indexOf('0')}
 if(pre>32)return null;
 const ip=((o[0]<<24)|(o[1]<<16)|(o[2]<<8)|o[3])>>>0,mask=pre?(0xFFFFFFFF<<(32-pre))>>>0:0,net=(ip&mask)>>>0,bc=(net|~mask)>>>0;
 const s=n=>[n>>>24,(n>>>16)&255,(n>>>8)&255,n&255].join('.');
 const hosts=pre>=31?(pre===32?1:2):Math.pow(2,32-pre)-2;
 return {net:s(net)+'/'+pre,mask:s(mask),wild:s((~mask)>>>0),bc:s(bc),first:pre>=31?s(net):s(net+1),last:pre>=31?s(bc):s(bc-1),hosts};
}
$('sn-in').oninput=()=>{const o=$('sn-out'),v=$('sn-in').value;if(!v.trim()){o.hidden=true;return}const r=subnet(v);o.hidden=false;o.className='tout'+(r?'':' err');
 o.textContent=r?`сеть:        ${r.net}\nмаска:       ${r.mask}\nобратная:    ${r.wild}\nbroadcast:   ${r.bc}\nхосты:       ${r.first} — ${r.last}\nвсего хостов: ${r.hosts.toLocaleString('ru')}`:'Формат: 192.168.1.0/24 или 10.0.0.0 255.255.0.0'};
function genPw(){const n=Math.max(8,Math.min(63,+$('pw-len').value||16)),cs='abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789',a=new Uint32Array(n);crypto.getRandomValues(a);
 const lim=Math.floor(4294967296/cs.length)*cs.length;let out='';for(let i=0;i<n;i++){let v=a[i];while(v>=lim){const t=new Uint32Array(1);crypto.getRandomValues(t);v=t[0]}out+=cs[v%cs.length]}return out}
$('pw-gen').onclick=()=>{$('pw-out').value=genPw()};
$('pw-copy').onclick=async()=>{const v=$('pw-out').value;if(!v)return;try{await navigator.clipboard.writeText(v);$('pw-copy').textContent='Скопировано ✓'}catch(e){$('pw-out').select();$('pw-copy').textContent='Выделено — Ctrl+C'}setTimeout(()=>$('pw-copy').textContent='Копировать',1800)};
$('pw-set').onclick=()=>{const v=$('pw-out').value||($('pw-out').value=genPw());$('rt-psk').value=v;toggleSettings(true);$('rt-psk').focus()};
/* доверенные процессы */
const trusted=()=>(data&&data.rules&&data.rules.trusted)||[];
function trustUI(){const el=$('c-trust'),t=trusted(),h=t.length?t.map(x=>`<span class="pill" data-untrust="${esc(x)}" style="cursor:pointer" title="Убрать">${esc(x)} ✕</span>`).join(''):'<span class="dim" style="font-size:12px">никого — отметьте процесс в его карточке</span>';if(el._h!==h){el._h=h;el.innerHTML=h}}
$('c-trust').onclick=async e=>{const b=e.target.closest('[data-untrust]');if(!b)return;await post('/config',{trust_del:b.dataset.untrust});await poll()};
$('pane-node').addEventListener('click',async e=>{const b=e.target.closest('[data-trust]');if(!b)return;e.stopPropagation();const n=b.dataset.trust;await post('/config',trusted().includes(n)?{trust_del:n}:{trust_add:n});await poll();details()},true);
/* акцент */
(function(){const cols=['#a78bfa','#3ee0cb','#f5b94a','#ff6b81','#5b9dff'],box=$('c-acc');
 const apply=c=>{document.documentElement.style.setProperty('--acc',c);COL.proc=c;try{localStorage.setItem('ng-acc',c)}catch(e){}box.querySelectorAll('i').forEach(i=>i.style.outline=i.dataset.c===c?'2px solid #fff':'none');refresh()};
 box.innerHTML=cols.map(c=>`<i data-c="${c}" style="width:18px;height:18px;border-radius:50%;background:${c};cursor:pointer;outline-offset:2px"></i>`).join('');
 box.onclick=e=>{const i=e.target.closest('[data-c]');if(i)apply(i.dataset.c)};
 let sv=null;try{sv=localStorage.getItem('ng-acc')}catch(e){}if(sv&&cols.includes(sv))setTimeout(()=>apply(sv),0);else box.querySelector('i').style.outline='2px solid #fff'})();
$('c-rate').onchange=e=>post('/config',{rate_mb:+e.target.value||0});$('c-outage').onchange=e=>post('/config',{outage:e.target.checked});
function setFocus(on){const app=$('app'),v=on===undefined?!app.classList.contains('focus'):on;if(v===app.classList.contains('focus'))return;app.classList.toggle('focus',v);
 $('c-focus').textContent=v?'Выключить':'Включить';if(view==='g')setTimeout(()=>fit(),350)}
$('c-focus').onclick=()=>{toggleSettings(false);setFocus(true)};
const exp=w=>()=>{location.href='/export?fmt=csv&what='+w};
$('ex-conns').onclick=exp('conns');$('ex-dev').onclick=exp('devices');$('ex-log').onclick=exp('log');
$('st-help').onclick=()=>{toggleSettings(false);$('help').hidden=false};
syncCfg();
window.__ng={setView,select,setTab,fit,setMode,toggleSettings,setFocus,toolFor};
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
    ap.add_argument("--rt-port", type=int, default=0, help="порт встроенной админки роутера (по умолчанию --port + 1)")
    a = ap.parse_args()
    ARGS.port, ARGS.demo, ARGS.rt_port = a.port, a.demo, a.rt_port
    ARGS.geo = a.geo or a.demo or os.path.exists(GEO_FLAG)
    if a.install_agent:
        install_agent()
        sys.exit()
    if a.demo:
        threading.Thread(target=demo_loop, daemon=True).start()
    else:
        threading.Thread(target=loop, daemon=True).start()
        threading.Thread(target=geo_loop, daemon=True).start()
        threading.Thread(target=ping_loop, daemon=True).start()
        threading.Thread(target=lan_loop, daemon=True).start()
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
