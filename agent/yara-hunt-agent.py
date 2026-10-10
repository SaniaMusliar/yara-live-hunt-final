#!/usr/bin/env python3
"""YARA Live Hunt agent (MIT). A local, lab-only bridge between your terminal and the web UI.
Binds 127.0.0.1 only. Every request needs the session token AND the allowed Origin.
Reads ~/yara-lab; runs one fixed command (yara -r -s -m rules/rules.yar fileserver). Stdlib only."""
import argparse, getpass, hashlib, hmac, http.server, json, os, platform, re, shutil, socket, subprocess, threading, time
ap = argparse.ArgumentParser()
ap.add_argument('--token', required=True); ap.add_argument('--origin', required=True)
ap.add_argument('--port', type=int, default=8765); ap.add_argument('--lab', default='~/yara-lab')
A = ap.parse_args(); LAB = os.path.expanduser(A.lab); FS = LAB + '/fileserver'
EV, N, VER, FILES, SCAN, SID = [], [0], [0], {}, [None], [0]

def push(k, **d):
    N[0] += 1; EV.append({'n': N[0], 't': time.time(), 'k': k, **d}); del EV[:-300]

def snap():
    o = {}
    for d, _, fs in os.walk(FS):
        for f in fs:
            p = os.path.join(d, f)
            try:
                if os.path.islink(p): continue   # never follow symlinks out of the lab
                o[os.path.relpath(p, FS)] = os.stat(p).st_size
            except OSError: pass
    return o

def rd(n):
    try: return open(os.path.join(LAB, n), errors='replace').read().split('\n')
    except OSError: return []

def meta(k, s):
    x = re.search(k + '="([^"]*)"', s); return x.group(1) if x else ''

def scan():
    t = time.time(); SID[0] += 1
    try: r = subprocess.run(['yara', '-r', '-s', '-m', 'rules/rules.yar', 'fileserver'], cwd=LAB, capture_output=True, text=True, timeout=60)
    except FileNotFoundError: SCAN[0] = {'id': SID[0], 'err': 'yara is not installed (sudo apt install yara -y)', 'matches': []}; return
    ms, cur = [], None
    for l in r.stdout.splitlines():
        s = re.match(r'^0x([0-9a-fA-F]+):(\$\w+): (.*)$', l); h = re.match(r'^(\S+) \[(.*)\] (.+)$', l)
        if s and cur: cur['strings'].append({'off': s.group(1), 'id': s.group(2), 'text': s.group(3)})
        elif h:
            cur = {'rule': h.group(1), 'severity': meta('severity', h.group(2)), 'stage': meta('stage', h.group(2)),
                   'path': h.group(3)[len('fileserver/'):], 'strings': []}; ms.append(cur)
    SCAN[0] = {'id': SID[0], 'matches': ms, 'n': len(FILES), 'secs': round(time.time() - t, 3)}
    push('scan', hits=len({m['path'] for m in ms}), n=len(FILES))

def watch():
    off, stg = 0, set()
    while True:
        now = snap()
        if now != FILES:
            add = [p for p in now if p not in FILES]; dele = [p for p in FILES if p not in now]
            mod = [p for p in now if p in FILES and FILES[p] != now[p]]
            for kind, lst in (('add', add), ('del', dele), ('mod', mod)):
                if len(lst) > 6: push(kind + 'n', n=len(lst))
                else:
                    for p in lst: push(kind, p=p)
            if len(dele) >= 50: SCAN[0] = None; stg.clear()
            FILES.clear(); FILES.update(now); VER[0] += 1
        f = [l for l in rd('.feed.log') if '\t' in l]
        if len(f) < off: off = 0
        for l in f[off:]:
            c = l.split('\t', 1)[1]; push('cmd', c=c)
            if re.search(r'\byara\b', c) and 'rules' in c and '--version' not in c: scan()
        off = len(f)
        for x in rd('.events.log'):
            if x.strip().isdigit() and int(x) not in stg: stg.add(int(x)); push('stage', s=int(x))
        time.sleep(0.4)

HC = [None, None]
def hashhits():
    try: key = (os.stat(LAB + '/known_bad_hashes.txt').st_mtime, VER[0])
    except OSError: return None
    if HC[0] == key: return HC[1]
    try: bad = {x.strip() for x in open(LAB + '/known_bad_hashes.txt') if x.strip()}
    except OSError: return None
    hit = None
    if bad:
        hit = []
        for p, size in FILES.items():
            if size > 5_000_000: continue     # lab files are tiny; skip anything large
            try:
                if hashlib.sha256(open(os.path.join(FS, p), 'rb').read()).hexdigest() in bad: hit.append(p)
            except OSError: pass
    HC[0], HC[1] = key, hit
    return hit

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def allowed(self):
        host = (self.headers.get('Host') or '').rsplit(':', 1)[0]
        return host in ('127.0.0.1', 'localhost') and self.headers.get('Origin') == A.origin
    def reply(self, code, obj=None):
        self.send_response(code)
        for k, v in (('Access-Control-Allow-Origin', A.origin), ('Vary', 'Origin'), ('Access-Control-Allow-Headers', 'X-YH-Token'),
                     ('Access-Control-Allow-Methods', 'GET,POST'), ('Access-Control-Allow-Private-Network', 'true'), ('Cache-Control', 'no-store')):
            self.send_header(k, v)
        b = json.dumps(obj).encode() if obj is not None else b''
        if obj is not None: self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(b))); self.end_headers(); self.wfile.write(b)
    def auth(self):
        if not self.allowed(): self.reply(403, {'err': 'origin'}); return False
        if not hmac.compare_digest(self.headers.get('X-YH-Token', ''), A.token): self.reply(401, {'err': 'token'}); return False
        return True
    def do_OPTIONS(self): self.reply(204 if self.allowed() else 403)
    def do_GET(self):
        if not self.auth(): return
        q = dict(re.findall(r'(\w+)=(-?\d+)', self.path)); since, ver = int(q.get('since', 0)), int(q.get('ver', -1))
        o = {'ok': 1, 'ver': VER[0], 'host': socket.gethostname(), 'user': getpass.getuser(), 'os': platform.platform(terse=True),
             'lab': A.lab, 'yara': bool(shutil.which('yara')),
             'ev': [x for x in EV if x['n'] > since], 'scan': SCAN[0], 'hash': hashhits(),
             'stages': sorted(x['s'] for x in EV if x['k'] == 'stage')}
        if ver != VER[0]: o['files'] = sorted(FILES.items())
        self.reply(200, o)
    def do_POST(self):
        if not self.auth(): return
        if self.path == '/scan': scan(); self.reply(200, {'ok': 1})
        elif self.path == '/stop': self.reply(200, {'ok': 1}); threading.Thread(target=self.server.shutdown, daemon=True).start()
        else: self.reply(404, {})

if __name__ == '__main__':
    threading.Thread(target=watch, daemon=True).start()
    print(f'YARA Live Hunt agent on 127.0.0.1:{A.port} for {A.origin}')
    http.server.ThreadingHTTPServer(('127.0.0.1', A.port), H).serve_forever()
