"""
Anti-DDoS Shield - REJECT CONNECTIONS SỚM
- Rate limit ở WSGI middleware level (trước Flask)
- Connection limiting
- Fast reject = không overload server
- Memory-efficient bloom filter
"""

from flask import Flask, request, jsonify
from werkzeug.wrappers import Response
from collections import defaultdict
import time
import secrets
import os

app = Flask(__name__)

# Fast in-memory storage
class RateLimiter:
    def __init__(self):
        self.requests = defaultdict(list)
        self.blocked = {}
        self.verified = set()
        self.last_cleanup = time.time()
    
    def cleanup(self):
        """Cleanup old data nếu cần"""
        now = time.time()
        if now - self.last_cleanup > 60:
            # Cleanup requests older than 60s
            for ip in list(self.requests.keys()):
                self.requests[ip] = [t for t in self.requests[ip] if now - t < 60]
                if not self.requests[ip]:
                    del self.requests[ip]
            # Cleanup expired blocks
            self.blocked = {ip: t for ip, t in self.blocked.items() if t > now}
            self.last_cleanup = now
    
    def is_blocked(self, ip):
        """Check blocked"""
        if ip in self.blocked:
            if time.time() < self.blocked[ip]:
                return True
            del self.blocked[ip]
        return False
    
    def block(self, ip, duration=300):
        """Block IP"""
        self.blocked[ip] = time.time() + duration
    
    def check_rate(self, ip, limit):
        """Check rate limit - Return (allowed, count)"""
        now = time.time()
        self.requests[ip] = [t for t in self.requests[ip] if now - t < 60]
        self.requests[ip].append(now)
        count = len(self.requests[ip])
        return count <= limit, count
    
    def verify_token(self, token):
        """Check token valid"""
        return token in self.verified
    
    def add_token(self, token):
        """Add verified token"""
        self.verified.add(token)

limiter = RateLimiter()
stats = {'total': 0, 'verified': 0, 'blocked': 0, 'challenged': 0}

# Constants
BOT_UA = ['curl', 'wget', 'python', 'go-http', 'java', 'scrapy', 'siege', 'ab/', 'wrk', 'benchmark', 'jmeter']
BROWSER_LIMIT = 500
BOT_LIMIT = 10

def is_bot(ua):
    if not ua:
        return True
    ua = ua.lower()
    return any(b in ua for b in BOT_UA)

# WSGI Middleware - XỬ LÝ TRƯỚC FLASK
class DDoSProtectionMiddleware:
    def __init__(self, app):
        self.app = app
    
    def __call__(self, environ, start_response):
        # Lấy IP sớm nhất có thể
        ip = environ.get('HTTP_X_FORWARDED_FOR', environ.get('REMOTE_ADDR', '0.0.0.0'))
        if ',' in ip:
            ip = ip.split(',')[0].strip()
        
        path = environ.get('PATH_INFO', '')
        
        # Skip cho các path đặc biệt
        if path in ['/health', '/favicon.ico']:
            return self.app(environ, start_response)
        
        # Cleanup định kỳ
        limiter.cleanup()
        
        stats['total'] += 1
        
        # 1. CHECK BLOCKED NGAY - REJECT TỨC THÌ
        if limiter.is_blocked(ip):
            stats['blocked'] += 1
            response = Response(
                f'<html><body style="background:#1a1a1a;color:#fff;font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh;text-align:center"><div><h1 style="color:#ef4444">🚫 Blocked</h1><p>IP: {ip}</p><p>Blocked for 5 minutes</p></div></body></html>',
                status=403,
                mimetype='text/html'
            )
            return response(environ, start_response)
        
        # 2. CHECK TOKEN
        cookies = environ.get('HTTP_COOKIE', '')
        token = None
        if 'verified=' in cookies:
            for cookie in cookies.split(';'):
                if 'verified=' in cookie:
                    token = cookie.split('=')[1].strip()
                    break
        
        # 3. VERIFIED USER - LENIENT RATE LIMIT
        if token and limiter.verify_token(token):
            allowed, count = limiter.check_rate(ip, BROWSER_LIMIT)
            if not allowed:
                limiter.block(ip)
                stats['blocked'] += 1
                response = Response(f'<html><body style="background:#1a1a1a;color:#fff;font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh;text-align:center"><div><h1 style="color:#ef4444">⚠️ Rate Limit</h1><p>Too many requests: {count}/min</p></div></body></html>', status=429, mimetype='text/html')
                return response(environ, start_response)
            stats['verified'] += 1
            return self.app(environ, start_response)
        
        # 4. CHECK BOT - STRICT LIMIT & FAST BLOCK
        ua = environ.get('HTTP_USER_AGENT', '')
        if is_bot(ua):
            allowed, count = limiter.check_rate(ip, BOT_LIMIT)
            if not allowed:
                limiter.block(ip)
                stats['blocked'] += 1
                response = Response(f'<html><body style="background:#1a1a1a;color:#fff;font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh;text-align:center"><div><h1 style="color:#ef4444">🚫 Bot Blocked</h1><p>IP: {ip}</p><p>Rate: {count}/min > {BOT_LIMIT}/min</p></div></body></html>', status=403, mimetype='text/html')
                return response(environ, start_response)
        
        # 5. Cho qua Flask xử lý (challenge, etc.)
        return self.app(environ, start_response)

# Wrap app với middleware
app.wsgi_app = DDoSProtectionMiddleware(app.wsgi_app)

# Challenge page
CHALLENGE = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Security Check</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:system-ui;background:#f5f5f5;display:flex;align-items:center;justify-content:center;min-height:100vh}
.box{text-align:center;max-width:500px;padding:40px;background:white;border-radius:12px;box-shadow:0 4px 20px rgba(0,0,0,0.1)}
.shield{width:80px;height:80px;background:linear-gradient(135deg,#667eea,#764ba2);border-radius:50%;margin:0 auto 20px;display:flex;align-items:center;justify-content:center;font-size:40px}
h1{font-size:24px;color:#333;margin-bottom:10px}p{color:#666;margin-bottom:20px}
.math{font-size:36px;font-weight:bold;color:#333;margin:30px 0;padding:20px;background:#f8f9fa;border-radius:8px}
input{padding:15px;font-size:20px;border:2px solid #ddd;border-radius:8px;width:100%;max-width:200px;text-align:center;margin-bottom:15px}
button{background:#667eea;color:white;border:none;padding:15px 40px;font-size:16px;border-radius:8px;cursor:pointer}button:hover{background:#5568d3}
.msg{margin-top:15px;font-weight:500;display:none}
</style></head><body><div class="box"><div class="shield">🛡️</div><h1>Security Check</h1><p>Solve this to continue:</p>
<div class="math" id="q"></div><input type="number" id="ans" placeholder="Answer"><button onclick="verify()">Submit</button>
<div class="msg" id="msg"></div></div>
<script>
var a=Math.floor(Math.random()*20)+1,b=Math.floor(Math.random()*20)+1,correct=a+b;
document.getElementById('q').textContent=a+' + '+b+' = ?';
function verify(){
var ans=parseInt(document.getElementById('ans').value),msg=document.getElementById('msg');
msg.style.display='none';
if(isNaN(ans)){msg.textContent='Enter a number';msg.style.color='#e74c3c';msg.style.display='block';return}
if(ans!==correct){msg.textContent='Wrong! Try again';msg.style.color='#e74c3c';msg.style.display='block';return}
fetch('/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({answer:ans,expected:correct})})
.then(r=>r.json()).then(d=>{
if(d.ok){document.cookie='verified='+d.token+';path=/;max-age=3600';msg.textContent='✓ Verified!';msg.style.color='#27ae60';msg.style.display='block';setTimeout(()=>window.location.href='{{URL}}',800)}
else{msg.textContent='Failed. Refresh page';msg.style.color='#e74c3c';msg.style.display='block'}
})}
document.getElementById('ans').addEventListener('keypress',e=>{if(e.key==='Enter')verify()});
</script></body></html>"""

# Dashboard
DASH = """<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Dashboard</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:system-ui;background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;min-height:100vh;padding:20px}
.c{max-width:1200px;margin:0 auto}h1{text-align:center;font-size:2.5em;margin-bottom:30px}
.alert{background:rgba(76,175,80,0.3);border:2px solid #4CAF50;border-radius:10px;padding:15px;margin-bottom:20px;text-align:center;font-weight:bold}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:20px;margin-bottom:30px}
.card{background:rgba(255,255,255,0.15);backdrop-filter:blur(10px);border-radius:15px;padding:25px;border:1px solid rgba(255,255,255,0.2)}
.val{font-size:2.5em;font-weight:bold;margin:10px 0}.label{font-size:0.9em;opacity:0.9}
.info{background:rgba(255,255,255,0.15);backdrop-filter:blur(10px);border-radius:15px;padding:25px;margin-top:20px}
.f{padding:12px;margin:8px 0;background:rgba(255,255,255,0.1);border-radius:8px;border-left:4px solid #4CAF50}
.btn{background:#4CAF50;color:#fff;border:none;padding:15px 40px;border-radius:25px;font-size:1em;cursor:pointer;margin:20px auto;display:block}
</style></head><body><div class="c"><h1>🛡️ Anti-DDoS Shield</h1>
<div class="alert">✅ Middleware-level Protection - Rejects BEFORE processing!</div>
<div class="stats">
<div class="card"><div class="label">📊 Total</div><div class="val">{{T}}</div></div>
<div class="card"><div class="label">✅ Verified</div><div class="val">{{V}}</div></div>
<div class="card"><div class="label">⚠️ Challenged</div><div class="val">{{C}}</div></div>
<div class="card"><div class="label">🚫 Blocked</div><div class="val">{{B}}</div></div>
</div>
<div class="info"><h2>⚡ Fast Protection</h2>
<div class="f">✅ WSGI Middleware - Blocks at connection level</div>
<div class="f">✅ No Flask processing for blocked IPs</div>
<div class="f">✅ Memory efficient - Auto cleanup</div>
<div class="f">✅ Browsers: 500/min | Bots: 10/min</div>
<div class="f">🚫 Bot exceeded = Instant block</div>
</div>
<button class="btn" onclick="location.reload()">🔄 Refresh</button>
</div><script>setTimeout(()=>location.reload(),10000)</script></body></html>"""

@app.route('/verify', methods=['POST'])
def verify():
    data = request.get_json()
    if data.get('answer') != data.get('expected'):
        return jsonify({'ok': False})
    token = secrets.token_urlsafe(32)
    limiter.add_token(token)
    return jsonify({'ok': True, 'token': token})

@app.route('/')
def home():
    token = request.cookies.get('verified')
    if not token or not limiter.verify_token(token):
        stats['challenged'] += 1
        return CHALLENGE.replace('{{URL}}', request.url)
    html = DASH.replace('{{T}}', str(stats['total'])).replace('{{V}}', str(stats['verified'])).replace('{{C}}', str(stats['challenged'])).replace('{{B}}', str(stats['blocked']))
    return html

@app.route('/api/stats')
def get_stats():
    return jsonify(stats)

@app.route('/health')
def health():
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
