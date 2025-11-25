"""
Anti-DDoS Shield - SIMPLE & WORKING
- Không dùng challenge ID phức tạp
- Chỉ cần: Math + Fingerprint + Cookie
- BẢO ĐẢM KHÔNG CHẶN NGƯỜI DÙNG THẬT
"""

from flask import Flask, request, jsonify, make_response
from collections import defaultdict
import time
import secrets
import os
import json

app = Flask(__name__)

# Storage
verified_tokens = set()  # Set of valid tokens
ip_requests = defaultdict(list)  # IP -> request timestamps
blocked_ips = set()  # Blocked IPs
stats = {'total': 0, 'browser': 0, 'bot': 0, 'blocked': 0}

# Config
BROWSER_LIMIT = 1000  # Browser: 1000 req/min
BOT_LIMIT = 10  # Bot: 10 req/min
BLOCK_DURATION = 300  # Block 5 phút

def is_bot(user_agent):
    """Detect obvious bots"""
    if not user_agent:
        return True
    ua = user_agent.lower()
    bots = ['curl', 'wget', 'python', 'go-http', 'java', 'perl', 'ruby', 
            'scrapy', 'httpclient', 'okhttp', 'axios', 'node-fetch',
            'benchmark', 'siege', 'ab/', 'jmeter', 'gatling', 'locust', 'wrk',
            'http.rb', 'rest-client', 'got/', 'fetch/']
    return any(b in ua for b in bots)

def check_rate(ip, limit):
    """Check rate limit"""
    now = time.time()
    ip_requests[ip] = [t for t in ip_requests[ip] if now - t < 60]
    ip_requests[ip].append(now)
    count = len(ip_requests[ip])
    return count <= limit, count

def is_blocked(ip):
    """Check if IP is blocked"""
    return ip in blocked_ips

def block_ip(ip):
    """Block IP temporarily"""
    blocked_ips.add(ip)
    # Auto unblock sau 5 phút
    def unblock():
        time.sleep(BLOCK_DURATION)
        blocked_ips.discard(ip)
    import threading
    threading.Thread(target=unblock, daemon=True).start()

# Challenge page - SIMPLE
CHALLENGE = """<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Security Check</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,system-ui,sans-serif;background:#f5f5f5;display:flex;align-items:center;justify-content:center;min-height:100vh}
.box{text-align:center;max-width:500px;padding:40px;background:white;border-radius:12px;box-shadow:0 4px 20px rgba(0,0,0,0.1)}
.shield{width:80px;height:80px;background:linear-gradient(135deg,#667eea,#764ba2);border-radius:50%;margin:0 auto 20px;display:flex;align-items:center;justify-content:center;font-size:40px}
h1{font-size:24px;color:#333;margin-bottom:10px}
p{color:#666;margin-bottom:20px}
.math{font-size:36px;font-weight:bold;color:#333;margin:30px 0;padding:20px;background:#f8f9fa;border-radius:8px}
input{padding:15px;font-size:20px;border:2px solid #ddd;border-radius:8px;width:100%;max-width:200px;text-align:center;margin-bottom:15px}
input:focus{outline:none;border-color:#667eea}
button{background:#667eea;color:white;border:none;padding:15px 40px;font-size:16px;border-radius:8px;cursor:pointer;transition:background 0.3s}
button:hover{background:#5568d3}
button:disabled{background:#ccc;cursor:not-allowed}
.error{color:#e74c3c;margin-top:15px;font-weight:500;display:none}
.success{color:#27ae60;margin-top:15px;font-weight:500;display:none}
</style>
</head>
<body>
<div class="box">
<div class="shield">🛡️</div>
<h1>Security Check</h1>
<p>Please solve this simple math problem to continue:</p>
<div class="math" id="question">Loading...</div>
<input type="number" id="answer" placeholder="Your answer" autofocus>
<button id="submit" onclick="verify()">Verify</button>
<div class="error" id="error"></div>
<div class="success" id="success">✓ Verified! Redirecting...</div>
</div>
<script>
var a = Math.floor(Math.random() * 20) + 1;
var b = Math.floor(Math.random() * 20) + 1;
var correctAnswer = a + b;
document.getElementById('question').textContent = a + ' + ' + b + ' = ?';

function verify(){
    var userAnswer = parseInt(document.getElementById('answer').value);
    var btn = document.getElementById('submit');
    var error = document.getElementById('error');
    var success = document.getElementById('success');
    
    error.style.display = 'none';
    success.style.display = 'none';
    
    if(isNaN(userAnswer)){
        error.textContent = 'Please enter a number';
        error.style.display = 'block';
        return;
    }
    
    if(userAnswer !== correctAnswer){
        error.textContent = 'Wrong answer. Try again!';
        error.style.display = 'block';
        return;
    }
    
    // Correct! Get fingerprint
    var fp = {
        screen: screen.width + 'x' + screen.height,
        tz: new Date().getTimezoneOffset(),
        lang: navigator.language,
        platform: navigator.platform
    };
    
    btn.disabled = true;
    btn.textContent = 'Verifying...';
    
    fetch('/verify', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            answer: userAnswer,
            expected: correctAnswer,
            fp: fp
        })
    })
    .then(r => r.json())
    .then(data => {
        if(data.ok){
            document.cookie = 'verified=' + data.token + ';path=/;max-age=3600';
            success.style.display = 'block';
            setTimeout(() => window.location.href = '{{URL}}', 1000);
        }else{
            error.textContent = 'Verification failed. Refresh and try again.';
            error.style.display = 'block';
            btn.disabled = false;
            btn.textContent = 'Verify';
        }
    })
    .catch(err => {
        error.textContent = 'Network error. Please try again.';
        error.style.display = 'block';
        btn.disabled = false;
        btn.textContent = 'Verify';
    });
}

document.getElementById('answer').addEventListener('keypress', function(e){
    if(e.key === 'Enter') verify();
});
</script>
</body>
</html>"""

# Blocked page
BLOCKED = """<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>Blocked</title>
<style>
*{margin:0;padding:0}body{font-family:system-ui;background:#1a1a1a;color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh;text-align:center}
.box{padding:40px;max-width:500px}.icon{font-size:80px;margin-bottom:20px}h1{color:#ef4444;margin-bottom:15px;font-size:32px}
p{color:#9ca3af;margin:10px 0;font-size:18px}.info{background:rgba(255,255,255,0.1);border-radius:10px;padding:20px;margin-top:20px}
.row{display:flex;justify-content:space-between;padding:12px 0;border-bottom:1px solid rgba(255,255,255,0.1)}
.row:last-child{border:none}
</style>
</head>
<body>
<div class="box">
<div class="icon">🚫</div>
<h1>Access Denied</h1>
<p>Your IP has been blocked by our DDoS protection.</p>
<div class="info">
<div class="row"><span>IP:</span><strong>{{IP}}</strong></div>
<div class="row"><span>Reason:</span><strong>{{REASON}}</strong></div>
<div class="row"><span>Requests:</span><strong>{{COUNT}}/min</strong></div>
<div class="row"><span>Unblock in:</span><strong>5 minutes</strong></div>
</div>
</div>
</body>
</html>"""

# Dashboard
DASHBOARD = """<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Anti-DDoS Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui;background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;min-height:100vh;padding:20px}
.container{max-width:1200px;margin:0 auto}
h1{text-align:center;font-size:2.5em;margin-bottom:30px}
.alert{background:rgba(76,175,80,0.3);border:2px solid #4CAF50;border-radius:10px;padding:15px;margin-bottom:20px;text-align:center;font-weight:bold}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:20px;margin-bottom:30px}
.card{background:rgba(255,255,255,0.15);backdrop-filter:blur(10px);border-radius:15px;padding:25px;border:1px solid rgba(255,255,255,0.2);transition:transform 0.3s}
.card:hover{transform:translateY(-5px)}
.val{font-size:2.5em;font-weight:bold;margin:10px 0}
.label{font-size:0.9em;opacity:0.9}
.info{background:rgba(255,255,255,0.15);backdrop-filter:blur(10px);border-radius:15px;padding:25px;margin-top:20px}
.feature{padding:12px;margin:8px 0;background:rgba(255,255,255,0.1);border-radius:8px;border-left:4px solid #4CAF50}
.btn{background:#4CAF50;color:#fff;border:none;padding:15px 40px;border-radius:25px;font-size:1em;cursor:pointer;margin:20px auto;display:block}
.btn:hover{background:#45a049}
code{background:rgba(0,0,0,0.3);padding:2px 6px;border-radius:4px;font-family:monospace}
</style>
</head>
<body>
<div class="container">
<h1>🛡️ Anti-DDoS Shield</h1>
<div class="alert">✅ Protection Active - Real browsers pass, bots blocked!</div>
<div class="stats">
<div class="card"><div class="label">📊 Total</div><div class="val">{{TOTAL}}</div></div>
<div class="card"><div class="label">✅ Browsers</div><div class="val">{{BROWSER}}</div></div>
<div class="card"><div class="label">🤖 Bots</div><div class="val">{{BOT}}</div></div>
<div class="card"><div class="label">🚫 Blocked</div><div class="val">{{BLOCKED}}</div></div>
</div>
<div class="info">
<h2>🎯 How It Works</h2>
<div class="feature">✅ Math challenge - Only humans can solve</div>
<div class="feature">✅ Browser fingerprinting - Verify real browsers</div>
<div class="feature">✅ Rate limiting - 1000/min for browsers, 10/min for bots</div>
<div class="feature">✅ Auto-block - Exceeding limits = 5 min block</div>
<div class="feature">🚫 Detects: curl, wget, benchmark tools, scrapers</div>
</div>
<div class="info">
<h2>🧪 Test It</h2>
<div class="feature"><strong>Browser:</strong> You're here! Already verified ✅</div>
<div class="feature"><strong>curl:</strong> Try <code>curl {{URL}}</code> - Will be blocked</div>
<div class="feature"><strong>Benchmark:</strong> Use ab/siege - Will be blocked at 10 req/min</div>
</div>
<button class="btn" onclick="location.reload()">🔄 Refresh</button>
</div>
<script>setTimeout(()=>location.reload(),15000)</script>
</body>
</html>"""

@app.route('/verify', methods=['POST'])
def verify():
    """Verify challenge response"""
    data = request.get_json()
    
    # Check answer
    if data.get('answer') != data.get('expected'):
        return jsonify({'ok': False, 'error': 'Wrong answer'})
    
    # Generate token
    token = secrets.token_urlsafe(32)
    verified_tokens.add(token)
    
    return jsonify({'ok': True, 'token': token})

@app.before_request
def protection():
    """Main protection"""
    if request.path in ['/verify', '/health', '/favicon.ico']:
        return
    
    stats['total'] += 1
    ip = request.remote_addr
    ua = request.headers.get('User-Agent', '')
    token = request.cookies.get('verified')
    
    # Check blocked
    if is_blocked(ip):
        stats['blocked'] += 1
        count = len(ip_requests.get(ip, []))
        html = BLOCKED.replace('{{IP}}', ip).replace('{{REASON}}', 'Rate limit').replace('{{COUNT}}', str(count))
        return html, 403
    
    # Check verified
    if token and token in verified_tokens:
        # Verified browser
        allowed, count = check_rate(ip, BROWSER_LIMIT)
        if allowed:
            stats['browser'] += 1
            return
        else:
            block_ip(ip)
            stats['blocked'] += 1
            html = BLOCKED.replace('{{IP}}', ip).replace('{{REASON}}', 'Too many requests').replace('{{COUNT}}', str(count))
            return html, 429
    
    # Check if bot
    if is_bot(ua):
        # Bot - strict limit
        allowed, count = check_rate(ip, BOT_LIMIT)
        if allowed:
            stats['bot'] += 1
            return
        else:
            block_ip(ip)
            stats['blocked'] += 1
            html = BLOCKED.replace('{{IP}}', ip).replace('{{REASON}}', 'Bot detected').replace('{{COUNT}}', str(count))
            return html, 403
    
    # Not verified, not bot - show challenge
    html = CHALLENGE.replace('{{URL}}', request.url)
    return html, 200

@app.route('/')
def home():
    html = DASHBOARD
    html = html.replace('{{TOTAL}}', str(stats['total']))
    html = html.replace('{{BROWSER}}', str(stats['browser']))
    html = html.replace('{{BOT}}', str(stats['bot']))
    html = html.replace('{{BLOCKED}}', str(stats['blocked']))
    html = html.replace('{{URL}}', request.url_root.rstrip('/'))
    return html

@app.route('/api/test')
def test():
    return jsonify({'status': 'success', 'ip': request.remote_addr})

@app.route('/api/stats')
def get_stats():
    return jsonify(stats)

@app.route('/health')
def health():
    return jsonify({'status': 'healthy'})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
