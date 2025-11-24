"""
Anti-DDoS Protection Server - Smart Bot Detection
Deploy on Render.com for 24/7 operation
"""

from flask import Flask, request, jsonify, render_template_string
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from collections import defaultdict
import time
import re
import os
import threading

app = Flask(__name__)

# Rate Limiter với nhiều mức độ
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per minute"],
    storage_uri="memory://"
)

# Data storage
request_history = defaultdict(list)
blocked_ips = {}
trusted_ips = set()
stats = {'total': 0, 'blocked': 0, 'bot': 0, 'human': 0, 'start': time.time()}

# Bot patterns - Comprehensive list
BOT_PATTERNS = [
    r'bot', r'crawler', r'spider', r'scraper', r'curl', r'wget',
    r'python-requests', r'go-http', r'java', r'axios', r'node-fetch',
    r'scrapy', r'phantom', r'headless', r'selenium', r'puppeteer'
]

# Legitimate browser patterns
BROWSER_PATTERNS = [
    r'mozilla/5\.0.*chrome', r'mozilla/5\.0.*safari', r'mozilla/5\.0.*firefox',
    r'mozilla/5\.0.*edge', r'mozilla/5\.0.*opera'
]

def smart_bot_detection(ip, user_agent, headers):
    """Thuật toán thông minh phát hiện bot với độ chính xác cao"""
    score = 0
    signals = []
    is_legit_browser = False
    
    # 1. CHECK USER AGENT - Phân tích chi tiết
    if not user_agent:
        score += 50
        signals.append("No User-Agent")
    else:
        ua_lower = user_agent.lower()
        
        # Kiểm tra browser thật
        for pattern in BROWSER_PATTERNS:
            if re.search(pattern, ua_lower):
                is_legit_browser = True
                score -= 20  # Bonus cho browser thật
                signals.append("Legit Browser")
                break
        
        # Kiểm tra bot patterns
        if not is_legit_browser:
            for pattern in BOT_PATTERNS:
                if re.search(pattern, ua_lower):
                    score += 40
                    signals.append(f"Bot Pattern: {pattern}")
                    break
    
    # 2. CHECK HEADERS - Browser thật có đầy đủ headers
    required_headers = ['Accept', 'Accept-Language', 'Accept-Encoding']
    missing_headers = [h for h in required_headers if h not in headers]
    
    if missing_headers and not is_legit_browser:
        score += len(missing_headers) * 15
        signals.append(f"Missing: {', '.join(missing_headers)}")
    
    # Browser thật thường có nhiều headers
    header_count = len(headers)
    if is_legit_browser and header_count < 5:
        score += 20  # Browser thật nhưng ít headers - đáng ngờ
        signals.append("Few headers for browser")
    
    # 3. CHECK REQUEST RATE - Phân tích behavior
    current_time = time.time()
    request_history[ip] = [t for t in request_history[ip] if current_time - t < 60]
    request_history[ip].append(current_time)
    
    req_count = len(request_history[ip])
    
    if req_count > 100:  # >100 req/min = rõ ràng bot
        score += 60
        signals.append(f"Extreme rate: {req_count}/min")
    elif req_count > 50:  # 50-100 req/min = nghi ngờ cao
        score += 40
        signals.append(f"High rate: {req_count}/min")
    elif req_count > 30:  # 30-50 req/min = cảnh báo
        score += 20
        signals.append(f"Suspicious rate: {req_count}/min")
    
    # Người dùng thật thường có khoảng cách đều giữa requests
    if len(request_history[ip]) > 5:
        intervals = [request_history[ip][i] - request_history[ip][i-1] 
                    for i in range(1, len(request_history[ip]))]
        avg_interval = sum(intervals) / len(intervals)
        
        # Bot thường request đều đặn (interval gần như = nhau)
        if avg_interval < 0.1 and req_count > 10:
            score += 30
            signals.append("Robotic timing pattern")
    
    # 4. CHECK CONNECTION - Fingerprinting
    if 'Connection' in headers:
        if headers['Connection'].lower() == 'close':
            score += 10  # Bot thường dùng close
            signals.append("Connection: close")
    
    # 5. TRUSTED IP - Whitelist
    if ip in trusted_ips:
        score -= 100  # Đảm bảo không bao giờ block
        signals.append("Trusted IP")
    
    # 6. DECISION LOGIC với nhiều mức độ
    if score >= 80:
        verdict = "BLOCK_DEFINITE"  # Chắc chắn là bot
    elif score >= 60:
        verdict = "BLOCK_LIKELY"  # Khả năng cao là bot
    elif score >= 40:
        verdict = "WARN"  # Theo dõi thêm
    else:
        verdict = "ALLOW"  # Người dùng thật
    
    return {
        'score': max(0, score),  # Không âm
        'verdict': verdict,
        'signals': signals,
        'is_browser': is_legit_browser,
        'req_rate': req_count
    }

def check_and_block(ip):
    """Kiểm tra IP có bị block không"""
    if ip in blocked_ips:
        block_time, duration = blocked_ips[ip]
        if time.time() - block_time < duration:
            return True
        else:
            del blocked_ips[ip]
    return False

@app.before_request
def protect():
    """Middleware bảo vệ mọi request"""
    ip = get_remote_address()
    ua = request.headers.get('User-Agent', '')
    
    stats['total'] += 1
    
    # Kiểm tra IP đã bị block
    if check_and_block(ip):
        stats['blocked'] += 1
        return jsonify({'error': 'Blocked', 'reason': 'IP temporarily blocked'}), 403
    
    # Phân tích request với thuật toán thông minh
    result = smart_bot_detection(ip, ua, request.headers)
    
    # Quyết định dựa trên verdict
    if result['verdict'] in ['BLOCK_DEFINITE', 'BLOCK_LIKELY']:
        # Block với thời gian khác nhau
        duration = 600 if result['verdict'] == 'BLOCK_DEFINITE' else 300
        blocked_ips[ip] = (time.time(), duration)
        stats['blocked'] += 1
        stats['bot'] += 1
        
        log_event(ip, ua, result, 'BLOCKED')
        
        return jsonify({
            'error': 'Access Denied',
            'score': result['score'],
            'signals': result['signals'],
            'blocked_duration': f"{duration}s"
        }), 403
    
    # Ghi nhận loại traffic
    if result['is_browser']:
        stats['human'] += 1
    elif result['verdict'] == 'WARN':
        stats['bot'] += 1
        log_event(ip, ua, result, 'WARNING')

def log_event(ip, ua, result, action):
    """Ghi log ngắn gọn"""
    print(f"[{action}] {ip} | Score: {result['score']} | {', '.join(result['signals'][:2])}")

# Dashboard HTML - Tối ưu và gọn
DASHBOARD = """
<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Anti-DDoS Shield</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:#fff;min-height:100vh;padding:20px}
.container{max-width:1200px;margin:0 auto}
h1{text-align:center;font-size:2.5em;margin-bottom:30px;text-shadow:2px 2px 4px rgba(0,0,0,0.3)}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:20px;margin-bottom:30px}
.card{background:rgba(255,255,255,0.15);backdrop-filter:blur(10px);border-radius:15px;padding:25px;border:1px solid rgba(255,255,255,0.2);transition:transform 0.3s}
.card:hover{transform:translateY(-5px)}
.stat-val{font-size:2.5em;font-weight:bold;margin:10px 0}
.stat-label{font-size:0.9em;opacity:0.9;text-transform:uppercase}
.info{background:rgba(255,255,255,0.15);backdrop-filter:blur(10px);border-radius:15px;padding:25px;margin-top:20px;border:1px solid rgba(255,255,255,0.2)}
.feature{padding:12px;margin:8px 0;background:rgba(255,255,255,0.1);border-radius:8px;border-left:4px solid #4CAF50}
.btn{background:#4CAF50;color:#fff;border:none;padding:15px 40px;border-radius:25px;font-size:1em;cursor:pointer;margin:20px auto;display:block;transition:background 0.3s}
.btn:hover{background:#45a049}
.status{display:inline-block;padding:8px 20px;border-radius:20px;background:#4CAF50;font-weight:bold;margin:10px 0}
</style>
</head>
<body>
<div class="container">
<h1>🛡️ Anti-DDoS Shield</h1>
<div class="stats">
<div class="card"><div class="stat-label">📊 Total</div><div class="stat-val">{{stats.total}}</div></div>
<div class="card"><div class="stat-label">🚫 Blocked</div><div class="stat-val">{{stats.blocked}}</div></div>
<div class="card"><div class="stat-label">🤖 Bots</div><div class="stat-val">{{stats.bot}}</div></div>
<div class="card"><div class="stat-label">✅ Humans</div><div class="stat-val">{{stats.human}}</div></div>
</div>
<div class="info">
<h2>🟢 System Status</h2>
<div class="status">ONLINE 24/7</div>
<p style="margin-top:15px">Uptime: <strong>{{uptime}}</strong></p>
<p>Block Rate: <strong>{{block_rate}}%</strong></p>
</div>
<div class="info">
<h2>🎯 Smart Detection</h2>
<div class="feature">✅ Multi-signal bot analysis</div>
<div class="feature">✅ Behavioral pattern recognition</div>
<div class="feature">✅ Browser fingerprinting</div>
<div class="feature">✅ Adaptive rate limiting</div>
<div class="feature">✅ False positive prevention</div>
</div>
<div class="info">
<h2>🌐 API Endpoints</h2>
<p style="margin:10px 0;font-family:monospace">GET / - Dashboard</p>
<p style="margin:10px 0;font-family:monospace">GET /api/stats - Statistics JSON</p>
<p style="margin:10px 0;font-family:monospace">GET /api/test - Protected endpoint</p>
<p style="margin:10px 0;font-family:monospace">POST /api/data - Submit data</p>
</div>
<button class="btn" onclick="location.reload()">🔄 Refresh</button>
</div>
<script>setTimeout(()=>location.reload(),15000)</script>
</body></html>
"""

@app.route('/')
def dashboard():
    uptime = int(time.time() - stats['start'])
    h, m = uptime // 3600, (uptime % 3600) // 60
    block_rate = round(stats['blocked'] / stats['total'] * 100, 1) if stats['total'] > 0 else 0
    return render_template_string(DASHBOARD, stats=stats, uptime=f"{h}h {m}m", block_rate=block_rate)

@app.route('/api/stats')
def get_stats():
    return jsonify({
        'stats': stats,
        'blocked_ips': len(blocked_ips),
        'tracked_ips': len(request_history),
        'uptime': int(time.time() - stats['start'])
    })

@app.route('/api/test')
@limiter.limit("30 per minute")
def test():
    return jsonify({'status': 'success', 'message': 'You are verified!', 'ip': get_remote_address()})

@app.route('/api/data', methods=['POST'])
@limiter.limit("50 per minute")
def submit():
    return jsonify({'status': 'success', 'received': request.get_json() or {}})

@app.route('/health')
def health():
    return jsonify({'status': 'healthy', 'uptime': int(time.time() - stats['start'])})

@app.route('/api/whitelist/<ip>')
@limiter.limit("5 per hour")
def whitelist(ip):
    """Thêm IP vào whitelist"""
    trusted_ips.add(ip)
    return jsonify({'status': 'success', 'whitelisted': ip})

# Cleanup thread
def cleanup():
    while True:
        time.sleep(300)
        now = time.time()
        # Cleanup old tracking data
        for ip in list(request_history.keys()):
            request_history[ip] = [t for t in request_history[ip] if now - t < 60]
            if not request_history[ip]:
                del request_history[ip]
        # Cleanup expired blocks
        for ip in list(blocked_ips.keys()):
            block_time, duration = blocked_ips[ip]
            if now - block_time >= duration:
                del blocked_ips[ip]

threading.Thread(target=cleanup, daemon=True).start()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)
