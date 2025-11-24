"""
Anti-DDoS Protection Server - KHÔNG BAO GIỜ CHẶN BROWSER THẬT
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

# Rate Limiter nhẹ nhàng cho browser thật
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["500 per minute"],  # Tăng lên để không chặn người dùng thật
    storage_uri="memory://"
)

# Data storage
request_history = defaultdict(list)
blocked_ips = {}
trusted_ips = set()
stats = {'total': 0, 'blocked': 0, 'bot': 0, 'human': 0, 'start': time.time()}

# Legitimate browser patterns - QUAN TRỌNG
BROWSER_PATTERNS = [
    r'mozilla/5\.0.*chrome',
    r'mozilla/5\.0.*safari', 
    r'mozilla/5\.0.*firefox',
    r'mozilla/5\.0.*edge',
    r'mozilla/5\.0.*opera',
    r'mozilla/5\.0.*windows',
    r'mozilla/5\.0.*macintosh',
    r'mozilla/5\.0.*android',
    r'mozilla/5\.0.*iphone'
]

# Bot patterns - CHỈ chặn những cái này
DEFINITE_BOT_PATTERNS = [
    r'curl', r'wget', r'python-requests', r'go-http-client',
    r'scrapy', r'httpclient', r'java/', r'ruby', r'perl',
    r'bot[^a-z]', r'crawler', r'spider', r'scraper'
]

def is_real_browser(user_agent):
    """Kiểm tra có phải browser thật KHÔNG"""
    if not user_agent:
        return False
    
    ua_lower = user_agent.lower()
    
    # Kiểm tra browser thật - CHỈ CẦN 1 pattern khớp là OK
    for pattern in BROWSER_PATTERNS:
        if re.search(pattern, ua_lower):
            return True
    
    return False

def is_definite_bot(user_agent):
    """Kiểm tra có CHẮC CHẮN là bot không"""
    if not user_agent:
        return True
    
    ua_lower = user_agent.lower()
    
    # CHỈ chặn khi tìm thấy bot pattern RÕ RÀNG
    for pattern in DEFINITE_BOT_PATTERNS:
        if re.search(pattern, ua_lower):
            return True
    
    return False

def analyze_request(ip, user_agent, headers):
    """Phân tích request - ƯU TIÊN KHÔNG CHẶN BROWSER THẬT"""
    
    # BƯỚC 1: Kiểm tra browser thật NGAY LẬP TỨC
    is_browser = is_real_browser(user_agent)
    
    if is_browser:
        # BROWSER THẬT = CHO QUA LUÔN (trừ khi spam CỰC KỲ nặng)
        current_time = time.time()
        request_history[ip] = [t for t in request_history[ip] if current_time - t < 60]
        request_history[ip].append(current_time)
        req_count = len(request_history[ip])
        
        # CHỈ chặn khi spam THỰC SỰ quá đà (>300 req/min)
        if req_count > 300:
            return {
                'verdict': 'BLOCK',
                'reason': 'Browser spam quá nhanh',
                'score': 100,
                'is_browser': True,
                'req_rate': req_count
            }
        
        # Cho qua tất cả browser thật
        return {
            'verdict': 'ALLOW',
            'reason': 'Real browser detected',
            'score': 0,
            'is_browser': True,
            'req_rate': req_count
        }
    
    # BƯỚC 2: Không phải browser → Kiểm tra có phải bot chắc chắn không
    is_bot = is_definite_bot(user_agent)
    
    if not is_bot:
        # Không phải browser NHƯNG cũng không phải bot rõ ràng
        # → CHO QUA (có thể là API client, mobile app, etc.)
        return {
            'verdict': 'ALLOW',
            'reason': 'Not a known bot',
            'score': 20,
            'is_browser': False,
            'req_rate': 0
        }
    
    # BƯỚC 3: CHẮC CHẮN là bot → Kiểm tra rate
    current_time = time.time()
    request_history[ip] = [t for t in request_history[ip] if current_time - t < 60]
    request_history[ip].append(current_time)
    req_count = len(request_history[ip])
    
    # Bot với rate cao = CHẶN
    if req_count > 100:
        return {
            'verdict': 'BLOCK',
            'reason': f'Bot with high rate: {req_count}/min',
            'score': 100,
            'is_browser': False,
            'req_rate': req_count
        }
    elif req_count > 50:
        return {
            'verdict': 'WARN',
            'reason': f'Bot detected: {req_count}/min',
            'score': 60,
            'is_browser': False,
            'req_rate': req_count
        }
    
    # Bot nhưng rate thấp → Cho qua (có thể là good bot như Google)
    return {
        'verdict': 'ALLOW',
        'reason': 'Bot with low rate',
        'score': 30,
        'is_browser': False,
        'req_rate': req_count
    }

def check_blocked(ip):
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
    """Middleware bảo vệ - ƯU TIÊN KHÔNG CHẶN NGƯỜI DÙNG THẬT"""
    ip = get_remote_address()
    ua = request.headers.get('User-Agent', '')
    
    stats['total'] += 1
    
    # Kiểm tra whitelist TRƯỚC TIÊN
    if ip in trusted_ips:
        stats['human'] += 1
        return  # Cho qua ngay lập tức
    
    # Kiểm tra đã bị block trước đó chưa
    if check_blocked(ip):
        stats['blocked'] += 1
        return jsonify({'error': 'Blocked', 'reason': 'IP temporarily blocked due to bot activity'}), 403
    
    # Phân tích request
    result = analyze_request(ip, ua, request.headers)
    
    # Quyết định
    if result['verdict'] == 'BLOCK':
        # CHỈ block khi THỰC SỰ chắc chắn
        blocked_ips[ip] = (time.time(), 300)  # Block 5 phút
        stats['blocked'] += 1
        stats['bot'] += 1
        
        print(f"[BLOCKED] {ip} | {result['reason']} | Rate: {result['req_rate']}/min")
        
        return jsonify({
            'error': 'Access Denied',
            'reason': result['reason'],
            'rate': result['req_rate'],
            'note': 'Nếu bạn là người dùng thật, vui lòng thử lại sau 5 phút'
        }), 403
    
    # Ghi nhận loại traffic
    if result['is_browser']:
        stats['human'] += 1
    else:
        stats['bot'] += 1
        if result['verdict'] == 'WARN':
            print(f"[WARNING] {ip} | {result['reason']}")

# Dashboard HTML - Gọn gàng
DASHBOARD = """
<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Anti-DDoS Shield</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:#fff;min-height:100vh;padding:20px}
.container{max-width:1200px;margin:0 auto}
h1{text-align:center;font-size:2.5em;margin-bottom:30px;text-shadow:2px 2px 4px rgba(0,0,0,0.3)}
.alert{background:rgba(255,193,7,0.2);border:2px solid #ffc107;border-radius:10px;padding:15px;margin-bottom:20px;text-align:center}
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
<div class="alert">
⚠️ <strong>Chế độ an toàn:</strong> Hệ thống KHÔNG BAO GIỜ chặn browser thật (Chrome, Firefox, Safari, Edge)
</div>
<div class="stats">
<div class="card"><div class="stat-label">📊 Total</div><div class="stat-val">{{stats.total}}</div></div>
<div class="card"><div class="stat-label">🚫 Blocked</div><div class="stat-val">{{stats.blocked}}</div></div>
<div class="card"><div class="stat-label">🤖 Bots</div><div class="stat-val">{{stats.bot}}</div></div>
<div class="card"><div class="stat-label">✅ Humans</div><div class="stat-val">{{stats.human}}</div></div>
</div>
<div class="info">
<h2>🟢 System Status</h2>
<div class="status">ONLINE 24/7 - Safe Mode</div>
<p style="margin-top:15px">Uptime: <strong>{{uptime}}</strong></p>
<p>Block Rate: <strong>{{block_rate}}%</strong></p>
</div>
<div class="info">
<h2>✅ Protection Policy</h2>
<div class="feature">✅ Real browsers ALWAYS allowed (Chrome, Safari, Firefox, Edge)</div>
<div class="feature">✅ Mobile browsers protected</div>
<div class="feature">✅ Only block confirmed bots (curl, scrapy, etc.)</div>
<div class="feature">✅ High rate limit: 500 req/min for humans</div>
<div class="feature">⚠️ Only block at 300+ req/min for browsers</div>
</div>
<div class="info">
<h2>🌐 API Endpoints</h2>
<p style="margin:10px 0;font-family:monospace">GET / - Dashboard (You are here!)</p>
<p style="margin:10px 0;font-family:monospace">GET /api/stats - Statistics</p>
<p style="margin:10px 0;font-family:monospace">GET /api/test - Test endpoint</p>
<p style="margin:10px 0;font-family:monospace">POST /api/data - Submit data</p>
</div>
<button class="btn" onclick="location.reload()">🔄 Refresh Stats</button>
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
def test():
    ip = get_remote_address()
    ua = request.headers.get('User-Agent', '')
    is_browser = is_real_browser(ua)
    return jsonify({
        'status': 'success',
        'message': 'You are verified!',
        'ip': ip,
        'user_agent': ua,
        'detected_as': 'Real Browser ✅' if is_browser else 'API Client/Bot',
        'note': 'Real browsers are never blocked!'
    })

@app.route('/api/data', methods=['POST'])
def submit():
    return jsonify({'status': 'success', 'received': request.get_json() or {}})

@app.route('/health')
def health():
    return jsonify({'status': 'healthy', 'uptime': int(time.time() - stats['start'])})

@app.route('/api/whitelist/<ip>')
def whitelist(ip):
    """Thêm IP vào whitelist"""
    trusted_ips.add(ip)
    return jsonify({'status': 'success', 'whitelisted': ip})

# Cleanup thread
def cleanup():
    while True:
        time.sleep(300)
        now = time.time()
        for ip in list(request_history.keys()):
            request_history[ip] = [t for t in request_history[ip] if now - t < 60]
            if not request_history[ip]:
                del request_history[ip]
        for ip in list(blocked_ips.keys()):
            block_time, duration = blocked_ips[ip]
            if now - block_time >= duration:
                del blocked_ips[ip]

threading.Thread(target=cleanup, daemon=True).start()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)
