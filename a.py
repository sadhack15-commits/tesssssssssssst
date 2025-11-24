"""
Anti-DDoS Protection Server
Deploy on Render.com for 24/7 operation
"""

from flask import Flask, request, jsonify, render_template_string
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from collections import defaultdict
import time
import hashlib
import re
from datetime import datetime
import threading

app = Flask(__name__)

# Cấu hình Rate Limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per minute"],
    storage_uri="memory://"
)

# Lưu trữ thông tin request
request_tracker = defaultdict(list)
blocked_ips = {}
bot_patterns = [
    r'bot', r'crawler', r'spider', r'scraper', r'curl', r'wget',
    r'python-requests', r'go-http-client', r'java', r'axios'
]

# Thống kê
stats = {
    'total_requests': 0,
    'blocked_requests': 0,
    'bot_detected': 0,
    'human_verified': 0,
    'start_time': time.time()
}

def is_bot(user_agent):
    """Kiểm tra User-Agent có phải bot không"""
    if not user_agent:
        return True
    
    user_agent_lower = user_agent.lower()
    for pattern in bot_patterns:
        if re.search(pattern, user_agent_lower):
            return True
    return False

def calculate_threat_score(ip, user_agent, headers):
    """Tính điểm nguy hiểm của request"""
    score = 0
    reasons = []
    
    # Kiểm tra bot
    if is_bot(user_agent):
        score += 40
        reasons.append("Bot User-Agent")
    
    # Kiểm tra tốc độ request
    current_time = time.time()
    request_tracker[ip] = [t for t in request_tracker[ip] if current_time - t < 60]
    request_tracker[ip].append(current_time)
    
    request_rate = len(request_tracker[ip])
    if request_rate > 50:
        score += 50
        reasons.append(f"High request rate: {request_rate}/min")
    elif request_rate > 30:
        score += 30
        reasons.append(f"Suspicious rate: {request_rate}/min")
    
    # Kiểm tra headers
    if 'Accept-Language' not in headers:
        score += 10
        reasons.append("No Accept-Language")
    
    if 'Accept-Encoding' not in headers:
        score += 10
        reasons.append("No Accept-Encoding")
    
    # Kiểm tra Cookie
    if 'Cookie' not in headers:
        score += 5
        reasons.append("No cookies")
    
    return score, reasons

def check_blocked(ip):
    """Kiểm tra IP có bị block không"""
    if ip in blocked_ips:
        block_time, duration = blocked_ips[ip]
        if time.time() - block_time < duration:
            return True
        else:
            del blocked_ips[ip]
    return False

def block_ip(ip, duration=300):
    """Block IP trong một khoảng thời gian (giây)"""
    blocked_ips[ip] = (time.time(), duration)

@app.before_request
def before_request():
    """Kiểm tra mọi request trước khi xử lý"""
    ip = get_remote_address()
    user_agent = request.headers.get('User-Agent', '')
    
    stats['total_requests'] += 1
    
    # Kiểm tra IP đã bị block
    if check_blocked(ip):
        stats['blocked_requests'] += 1
        return jsonify({
            'error': 'Access Denied',
            'message': 'Your IP has been temporarily blocked due to suspicious activity',
            'ip': ip
        }), 403
    
    # Tính threat score
    threat_score, reasons = calculate_threat_score(ip, user_agent, request.headers)
    
    # Block nếu điểm nguy hiểm cao
    if threat_score >= 60:
        block_ip(ip, duration=600)  # Block 10 phút
        stats['blocked_requests'] += 1
        
        log_threat(ip, user_agent, threat_score, reasons, 'BLOCKED')
        
        return jsonify({
            'error': 'Access Denied',
            'message': 'Your request has been blocked',
            'threat_score': threat_score,
            'reasons': reasons
        }), 403
    
    # Ghi nhận bot
    if is_bot(user_agent):
        stats['bot_detected'] += 1
        log_threat(ip, user_agent, threat_score, reasons, 'BOT_DETECTED')
    else:
        stats['human_verified'] += 1

def log_threat(ip, user_agent, score, reasons, action):
    """Ghi log các mối đe dọa"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{timestamp}] {action} - IP: {ip} - Score: {score} - Reasons: {', '.join(reasons)}")

# HTML Dashboard
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Anti-DDoS Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 20px;
            min-height: 100vh;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 {
            text-align: center;
            margin-bottom: 30px;
            font-size: 2.5em;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 25px;
            border: 1px solid rgba(255, 255, 255, 0.2);
            transition: transform 0.3s;
        }
        .stat-card:hover { transform: translateY(-5px); }
        .stat-value {
            font-size: 2.5em;
            font-weight: bold;
            margin: 10px 0;
        }
        .stat-label {
            font-size: 0.9em;
            opacity: 0.8;
            text-transform: uppercase;
        }
        .info-section {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 25px;
            margin-top: 20px;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        .status {
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            background: #4CAF50;
            font-weight: bold;
            margin: 10px 0;
        }
        .feature-list {
            list-style: none;
            padding: 0;
        }
        .feature-list li {
            padding: 10px;
            margin: 5px 0;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 8px;
            border-left: 4px solid #4CAF50;
        }
        .refresh-btn {
            background: #4CAF50;
            color: white;
            border: none;
            padding: 12px 30px;
            border-radius: 25px;
            font-size: 1em;
            cursor: pointer;
            margin: 20px auto;
            display: block;
            transition: background 0.3s;
        }
        .refresh-btn:hover { background: #45a049; }
        .endpoint {
            background: rgba(0, 0, 0, 0.3);
            padding: 10px;
            border-radius: 8px;
            margin: 10px 0;
            font-family: 'Courier New', monospace;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Anti-DDoS Protection Dashboard</h1>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">📊 Tổng Requests</div>
                <div class="stat-value" id="total">{{ stats.total_requests }}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">🚫 Đã Chặn</div>
                <div class="stat-value" id="blocked">{{ stats.blocked_requests }}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">🤖 Bot Phát Hiện</div>
                <div class="stat-value" id="bots">{{ stats.bot_detected }}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">✅ Người Dùng Thực</div>
                <div class="stat-value" id="humans">{{ stats.human_verified }}</div>
            </div>
        </div>

        <div class="info-section">
            <h2>🟢 Trạng Thái Hệ Thống</h2>
            <div class="status">ONLINE - Running 24/7</div>
            <p style="margin-top: 15px;">Server đã chạy được: <strong>{{ uptime }}</strong></p>
        </div>

        <div class="info-section">
            <h2>🔒 Tính Năng Bảo Vệ</h2>
            <ul class="feature-list">
                <li>✅ Rate Limiting: 100 requests/phút mỗi IP</li>
                <li>✅ Bot Detection qua User-Agent Analysis</li>
                <li>✅ Threat Score Calculation</li>
                <li>✅ Tự động block IP nguy hiểm</li>
                <li>✅ Header & Cookie Validation</li>
                <li>✅ Real-time Monitoring</li>
            </ul>
        </div>

        <div class="info-section">
            <h2>🌐 API Endpoints</h2>
            <div class="endpoint">GET / - Dashboard này</div>
            <div class="endpoint">GET /api/stats - Thống kê JSON</div>
            <div class="endpoint">GET /api/test - Test endpoint được bảo vệ</div>
            <div class="endpoint">POST /api/data - Submit data (rate limited)</div>
        </div>

        <button class="refresh-btn" onclick="location.reload()">🔄 Refresh Stats</button>
    </div>

    <script>
        // Auto refresh mỗi 10 giây
        setTimeout(() => location.reload(), 10000);
    </script>
</body>
</html>
"""

@app.route('/')
def dashboard():
    """Dashboard hiển thị thống kê"""
    uptime_seconds = int(time.time() - stats['start_time'])
    hours = uptime_seconds // 3600
    minutes = (uptime_seconds % 3600) // 60
    uptime = f"{hours}h {minutes}m"
    
    return render_template_string(DASHBOARD_HTML, stats=stats, uptime=uptime)

@app.route('/api/stats')
def get_stats():
    """API trả về thống kê"""
    return jsonify({
        'stats': stats,
        'blocked_ips': len(blocked_ips),
        'tracked_ips': len(request_tracker),
        'uptime_seconds': int(time.time() - stats['start_time'])
    })

@app.route('/api/test')
@limiter.limit("10 per minute")
def test_endpoint():
    """Endpoint test được bảo vệ"""
    return jsonify({
        'status': 'success',
        'message': 'Request successful! You are verified.',
        'ip': get_remote_address(),
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/data', methods=['POST'])
@limiter.limit("20 per minute")
def submit_data():
    """API nhận dữ liệu"""
    data = request.get_json() or {}
    return jsonify({
        'status': 'success',
        'message': 'Data received',
        'received': data
    })

@app.route('/health')
def health_check():
    """Health check cho Render"""
    return jsonify({'status': 'healthy', 'uptime': int(time.time() - stats['start_time'])})

# Cleanup task - xóa dữ liệu cũ mỗi 5 phút
def cleanup_old_data():
    while True:
        time.sleep(300)  # 5 phút
        current_time = time.time()
        
        # Xóa IP tracking cũ
        for ip in list(request_tracker.keys()):
            request_tracker[ip] = [t for t in request_tracker[ip] if current_time - t < 60]
            if not request_tracker[ip]:
                del request_tracker[ip]
        
        # Xóa blocked IPs hết hạn
        for ip in list(blocked_ips.keys()):
            block_time, duration = blocked_ips[ip]
            if current_time - block_time >= duration:
                del blocked_ips[ip]

# Start cleanup thread
cleanup_thread = threading.Thread(target=cleanup_old_data, daemon=True)
cleanup_thread.start()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)
