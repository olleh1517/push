# ────────────────────────────────────────────────
# server.py
# ────────────────────────────────────────────────

# 1) --- IPv4 전용 DNS 강제 패치 (반드시 최상단에!)
import socket
_old_getaddrinfo = socket.getaddrinfo
def _getaddrinfo_ipv4_only(host, port, family=0, socktype=0, proto=0, flags=0):
    results = _old_getaddrinfo(host, port, family, socktype, proto, flags)
    return [res for res in results if res[0] == socket.AF_INET]
socket.getaddrinfo = _getaddrinfo_ipv4_only

# 2) 나머지 표준 임포트
from flask import Flask, request, jsonify, render_template, redirect
from flask_socketio import SocketIO, emit
import firebase_admin
from firebase_admin import credentials, auth as firebase_auth
from firebase_admin._token_gen import CertificateFetchError
from .smtp_utils import send_verification_email
import uuid, time, random, os, json, traceback

# 3) Flask 앱 초기화
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)

# 4) Firebase Admin 초기화
firebase_json = os.environ.get("FIREBASE_CREDENTIALS")
if not firebase_json:
    raise ValueError("FIREBASE_CREDENTIALS 환경변수가 설정되어 있지 않습니다.")

cred_dict = json.loads(firebase_json)
cred = credentials.Certificate(cred_dict)

if not firebase_admin._apps:
    firebase_admin.initialize_app(cred)

# 5) 인증 상태 저장용
login_requests = {}
pending_codes = {}

# 6) 라우트 정의
@app.route('/')
def index():
    return redirect('/login')

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/success')
def success():
    return render_template('success.html')

@app.route('/signup')
def signup_page():
    return render_template('signup.html')

@app.route('/admin')
def admin():
    return render_template('admin.html')

@app.route('/send-code', methods=['POST'])
def send_code():
    email = request.json['email']
    code = str(random.randint(100000, 999999))
    pending_codes[email] = code
    send_verification_email(email, code)
    return jsonify({'message': '인증코드를 이메일로 전송했습니다.'})

@app.route('/verify-code', methods=['POST'])
def verify_code():
    data = request.json
    email = data.get('email')
    code = data.get('code')
    if pending_codes.get(email) == code:
        return jsonify({'status': 'ok'})
    return jsonify({'status': 'fail'})

@app.route('/request-login', methods=['POST'])
def request_login():
    token = request.json.get('token')
    print("[DEBUG] 받은 토큰:", token)

    decoded = None
    # CertificateFetchError 시 최대 5회 재시도
    for attempt in range(1, 6):
        try:
            decoded = firebase_auth.verify_id_token(token)
            print(f"[DEBUG] Firebase 인증 성공 (attempt {attempt}):", decoded)
            break
        except CertificateFetchError as e:
            print(f"[WARN] 인증서 서버 연결 실패 (attempt {attempt}):", e)
            time.sleep(attempt)  # backoff: 1s, 2s, 3s...
        except Exception as e:
            print("[ERROR] Firebase 인증 실패:", repr(e))
            traceback.print_exc()
            return jsonify({'error': 'Firebase 인증 오류 발생'}), 401

    if decoded is None:
        return jsonify({
            'error': 'Google 인증서 서버와 연결되지 않았습니다. 잠시 후 다시 시도해 주세요.'
        }), 503

    email = decoded.get('email')
    request_id = str(uuid.uuid4())
    login_requests[request_id] = {
        'email': email,
        'status': 'pending',
        'timestamp': time.time()
    }
    socketio.emit('login_request', {'request_id': request_id, 'email': email})
    return jsonify({'request_id': request_id})

@app.route('/confirm-login', methods=['POST'])
def confirm_login():
    data = request.json or {}
    request_id = data.get('request_id')
    status = data.get('status')
    if not request_id or not status:
        return jsonify({'result': 'fail', 'error': 'Missing request_id or status'}), 400
    if request_id in login_requests:
        login_requests[request_id]['status'] = status
        return jsonify({'result': 'ok'})
    return jsonify({'result': 'fail', 'error': 'Invalid request_id'}), 400

@app.route('/check-status/<request_id>')
def check_status(request_id):
    req = login_requests.get(request_id, {})
    return jsonify({'status': req.get('status', 'unknown')})

# 7) 앱 실행
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, debug=False, host='0.0.0.0', port=port)
