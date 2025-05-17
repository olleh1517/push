from flask import Flask, request, jsonify, render_template, redirect
from flask_socketio import SocketIO, emit
import firebase_admin
from firebase_admin import credentials, auth as firebase_auth
from .smtp_utils import send_verification_email
import uuid, time, random, os, json, traceback
from firebase_admin._token_gen import CertificateFetchError

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)

# ✅ Firebase Admin 초기화
firebase_json = os.environ.get("FIREBASE_CREDENTIALS")
if not firebase_json:
    raise ValueError("FIREBASE_CREDENTIALS 환경변수가 설정되어 있지 않습니다.")

cred_dict = json.loads(firebase_json)
cred = credentials.Certificate(cred_dict)

# 중복 초기화 방지
if not firebase_admin._apps:
    firebase_admin.initialize_app(cred)

# ✅ 인증 상태 저장용
login_requests = {}   # push 인증 요청 저장
pending_codes = {}    # 이메일 인증코드 저장

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

    try:
        decoded = firebase_auth.verify_id_token(token)
        print("[DEBUG] Firebase 인증 성공:", decoded)

        email = decoded.get('email')
        request_id = str(uuid.uuid4())
        login_requests[request_id] = {
            'email': email,
            'status': 'pending',
            'timestamp': time.time()
        }

        # 실시간 로그인 요청 전송
        socketio.emit('login_request', {'request_id': request_id, 'email': email})
        return jsonify({'request_id': request_id})
    except CertificateFetchError as e:
        print("[ERROR] 인증서 서버 연결 실패:", e)
        return jsonify({'error': 'Google 인증서 서버와 연결되지 않았습니다. 잠시 후 다시 시도해 주세요.'}), 503

    except Exception as e:
        print("[ERROR] Firebase 인증 실패:", repr(e))
        traceback.print_exc()
        return jsonify({'error': 'Firebase 인증 오류 발생'}), 401

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

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, debug=False, host='0.0.0.0', port=port)
