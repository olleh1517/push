from flask import Flask, request, jsonify, render_template, redirect
from flask_socketio import SocketIO, emit
import firebase_admin
from firebase_admin import credentials, auth as firebase_auth
from .smtp_utils import send_verification_email
import uuid, time, random, os
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)

# Firebase 초기화 - 환경변수에서 JSON 문자열 받아서 파싱
firebase_json = os.environ.get("FIREBASE_CREDENTIALS")
if not firebase_json:
    raise ValueError("FIREBASE_CREDENTIALS 환경변수가 설정되어 있지 않습니다.")

try:
    cred_dict = json.loads(firebase_json)
except json.JSONDecodeError:
    raise ValueError("FIREBASE_CREDENTIALS 환경변수의 JSON 형식이 올바르지 않습니다.")

cred = credentials.Certificate(cred_dict)
firebase_admin.initialize_app(cred)

login_requests = {}   # 로그인 요청 저장 {request_id: {email, status, timestamp}}
pending_codes = {}    # 이메일 인증 코드 저장 {email: code}

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
    email = request.json.get('email')
    if not email:
        return jsonify({'error': '이메일이 필요합니다.'}), 400
    
    code = str(random.randint(100000, 999999))
    pending_codes[email] = code
    send_verification_email(email, code)
    return jsonify({'message': '인증코드를 이메일로 전송했습니다.'})

@app.route('/verify-code', methods=['POST'])
def verify_code():
    data = request.json or {}
    email = data.get('email')
    code = data.get('code')

    if not email or not code:
        return jsonify({'status': 'fail', 'error': '이메일과 코드를 모두 입력해야 합니다.'}), 400
    
    if pending_codes.get(email) == code:
        return jsonify({'status': 'ok'})
    return jsonify({'status': 'fail'})

@app.route('/request-login', methods=['POST'])
def request_login():
    token = request.json.get('token')
    if not token:
        return jsonify({'error': '토큰이 필요합니다.'}), 400

    try:
        decoded = firebase_auth.verify_id_token(token)
        email = decoded.get('email')
        if not email:
            return jsonify({'error': '토큰에서 이메일을 찾을 수 없습니다.'}), 400

        request_id = str(uuid.uuid4())
        login_requests[request_id] = {
            'email': email,
            'status': 'pending',
            'timestamp': time.time()
        }
        socketio.emit('login_request', {'request_id': request_id, 'email': email})
        return jsonify({'request_id': request_id})
    except Exception as e:
        return jsonify({'error': str(e)}), 401

@app.route('/confirm-login', methods=['POST'])
def confirm_login():
    data = request.json or {}
    print('confirm-login 요청 데이터:', data)

    request_id = data.get('request_id')
    status = data.get('status')

    if not request_id or not status:
        return jsonify({'result': 'fail', 'error': 'request_id와 status가 모두 필요합니다.'}), 400
    
    if request_id in login_requests:
        login_requests[request_id]['status'] = status
        return jsonify({'result': 'ok'})

    return jsonify({'result': 'fail', 'error': '유효하지 않은 request_id 입니다.'}), 400

@app.route('/check-status/<request_id>')
def check_status(request_id):
    req = login_requests.get(request_id)
    if not req:
        return jsonify({'status': 'unknown', 'error': '존재하지 않는 요청 ID입니다.'}), 404
    return jsonify({'status': req.get('status', 'unknown')})

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, debug=False, host='0.0.0.0', port=port)
