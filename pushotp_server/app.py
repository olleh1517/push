# Step 1: 기존 기기 인증 기능 제거 + 새로운 OTP 사용자 기반 구조 설계

# ✅ 필요한 모듈 임포트
import os
import random
import bcrypt
import pyotp
from datetime import datetime, timezone
from flask import Flask, request, jsonify, render_template, redirect
from dotenv import load_dotenv
import firebase_admin
from firebase_admin import credentials, auth as firebase_auth, firestore
import qrcode
import io
import base64

import smtplib
from email.mime.text import MIMEText

# ✅ 초기 설정
load_dotenv()
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')

firebase_credentials_path = "/etc/secrets/firebase_credentials.json"
if not firebase_admin._apps:
    cred = credentials.Certificate(firebase_credentials_path)
    firebase_admin.initialize_app(cred)

db = firestore.client()

# ✅ 유틸 함수들

def save_user_otp(email, data):
    db.collection('users_otp').document(email).set(data)

def get_user_otp(email):
    doc = db.collection('users_otp').document(email).get()
    return doc.to_dict() if doc.exists else None

SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
SMTP_EMAIL = os.getenv('SMTP_EMAIL')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')
login_logs = []

def send_email(to, subject, body):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = SMTP_EMAIL
    msg['To'] = to
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            server.sendmail(SMTP_EMAIL, to, msg.as_string())
        return True
    except Exception as e:
        print(f"[이메일 전송 실패] {e}")
        return False

# ✅ 라우트 1: 회원가입 페이지
@app.route('/signup', methods=['GET'])
def signup_page():
    return render_template('signup_otp.html')

@app.route('/signup', methods=['POST'])
def signup_post():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'status': 'fail', 'message': '이메일과 비밀번호가 필요합니다.'}), 400

    if get_user_otp(email):
        return jsonify({'status': 'fail', 'message': '이미 가입된 이메일입니다.'}), 400

    hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    otp_secret = pyotp.random_base32()

    save_user_otp(email, {
        'email': email,
        'password': hashed_pw,
        'otp_secret': otp_secret,
        'approved': True
    })

    # OTP URI 생성
    otp_uri = pyotp.totp.TOTP(otp_secret).provisioning_uri(name=email, issuer_name="PushOTP")

    # 🔽 QR 코드 이미지 생성
    img = qrcode.make(otp_uri)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    qr_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')

    return jsonify({
        'status': 'ok',
        'qr_code_base64': qr_b64,
        'message': '가입 완료! 아래 QR을 OTP 앱으로 스캔하세요.'
    })

@app.route('/request-signup-code', methods=['POST'])
def request_signup_code():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({'status': 'fail', 'message': '이메일이 필요합니다.'}), 400

    code = str(random.randint(100000, 999999))
    db.collection('pending_signup_codes').document(email).set({
        'code': code,
        'created_at': datetime.now(timezone.utc)
    })

    # 이메일 전송
    send_email(email, 'PushOTP 가입 인증코드', f'인증코드: {code}')
    return jsonify({'status': 'ok', 'message': '인증코드를 이메일로 전송했습니다.'})

@app.route('/verify-signup-code', methods=['POST'])
def verify_signup_code():
    data = request.get_json()
    email = data.get('email')
    code = data.get('code')

    doc = db.collection('pending_signup_codes').document(email).get()
    if not doc.exists:
        return jsonify({'status': 'fail', 'message': '인증코드가 없습니다.'}), 400

    record = doc.to_dict()
    if record['code'] != code:
        return jsonify({'status': 'fail', 'message': '인증코드가 틀렸습니다.'}), 403

    # 시간 만료 검증 (예: 5분)
    if (datetime.now(timezone.utc) - record['created_at']).total_seconds() > 300:
        return jsonify({'status': 'fail', 'message': '인증코드가 만료되었습니다.'}), 400

    return jsonify({'status': 'ok', 'message': '인증 완료'})


@app.route('/login-otp', methods=['POST'])
def login_otp():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    otp_code = data.get('otp')
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)

    log = {
        'email': email,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'ip': ip,
    }

    if not all([email, password, otp_code]):
        log.update({'status': 'fail', 'reason': '입력 누락'})
        login_logs.append(log)
        return jsonify({'status': 'fail', 'message': '모든 항목을 입력하세요.'}), 400

    user_doc = db.collection('users_otp').document(email).get()
    if not user_doc.exists:
        log.update({'status': 'fail', 'reason': '사용자 없음'})
        login_logs.append(log)
        return jsonify({'status': 'fail', 'message': '사용자를 찾을 수 없습니다.'}), 404

    info = user_doc.to_dict()
    if not bcrypt.checkpw(password.encode(), info.get('hashed_pw', '').encode()):
        log.update({'status': 'fail', 'reason': '비밀번호 틀림'})
        login_logs.append(log)
        return jsonify({'status': 'fail', 'message': '비밀번호가 틀렸습니다.'}), 403

    totp = pyotp.TOTP(info.get('otp_secret'))
    if not totp.verify(otp_code):
        log.update({'status': 'fail', 'reason': 'OTP 실패'})
        login_logs.append(log)
        return jsonify({'status': 'fail', 'message': 'OTP 코드가 틀렸습니다.'}), 403

    log.update({'status': 'success', 'reason': '로그인 성공'})
    login_logs.append(log)
    return jsonify({'status': 'ok', 'message': '로그인 성공'})


@app.route('/admin')
def admin_page():
    return render_template('admin.html', logs=login_logs)

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.getenv('PORT', 5000)))
