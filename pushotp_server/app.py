import os
import random
import datetime
import smtplib
from email.mime.text import MIMEText
from flask import Flask, request, jsonify, render_template, redirect
import firebase_admin
from firebase_admin import credentials, auth as firebase_auth, firestore
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')

firebase_credentials_path = "/etc/secrets/firebase_credentials.json"
cred = credentials.Certificate(firebase_credentials_path)
firebase_admin.initialize_app(cred)

db = firestore.client()
pending_codes = {}
login_logs = []

SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
SMTP_EMAIL = os.getenv('SMTP_EMAIL')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')
ADMIN_EMAIL = os.getenv('ADMIN_EMAIL')


def send_verification_email(email, code):
    subject = "회원가입 인증 코드"
    body = f"인증 코드: {code}"
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = SMTP_EMAIL
    msg['To'] = email
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            server.sendmail(SMTP_EMAIL, email, msg.as_string())
    except Exception as e:
        print(f"[메일발송 실패] {e}")


def send_admin_approval_email(email, device_token):
    subject = "회원가입 승인 요청"
    body = f"이메일: {email}\n기기 토큰: {device_token}\n\n관리자 페이지에서 승인을 진행해주세요."
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = SMTP_EMAIL
    msg['To'] = ADMIN_EMAIL
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            server.sendmail(SMTP_EMAIL, ADMIN_EMAIL, msg.as_string())
    except Exception as e:
        print(f"[메일발송 실패] {e}")


def get_user(email):
    doc = db.collection("users").document(email).get()
    return doc.to_dict() if doc.exists else None


def save_user(email, data):
    db.collection("users").document(email).set(data)


def delete_user(email):
    db.collection("users").document(email).delete()


@app.route('/')
def index():
    return redirect('/signup')


@app.route('/signup', methods=['GET'])
def signup_page():
    return render_template('signup.html')


@app.route('/signup', methods=['POST'])
def signup_post():
    data = request.json
    email = data.get('email')
    device_token = data.get('device_token')

    if not email or not device_token:
        return jsonify({'error': '이메일과 기기 토큰이 필요합니다.'}), 400

    if get_user(email) or email in pending_codes:
        return jsonify({'error': '이미 인증 중이거나 가입된 이메일입니다.'}), 400

    code = str(random.randint(100000, 999999))
    pending_codes[email] = {'code': code, 'device_token': device_token}
    send_verification_email(email, code)

    return jsonify({'message': '인증코드를 이메일로 보냈습니다.'})


@app.route('/verify-email', methods=['POST'])
def verify_email():
    data = request.json
    email = data.get('email')
    code = data.get('code')
    password = data.get('password')

    if not all([email, code, password]):
        return jsonify({'status': 'fail', 'message': '모든 항목이 필요합니다.'}), 400

    pending = pending_codes.get(email)
    if not pending or pending['code'] != code:
        return jsonify({'status': 'fail', 'message': '인증코드가 틀립니다.'}), 400

    user_data = {
        "device_tokens": [pending['device_token']],
        "approved": False,
        "password": password
    }
    save_user(email, user_data)
    del pending_codes[email]
    send_admin_approval_email(email, pending['device_token'])
    return jsonify({'status': 'pending', 'message': '가입 신청 완료. 승인을 기다려 주세요.'})


@app.route('/check-approval', methods=['POST'])
def check_approval():
    data = request.get_json()
    email = data.get('email')
    user_info = get_user(email)
    if not user_info:
        return jsonify({'status': 'fail', 'message': '사용자 없음'}), 404
    return jsonify({'status': 'approved' if user_info.get('approved') else 'pending'})


@app.route('/commit/approve-user', methods=['POST'])
def approve_user():
    data = request.get_json()
    email = data.get('email')
    user = get_user(email)
    if not user:
        return jsonify({'status': 'fail', 'message': '사용자 없음'}), 400
    if user.get('approved'):
        return jsonify({'status': 'fail', 'message': '이미 승인됨'}), 400

    try:
        firebase_auth.create_user(email=email, password=user['password'])
    except firebase_auth.EmailAlreadyExistsError:
        pass
    except Exception as e:
        return jsonify({'status': 'fail', 'message': str(e)}), 500

    user['approved'] = True
    save_user(email, user)
    return jsonify({'status': 'ok'})


@app.route('/commit/reject-user', methods=['POST'])
def reject_user():
    data = request.get_json()
    email = data.get('email')
    user = get_user(email)
    if not user or user.get('approved'):
        return jsonify({'status': 'fail', 'message': '잘못된 요청'}), 400
    delete_user(email)
    return jsonify({'status': 'ok'})


@app.route('/commit', methods=['GET'])
def commit_page():
    docs = db.collection("users").stream()
    pending_users = {
        doc.id: doc.to_dict() for doc in docs
        if not doc.to_dict().get('approved')
    }
    return render_template('commit.html', pending_users=pending_users)


@app.route('/register-device', methods=['POST'])
def register_device():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    device_token = data.get('device_token')

    user = get_user(email)
    if not user or not user.get('approved'):
        return jsonify({'status': 'fail', 'message': '승인된 사용자 아님'}), 403

    if password != user['password']:
        return jsonify({'status': 'fail', 'message': '비밀번호 불일치'}), 403

    if device_token in user.get('device_tokens', []):
        return jsonify({'status': 'already_registered'})

    pending = user.get('pending_device_tokens', [])
    if device_token in pending:
        return jsonify({'status': 'fail', 'message': '이미 등록 요청 중인 기기입니다.'})

    pending.append(device_token)
    user['pending_device_tokens'] = pending
    save_user(email, user)
    send_admin_approval_email(email, device_token)
    return jsonify({'status': 'pending', 'message': '기기 등록 요청 완료'})


@app.route('/login', methods=['POST'])
def login_post():
    data = request.json
    email = data.get('email')
    device_token = data.get('device_token')
    status = data.get('status')
    reason = data.get('reason', '')

    log = {
        'email': email,
        'timestamp': datetime.datetime.utcnow().isoformat() + 'Z',
        'status': status,
        'reason': reason
    }

    user = get_user(email)
    if not user:
        log['status'] = 'fail'
        log['reason'] = '사용자 없음'
        login_logs.append(log)
        return jsonify({'status': 'fail', 'message': '사용자 없음'}), 403

    if not user.get('approved'):
        log['status'] = 'fail'
        log['reason'] = '미승인 사용자'
        login_logs.append(log)
        return jsonify({'status': 'fail', 'message': '미승인 사용자'}), 403

    if device_token not in user.get('device_tokens', []):
        log['status'] = 'fail'
        log['reason'] = '기기 불일치'
        login_logs.append(log)
        return jsonify({'status': 'fail', 'message': '기기 불일치'}), 403

    log['status'] = 'success'
    login_logs.append(log)
    return jsonify({'status': 'ok', 'message': '로그인 성공'})


if __name__ == '__main__':
    port = int(os.getenv("PORT", 5000))
    app.run(debug=True, host='0.0.0.0', port=port)
