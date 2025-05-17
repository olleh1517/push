import os
import random
import datetime
import smtplib
from email.mime.text import MIMEText
from flask import Flask, request, jsonify, render_template, redirect
import firebase_admin
from firebase_admin import credentials, auth as firebase_auth
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')

# Render에 업로드된 Secret File 경로
firebase_credentials_path = "/etc/secrets/firebase_credentials.json"

# 그대로 초기화
cred = credentials.Certificate(firebase_credentials_path)
firebase_admin.initialize_app(cred)

pending_codes = {}  # 이메일: 인증코드 및 임시 토큰 저장
users = {}  # users[email] = {"device_tokens": [...], "approved": bool, "password": "..."}
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
        print(f"[메일발송 성공] {email} 에 인증코드 {code} 전송됨")
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
        print(f"[관리자 승인 요청 메일 발송 성공] {ADMIN_EMAIL} 에 전송됨")
    except Exception as e:
        print(f"[메일발송 실패] {e}")


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

    if email in users or email in pending_codes:
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

    users[email] = {
        "device_tokens": [pending['device_token']],
        "approved": False,
        "password": password  # Firebase 등록은 승인 후에
    }
    del pending_codes[email]
    send_admin_approval_email(email, users[email]['device_tokens'][0])
    return jsonify({'status': 'pending', 'message': '가입 신청 완료. 승인을 기다려 주세요.'})


@app.route('/check-approval', methods=['POST'])
def check_approval():
    data = request.get_json()
    email = data.get('email')
    user_info = users.get(email)
    if not user_info:
        return jsonify({'status': 'fail', 'message': '사용자 없음'}), 404
    return jsonify({'status': 'approved' if user_info['approved'] else 'pending'})

@app.route('/commit', methods=['GET', 'POST'])
def commit_page():
    pending_users = {email: info for email, info in users.items() if not info['approved']}
    pending_devices = {
        email: info['pending_device_tokens']
        for email, info in users.items()
        if info.get('approved') and info.get('pending_device_tokens')
    }

    return render_template('commit.html', pending_users=pending_users, pending_devices=pending_devices)


@app.route('/commit/approve-user', methods=['POST'])
def approve_user():
    data = request.get_json()
    email = data.get('email')
    if not email or email not in users:
        return jsonify({'status': 'fail', 'message': '이메일 오류'}), 400
    if users[email]['approved']:
        return jsonify({'status': 'fail', 'message': '이미 승인된 사용자입니다.'}), 400

    try:
        firebase_auth.create_user(
            email=email,
            password=users[email]['password']
        )
    except firebase_auth.EmailAlreadyExistsError:
        return jsonify({'status': 'fail', 'message': '이미 Firebase에 존재하는 이메일입니다.'}), 400
    except Exception as e:
        return jsonify({'status': 'fail', 'message': f'Firebase 등록 실패: {str(e)}'}), 500

    users[email]['approved'] = True
    return jsonify({'status': 'ok', 'message': '승인 및 등록 완료'})


@app.route('/commit/reject-user', methods=['POST'])
def reject_user():
    data = request.get_json()
    email = data.get('email')
    if not email or email not in users:
        return jsonify({'status': 'fail', 'message': '이메일 오류'}), 400
    if users[email]['approved']:
        return jsonify({'status': 'fail', 'message': '이미 승인된 사용자입니다.'}), 400
    del users[email]
    return jsonify({'status': 'ok', 'message': '가입 요청 거부됨'})


@app.route('/commit/approve-device', methods=['POST'])
def approve_device():
    data = request.get_json()
    email = data.get('email')
    device_token = data.get('device_token')

    user = users.get(email)
    if not user or device_token not in user.get('pending_device_tokens', []):
        return jsonify({'status': 'fail', 'message': '승인 대상이 올바르지 않습니다.'}), 400

    user['device_tokens'].append(device_token)
    user['pending_device_tokens'].remove(device_token)

    return jsonify({'status': 'ok', 'message': '기기 등록 승인됨'})


@app.route('/commit/reject-device', methods=['POST'])
def reject_device():
    data = request.get_json()
    email = data.get('email')
    device_token = data.get('device_token')

    user = users.get(email)
    if not user or device_token not in user.get('pending_device_tokens', []):
        return jsonify({'status': 'fail', 'message': '거부 대상이 올바르지 않습니다.'}), 400

    user['pending_device_tokens'].remove(device_token)

    return jsonify({'status': 'ok', 'message': '기기 등록 거부됨'})


@app.route('/admin')
def admin_page():
    pending_users = {email: info for email, info in users.items() if not info['approved']}
    return render_template('admin.html', pending_users=pending_users, logs=login_logs)


@app.route('/login', methods=['GET'])
def login_page():
    return render_template('login.html')


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

    user = users.get(email)
    if not user:
        log['status'] = 'fail'
        log['reason'] = '등록되지 않은 사용자'
        login_logs.append(log)
        return jsonify({'status': 'fail', 'message': '사용자 없음'}), 403

    if not user['approved']:
        log['status'] = 'fail'
        log['reason'] = '미승인 사용자'
        login_logs.append(log)
        return jsonify({'status': 'fail', 'message': '미승인 사용자'}), 403

    if device_token not in user['device_tokens']:
        log['status'] = 'fail'
        log['reason'] = '기기 토큰 불일치'
        login_logs.append(log)
        return jsonify({'status': 'fail', 'message': '기기 불일치'}), 403

    if status == 'success':
        log['status'] = 'success'
        login_logs.append(log)
        return jsonify({'status': 'ok', 'message': '로그인 성공'})
    else:
        log['status'] = 'fail'
        login_logs.append(log)
        return jsonify({'status': 'fail', 'message': reason or '로그인 실패'})
    
@app.route('/register-device', methods=['POST'])
def register_device():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    device_token = data.get('device_token')

    if not all([email, password, device_token]):
        return jsonify({'status': 'fail', 'message': '이메일, 비밀번호, 기기 토큰 모두 필요합니다.'}), 400

    # 사용자 존재 확인 및 비밀번호 검증 (여기선 간략화, 실제론 Firebase에서 확인)
    try:
        user_record = firebase_auth.get_user_by_email(email)
        # TODO: 비밀번호 확인은 Firebase에서 별도 처리 (여기선 생략)
    except firebase_auth.UserNotFoundError:
        return jsonify({'status': 'fail', 'message': '등록되지 않은 이메일입니다.'}), 404

    user_info = users.get(email)
    if not user_info or not user_info.get('approved', False):
        return jsonify({'status': 'fail', 'message': '승인된 사용자가 아닙니다.'}), 403

    if device_token in user_info.get('device_tokens', []):
        return jsonify({'status': 'already_registered', 'message': '이미 등록된 기기입니다.'})

    # 등록 요청 처리: 승인 대기 상태로 등록 신청 기록 남기기
    # (기존 users 딕셔너리에 따로 저장하거나 별도 구조로 관리 가능)
    if 'pending_device_tokens' not in user_info:
        user_info['pending_device_tokens'] = []
    if device_token in user_info['pending_device_tokens']:
        return jsonify({'status': 'fail', 'message': '이미 등록 요청 중인 기기입니다.'})

    user_info['pending_device_tokens'].append(device_token)

    # 관리자에게 승인 요청 메일 보내기 (기존 send_admin_approval_email 재활용 가능)
    subject = "새로운 기기 등록 승인 요청"
    body = (
        f"새로운 기기 등록 요청이 있습니다.\n\n"
        f"이메일: {email}\n"
        f"기기 토큰: {device_token}\n\n"
        f"관리자 페이지에서 승인을 진행해주세요."
    )
    # 메일 발송 함수 재활용
    send_admin_approval_email(email, device_token)

    return jsonify({'status': 'pending', 'message': '기기 등록 신청 완료. 관리자의 승인을 기다려 주세요.'})


if __name__ == '__main__':
    port = int(os.getenv("PORT", 5000))
    app.run(debug=True, host='0.0.0.0', port=port)