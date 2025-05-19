import os
import random
import datetime
import smtplib
import requests
import bcrypt
from email.mime.text import MIMEText
from flask import Flask, request, jsonify, render_template, redirect
import firebase_admin
from firebase_admin import credentials, auth as firebase_auth, firestore
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')

# Firebase Admin SDK 초기화
firebase_credentials_path = "/etc/secrets/firebase_credentials.json"
if not firebase_admin._apps:
    cred = credentials.Certificate(firebase_credentials_path)
    firebase_admin.initialize_app(cred, {
        'projectId': 'pushotp-49168'
    })

db = firestore.client()

# SMTP 설정
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
SMTP_EMAIL = os.getenv('SMTP_EMAIL')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')
ADMIN_EMAIL = os.getenv('ADMIN_EMAIL')

pending_codes = {}  # 인증 코드 임시 저장소
login_logs = []     # 로그인 기록 저장소


# Firestore 유틸
def save_user(email, data):
    db.collection('users').document(email).set(data)

def get_user(email):
    doc = db.collection('users').document(email).get()
    if doc.exists:
        user = doc.to_dict()
        print("[Firestore 유저 로드]", user)  # 🔍 여기에 로그 추가
        return user
    return None


# 이메일 유틸
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
        print(f"[메일발송 실패] {e}")
        return False

def send_verification_email(email, code):
    subject = "회원가입 인증 코드"
    body = f"인증 코드: {code}"
    return send_email(email, subject, body)

def send_admin_approval_email(email, device_token, is_new_user=True):
    subject = "회원가입 승인 요청" if is_new_user else "기기 등록 승인 요청"
    body = f"이메일: {email}\n기기 토큰: {device_token}\n\n관리자 페이지에서 승인을 진행해주세요."
    send_email(ADMIN_EMAIL, subject, body)

def send_security_alert(email, location_info):
    subject = "보안 경고: 허가되지 않은 기기에서 로그인 시도"
    body = f"""
이메일: {email}
IP: {location_info['ip']}
위치: {location_info.get('city')}, {location_info.get('region')}, {location_info.get('country')}
시간: {datetime.datetime.utcnow().isoformat()} UTC
"""
    send_email(email, subject, body)

def get_ip_location(ip):
    try:
        res = requests.get(f"https://ipapi.co/{ip}/json/")
        if res.status_code == 200:
            data = res.json()
            return {
                'ip': ip,
                'city': data.get('city'),
                'region': data.get('region'),
                'country': data.get('country_name'),
                'latitude': data.get('latitude'),
                'longitude': data.get('longitude'),
            }
    except Exception as e:
        print(f"IP 위치 조회 실패: {e}")
    return {'ip': ip}

def load_all_users():
    return { doc.id: doc.to_dict() for doc in db.collection('users').stream() }

def load_pending():
    return { doc.id: doc.to_dict() for doc in db.collection('pending_codes').stream() }


@app.route('/')
def index():
    return redirect('/login')

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

    if get_user(email):
        return jsonify({'error': '이미 가입된 이메일입니다.'}), 400

    doc_ref = db.collection('pending_codes').document(email)
    if doc_ref.get().exists:
        return jsonify({'error': '이미 인증 중인 이메일입니다.'}), 400

    code = str(random.randint(100000, 999999))
    doc_ref.set({
        'code': code,
        'device_token': device_token,
        'created_at': firestore.SERVER_TIMESTAMP
    })

    print(email, code)

    if not send_verification_email(email, code):
        return jsonify({'error': '이메일 발송에 실패했습니다.'}), 500

    return jsonify({'message': '인증코드를 이메일로 보냈습니다.'})


@app.route('/verify-email', methods=['POST'])
def verify_email():
    data = request.json
    email = data.get('email')
    code = data.get('code')
    password = data.get('password')

    if not all([email, code, password]):
        return jsonify({'status': 'fail', 'message': '모든 항목이 필요합니다.'}), 400

    doc = db.collection('pending_codes').document(email).get()
    if not doc.exists:
        return jsonify({'status': 'fail', 'message': '인증 정보가 없습니다.'}), 400

    pending = doc.to_dict()
    created_at = pending.get('created_at')
    if not created_at or (datetime.datetime.utcnow() - created_at.replace(tzinfo=None)).total_seconds() > 300:
        return jsonify({'status': 'fail', 'message': '인증코드가 만료되었습니다.'}), 400

    if pending['code'] != code:
        return jsonify({'status': 'fail', 'message': '인증코드가 틀립니다.'}), 400

    # 🔐 해시 비밀번호와 평문 비밀번호 둘 다 저장 (주의: 실제 서비스에선 평문 저장 ❌)
    hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    db.collection('pending_codes').document(email).set({
         'code': pending['code'],
         'device_token': pending['device_token'],
         'hashed_pw': hashed_pw,
         'plain_pw': password,  # 🟡 Firebase 사용자 등록용으로만 사용
         'created_at': pending['created_at']
    })

    send_admin_approval_email(email, pending['device_token'])

    return jsonify({'status': 'pending', 'message': '가입 신청 완료. 승인을 기다려 주세요.'})


@app.route('/check-approval', methods=['POST'])
def check_approval():
    data = request.get_json()
    email = data.get('email')

    user = get_user(email)
    if not email or not user:
        return jsonify({'status': 'fail', 'message': '유효하지 않은 이메일입니다.'})

    return jsonify({'status': 'approved' if user.get('approved') else 'pending'})

@app.route('/login', methods=['POST'])
def login_post():
    data = request.json
    email = data.get('email')
    password = data.get('password')  # 추가
    device_token = data.get('device_token')
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    print("최신본 수정사항이 적용됐는지 체크크")

    user = get_user(email)
    log = {'email': email, 'timestamp': datetime.datetime.utcnow().isoformat() + 'Z'}

    if not user:
        log['status'] = 'fail'
        log['reason'] = '사용자 없음'
        login_logs.append(log)
        return jsonify({'status': 'fail', 'message': '사용자 없음'}), 403
    if not user['approved']:
        log['status'] = 'fail'
        log['reason'] = '미승인 사용자'
        login_logs.append(log)
        return jsonify({'status': 'fail', 'message': '미승인 사용자'}), 403
    if device_token not in user['device_tokens']:
        location = get_ip_location(ip)
        send_security_alert(email, location)
        log['status'] = 'fail'
        log['reason'] = '기기 불일치'
        login_logs.append(log)
        return jsonify({'status': 'fail', 'message': '기기 불일치'}), 403
    hashed_pw = user.get('password') or user.get('hashed_pw')
    if not hashed_pw:
        return jsonify({'status': 'fail', 'message': '비밀번호 정보가 없습니다.'}), 500

    if not bcrypt.checkpw(password.encode(), hashed_pw.encode()):
        return jsonify({'status': 'fail', 'message': '비밀번호가 틀렸습니다.'}), 403

    log['status'] = 'success'
    login_logs.append(log)
    return jsonify({'status': 'ok', 'message': '로그인 성공'})

@app.route('/commit', methods=['GET', 'POST'])
def commit_page():
    all_users = load_all_users()
    pending_users = {email: info for email, info in all_users.items() if not info.get('approved')}

    # ✅ 여기 추가: pending_codes 컬렉션 불러오기
    pending_codes = load_pending()

    pending_devices = {
        email: info['pending_device_tokens']
        for email, info in all_users.items()
        if info.get('approved') and info.get('pending_device_tokens')
    }

    return render_template(
        'commit.html',
        pending_users=pending_users,
        pending_devices=pending_devices,
        pending_codes=pending_codes  # 템플릿에서 이 값으로 표시
    )



@app.route('/commit/approve-user', methods=['POST'])
def approve_user():
    data = request.get_json()
    email = data.get('email')

    doc = db.collection('pending_codes').document(email).get()
    if not email or not doc.exists:
        return jsonify({'status': 'fail', 'message': '이메일 오류'}), 400

    info = doc.to_dict()

    # 🔍 비밀번호 유효성 검사
    if 'plain_pw' not in info or not info['plain_pw']:
        print("if 'plain_pw' not in info or not info['plain_pw']: 이거 오류 뜸뜸")
        return jsonify({'status': 'fail', 'message': '비밀번호 정보가 누락되었습니다.'}), 400

    try:
        firebase_auth.create_user(
            email=email,
            password=info['plain_pw']
        )
    except firebase_auth.EmailAlreadyExistsError:
        pass
    except Exception as e:
        return jsonify({'status': 'fail', 'message': f'Firebase 등록 실패: {str(e)}'}), 500

    save_user(email, {
        'password': info['hashed_pw'],
        'device_tokens': [info['device_token']],
        'approved': True
    })

    db.collection('pending_codes').document(email).delete()
    return jsonify({'status': 'ok', 'message': '승인 및 등록 완료'})



@app.route('/commit/reject-user', methods=['POST'])
def reject_user():
    data = request.get_json()
    email = data.get('email')
    user = get_user(email)

    if not email or not user:
        return jsonify({'status': 'fail', 'message': '이메일 오류'}), 400
    if user.get('approved'):
        return jsonify({'status': 'fail', 'message': '이미 승인된 사용자입니다.'}), 400

    # Firestore 문서 삭제
    db.collection('users').document(email).delete()

    return jsonify({'status': 'ok', 'message': '가입 요청 거부됨'})

@app.route('/commit/approve-device', methods=['POST'])
def approve_device():
    data = request.get_json()
    email = data.get('email')
    device_token = data.get('device_token')

    user = get_user(email)
    if not user or device_token not in user.get('pending_device_tokens', []):
        return jsonify({'status': 'fail', 'message': '승인 대상이 올바르지 않습니다.'}), 400

    user['device_tokens'].append(device_token)
    user['pending_device_tokens'].remove(device_token)
    save_user(email, user)  # 🔁 Firestore에 변경 사항 저장

    return jsonify({'status': 'ok', 'message': '기기 등록 승인됨'})


@app.route('/commit/reject-device', methods=['POST'])
def reject_device():
    data = request.get_json()
    email = data.get('email')
    device_token = data.get('device_token')

    user = get_user(email)
    if not user or device_token not in user.get('pending_device_tokens', []):
        return jsonify({'status': 'fail', 'message': '거부 대상이 올바르지 않습니다.'}), 400

    user['pending_device_tokens'].remove(device_token)
    save_user(email, user)  # 🔁 Firestore에 변경 사항 저장

    return jsonify({'status': 'ok', 'message': '기기 등록 거부됨'})


@app.route('/admin')
def admin_page():
    all_users = load_all_users()
    pending_users = {email: info for email, info in all_users.items() if not info.get('approved')}
    return render_template('admin.html', pending_users=pending_users, logs=login_logs)



@app.route('/login', methods=['GET'])
def login_page():
    return render_template('login.html')
    
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

    user_info = get_user(email)
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