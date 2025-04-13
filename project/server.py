from flask import Flask, request, jsonify, render_template, redirect
from flask_socketio import SocketIO, emit
import firebase_admin
from firebase_admin import credentials, auth as firebase_auth
from smtp_utils import send_verification_email
import uuid, time, random
import os

if __name__ == '__main__':
    socketio.run(app, debug=False, host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))
    
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)

cred = credentials.Certificate("firebase-adminsdk.json")
firebase_admin.initialize_app(cred)

login_requests = {}   # Push 인증 요청 저장
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
    email = data['email']
    code = data['code']
    if pending_codes.get(email) == code:
        return jsonify({'status': 'ok'})
    return jsonify({'status': 'fail'})

@app.route('/request-login', methods=['POST'])
def request_login():
    token = request.json.get('token')
    try:
        decoded = firebase_auth.verify_id_token(token)
        email = decoded['email']
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
    data = request.json
    request_id = data['request_id']
    status = data['status']
    if request_id in login_requests:
        login_requests[request_id]['status'] = status
        return jsonify({'result': 'ok'})
    return jsonify({'result': 'fail'}), 400

@app.route('/check-status/<request_id>')
def check_status(request_id):
    req = login_requests.get(request_id, {})
    return jsonify({'status': req.get('status', 'unknown')})

if __name__ == '__main__':
    socketio.run(app, debug=True)


# smtp_utils.py
import smtplib
from email.mime.text import MIMEText

GMAIL_USER = 'your_email@gmail.com'
GMAIL_PASSWORD = 'your_app_password'

def send_verification_email(to_email, code):
    msg = MIMEText(f"인증코드는 다음과 같습니다:\n\n{code}")
    msg['Subject'] = '회원가입 인증코드'
    msg['From'] = GMAIL_USER
    msg['To'] = to_email

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
        server.login(GMAIL_USER, GMAIL_PASSWORD)
        server.send_message(msg)