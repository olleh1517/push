from flask import Flask, request, jsonify
import csv, time, os
from datetime import datetime

app = Flask(__name__)
LOG_FILE = "login_logs/device_login.csv"
USER_FILE = "users.csv"

EXPECTED_OTP = "123456"
EXPECTED_PUSH = "yes"
EXPECTED_DEVICE = "mydevice"

def load_users():
    users = {}
    with open(USER_FILE, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            users[row["email"]] = (row["password"], row.get("device_id", ""))
    return users

@app.route("/login", methods=["POST"])
def login():
    start = time.time()
    email = request.form.get("email")
    password = request.form.get("password")
    otp = request.form.get("otp")
    push = request.form.get("push")
    device = request.form.get("device_id")
    ip = request.remote_addr
    ua = request.headers.get("User-Agent")

    users = load_users()
    is_bot = "bot" in email.lower()
    success = (
        email in users and
        users[email][0] == password and
        device == EXPECTED_DEVICE
    )
    duration = int((time.time() - start) * 1000)

    os.makedirs("login_logs", exist_ok=True)
    with open(LOG_FILE, "a", newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.now(), email, success, duration,
            ip, is_bot, ua, False, False, True
        ])

    return jsonify({"result": "success" if success else "fail", "duration(ms)": duration})

if __name__ == "__main__":
    app.run(port=5004)
