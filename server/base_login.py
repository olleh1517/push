from flask import Flask, request, jsonify
import csv, time, os
from datetime import datetime

app = Flask(__name__)
PORT = 5001
LOG_FILE = "login_logs/base.csv"
USER_FILE = "users.csv"

REQUIRE_PUSH = False
REQUIRE_OTP = False
REQUIRE_DEVICE = False

def load_users():
    users = {}
    with open(USER_FILE, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            users[row["email"]] = (row["password"], row["device_id"])
    return users

@app.route("/login", methods=["POST"])
def login():
    start = time.time()
    email = request.form.get("email")
    password = request.form.get("password")
    otp = request.form.get("otp")
    push = request.form.get("push")
    device_id = request.form.get("device_id")
    ip = request.remote_addr
    ua = request.headers.get("User-Agent")

    users = load_users()
    is_bot = "bot" in email.lower()

    success = (
        email in users and
        users[email][0] == password and
        (not REQUIRE_OTP or otp == "123456") and
        (not REQUIRE_PUSH or push == "yes") and
        (not REQUIRE_DEVICE or device_id == users[email][1])
    )

    duration = int((time.time() - start) * 1000)
    os.makedirs("login_logs", exist_ok=True)
    with open(LOG_FILE, "a", newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.now(), email, success, duration,
            ip, is_bot, ua,
            REQUIRE_PUSH, REQUIRE_OTP, REQUIRE_DEVICE
        ])
    return jsonify({"result": "success" if success else "fail", "duration(ms)": duration})

if __name__ == "__main__":
    app.run(port=PORT)
