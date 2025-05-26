from flask import Flask, request, jsonify
import csv, time, os
from datetime import datetime

app = Flask(__name__)
LOG_FILE = "login_logs/push_device_login.csv"
USER_FILE = "users.csv"

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
    push_approved = request.form.get("push") == "yes"
    device_id = request.form.get("device_id")
    ip = request.remote_addr
    ua = request.headers.get("User-Agent")
    users = load_users()
    is_bot = "bot" in email.lower()
    success = (
        (email in users)
        and (users[email][0] == password)
        and push_approved
        and device_id == users[email][1]
    )
    duration = int((time.time() - start) * 1000)
    os.makedirs("login_logs", exist_ok=True)
    with open(LOG_FILE, "a", newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.now(), email, success, duration,
            ip, is_bot, ua, True, False, True
        ])
    return jsonify({"result": "success" if success else "fail", "duration(ms)": duration})

if __name__ == "__main__":
    app.run(port=5006)

