import requests
import time
import argparse
import csv

def load_mfa_bots(file="users.csv"):
    mfa_bots = {}
    with open(file, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            email = row["email"]
            mfa_bots[email] = {
                "password": row["password"],
                "device_id": row.get("device_id", ""),
                "push": row.get("push", ""),
                "otp": row.get("otp", "")
            }
    return mfa_bots

def simulate_attack(url, count=100, use_otp=False, use_push=False, use_device=False):
    mfa_bots = load_mfa_bots()
    for i in range(count):
        email = f"bot{i}@example.com"
        bot = mfa_bots.get(email)

        if bot:
            payload = {
                "email": email,
                "password": bot["password"]
            }
            if use_otp:
                payload["otp"] = bot.get("otp", "000000")
            if use_push:
                payload["push"] = bot.get("push", "no")
            if use_device:
                payload["device_id"] = bot.get("device_id", "bad_device")
        else:
            payload = {
                "email": email,
                "password": f"wrongpass{i}"
            }
            if use_otp:
                payload["otp"] = "000000"
            if use_push:
                payload["push"] = "no"
            if use_device:
                payload["device_id"] = "bad_device"

        try:
            res = requests.post(url, data=payload)
            print(f"[{i}] {res.status_code} | {res.json()}")
        except Exception as e:
            print(f"[{i}] 오류 발생: {e}")
        time.sleep(0.01)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--use_otp", action="store_true")
    parser.add_argument("--use_push", action="store_true")
    parser.add_argument("--use_device", action="store_true")
    args = parser.parse_args()

    simulate_attack(
        url=args.url,
        count=args.count,
        use_otp=args.use_otp,
        use_push=args.use_push,
        use_device=args.use_device
    )

