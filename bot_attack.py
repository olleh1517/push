import requests, time, random, argparse

otp_range = range(100000, 100010)
device_ids = ["mydevice", "deviceX", "guessed1", "guessed2"]

def simulate_realistic_attack(url, use_otp=False, use_push=False, use_device=False, count=100):
    for i in range(count):
        payload = {
            "email": f"bot{i}@example.com",
            "password": f"wrongpass{i}",
        }

        if use_otp:
            payload["otp"] = f"{random.choice(otp_range):06d}"
        if use_push:
            payload["push"] = random.choice(["yes", "no"])
        if use_device:
            payload["device_id"] = random.choice(device_ids)

        try:
            res = requests.post(url, data=payload)
            json = res.json()
            print(f"[{i}] {res.status_code} | {json}")
            if json.get("result") == "success":
                print(" 공격 성공!", payload)
        except Exception as e:
            print(f"[{i}] 오류 발생: {e}")
        time.sleep(0.01)  # 빠르게 처리

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--use_otp", action="store_true")
    parser.add_argument("--use_push", action="store_true")
    parser.add_argument("--use_device", action="store_true")
    parser.add_argument("--count", type=int, default=100)
    args = parser.parse_args()

    simulate_realistic_attack(
        url=args.url,
        use_otp=args.use_otp,
        use_push=args.use_push,
        use_device=args.use_device,
        count=args.count
    )
