import multiprocessing
import subprocess
import time
import os

ATTACK_COUNT = 100000

servers = [
    {"script": "base_login.py", "port": 5001, "options": ""},
    {"script": "push_login.py", "port": 5002, "options": "--use_push"},
    {"script": "otp_login.py", "port": 5003, "options": "--use_otp"},
    {"script": "device_login.py", "port": 5004, "options": "--use_device"},
    {"script": "push_otp_login.py", "port": 5005, "options": "--use_push --use_otp"},
    {"script": "push_device_login.py", "port": 5006, "options": "--use_push --use_device"},
    {"script": "otp_device_login.py", "port": 5007, "options": "--use_otp --use_device"},
    {"script": "push_otp_device_login.py", "port": 5008, "options": "--use_push --use_otp --use_device"},
]

def start_server(server):
    return subprocess.Popen(["python", f"server/{server['script']}"])

def run_attack(server):
    url = f"http://127.0.0.1:{server['port']}/login"
    print(f"  봇 공격 시작: {url} {server['options']}")
    command = f"python bot_attack.py --url {url} {server['options']} --count {ATTACK_COUNT}"
    os.system(command)

if __name__ == "__main__":
    print(" 서버 실행 중...")
    server_processes = [start_server(s) for s in servers]
    time.sleep(3)  # 서버 준비 시간 충분히 확보

    print(" 봇 병렬 공격 시작...")
    with multiprocessing.Pool(processes=len(servers)) as pool:
        pool.map(run_attack, servers)

    print("\n 모든 실험 완료! 이제 analyze_result.py 로 분석을 시작하세요.")