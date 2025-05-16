import smtplib
from email.mime.text import MIMEText
import os

GMAIL_USER = os.environ.get("GMAIL_USER")
GMAIL_PASSWORD = os.environ.get("GMAIL_PASSWORD")

def send_verification_email(to_email, code):
    msg = MIMEText(f"인증코드는 다음과 같습니다:\n\n{code}")
    msg['Subject'] = '회원가입 인증코드'
    msg['From'] = GMAIL_USER
    msg['To'] = to_email

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
        server.login(GMAIL_USER, GMAIL_PASSWORD)
        server.send_message(msg)
# 변경테스트트