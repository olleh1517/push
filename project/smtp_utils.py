import smtplib
from email.mime.text import MIMEText

GMAIL_USER = 'your_email@gmail.com'  
GMAIL_PASSWORD = 'your_app_password'  

def send_verification_email(to_email, code):
    msg = MIMEText(f"인증 코드는 다음과 같습니다:\n\n{code}")
    msg['Subject'] = '회원가입 인증코드'
    msg['From'] = GMAIL_USER
    msg['To'] = to_email

    try:
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(GMAIL_USER, GMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        print(f"[이메일 전송 성공] → {to_email}")
    except Exception as e:
        print(f"[이메일 전송 실패] → {e}")