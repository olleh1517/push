import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os

def load_logs(folder='login_logs/'):
    all_logs = []
    for file in os.listdir(folder):
        if not file.endswith('.csv'):
            continue
        df = pd.read_csv(os.path.join(folder, file), header=None)
        df.columns = [
            'timestamp', 'email', 'success', 'duration',
            'ip', 'is_bot', 'ua', 'push', 'otp', 'device'
        ]
        df['source'] = file.replace('.csv', '')
        all_logs.append(df)
    return pd.concat(all_logs)

df = load_logs()

print(" 불러온 로그 수:", len(df))
print(df.head())

#  응답 시간 시각화 (Y축 좁힘)
mean_duration = df.groupby('source')['duration'].mean().sort_values()
plt.figure(figsize=(12, 6))
sns.barplot(x=mean_duration.index, y=mean_duration.values, palette='Blues_d')
sns.stripplot(data=df, x='source', y='duration', jitter=True, color='black', alpha=0.4, size=3)
plt.title('Average Response Time per Login Method (ms)', fontsize=14)
plt.xlabel('Login Method', fontsize=12)
plt.ylabel('Response Time (ms)', fontsize=10)
plt.xticks(rotation=35, ha='right', fontsize=10)

#  평균 값 기준으로 Y축 확대
y_min = mean_duration.min() * 0.97
y_max = mean_duration.max() * 1.02
plt.ylim(y_min, y_max)

plt.grid(True, axis='y', linestyle='--', alpha=0.5)
plt.tight_layout()
plt.savefig('response_time_comparison.png')
plt.show()

df['is_bot'] = df['is_bot'].astype(str).str.lower() == 'true'
bot_df = df[df['is_bot'] == True]

if bot_df.empty:
    print(" No bot data found.")
else:
    bot_fail_rate = bot_df.groupby('source')['success'].apply(lambda x: 1 - x.mean())

    plt.figure(figsize=(10, 6))
    bars = plt.bar(bot_fail_rate.index, bot_fail_rate.values, color='tomato')
    plt.title('Bot Block Rate per Login Method', fontsize=14)
    plt.ylabel('Block Rate (1 - success)', fontsize=12)
    plt.xlabel('Login Method')
    plt.xticks(rotation=35, ha='right')

    #  최소값과 최대값 계산
    min_val = bot_fail_rate.min()
    max_val = bot_fail_rate.max()

    #  차이를 강조하되 음수 방지
    lower = max(min_val - 0.0003, 0.998)     # 최소 0.998로 고정
    upper = min(max_val + 0.0003, 1.0005)    # 최대 1.0005로 제한
    plt.ylim(lower, upper)

    #  막대 위에 차단율 표시
    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2, yval + 0.00005, f"{yval:.3%}", ha='center', va='bottom', fontsize=9)

    plt.grid(True, axis='y', linestyle='--', alpha=0.4)
    plt.tight_layout()
    plt.savefig('bot_block_rate.png')
    plt.show()