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

df['is_bot'] = df['is_bot'].astype(str).str.lower().isin(['true', '1'])
df['success'] = df['success'].astype(str).str.lower().map({'true': True, 'false': False})

mean_duration = df.groupby('source')['duration'].mean().sort_values()

plt.figure(figsize=(12, 6))
sns.barplot(x=mean_duration.index, y=mean_duration.values, palette='Blues_d')
sns.stripplot(data=df, x='source', y='duration', jitter=True, color='black', alpha=0.3, size=2)
plt.title('Average Response Time per Login Method')
plt.ylabel('Response Time (ms)')
plt.xlabel('Login Method')
plt.xticks(rotation=35, ha='right')
plt.ylim(0, 0.5)
plt.grid(True, axis='y', linestyle='--', alpha=0.4)
plt.tight_layout()
plt.savefig('response_time_comparison.png')
plt.show()

bot_df = df[df['is_bot'] == True]
if not bot_df.empty:
    bot_fail_rate = bot_df.groupby('source')['success'].apply(lambda x: 1 - x.mean())
    plt.figure(figsize=(10, 6))
    bars = plt.bar(bot_fail_rate.index, bot_fail_rate.values, color='tomato')
    plt.title('Bot Block Rate per Login Method')
    plt.ylabel('Block Rate (1 - success)')
    plt.ylim(0.9980, 1.0000)
    plt.xlabel('Login Method')
    plt.xticks(rotation=35, ha='right')
    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2, yval + 0.004, f"{yval:.1%}", ha='center', va='bottom', fontsize=9)
    plt.tight_layout()
    plt.savefig('bot_block_rate.png')
    plt.show()
else:
    print(" No bot data found.")
