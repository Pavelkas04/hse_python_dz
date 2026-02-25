import json
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

with open("botsv1.json", encoding="utf-8") as f:
    raw = json.load(f)

df = pd.json_normalize([e["result"] for e in raw])
df["EventCode"] = df["EventCode"].astype(str)

df_win = df[df["LogName"] == "Security"]
df_dns = df[df["LogName"] == "DNS"]

SUSPICIOUS = {
    "4625": "Неудачный вход",
    "4648": "Вход с явными учётными данными",
    "4656": "Запрос доступа к объекту",
    "4672": "Назначение спец. привилегий",
    "4697": "Установка службы",
    "4698": "Создание запланированной задачи",
    "4703": "Изменение прав токена",
    "4720": "Создание учётной записи",
}

win = df_win[df_win["EventCode"].isin(SUSPICIOUS)].copy()
win["label"] = win["EventCode"].map(lambda c: f"{c} — {SUSPICIOUS[c]}")
win_top = win["label"].value_counts().reset_index(name="count")

SAFE_DOMAINS = {"google.com", "microsoft.com", "windowsupdate.com", "bing.com"}

dns = df_dns[~df_dns["QueryName"].isin(SAFE_DOMAINS)].copy()
dns["label"] = dns["QueryName"]
dns_top = dns["label"].value_counts().reset_index(name="count")

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))

sns.barplot(data=win_top.head(10), y="label", x="count", ax=ax1)
ax1.set_title("Топ-10 подозрительных WinEventLog")
ax1.set_xlabel("Количество")

sns.barplot(data=dns_top.head(10), y="label", x="count", ax=ax2)
ax2.set_title("Топ-10 подозрительных DNS-запросов")
ax2.set_xlabel("Количество")

plt.tight_layout()
plt.savefig("suspicious_events.png", dpi=150, bbox_inches="tight")
print("\nГрафик сохранён: suspicious_events.png")
# plt.show()
