import json
import os
import time
from datetime import datetime
import requests
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

VT_API_KEY = os.getenv("VT_API_KEY", "")
ALERT_THRESHOLD = 2
VT_MALICIOUS_THRESHOLD = 3


def check_ip_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            attrs = resp.json()["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})
            return {
                "ip": ip,
                "malicious": stats.get("malicious", 0),
                "country": attrs.get("country", "N/A"),
            }
        if resp.status_code == 429:
            print(f"  Rate-limit VT, пауза 15 с…")
            time.sleep(15)
            return check_ip_virustotal(ip)
        print(f"  VT вернул {resp.status_code} для {ip}")
    except requests.RequestException as e:
        print(f"  Ошибка VT: {e}")
    return None


def main():
    print("Загружаем данные из файла лога Suricata...\n")
    with open("logs/alerts-only.json", "r", encoding="utf-8") as f:
        events = json.load(f)
    print(f"Загружено алертов Suricata: {len(events)}")

    df = pd.json_normalize(events)

    top_ips = df["src_ip"].value_counts()
    top_sigs = df["alert.signature"].value_counts()

    print(f"Уникальных source IP: {df['src_ip'].nunique()}")
    print(f"Уникальных сигнатур:  {df['alert.signature'].nunique()}\n")

    print("Топ source IP:")
    for ip, cnt in top_ips.head(10).items():
        print(f"    {ip:20s}  {cnt}")

    print("Топ сигнатур:")
    for sig, cnt in top_sigs.head(10).items():
        print(f"    {sig[:55]:55s}  {cnt}")

    suspicious_ips = top_ips[top_ips >= ALERT_THRESHOLD].index.tolist()
    print(f"IP-адреса с слишком частыми алертами: {suspicious_ips}")

    print("\nПроверяем подозрительные IP-адреса через VirusTotal...")
    
    vt_results = []
    if VT_API_KEY:
        for ip in suspicious_ips[:5]:
            print(f"    Проверяю {ip}…")
            result = check_ip_virustotal(ip)
            if result:
                vt_results.append(result)
                print(f"      malicious={result['malicious']}, country={result['country']}\n")
    else:
        print("VT_API_KEY не задан — проверка VirusTotal пропущена\n")
    
    print("Заблокируем подозрительные IP-адреса...")
    blocked = []
    notifications = []

    for ip in suspicious_ips:
        msg = f"[BLOCK] IP {ip} заблокирован ({top_ips[ip]} алертов)"
        print(msg)
        blocked.append(ip)
        notifications.append(msg)

    for vt in vt_results:
        if vt["malicious"] >= VT_MALICIOUS_THRESHOLD and vt["ip"] not in blocked:
            msg = f"[BLOCK] IP {vt['ip']} заблокирован (VT: {vt['malicious']} malicious)"
            print(msg)
            blocked.append(vt["ip"])
            notifications.append(msg)

    if notifications:
        print(f"Отправка email:  Заблокировано {len(blocked)} IP-адресов:")
        for n in notifications:
            print(f"  {n}")
    
    print("Формируем отчёт...")

    report = {
        "generated_at": datetime.now().isoformat(),
        "total_alerts": len(df),
        "unique_src_ips": int(df["src_ip"].nunique()),
        "blocked_ips": blocked,
        "virustotal_results": vt_results,
        "notifications": notifications,
        "top_signatures": top_sigs.head(10).to_dict(),
        "top_src_ips": top_ips.head(10).to_dict(),
    }

    with open("output/report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(" JSON-отчёт сохранён: output/report.json\n")

    print("Строим график...")

    sns.set_theme(style="whitegrid")
    fig, axes = plt.subplots(1, 2, figsize=(16, 7))
    fig.suptitle("Отчёт об угрозах: Suricata + VirusTotal", fontsize=14, fontweight="bold")

    top10 = top_ips.head(10)
    sns.barplot(x=top10.values, y=top10.index, hue=top10.index,
                ax=axes[0], palette="Reds_r", legend=False)
    axes[0].set_title("Топ-10 IP по числу алертов")
    axes[0].set_xlabel("Количество")

    cats = df["alert.category"].value_counts()
    sns.barplot(x=cats.values, y=cats.index, hue=cats.index,
                ax=axes[1], palette="Oranges_r", legend=False)
    axes[1].set_title("Категории алертов")
    axes[1].set_xlabel("Количество")

    plt.tight_layout()
    plt.savefig("output/report.png", dpi=150, bbox_inches="tight")
    plt.close()
    print(f" График сохранён: output/report.png")


if __name__ == "__main__":
    main()
