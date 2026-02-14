import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

with open("events.json", "r", encoding="utf-8") as f:
    data = json.load(f)

df = pd.DataFrame(data["events"])
df["timestamp"] = pd.to_datetime(df["timestamp"])
print(f"Всего событий: {len(df)}")
signature_counts = df["signature"].value_counts()
print(f"\nУникальных типов событий: {df['signature'].nunique()}\n")
print(signature_counts)

plt.figure(figsize=(12, 6))
sns.countplot(data=df, y="signature", hue="signature", order=signature_counts.index,
              palette="Set2", legend=False)
plt.title("Распределение типов событий информационной безопасности")
plt.xlabel("Количество событий")
plt.ylabel("Тип события (signature)")
plt.tight_layout()
plt.savefig("graph.png", dpi=150)
print("\nГрафик сохранён: graph.png")
plt.show()
