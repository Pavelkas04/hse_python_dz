# Запуск: VT_API_KEY=<ваш_ключ> python main.py <путь_к_файлу>
import json
import os
import sys
import time
import requests

API_KEY = os.environ["VT_API_KEY"]
FILE_PATH = sys.argv[1]
HEADERS = {"x-apikey": API_KEY}

with open(FILE_PATH, "rb") as f:
    upload = requests.post(
        "https://www.virustotal.com/api/v3/files",
        headers=HEADERS,
        files={"file": f},
    )

analysis_id = upload.json()["data"]["id"]
time.sleep(15)

result = requests.get(
    f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
    headers=HEADERS,
).json()

output = json.dumps(result, indent=2, ensure_ascii=False)
print(output)

with open("dz13/response.json", "w", encoding="utf-8") as f:
    f.write(output)