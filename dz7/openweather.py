import requests
import os
from dotenv import load_dotenv

def main():
    load_dotenv()
    api_key = os.getenv("API_KEY")
    if not api_key:
        raise ValueError("API_KEY не установлен!")

    api_url = "https://api.openweathermap.org/data/2.5/weather"

    town = input("Введите название города: ").strip()
    if not town:
        print("Город не должен быть пустым.")
        return

    params = {
        "q": town,
        "appid": api_key,
        "units": "metric",
        "lang": "ru",
    }

    res = requests.get(api_url, params=params)
    if not res.ok:
        print("Ошибка:", res.status_code, "–", res.text)
        return

    try:
        data = res.json()
    except ValueError as e:
        print(f"Ответ не является валидным JSON: {e}")
        print("Фрагмент ответа:", res.text[:200])
        return

    print(f'Погода в {data.get("name", town)}: {data["main"]["temp"]:.1f}°C, {data["weather"][0]["description"]}')

if __name__ == "__main__":
    main()