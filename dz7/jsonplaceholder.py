import requests

def main():
    url = "https://jsonplaceholder.typicode.com/posts"
    res = requests.get(url)
    if not res.ok:
        print("Ошибка:", res.status_code)
        return

    try:
        posts = res.json()[:5]
    except ValueError as e:
        print(f"Ответ не является валидным JSON: {e}")
        print("Фрагмент ответа:", res.text[:200])
        return

    for i, post in enumerate(posts, start=1):
        print(f"--- Пост #{i} ---")
        print(f'Заголовок: {post.get("title", "")}')
        print("Тело:")
        print(post.get("body", ""))
        print()

if __name__ == "__main__":
    main()