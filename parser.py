import os
import re
import base64
import requests
from bs4 import BeautifulSoup

# Список публичных источников (веб-зеркала Telegram-каналов или прямые RAW-ссылки)
CHANNELS = [
    "https://t.me/s/vpn_channel_example", # замените на реальные каналы
]

# Регулярка для захвата стандартных протоколов
PROTOCOL_REGEX = re.compile(r"(?:vless|vmess|trojan|ss|wireguard)://[^\s<>\"']+")

def fetch_keys():
    unique_keys = set()
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
    }

    for url in CHANNELS:
        try:
            resp = requests.get(url, headers=headers, timeout=15)
            if resp.status_code == 200:
                found = PROTOCOL_REGEX.findall(resp.text)
                for key in found:
                    # Очистка от возможных trailing-символов разметки
                    clean_key = key.rstrip(".,;)\"'>")
                    unique_keys.add(clean_key)
        except Exception as e:
            print(f"Ошибка при обработке {url}: {e}")

    return sorted(list(unique_keys))

def export_subscription(keys, output_dir="dist"):
    os.makedirs(output_dir, exist_ok=True)
    
    # 1. Сырой список (каждый ключ с новой строки)
    raw_content = "\n".join(keys)
    with open(f"{output_dir}/raw.txt", "w", encoding="utf-8") as f:
        f.write(raw_content)

    # 2. Base64 подписка (стандарт для v2rayNG, Happ, Nekobox, v2rayN)
    b64_content = base64.b64encode(raw_content.encode("utf-8")).decode("utf-8")
    with open(f"{output_dir}/index.html", "w", encoding="utf-8") as f:
        f.write(b64_content)

    print(f"Готово! Собрано уникальных ключей: {len(keys)}")

if __name__ == "__main__":
    keys = fetch_keys()
    export_subscription(keys)
