import os
import re
import base64
import socket
import time
from urllib.parse import urlparse, parse_qs, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

# Список источников (веб-версии открытых Telegram-каналов или raw-ссылки)
SOURCES = [
    "https://t.me/s/vpn_channel_example",  # Замените на ваши реальные каналы/ссылки
]

VLESS_REGEX = re.compile(r"vless://[^\s<>\"']+")

# Домены и зоны, определяющие обход белых списков
RU_DOMAINS = (
    ".ru", ".su", ".xn--p1ai", "vk.com", "yandex", "gosuslugi",
    "ozon", "wildberries", "mail.ru", "dzen.ru", "tbank", "sberbank"
)

def fetch_all_vless():
    """Сбор всех VLESS ключей из источников"""
    found = set()
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    
    for url in SOURCES:
        try:
            resp = requests.get(url, headers=headers, timeout=12)
            if resp.status_code == 200:
                matches = VLESS_REGEX.findall(resp.text)
                for key in matches:
                    clean = key.rstrip(".,;)\"'>")
                    found.add(clean)
        except Exception as e:
            print(f"Ошибка загрузки источника {url}: {e}")
            
    return list(found)

def parse_vless(key_uri):
    """Разбор параметров VLESS ссылки"""
    try:
        parsed = urlparse(key_uri)
        if not parsed.hostname or not parsed.port:
            return None
        
        query = parse_qs(parsed.query)
        sni = query.get("sni", [""])[0].lower()
        host = query.get("host", [""])[0].lower()
        target_domain = sni or host or parsed.hostname.lower()

        # Проверяем, относится ли ключ к белым спискам
        is_whitelist = any(target_domain.endswith(ext) or ext in target_domain for ext in RU_DOMAINS)
        
        return {
            "uri": key_uri,
            "host": parsed.hostname,
            "port": int(parsed.port),
            "is_whitelist": is_whitelist
        }
    except Exception:
        return None

def check_tcp_ping(item, timeout=2.5):
    """Быстрая проверка доступности сервера по TCP (Health Check)"""
    start = time.perf_counter()
    try:
        with socket.create_connection((item["host"], item["port"]), timeout=timeout):
            latency = (time.perf_counter() - start) * 1000
            item["latency"] = latency
            return item
    except Exception:
        return None

def filter_and_rank_keys(raw_keys):
    """Многопоточный тест работоспособности и сортировка по пингу"""
    parsed_items = [parse_vless(k) for k in raw_keys if parse_vless(k)]
    alive_items = []

    print(f"Тестируем доступность {len(parsed_items)} ключей...")
    # Опрос в 30 параллельных потоков занимает всего 2-5 секунд
    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = [executor.submit(check_tcp_ping, it) for it in parsed_items]
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                alive_items.append(res)

    # Сортируем рабочие ключи по минимальному отклику (пинг)
    alive_items.sort(key=lambda x: x["latency"])

    regular_keys = [it["uri"] for it in alive_items if not it["is_whitelist"]]
    whitelist_keys = [it["uri"] for it in alive_items if it["is_whitelist"]]

    print(f"Рабочих обычных: {len(regular_keys)}, рабочих для белых списков: {len(whitelist_keys)}")
    return regular_keys, whitelist_keys

def make_b64(keys_list):
    """Упаковка в Base64 для клиента подписки"""
    raw = "\n".join(keys_list)
    return base64.b64encode(raw.encode("utf-8")).decode("utf-8")

def build_subscriptions(regular, whitelist, output_dir="dist"):
    os.makedirs(f"{output_dir}/lite", exist_ok=True)
    os.makedirs(f"{output_dir}/plus", exist_ok=True)

    # Набор Lite: 3 обычных + 3 белых
    lite_keys = regular[:3] + whitelist[:3]
    lite_b64 = make_b64(lite_keys)

    # Набор Plus: 6 обычных + 6 белых
    plus_keys = regular[:6] + whitelist[:6]
    plus_b64 = make_b64(plus_keys)

    # Запись файлов (в форматах text/base64 и direct HTML для страниц)
    # Lite
    with open(f"{output_dir}/lite.txt", "w", encoding="utf-8") as f:
        f.write(lite_b64)
    with open(f"{output_dir}/lite/index.html", "w", encoding="utf-8") as f:
        f.write(lite_b64)

    # Plus
    with open(f"{output_dir}/plus.txt", "w", encoding="utf-8") as f:
        f.write(plus_b64)
    with open(f"{output_dir}/plus/index.html", "w", encoding="utf-8") as f:
        f.write(plus_b64)

    print("Подписки успешно сгенерированы!")

if __name__ == "__main__":
    raw_keys = fetch_all_vless()
    print(f"Всего спаршено VLESS ссылок: {len(raw_keys)}")
    reg, wl = filter_and_rank_keys(raw_keys)
    build_subscriptions(reg, wl)
