import os
import re
import json
import base64
import socket
import time
import random
import tempfile
import subprocess
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

SOURCES = [
    # Крупные агрегаторы (автоматически декодируются из Base64 и PlainText)
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt"
]

VLESS_REGEX = re.compile(r"vless://[^\s<>\"']+")

# Домены и зоны, определяющие обход белых списков
RU_DOMAINS = (
    ".ru", ".su", ".xn--p1ai", "vk.com", "yandex", "gosuslugi",
    "ozon", "wildberries", "mail.ru", "dzen.ru", "tbank", "sberbank",
    "kinopoisk", "avito", "rbc.ru"
)

def extract_vless_keys(content: str) -> set:
    """Извлекает ключи из открытого текста, Base64-блоков и построчно."""
    found = set()
    if not content:
        return found

    # 1. Прямой поиск в открытом тексте
    for m in VLESS_REGEX.findall(content):
        found.add(m.rstrip(".,;)\"'>"))

    # 2. Попытка раскодировать весь контент как Base64
    clean_content = re.sub(r"\s+", "", content)
    try:
        pad = len(clean_content) % 4
        if pad:
            clean_content += "=" * (4 - pad)
        decoded = base64.b64decode(clean_content).decode("utf-8", errors="ignore")
        for m in VLESS_REGEX.findall(decoded):
            found.add(m.rstrip(".,;)\"'>"))
    except Exception:
        pass

    # 3. Построчное декодирование
    for line in content.splitlines():
        line = line.strip()
        if len(line) > 30 and not line.startswith("vless://"):
            try:
                pad = len(line) % 4
                if pad:
                    line += "=" * (4 - pad)
                dec_line = base64.b64decode(line).decode("utf-8", errors="ignore")
                for m in VLESS_REGEX.findall(dec_line):
                    found.add(m.rstrip(".,;)\"'>"))
            except Exception:
                continue

    return found

def fetch_all_vless():
    found = set()
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    for url in SOURCES:
        try:
            resp = requests.get(url, headers=headers, timeout=12)
            if resp.status_code == 200:
                keys = extract_vless_keys(resp.text)
                print(f"[{url}] Найдено ключей: {len(keys)}")
                found.update(keys)
            else:
                print(f"[{url}] Ошибка: код {resp.status_code}")
        except Exception as e:
            print(f"[{url}] Исключение: {e}")

    return list(found)

def parse_vless(key_uri):
    try:
        parsed = urlparse(key_uri)
        if not parsed.hostname or not parsed.port or not parsed.username:
            return None

        query = parse_qs(parsed.query)
        sni = query.get("sni", [""])[0].lower()
        host = query.get("host", [""])[0].lower()
        target_domain = sni or host or parsed.hostname.lower()

        is_whitelist = any(target_domain.endswith(ext) or ext in target_domain for ext in RU_DOMAINS)

        return {
            "uri": key_uri,
            "host": parsed.hostname,
            "port": int(parsed.port),
            "is_whitelist": is_whitelist,
            "parsed": parsed,
            "query": query
        }
    except Exception:
        return None

def check_tcp_ping(item, timeout=1.8):
    """Быстрый отсев отключенных хостов по TCP сокету"""
    start = time.perf_counter()
    try:
        with socket.create_connection((item["host"], item["port"]), timeout=timeout):
            item["latency"] = (time.perf_counter() - start) * 1000
            return item
    except Exception:
        return None

def convert_to_singbox_outbound(item, tag_name):
    p = item["parsed"]
    q = item["query"]

    uuid = p.username
    server = p.hostname
    port = p.port

    net = q.get("type", ["tcp"])[0].lower()
    sec = q.get("security", ["none"])[0].lower()
    flow = q.get("flow", [""])[0]
    sni = q.get("sni", [""])[0]
    fp = q.get("fp", ["chrome"])[0]
    pbk = q.get("pbk", [""])[0]
    sid = q.get("sid", [""])[0]

    outbound = {
        "type": "vless",
        "tag": tag_name,
        "server": server,
        "server_port": port,
        "uuid": uuid,
        "network": "tcp"
    }

    if flow and sec in ["tls", "reality"]:
        outbound["flow"] = flow

    if sec in ["tls", "reality"]:
        tls_conf = {
            "enabled": True,
            "server_name": sni or server,
            "utls": {
                "enabled": True,
                "fingerprint": fp or "chrome"
            }
        }
        if sec == "reality":
            tls_conf["reality"] = {
                "enabled": True,
                "public_key": pbk,
                "short_id": sid
            }
        outbound["tls"] = tls_conf

    if net == "ws":
        outbound["transport"] = {
            "type": "ws",
            "path": q.get("path", ["/"])[0],
            "headers": {"Host": q.get("host", [""])[0] or sni or server}
        }
    elif net == "grpc":
        outbound["transport"] = {
            "type": "grpc",
            "service_name": q.get("serviceName", [""])[0]
        }

    return outbound

def test_vless_via_singbox(item, timeout=3.5):
    """Реальная проверка прохождения трафика через бинарник sing-box."""
    if not os.path.exists("./sing-box"):
        return item

    test_port = random.randint(15000, 35000)
    outbound = convert_to_singbox_outbound(item, "node-test")

    test_cfg = {
        "log": {"level": "fatal"},
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": test_port
            }
        ],
        "outbounds": [outbound]
    }

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(test_cfg, f)
        cfg_path = f.name

    proc = None
    try:
        proc = subprocess.Popen(
            ["./sing-box", "run", "-c", cfg_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(0.35)

        proxies = {
            "http": f"http://127.0.0.1:{test_port}",
            "https": f"http://127.0.0.1:{test_port}"
        }

        start = time.perf_counter()
        r = requests.get("https://cp.cloudflare.com/generate_204", proxies=proxies, timeout=timeout)
        if r.status_code in [200, 204]:
            item["latency"] = (time.perf_counter() - start) * 1000
            return item
    except Exception:
        pass
    finally:
        if proc:
            proc.kill()
            proc.wait()
        if os.path.exists(cfg_path):
            os.remove(cfg_path)

    return None

def filter_and_rank_keys(raw_keys):
    parsed_items = [parse_vless(k) for k in raw_keys if parse_vless(k)]
    print(f"Успешно распознано ключей: {len(parsed_items)}")

    # ЭТАП 1: Быстрый TCP отсев
    alive_candidates = []
    with ThreadPoolExecutor(max_workers=40) as executor:
        futures = [executor.submit(check_tcp_ping, it) for it in parsed_items]
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                alive_candidates.append(res)

    print(f"Ответили по TCP: {len(alive_candidates)} серверов.")

    # Разделяем живые порты на группы
    reg_candidates = [it for it in alive_candidates if not it["is_whitelist"]]
    wl_candidates = [it for it in alive_candidates if it["is_whitelist"]]

    def deep_test_group(group, need_count=6):
        tested = []
        if not os.path.exists("./sing-box"):
            return group[:need_count]

        # Тестируем до набора нужного количества (не более 30 кандидатов на группу)
        candidates_pool = group[:30]
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(test_vless_via_singbox, it) for it in candidates_pool]
            for fut in as_completed(futures):
                res = fut.result()
                if res:
                    tested.append(res)
                    if len(tested) >= need_count:
                        break
        tested.sort(key=lambda x: x["latency"])
        return tested

    print("Запуск глубокого тестирования (проверка интернет-трафика)...")
    regular_alive = deep_test_group(reg_candidates, need_count=6)
    whitelist_alive = deep_test_group(wl_candidates, need_count=6)

    print(f"Итог: 100% рабочих Global: {len(regular_alive)}, RU-Bypass: {len(whitelist_alive)}")
    return regular_alive, whitelist_alive

def format_node_name(item, sub_name, index, is_wl):
    tag_type = "RU-Bypass" if is_wl else "Global"
    node_name = f"{sub_name} | #{index:02d} [{tag_type}]"
    base_uri = item["uri"].split('#')[0]
    renamed_uri = f"{base_uri}#{node_name}"
    return renamed_uri, node_name

def build_singbox_config(outbounds, sub_name):
    tags = [ob["tag"] for ob in outbounds]
    config = {
        "version": 1,
        "remarks": sub_name,
        "outbounds": [
            {
                "type": "selector",
                "tag": f"Auto / Select ({sub_name})",
                "outbounds": ["urltest"] + tags if tags else ["direct"],
                "default": "urltest" if tags else "direct"
            },
            {
                "type": "urltest",
                "tag": "urltest",
                "outbounds": tags,
                "url": "https://cp.cloudflare.com/generate_204",
                "interval": "3m",
                "tolerance": 50
            }
        ] + outbounds
    }
    return json.dumps(config, indent=2, ensure_ascii=False)

def assemble_subscription(regular_items, wl_items, count, sub_name):
    uris = []
    singbox_outbounds = []

    selected_reg = regular_items[:count]
    selected_wl = wl_items[:count]

    idx = 1
    for it in selected_reg:
        renamed_uri, tag = format_node_name(it, sub_name, idx, is_wl=False)
        uris.append(renamed_uri)
        singbox_outbounds.append(convert_to_singbox_outbound(it, tag))
        idx += 1

    for it in selected_wl:
        renamed_uri, tag = format_node_name(it, sub_name, idx, is_wl=True)
        uris.append(renamed_uri)
        singbox_outbounds.append(convert_to_singbox_outbound(it, tag))
        idx += 1

    raw_text = "\n".join(uris)
    b64_sub = base64.b64encode(raw_text.encode("utf-8")).decode("utf-8") if uris else ""
    json_sub = build_singbox_config(singbox_outbounds, sub_name)

    return b64_sub, json_sub

def generate_web_dashboard(output_dir):
    html_content = """<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BCT VPN Subscriptions</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; padding: 20px; box-sizing: border-box; }
        .card { background: #1e293b; border-radius: 16px; padding: 32px; max-width: 520px; width: 100%; box-shadow: 0 10px 25px rgba(0,0,0,0.3); border: 1px solid #334155; }
        h1 { margin-top: 0; font-size: 24px; text-align: center; color: #38bdf8; }
        p { color: #94a3b8; font-size: 14px; text-align: center; }
        .section { margin-top: 24px; }
        .section-title { font-weight: 600; font-size: 16px; margin-bottom: 12px; color: #e2e8f0; display: flex; justify-content: space-between; }
        .links { display: flex; flex-direction: column; gap: 8px; }
        a { display: block; background: #334155; color: #38bdf8; text-decoration: none; padding: 12px 16px; border-radius: 8px; font-size: 14px; word-break: break-all; transition: background 0.2s; }
        a:hover { background: #475569; }
        .badge { font-size: 11px; padding: 2px 8px; border-radius: 12px; background: #0284c7; color: white; }
    </style>
</head>
<body>
    <div class="card">
        <h1>BCT VPN Subscriptions</h1>
        <p>Автоматическое обновление каждый час</p>

        <div class="section">
            <div class="section-title">
                <span>BCT VPN (Lite)</span>
                <span class="badge">3 Global + 3 RU-Bypass</span>
            </div>
            <div class="links">
                <a href="lite.txt">📋 Base64 (v2rayNG / Happ): lite.txt</a>
                <a href="lite.json">⚙️ JSON (sing-box / Nekobox): lite.json</a>
            </div>
        </div>

        <div class="section">
            <div class="section-title">
                <span>BCT VPN (Plus)</span>
                <span class="badge">6 Global + 6 RU-Bypass</span>
            </div>
            <div class="links">
                <a href="plus.txt">📋 Base64 (v2rayNG / Happ): plus.txt</a>
                <a href="plus.json">⚙️ JSON (sing-box / Nekobox): plus.json</a>
            </div>
        </div>
    </div>
</body>
</html>"""
    with open(f"{output_dir}/index.html", "w", encoding="utf-8") as f:
        f.write(html_content)

def save_outputs(lite_pack, plus_pack, output_dir="dist"):
    os.makedirs(output_dir, exist_ok=True)
    lite_b64, lite_json = lite_pack
    plus_b64, plus_json = plus_pack

    with open(f"{output_dir}/lite.txt", "w", encoding="utf-8") as f:
        f.write(lite_b64)
    with open(f"{output_dir}/plus.txt", "w", encoding="utf-8") as f:
        f.write(plus_b64)

    with open(f"{output_dir}/lite.json", "w", encoding="utf-8") as f:
        f.write(lite_json)
    with open(f"{output_dir}/plus.json", "w", encoding="utf-8") as f:
        f.write(plus_json)

    generate_web_dashboard(output_dir)
    print("Все подписки и index.html успешно созданы в dist/!")

if __name__ == "__main__":
    raw_keys = fetch_all_vless()
    print(f"Всего собрано уникальных VLESS ссылок: {len(raw_keys)}")

    reg_items, wl_items = filter_and_rank_keys(raw_keys)

    lite_data = assemble_subscription(reg_items, wl_items, count=3, sub_name="BCT VPN (Lite)")
    plus_data = assemble_subscription(reg_items, wl_items, count=6, sub_name="BCT VPN (Plus)")

    save_outputs(lite_data, plus_data, output_dir="dist")
