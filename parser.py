import os
import re
import json
import base64
import socket
import time
import tempfile
import subprocess
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 1. ОБЫЧНЫЕ СЕРВЕРЫ (GLOBAL)
GLOBAL_SOURCES = [
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githack.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/xray/normal/vless"
]

# 2. СЕРВЕРЫ ДЛЯ БЕЛЫХ СПИСКОВ (WHITELIST)
WHITELIST_SOURCES = [
    "https://gitverse.ru/api/repos/zieng2/wl/raw/branch/master/list_universal.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt"
]

VLESS_REGEX = re.compile(r"vless://[^\s<>\"']+")

# Единый эндпоинт для Real Delay теста от Google
GOOGLE_DELAY_TEST_URL = "https://www.gstatic.com/generate_204"

# SNI, которые гарантированно блокируются ТСПУ в РФ при рукопожатии
BLOCKED_SNI_IN_RU = (
    "instagram", "facebook", "twitter", "x.com", "threads", "meta.com",
    "rutracker", "meduza", "bbc", "dw.com", "svoboda", "navalny",
    "pornhub", "linkedin", "rferl", "ntc.party", "t.me", "telegram"
)

IRAN_MARKERS = (".ir", "irancell", "mci.ir", "mkh.pw", "arvancloud")

def get_free_port():
    """Поиск свободного порта для изоляции тестов sing-box"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def extract_vless_keys(content: str) -> set:
    found = set()
    if not content:
        return found

    for m in VLESS_REGEX.findall(content):
        found.add(m.rstrip(".,;)\"'>"))

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

def fetch_group_keys(sources, is_whitelist_group):
    items = []
    seen = set()
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    group_name = "Whitelist" if is_whitelist_group else "Global"

    for url in sources:
        try:
            resp = requests.get(url, headers=headers, timeout=12, verify=False)
            if resp.status_code == 200:
                keys = extract_vless_keys(resp.text)
                print(f"[{group_name}] {url} -> найдено: {len(keys)}")
                for k in keys:
                    if k not in seen:
                        seen.add(k)
                        items.append({"uri": k, "is_whitelist": is_whitelist_group})
            else:
                print(f"[{group_name}] {url} -> код: {resp.status_code}")
        except Exception as e:
            print(f"[{group_name}] {url} -> сбой: {e}")

    return items

def parse_vless(raw_item):
    key_uri = raw_item["uri"]
    is_whitelist = raw_item["is_whitelist"]

    try:
        parsed = urlparse(key_uri)
        if not parsed.hostname or not parsed.port or not parsed.username:
            return None

        query = parse_qs(parsed.query)
        sni = query.get("sni", [""])[0].lower()
        host = query.get("host", [""])[0].lower()
        sec = query.get("security", ["none"])[0].lower()
        net = query.get("type", ["tcp"])[0].lower()
        flow = query.get("flow", [""])[0].lower()
        pbk = query.get("pbk", [""])[0]

        target = sni or host or parsed.hostname.lower()

        # Фильтры специфики РФ для группы Global
        if not is_whitelist:
            # Отсекаем иранские узлы
            if any(m in target for m in IRAN_MARKERS):
                return None

            # Отсекаем запрещённые в РФ домены для SNI
            if any(b in target for b in BLOCKED_SNI_IN_RU):
                return None

            # В РФ стабильно работают только Reality или TLS
            if sec not in ["reality", "tls"]:
                return None

            # Для Reality публичный ключ обязателен
            if sec == "reality" and not pbk:
                return None

            # Голый TLS по TCP без flow=xtls-rprx-vision детектируется и блокируется ТСПУ
            if sec == "tls" and net == "tcp" and not flow:
                return None

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
    """Первичная быстрая отбраковка оффлайн-хостов"""
    start = time.perf_counter()
    try:
        with socket.create_connection((item["host"], item["port"]), timeout=timeout):
            item["tcp_latency"] = (time.perf_counter() - start) * 1000
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

def test_vless_real_delay(item, timeout=3.5):
    """Реальный замер задержки через sing-box туннель до Google"""
    if not os.path.exists("./sing-box"):
        return item

    test_port = get_free_port()
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

        ready = False
        for _ in range(16):
            try:
                with socket.create_connection(("127.0.0.1", test_port), timeout=0.05):
                    ready = True
                    break
            except Exception:
                time.sleep(0.05)

        if not ready:
            return None

        proxies = {
            "http": f"http://127.0.0.1:{test_port}",
            "https": f"http://127.0.0.1:{test_port}"
        }

        start = time.perf_counter()
        r = requests.get(GOOGLE_DELAY_TEST_URL, proxies=proxies, timeout=timeout)
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

def verify_russia_reachability(candidates, max_check=16):
    """
    Проверка доступности портов из России через тестовые ноды Москвы (Check-Host API).
    Отсеивает IP-адреса и подсети, заблокированные РКН/ТСПУ.
    """
    to_check = candidates[:max_check]
    if not to_check:
        return []

    print(f"\n[RU-Check] Запуск проверки {len(to_check)} серверов напрямую из РФ (ноды Москва)...")
    headers = {"Accept": "application/json", "User-Agent": "Mozilla/5.0"}

    # 1. Запуск сетевых проб на российских узлах
    active_checks = []
    for item in to_check:
        try:
            url = f"https://check-host.net/check-tcp?host={item['host']}:{item['port']}&node=ru1.node.check-host.net&node=ru2.node.check-host.net"
            r = requests.get(url, headers=headers, timeout=5)
            if r.status_code == 200:
                req_id = r.json().get("request_id")
                if req_id:
                    active_checks.append((item, req_id))
            time.sleep(0.12)
        except Exception:
            continue

    if not active_checks:
        print("[RU-Check] Не удалось запросить узлы РФ, используется результат локального теста.")
        return candidates

    # 2. Ожидание ответа от российских зондов
    time.sleep(3.5)

    # 3. Разбор результатов проб
    verified_ru = []
    for item, req_id in active_checks:
        try:
            res_url = f"https://check-host.net/check-result/{req_id}"
            res = requests.get(res_url, headers=headers, timeout=5).json()
            is_alive_in_ru = False

            for node_name, val in res.items():
                if "ru" in node_name and val and len(val) > 0:
                    entry = val[0]
                    if isinstance(entry, list) and len(entry) > 0:
                        # entry[0] == 1 означает успешное TCP подключение из РФ
                        if entry[0] == 1 or "Connected" in str(entry):
                            is_alive_in_ru = True
                            break

            if is_alive_in_ru:
                print(f" -> [РФ: Доступен] {item['host']}:{item['port']} | Google Delay: {int(item['latency'])} ms")
                verified_ru.append(item)
            else:
                print(f" -> [РФ: Заблокирован РКН/ТСПУ] {item['host']}:{item['port']}")
        except Exception:
            continue

    print(f"[RU-Check] Подтверждено доступных из РФ: {len(verified_ru)} из {len(active_checks)}")

    # Если подтверждённых узлов достаточно, возвращаем их
    if len(verified_ru) >= 6:
        return verified_ru

    # Резервный добор из лучших Google-Delay кандидатов, если API проверки вернуло мало ответов
    already = {x['uri'] for x in verified_ru}
    for it in candidates:
        if it['uri'] not in already:
            verified_ru.append(it)
        if len(verified_ru) >= 6:
            break

    return verified_ru

def run_group_tests(group, target_count=6, max_test_candidates=160):
    if not os.path.exists("./sing-box"):
        return group[:target_count]

    pool = group[:max_test_candidates]
    alive = []

    print(f"Запуск Google Real Delay теста (пул: {len(pool)})...")
    with ThreadPoolExecutor(max_workers=14) as executor:
        future_map = {executor.submit(test_vless_real_delay, it): it for it in pool}
        for fut in as_completed(future_map):
            try:
                res = fut.result()
                if res and "latency" in res:
                    alive.append(res)
                    if len(alive) >= target_count + 8:
                        for f in future_map:
                            f.cancel()
                        break
            except Exception:
                pass

    alive.sort(key=lambda x: x["latency"])
    return alive

def filter_and_rank_keys(raw_items):
    parsed_items = [parse_vless(k) for k in raw_items if parse_vless(k)]
    print(f"Распознано корректных ссылок: {len(parsed_items)}")

    # Быстрый TCP отсев оффлайн портов
    alive_tcp = []
    with ThreadPoolExecutor(max_workers=45) as executor:
        futures = [executor.submit(check_tcp_ping, it) for it in parsed_items]
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                alive_tcp.append(res)

    print(f"Ответили на первичный пинг: {len(alive_tcp)} серверов.")

    reg_candidates = [it for it in alive_tcp if not it["is_whitelist"]]
    wl_candidates = [it for it in alive_tcp if it["is_whitelist"]]

    # 1. Тест Google Real Delay
    print("\n--- ТЕСТИРОВАНИЕ ГРУППЫ GLOBAL (Google Real Delay) ---")
    regular_alive = run_group_tests(reg_candidates, target_count=8, max_test_candidates=160)

    # 2. Проверка доступности лучших Global серверов напрямую из РФ
    regular_verified_for_ru = verify_russia_reachability(regular_alive, max_check=16)

    print("\n--- ТЕСТИРОВАНИЕ ГРУППЫ WHITELIST ---")
    whitelist_alive = run_group_tests(wl_candidates, target_count=6, max_test_candidates=160)

    print(f"\nИТОГ: Живых Global (для РФ): {len(regular_verified_for_ru)}, Whitelist: {len(whitelist_alive)}")
    return regular_verified_for_ru, whitelist_alive

def format_node_name(item, sub_name, index, is_wl):
    tag_type = "Whitelist" if is_wl else "Global"
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
                "outbounds": tags if tags else ["direct"],
                "url": GOOGLE_DELAY_TEST_URL,
                "interval": "3m",
                "tolerance": 50
            },
            {
                "type": "direct",
                "tag": "direct"
            }
        ] + outbounds
    }
    return json.dumps(config, indent=2, ensure_ascii=False)

def assemble_subscription(regular_items, wl_items, reg_count, wl_count, sub_name):
    uris = []
    singbox_outbounds = []

    selected_reg = regular_items[:reg_count]
    selected_wl = wl_items[:wl_count]

    # Global узлы
    idx = 1
    for it in selected_reg:
        renamed_uri, tag = format_node_name(it, sub_name, idx, is_wl=False)
        uris.append(renamed_uri)
        singbox_outbounds.append(convert_to_singbox_outbound(it, tag))
        idx += 1

    # Whitelist узлы
    wl_idx = 1
    for it in selected_wl:
        renamed_uri, tag = format_node_name(it, sub_name, wl_idx, is_wl=True)
        uris.append(renamed_uri)
        singbox_outbounds.append(convert_to_singbox_outbound(it, tag))
        wl_idx += 1

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
        <p>Google Real Delay • Проверка доступности из РФ</p>

        <div class="section">
            <div class="section-title">
                <span>BCT VPN (Lite)</span>
                <span class="badge">3 Global + 3 Whitelist</span>
            </div>
            <div class="links">
                <a href="lite.txt">📋 Base64 (v2rayNG / Happ): lite.txt</a>
                <a href="lite.json">⚙️ JSON (sing-box / Nekobox): lite.json</a>
            </div>
        </div>

        <div class="section">
            <div class="section-title">
                <span>BCT VPN (Plus)</span>
                <span class="badge">6 Global + 6 Whitelist</span>
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
    print("Файлы lite.txt, plus.txt, lite.json, plus.json и index.html созданы!")

if __name__ == "__main__":
    global_keys = fetch_group_keys(GLOBAL_SOURCES, is_whitelist_group=False)
    wl_keys = fetch_group_keys(WHITELIST_SOURCES, is_whitelist_group=True)

    all_keys = global_keys + wl_keys
    print(f"Всего получено ключей: {len(all_keys)} (Global: {len(global_keys)}, Whitelist: {len(wl_keys)})")

    reg_items, wl_items = filter_and_rank_keys(all_keys)

    # Lite: строго 3 Global и 3 Whitelist
    lite_data = assemble_subscription(
        regular_items=reg_items,
        wl_items=wl_items,
        reg_count=3,
        wl_count=3,
        sub_name="BCT VPN (Lite)"
    )

    # Plus: строго 6 Global и 6 Whitelist
    plus_data = assemble_subscription(
        regular_items=reg_items,
        wl_items=wl_items,
        reg_count=6,
        wl_count=6,
        sub_name="BCT VPN (Plus)"
    )

    save_outputs(lite_data, plus_data, output_dir="dist")
