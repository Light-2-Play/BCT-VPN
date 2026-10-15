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
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/xray/normal/vless",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/vless"
]

# 2. СЕРВЕРЫ ДЛЯ БЕЛЫХ СПИСКОВ (WHITELIST)
WHITELIST_SOURCES = [
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt",
    "https://gitlab.com/zieng2/wl/raw/main/vless_universal.txt",
    "https://codeberg.org/zieng2/wl/raw/branch/main/vless_universal.txt",
    "https://gitverse.ru/api/repos/zieng2/wl/raw/branch/master/list_universal.txt"
]

VLESS_REGEX = re.compile(r"vless://[^\s<>\"']+")

# Официальный контрольный эндпоинт Google
GOOGLE_DELAY_TEST_URL = "https://www.gstatic.com/generate_204"

# Заблокированные в РФ домены для SNI
BLOCKED_SNI_IN_RU = (
    "instagram", "facebook", "twitter", "x.com", "threads", "meta.com",
    "rutracker", "meduza", "bbc", "dw.com", "svoboda", "navalny",
    "pornhub", "linkedin", "rferl", "ntc.party", "t.me", "telegram"
)

IRAN_MARKERS = (".ir", "irancell", "mci.ir", "mkh.pw", "arvancloud")

def get_free_port():
    """Выделение изолированного порта для каждого процесса sing-box"""
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
                print(f"[{group_name}] {url} -> получено: {len(keys)}")
                for k in keys:
                    if k not in seen:
                        seen.add(k)
                        items.append({"uri": k, "is_whitelist": is_whitelist_group})
            else:
                print(f"[{group_name}] {url} -> статус: {resp.status_code}")
        except Exception as e:
            print(f"[{group_name}] {url} -> ошибка: {e}")

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

        # Фильтры под требования РФ для Global
        if not is_whitelist:
            if any(m in target for m in IRAN_MARKERS):
                return None
            if any(b in target for b in BLOCKED_SNI_IN_RU):
                return None
            if sec not in ["reality", "tls"]:
                return None
            if sec == "reality" and not pbk:
                return None
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

def quick_socket_check(item, timeout=1.5):
    """Предварительный отсев выключенных хостов, чтобы не тратить время теста sing-box"""
    try:
        with socket.create_connection((item["host"], item["port"]), timeout=timeout):
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

    # Flow xtls-rprx-vision допустим ТОЛЬКО для tcp. Для ws/grpc он ломает sing-box
    if flow and sec in ["tls", "reality"] and net in ["tcp", ""]:
        outbound["flow"] = flow

    if sec in ["tls", "reality"]:
        tls_conf = {
            "enabled": True,
            "server_name": sni or server,
            "insecure": True,  # Обязательно для Whitelist (обход проверки чужого SNI)
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

def test_vless_live_google(item, timeout=4.0):
    """
    «ЖИВОЙ ТЕСТ»: Поднимает реальный sing-box туннель и совершает HTTP GET к Google.
    Сервер считается живым ТОЛЬКО если Google вернул код 204 или 200.
    """
    if not os.path.exists("./sing-box"):
        return None

    test_port = get_free_port()
    outbound = convert_to_singbox_outbound(item, "node-live-test")

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

        # Ожидание готовности локального порта
        ready = False
        for _ in range(20):
            try:
                with socket.create_connection(("127.0.0.1", test_port), timeout=0.04):
                    ready = True
                    break
            except Exception:
                time.sleep(0.04)

        if not ready:
            return None

        proxies = {
            "http": f"http://127.0.0.1:{test_port}",
            "https": f"http://127.0.0.1:{test_port}"
        }

        # Отправляем реальный пакет через поднятый туннель
        start = time.perf_counter()
        r = requests.get(GOOGLE_DELAY_TEST_URL, proxies=proxies, timeout=timeout, allow_redirects=False)
        
        if r.status_code in [200, 204]:
            real_delay = (time.perf_counter() - start) * 1000
            item["latency"] = real_delay
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

def run_pure_live_test_pool(group, target_count=6, max_candidates=180):
    """
    Проверяет собранную базу ТОЛЬКО живым тестом.
    Никаких доборов по TCP: если сервер не пропустил трафик Google, он отбрасывается.
    """
    if not os.path.exists("./sing-box"):
        print("sing-box не найден в системе!")
        return []

    pool = group[:max_candidates]
    live_verified = []

    print(f"Запуск живого теста Google (пул: {len(pool)} кандидатов, цель: {target_count})...")
    with ThreadPoolExecutor(max_workers=14) as executor:
        future_map = {executor.submit(test_vless_live_google, it): it for it in pool}
        for fut in as_completed(future_map):
            try:
                res = fut.result()
                if res and "latency" in res:
                    live_verified.append(res)
                    print(f" -> [ЖИВОЙ КЛЮЧ] {res['host']}:{res['port']} | Google Delay: {int(res['latency'])} ms")
                    # Останавливаем опрос при наборе достаточного запаса лучших серверов
                    if len(live_verified) >= target_count + 4:
                        for f in future_map:
                            f.cancel()
                        break
            except Exception:
                pass

    # Сортируем строго по реальному времени отклика от Google
    live_verified.sort(key=lambda x: x["latency"])
    return live_verified

def filter_and_rank_keys(raw_items):
    parsed_items = [parse_vless(k) for k in raw_items if parse_vless(k)]
    print(f"Всего синтаксически корректных ключей: {len(parsed_items)}")

    # Быстрый сокет-фильтр (отсеивает заведомо выключенные порты)
    alive_socket = []
    with ThreadPoolExecutor(max_workers=45) as executor:
        futures = [executor.submit(quick_socket_check, it) for it in parsed_items]
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                alive_socket.append(res)

    print(f"Ответили на сокет: {len(alive_socket)} серверов.")

    reg_candidates = [it for it in alive_socket if not it["is_whitelist"]]
    wl_candidates = [it for it in alive_socket if it["is_whitelist"]]

    print(f"\nКандидатов на живой тест: Global = {len(reg_candidates)}, Whitelist = {len(wl_candidates)}")

    # 1. Живой тест для Global (цель: минимум 6 живых для Plus)
    print("\n--- ЖИВОЙ ТЕСТ: ГРУППА GLOBAL ---")
    regular_live = run_pure_live_test_pool(reg_candidates, target_count=6, max_candidates=200)

    # 2. Живой тест для Whitelist (цель: минимум 6 живых для Plus)
    print("\n--- ЖИВОЙ ТЕСТ: ГРУППА WHITELIST ---")
    whitelist_live = run_pure_live_test_pool(wl_candidates, target_count=6, max_candidates=200)

    print(f"\nИТОГ ЖИВОГО ТЕСТА: 100% живых Global: {len(regular_live)}, Whitelist: {len(whitelist_live)}")
    return regular_live, whitelist_live

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
    """Формирует подписку строго из ключей, прошедших живой тест"""
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
        <p>100% Живой тест Google Real Delay • Обновление каждый час</p>

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
    print("\nПодписки BCT VPN (Lite) и (Plus) успешно сформированы и сохранены!")

if __name__ == "__main__":
    global_keys = fetch_group_keys(GLOBAL_SOURCES, is_whitelist_group=False)
    wl_keys = fetch_group_keys(WHITELIST_SOURCES, is_whitelist_group=True)

    all_keys = global_keys + wl_keys
    print(f"\nВсего в базе для анализа: {len(all_keys)} ключей (Global: {len(global_keys)}, Whitelist: {len(wl_keys)})")

    # Глубокий живой тест собранной базы
    regular_live, whitelist_live = filter_and_rank_keys(all_keys)

    # 1. BCT VPN (Lite): берём 3 самых быстрых Global и 3 самых быстрых Whitelist
    lite_data = assemble_subscription(
        regular_items=regular_live,
        wl_items=whitelist_live,
        reg_count=3,
        wl_count=3,
        sub_name="BCT VPN (Lite)"
    )

    # 2. BCT VPN (Plus): берём 6 самых быстрых Global и 6 самых быстрых Whitelist
    plus_data = assemble_subscription(
        regular_items=regular_live,
        wl_items=whitelist_live,
        reg_count=6,
        wl_count=6,
        sub_name="BCT VPN (Plus)"
    )

    save_outputs(lite_data, plus_data, output_dir="dist")
