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

# ==========================================
# 1. ИСТОЧНИКИ, ОРИЕНТИРОВАННЫЕ НА РФ И СНГ
# ==========================================
GLOBAL_SOURCES = [
    # База серверов, настроенных специально под ТСПУ в РФ
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt",
    # Отфильтрованные Reality-пулы
    "https://raw.githubusercontent.com/LalatinaHub/Mineral/master/result/nodes",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/vless",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/xray/normal/vless"
]

WHITELIST_SOURCES = [
    # Прямые базы белых списков (RU-Bypass)
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt",
    "https://gitlab.com/zieng2/wl/raw/main/vless_universal.txt",
    "https://codeberg.org/zieng2/wl/raw/branch/main/vless_universal.txt",
    "https://gitverse.ru/api/repos/zieng2/wl/raw/branch/master/list_universal.txt"
]

VLESS_REGEX = re.compile(r"vless://[^\s<>\"']+")
GOOGLE_DELAY_TEST_URL = "https://www.gstatic.com/generate_204"

# ==========================================
# 2. ЧЕРНЫЙ СПИСОК ASN И ХОСТИНГОВ (БЛОК В РФ)
# ==========================================
# Эти провайдеры на 95-100% заблокированы ТСПУ по подсетям
BLOCKED_ASNS = {
    "24940", "213230",  # Hetzner Online GmbH
    "16276", "35540",   # OVH SAS
    "14061",            # DigitalOcean
    "12876",            # Scaleway
    "63949",            # Akamai / Linode
    "31898",            # Oracle Cloud
    "13335",            # Cloudflare (WARP подсети)
}

BLOCKED_ORG_KEYWORDS = (
    "hetzner", "ovh", "digitalocean", "scaleway", "linode",
    "oracle", "akamai", "arvancloud", "mci.ir", "irancell"
)

# Заблокированные в РФ SNI (если сервер маскируется под них, ТСПУ дропает соединение)
BLOCKED_SNI_IN_RU = (
    "instagram", "facebook", "twitter", "x.com", "threads", "meta.com",
    "rutracker", "meduza", "bbc", "dw.com", "svoboda", "navalny",
    "pornhub", "linkedin", "t.me", "telegram"
)

def get_free_port():
    """Выделение свободного порта для тестового инстанса sing-box"""
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
                print(f"[{group_name}] {url} -> ошибка: {resp.status_code}")
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

        # Для Global в РФ стабильно работает ТОЛЬКО Reality
        if not is_whitelist:
            if sec != "reality" or not pbk:
                return None  # Отсекаем голый TCP и обычный TLS без Reality
            if any(b in target for b in BLOCKED_SNI_IN_RU):
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

def check_tcp_socket(item, timeout=1.5):
    """Первичный сокет-отсев выключенных узлов"""
    try:
        with socket.create_connection((item["host"], item["port"]), timeout=timeout):
            return item
    except Exception:
        return None

# Кэш ASN для исключения повторных запросов
ASN_CACHE = {}

def is_asn_blocked(host):
    """
    Проверяет принадлежность IP-адреса хостинга к заблокированным в РФ ASN/провайдерам.
    """
    try:
        # Резолвим домен в IP
        ip = socket.gethostbyname(host)
    except Exception:
        return False

    if ip in ASN_CACHE:
        return ASN_CACHE[ip]

    try:
        # Быстрый бесплатный запрос информации об автономной системе
        r = requests.get(f"https://ipwho.is/{ip}", timeout=2.5)
        if r.status_code == 200:
            data = r.json()
            if not data.get("success", True):
                ASN_CACHE[ip] = False
                return False

            asn = str(data.get("connection", {}).get("asn", ""))
            org = str(data.get("connection", {}).get("org", "")).lower()
            isp = str(data.get("connection", {}).get("isp", "")).lower()
            full_info = f"{org} {isp}"

            # Проверка по номеру ASN
            if asn in BLOCKED_ASNS:
                print(f" -> [ASN БЛОК: AS{asn}] {host} ({org})")
                ASN_CACHE[ip] = True
                return True

            # Проверка по ключевым словам провайдера
            if any(keyword in full_info for keyword in BLOCKED_ORG_KEYWORDS):
                print(f" -> [ISP БЛОК: {org}] {host}")
                ASN_CACHE[ip] = True
                return True

            ASN_CACHE[ip] = False
            return False
    except Exception:
        pass

    ASN_CACHE[ip] = False
    return False

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

    if flow and sec in ["tls", "reality"] and net in ["tcp", ""]:
        outbound["flow"] = flow

    if sec in ["tls", "reality"]:
        tls_conf = {
            "enabled": True,
            "server_name": sni or server,
            "insecure": True,
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

def test_vless_live_google(item, timeout=3.8):
    """Живой тест: реальный запрос к Google через ядро sing-box"""
    if not os.path.exists("./sing-box"):
        return None

    test_port = get_free_port()
    outbound = convert_to_singbox_outbound(item, "live-test")

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

def run_pipeline_for_group(group, target_count=6, apply_asn_filter=False, max_candidates=160):
    """
    Многоступенчатая фильтрация:
    1. Быстрый сокет-тест
    2. Фильтр заблокированных ASN (для Global)
    3. Живой тест через sing-box до Google
    """
    print(f"\nКандидатов на входе: {len(group)}")

    # 1. Быстрый сокет-тест
    alive_socket = []
    with ThreadPoolExecutor(max_workers=45) as executor:
        futures = [executor.submit(check_tcp_socket, it) for it in group]
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                alive_socket.append(res)

    print(f"Ответили по сокету: {len(alive_socket)}")

    # 2. Фильтрация заблокированных ASN (только для Global, Whitelist уже на RU-хостах)
    asn_cleared = []
    if apply_asn_filter:
        print("Применение ASN-фильтра (отсеиваем Hetzner, OVH, DigitalOcean, Linode, Scaleway)...")
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_item = {executor.submit(is_asn_blocked, it["host"]): it for it in alive_socket[:max_candidates]}
            for fut in as_completed(future_to_item):
                it = future_to_item[fut]
                try:
                    if not fut.result():
                        asn_cleared.append(it)
                except Exception:
                    asn_cleared.append(it)
        print(f"Осталось после ASN-фильтра: {len(asn_cleared)}")
    else:
        asn_cleared = alive_socket[:max_candidates]

    # 3. Живой тест через sing-box
    print(f"Запуск живого теста Google (пул: {len(asn_cleared)}, цель: {target_count})...")
    live_verified = []
    if os.path.exists("./sing-box"):
        with ThreadPoolExecutor(max_workers=12) as executor:
            future_map = {executor.submit(test_vless_live_google, it): it for it in asn_cleared}
            for fut in as_completed(future_map):
                try:
                    res = fut.result()
                    if res and "latency" in res:
                        live_verified.append(res)
                        print(f" -> [OK] {res['host']}:{res['port']} | Задержка: {int(res['latency'])} ms")
                        if len(live_verified) >= target_count + 4:
                            for f in future_map:
                                f.cancel()
                            break
                except Exception:
                    pass

    live_verified.sort(key=lambda x: x["latency"])
    return live_verified

def filter_and_rank_keys(raw_items):
    parsed_items = [parse_vless(k) for k in raw_items if parse_vless(k)]
    print(f"Всего распознано валидных ключей: {len(parsed_items)}")

    reg_candidates = [it for it in parsed_items if not it["is_whitelist"]]
    wl_candidates = [it for it in parsed_items if it["is_whitelist"]]

    print(f"Пул Global (только Reality): {len(reg_candidates)}")
    print(f"Пул Whitelist (RU-Bypass): {len(wl_candidates)}")

    print("\n--- ОБРАБОТКА ГРУППЫ GLOBAL ---")
    regular_live = run_pipeline_for_group(reg_candidates, target_count=6, apply_asn_filter=True)

    print("\n--- ОБРАБОТКА ГРУППЫ WHITELIST ---")
    whitelist_live = run_pipeline_for_group(wl_candidates, target_count=6, apply_asn_filter=False)

    print(f"\nИТОГ: Живых чистых Global: {len(regular_live)}, Whitelist: {len(whitelist_live)}")
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
    uris = []
    singbox_outbounds = []

    selected_reg = regular_items[:reg_count]
    selected_wl = wl_items[:wl_count]

    idx = 1
    for it in selected_reg:
        renamed_uri, tag = format_node_name(it, sub_name, idx, is_wl=False)
        uris.append(renamed_uri)
        singbox_outbounds.append(convert_to_singbox_outbound(it, tag))
        idx += 1

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
        <p>ASN-фильтр • Reality • Google Real Delay • Обновление каждый час</p>

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
    print("\nПодписки BCT VPN (Lite) и (Plus) успешно созданы!")

if __name__ == "__main__":
    global_keys = fetch_group_keys(GLOBAL_SOURCES, is_whitelist_group=False)
    wl_keys = fetch_group_keys(WHITELIST_SOURCES, is_whitelist_group=True)

    all_keys = global_keys + wl_keys
    print(f"\nВсего собрано ключей: {len(all_keys)}")

    regular_live, whitelist_live = filter_and_rank_keys(all_keys)

    # Lite: 3 Global + 3 Whitelist
    lite_data = assemble_subscription(
        regular_items=regular_live,
        wl_items=whitelist_live,
        reg_count=3,
        wl_count=3,
        sub_name="BCT VPN (Lite)"
    )

    # Plus: 6 Global + 6 Whitelist
    plus_data = assemble_subscription(
        regular_items=regular_live,
        wl_items=whitelist_live,
        reg_count=6,
        wl_count=6,
        sub_name="BCT VPN (Plus)"
    )

    save_outputs(lite_data, plus_data, output_dir="dist")
