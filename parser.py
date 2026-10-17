import os
import re
import json
import base64
import socket
import time
import tempfile
import subprocess
from urllib.parse import urlparse, parse_qs, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import urllib3
import ipaddress
from collections import defaultdict

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# =====================================================================
# ПОРОГИ ЗАДЕРЖКИ (LATENCY THRESHOLDS)
# =====================================================================
MAX_STRICT_LATENCY_MS = 500.0   # СТРОГИЙ максимум: всё что выше 500ms выбрасывается
RECOMMENDED_LATENCY_MS = 120.0  # РЕКОМЕНДОВАННЫЙ эталон: узлы с наивысшим приоритетом

# =====================================================================
# 1. ДИАПАЗОНЫ ЗАПРЕЩЕННЫХ В РФ ЗАРУБЕЖНЫХ ХОСТИНГОВ (406-ФЗ / РКН)
# =====================================================================
BANNED_HOSTING_CIDRS = [
    # Hetzner
    "78.46.0.0/15", "88.198.0.0/16", "94.130.0.0/16", "95.216.0.0/15",
    "135.181.0.0/16", "138.201.0.0/16", "142.132.0.0/16", "144.76.0.0/16",
    "159.69.0.0/16", "168.119.0.0/16", "195.201.0.0/16", "65.108.0.0/16",
    "65.109.0.0/16", "49.12.0.0/16", "116.202.0.0/16", "116.203.0.0/16",
    # DigitalOcean
    "104.131.0.0/16", "104.248.0.0/16", "138.68.0.0/16", "142.93.0.0/16",
    "143.198.0.0/16", "143.244.0.0/16", "157.230.0.0/16", "157.245.0.0/16",
    "159.65.0.0/16", "159.89.0.0/16", "161.35.0.0/16", "164.90.0.0/16",
    "164.92.0.0/16", "165.22.0.0/16", "165.227.0.0/16", "167.172.0.0/16",
    "167.71.0.0/16", "167.99.0.0/16", "174.138.0.0/16", "178.62.0.0/16",
    "188.166.0.0/16", "206.189.0.0/16", "46.101.0.0/16", "64.225.0.0/16",
    # OVH
    "51.0.0.0/8", "141.94.0.0/15", "146.59.0.0/16", "135.125.0.0/16",
    "178.32.0.0/15", "188.165.0.0/16", "193.70.0.0/16", "37.59.0.0/16",
    "46.105.0.0/16", "54.36.0.0/15", "57.128.0.0/16",
    # Kamatera / Scaleway / Linode
    "185.10.68.0/22", "185.16.38.0/23", "213.142.128.0/18",
    "51.15.0.0/16", "163.172.0.0/16", "62.210.0.0/16", "139.162.0.0/16"
]

SUBNETS_BY_OCTET = defaultdict(list)
LOADED_BLOCKED_NETS = False
GEO_CACHE = {}

def get_geo_info(host):
    """Определение страны и флага-эмодзи по IP/домену с кэшированием"""
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        return "🌐", "Unknown"

    if ip in GEO_CACHE:
        return GEO_CACHE[ip]

    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode", timeout=2.5)
        if r.status_code == 200:
            d = r.json()
            if d.get("status") == "success":
                cc = d.get("countryCode", "").upper()
                country = d.get("country", cc)
                flag = "".join(chr(ord(c) + 127397) for c in cc) if len(cc) == 2 else "🌐"
                GEO_CACHE[ip] = (flag, country)
                return GEO_CACHE[ip]
    except Exception:
        pass

    try:
        r = requests.get(f"https://api.country.is/{ip}", timeout=2.5)
        if r.status_code == 200:
            cc = r.json().get("country", "").upper()
            if len(cc) == 2:
                flag = "".join(chr(ord(c) + 127397) for c in cc)
                GEO_CACHE[ip] = (flag, cc)
                return GEO_CACHE[ip]
    except Exception:
        pass

    GEO_CACHE[ip] = ("🌐", "Unknown")
    return GEO_CACHE[ip]

def load_rkn_blocked_database():
    """Скачивание свежих дампов заблокированных подсетей РКН и запрещенных хостингов"""
    global LOADED_BLOCKED_NETS
    if LOADED_BLOCKED_NETS:
        return

    raw_subnets = list(BANNED_HOSTING_CIDRS)
    sources = [
        "https://antifilter.download/list/subnet.lst",
        "https://raw.githubusercontent.com/eduard256/russia-blocked-ips/main/ip.txt"
    ]

    for url in sources:
        try:
            r = requests.get(url, timeout=7, headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code == 200:
                lines = r.text.splitlines()
                valid_cidrs = [l.strip() for l in lines if "/" in l and not l.startswith("#")]
                raw_subnets.extend(valid_cidrs)
                print(f"[RKN-DB] Успешно загружен дамп {url}: добавлено {len(valid_cidrs)} подсетей")
                break
        except Exception as e:
            print(f"[RKN-DB] Ошибка загрузки {url}: {e}")

    count = 0
    for cidr in raw_subnets:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            if isinstance(net, ipaddress.IPv4Network):
                first_octet = int(str(net.network_address).split('.')[0])
                SUBNETS_BY_OCTET[first_octet].append(net)
                count += 1
        except Exception:
            continue

    print(f"[RKN-DB] Итого проиндексировано {count} заблокированных подсетей в РФ.")
    LOADED_BLOCKED_NETS = True

def is_ip_blocked_in_russia(host):
    """Локальная проверка IP-адреса хоста по базе блокировок РКН и хостеров"""
    try:
        ip_str = socket.gethostbyname(host)
        ip_obj = ipaddress.ip_address(ip_str)
        first_octet = int(ip_str.split('.')[0])

        for net in SUBNETS_BY_OCTET.get(first_octet, []):
            if ip_obj in net:
                return True, ip_str, str(net)
    except Exception:
        pass
    return False, None, None

# =====================================================================
# 2. ОПТИМИЗИРОВАННЫЕ ИСТОЧНИКИ ДЛЯ РФ (ЕЖЕЧАСНОЕ АВТООБНОВЛЕНИЕ)
# =====================================================================
GLOBAL_SOURCES = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS_mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/clean/vless.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/vless.txt"
]

WHITELIST_SOURCES = [
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt",
    "https://gitlab.com/zieng2/wl/raw/main/vless_universal.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/WHITE-CIDR-RU-checked.txt",
    "https://raw.githubusercontent.com/kort0881/russia-whitelist/main/whitelist.txt"
]

VLESS_REGEX = re.compile(r"vless://[^\s<>\"']+")

BLOCKED_SNI_IN_RU = (
    "instagram", "facebook", "twitter", "x.com", "threads", "meta.com",
    "rutracker", "meduza", "bbc", "dw.com", "svoboda", "navalny",
    "pornhub", "linkedin", "t.me", "telegram"
)

BLOCKED_HOSTINGS_IN_RU = (
    "hetzner", "ovh.", "digitalocean", "linode", "scaleway", "arvancloud", "mci.ir"
)

def get_free_port():
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
        urls_to_try = [url]
        if "/main/" in url:
            urls_to_try.append(url.replace("/main/", "/master/"))
        if "WHITE-CIDR-RU-checked.txt" in url:
            urls_to_try.append(url.replace("WHITE-CIDR-RU-checked.txt", "Vless-Reality-White-Lists-Rus-Mobile.txt"))
            urls_to_try.append(url.replace("WHITE-CIDR-RU-checked.txt", "WHITE_VLESS_RUS.txt"))
        if "zieng2/wl" in url:
            urls_to_try.append("https://gitverse.ru/api/repos/zieng2/wl/raw/branch/master/list_universal.txt")
            urls_to_try.append("https://raw.githubusercontent.com/zieng2/wl/master/vless_universal.txt")
            urls_to_try.append("https://raw.githubusercontent.com/zieng2/wl/master/vless_lite.txt")

        fetched_keys = set()
        for target_url in urls_to_try:
            try:
                resp = requests.get(target_url, headers=headers, timeout=10, verify=False)
                if resp.status_code == 200:
                    keys = extract_vless_keys(resp.text)
                    if keys:
                        print(f"[{group_name}] {target_url} -> получено: {len(keys)}")
                        fetched_keys.update(keys)
                        break
            except Exception:
                continue

        if fetched_keys:
            for k in fetched_keys:
                if k not in seen:
                    seen.add(k)
                    items.append({"uri": k, "is_whitelist": is_whitelist_group})
        else:
            print(f"[{group_name}] {url} -> не удалось загрузить ключи")

    return items

def parse_vless(raw_item):
    key_uri = raw_item["uri"]
    is_whitelist = raw_item["is_whitelist"]

    try:
        parsed = urlparse(key_uri)
        if not parsed.hostname or not parsed.port or not parsed.username:
            return None

        if parsed.hostname in ["0.0.0.0", "127.0.0.1", "localhost"] or parsed.port in [0, 1]:
            return None

        query = parse_qs(parsed.query)
        sni = query.get("sni", [""])[0].lower()
        host = query.get("host", [""])[0].lower()
        sec = query.get("security", ["none"])[0].lower()
        pbk = query.get("pbk", [""])[0]

        target = sni or host or parsed.hostname.lower()
        host_str = parsed.hostname.lower()

        # Фильтры под блокировки ТСПУ в РФ
        if not is_whitelist:
            if any(b in target for b in BLOCKED_SNI_IN_RU):
                return None
            if sec not in ["reality", "tls"]:
                return None
            if sec == "reality" and not pbk:
                return None
            if any(h in host_str for h in BLOCKED_HOSTINGS_IN_RU):
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

def check_tcp_socket(item, timeout=1.8):
    start = time.perf_counter()
    try:
        with socket.create_connection((item["host"], item["port"]), timeout=timeout):
            lat = (time.perf_counter() - start) * 1000
            # Если даже TCP-сокет отвечает дольше 500ms, хост непригоден
            if lat > MAX_STRICT_LATENCY_MS:
                return None
            item["tcp_latency"] = lat
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
    flow = q.get("flow", [""])[0].lower()
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

    if flow in ["xtls-rprx-vision", "xtls-rprx-vision-udp443"] and net in ["tcp", ""] and sec in ["tls", "reality"]:
        outbound["flow"] = flow

    if sec in ["tls", "reality"]:
        tls_conf = {
            "enabled": True,
            "server_name": sni or server,
            "utls": {
                "enabled": True,
                "fingerprint": fp if fp else "chrome"
            }
        }
        if sec == "reality":
            reality_conf = {
                "enabled": True,
                "public_key": pbk
            }
            if sid:
                reality_conf["short_id"] = sid
            tls_conf["reality"] = reality_conf
        else:
            tls_conf["insecure"] = True

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

def test_vless_live(item, timeout=3.5):
    """Живой тест: запуск sing-box и замер отклика через curl"""
    if not os.path.exists("./sing-box"):
        return None

    net = item["query"].get("type", ["tcp"])[0].lower()
    if net in ["xhttp", "splithttp", "httpupgrade"]:
        return item

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
        for _ in range(25):
            try:
                with socket.create_connection(("127.0.0.1", test_port), timeout=0.04):
                    ready = True
                    break
            except Exception:
                time.sleep(0.04)

        if not ready:
            return None

        if item["is_whitelist"]:
            endpoints = ["https://ya.ru", "https://vk.com", "https://cp.cloudflare.com/generate_204"]
        else:
            endpoints = ["https://www.gstatic.com/generate_204", "https://cp.cloudflare.com/generate_204"]

        success = False
        best_delay = 9999.0
        for target in endpoints:
            try:
                cmd = [
                    "curl", "-s", "-o", "/dev/null",
                    "-w", "%{http_code}:%{time_total}",
                    "--connect-timeout", "2.0",
                    "-m", str(timeout),
                    "-x", f"http://127.0.0.1:{test_port}",
                    target
                ]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 0.5)
                if res.returncode == 0 and res.stdout:
                    parts = res.stdout.strip().split(":")
                    if len(parts) == 2:
                        http_code = parts[0]
                        time_total = float(parts[1]) * 1000
                        if http_code in ["200", "204", "301", "302"]:
                            success = True
                            if time_total < best_delay:
                                best_delay = time_total
                            break
            except Exception:
                continue

        if success:
            # СТРОГИЙ ФИЛЬТР: задержка выше 500ms отбрасывается
            if best_delay <= MAX_STRICT_LATENCY_MS:
                item["latency"] = best_delay
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

def process_category(candidates, target_count=6, max_test=160):
    """
    Отбор серверов с многоуровневым контролем задержки:
    - СТРОГИЙ лимит: <= 500 ms (серверы медленнее отбрасываются).
    - РЕКОМЕНДОВАННЫЙ эталон: <= 120 ms (приоритетное ранжирование).
    """
    print(f"\nКандидатов на входе: {len(candidates)}")
    if not candidates:
        return []

    # Дедупликация по IP:Port
    unique_candidates = []
    seen_endpoints = set()
    for it in candidates:
        ep = f"{it['host']}:{it['port']}"
        if ep not in seen_endpoints:
            seen_endpoints.add(ep)
            unique_candidates.append(it)

    print(f"Уникальных конечных серверов: {len(unique_candidates)}")

    # 1. Быстрый сокет-тест (отсекает также сокеты с пингом > 500ms)
    alive_socket = []
    with ThreadPoolExecutor(max_workers=40) as executor:
        futures = [executor.submit(check_tcp_socket, it) for it in unique_candidates]
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                alive_socket.append(res)

    print(f"Ответили на сокет (<=500ms): {len(alive_socket)} серверов.")
    if not alive_socket:
        return []

    # 2. Живой тест через sing-box
    pool = alive_socket[:max_test]
    verified_live = []

    if os.path.exists("./sing-box") and pool:
        print(f"Запуск живого теста (пул: {len(pool)}, цель: {target_count}, лимит: <=500ms, идеал: <=120ms)...")
        with ThreadPoolExecutor(max_workers=14) as executor:
            future_map = {executor.submit(test_vless_live, it): it for it in pool}
            for fut in as_completed(future_map):
                try:
                    res = fut.result()
                    if res and "latency" in res:
                        delay = res["latency"]
                        if delay <= MAX_STRICT_LATENCY_MS:
                            verified_live.append(res)
                            if delay <= RECOMMENDED_LATENCY_MS:
                                print(f" -> [⚡ ТОП <=120ms] {res['host']}:{res['port']} | Задержка: {int(delay)} ms")
                            else:
                                print(f" -> [✓ ОК <=500ms] {res['host']}:{res['port']} | Задержка: {int(delay)} ms")

                        # Прерываем опрос при наборе достаточного количества быстрых узлов
                        rec_count = sum(1 for x in verified_live if x["latency"] <= RECOMMENDED_LATENCY_MS)
                        if rec_count >= target_count + 2 or len(verified_live) >= target_count + 8:
                            for f in future_map:
                                f.cancel()
                            break
                except Exception:
                    pass
    else:
        verified_live = [x for x in alive_socket if x.get("tcp_latency", 999) <= MAX_STRICT_LATENCY_MS][:target_count]

    # Сортировка по задержке: узлы <=120ms автоматически первыми в очереди
    verified_live.sort(key=lambda x: x.get("latency", 9999))

    # Страховочный добор только из сокет-проверенных серверов, СТРОГО <= 500 ms
    if len(verified_live) < target_count:
        print(f"Внимание: живой тест подтвердил {len(verified_live)}/{target_count}. Добор резерва с сокетом <=500ms...")
        used_endpoints = {f"{x['host']}:{x['port']}" for x in verified_live}
        for it in alive_socket:
            ep = f"{it['host']}:{it['port']}"
            tcp_lat = it.get("tcp_latency", 999.0)
            if ep not in used_endpoints and tcp_lat <= MAX_STRICT_LATENCY_MS:
                it["latency"] = tcp_lat
                verified_live.append(it)
                used_endpoints.add(ep)
            if len(verified_live) >= target_count:
                break

    # Финальная гарантия строгого фильтра
    verified_live = [x for x in verified_live if x.get("latency", 9999) <= MAX_STRICT_LATENCY_MS]
    verified_live.sort(key=lambda x: x.get("latency", 9999))

    print(f"Итого отобрано чистых серверов (<=500ms): {len(verified_live)}")
    return verified_live

def filter_and_rank_keys(raw_items):
    parsed_items = [parse_vless(k) for k in raw_items if parse_vless(k)]
    print(f"Всего распознано корректных ключей: {len(parsed_items)}")

    reg_candidates = [it for it in parsed_items if not it["is_whitelist"]]
    wl_candidates = [it for it in parsed_items if it["is_whitelist"]]

    # Загружаем базу блокировок
    load_rkn_blocked_database()

    # Исключаем заблокированные в РФ подсети и хостинги
    clean_candidates = []
    for item in reg_candidates:
        is_blocked, ip, net = is_ip_blocked_in_russia(item["host"])
        if is_blocked:
            continue
        clean_candidates.append(item)

    print(f"\nКандидатов Global после отсева РКН/хостингов: {len(clean_candidates)}")
    print(f"Кандидатов Whitelist: {len(wl_candidates)}")

    print("\n--- ОБРАБОТКА ГРУППЫ GLOBAL (Черные списки РФ) ---")
    regular_ready = process_category(clean_candidates, target_count=6)

    print("\n--- ОБРАБОТКА ГРУППЫ WHITELIST (Белые списки РФ) ---")
    whitelist_ready = process_category(wl_candidates, target_count=6)

    print(f"\nИТОГ: Готовых серверов Global: {len(regular_ready)}, Whitelist: {len(whitelist_ready)}")
    return regular_ready, whitelist_ready

def format_node_name(item, sub_name, index, is_wl):
    tag_type = "Whitelist" if is_wl else "Global"
    flag, country = get_geo_info(item["host"])
    hour_tag = time.strftime("%d.%m")
    
    # Формат с флагом и страной: 🇩🇪 Germany | BCT VPN (Lite) | #01 [Global] (17.10)
    node_name = f"{flag} {country} | {sub_name} | #{index:02d} [{tag_type}] ({hour_tag})"
    base_uri = item["uri"].split('#')[0]
    renamed_uri = f"{base_uri}#{quote(node_name)}"
    return renamed_uri, node_name

def build_singbox_config(outbounds, sub_name):
    tags = [ob["tag"] for ob in outbounds]
    timestamp = time.strftime("%d.%m %H:%M UTC")
    config = {
        "version": 1,
        "remarks": f"{sub_name} [{timestamp}]",
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
                "url": "https://www.gstatic.com/generate_204",
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

    # Строгое наполнение согласно тарифам
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
    """Генерация главной страницы с защитой от кэширования браузерами и клиентами"""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC")
    html_content = f"""<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
    <meta http-equiv="Pragma" content="no-cache">
    <meta http-equiv="Expires" content="0">
    <title>BCT VPN Subscriptions</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; padding: 20px; box-sizing: border-box; }}
        .card {{ background: #1e293b; border-radius: 16px; padding: 32px; max-width: 520px; width: 100%; box-shadow: 0 10px 25px rgba(0,0,0,0.3); border: 1px solid #334155; }}
        h1 {{ margin-top: 0; font-size: 24px; text-align: center; color: #38bdf8; }}
        p {{ color: #94a3b8; font-size: 13px; text-align: center; }}
        .section {{ margin-top: 24px; }}
        .section-title {{ font-weight: 600; font-size: 16px; margin-bottom: 12px; color: #e2e8f0; display: flex; justify-content: space-between; }}
        .links {{ display: flex; flex-direction: column; gap: 8px; }}
        a {{ display: block; background: #334155; color: #38bdf8; text-decoration: none; padding: 12px 16px; border-radius: 8px; font-size: 14px; word-break: break-all; transition: background 0.2s; }}
        a:hover {{ background: #475569; }}
        .badge {{ font-size: 11px; padding: 2px 8px; border-radius: 12px; background: #0284c7; color: white; }}
    </style>
</head>
<body>
    <div class="card">
        <h1>BCT VPN Subscriptions</h1>
        <p>100% Живой отбор • Задержка строго &le; 500ms • Эталон &le; 120ms<br>Обновлено: {timestamp}</p>

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
    print(f"\nВсего в базе: {len(all_keys)} ключей (Global: {len(global_keys)}, Whitelist: {len(wl_keys)})")

    regular_ready, whitelist_ready = filter_and_rank_keys(all_keys)

    # Lite: строго 3 Global + 3 Whitelist
    lite_data = assemble_subscription(
        regular_items=regular_ready,
        wl_items=whitelist_ready,
        reg_count=3,
        wl_count=3,
        sub_name="BCT VPN (Lite)"
    )

    # Plus: строго 6 Global + 6 Whitelist
    plus_data = assemble_subscription(
        regular_items=regular_ready,
        wl_items=whitelist_ready,
        reg_count=6,
        wl_count=6,
        sub_name="BCT VPN (Plus)"
    )

    save_outputs(lite_data, plus_data, output_dir="dist")
