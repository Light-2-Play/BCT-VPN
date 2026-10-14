import os
import re
import json
import base64
import socket
import time
from urllib.parse import urlparse, parse_qs, quote, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

# Список источников (Telegram-каналы или raw-ссылки)
SOURCES = [
    "https://t.me/s/vpn_channel_example",  # Замените на ваши каналы
]

VLESS_REGEX = re.compile(r"vless://[^\s<>\"']+")

RU_DOMAINS = (
    ".ru", ".su", ".xn--p1ai", "vk.com", "yandex", "gosuslugi",
    "ozon", "wildberries", "mail.ru", "dzen.ru", "tbank", "sberbank"
)

def fetch_all_vless():
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
    try:
        parsed = urlparse(key_uri)
        if not parsed.hostname or not parsed.port:
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

def check_tcp_ping(item, timeout=2.5):
    start = time.perf_counter()
    try:
        with socket.create_connection((item["host"], item["port"]), timeout=timeout):
            latency = (time.perf_counter() - start) * 1000
            item["latency"] = latency
            return item
    except Exception:
        return None

def filter_and_rank_keys(raw_keys):
    parsed_items = [parse_vless(k) for k in raw_keys if parse_vless(k)]
    alive_items = []

    print(f"Тестируем доступность {len(parsed_items)} ключей...")
    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = [executor.submit(check_tcp_ping, it) for it in parsed_items]
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                alive_items.append(res)

    alive_items.sort(key=lambda x: x["latency"])

    regular = [it for it in alive_items if not it["is_whitelist"]]
    whitelist = [it for it in alive_items if it["is_whitelist"]]

    print(f"Рабочих обычных: {len(regular)}, для белых списков: {len(whitelist)}")
    return regular, whitelist

def format_node_name(item, sub_name, index, is_wl):
    """Присваивает узлу брендированное название для отображения в списке"""
    tag_type = "RU-Bypass" if is_wl else "Global"
    node_name = f"{sub_name} | #{index:02d} [{tag_type}]"
    
    # Заменяем хеш (#) в VLESS ссылке на новое имя
    base_uri = item["uri"].split('#')[0]
    renamed_uri = f"{base_uri}#{quote(node_name)}"
    return renamed_uri, node_name

def convert_to_singbox_outbound(item, tag_name):
    """Преобразует распарсенный VLESS в формат sing-box outbound"""
    p = item["parsed"]
    q = item["query"]
    
    uuid = p.username
    server = p.hostname
    port = p.port
    
    net = q.get("type", ["tcp"])[0]
    sec = q.get("security", ["none"])[0]
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
        "network": net if net in ["tcp", "udp"] else "tcp"
    }
    
    if flow:
        outbound["flow"] = flow
        
    if sec in ["tls", "reality"]:
        tls_conf = {
            "enabled": True,
            "server_name": sni or server,
            "utls": {
                "enabled": True,
                "fingerprint": fp
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

def build_singbox_config(outbounds, sub_name):
    """Собирает полный валидный .json профиль для sing-box / Nekobox"""
    tags = [ob["tag"] for ob in outbounds]
    
    config = {
        "version": 1,
        "remarks": sub_name,
        "outbounds": [
            {
                "type": "selector",
                "tag": f"Auto / Select ({sub_name})",
                "outbounds": ["urltest"] + tags,
                "default": "urltest"
            },
            {
                "type": "urltest",
                "tag": "urltest",
                "outbounds": tags,
                "url": "https://www.gstatic.com/generate_204",
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
        
    # Формируем Base64
    raw_text = "\n".join(uris)
    b64_sub = base64.b64encode(raw_text.encode("utf-8")).decode("utf-8")
    
    # Формируем JSON
    json_sub = build_singbox_config(singbox_outbounds, sub_name)
    
    return b64_sub, json_sub

def save_outputs(lite_pack, plus_pack, output_dir="dist"):
    os.makedirs(output_dir, exist_ok=True)
    
    lite_b64, lite_json = lite_pack
    plus_b64, plus_json = plus_pack
    
    # Base64 подписки (для v2rayNG, Happ, v2rayN)
    with open(f"{output_dir}/lite.txt", "w", encoding="utf-8") as f:
        f.write(lite_b64)
    with open(f"{output_dir}/plus.txt", "w", encoding="utf-8") as f:
        f.write(plus_b64)
        
    # JSON подписки (для sing-box, Nekobox, Hiddify)
    with open(f"{output_dir}/lite.json", "w", encoding="utf-8") as f:
        f.write(lite_json)
    with open(f"{output_dir}/plus.json", "w", encoding="utf-8") as f:
        f.write(plus_json)
        
    print("Файлы lite.txt, plus.txt, lite.json, plus.json успешно сгенерированы!")

if __name__ == "__main__":
    raw_keys = fetch_all_vless()
    print(f"Спаршено сырых ключей: {len(raw_keys)}")
    
    reg_items, wl_items = filter_and_rank_keys(raw_keys)
    
    # Lite: 3 обычных + 3 для белых списков
    lite_data = assemble_subscription(reg_items, wl_items, count=3, sub_name="BCT VPN (Lite)")
    
    # Plus: 6 обычных + 6 для белых списков
    plus_data = assemble_subscription(reg_items, wl_items, count=6, sub_name="BCT VPN (Plus)")
    
    save_outputs(lite_data, plus_data)
