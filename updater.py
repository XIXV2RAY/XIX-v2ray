import os
import re
import json
import base64
import socket
import logging
import requests
import ipaddress
import platform
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from time import sleep, time
from typing import Tuple

# ---------- پیکربندی ----------
INPUT_URLS = [
    "https://raw.githubusercontent.com/Rayan-Config/C-Sub/refs/heads/main/configs/proxy.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/Rayan-Config/C-Sub/refs/heads/main/configs/proxy.txt",
    "https://raw.githubusercontent.com/Surfboardv2ray/Proxy-sorter/refs/heads/main/output/IR.txt",
]
OUTPUT_LOCAL = "VIP.txt"
GITHUB_OWNER = "XIXV2RAY"
GITHUB_REPO = "configs"
GITHUB_TARGET_PATH = "VIP.txt"
NEW_MSG = "🍓 @xixv2ray"
GEOIP_DB_PATH = "GeoLite2-Country.mmdb"

MAX_WORKERS = 30
RATE_LIMIT_PER_SEC = 5
PING_THRESHOLD_MS = 500

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("error.txt", encoding="utf-8"),
        logging.StreamHandler()
    ]
)

session = requests.Session()
session.headers.update({"User-Agent": "config-updater/1.0"})

_last_api_call = 0.0
def throttle():
    global _last_api_call
    interval = 1.0 / RATE_LIMIT_PER_SEC
    now = time()
    delta = now - _last_api_call
    if delta < interval:
        sleep(interval - delta)
    _last_api_call = time()

def is_ip(addr: str) -> bool:
    try:
        ipaddress.ip_address(addr.strip())
        return True
    except ValueError:
        return False

def resolve_host(host: str) -> str:
    if is_ip(host):
        return host.strip()
    try:
        ip = socket.gethostbyname(host)
        logging.debug(f"Resolved host {host} to IP {ip}")
        return ip
    except Exception as e:
        logging.warning(f"resolve_host failed for {host}: {e}")
        return ""

def country_code_to_flag(code: str) -> str:
    if not code or len(code) != 2:
        return ""
    base = 0x1F1E6
    return chr(base + ord(code[0].upper()) - ord('A')) + chr(base + ord(code[1].upper()) - ord('A'))

def extract_flags(text: str) -> str:
    return ''.join(re.findall(r'[\U0001F1E6-\U0001F1FF]{2}', text))

try:
    import geoip2.database
    from geoip2.errors import AddressNotFoundError
    GEOIP2_AVAILABLE = True
except ImportError:
    GEOIP2_AVAILABLE = False

def lookup_country_local(ip: str, reader, cache) -> Tuple[str, str]:
    if ip in cache and "local" in cache[ip]:
        return cache[ip]["local"]
    try:
        resp = reader.country(ip)
        code = resp.country.iso_code or ""
        name = resp.country.names.get("en", "") if resp.country.names else ""
        cache.setdefault(ip, {})["local"] = (code, name)
        return code, name
    except Exception:
        cache.setdefault(ip, {})["local"] = ("", "")
        return "", ""

def lookup_country_api(ip: str, cache) -> Tuple[str, str]:
    if ip in cache and "api" in cache[ip]:
        return cache[ip]["api"]
    try:
        throttle()
        r = session.get(f"http://ip-api.com/json/{ip}?fields=country,countryCode", timeout=4)
        if r.status_code == 200:
            data = r.json()
            code = data.get("countryCode", "") or ""
            name = data.get("country", "") or ""
            cache.setdefault(ip, {})["api"] = (code, name)
            return code, name
    except Exception as e:
        logging.error(f"lookup_country_api failed for {ip}: {e}")
    cache.setdefault(ip, {})["api"] = ("", "")
    return "", ""

def lookup_country(ip: str, reader, cache) -> Tuple[str, str]:
    if not ip:
        return "", ""
    if GEOIP2_AVAILABLE and reader:
        try:
            code, name = lookup_country_local(ip, reader, cache)
            if code:
                return code, name
        except Exception:
            pass
    return lookup_country_api(ip, cache)

def get_ping_ms(ip: str, timeout_sec: int = 1) -> float | None:
    try:
        system = platform.system().lower()
        if system == "windows":
            proc = subprocess.run(
                ["ping", "-n", "1", "-w", str(timeout_sec * 1000), ip],
                capture_output=True,
                text=True,
                timeout=timeout_sec + 1
            )
            if proc.returncode != 0:
                return None
            m = re.search(r"زمان[=<]\s*([\d]+)ms", proc.stdout)
            if not m:
                m = re.search(r"time[=<]\s*([\d]+)ms", proc.stdout)
            if not m:
                return None
            ping_ms = float(m.group(1))
        else:
            proc = subprocess.run(
                ["ping", "-c", "1", "-W", str(timeout_sec), ip],
                capture_output=True,
                text=True,
                timeout=timeout_sec + 1
            )
            if proc.returncode != 0:
                return None
            m = re.search(r"time=([\d\.]+)\s*ms", proc.stdout)
            if not m:
                return None
            ping_ms = float(m.group(1))
        if ping_ms >= PING_THRESHOLD_MS:
            return None
        return ping_ms
    except Exception as e:
        logging.debug(f"get_ping_ms failed for {ip}: {e}")
        return None

def update_vmess(line: str, reader, cache):
    try:
        data_b64 = line[7:]
        data_json = base64.b64decode(data_b64).decode('utf-8')
        data = json.loads(data_json)
    except Exception as e:
        logging.error(f"vmess decode error: {e} | line: {line[:80]}")
        return None, None, False

    add = data.get("add", "")
    if not is_ip(add):
        logging.info(f"vmess: skipped invalid address: {add}")
        return None, None, False

    ip = resolve_host(add)
    if not ip or not is_ip(ip):
        logging.info(f"vmess: can't resolve IP for {add}")
        return None, None, False

    ping = get_ping_ms(ip)
    if ping is None:
        logging.info(f"vmess: skipping {add} because ping >= {PING_THRESHOLD_MS}ms or failed")
        return None, None, False
    logging.debug(f"vmess: ping to {ip} = {ping} ms")

    code, name = lookup_country(ip, reader, cache)
    flag = country_code_to_flag(code)
    existing_flags = extract_flags(data.get("ps", ""))
    new_ps = (flag or existing_flags)
    if name:
        new_ps += f" {name}"
    new_ps += " " + NEW_MSG
    new_ps = new_ps.strip()

    prev_ps = data.get("ps", "")
    if new_ps == prev_ps:
        return None, None, False

    data["ps"] = new_ps

    try:
        updated_json = json.dumps(data, ensure_ascii=False)
        updated_b64 = base64.b64encode(updated_json.encode("utf-8")).decode("utf-8")
        new_line = "vmess://" + updated_b64
    except Exception as e:
        logging.error(f"vmess encode error: {e}")
        return None, None, False

    key = ("vmess", data.get("id", ""), data.get("add", ""), data.get("port", ""), data.get("net", ""), data.get("tls", ""))
    return new_line, key, True

def extract_host(line: str):
    try:
        main = line.split("#")[0]
        if "@" not in main:
            return None
        after_at = main.split("@",1)[1]
        host = after_at.split(":",1)[0]
        return host
    except Exception as e:
        logging.warning(f"extract_host failed: {e}")
        return None

def update_other(line: str, reader, cache):
    for scheme in ["vless://", "ss://", "hysteria2://", "trojan://"]:
        if line.startswith(scheme) and "#" in line:
            host = extract_host(line)
            if not host:
                return None, None, False

            ip = resolve_host(host)
            if not ip or not is_ip(ip):
                logging.info(f"{scheme} can't resolve IP for {host}")
                return None, None, False

            ping = get_ping_ms(ip)
            if ping is None:
                logging.info(f"{scheme} skipping {host} because ping >= {PING_THRESHOLD_MS}ms or failed")
                return None, None, False
            logging.debug(f"{scheme}: ping to {ip} = {ping} ms")

            code, name = lookup_country(ip, reader, cache)
            flag = country_code_to_flag(code)

            idx = line.rfind("#")
            tag_enc = line[idx+1:]
            tag_dec = requests.utils.unquote(tag_enc)
            existing_flags = extract_flags(tag_dec)

            new_tag = (flag or existing_flags)
            if name:
                new_tag += f" {name}"
            new_tag += " " + NEW_MSG
            new_tag = new_tag.strip()

            prev_tag = requests.utils.unquote(tag_enc)
            if new_tag == prev_tag:
                return None, None, False

            new_tag_enc = requests.utils.quote(new_tag)
            new_line = line[:idx+1] + new_tag_enc

            key = (scheme, ip)
            return new_line, key, True
    return None, None, False

def fetch_and_merge_inputs():
    accumulated = []
    for url in INPUT_URLS:
        try:
            r = session.get(url, timeout=10)
            if r.status_code == 200:
                for ln in r.text.splitlines():
                    ln = ln.strip()
                    if ln:
                        accumulated.append(ln)
            else:
                logging.warning(f"Failed to fetch {url}: status {r.status_code}")
        except Exception as e:
            logging.error(f"Exception fetching {url}: {e}")
    return accumulated

def process_lines(lines):
    result = []
    seen = set()
    stats = {"total": 0, "skipped": 0, "duplicates": 0, "updated": 0}
    reader = None
    if GEOIP2_AVAILABLE and os.path.isfile(GEOIP_DB_PATH):
        try:
            import geoip2.database
            reader = geoip2.database.Reader(GEOIP_DB_PATH)
        except Exception as e:
            logging.warning(f"GeoIP DB load failed: {e}")
    cache = {}

    def worker(line):
        if line.startswith("vmess://"):
            return update_vmess(line, reader, cache)
        else:
            return update_other(line, reader, cache)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(worker, ln): ln for ln in lines}
        for fut in as_completed(futures):
            orig = futures[fut]
            try:
                new_line, key, changed = fut.result()
            except Exception as e:
                logging.error(f"Worker exception for line {orig[:80]}: {e}")
                stats["skipped"] += 1
                stats["total"] += 1
                continue
            stats["total"] += 1
            if not changed or new_line is None or key is None:
                stats["skipped"] += 1
                continue
            if key in seen:
                stats["duplicates"] += 1
                continue
            seen.add(key)
            result.append(new_line)
            stats["updated"] += 1

    if reader:
        reader.close()
    return result, stats

def get_file_sha_and_content():
    url = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/contents/{GITHUB_TARGET_PATH}"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json"
    }
    r = session.get(url, headers=headers, timeout=10)
    logging.debug(f"[DEBUG] GET {url} status {r.status_code}")
    if r.status_code == 200:
        payload = r.json()
        sha = payload.get("sha")
        content = base64.b64decode(payload.get("content", "")).decode("utf-8")
        return sha, content
    elif r.status_code == 404:
        return None, ""
    else:
        raise RuntimeError(f"GitHub get file failed {r.status_code}: {r.text}")

def push_updated_file(new_content: str, previous_sha: str):
    url = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/contents/{GITHUB_TARGET_PATH}"
    message = "Auto-update configs with enriched tags"
    encoded = base64.b64encode(new_content.encode("utf-8")).decode("utf-8")
    data = {
        "message": message,
        "content": encoded,
        "branch": "main",
    }
    if previous_sha:
        data["sha"] = previous_sha
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json"
    }
    logging.debug(f"[DEBUG] PUT {url}")
    r = session.put(url, headers=headers, json=data, timeout=20)
    logging.debug(f"[DEBUG] Response status: {r.status_code}")
    logging.debug(f"[DEBUG] Response body: {r.text}")
    if r.status_code in (200, 201):
        print("✅ Updated on GitHub successfully.")
    else:
        raise RuntimeError(f"GitHub push failed {r.status_code}: {r.text}")

def main():
    print(f"[DEBUG] GITHUB_TOKEN present: {'yes' if GITHUB_TOKEN else 'no'}")
    if not GITHUB_TOKEN:
        print("ERROR: توکن گیت‌هاب تنظیم نشده.")
        return

    print("Fetching remote inputs...")
    lines = fetch_and_merge_inputs()
    print(f"Fetched {len(lines)} raw lines.")

    print("Processing lines...")
    updated_lines, stats = process_lines(lines)
    print("Stats:", stats)

    if not updated_lines:
        print("No valid updated lines; exiting.")
        return

    with open(OUTPUT_LOCAL, "w", encoding="utf-8") as f:
        f.write("\n".join(updated_lines) + "\n")
    print(f"Wrote local output to {OUTPUT_LOCAL} ({len(updated_lines)} entries).")

    try:
        sha, old_content = get_file_sha_and_content()
        new_content = "\n".join(updated_lines) + "\n"
        if old_content is not None and new_content.strip() == old_content.strip():
            print("No change compared to existing GitHub file; skipping push.")
        else:
            push_updated_file(new_content, sha)
    except Exception as e:
        logging.error(f"GitHub sync failed: {e}")
        print("GitHub sync failed:", e)

if __name__ == "__main__":
    main()
