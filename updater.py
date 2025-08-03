import os
import base64
import requests
import logging
import socket
import re

# --------- پیکربندی ---------
SOURCE_URL = "https://raw.githubusercontent.com/Rayan-Config/C-Sub/refs/heads/main/configs/proxy.txt"
GITHUB_OWNER = "XIXV2RAY"
GITHUB_REPO = "config-updater"
GITHUB_TARGET_PATH = "VIP.txt"

NEW_TAG_BASE = "🍓 @xixv2ray"

# توکن گیت‌هاب (از environment میاد)
GITHUB_TOKEN = os.getenv("MY_GITHUB_TOKEN") or os.getenv("GITHUB_TOKEN", "")

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)

session = requests.Session()
session.headers.update({"User-Agent": "config-updater/1.0"})

def is_ip(addr: str) -> bool:
    try:
        parts = addr.strip().split('.')
        if len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts):
            return True
        return False
    except:
        return False

def resolve_host(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except Exception as e:
        logging.debug(f"resolve_host failed for {host}: {e}")
        return ""

def country_code_to_flag(code: str) -> str:
    if not code or len(code) != 2:
        return ""
    base = 0x1F1E6
    return chr(base + ord(code[0].upper()) - ord('A')) + chr(base + ord(code[1].upper()) - ord('A'))

def get_country(ip: str):
    # میریم ip-api می‌زنیم و کشور و کد کشور رو می‌گیریم
    try:
        r = session.get(f"http://ip-api.com/json/{ip}?fields=country,countryCode", timeout=5)
        if r.status_code == 200:
            data = r.json()
            return data.get("countryCode", ""), data.get("country", "")
    except Exception as e:
        logging.error(f"get_country failed for {ip}: {e}")
    return "", ""

def extract_host(line: str):
    # این تابع هاست یا IP داخل خط رو استخراج می‌کنه
    # برای کانفیگ‌هایی مثل vless:// trojan:// ss:// و غیره
    try:
        main = line.split("#")[0]
        if "@" not in main:
            return None
        after_at = main.split("@",1)[1]
        host = after_at.split(":",1)[0]
        return host
    except Exception as e:
        logging.debug(f"extract_host failed: {e}")
        return None

def process_line(line):
    line = line.strip()
    if not line or line.startswith("#"):
        return line

    host = extract_host(line)
    if not host:
        # اگر نتونست میزبان رو استخراج کنه فقط تگ قبلی رو نگه می‌داره و متن جدید رو اضافه می‌کنه
        if "#" in line:
            prefix, old_tag = line.split("#", 1)
            new_tag = f"{old_tag.strip()} | {NEW_TAG_BASE}"
            return f"{prefix.strip()}#{new_tag}"
        else:
            return f"{line}#{NEW_TAG_BASE}"

    ip = host if is_ip(host) else resolve_host(host)
    if not ip:
        ip = host

    country_code, country_name = get_country(ip)
    flag = country_code_to_flag(country_code)

    if "#" in line:
        prefix, old_tag = line.split("#", 1)
        additions = f"{flag} {country_name}".strip()
        new_tag = f"{old_tag.strip()} | {additions} | {NEW_TAG_BASE}".strip()
        return f"{prefix.strip()}#{new_tag}"
    else:
        additions = f"{flag} {country_name}".strip()
        new_tag = f"{NEW_TAG_BASE} | {additions}".strip()
        return f"{line}#{new_tag}"

def get_source_content():
    logging.info(f"Fetching source from {SOURCE_URL}")
    r = requests.get(SOURCE_URL, timeout=30)
    if r.status_code == 200:
        return r.text
    else:
        raise RuntimeError(f"Failed to fetch source: {r.status_code} {r.text[:200]}")

def get_file_sha():
    url = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/contents/{GITHUB_TARGET_PATH}"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json"
    }
    r = requests.get(url, headers=headers, timeout=15)
    logging.debug(f"GET existing file status: {r.status_code}")
    if r.status_code == 200:
        payload = r.json()
        return payload.get("sha"), base64.b64decode(payload.get("content", "")).decode("utf-8")
    elif r.status_code == 404:
        return None, ""
    else:
        raise RuntimeError(f"Failed to get file sha: {r.status_code} {r.text}")

def update_file(new_content, sha=None):
    url = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/contents/{GITHUB_TARGET_PATH}"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json"
    }
    encoded = base64.b64encode(new_content.encode("utf-8")).decode("utf-8")
    data = {
        "message": "Update VIP.txt with enriched tags", 
        "content": encoded,
        "branch": "main"
    }
    if sha:
        data["sha"] = sha
    r = requests.put(url, headers=headers, json=data, timeout=20)
    logging.debug(f"PUT update file status: {r.status_code}")
    if r.status_code in (200, 201):
        logging.info("✅ VIP.txt updated successfully on GitHub.")
    else:
        raise RuntimeError(f"Failed to update file: {r.status_code} {r.text}")

def main():
    logging.info(f"GITHUB_TOKEN present: {'yes' if GITHUB_TOKEN else 'no'}")
    if not GITHUB_TOKEN:
        raise RuntimeError("No GitHub token provided via MY_GITHUB_TOKEN or GITHUB_TOKEN environment variable.")

    content = get_source_content()
    lines = content.splitlines()
    updated_lines = [process_line(line) for line in lines]

    new_content = "\n".join(updated_lines) + "\n"

    sha, old_content = get_file_sha()

    if old_content is not None and new_content.strip() == old_content.strip():
        logging.info("No change compared to existing VIP.txt; skipping update.")
        return

    update_file(new_content, sha)

if __name__ == "__main__":
    main()
