import os
import re
import base64
import json
import requests
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, unquote, quote

# ---------- پیکربندی ----------
SOURCE_URL = "https://raw.githubusercontent.com/Rayan-Config/C-Sub/refs/heads/main/configs/proxy.txt"
GITHUB_OWNER = "XIXV2RAY"
GITHUB_REPO = "config-updater"
GITHUB_TARGET_PATH = "VIP.txt"

GITHUB_TOKEN = os.getenv("MY_GITHUB_TOKEN") or os.getenv("GITHUB_TOKEN", "")

NEW_TAG_BASE = "🍓 @xixv2ray"

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)

session = requests.Session()
session.headers.update({"User-Agent": "config-updater/1.0"})

def get_source_content():
    logging.info(f"Fetching source from {SOURCE_URL}")
    r = requests.get(SOURCE_URL, timeout=30)
    if r.status_code == 200:
        return r.text
    else:
        raise RuntimeError(f"Failed to fetch source: {r.status_code} {r.text[:200]}")

def get_country_info(ip_or_host):
    try:
        # سعی می‌کنیم ip-api.com با فرمت json بگیریم
        url = f"http://ip-api.com/json/{ip_or_host}?fields=country,countryCode,status,message"
        r = session.get(url, timeout=5)
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                country_code = data.get("countryCode", "")
                country_name = data.get("country", "")
                flag = country_code_to_flag(country_code)
                return flag, country_name
            else:
                logging.debug(f"ip-api failure for {ip_or_host}: {data.get('message')}")
                return "", ""
        else:
            logging.debug(f"ip-api http error {r.status_code} for {ip_or_host}")
            return "", ""
    except Exception as e:
        logging.debug(f"ip-api exception for {ip_or_host}: {e}")
        return "", ""

def country_code_to_flag(code: str) -> str:
    if not code or len(code) != 2:
        return ""
    base = 0x1F1E6
    return chr(base + ord(code[0].upper()) - ord('A')) + chr(base + ord(code[1].upper()) - ord('A'))

def extract_host(line: str):
    try:
        # حذف تگ (بعد از #)
        line_wo_tag = line.split("#")[0].strip()
        parsed = urlparse(line_wo_tag)

        # بیشتر پروتکل‌ها host:port تو netloc دارند
        if parsed.netloc:
            host = parsed.netloc.split(":", 1)[0]
            if host:
                return host

        # اگر خالی بود، تلاش می‌کنیم بعد از @ و قبل از : رو بگیریم
        if "@" in line_wo_tag:
            after_at = line_wo_tag.split("@", 1)[1]
            host = after_at.split(":", 1)[0]
            if host:
                return host

        return None
    except Exception as e:
        logging.debug(f"extract_host failed: {e}")
        return None

def update_line_tag(line: str):
    host = extract_host(line)
    if not host:
        logging.debug(f"No host found in line, skipping tag update: {line[:50]}")
        return line

    flag, country_name = get_country_info(host)

    # ساخت تگ جدید
    new_tag = NEW_TAG_BASE
    if flag:
        new_tag = flag + " " + new_tag
    if country_name:
        new_tag += " " + country_name

    # حالا جایگزین کردن تگ (بعد از #) با new_tag
    if "#" in line:
        idx = line.rfind("#")
        new_line = line[:idx+1] + quote(new_tag)
    else:
        new_line = line + "#" + quote(new_tag)

    logging.debug(f"Updated tag: {new_line[:80]}")
    return new_line

def main():
    if not GITHUB_TOKEN:
        raise RuntimeError("No GitHub token provided via MY_GITHUB_TOKEN or GITHUB_TOKEN environment variable.")

    content = get_source_content()
    lines = [line.strip() for line in content.splitlines() if line.strip()]

    updated_lines = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(update_line_tag, line): line for line in lines}
        for fut in as_completed(futures):
            try:
                updated_line = fut.result()
                updated_lines.append(updated_line)
            except Exception as e:
                logging.error(f"Error updating line tag: {e}")

    final_content = "\n".join(updated_lines) + "\n"

    # حالا آپدیت کردن روی گیت‌هاب (مثل قبل)
    url = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/contents/{GITHUB_TARGET_PATH}"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json"
    }
    # گرفتن sha برای آپدیت
    r = session.get(url, headers=headers, timeout=15)
    if r.status_code == 200:
        payload = r.json()
        sha = payload.get("sha")
        old_content = base64.b64decode(payload.get("content", "")).decode("utf-8")
        if old_content.strip() == final_content.strip():
            logging.info("No change compared to existing VIP.txt; skipping update.")
            return
    elif r.status_code == 404:
        sha = None
    else:
        raise RuntimeError(f"Failed to get file sha: {r.status_code} {r.text}")

    # کدگذاری محتوا و ارسال PUT
    encoded = base64.b64encode(final_content.encode("utf-8")).decode("utf-8")
    data = {
        "message": "Update VIP.txt with country flags and new tags",
        "content": encoded,
        "branch": "main"
    }
    if sha:
        data["sha"] = sha

    r2 = session.put(url, headers=headers, json=data, timeout=20)
    if r2.status_code in (200, 201):
        logging.info("✅ VIP.txt updated successfully on GitHub.")
    else:
        raise RuntimeError(f"Failed to update file: {r2.status_code} {r2.text}")

if __name__ == "__main__":
    main()
