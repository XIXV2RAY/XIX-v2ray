import os
import re
import base64
import json
import logging
import socket
import requests

# GeoIP
try:
    import geoip2.database
    from geoip2.errors import AddressNotFoundError
    GEOIP2_AVAILABLE = True
except ImportError:
    GEOIP2_AVAILABLE = False

# ---------- پیکربندی ----------
SOURCE_URL = "https://raw.githubusercontent.com/Rayan-Config/C-Sub/refs/heads/main/configs/proxy.txt"
GEOIP_DB_PATH = "GeoLite2-Country.mmdb"  # باید در ریشه‌ی ریپو باشه
GITHUB_OWNER = "XIXV2RAY"
GITHUB_REPO = "config-updater"
GITHUB_TARGET_PATH = "VIP.txt"
GITHUB_BRANCH = "main"

NEW_TAG_BASE = "🍓 @xixv2ray"

# توکن
GITHUB_TOKEN = os.getenv("MY_GITHUB_TOKEN") or os.getenv("GITHUB_TOKEN", "")

# لاگ
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)s %(message)s")

session = requests.Session()
session.headers.update({"User-Agent": "config-updater/1.0"})

# ---------- کانفیگ‌های ثابت که همیشه اول اضافه میشن ----------
FIXED_CONFIGS = [
    "vless://0fc95877-cdc3-458f-8b00-d554c99ecbfb@cb6.connectbaash.info:4406?security=&fp=chrome&type=tcp&encryption=none#🍓 More configs 🍓 @xixv2ray",
    "vless://b976f215-3def-4271-8baa-511c4087cf17@sv1.provps.fun:443?security=&fp=chrome&type=tcp&encryption=none#🌐 For more configs, join Telegram 🍓 @xixv2ray",
    "vless://0aef4ee4-8e8b-488c-9ea4-9fe8d7b84b7a@85.133.208.147:2089?security=&fp=chrome&type=tcp&encryption=none#🇮🇷 برای دریافت کانفیگ‌های بیشتر وارد تلگرام شوید 🍓 @xixv2ray",
    "vless://0aef4ee4-8e8b-488c-9ea4-9fe8d7b84b7a@85.133.208.147:2089?security=&fp=chrome&type=tcp&encryption=none#🍓🍓🍓🍓🍓🍓🍓🍓🍓🍓🍓"
]

# ---------- کمکی‌ها ----------
def country_code_to_flag(code: str) -> str:
    if not code or len(code) != 2:
        return ""
    base = 0x1F1E6
    return chr(base + ord(code[0].upper()) - ord("A")) + chr(base + ord(code[1].upper()) - ord("A"))

def lookup_country_local(ip: str, reader, cache):
    if ip in cache and "local" in cache[ip]:
        return cache[ip]["local"]
    try:
        resp = reader.country(ip)
        code = resp.country.iso_code or ""
        name = resp.country.names.get("en", "") if resp.country.names else ""
        cache.setdefault(ip, {})["local"] = (code, name)
        return code, name
    except AddressNotFoundError:
        cache.setdefault(ip, {})["local"] = ("", "")
        return "", ""
    except Exception as e:
        logging.debug(f"lookup_country_local error for {ip}: {e}")
        cache.setdefault(ip, {})["local"] = ("", "")
        return "", ""

def lookup_country_api(ip: str, cache):
    if ip in cache and "api" in cache[ip]:
        return cache[ip]["api"]
    try:
        r = session.get(f"http://ip-api.com/json/{ip}?fields=country,countryCode", timeout=5)
        if r.status_code == 200:
            data = r.json()
            code = data.get("countryCode", "") or ""
            name = data.get("country", "") or ""
            cache.setdefault(ip, {})["api"] = (code, name)
            return code, name
    except Exception as e:
        logging.debug(f"lookup_country_api failed for {ip}: {e}")
    cache.setdefault(ip, {})["api"] = ("", "")
    return "", ""

def lookup_country(ip: str, reader, cache):
    if not ip:
        return "", ""
    if GEOIP2_AVAILABLE and reader:
        code, name = lookup_country_local(ip, reader, cache)
        if code:
            return code, name
    return lookup_country_api(ip, cache)

def extract_ip_or_host(line: str):
    try:
        # حذف قسمت تگ
        main = line.split("#")[0]
        if "@" not in main:
            return None
        after_at = main.split("@", 1)[1]
        # جدا کردن تا اولین : یا ? یا /
        m = re.match(r"([^:\/\?]+)", after_at)
        if m:
            return m.group(1)
    except Exception as e:
        logging.debug(f"extract_ip_or_host error: {e}")
    return None

# ---------- منطق اصلی ----------
def fetch_source():
    logging.info(f"Fetching source from {SOURCE_URL}")
    r = requests.get(SOURCE_URL, timeout=30)
    r.raise_for_status()
    return r.text.splitlines()

def build_updated_line(line: str, reader, cache):
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return line  # بدون تغییر

    # اگر کانفیگ جزو ثابت هاست، تگ نمی‌زنیم (می‌تونی تغییرش بدی)
    if line in FIXED_CONFIGS:
        return line

    host = extract_ip_or_host(stripped)
    country_code = ""
    country_name = ""
    if host:
        ip = None
        try:
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
                ip = host
            else:
                ip = socket.gethostbyname(host)
        except Exception:
            ip = host

        country_code, country_name = lookup_country(ip, reader, cache)
    else:
        logging.debug(f"No host extracted from line: {line[:80]}")

    flag = country_code_to_flag(country_code)
    new_tag_parts = []
    if flag:
        new_tag_parts.append(flag)
    if country_name:
        new_tag_parts.append(country_name)
    new_tag_parts.append(NEW_TAG_BASE)
    new_tag = " ".join(new_tag_parts).strip()

    if "#" in stripped:
        prefix = stripped.split("#", 1)[0].rstrip()
        updated = f"{prefix}#{new_tag}"
    else:
        updated = f"{stripped}#{new_tag}"

    return updated

def get_file_sha():
    url = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/contents/{GITHUB_TARGET_PATH}?ref={GITHUB_BRANCH}"
    headers = {"Authorization": f"Bearer {GITHUB_TOKEN}"}
    r = requests.get(url, headers=headers, timeout=15)
    if r.status_code == 200:
        return r.json()["sha"], base64.b64decode(r.json().get("content", "")).decode("utf-8")
    elif r.status_code == 404:
        return None, ""
    else:
        raise RuntimeError(f"GitHub GET file failed {r.status_code}: {r.text}")

def push_updated_file(new_content: str, sha: str | None):
    url = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/contents/{GITHUB_TARGET_PATH}"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json"
    }
    data = {
        "message": "Auto-update VIP.txt with enriched country tags",
        "content": base64.b64encode(new_content.encode("utf-8")).decode("utf-8"),
        "branch": GITHUB_BRANCH
    }
    if sha:
        data["sha"] = sha
    r = requests.put(url, headers=headers, json=data, timeout=20)
    logging.debug(f"PUT response: {r.status_code} {r.text[:200]}")
    if r.status_code not in (200, 201):
        raise RuntimeError(f"GitHub push failed {r.status_code}: {r.text}")
    logging.info("✅ Updated VIP.txt on GitHub.")

def main():
    logging.info(f"GITHUB_TOKEN present: {'yes' if GITHUB_TOKEN else 'no'}")
    if not GITHUB_TOKEN:
        raise RuntimeError("GitHub token not set in MY_GITHUB_TOKEN or GITHUB_TOKEN environment variable.")

    reader = None
    if GEOIP2_AVAILABLE and os.path.isfile(GEOIP_DB_PATH):
        try:
            reader = geoip2.database.Reader(GEOIP_DB_PATH)
        except Exception as e:
            logging.warning(f"Failed to open GeoIP DB: {e}")

    cache = {}

    lines = fetch_source()
    updated = []

    # اضافه کردن کانفیگ‌های ثابت اول
    updated.extend(FIXED_CONFIGS)

    # اضافه کردن بقیه کانفیگ‌ها با تگ کشور
    for ln in lines:
        # اگر کانفیگ توی ثابت ها بود، رد می‌کنیم چون قبلا اضافه شده
        if ln in FIXED_CONFIGS:
            continue
        updated.append(build_updated_line(ln, reader, cache))

    new_content = "\n".join(updated) + "\n"

    sha, old_content = get_file_sha()
    if old_content is not None and new_content.strip() == old_content.strip():
        logging.info("No change compared to existing VIP.txt; exiting.")
        return

    push_updated_file(new_content, sha)

    if reader:
        reader.close()

if __name__ == "__main__":
    main()
