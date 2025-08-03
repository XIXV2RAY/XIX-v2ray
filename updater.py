import os
import base64
import requests
import logging
import re

# لینک فایل منبع
SOURCE_URL = "https://raw.githubusercontent.com/Rayan-Config/C-Sub/refs/heads/main/configs/proxy.txt"

# اطلاعات گیت‌هاب
GITHUB_OWNER = "XIXV2RAY"
GITHUB_REPO = "config-updater"
GITHUB_TARGET_PATH = "VIP.txt"
GITHUB_BRANCH = "main"

# توکن را از محیط می‌خوانیم
GITHUB_TOKEN = os.getenv("MY_GITHUB_TOKEN")

# لاگ
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

def fetch_source():
    logging.info(f"Fetching content from {SOURCE_URL}")
    resp = requests.get(SOURCE_URL)
    resp.raise_for_status()
    return resp.text

def ip_to_country_flag_and_name(ip):
    """از API رایگان ip-api.com برای دریافت کشور و پرچم استفاده می‌کند"""
    try:
        url = f"http://ip-api.com/json/{ip}?fields=country,countryCode,status"
        r = requests.get(url, timeout=5)
        r.raise_for_status()
        data = r.json()
        if data.get("status") == "success":
            country_code = data.get("countryCode", "")
            country_name = data.get("country", "")
            if len(country_code) == 2:
                flag = chr(0x1F1E6 + ord(country_code[0]) - ord('A')) + chr(0x1F1E6 + ord(country_code[1]) - ord('A'))
                return flag, country_name
        return "", ""
    except Exception as e:
        logging.warning(f"Failed to get country info for IP {ip}: {e}")
        return "", ""

def extract_ip(line):
    """
    سعی می‌کنیم IP یا هاست رو از خط استخراج کنیم.
    بیشتر کانفیگ‌ها فرمت‌های شبیه به این‌ها دارند:
    hysteria2://<uuid>@IP:port?...#tag
    vless://<uuid>@host:port?...#tag
    ss://...@host:port#tag
    """
    # اولین تلاش: بعد از @ تا اولین : یا ? یا # جدا کنیم
    try:
        if "@" in line:
            after_at = line.split("@",1)[1]
            # تا اولین : یا ? یا # جدا می‌کنیم
            match = re.match(r"([^:?#]+)", after_at)
            if match:
                return match.group(1)
    except Exception as e:
        logging.warning(f"extract_ip failed: {e}")
    return None

def replace_tags(content):
    lines = content.splitlines()
    new_lines = []
    for line in lines:
        ip_or_host = extract_ip(line)
        flag = ""
        country = ""
        if ip_or_host:
            flag, country = ip_to_country_flag_and_name(ip_or_host)
        # ساخت تگ جدید
        tag = f"🍓 @xixv2ray"
        if flag and country:
            tag = f"{flag} {country} {tag}"
        # جایگزینی تگ (قسمت بعد از #)
        if "#" in line:
            line = line.split("#")[0].rstrip() + "#" + tag
        else:
            line = line.rstrip() + "#" + tag
        new_lines.append(line)
    return "\n".join(new_lines) + "\n"

def get_file_sha():
    url = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/contents/{GITHUB_TARGET_PATH}?ref={GITHUB_BRANCH}"
    headers = {"Authorization": f"Bearer {GITHUB_TOKEN}"}
    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        return r.json().get("sha")
    elif r.status_code == 404:
        return None
    else:
        r.raise_for_status()

def update_file(content, sha=None):
    url = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/contents/{GITHUB_TARGET_PATH}"
    headers = {"Authorization": f"Bearer {GITHUB_TOKEN}"}
    data = {
        "message": "Update VIP.txt with country flags and replaced tags",
        "content": base64.b64encode(content.encode()).decode(),
        "branch": GITHUB_BRANCH,
    }
    if sha:
        data["sha"] = sha
    r = requests.put(url, headers=headers, json=data)
    r.raise_for_status()
    logging.info("File updated successfully.")

def main():
    if not GITHUB_TOKEN:
        raise RuntimeError("MY_GITHUB_TOKEN environment variable not set!")

    content = fetch_source()
    new_content = replace_tags(content)
    sha = get_file_sha()
    update_file(new_content, sha)

if __name__ == "__main__":
    main()
