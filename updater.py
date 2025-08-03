import os
import base64
import requests
import logging

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

def replace_tags(content):
    lines = content.splitlines()
    new_lines = []
    for line in lines:
        # اگر خط خالی یا بدون تگ بود، همین خط باشه
        if "#" in line:
            line = line.split("#")[0].rstrip() + "#" + "🍓 @xixv2ray"
        else:
            line = line.rstrip() + "#" + "🍓 @xixv2ray"
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
        "message": "Update VIP.txt with replaced tags",
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
