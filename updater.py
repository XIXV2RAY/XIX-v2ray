import os
import base64
import requests
import logging
from time import sleep

# ---------- پیکربندی ----------
SOURCE_URL = "https://raw.githubusercontent.com/barry-far/V2ray-config/main/All_Configs_Sub.txt"
GITHUB_OWNER = "XIXV2RAY"
GITHUB_REPO = "config-updater"
GITHUB_TARGET_PATH = "VIP.txt"

# اول سعی می‌کنه از secret شخصی استفاده کنه، اگر نبود از توکن پیش‌فرض اکشن
GITHUB_TOKEN = os.getenv("MY_GITHUB_TOKEN") or os.getenv("GITHUB_TOKEN", "")

# لاگ
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)

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
        "message": "Update VIP.txt from source", 
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
    sha, old_content = get_file_sha()

    # اگر محتوا بدون تغییره، زدنش منطقی نیست
    if old_content is not None and content.strip() == old_content.strip():
        logging.info("No change compared to existing VIP.txt; skipping update.")
        return

    update_file(content, sha)

if __name__ == "__main__":
    main()
