import os
import base64
import requests

# پیکربندی
SOURCE_URL = "https://raw.githubusercontent.com/barry-far/V2ray-config/main/All_Configs_Sub.txt"
GITHUB_OWNER = "XIXV2RAY"
GITHUB_REPO = "config-updater"
GITHUB_TARGET_PATH = "VIP.txt"

# اگر از سکرت MY_GITHUB_TOKEN استفاده می‌کنی:
GITHUB_TOKEN = os.getenv("MY_GITHUB_TOKEN", "")

def get_source_content():
    print(f"[DEBUG] Fetching from {SOURCE_URL} ...")
    r = requests.get(SOURCE_URL, timeout=20)
    if r.status_code == 200:
        return r.text
    else:
        raise RuntimeError(f"Failed to fetch source: {r.status_code}")

def get_file_sha():
    url = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/contents/{GITHUB_TARGET_PATH}"
    headers = {"Authorization": f"Bearer {GITHUB_TOKEN}"}
    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        return r.json()["sha"]
    elif r.status_code == 404:
        return None
    else:
        raise RuntimeError(f"Failed to get file sha: {r.status_code} {r.text}")

def update_file(new_content, sha=None):
    url = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/contents/{GITHUB_TARGET_PATH}"
    headers = {"Authorization": f"Bearer {GITHUB_TOKEN}"}
    data = {
        "message": "Update VIP.txt from source",
        "content": base64.b64encode(new_content.encode("utf-8")).decode("utf-8"),
        "branch": "main"
    }
    if sha:
        data["sha"] = sha
    r = requests.put(url, headers=headers, json=data)
    if r.status_code in (200, 201):
        print("✅ VIP.txt updated successfully.")
    else:
        raise RuntimeError(f"Failed to update file: {r.status_code} {r.text}")

def main():
    if not GITHUB_TOKEN:
        raise RuntimeError("MY_GITHUB_TOKEN is not set in environment variables!")

    content = get_source_content()
    sha = get_file_sha()
    update_file(content, sha)

if __name__ == "__main__":
    main()
