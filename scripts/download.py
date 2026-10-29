"""下载三大漏洞库的全量数据到 data/raw/。

数据源：
  - CVEProject/cvelistV5：CVE 官方全量记录（最新 release 的 all_CVEs 包）
  - github/advisory-database：GitHub 安全公告（含 reviewed 与 unreviewed）
  - OSV.dev：npm 与 PyPI 生态的全量漏洞

用法：python3 scripts/download.py [--force]
"""
import json
import subprocess
import sys
from pathlib import Path

RAW = Path(__file__).resolve().parent.parent / "data" / "raw"

GHSA_URL = "https://codeload.github.com/github/advisory-database/zip/refs/heads/main"
OSV_URLS = {
    "osv_npm.zip": "https://storage.googleapis.com/osv-vulnerabilities/npm/all.zip",
    "osv_pypi.zip": "https://storage.googleapis.com/osv-vulnerabilities/PyPI/all.zip",
}


def cvelist_url():
    api = "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"
    release = json.loads(subprocess.run(["curl", "-sSfL", api], check=True, capture_output=True).stdout)
    for asset in release["assets"]:
        if "all_CVEs" in asset["name"]:
            return asset["browser_download_url"]
    raise RuntimeError("未在最新 release 中找到 all_CVEs 全量包")


def fetch(url, dest, force):
    # 用 curl 而非 urllib：部分网络环境下 Python 的 SSL 握手会失败
    if dest.exists() and not force:
        print(f"[跳过] {dest.name} 已存在")
        return
    print(f"[下载] {url}", flush=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    subprocess.run(["curl", "-sSfL", "--retry", "3", "-o", str(tmp), url], check=True)
    tmp.rename(dest)
    print(f"[完成] {dest.name} ({dest.stat().st_size >> 20} MB)")


def main():
    force = "--force" in sys.argv
    RAW.mkdir(parents=True, exist_ok=True)
    for name, url in OSV_URLS.items():
        fetch(url, RAW / name, force)
    fetch(GHSA_URL, RAW / "ghsa.zip", force)
    fetch(cvelist_url(), RAW / "cvelist.zip", force)


if __name__ == "__main__":
    main()
