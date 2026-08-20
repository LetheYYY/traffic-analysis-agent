#!/usr/bin/env python3
"""下载 Net4n6Bench 子集到 benchmark/Net4n6Bench/<DS>/。

用法: python tools/fetch_net4n6bench.py Public IDS
来源: github.com/bmthanh/Net4n6Bench (main 分支)，经 gh-proxy 镜像访问。
"""
from __future__ import annotations

import os
import sys

import requests

REPO = "bmthanh/Net4n6Bench"
BRANCH = "main"
PROXY = "https://gh-proxy.com/https://raw.githubusercontent.com"
# 各子集的事件数（来自仓库树）
SUBSET_SIZES = {"Lab": 70, "Combine": 70, "IDS": 25, "Private": 20, "Public": 15}
BASE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "benchmark", "Net4n6Bench")


def fetch(url: str, dest: str) -> None:
    if os.path.exists(dest) and os.path.getsize(dest) > 0:
        return
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    r = requests.get(url, timeout=120)
    r.raise_for_status()
    with open(dest, "wb") as f:
        f.write(r.content)
    print(f"  {os.path.relpath(dest, BASE)}  ({len(r.content)} B)")


def main() -> int:
    subsets = sys.argv[1:] or ["Public", "IDS"]
    for ds in subsets:
        n = SUBSET_SIZES[ds]
        print(f"=== {ds} ({n} events) ===")
        for i in range(n):
            name = f"{ds}_eventID_{i}"
            pcap_url = f"{PROXY}/{REPO}/{BRANCH}/datasets/{ds}/raw/eventID_{i}/{name}.pcap"
            fetch(pcap_url, os.path.join(BASE, ds, "raw", f"eventID_{i}", f"{name}.pcap"))
        fetch(f"{PROXY}/{REPO}/{BRANCH}/datasets/{ds}/tasks/data.json",
              os.path.join(BASE, ds, "tasks", "data.json"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
