#!/usr/bin/env python3
"""评测实时监控：在终端窗口里实时刷新进度与指标。

用法: python tools/benchmark_watch.py [results_dir]
自动选择最新的 results 目录；Ctrl+C 退出。
"""
from __future__ import annotations

import glob
import json
import os
import sys
import time

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUBSET_SIZES = {"Lab": 70, "Combine": 70, "IDS": 25, "Private": 20, "Public": 15}
DEFAULT_TOTAL = 40  # 未识别到子集时兜底


def latest_jsonl() -> str:
    cands = glob.glob(os.path.join(BASE, "benchmark", "results", "*", "benchmark.jsonl"))
    return max(cands, key=os.path.getmtime) if cands else ""


def main() -> int:
    jl = sys.argv[1] if len(sys.argv) > 1 else latest_jsonl()
    if not jl:
        print("未找到 benchmark.jsonl"); return 1
    print(f"监控: {os.path.relpath(jl, BASE)}  (Ctrl+C 退出)\n")
    last_len = -1
    while True:
        rows = []
        if os.path.exists(jl):
            for line in open(jl, encoding="utf-8"):
                try:
                    rows.append(json.loads(line))
                except Exception:
                    pass
        n = len(rows)
        dss = {r.get("ds") for r in rows}
        total = sum(SUBSET_SIZES.get(d, 0) for d in dss) if dss else DEFAULT_TOTAL
        fields = ("service", "cve", "vulnerable", "attack_outcome")
        acc = {}
        for f in fields:
            vals = [r["scores"].get(f) for r in rows]
            denom = sum(1 for v in vals if v is not None)
            acc[f] = (sum(1 for v in vals if v is True) / denom) if denom else 0
        perfect = sum(1 for r in rows if all(r["scores"].get(f) is True for f in fields))
        # ETA: 用最近 8 条的平均间隔
        eta = "?"
        if n >= 4:
            times = [r.get("_t", 0) for r in rows[-8:]]
            t0 = os.path.getmtime(jl)
            try:
                with open(jl, encoding="utf-8") as f:
                    last_line = f.readlines()[-1]
                t_last = json.loads(last_line).get("_t", t0)
            except Exception:
                t_last = t0
            n_done_now = n
            started = next((r["_t"] for r in rows if r.get("_t")), t_last)
            if n_done_now > 1 and t_last > started:
                rate = (t_last - started) / n_done_now
                eta = f"{rate * (total - n_done_now) / 60:.0f} 分钟"
        # 最近事件
        last5 = rows[-5:]
        done_all = n >= total
        alive = n > 0 and not done_all

        out = []
        bar_w = 30
        filled = int(bar_w * n / total)
        bar = "#" * filled + "." * (bar_w - filled)
        out.append(f"进度: {n}/{total}  {bar}  {n / total:.0%}   剩余约 {eta}")
        if alive and len(rows) != last_len:
            out.append(f"（评测进程运行中，最新完成: {last5[-1]['event_key'] if last5 else '-'}）")
        elif done_all:
            out.append(f"[完成] 全部 {total} 个事件跑完！")
        out.append("")
        out.append(f"  四字段准确率:  service={acc['service']:.0%}  cve={acc['cve']:.0%}  "
                   f"vulnerable={acc['vulnerable']:.0%}  attack_outcome={acc['attack_outcome']:.0%}")
        out.append(f"  全中: {perfect}/{n} ({perfect / n:.0%})   解析率: "
                   f"{sum(1 for r in rows if r['scores']['parsed']) / n:.0%}" if n else "")
        out.append("")
        if last5:
            out.append("  最近事件:")
            for r in reversed(last5):
                hit = sum(1 for f in fields if r["scores"].get(f) is True)
                v = r.get("verdict") or {}
                out.append(f"    {r['event_key']:12s} 命中 {hit}/4  "
                           f"GT: {str(r['ground_truth'].get('service'))[:22]:22s} | {r['ground_truth'].get('attack_outcome')}")
        sys.stdout.write("\x1b[2J\x1b[H" + "\n".join(out) + "\n")
        sys.stdout.flush()
        last_len = len(rows)
        if done_all:
            time.sleep(2)
            sys.stdout.write("\x1b[2J\x1b[H" + "\n".join(out) + "\n")
            return 0
        time.sleep(4)


if __name__ == "__main__":
    sys.exit(main())
