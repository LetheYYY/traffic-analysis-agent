#!/usr/bin/env python3
"""Net4n6Bench 批量评测：headless 跑流量分析 Agent，对照 ground truth 打分。

用法:
    python tools/run_benchmark.py Public IDS --limit 3        # 先小批验证
    python tools/run_benchmark.py Public IDS                  # 全量
    python tools/run_benchmark.py Public IDS --resume results/xxx.jsonl

输出:
    results/<ts>/benchmark.jsonl   逐事件结果（增量追加，可断点续跑）
    results/<ts>/summary.json      汇总指标
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
import time

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))     # C:\workspace\dsr
REPO = os.path.join(BASE, "deepseek-harness-master", "deepseek-harness-master")
DS_DIR = os.path.join(BASE, "benchmark", "Net4n6Bench")
RESULTS = os.path.join(BASE, "benchmark", "results")

AGENT_CMD = [
    "node",
    "--import", "tsx/esm",
    os.path.join(REPO, "apps", "cli", "src", "bin.ts"),
    "--profile", "traffic-agent-hl",
]

PROMPT = (
    "对抓包文件做安全取证分析，判断其对应的攻击事件。\n"
    "步骤：1) 先用 python tools/pcap_analyze.py <文件> 获取概览；2) 用 tshark 对可疑流量深挖；"
    "3) 判断受影响的 service、相关 CVE、系统是否受影响、攻击结果。\n"
    "注意：攻击流量可能基于非 HTTP 协议（Erlang RPC、SMB、数据库协议、ICMP 等），"
    "先看概览的协议构成再深挖，不要默认 HTTP。\n"
    "【评测模式】不要创建报告文件，不要写入 Obsidian，不要输出多余解释。\n"
    "最后一行必须且只能是一个 JSON 对象（不要 Markdown 代码块、不要额外文字），"
    "键为 service / cve / vulnerable / attack_outcome：\n"
    '{"service": "受影响的服务名", "cve": "CVE 编号或 N/A", "vulnerable": true或false, '
    '"attack_outcome": "successful|unsuccessful|inconclusive|benign"}'
)


def norm(s) -> str:
    return re.sub(r"[^a-z0-9]", "", str(s).lower())


def parse_verdict(text: str) -> dict | None:
    """从 agent 输出提取 verdict JSON。"""
    if not text:
        return None
    m = re.search(r"```json\s*(\{.*?\})\s*```", text, re.S)
    if m:
        try:
            return json.loads(m.group(1))
        except Exception:
            pass
    m = re.search(r"\{[^{}]*\"attack_outcome\"[^{}]*\}", text, re.S)
    if m:
        try:
            return json.loads(m.group(0))
        except Exception:
            pass
    # 兜底: 逐字段提取
    v = {}
    for key, pat in (
        ("service", r"\"service\"\s*:\s*\"([^\"]+)\""),
        ("cve", r"\"cve\"\s*:\s*\"([^\"]+)\""),
        ("vulnerable", r"\"vulnerable\"\s*:\s*(true|false)"),
        ("attack_outcome", r"\"attack_outcome\"\s*:\s*\"([^\"]+)\""),
    ):
        mm = re.search(pat, text)
        if mm:
            v[key] = mm.group(1) if key != "vulnerable" else mm.group(1) == "true"
    return v or None


def load_tasks(ds: str) -> list[dict]:
    with open(os.path.join(DS_DIR, ds, "tasks", "data.json"), encoding="utf-8") as f:
        return json.load(f)["tasks"]


def run_agent(pcap_abs: str, timeout: int) -> str:
    env = dict(os.environ)
    env["TSX_TSCONFIG_PATH"] = os.path.join(REPO, "tsconfig.json")
    task = f"分析文件 {pcap_abs}\n\n{PROMPT}"
    flags = 0
    if os.name == "nt":
        flags = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
    p = subprocess.Popen(
        AGENT_CMD + [task], cwd=BASE, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace",
        creationflags=flags,
    )
    try:
        out, _ = p.communicate(timeout=timeout)
        return out or ""
    except subprocess.TimeoutExpired:
        # Windows 下直接 kill 会留下孙进程占着管道，必须杀整棵进程树
        try:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(p.pid)],
                           capture_output=True, timeout=10)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass
        try:
            p.communicate(timeout=15)
        except Exception:
            pass
        return "<TIMEOUT>"


def score(gt: dict, pred: dict | None) -> dict:
    empty = {"service": None, "cve": None, "vulnerable": None, "attack_outcome": None,
             "parsed": False}
    if not pred:
        return {**empty, "error": "no_verdict"}
    r = {"parsed": True}

    def cmp(key, gv, pv):
        """GT 缺失/未知 → None(不评分); 否则 True/False。"""
        if gv is None:
            return None
        if isinstance(gv, str) and gv.strip().lower() in ("", "n/a", "none", "unknown"):
            return None
        return pv is not None and norm(pv) == norm(gv)

    r["service"] = cmp("service", gt.get("service"), pred.get("service"))
    r["cve"] = cmp("cve", gt.get("cve"), pred.get("cve"))
    r["vulnerable"] = cmp("vulnerable", gt.get("vulnerable"), pred.get("vulnerable"))
    r["attack_outcome"] = cmp("attack_outcome", gt.get("attack_outcome"), pred.get("attack_outcome"))
    return r


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("subsets", nargs="+", default=["Public", "IDS"])
    ap.add_argument("--limit", type=int, default=0, help="仅跑前 N 个事件（验证用）")
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--no-retry", action="store_false", dest="retry", default=True,
                    help="解析失败时自动重跑一次（默认开，v1.1 调优）")
    ap.add_argument("--resume", default="")
    args = ap.parse_args()

    ts = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    outdir = args.resume and os.path.dirname(args.resume) or os.path.join(RESULTS, ts)
    os.makedirs(outdir, exist_ok=True)
    jl = args.resume or os.path.join(outdir, "benchmark.jsonl")
    done_events = set()
    if args.resume and os.path.exists(jl):
        for line in open(jl, encoding="utf-8"):
            try:
                done_events.add(json.loads(line)["event_key"])
            except Exception:
                pass
        print(f"断点续跑: 已完成 {len(done_events)} 条")

    rows = []
    for ds in args.subsets:
        tasks = load_tasks(ds)
        for i, t in enumerate(tasks):
            key = f"{ds}/{t['event']}"
            if args.limit and len(rows) >= args.limit and not args.resume:
                break
            if key in done_events:
                continue
            pcap = os.path.join(DS_DIR, ds, "raw", f"eventID_{t['event']}", f"{ds}_eventID_{t['event']}.pcap")
            if not os.path.exists(pcap):
                print(f"[skip] {key}: pcap 缺失")
                continue
            print(f"[{dt.datetime.now().strftime('%H:%M:%S')}] {key} 分析中…", flush=True)
            attempts = 2 if args.retry else 1
            row = None
            for attempt in range(attempts):
                out = run_agent(pcap, args.timeout)
                if out.startswith("<TIMEOUT>"):
                    row = {"event_key": key, "ds": ds, "event": t["event"], "ground_truth": t,
                           "verdict": None, "scores": score(t, None), "error": "timeout",
                           "output": "", "_t": time.time(), "attempts": attempt + 1}
                    break
                pred = parse_verdict(out)
                if pred is not None or attempt == attempts - 1:
                    row = {"event_key": key, "ds": ds, "event": t["event"], "ground_truth": t,
                           "verdict": pred, "scores": score(t, pred), "output": out[-2000:],
                           "_t": time.time(), "attempts": attempt + 1}
                    break
                print(f"  → 解析失败，自动重跑…", flush=True)
            rows.append(row)
            with open(jl, "a", encoding="utf-8") as f:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
            ok = sum(1 for k in ("service", "cve", "vulnerable", "attack_outcome")
                     if row["scores"].get(k) is True)
            print(f"  → parsed={row['scores']['parsed']} 命中 {ok}/4  {t.get('service')} | {t.get('attack_outcome')}")

    # 汇总
    n = len(rows)
    if n == 0:
        print("无新结果")
        return 0
    fields = ("service", "cve", "vulnerable", "attack_outcome")
    acc = {}
    for f in fields:
        vals = [r["scores"].get(f) for r in rows]
        denom = sum(1 for v in vals if v is not None)
        acc[f] = (sum(1 for v in vals if v is True) / denom) if denom else None
    outcomes = {}
    for r in rows:
        g = norm(r["ground_truth"].get("attack_outcome"))
        p = norm(r["verdict"].get("attack_outcome")) if r["verdict"] else "?"
        outcomes.setdefault(g, {"tp": 0, "n": 0})
        outcomes[g]["n"] += 1
        if p == g:
            outcomes[g]["tp"] += 1
    macro_f1 = sum(v["tp"] / v["n"] for v in outcomes.values()) / len(outcomes) if outcomes else 0
    parsed_rate = sum(1 for r in rows if r["scores"]["parsed"]) / n
    summary = {
        "timestamp": ts, "n": n, "subsets": args.subsets,
        "accuracy": acc, "attack_outcome_macro_f1": macro_f1,
        "verdict_parsed_rate": parsed_rate,
        "per_outcome": {k: v for k, v in outcomes.items()},
        "error_counts": {e: sum(1 for r in rows if r.get("error") == e) for e in ("timeout", "no_verdict")},
    }
    with open(os.path.join(outdir, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print("\n=== 汇总 ===")
    for f in fields:
        print(f"  {f:14s} acc = {acc[f]:.2%}")
    print(f"  attack_outcome macro-F1 = {macro_f1:.2%}")
    print(f"  verdict 解析率 = {parsed_rate:.2%}")
    print(f"  结果: {os.path.join(outdir, 'benchmark.jsonl')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
