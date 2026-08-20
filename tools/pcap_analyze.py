#!/usr/bin/env python3
"""pcap/pcapng 流式概览分析（dpkt 实现，大文件秒级）。

用法:
    python tools/pcap_analyze.py <file.pcap|file.pcapng> [--top N]

输出: 包量 / 时间范围 / 协议构成 / 端口 TOP / 会话 TOP / TCP 标志 / 可疑特征提示。
自动适配 Ethernet / RAW 链路类型; VLAN 标签 (0x8100/0x88a8) 自动解封装。
"""
from __future__ import annotations

import argparse
import collections
import datetime as dt
import os
import socket
import sys

try:
    import dpkt
except ImportError:
    sys.exit("缺少 dpkt: pip install dpkt")

TZ = dt.timezone(dt.timedelta(hours=8), "Asia/Shanghai")
DLT_EN10MB = 1
DLT_RAW = 101        # Linux cooked? 实为 DLT_RAW
DLT_RAW_BSD = 12
DLT_LOOP = 108
TCP_FLAGS = {"SYN": 0x02, "ACK": 0x10, "RST": 0x04, "FIN": 0x01, "PSH": 0x08}


def open_reader(path: str):
    """返回 (reader, linktype)。"""
    with open(path, "rb") as f:
        head = f.read(4)
    if head in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
        r = dpkt.pcap.Reader(open(path, "rb"))
        return r, r.datalink()
    r = dpkt.pcapng.Reader(open(path, "rb"))
    try:
        return r, r.datalink()
    except Exception:
        return r, DLT_EN10MB


def parse_frame(linktype: int, buf: bytes):
    """返回 (ethertype, payload)；RAW 链路直接返回 IP 协议号与载荷。
    802.1Q/QinQ VLAN 标签手工剥离（dpkt 可能不解析 VLAN 类）。"""
    if linktype == DLT_EN10MB:
        off = 0
        etype = int.from_bytes(buf[12:14], "big")
        while etype in (0x8100, 0x88A8) and len(buf) >= 18 + off:
            etype = int.from_bytes(buf[16 + off:18 + off], "big")
            off += 4
        if off:
            buf = buf[:12] + buf[12 + off:]
        eth = dpkt.ethernet.Ethernet(buf)
        etype, payload = eth.type, eth.data
        return etype, payload
    # RAW/LOOP: 载荷直接是 IP
    if buf[:1] == b"\x06" or (len(buf) > 0 and (buf[0] >> 4) == 6):
        return 0x86DD, dpkt.ip6.IP6(buf)
    return 0x0800, dpkt.ip.IP(buf)


def ip_str(b) -> str:
    """dpkt 的 IP 地址是 bytes，转可读字符串。"""
    try:
        return socket.inet_ntoa(b) if len(b) == 4 else b.decode(errors="replace")
    except Exception:
        return repr(b)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--top", type=int, default=10)
    ap.add_argument("--quick", action="store_true",
                    help="轻量模式：跳过逐包 HTTP/DNS 深度解析（大包快速概览）")
    args = ap.parse_args()
    if not os.path.isfile(args.pcap):
        sys.exit(f"文件不存在: {args.pcap}")

    reader, linktype = open_reader(args.pcap)
    n = 0
    t0 = t1 = None
    proto_cnt = collections.Counter()
    ports = collections.Counter()
    conv = collections.Counter()
    flags = collections.Counter()
    syn_src_dstports = collections.defaultdict(set)
    http_methods = collections.Counter()
    dns_names = collections.Counter()
    dns_txt = collections.Counter()
    dns_q = 0
    beacon_candidates = collections.defaultdict(list)  # dst:port -> [ts]

    for ts, buf in reader:
        n += 1
        if t0 is None:
            t0 = t1 = ts
        t1 = max(t1, ts)
        try:
            etype, pkt = parse_frame(linktype, buf)
        except Exception:
            proto_cnt["解析失败"] += 1
            continue
        if etype == 0x0800 and isinstance(pkt, dpkt.ip.IP):
            ip = pkt
            proto_cnt[ip.p] += 1
            if ip.p == dpkt.ip.IP_PROTO_TCP:
                tcp = ip.data
                ports[("tcp", tcp.dport)] += 1
                conv[(ip.src, tcp.sport, ip.dst, tcp.dport)] += 1
                for name, val in TCP_FLAGS.items():
                    if tcp.flags & val:
                        flags[name] += 1
                if tcp.flags & 0x02 and not (tcp.flags & 0x10):
                    syn_src_dstports[ip.src].add(tcp.dport)
                if not args.quick and (tcp.dport in (80, 8080) or tcp.sport in (80, 8080)) and tcp.data:
                    try:
                        http = dpkt.http.Request(tcp.data)
                        if http.method:
                            http_methods[http.method] += 1
                    except Exception:
                        pass
            elif ip.p == dpkt.ip.IP_PROTO_UDP:
                udp = ip.data
                ports[("udp", udp.dport)] += 1
                conv[(ip.src, udp.sport, ip.dst, udp.dport)] += 1
                if (udp.dport == 53 or udp.sport == 53):
                    dns_q += 1
                    if args.quick:
                        continue
                    try:
                        dns = dpkt.dns.DNS(udp.data)
                        for q in dns.qd:
                            name = getattr(q, "name", None)
                            if name:
                                if isinstance(name, bytes):
                                    name = name.decode(errors="replace")
                                dns_names[str(name)] += 1
                        for rr in getattr(dns, "ar", []) or []:
                            if getattr(rr, "type", None) == dpkt.dns.DNS_TXT:
                                nm = rr.name
                                if isinstance(nm, bytes):
                                    nm = nm.decode(errors="replace")
                                dns_txt[str(nm)] += 1
                    except Exception:
                        pass
        elif etype == 0x86DD:
            proto_cnt["IPv6"] += 1
        else:
            proto_cnt[f"eth/0x{etype:04x}"] += 1
        # beacon 候选: 到同一 目的ip:port 的 SYN 时间序列（仅 IP/TCP 帧）
        if not args.quick and isinstance(pkt, dpkt.ip.IP) and isinstance(pkt.data, dpkt.tcp.TCP) and (pkt.data.flags & 0x02):
            beacon_candidates[(pkt.src, pkt.dst, pkt.data.dport)].append(ts)

    print(f"=== 概览: {os.path.basename(args.pcap)} ===")
    print(f"包数: {n}")
    if t0 is not None:
        print(f"时间范围(UTC): {dt.datetime.utcfromtimestamp(t0).isoformat()} ~ "
              f"{dt.datetime.utcfromtimestamp(t1).isoformat()}")
        print(f"时间范围(+8):  {dt.datetime.fromtimestamp(t0, TZ).isoformat()} ~ "
              f"{dt.datetime.fromtimestamp(t1, TZ).isoformat()}")
        dur = max(t1 - t0, 1e-9)
        print(f"时长: {dur:.1f}s  平均速率: {n / dur:.1f} pkt/s")

    print("\n=== 协议构成 (IP proto) ===")
    for k, v in proto_cnt.most_common(12):
        print(f"  {k}: {v}")

    print(f"\n=== 端口 TOP{args.top} ===")
    for (proto, port), v in ports.most_common(args.top):
        print(f"  {proto}/{port}: {v}")

    print(f"\n=== 会话 TOP{args.top} ===")
    for (s, sp, d, dp), v in conv.most_common(args.top):
        print(f"  {ip_str(s)}:{sp} -> {ip_str(d)}:{dp}  x{v}")

    print("\n=== TCP 标志计数 ===")
    print("  " + "  ".join(f"{k}={flags[k]}" for k in TCP_FLAGS))

    print("\n=== 可疑特征提示 ===")
    hits = 0
    for src, dstports in syn_src_dstports.items():
        if len(dstports) >= 10:
            print(f"  [扫描] {ip_str(src)} 对 {len(dstports)} 个目的端口发 SYN(无ACK)")
            hits += 1
    if http_methods:
        print(f"  [HTTP] 方法分布: {dict(http_methods)}")
        if http_methods.get("POST", 0) >= 10:
            print(f"  [爆破?] POST 请求达 {http_methods['POST']} 次")
            hits += 1
    for (src, dst, dport), ts_list in beacon_candidates.items():
        if len(ts_list) >= 3:
            gaps = [round(b - a, 1) for a, b in zip(ts_list, ts_list[1:])]
            if gaps and min(gaps) >= 2.0 and max(gaps) - min(gaps) <= 2.0:
                print(f"  [Beacon?] {ip_str(src)} -> {ip_str(dst)}:{dport} 周期 {len(ts_list)} 次, 间隔 {gaps}")
                hits += 1
    if dns_q:
        long = [k for k in dns_names if len(k) > 40]
        if long:
            print(f"  [隧道?] 超长域名: {long[:3]}")
            hits += 1
        if dns_txt:
            print(f"  [隧道?] TXT 记录: {dict(dns_txt.most_common(5))}")
            hits += 1
    if hits == 0:
        print("  （无明显可疑特征）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
