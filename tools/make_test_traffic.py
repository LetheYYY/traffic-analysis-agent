#!/usr/bin/env python3
"""生成带攻击特征的测试流量 pcap（供流量分析 Agent 自测）。

生成 testdata/sample-traffic.pcap，包含:
  - 正常流量: TCP 握手 + HTTP GET
  - 端口扫描: 单源 SYN-only 探多个端口
  - 爆破迹象: 多次 HTTP POST /login（401）
  - DNS 隧道迹象: 长子域名查询 + 大 TXT 记录
  - 可疑外联: 固定间隔(30s) beacon 连接
时间戳从基准时间开始累计，便于 beacon 周期检测。
"""
from __future__ import annotations

import os
import time

from scapy.all import (
    DNS, DNSQR, DNSRR, Ether, IP, Raw, TCP, UDP, wrpcap,
)

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(os.path.dirname(HERE), "testdata", "sample-traffic.pcap")
os.makedirs(os.path.dirname(OUT), exist_ok=True)

GATEWAY_MAC = "00:1a:2b:3c:4d:0e"
HOST_MACS = {
    "10.0.0.1": "00:1a:2b:3c:4d:01",
    "10.0.0.2": "00:1a:2b:3c:4d:02",
    "10.0.0.3": "00:1a:2b:3c:4d:03",
    "10.0.0.5": "00:1a:2b:3c:4d:05",
    "10.0.0.7": "00:1a:2b:3c:4d:07",
    "10.0.0.8": "00:1a:2b:3c:4d:08",
}


def mac_of(ip: str) -> str:
    return HOST_MACS.get(ip, "00:1a:2b:3c:4d:ff")


pkts: list = []
t = time.time() - 600  # 基准时间: 10 分钟前


def add(pkt, gap: float = 0.0):
    global t
    t += gap
    pkt.time = t
    pkts.append(pkt)


def l3(pkt):
    """给 IP 包加以太网头（按源 IP 选 MAC）。"""
    src = pkt.src
    return Ether(src=mac_of(src), dst=GATEWAY_MAC) / pkt


# --- 1. 正常: HTTP GET 到公网站点 -------------------------------------------
for i in range(3):
    add(l3(IP(src="10.0.0.2", dst="93.184.216.34") / TCP(sport=40000 + i, dport=80, flags="S")), 0.1)
    add(l3(IP(src="93.184.216.34", dst="10.0.0.2") / TCP(sport=80, dport=40000 + i, flags="SA")), 0.01)
    add(l3(IP(src="10.0.0.2", dst="93.184.216.34") / TCP(sport=40000 + i, dport=80, flags="A")), 0.01)
    add(l3(IP(src="10.0.0.2", dst="93.184.216.34") / TCP(sport=40000 + i, dport=80, flags="PA")
           / Raw(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")), 0.01)
    add(l3(IP(src="93.184.216.34", dst="10.0.0.2") / TCP(sport=80, dport=40000 + i, flags="PA")
           / Raw(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")), 0.01)

# --- 2. 端口扫描: 10.0.0.5 SYN 探测 30 个端口 ---------------------------------
for port in range(1024, 1054):
    add(l3(IP(src="10.0.0.5", dst="192.168.1.10") / TCP(sport=50000, dport=port, flags="S")), 0.002)

# --- 3. 爆破迹象: 12 次 POST /login（401） ------------------------------------
for i in range(12):
    add(l3(IP(src="10.0.0.7", dst="10.0.0.1") / TCP(sport=30000 + i, dport=8080, flags="S")), 0.05)
    add(l3(IP(src="10.0.0.1", dst="10.0.0.7") / TCP(sport=8080, dport=30000 + i, flags="SA")), 0.01)
    add(l3(IP(src="10.0.0.7", dst="10.0.0.1") / TCP(sport=30000 + i, dport=8080, flags="PA")
           / Raw(f"POST /login HTTP/1.1\r\nHost: 10.0.0.1:8080\r\nContent-Length: 20\r\n\r\nuser=admin&pass=try{i}")), 0.01)
    add(l3(IP(src="10.0.0.1", dst="10.0.0.7") / TCP(sport=8080, dport=30000 + i, flags="PA")
           / Raw(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")), 0.01)

# --- 4. DNS 隧道迹象: 长子域名查询 + 大 TXT ------------------------------------
for i in range(6):
    sub = "a" * 40 + str(i)
    add(l3(IP(src="10.0.0.3", dst="8.8.8.8") / UDP(sport=53000 + i, dport=53)
           / DNS(rd=1, qd=DNSQR(qname=f"{sub}.tunnel.example.com"))), 0.02)
add(l3(IP(src="8.8.8.8", dst="10.0.0.3") / UDP(sport=53, dport=53000)
       / DNS(qr=1, aa=1, qd=DNSQR(qname="exfil.example.com"),
             ar=DNSRR(rrname="exfil.example.com", type=16, rdata=b"Z" * 200))), 0.02)

# --- 5. Beacon: 10.0.0.8 每 30s 连 203.0.113.9:4444 ---------------------------
for i in range(4):
    add(l3(IP(src="10.0.0.8", dst="203.0.113.9") / TCP(sport=60000 + i, dport=4444, flags="S")), 30.0)
    add(l3(IP(src="203.0.113.9", dst="10.0.0.8") / TCP(sport=4444, dport=60000 + i, flags="SA")), 0.01)
    add(l3(IP(src="10.0.0.8", dst="203.0.113.9") / TCP(sport=60000 + i, dport=4444, flags="PA")
           / Raw(b"\x00\x01\x02heartbeat")), 0.01)

wrpcap(OUT, pkts)
print(f"已生成: {OUT}  ({len(pkts)} 包, 基准时间 {time.strftime('%H:%M:%S', time.localtime(t - 90))} 起)")
