# testdata/sample-traffic.pcap 流量安全分析报告

- **分析日期**：2026-08-20 23:46 (Asia/Shanghai)
- **输入文件**：`testdata/sample-traffic.pcap`（10,429 字节，经典 pcap 格式）
- **抓包时间（+8）**：2026-08-20 23:13:01.839 ~ 23:15:03.399，时长 **121.6s**
- **包量**：112 包 / 8,613 字节，平均 0.9 pkt/s
- **分析工具**：`tools/pcap_analyze.py`（dpkt 概览）+ tshark 4.6.8（深挖，`C:\Program Files\Wireshark\tshark.exe`）

## 摘要

样本为一段 2 分钟的小型抓包，包含 **5 类行为**：1 类正常 HTTP 浏览，**4 类明确的恶意行为**——

1. **TCP 水平端口扫描**（10.0.0.5 → 192.168.1.10，连续 30 端口纯 SYN）；
2. **HTTP 登录爆破**（10.0.0.7 → 10.0.0.1:8080，12 次 POST /login 全 401）；
3. **C2 Beacon / 心跳**（10.0.0.8 → 203.0.113.9:4444，每 30s 精确周期）；
4. **DNS 隧道 + TXT 数据外传**（10.0.0.3 ↔ 8.8.8.8:53，40×'a' 超长子域 + 100B TXT 载荷）。

经与 `tools/make_test_traffic.py` 源码交叉验证，确认该样本为本地生成的测试流量，攻击场景与上述结论完全一致。

## 一、协议统计

```
Protocol Hierarchy (tshark -z io,phs)
frame                                  112 帧 / 8,613 B
  eth                                 112 帧 / 8,613 B
    ip（全部 IPv4）                    112 帧 / 8,613 B
      tcp                              105 帧 / 7,586 B   (IP proto 6)
        http                            30 帧 / 3,488 B
        data                             4 帧 /   264 B   (Beacon 载荷)
      udp                                7 帧 / 1,027 B   (IP proto 17)
        dns                              7 帧 / 1,027 B
```

- IP 协议号：TCP(6)=105，UDP(17)=7
- TCP 标志：SYN=68，ACK=56，PSH=34，**RST=0，FIN=0** —— 扫描与 Beacon 连接均只走到握手/首包，无正常关闭，符合恶意探测特征
- UDP 全部为 DNS（7 帧），无其它 UDP 业务

## 二、会话 TOP（tshark -z conv,tcp / conv,udp）

| 排序 | 会话（源 → 目的） | 帧数 | 说明 |
|---|---|---|---|
| 1 | 10.0.0.2:40000~40002 ↔ 93.184.216.34:80 | 15 | 正常 HTTP 浏览（example.com，3 次 GET /index.html 均 200） |
| 2 | 10.0.0.7:30000~30011 ↔ 10.0.0.1:8080 | 48 | **HTTP 登录爆破**（12 个独立连接，各 4 帧） |
| 3 | 10.0.0.5:50000 → 192.168.1.10:1024~1053 | 30 | **端口扫描**（30 个纯 SYN，无任何响应） |
| 4 | 10.0.0.3:53000~53005 ↔ 8.8.8.8:53 | 7 | **DNS 隧道**（6 查询 + 1 响应） |
| 5 | 10.0.0.8:60000~60003 ↔ 203.0.113.9:4444 | 12 | **C2 Beacon**（4 轮，每 30s 一轮） |

IP 端点（tshark -z endpoints,ip）按包量：10.0.0.7/10.0.0.1 各 48 帧（爆破），10.0.0.5/192.168.1.10 各 30 帧（扫描），10.0.0.2/93.184.216.34 各 15 帧（正常浏览），10.0.0.8/203.0.113.9 各 12 帧（Beacon），10.0.0.3/8.8.8.8 各 7 帧（DNS）。

## 三、可疑行为清单

### 1. TCP 端口扫描（高置信度）
- **来源**：10.0.0.5:50000 → **192.168.1.10**（内网横向探测）
- **证据**：帧 16~45，对 **1024~1053 共 30 个连续端口**发送纯 SYN（`syn=1, ack=0`），每 2ms 一个；**零响应**（无 SYN-ACK 也无 RST）；TTL=64、窗口=8192 完全一致（单一扫描工具指纹）
- **判定**：水平端口扫描 / 内网侦察，未发现存活端口
- **验证命令**：
  ```
  tshark -r testdata/sample-traffic.pcap -Y "tcp.flags.syn==1 && tcp.flags.ack==0" -T fields -e ip.src -e ip.dst -e tcp.dstport
  ```

### 2. HTTP 登录暴力破解（高置信度）
- **来源**：10.0.0.7 → **10.0.0.1:8080** `/login`
- **证据**：帧 48~93，**12 次 POST /login**，固定 80ms 间隔，每个新源端口重试；请求体为 `user=admin&pass=try0` ~ `try9`（密码字典化枚举）；**服务端全部返回 401 Unauthorized** —— 破解未成功
- **判定**：针对管理后台 admin 账户的口令爆破
- **验证命令**：
  ```
  tshark -r testdata/sample-traffic.pcap -Y "http.request.method==POST" -T fields -e http.request.uri -e http.file_data -e http.response.code
  ```

### 3. C2 Beacon / 心跳（高置信度）
- **来源**：10.0.0.8 → **203.0.113.9:4444**（4444 为 Metasploit 默认监听端口）
- **证据**：帧 101~112，**4 轮连接，周期精确 30s**（31.48 / 61.50 / 91.52 / 121.54s）；每轮 SYN→SYN/ACK→ACK+12B 载荷 `00 01 02 68 65 61 72 74 62 65 61 74`（`\x00\x01\x02heartbeat`）
- **周期性佐证**：`-z io,stat,30` 显示 30~60s、60~90s、90~120s、120~Dur 各区间恰好 **3 帧 / 174B**
- **判定**：受控主机向 C2 服务器发送的**固定周期信标/心跳**，端口 4444 + "heartbeat" 载荷高度符合远控/木马特征
- **验证命令**：
  ```
  tshark -r testdata/sample-traffic.pcap -Y "tcp.port==4444" -T fields -e frame.time_relative -e ip.src -e ip.dst -e tcp.payload
  tshark -r testdata/sample-traffic.pcap -q -z io,stat,30
  ```

### 4. DNS 隧道 + TXT 数据外传（高置信度）
- **来源**：10.0.0.3 ↔ **8.8.8.8:53**
- **证据**：
  - 帧 94~99：6 个 A 查询，查询名 = **40×'a' + 序号 0~5 + `.tunnel.example.com`**（单标签 40+ 字符，远超正常域名长度，典型 DNS 隧道编码格式）；
  - 帧 100：响应携带 **TXT 记录 `exfil.example.com`，内容 100 字节 `ZZZZ…`**（数据经 TXT 记录回传）
- **判定**：疑似**DNS 隧道通道建立**（子域编码数据上行）+ **TXT 记录数据外传**（下行）
- **验证命令**：
  ```
  tshark -r testdata/sample-traffic.pcap -Y dns -T fields -e dns.qry.name -e dns.txt
  ```

### 5. 正常流量（对照组）
- 10.0.0.2 三次 `GET /index.html` → 93.184.216.34:80（example.com），均返回 200，正文 `hello` —— 正常网页浏览，无异常

## 四、结论与建议

**结论**：该 pcap 为一份包含 **4 类明确恶意行为**的安全测试样本（端口扫描 / HTTP 爆破 / C2 Beacon / DNS 隧道外传），另有 1 类正常 HTTP 流量。内网主机 10.0.0.5、10.0.0.7、10.0.0.8、10.0.0.3 分别扮演扫描器、爆破源、受控端（Bot）、隧道客户端。

**建议**：
1. **主机排查**：对 10.0.0.5 / 10.0.0.7 / 10.0.0.8 / 10.0.0.3 四台主机做进程、计划任务、自启动项与已建立连接排查，重点查 4444 端口回连与 DNS 隧道进程。
2. **边界/内网防护**：出站方向封禁非常见端口回连（如 4444），限制内网到外网 DNS 的非 53 端口/超长查询名流量；IDS/IPS 增加规则——同源 SYN 高扇出、DNS 查询名 > 40 字符或 QPS 异常、同账号连续 401。
3. **应用加固**：10.0.0.1:8080 管理后台应启用账户锁定策略、双因素认证与登录限速，避免弱口令爆破。
4. **监控完善**：开启全流量留存与 DNS 日志审计，对 `*.tunnel.example.com` 类域名及 TEST-NET-3（203.0.113.0/24）等保留地址回连告警。
5. **样本管理**：本样本由 `tools/make_test_traffic.py` 生成，可纳入安全检测规则回归测试集，验证扫描/爆破/Beacon/隧道规则的告警准确率。

## 附：证据命令汇总

```powershell
# 1) 概览
python tools/pcap_analyze.py testdata/sample-traffic.pcap

# 2) 协议树 / 会话 / 端点 / 时间分布
tshark -r testdata/sample-traffic.pcap -q -z io,phs
tshark -r testdata/sample-traffic.pcap -q -z conv,tcp -z conv,udp
tshark -r testdata/sample-traffic.pcap -q -z endpoints,ip
tshark -r testdata/sample-traffic.pcap -q -z io,stat,30

# 3) 深挖各场景
tshark -r testdata/sample-traffic.pcap -Y "tcp.flags.syn==1 && tcp.flags.ack==0" -T fields -e ip.src -e ip.dst -e tcp.dstport
tshark -r testdata/sample-traffic.pcap -Y "http.request.method==POST" -T fields -e http.request.uri -e http.file_data -e http.response.code
tshark -r testdata/sample-traffic.pcap -Y "tcp.port==4444" -T fields -e frame.time_relative -e ip.src -e ip.dst -e tcp.payload
tshark -r testdata/sample-traffic.pcap -Y dns -T fields -e dns.qry.name -e dns.txt
```
