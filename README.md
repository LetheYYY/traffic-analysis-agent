# 流量分析 Agent（Traffic Analysis Agent）

基于 [DeepSeek Harness (dsh)](https://github.com/deepseek-ai/deepseek-harness) 构建的专用流量安全分析智能体：输入 pcap/pcapng 抓包文件，自动完成协议统计、会话追踪、攻击特征识别与取证报告，并归档到 Obsidian 知识库。

## 功能特性

- **全自动分析流水线**：Agent 自主调用工具链完成 概览 → 协议树/会话统计 → 可疑行为深挖 → 中文取证报告
- **攻击特征检测**：端口扫描 / 暴力破解 / C2 Beacon / DNS 隧道 / 数据外传 / ARP 欺骗等（dpkt 流式脚本 + tshark 深挖）
- **大包快扫**：`--quick` 模式，8.59GB / 1140 万包级别可在数分钟内出概览（VLAN/QinQ 自动解封装）
- **批量评测**：Net4n6Bench 基准，headless 批量跑事件 → 结构化 verdict → 对照 ground truth 打分（支持断点续跑、超时进程树击杀、解析失败自动重跑）
- **实时监控**：独立终端窗口实时显示评测进度与指标
- **Obsidian 归档**：分析报告 / 运行记录 / 项目总览自动同步（含 Mermaid 图表）

## 快速开始

前置条件：Node.js ≥ 22.19、Python 3.11+、[TShark](https://www.wireshark.org/)（`C:\Program Files\Wireshark\tshark.exe`）。

```bash
# 1. 部署 dsh 源码（未入库，需自行拉取构建）：
#    git clone https://github.com/deepseek-ai/deepseek-harness.git deepseek-harness-master/deepseek-harness-master
#    cd deepseek-harness-master/deepseek-harness-master && pnpm install && pnpm run build

# 2. 配置 DeepSeek API Key（二选一）
#    a) Web UI：设置 → 模型 → 填入 Key
#    b) 环境变量：set DEEPSEEK_API_KEY=sk-xxx

# 3. 交互分析（Web UI）
agent-web.bat

# 4. 批处理分析（headless，适合脚本/CI/批量）
agent-hl.bat "分析 testdata/sample-traffic.pcap"

# 5. 生成测试流量 / 拉取评测数据集 / 批量评测 / 实时监控
python tools/make_test_traffic.py
python tools/fetch_net4n6bench.py Public IDS
python tools/run_benchmark.py IDS
python tools/benchmark_watch.py
```

> 启动器保证进程 cwd = 项目根（Agent 工作区 = 本项目），并通过 `TSX_TSCONFIG_PATH` 让 tsx 正确解析 dsh 的 workspace 包。

## 架构

```
使用层   Web UI :3080  /  headless CLI
配置层   traffic-agent profile (base + web-app)
        traffic-agent-hl profile (base + headless)
内核层   dsh：agent loop · 会话日志 · 沙箱与审批 · 模型路由 · 事件系统
能力层   traffic-analysis 技能（自动发现自 ~/.agents/skills）
        tshark / scapy / dpkt 工具链（shell 直接调用）
外部     DeepSeek API · TShark · Python 3.11 · Obsidian vault
```

技能文件（`~/.agents/skills/traffic-analysis/SKILL.md`）内含：分析 SOP、tshark 命令库、攻击特征 Checklist、判定规范（CVE 定稿前比对 / service 命名粒度 / attack_outcome 证据强度）、Obsidian 归档规范。

## 工具链

| 脚本 | 用途 |
|---|---|
| `tools/pcap_analyze.py` | dpkt 流式概览：包量/时间/协议/端口/会话/标志 + 攻击特征检出；`--quick` 大包模式 |
| `tools/make_test_traffic.py` | 生成含 5 类攻击特征的测试 pcap（testdata/sample-traffic.pcap） |
| `tools/fetch_net4n6bench.py` | 下载 Net4n6Bench 评测数据集（benchmark/Net4n6Bench/） |
| `tools/run_benchmark.py` | 批量评测：headless 跑事件 → verdict 解析 → 对照打分（resume/retry/超时树杀） |
| `tools/benchmark_watch.py` | 实时监控窗口（进度/指标/最近事件） |

## 评测结果（Net4n6Bench，IDS-25 公平口径：GT 缺失字段不评分）

![Accuracy v1 vs v1.1](docs/charts/accuracy-comparison.svg)

| 指标 | v1 基线 | v1.1（技能调优后） |
|---|---|---|
| service 准确率 | 60% | **80%** |
| cve 准确率 | 72% | **84%** |
| vulnerable 准确率 | 86% | **100%** |
| attack_outcome 准确率 | 64% | **84%** |
| 四字段全中 | 1/25 | **4/25** |
| verdict 解析率 | 21/25 | **23/25** |

调优方式：不换模型、不加工具，仅通过**技能 Checklist + 评测提示词**两处最小改动（同族 CVE 区分、service 粒度、outcome 证据强度、输出格式约束、解析失败重跑、非 HTTP 协议提示）。

📊 **完整图表对比与深度分析见 [BENCHMARK.md](BENCHMARK.md)**（5 张图：四字段对比 / 命中分布 / outcome 判定 / 残留失败 / 类别对比）。

## 已知限制

- 面向 Windows + DeepSeek API；dsh 的 Python SDK 不支持 Windows（官方仅 Linux/macOS）
- nfstream 在本机无法加载（Npcap 兼容问题），离线解析使用 dpkt/pyshark/tshark
- pcapkit 无 PyPI 包，未安装
- dsh 为开发者预览版（0.1.0-rc.8），升级需重新 `pnpm install && pnpm run build`

## 致谢（参考的开源项目）

本项目站在以下开源项目之上，特此致谢：

| 项目 | 用途 |
|---|---|
| [deepseek-ai/deepseek-harness](https://github.com/deepseek-ai/deepseek-harness) | Agent 底座框架（一切皆插件，MIT） |
| [bmthanh/Net4n6Bench](https://github.com/bmthanh/Net4n6Bench) | 评测基准：真实攻击流量数据集 + ground truth + verdict 评分范式 |
| [jus1-c/network-forensics-mcp-server](https://github.com/jus1-c/network-forensics-mcp-server) | 取证 MCP 设计参考（证据索引 / triage / 有界 tshark 执行） |
| [automateyournetwork/packet_buddy](https://github.com/automateyournetwork/packet_buddy) | LLM+tshark 有界执行设计参考 |
| [Pcapchu/Pcapchu](https://github.com/Pcapchu/Pcapchu) | pcap → 结构化日志 → 查询的取证流水线架构参考 |
| [nfstream/nfstream](https://github.com/nfstream/nfstream) | 网络流特征分析框架参考 |
| [stratosphereips/StratosphereLinuxIPS](https://github.com/stratosphereips/StratosphereLinuxIPS) | 行为检测（SLIPS）参考 |
| [activecm/rita](https://github.com/activecm/rita) | Beacon / DNS 隧道检测思路参考 |
| [odedshimon/BruteShark](https://github.com/odedshimon/BruteShark)、[zeek/zeek](https://github.com/zeek/zeek)、[cisagov/Malcolm](https://github.com/cisagov/Malcolm) | 网络流量分析工具调研参考 |
| [Yara-Rules/rules](https://github.com/Yara-Rules/rules) | YARA 规则集参考（可选集成） |
| [Wireshark/TShark](https://www.wireshark.org/) | 包解析引擎 |
| [coddingtonbear/obsidian-local-rest-api](https://github.com/coddingtonbear/obsidian-local-rest-api) | Obsidian API 集成方案参考 |

## 未入库内容说明

- `deepseek-harness-master/`（dsh 源码 + node_modules，约 1GB）不入库，见快速开始部署步骤
- `benchmark/`（Net4n6Bench 数据集，第三方许可不明）与 `testdata/`（生成的测试包）不入库，由脚本自动拉取/生成
- 评测结果汇总见 README 表格；逐事件明细可本地复现（`tools/run_benchmark.py`）
