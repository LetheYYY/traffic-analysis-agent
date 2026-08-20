@echo off
rem 流量分析 Agent · 批处理版（headless，一次性任务）
rem 用法: agent-hl.bat "分析 testdata/sample-traffic.pcap"
rem 工作区 = 本目录(C:\workspace\dsr)；API Key 已在 Web UI 配置(共用凭据)
cd /d "C:\workspace\dsr"
set TSX_TSCONFIG_PATH=C:\workspace\dsr\deepseek-harness-master\deepseek-harness-master\tsconfig.json
node --import tsx/esm "C:\workspace\dsr\deepseek-harness-master\deepseek-harness-master\apps\cli\src\bin.ts" --profile traffic-agent-hl %*
