@echo off
rem 流量分析 Agent · 交互版（Web UI）
rem 用法: agent-web.bat   （浏览器打开 http://127.0.0.1:3080，需在 设置→模型 配置 DeepSeek API Key）
cd /d "C:\workspace\dsr"
set TSX_TSCONFIG_PATH=C:\workspace\dsr\deepseek-harness-master\deepseek-harness-master\tsconfig.json
node --import tsx/esm "C:\workspace\dsr\deepseek-harness-master\deepseek-harness-master\apps\cli\src\bin.ts" --profile traffic-agent
