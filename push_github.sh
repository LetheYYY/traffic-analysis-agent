#!/usr/bin/env bash
# 一次性脚本：创建 GitHub 私有仓库并推送本仓库（需环境变量 GITHUB_TOKEN）
# 用法: GITHUB_TOKEN=xxx bash push_github.sh
set -euo pipefail
cd "$(dirname "$0")"

TOKEN="${GITHUB_TOKEN:?需要 GITHUB_TOKEN 环境变量}"
REPO_NAME="traffic-analysis-agent"
DESC="DeepSeek Harness based traffic analysis agent: pcap analysis, attack detection, Net4n6Bench benchmark, Obsidian archiving"

echo "== 1/3 验证 Token =="
USER=$(curl -s -H "Authorization: Bearer $TOKEN" https://api.github.com/user | python -c "import json,sys; print(json.load(sys.stdin).get('login',''))")
[ -n "$USER" ] || { echo "Token 无效"; exit 1; }
echo "账号: $USER"

echo "== 2/3 创建仓库（若不存在）=="
RESP=$(curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/vnd.github+json" \
  https://api.github.com/user/repos \
  -d "{\"name\":\"$REPO_NAME\",\"description\":\"$DESC\",\"private\":true}")
echo "$RESP" | python -c "import json,sys; d=json.load(sys.stdin); print('仓库:', d.get('full_name') or ('已存在/错误: '+str(d.get('message'))))"

echo "== 3/3 推送 =="
git remote remove origin 2>/dev/null || true
git remote add origin "https://github.com/$USER/$REPO_NAME.git"
git push "https://oauth2:${TOKEN}@github.com/$USER/$REPO_NAME.git" main 2>&1 | tail -4
echo "== 完成: https://github.com/$USER/$REPO_NAME =="
