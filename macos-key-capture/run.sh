#!/bin/bash
# 一条龙：重启微信 -> LLDB 抓 passphrase -> 派生全部 enc_key -> 写 wx-cli 的 all_keys.json
#
# 用法：
#   WX_DB_DIR="$HOME/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/<wxid>/db_storage" \
#     bash run.sh
#
# 需要 sudo（llbd attach 到微信要 root）。抓取阶段会在微信里产生一次短暂停顿，属正常。
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
DB_DIR="${WX_DB_DIR:-}"
OUT="${WX_CAPTURE_OUT:-$HOME/.wx-cli/captured-keys.txt}"
WX_KEYS="${WX_KEYS_JSON:-$HOME/.wx-cli/all_keys.json}"
HOOK_SECONDS="${WX_CAPTURE_SECONDS:-120}"

if [ -z "$DB_DIR" ]; then
  echo "需要设置 WX_DB_DIR 指向微信的 db_storage 目录" >&2
  exit 1
fi

echo "== 1/4 重启微信（不重启的话 PBKDF 断点不会被命中：连接是长期持有的）=="
killall WeChat 2>/dev/null || true
sleep 2
open -a WeChat
sleep 5
PID=$(pgrep -x WeChat | head -1)
if [ -z "$PID" ]; then
  echo "微信没起来，中止" >&2
  exit 1
fi
echo "   WeChat PID=$PID"

echo "== 2/4 挂 LLDB 探针 ${HOOK_SECONDS}s =="
sudo WX_DB_DIR="$DB_DIR" WX_CAPTURE_OUT="$OUT" WX_CAPTURE_SECONDS="$HOOK_SECONDS" \
  lldb -p "$PID" --batch \
  -o "command script import $HERE/capture-keys.py" \
  -o "process continue"

if [ ! -s "$OUT" ]; then
  echo "没抓到任何候选密钥。" >&2
  echo "确认微信在抓取期间有访问数据库（打开几个会话），且确实重启过。" >&2
  exit 1
fi
chmod 600 "$OUT" 2>/dev/null || true
echo "   候选密钥 $(wc -l < "$OUT" | tr -d ' ') 个 -> $OUT"

echo "== 3/4 这些候选就是 enc_key（rounds=2 那次调用的 password）=="
echo "   如需从 passphrase 重新派生，脚本见 derive-keys.py"

echo "== 4/4 完成 =="
echo "   候选密钥：$OUT"
echo "   注意：该文件等同于你的整个微信，权限已设为 600，别同步、别备份到云端。"
