#!/usr/bin/env python3
"""独立 LLDB 探针：从运行中的微信进程里捕获 SQLCipher 数据库密钥。

用法（需要 root）：

    # 1. 重启微信，让数据库连接重新建立（连接是长期持有的，
    #    不重启的话下面这个断点挂多久都不会被命中）
    killall WeChat; open -a WeChat
    sleep 5

    # 2. 挂探针
    sudo WX_DB_DIR="$HOME/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/<wxid>/db_storage" \
         WX_CAPTURE_OUT=/tmp/wx-keys.txt \
         WX_CAPTURE_SECONDS=120 \
         lldb -p "$(pgrep -x WeChat)" --batch \
         -o "command script import $(pwd)/capture-keys.py" \
         -o "process continue"

    # 3. 输出里每行是一个 64 位 hex，即某个库的 enc_key

原理见 README.md。这个脚本本身不落任何 passphrase 到磁盘，
只把推导出来的 enc_key 写进 WX_CAPTURE_OUT。
"""
import hashlib
import lldb
import os
import threading
import time

OUT = os.environ.get("WX_CAPTURE_OUT", "/tmp/wx-keys.txt")
SECONDS = int(os.environ.get("WX_CAPTURE_SECONDS", "120"))
DB_DIR = os.environ.get("WX_DB_DIR", "")

captured = set()
seen_passphrases = set()
_debugger = None


def _load_db_salts():
    """每个 .db 文件的前 16 字节就是它自己的 PBKDF2 salt。"""
    salts = []
    if not DB_DIR or not os.path.isdir(DB_DIR):
        return salts
    for root, _dirs, files in os.walk(DB_DIR):
        for fn in sorted(files):
            if not fn.endswith(".db"):
                continue
            try:
                with open(os.path.join(root, fn), "rb") as f:
                    salt = f.read(16)
            except OSError:
                continue
            if len(salt) == 16:
                salts.append(salt)
    return salts


DB_SALTS = _load_db_salts()


def _save(hx):
    if hx in captured:
        return
    captured.add(hx)
    try:
        with open(OUT, "a") as f:
            f.write(hx + "\n")
    except Exception:
        pass


def _derive_all(passphrase, rounds):
    for salt in DB_SALTS:
        try:
            hx = hashlib.pbkdf2_hmac("sha512", passphrase, salt, rounds, dklen=32).hex()
        except Exception:
            continue
        _save(hx)


def on_pbkdf(frame, bp_loc, _dict):
    """CCKeyDerivationPBKDF(algorithm, password, passwordLen, salt, saltLen,
                            prf, rounds, derivedKey, derivedKeyLen)
    arm64: x1=password, x2=passwordLen, x3=salt, x4=saltLen, x5=prf, x6=rounds
    """
    try:
        process = frame.GetThread().GetProcess()
        x1 = frame.FindRegister("x1").GetValueAsUnsigned()
        x2 = frame.FindRegister("x2").GetValueAsUnsigned()
        x6 = frame.FindRegister("x6").GetValueAsUnsigned()
        if not x1 or not x2 or x2 > 256:
            return False
        err = lldb.SBError()
        data = process.ReadMemory(x1, x2, err)
        if not err.Success() or not data or len(data) != x2:
            return False
        pw = bytes(data)
        if x6 == 2 and x2 == 32:
            # 派生 mac_key 的那次调用，password 参数直接就是该库的 enc_key
            print("[capture] enc_key via mac_key derivation", flush=True)
            _save(pw.hex())
        elif x6 >= 1000 and pw not in seen_passphrases:
            # 派生 enc_key 的那次调用，password 是 raw passphrase
            seen_passphrases.add(pw)
            print("[capture] passphrase rounds=%d -> deriving per-db keys" % x6, flush=True)
            _derive_all(pw, x6)
    except Exception as e:
        print("[capture] err " + str(e), flush=True)
    return False


def _finish():
    time.sleep(SECONDS)
    try:
        if _debugger is not None:
            _debugger.HandleCommand("process detach")
            _debugger.HandleCommand("quit")
    except Exception as e:
        print("[capture] detach err " + str(e), flush=True)


def __lldb_init_module(debugger, _internal_dict):
    global _debugger
    _debugger = debugger
    target = debugger.GetSelectedTarget()
    if not target or not target.IsValid():
        print("[capture] no valid target", flush=True)
        return
    print("[capture] 载入 %d 个库 salt" % len(DB_SALTS), flush=True)
    bp = target.BreakpointCreateByName("CCKeyDerivationPBKDF")
    n = bp.GetNumLocations()
    if n == 0:
        print("[capture] 找不到 CCKeyDerivationPBKDF 断点", flush=True)
        return
    bp.SetScriptCallbackFunction(__name__ + ".on_pbkdf")
    bp.SetAutoContinue(True)
    print("[capture] CCKeyDerivationPBKDF locs=%d，等待 %ds -> %s" % (n, SECONDS, OUT),
          flush=True)
    open(OUT, "w").close()
    threading.Thread(target=_finish, daemon=True).start()
