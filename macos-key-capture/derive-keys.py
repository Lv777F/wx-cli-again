#!/usr/bin/env python3
"""从 passphrase 派生所有库的 enc_key。

微信 4.x 用的就是标准 SQLCipher 4 两级派生：

    enc_key = PBKDF2-HMAC-SHA512(passphrase, 该库文件头前16字节, 256000 轮, 32B)
    mac_key = PBKDF2-HMAC-SHA512(enc_key,    salt ^ 0x3a,          2 轮,   32B)

所有库**共用同一个 passphrase**，各自用自己的 salt（= 文件头前 16 字节）。

输入：passphrase（64 位 hex）+ 数据目录。
输出：每个库的 enc_key。

    python3 derive-keys.py --passphrase <64hex> --db-dir <db_storage> [--json out.json]
"""
import argparse
import hashlib
import json
import os
import sys

ROUNDS = 256000
HASH = "sha512"


def derive(passphrase: bytes, salt: bytes, rounds: int = ROUNDS) -> str:
    return hashlib.pbkdf2_hmac(HASH, passphrase, salt, rounds, dklen=32).hex()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--passphrase", required=True,
                    help="64 位 hex 的 raw passphrase")
    ap.add_argument("--db-dir", required=True, help="微信的 db_storage 目录")
    ap.add_argument("--json", help="可选：把 <相对路径> -> enc_key 写成 JSON")
    args = ap.parse_args()

    try:
        passphrase = bytes.fromhex(args.passphrase.strip())
    except ValueError:
        sys.exit("passphrase 必须是 64 位十六进制字符串")

    db_dir = os.path.expanduser(args.db_dir)
    if not os.path.isdir(db_dir):
        sys.exit("数据目录不存在: %s" % db_dir)

    keys = {}
    for root, _dirs, files in os.walk(db_dir):
        for fn in sorted(files):
            if not fn.endswith(".db"):
                continue
            path = os.path.join(root, fn)
            rel = os.path.relpath(path, db_dir)
            try:
                with open(path, "rb") as f:
                    salt = f.read(16)
            except OSError:
                continue
            if len(salt) != 16:
                continue
            keys[rel] = derive(passphrase, salt)
            print("%-40s %s" % (rel, keys[rel]))

    print("\n共 %d 个库" % len(keys))

    if args.json:
        with open(args.json, "w") as f:
            json.dump({k: {"enc_key": v} for k, v in keys.items()}, f, indent=2)
        os.chmod(args.json, 0o600)
        print("已写入 %s（权限 600）" % args.json)


if __name__ == "__main__":
    main()
