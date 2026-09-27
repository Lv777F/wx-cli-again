# macOS 微信数据库密钥捕获

一套独立的工具，用来提取微信 4.x（macOS）的 SQLCipher 数据库密钥。
当 `wx key extract` / `wx init` 在 macOS 上抓不到密钥时，用它。

## 关键结论（先看这个）

**要 hook 的是 `CCKeyDerivationPBKDF`，不是 `CCCrypt*`。**

微信的数据库密钥**不会**以裸 32 字节的形式出现在 AES 加解密函数上。它是在
**密钥派生**的调用参数里流过去的。所以 hook `CCCryptorCreate` / `CCCrypt` /
`CCCryptorCreateWithMode` / `CCCryptorCreateFromData` 全都会落空 —— 它们能抓到的
只是恰好路过寄存器、长度为 32 的字节串（噪声），拿去解密必然失败。

## 原理

微信 4.x 用的是标准 SQLCipher 4，两级 PBKDF2：

```
enc_key = PBKDF2-HMAC-SHA512(passphrase, 该库文件头前 16 字节, 256000 轮, 32 字节)
mac_key = PBKDF2-HMAC-SHA512(enc_key,    salt ^ 0x3a,           2 轮,    32 字节)
```

在 `CCKeyDerivationPBKDF` 上看到的两次调用，正好对应这两级：

| rounds | password 参数是什么 | 用途 |
| --- | --- | --- |
| 256000 | raw **passphrase** | 派生该库的 `enc_key` |
| 2 | 直接就是该库的 **enc_key** | 派生 `mac_key` |

也就是说：

- **所有库共用一个 passphrase**，但**每个库有自己的 salt**（= `.db` 文件的前 16 字节），
  所以要得某个库的 `enc_key`，必须拿 passphrase 配它自己的 salt 再派生一次。
- `rounds=2` 那次调用的 `password` 参数**直接就是 enc_key**，可以顺手白捡 ——
  但它只覆盖那些真正被打开过的库，冷分片不会出现。

`prf` 参数编码：1=SHA1, 2=SHA224, 3=SHA256, 4=SHA384, **5=SHA512**（微信用的是 5）。

arm64 调用约定：

```
CCKeyDerivationPBKDF(algorithm, password, passwordLen, salt, saltLen,
                     prf, rounds, derivedKey, derivedKeyLen)
  x1=password, x2=passwordLen, x3=salt, x4=saltLen, x5=prf, x6=rounds
```

## 用法

```bash
# 正常情况用这个
WX_DB_DIR="$HOME/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/<wxid>/db_storage" \
  bash run.sh
```

拆开用：

```bash
# 只抓候选（需要 sudo）
sudo WX_DB_DIR=... WX_CAPTURE_OUT=/tmp/wx-keys.txt WX_CAPTURE_SECONDS=120 \
  lldb -p "$(pgrep -x WeChat)" --batch \
  -o "command script import $PWD/capture-keys.py" \
  -o "process continue"

# 从 passphrase 派生所有库（passphrase = 64 位 hex）
python3 derive-keys.py --passphrase <64hex> --db-dir <db_storage> --json all_keys.json
```

## 必须知道的坑

1. **不重启微信，hook 挂多久都是 0 调用。** 数据库连接是长期持有的，`mac_key`
   一旦派生就被缓存住。必须 `killall WeChat` 再打开，让连接重新建立。

2. **解密出来的第 1 页不以 `SQLite format 3` 开头，这不代表失败。**
   SQLCipher 用 salt 占掉了前 16 字节，`"SQLite format 3\0"` 是解密后由库自己补上的。
   解出来的内容对应真正的数据库头 **offset 16** 起 —— 拿 offset 0 去比对会误判成失败。
   正确的自检是看这几处：
   ```
   [0:2]  = 0x10 0x00            → page size 4096（大端）
   [2:4]  = 0x02 0x02            → write/read version 2（WAL）
   [4:5]  = 0x50                 → 每页预留 80 字节（SQLCipher 的特征）
   [5:8]  = 0x40 0x20 0x20       → SQLite 标准的 payload fraction 64/32/32
   ```

3. **`rounds=2` 的调用里 password 就是 enc_key**，不需要再派生。别把它当
   passphrase 拿去跑 256000 轮，那样算出来的东西什么都不是。

4. **需要 root。** SSH 这种非交互会话里 lldb 拿不到调试授权（会报
   `attach failed: this is a non-interactive debug session`）。`ssh -tt` 能骗过 TTY
   检查，但非 root 时仍然取不到。老老实实 `sudo`。

5. **内存扫描这条路走不通。** 常见的做法是"在内存里找紧邻 salt 的 32 字节"，
   但在微信 4.1.11 上不成立 —— 扫了 1.9 GB 内存、175 个候选，0 命中。
   密钥根本不以那个形态常驻。

6. **macOS 的 `mac_key` 派生用 `salt ^ 0x3a`** 而不是 `salt || 0x3a`（Windows 上是后者）。
   如果自己实现解密，注意这个差异。

## 相关

- `capture-keys.py` — LLDB 探针，hook `CCKeyDerivationPBKDF`
- `derive-keys.py` — 从 passphrase 派生所有库的 enc_key
- `run.sh` — 一条龙

**产物等同于你的整个微信。** 落盘的密钥文件权限一律 600，别放进同步盘、
别备份到云端、别随手发人。重新登录微信会换 passphrase，届时需要重抓。
