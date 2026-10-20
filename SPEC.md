# Mist（雾）协议 v0.2 规约

> 自研代理传输协议。用途：代理上网（翻墙）。
> 设计目标：**高伪装、抗封锁、高速、稳定**。
> 本文档是 v0.2 的完整实现规约——照着写代码即可实现互通。
> 状态：v0.2（2026-10-20）
>
> **v0.2 变更**：移除应用层流控窗口（第 9.5 节），完全依靠 TCP 流控。v0.1 的 WINDOW_UPDATE 机制已废弃。

---

## 目录

1. [概述](#1-概述)
2. [目标与非目标](#2-目标与非目标)
3. [威胁模型](#3-威胁模型)
4. [传输层](#4-传输层)
5. [443 共用与 SNI 分流](#5-443-共用与-sni-分流)
6. [握手协议](#6-握手协议)
7. [帧格式](#7-帧格式)
8. [流量整形](#8-流量整形)
9. [多路复用](#9-多路复用)
10. [稳定性机制](#10-稳定性机制)
11. [安全分析](#11-安全分析)
12. [性能分析](#12-性能分析)
13. [客户端接入方式](#13-客户端接入方式)
14. [附录 A：伪代码](#附录-a伪代码)
15. [附录 B：参数表](#附录-b参数表)
16. [版本规划](#版本规划)

---

## 1. 概述

Mist（雾）是一套运行在 **TCP 443 + 真实 TLS 1.3** 之上的代理传输协议。

它的核心思想只有一句话：**不伪装成"某种协议"，而是伪装成"一个正常网站"。**

- 对防火墙：看到的是一次普通的 HTTPS 访问——真实域名、真实有效证书（Let's Encrypt）、Chrome 指纹的 ClientHello、443 端口。
- 对主动探测者：没有密钥的人连上来，看到的是一个真实网站（博客/静态页），没有任何代理特征。
- 对流量分析：连接建立初期的包长、间隔被随机化整形，稳定后接近零开销跑满带宽。
- 对用户：一次 1-RTT 握手，多路复用，断线/换网（WiFi↔5G）可迁移会话不断流。

协议分三层：

```
┌─────────────────────────────────────┐
│ 代理语义层： CONNECT / UDP / 流控    │  ← 第9节
├─────────────────────────────────────┤
│ Mist 帧层： 加密帧、多路复用、心跳   │  ← 第7、8节
├─────────────────────────────────────┤
│ 传输层：    TCP 443 + TLS 1.3 (uTLS) │  ← 第4节
└─────────────────────────────────────┘
```

**术语**：

| 术语 | 含义 |
|---|---|
| 客户端 | 用户设备上 Xray 核心内的 Mist 出站实现（见第13节） |
| 服务端 | VPS 上的 Mist 服务进程 |
| 分流器 | 443 端口上的单监听进程，只读 SNI 做分流（第5节） |
| 访客 | 未通过认证的连接，被当作普通网站访问者对待 |
| 会话 | 一次认证成功后建立的逻辑连接，由 connection_id 标识 |
| 流 | 会话内的一条代理子流，由 stream_id 标识 |
| 纪元 epoch | 会话的代次，连接迁移时递增，用于 nonce 域隔离 |

---

## 2. 目标与非目标

### 2.1 目标（v0.1 必做）

| # | 目标 | 对应机制 |
|---|---|---|
| G1 | 高伪装：DPI 看不出代理特征 | 真 TLS 1.3 + uTLS Chrome 拟态 + 真域名真证书 |
| G2 | 抗 SNI 审查 | SNI 为普通网站域名，无敏感 SNI |
| G3 | 抗主动探测 | 认证失败→访客模式，返回真实网页 |
| G4 | 抗流量分析 | 前 32 包随机填充/分片/抖动整形 |
| G5 | 抗封锁 | 单 443 端口，可套 CDN，可换 IP/域名，封锁代价高 |
| G6 | 高速 | 握手 1-RTT；整形只在前 32 包；XChaCha20-Poly1305 |
| G7 | 稳定 | 心跳、会话恢复、连接迁移（换网不断流）、服务端限流与优雅重启 |
| G8 | 前向安全 | 每会话 ECDHE（X25519）+ HKDF 派生会话密钥 |
| G9 | 防重放 | 时间戳窗口 + 服务端 nonce 缓存 |

### 2.2 非目标（v0.1 不做）

- ❌ 原生 UDP/QUIC 传输模式 → v1.1（注：TCP 上的 UDP 中继见 9.4，v0.1 必做，DNS 需要它）
- ❌ TLS 0-RTT → v1.1（v0.1 用应用层会话恢复令牌实现 1-RTT 重连）
- ❌ 后量子密钥交换 → 未来版本
- ❌ 匿名性（Tor 式多跳）→ 本协议只做传输伪装，不做匿名
- ❌ 服务端无状态（stateless）→ v0.1 服务端需保存会话表

---

## 3. 威胁模型

假设攻击者（防火墙）能力如下，按强度排序。11 节逐条回应。

| # | 能力 | 说明 |
|---|---|---|
| T1 | SNI 黑白名单 | 按 ClientHello 的 SNI 阻断/放行 |
| T2 | TLS 指纹（JA3/JA4） | 按 ClientHello 指纹识别客户端类型 |
| T3 | 证书审查 | 检查证书是否自签、是否与域名匹配 |
| T4 | 主动探测 | 向可疑服务器发探测包，根据响应判断是否为代理 |
| T5 | 流量分析 | 用包长/间隔/方向序列的机器学习模型识别代理流量 |
| T6 | 关键字/SNI 阻断后的 IP 封锁 | 封 IP、封端口 |
| T7 | 中间人 | 伪造证书劫持（要求客户端校验证书） |
| T8 | 重放攻击 | 重放截获的认证包试图建连 |
| T9 | 长期密钥泄露后的历史流量解密 | 要求前向安全 |

**不防御**：攻击者完全控制客户端设备；攻击者封锁全部境外 IP（白名单制上网）。

---

## 4. 传输层

- **传输**：TCP，目标端口 **443**。
- **TLS**：TLS 1.3（不接受 1.2 及以下，服务端直接拒绝）。
- **SNI**：雾域名，如 `www.example-blog.com`——必须是**真实解析到服务端的域名**。
- **证书**：真实有效证书（Let's Encrypt），**禁止自签/IP 证书**。
- **ClientHello 拟态**：客户端必须用 uTLS（Go）**完整模仿 Chrome** 的 ClientHello：
  - 加密套件顺序、扩展顺序与 Chrome 一致
  - ALPN：`h2,http/1.1`
  - 扩展含 `supported_versions`（仅 1.3）、`key_share`（X25519）、`psk_key_exchange_modes`
  - JA3/JA4 指纹与同版本 Chrome 一致
- **应用层协议**：TLS 之上直接跑 Mist 帧（**不**再套 HTTP/2，不套 WebSocket——减少指纹面；ALPN 声明 h2 只是为了拟态一致，实际不走 h2 帧）。

> 实现提示：uTLS 的 `utls.HelloChrome_Auto` 会随 Chrome 版本更新，客户端应定期更新 uTLS 库。

---

## 5. 443 共用与 SNI 分流

**问题**：服务端 443 端口已有 xray（Reality/xhttp）在监听，Mist 也要 443。

**方案**：443 上只跑**一个**监听进程——**SNI 分流器**。它**不解密**，只解析 ClientHello 明文中的 SNI，按表转发。

### 5.1 分流逻辑

```
监听 0.0.0.0:443 (TCP)
  │
  ├─ 读前 5 字节 TLS record header，确认是 handshake(0x16)
  ├─ 解析 ClientHello，提取 SNI（明文扩展，人人可读）
  │
  ├─ SNI == 雾域名          → 交给本机 Mist 服务 (127.0.0.1:14431)
  ├─ SNI == xhttp 域名      → 转发给本机 xray   (127.0.0.1:14432)
  ├─ SNI == Reality 目标域名 → 转发给本机 xray  (127.0.0.1:14432)
  ├─ SNI 为空 / 无 SNI      → 交给 Mist（当访客处理）
  └─ 其他未知 SNI           → 转发给默认后端（xray 或网站，按配置）
```

- xray 改为只监听内网端口（如 `127.0.0.1:14432`），**对外永远只有一个 443**。
- 分流器转发时必须把**已读的字节原样拼回去**再 splice（不能丢 ClientHello）。
- 分流器本身无状态、不解密、不做 TLS 终结，性能开销可忽略。
- 非 TLS 流量（首字节不是 0x16）→ 直接关闭连接。

### 5.2 对 Reality 防探测的影响

无影响。分流器对 Reality 的 SNI 只是**透明转发**，探测者看到的仍是 xray 的真实响应；Mist 的访客回退逻辑只作用于雾域名的 SNI。

### 5.3 配置示例

```json
{
  "listen": "0.0.0.0:443",
  "routes": {
    "www.example-blog.com": "127.0.0.1:14431",
    "xhttp.example.com":    "127.0.0.1:14432"
  },
  "default_backend": "127.0.0.1:14432",
  "no_sni_backend":  "127.0.0.1:14431"
}
```

---

## 6. 握手协议

**总 RTT：1**（标准 TLS 1.3 握手；认证帧搭在第一个应用数据包里，不增加往返）。

### 6.1 消息序列

```
客户端                                          服务端
  │                                                 │
  │──── TCP connect ───────────────────────────────▶│
  │                                                 │
  │◀─── TCP accept ─────────────────────────────────│
  │                                                 │
  │──── ClientHello ───────────────────────────────▶│  (uTLS Chrome拟态,
  │                                                 │   SNI=雾域名)
  │◀─── ServerHello … Finished ────────────────────│  (TLS 1.3, 1-RTT)
  │                                                 │
  │──── AUTH ──────────────────────────────────────▶│  TLS应用数据:
  │         [CID明文16][NONCE明文12]                 │  AEAD_Kauth(TS|EPH_PUB|PARAMS)
  │          │                                      │
  │          │  服务端：查 CID→K_auth；解密；        │
  │          │  验时间戳±60s；验nonce未用过；        │
  │          │  失败→标记为访客，走网站逻辑；        │
  │          │  成功→派生会话密钥，记入会话表       │
  │          │                                      │
  │◀─── AUTH_OK ───────────────────────────────────│  TLS应用数据:
  │         AEAD_Kauth(                            │  [服务端EPH_PUB 32]
  │           服务端X25519临时公钥32                 │  [connection_id 16]
  │           connection_id 16                     │  [resume_token 32]
  │           resume_token 32 …)                   │  [服务端参数]
  │                                                 │
  │════ 双方 HKDF 派生会话密钥，会话建立 ════════════│
  │                                                 │
  │──── 数据帧（多路复用流）◀───▶ 数据帧 ───────────│
```

### 6.2 AUTH 帧（客户端→服务端）

TLS 应用数据载荷：

```
+------------+--------------+-------------------------------+
| CID(16)    | NONCE(12)    | CIPHERTEXT (变长)             |
| 明文       | 明文         | AEAD_Kauth 加密               |
+------------+--------------+-------------------------------+
```

`CIPHERTEXT = AEAD_Encrypt(key=K_auth, nonce=NONCE, plaintext=AUTH_PLAIN, aad=CID)`

`AUTH_PLAIN`（解密后）：

```
+--------+----------+---------------+--------+----------+
| VER(1) | TS(8)    | EPH_PUB(32)   | FEAT(1)| RSVD(3)  |
| =0x01  | Unix秒   | 客户端X25519   | 功能位  | 保留置0  |
|        | 大端     | 临时公钥       |        |          |
+--------+----------+---------------+--------+----------+
```

- `K_auth`：32 字节长效认证密钥，**每客户端独立**，通过安全渠道预置（如订阅下发）。
- `CID`：16 字节客户端 ID（K_auth 的索引）。**明文传输**——权衡：服务端需先知道用哪把钥匙解密。注意这带来可链接性（见 11.6），建议定期轮换。
- `TS`：客户端 Unix 时间戳（秒）。服务端要求 `|now - TS| ≤ 60`。
- `EPH_PUB`：客户端 X25519 临时公钥，用于会话密钥派生。
- `FEAT`：功能位，bit0=支持连接迁移，bit1=支持 UDP 中继，其余保留。

**服务端验证步骤**（任一步失败 → 访客模式）：

1. CID 查表找到 K_auth；找不到 → 访客。
2. AEAD 解密失败 → 访客。
3. `VER != 0x01` → 访客。
4. `|now - TS| > 60` → 访客。
5. NONCE 已在缓存中 → 访客（防重放）。
6. 通过 → NONCE 记入缓存，继续。

### 6.3 AUTH_OK 帧（服务端→客户端）

`CIPHERTEXT = AEAD_Encrypt(key=K_auth, nonce=随机12字节, plaintext=AUTH_OK_PLAIN, aad="mist-v0.1-auth-ok")`

线格式：`[NONCE(12)明文][CIPHERTEXT]`，解密后：

```
+-----------------+------------------+----------------+----------+---------------+--------+-------+
| SRV_EPH_PUB(32) | CONN_ID(16)      | RESUME_TOK(32) | SRV_TS(8)| MAX_STREAMS(1)| HB(2)  |RSVD(5)|
| 服务端X25519     | 会话ID（随机）    | 恢复令牌（随机）| 服务端时间| 最大并发流数   |心跳秒数 | 保留  |
| 临时公钥         |                  |                | 大端     | 默认16        |默认30   | 置0   |
+-----------------+------------------+----------------+----------+---------------+--------+-------+
```

客户端收到后验证解密 → 派生会话密钥（6.4）→ 会话建立。

> 失败时的行为（关键！）：服务端**不返回任何错误**，连接保持为普通 TLS，由网站逻辑接管（返回真实网页）。探测者无法区分"密钥错的客户端"和"普通访客"。

### 6.4 会话密钥派生

```
shared = X25519(client_eph_priv, server_eph_pub)
         = X25519(server_eph_priv, client_eph_pub)   # 两边算出一致

salt = client_eph_pub || server_eph_pub   # 各 32 字节，共 64 字节
okm  = HKDF-SHA256(salt=salt, ikm=shared, info="mist-v0.1/session", L=64)

k_c2s = okm[0:32]    # 客户端→服务端 AEAD 密钥
k_s2c = okm[32:64]   # 服务端→客户端 AEAD 密钥
```

- 临时密钥用后立即清零 → **前向安全**：K_auth 泄露也解不开历史会话。
- AEAD 统一用 **XChaCha20-Poly1305**。

### 6.5 PSK 模式（可选）

无 ECDHE 需求的场景：AUTH_PLAIN 的 EPH_PUB 置全 0，`FEAT` bit2=1 表示请求 PSK 模式。服务端若允许，则会话密钥 = `HKDF(salt=CID, ikm=K_auth, info="mist-v0.1/psk-session", L=64)` 切分。**注意**：PSK 模式无前向安全，默认关闭，服务端配置 `allow_psk: false`。

---

## 7. 帧格式

TLS 应用数据里跑的是 Mist 帧流。**所有多字节整数均为大端序。**

### 7.1 帧头（4 字节）+ 载荷

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             LEN (16)          |    PLEN (8)     |  SID/F (8)    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|              ENC_PAYLOAD (变长)                                |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|              PADDING (PLEN 字节，随机)                          |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| 字段 | 长度 | 说明 |
|---|---|---|
| LEN | 2 字节 | **LEN 字段之后**的总字节数（= 2 + ENC_PAYLOAD长度 + PLEN）。最大 16384 |
| PLEN | 1 字节 | 尾部随机填充字节数（0–255），解密后丢弃 |
| SID/F | 1 字节 | 高 4 位=标志，低 4 位=流 ID（0=控制流，1–15=数据流） |
| ENC_PAYLOAD | 变长 | AEAD 加密后的载荷（含 16 字节认证标签） |
| PADDING | PLEN 字节 | CSPRNG 随机字节，无意义 |

标志位（高 4 位）：

| 位 | 值 | 含义 |
|---|---|---|
| bit7 | 0x8 | **SYN**：新开流（载荷首部为握手信息，见 9.2） |
| bit6 | 0x4 | **FIN**：本端已无数据发送（半关闭） |
| bit5 | 0x2 | **RST**：立即终止流 |
| bit4 | 0x1 | 保留 |

### 7.2 加密与 nonce

```
ENC_PAYLOAD = AEAD_Encrypt(key=方向密钥, nonce=NONCE, plaintext=明文载荷, aad=帧头4字节)

NONCE (12字节) = [EPOCH(4,大端)][DIR(4)][CTR(4,大端)]
  - EPOCH：会话纪元，初始 0，连接迁移时递增（见 10.3）
  - DIR：0x00000000 = 客户端→服务端；0xFFFFFFFF = 服务端→客户端
  - CTR：每方向每纪元独立计数器，从 0 开始，每帧 +1
```

**nonce 永不重用**：同一 (key, nonce) 只加密一帧。CTR 上限 2³¹−1，达到后必须重认证（实践中几乎到不了）。

AAD 绑定帧头 → 攻击者无法篡改长度/流 ID 而不被发现。

### 7.3 解码流程（伪代码见附录）

1. 读 2 字节 LEN；若 LEN > 16384 或 < 2 → 协议错误，关闭连接。
2. 读 LEN 字节；解析 PLEN、SID/F。
3. 取 `ENC_PAYLOAD = bytes[2 : 2+LEN-2-PLEN]`；`PADDING` 丢弃。
4. AEAD 解密（AAD=4 字节帧头）；失败 → 关闭连接（**不返回错误帧**，防探测）。
5. 按 SID/F 分发到对应流。

---

## 8. 流量整形

目标：对抗 T5（流量分析）。策略：**前重后轻**——识别模型主要看连接前几十个包。

### 8.1 整形参数

| 参数 | 默认值 | 范围 | 说明 |
|---|---|---|---|
| `shaping_heavy_packets` | 32 | 0–128 | 重整形包数（TLS 应用数据包计数） |
| `shaping_pad_min` | 64 | 0–1024 | 重整形期每帧最小填充 |
| `shaping_pad_max` | 512 | 64–1400 | 重整形期每帧最大填充 |
| `shaping_jitter_max_ms` | 15 | 0–100 | 重整形期帧间随机延迟上限 |
| `shaping_tail_pad` | 0 | 0–64 | 轻量期填充上限（0=关闭） |

### 8.2 行为

- **前 N 包**（N=`shaping_heavy_packets`，默认 32）：
  - 每帧 PLEN = `rand(pad_min, pad_max)` 随机字节；
  - 发送前延迟 `rand(0, jitter_max_ms)` 毫秒；
  - 允许把一帧拆成多次 `write`（不规则分片）。
- **N 包之后**：
  - PLEN = 0（或 `rand(0, shaping_tail_pad)` 若开启）；
  - 无人工延迟，写满即发。
- **心跳包**（10.1）同样参与整形计数，不豁免。
- 计数按**每个方向独立**（上行/下行各前 32 包）。

### 8.3 开销说明

- 前 32 包约增加 5–15% 字节开销 + 平均约 7ms 抖动延迟。
- 32 包后：每帧固定开销 = 4 字节帧头 + 16 字节 AEAD 标签，接近零。
- 关闭整形（`shaping_heavy_packets=0`）→ 退化为普通加密隧道（不推荐，但允许局域网调试）。

---

## 9. 多路复用

一条 TLS 连接上跑多条代理流，省掉重复握手。

### 9.1 流 ID

- SID 占 4 位：`0` = 控制流，`1–15` = 数据流。
- 客户端发起的流用奇数 ID？——v0.1 简化：**只允许客户端发起流**（代理场景足够），ID 由客户端分配 1–15 轮转，关闭后可复用。
- 并发流超过 15 → 客户端**再开一条 TLS 会话**（连接池），服务端 `MAX_STREAMS` 告知上限。

### 9.2 建流（SYN）

首帧置 SYN 标志，解密后载荷为建流请求：

```
CONNECT 请求（TCP）：
+--------+----------+-------------+--------+
| ATYP(1)| ADDR(变长)| PORT(2,大端)|        |
+--------+----------+-------------+--------+
ATYP: 0x01=IPv4(4字节) 0x03=域名(1字节长+域名) 0x04=IPv6(16字节)

服务端响应（同一流，无 SYN）：
+-----------+
| CODE(1)   |  0x00=成功；其他=失败码
+-----------+
失败码：0x01 网络不可达 0x02 连接被拒 0x03 超时 0x04 不支持的地址类型
```

成功后该流即为双向字节流。

### 9.3 关流

- **FIN**：本端发完数据，半关闭；对端 FIN 后全关闭，流 ID 可复用。
- **RST**：立即丢弃流状态。
- 会话结束时所有流自动关闭。

### 9.4 UDP 中继（v0.1 必做，供 DNS 等）

- 客户端先在**控制流**上发送 `UDP_ASSOC_REQ`（TYPE=0x03），同时新开一条数据流（SYN）作为该中继的承载流。
- 承载流上之后只跑 UDP 数据报帧（解密后载荷格式）：

```
+--------+----------+-------------+--------+----------------+
| ATYP(1)| ADDR(变长)| PORT(2)     | LEN(2) | DATA (变长)    |
+--------+----------+-------------+--------+----------------+
```

- 每个数据报独立寻址，服务端按目标发出，响应按源回包。
- UDP 流无连接语义：FIN/RST 即关闭中继。

### 9.5 流控（v0.2 已移除）

> **v0.2 废弃**：应用层流控窗口已移除。协议完全依靠 TCP 流控，与 xhttp 等标准传输一致。WINDOW_UPDATE 帧（0x04）不再发送，接收方应忽略。

### 9.5 流控

- 每流初始接收窗口 2MB（`init_window`，可调 64KB–4MB，v0.2 起默认 2MB 以支撑高 RTT 链路）。
- 接收方每消耗 1MB 发送 `WINDOW_UPDATE`（控制流消息，TYPE=0x04）：`[SID(1)][增量(4,大端)]`。
- 发送方窗口耗尽必须停发，等待更新。**控制流不受流控限制**。

### 9.6 控制流消息表（SID=0）

| TYPE | 名称 | BODY | 方向 |
|---|---|---|---|
| 0x01 | CONNECT_REQ | 见 9.2（随 SYN 帧发出，也可在控制流发） | C→S |
| 0x02 | CONNECT_RESP | `[CODE(1)]` | S→C |
| 0x03 | UDP_ASSOC_REQ | 空 | C→S |
| 0x04 | WINDOW_UPDATE | `[SID(1)][增量(4)]` | 双向 |
| 0x05 | PING | `[COOKIE(8)]` | C→S |
| 0x06 | PONG | `[COOKIE(8)]` | S→C |
| 0x07 | RESUME | 见 10.3 | C→S |
| 0x08 | RESUME_OK | 见 10.3 | S→C |
| 0x09 | CLOSE_SESSION | 空（优雅关闭） | 双向 |

---

## 10. 稳定性机制

### 10.1 心跳

- 客户端每 `HB` 秒（默认 30，可调 10–120）在控制流发 PING（8 字节随机 cookie）。
- 服务端必须回 PONG（原样 cookie）。
- 连续 2 个周期无 PONG → 客户端判定连接死亡，走 10.2/10.3 恢复。
- 心跳同样受第 8 节整形约束（不断流、不裸奔）。

### 10.2 断线重连（会话恢复令牌）

- AUTH_OK 下发的 `RESUME_TOK`（32 字节随机）即恢复令牌，客户端持久化保存（与 CID 绑定）。
- 断线后：新 TCP + TLS 握手（1-RTT），第一个应用数据发 RESUME（用**旧会话密钥**加密）：

```
RESUME 明文：
+-----------------+----------------+----------+-----------+
| CONN_ID(16)     | RESUME_TOK(32) | EPOCH(4) | RSVD(4)   |
|                 |                | 新纪元   | 置0       |
|                 |                | =旧+1    |           |
+-----------------+----------------+----------+-----------+
```

- 服务端：查 CONN_ID → 常量时间比较 RESUME_TOK → 通过则将会话绑定到新传输，EPOCH 更新，旧传输 5 秒宽限后关闭（吸收在途包）。
- 失败（令牌错/会话已回收）→ 服务端**静默关闭**（不报错，防探测），客户端回退到完整 AUTH 握手。

### 10.3 连接迁移（换网不断流）

- 会话由 **CONN_ID 标识，不由 TCP 四元组标识**。WiFi→5G 切换 IP 变化时，客户端直接在新网络上发起 10.2 的 RESUME 流程。
- EPOCH 递增保证 nonce 域隔离（7.2），**绝不重用 nonce**。
- 要求客户端声明支持（AUTH 的 FEAT bit0）；服务端实现中会话表以 CONN_ID 为主键。

### 10.4 服务端保护

| 机制 | 默认值 | 说明 |
|---|---|---|
| 单 IP 并发连接上限 | 32 | 超过则新连接直接 RST |
| 单 IP 新建连接速率 | 10/分钟 | 超过则延迟接受或拒绝 |
| 全局最大会话数 | 10000 | 达到后拒绝新 AUTH（访客不受影响） |
| 会话空闲回收 | 300 秒无流则回收（先发 CLOSE_SESSION） | |
| 优雅重启 | SIGHUP 重载配置；SIGTERM 时停止接受新连接，等待现有会话 30 秒排空 | |

### 10.5 客户端重连策略

- 退避：1s → 2s → 4s → … 上限 60s，抖动 ±25%。
- 连续失败 10 次 → 通知上层（App 显示断开），停止自动重连。
- 网络切换监听（Android `ConnectivityManager`）：网络变化时**立即**尝试迁移，不等心跳超时。

---

## 11. 安全分析

逐条回应第 3 节威胁模型。

| # | 威胁 | 回应机制 | 残余风险 |
|---|---|---|---|
| T1 | SNI 审查 | SNI 为普通网站域名；无敏感 SNI | 若域名本身被列入黑名单需换域名（配置化，秒级） |
| T2 | TLS 指纹 | uTLS 完整模仿 Chrome；定期跟进 Chrome 版本 | uTLS 库过期会导致指纹与当前 Chrome 偏离——**必须保持更新** |
| T3 | 证书审查 | 真实有效证书，非自签 | 无 |
| T4 | 主动探测 | 认证失败→访客模式，返回真实网页；全程无特征错误码 | 攻击者可长期观察，但看到的永远是正常网站 |
| T5 | 流量分析 | 前 32 包随机填充/分片/抖动；多路复用混合多流 | 长连接稳态流量仍可能被高级模型分析——残余风险接受（见 8.3） |
| T6 | IP 封锁 | 单 443 + 真网站伪装提高封锁代价；支持套 CDN；IP/域名可快速更换 | 单 IP 被精准封锁后需手动切换（v0.1 无自动前置调度） |
| T7 | 中间人 | TLS 1.3 + 真证书；客户端**必须**校验证书链与 SNI（可选 pin） | 客户端关闭校验则完全失效——实现中禁止提供关闭选项 |
| T8 | 重放 | 时间戳 ±60s + 服务端 nonce 缓存 | 60s 窗口内重放 AUTH 包：nonce 缓存拦截 |
| T9 | 历史流量解密 | 每会话 ECDHE + HKDF，用后清零 | K_auth 泄露不影响历史会话；当前会话仍受影响（重认证即可） |

**诚实声明的弱点**：

1. **CID 明文传输**（6.2）：同一 CID 的多次连接可被链接。缓解：定期轮换 CID/K_auth；v1.1 考虑加密 CID（需服务端 trial-decrypt）。
2. **ALPN 声明 h2 但实际不走 h2 帧**：深度检测若校验"ALPN=h2 却无 HTTP/2 帧"，可能起疑。v0.1 接受此风险（实际部署中极少有中间设备做这种校验）；v1.1 可选真 WebSocket 承载。
3. **整形只覆盖前 32 包**：这是有意的性能折中（第 8 节）。

---

## 12. 性能分析

| 项目 | 数值/结论 |
|---|---|
| 握手延迟 | 1-RTT（= 普通 HTTPS），认证不增加往返 |
| 重连延迟 | 1-RTT（RESUME），换网迁移同理 |
| 每帧固定开销 | 4 字节帧头 + 16 字节 AEAD 标签 |
| 整形开销 | 仅前 32 包，约 5–15% 字节开销 + 平均 ~7ms 抖动 |
| 稳态吞吐 | 接近裸 TCP（受限于 BBR 与对端带宽） |
| 加密 | XChaCha20-Poly1305，ARM 软算 ~GB/s 级，不构成瓶颈 |
| 多路复用 | 省掉每连接 TLS 握手；浏览器多连接场景延迟明显降低 |
| 服务端建议 | 开 BBR（`net.ipv4.tcp_congestion_control=bbr`）；单核可跑满千兆级转发 |

---

## 13. 客户端接入方式（Xray 原生出站）

**设计原则**：Mist 实现为 Xray 核心的原生出站协议（`proxy/mist`，client only），与 VLESS / Reality 并列。**无独立进程、无 SOCKS、无本地中转**——TLS（含 uTLS 指纹）与 Mist 握手全部在 Xray 进程内部完成。

### 13.1 架构

```
Weave App (Android)
  │  生成 Xray 配置（含 mist 出站）
  ▼
Xray 核心 ── mist 出站 ──(uTLS Chrome 指纹 TLS 1.3)──▶ 服务端 443
```

- Mist 在 Weave 里就是一个普通节点类型（`protocol: "mist"`）：路由、流量统计、延迟测试、链式（dialerProxy）、出口检测全部走现有逻辑，无需改动。
- uTLS 指纹复用 Xray 自带的 `fingerprint: chrome` 机制，不另起一套。
- 日志**禁止**输出 `authKey` 与 `clientId` 明文。

### 13.2 出站配置（Weave 生成）

```json
{
  "tag": "mist-out",
  "protocol": "mist",
  "settings": {
    "address": "www.example-blog.com",
    "port": 443,
    "clientId": "<hex:16字节CID>",
    "authKey": "<base64:32字节K_auth>",
    "heartbeatInterval": 30,
    "shapingHeavyPackets": 32
  },
  "streamSettings": {
    "network": "tcp",
    "security": "tls",
    "tlsSettings": {
      "serverName": "www.example-blog.com",
      "fingerprint": "chrome",
      "alpn": ["h2", "http/1.1"]
    }
  }
}
```

字段细节、编码要求与行为说明见实现仓库内的 `XRAY_INTEGRATION.md`。

### 13.3 服务端形态

- Go 单二进制：`mist-server`，内含 **SNI 分流器 + Mist 服务 + 访客网站**（可反代本地真实站点）。
- 访客网站：建议反代一个**真实存在的轻量站点**（如本机 8080 的博客），不要用默认"Hello"页——探测者会看内容合理性。

---

## 附录 A：伪代码

### A.1 客户端握手

```python
def mist_connect(server, sni, cid, k_auth):
    tcp = TCP.connect(server, 443)
    tls = uTLS_Chrome_Handshake(tcp, sni=sni)   # 1-RTT, 校验证书链+SNI

    # 构造 AUTH
    eph_priv, eph_pub = X25519.generate()
    auth_plain = b"\x01" + now_seconds().to_be8() + eph_pub + b"\x03" + b"\x00"*3
    nonce = CSPRNG(12)
    ct = AEAD_Encrypt(k_auth, nonce, auth_plain, aad=cid)
    tls.send(cid + nonce + ct)                    # 搭在第一个应用数据包

    # 等 AUTH_OK
    resp = tls.recv()
    nonce2, ct2 = resp[0:12], resp[12:]
    ok = AEAD_Decrypt(k_auth, nonce2, ct2, aad=b"mist-v0.1-auth-ok")
    assert ok, "认证失败（服务端无响应/密钥错）"
    srv_eph, conn_id, resume_tok, srv_ts, max_s, hb, _ = parse_auth_ok(ok)

    # 派生会话密钥
    shared = X25519(eph_priv, srv_eph)
    okm = HKDF_SHA256(salt=eph_pub+srv_eph, ikm=shared,
                      info=b"mist-v0.1/session", L=64)
    k_c2s, k_s2c = okm[0:32], okm[32:64]
    zero(eph_priv)

    return Session(tls, k_c2s, k_s2c, conn_id, resume_tok, epoch=0)
```

### A.2 服务端 AUTH 处理

```python
def handle_new_tls(tls_conn):
    data = tls_conn.recv_first_app_data(timeout=10)
    cid, nonce, ct = data[0:16], data[16:28], data[28:]
    k_auth = lookup(cid)
    if k_auth is None:
        return serve_website(tls_conn)            # 访客
    pt = AEAD_Decrypt(k_auth, nonce, ct, aad=cid)
    if pt is None or pt[0] != 0x01:
        return serve_website(tls_conn)            # 访客：不报错！
    ts = be64(pt[1:9])
    if abs(now() - ts) > 60:
        return serve_website(tls_conn)
    if nonce_cache.contains(nonce):
        return serve_website(tls_conn)
    nonce_cache.add(nonce, ttl=120)

    eph_pub = pt[9:41]
    srv_priv, srv_pub = X25519.generate()
    shared = X25519(srv_priv, eph_pub)
    okm = HKDF_SHA256(salt=eph_pub+srv_pub, ikm=shared,
                      info=b"mist-v0.1/session", L=64)
    conn_id, resume_tok = CSPRNG(16), CSPRNG(32)
    sessions[conn_id] = Session(keys=okm, token=resume_tok, epoch=0, ...)
    zero(srv_priv)

    ok_plain = srv_pub + conn_id + resume_tok + now().to_be8() \
               + b"\x10" + (30).to_be16() + b"\x00"*5
    n2 = CSPRNG(12)
    tls_conn.send(n2 + AEAD_Encrypt(k_auth, n2, ok_plain,
                                    aad=b"mist-v0.1-auth-ok"))
    serve_mist_session(tls_conn, sessions[conn_id])
```

### A.3 帧编解码

```python
def frame_encode(sid_flags: int, plaintext: bytes, pad_len: int,
                 key, epoch, direction, ctr) -> bytes:
    # 先算 LEN（只依赖明文长度与 pad_len，与密文无关）：
    # LEN = 2(PLEN+SID/F) + (len(plaintext)+16 tag) + pad_len
    total_after_len = 2 + (len(plaintext) + 16) + pad_len
    assert total_after_len <= 16384
    header = total_after_len.to_be16() + bytes([pad_len, sid_flags])
    nonce = epoch.to_be32() + direction.to_be32() + ctr.to_be32()
    enc = AEAD_Encrypt(key, nonce, plaintext, aad=header)  # AAD=完整帧头
    padding = CSPRNG(pad_len)
    return header + enc + padding

def frame_decode(buf: bytes, key, epoch, direction, expected_ctr) -> (sid_flags, plaintext):
    assert len(buf) >= 2
    ln = be16(buf[0:2])
    assert 2 <= ln <= 16384 and len(buf) >= 2 + ln
    header, rest = buf[0:4], buf[4:2+ln]
    pad_len, sid_flags = rest[0], rest[1]
    enc = rest[2:2+ln-2-pad_len]
    nonce = epoch.to_be32() + direction.to_be32() + expected_ctr.to_be32()
    pt = AEAD_Decrypt(key, nonce, enc, aad=header)
    assert pt is not None, "AEAD失败：静默关闭连接"
    return sid_flags, pt
```

### A.4 RESUME（连接迁移）

```python
def mist_resume(server, sni, old_session):
    tcp = TCP.connect(server, 443)
    tls = uTLS_Chrome_Handshake(tcp, sni=sni)
    resume_plain = (old_session.conn_id + old_session.resume_tok
                    + (old_session.epoch + 1).to_be32() + b"\x00"*4)
    # 用旧会话密钥加密，控制流(SID=0)，TYPE=0x07
    tls.send(frame_encode(sid_flags=0x00,
                          plaintext=b"\x07" + resume_plain,
                          pad_len=rand_pad(),
                          key=old_session.k_c2s,
                          epoch=old_session.epoch,
                          direction=C2S, ctr=old_session.next_ctr()))
    resp = frame_decode_next(tls, old_session.k_s2c, ...)
    assert resp.plaintext[0] == 0x08, "恢复失败，回退完整握手"
    new_epoch = be32(resp.plaintext[1:5])
    old_session.epoch = new_epoch
    old_session.reset_counters()
    old_session.transport = tls
    # 服务端：将会话绑定到新传输，旧传输5秒后关闭
```

---

## 附录 B：参数表

### B.1 协议常量

| 常量 | 值 | 说明 |
|---|---|---|
| 协议版本 VER | 0x01 | AUTH_PLAIN 首字节 |
| AEAD | XChaCha20-Poly1305 | 全部加密处统一 |
| KDF | HKDF-SHA256 | |
| 密钥交换 | X25519（ECDHE） | |
| TLS 版本 | 1.3 only | |
| 端口 | TCP 443 | |
| 最大帧线长 | 16386 字节（LEN ≤ 16384，LEN 不含自身 2 字节） | |
| 最大流 ID | 15（4 位） | 0=控制流 |
| 初始流窗口 | 2 MB | |
| Nonce 结构 | epoch(4)+方向(4)+计数器(4) | 12 字节 |

### B.2 可调参数（默认值 / 范围）

| 参数 | 默认 | 范围 | 说明 |
|---|---|---|---|
| 时间戳窗口 | 60s | 30–300 | AUTH 防重放窗口 |
| nonce 缓存 TTL | 120s | ≥2×窗口 | |
| shaping_heavy_packets | 32 | 0–128 | 重整形包数 |
| shaping_pad_min/max | 64 / 512 | 0–1400 | 填充字节范围 |
| shaping_jitter_max_ms | 15 | 0–100 | 帧间抖动上限 |
| shaping_tail_pad | 0 | 0–64 | 稳态填充 |
| 心跳间隔 HB | 30s | 10–120 | |
| 心跳超时 | 2 个周期 | 固定 | |
| 会话空闲回收 | 300s | 60–3600 | |
| 单 IP 并发上限 | 32 | 1–1024 | |
| 单 IP 新建速率 | 10/分钟 | 1–600 | |
| 重连退避上限 | 60s | 10–300 | |
| 连续失败停试 | 10 次 | 1–100 | |
| 旧传输宽限 | 5s | 1–30 | 迁移时旧连接保持 |

### B.3 错误处理总则

- **认证/解密失败**：永远静默——服务端转访客模式或关闭连接，**不返回任何特征性错误**。
- **帧格式错误**（LEN 越界等）：关闭 TCP，不告警。
- **客户端行为**：把"无响应"统一视为网络错误，按退避重试，不区分原因（避免给探测者提供侧信道）。

---

## 版本规划

| 版本 | 内容 | 状态 |
|---|---|---|
| **v0.1** | 本文档全部：TCP 443、握手、多路复用、整形、迁移、SNI 分流、Go 客户端/服务端 | 草案，待实现 |
| v1.1 | 原生 UDP/QUIC 传输模式；TLS 1.3 0-RTT 快速重连；加密 CID（trial-decrypt） | 规划中 |
| v2.0 | 后量子密钥交换（X25519+Kyber 混合）；真 WebSocket 承载选项 | 远期 |

---

*文档结束。实现时如发现规约歧义，以"防探测静默"和"nonce 永不重用"两条铁律为准，其余提交 issue 讨论。*
