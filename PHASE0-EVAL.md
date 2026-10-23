# Phase 0 评估：Mist UDP Initial 深度伪装工作量

**日期**：2026-10-22
**状态**：评估完成，待 chan 决策
**设计文档**：`UDP-DESIGN.md` v1.0（§13 Phase 0）

---

## 0. 结论先行

| 项目 | 结论 |
|---|---|
| 推荐路线 | **路线 B（自己写）** |
| 路线 B 工作量 | **2.8 人天**（熟悉 Go + TLS 的工程师） |
| 路线 A 工作量 | **3–4 人天**（且有长期维护负担） |
| Phase 1 建议 | **先做"随机密文 Initial"简化版跑通**（带两个条件，见 §5），Phase 0 在上真实网络前完成 |
| AUTH_OK | **暂不伪装**（见 §6；若做则首包必须是合法 Initial，见 §6 补充） |

**核心理由**：RFC 9001 附录 A 提供了完整的测试向量，HKDF-Expand-Label、AES-128-GCM、AES-ECB 都是标准操作，Go 标准库 + `golang.org/x/crypto` 全覆盖。自己写约 400 行代码，一天可写完，两天可调通。拷贝 quic-go 反而要处理 internal 包的依赖剥离，工作量更大。

---

## 1. RFC 9001 附录 A 测试向量（完整派生链）

### 1.1 固定参数

```
initial_salt (QUIC v1) = 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a  (20 字节)
测试 DCID              = 0x8394c8f03e515708                          (8 字节)
```

### 1.2 派生链（附录 A.1，全部有测试向量）

```
步骤 1: initial_secret = HKDF-Extract(salt=initial_salt, ikm=DCID)
        = 7db5df06e7a69e432496adedb0085192 3595221596ae2ae9fb8115c1e9ed0a44

步骤 2: client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
        = c00cf151ca5be075ed0ebfb5c80323c4 2d6b7db67881289af4008f1f6c357aea

步骤 3: key = HKDF-Expand-Label(client_initial_secret, "quic key", "", 16)
        = 1f369613dd76d5467730efcbe3b1a22d

步骤 4: iv  = HKDF-Expand-Label(client_initial_secret, "quic iv", "", 12)
        = fa044b2f42a3fd3b46fb255c

步骤 5: hp  = HKDF-Expand-Label(client_initial_secret, "quic hp", "", 16)
        = 9f50449e04a0e810283a1e9933adedd2
```

服务端方向同理，label 换 `"server in"`：
```
server_initial_secret = 3c199828fd139efd216c155ad844cc81 fb82fa8d7446fa7d78be803acdda951b
server key = cf3a5331653c364c88f0f379b6067e37
server iv  = 0ac1493ca1905853b0bba03e
server hp  = c206b8d9b9f0f37644430b490eeaa314
```

### 1.3 HKDF-Expand-Label 格式（RFC 8446 §7.1）

```go
// 伪代码：HkdfLabel 结构
// struct {
//    uint16 length = Length;
//    opaque label<7..255> = "tls13 " + Label;
//    opaque context<0..255> = Context;
// } HkdfLabel;
//
// HKDF-Expand-Label(Secret, Label, Context, Length) =
//      HKDF-Expand(Secret, HkdfLabel, Length)
```

附录 A 给出的 wire 格式（已验证）：
```
"client in" → 0020 0f 746c73313320636c69656e7420696e 00
               │    │  └─ "tls13 client in" (15 字节)      └─ context 为空
               │    └─ label 长度 15
               └─ 输出长度 32

"quic key"  → 0010 0e 746c7331332071756963206b6579 00
"quic iv"   → 000c 0d 746c7331332071756963206976 00
"quic hp"   → 0010 0d 746c7331332071756963206870 00
```

### 1.4 Header Protection（RFC 9001 §5.4.4，附录 A 有向量）

```
sample = 保护后载荷的前 16 字节
       = d1b1c98dd7689fb8ec11d242b123dc9b   (测试向量)

mask = AES-ECB(hp, sample)[0:5]
     = 437b9aec36                            (测试向量)

// 长包头（Initial）：掩码低 4 位
header[0] ^= mask[0] & 0x0f    // c3 → c0 (测试向量)
header[18:22] ^= mask[1:5]     // 包号 00000002 → 7b9aec34

// 短包头：掩码低 5 位（spin bit 不动）
// header[0] ^= mask[0] & 0x1f
```

### 1.5 客户端 Initial 包示例（附录 A.2）

未保护的载荷（CRYPTO 帧 + PADDING，1162 字节）：
```
060040f1010000ed0303ebf8fa56f129 39b9584a3896472ec40bb863cfd3e868
04fe3a47f06a2b69484c000004130113 02010000c000000010000e00000b6578
...（完整 1162 字节，见 RFC）
```

未保护的包头（包号 2）：
```
c300000001088394c8f03e5157080000449e00000002
```

保护后的包头：
```
c000000001088394c8f03e5157080000449e7b9aec34
```

**关键**：附录 A 的 ClientHello 是真实的 TLS ClientHello（含 SNI `example.com`、ALPN、QUIC transport parameters），这正是我们要模仿的。

---

## 2. 路线 B 工作量估算（自己写）

### 模块 1：HKDF-Expand-Label（0.3 人天）

Go 标准库没有 `HKDF-Expand-Label`，但有 `HKDF-Expand`（`golang.org/x/crypto/hkdf`）。只需按 RFC 8446 §7.1 封装：

```go
package quicinit

import (
    "golang.org/x/crypto/hkdf"
    "crypto/sha256"
)

// HKDF-Expand-Label 按 RFC 8446 §7.1
func hkdfExpandLabel(secret []byte, label string, context []byte, length int) []byte {
    // 构造 HkdfLabel
    // struct {
    //     uint16 length = Length;
    //     opaque label<7..255> = "tls13 " + Label;
    //     opaque context<0..255> = Context;
    // }
    fullLabel := "tls13 " + label
    hkdfLabel := make([]byte, 0, 2+1+len(fullLabel)+1+len(context))
    hkdfLabel = append(hkdfLabel, byte(length>>8), byte(length))
    hkdfLabel = append(hkdfLabel, byte(len(fullLabel)))
    hkdfLabel = append(hkdfLabel, fullLabel...)
    hkdfLabel = append(hkdfLabel, byte(len(context)))
    hkdfLabel = append(hkdfLabel, context...)

    out := make([]byte, length)
    r := hkdf.Expand(sha256.New, secret, hkdfLabel)
    io.ReadFull(r, out)
    return out
}

// Initial 密钥派生（客户端方向）
func deriveInitialKeys(dcid []byte) (key, iv, hp []byte) {
    initialSalt, _ := hex.DecodeString("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
    // HKDF-Extract(salt, ikm) = HMAC(salt, ikm)
    h := hmac.New(sha256.New, initialSalt)
    h.Write(dcid)
    initialSecret := h.Sum(nil)

    clientSecret := hkdfExpandLabel(initialSecret, "client in", nil, 32)
    key = hkdfExpandLabel(clientSecret, "quic key", nil, 16)
    iv  = hkdfExpandLabel(clientSecret, "quic iv", nil, 12)
    hp  = hkdfExpandLabel(clientSecret, "quic hp", nil, 16)
    return
}
```

**验证**：用 §1.2 的测试向量，DCID=`8394c8f03e515708`，检查输出是否等于预期值。5 分钟写测试，10 分钟调通。

**工作量**：0.3 人天（含测试）

### 模块 2：AES-128-GCM 加密 Initial 载荷（0.2 人天）

```go
import "crypto/aes"
import "crypto/cipher"

func sealInitialPayload(key, iv []byte, pn uint32, header []byte, plaintext []byte) []byte {
    block, _ := aes.NewCipher(key)
    aead, _ := cipher.NewGCM(block)

    // Nonce = IV XOR 包号（左填充到 12 字节）
    // RFC 9001 §5.3: nonce = iv XOR pn (pn 为大端，右对齐)
    nonce := make([]byte, 12)
    copy(nonce, iv)
    pnBytes := make([]byte, 4)
    binary.BigEndian.PutUint32(pnBytes, pn)
    for i := 0; i < 4; i++ {
        nonce[12-4+i] ^= pnBytes[i]
    }

    // AAD = 包头（掩码前）
    return aead.Seal(nil, nonce, plaintext, header)
}
```

**工作量**：0.2 人天（标准操作，无坑）

### 模块 3：AES-ECB Header Protection（0.3 人天）

```go
func applyHeaderProtection(hp []byte, header []byte, pnOffset int, payload []byte, isLongHeader bool) {
    // sample = 载荷（密文）的前 16 字节
    // 注意：header 和 payload 是分开传的，不要用 payload[pnOffset+4:…]
    // （附录 A 例子里 pnOffset=18 是包头内的偏移，不是 payload 内的）
    // RFC 向量会立刻暴露这个错。
    sample := payload[0:16]

    // mask = AES-ECB(hp, sample)[0:5]
    block, _ := aes.NewCipher(hp)
    mask := make([]byte, 16)
    block.Encrypt(mask, sample)
    mask = mask[:5]

    if isLongHeader {
        header[0] ^= mask[0] & 0x0f  // 长包头：低 4 位
    } else {
        header[0] ^= mask[0] & 0x1f  // 短包头：低 5 位（spin bit 不动）
    }
    // 包号字节（4 字节）
    for i := 0; i < 4; i++ {
        header[pnOffset+i] ^= mask[1+i]
    }
}
```

**验证**：用 §1.4 的测试向量，检查 `c3 → c0` 和包号 `00000002 → 7b9aec34`。

**工作量**：0.3 人天（含测试）

### 模块 4：构造合法 ClientHello（1.0–1.5 人天）

这是工作量最大的一块。需要构造一个能被标准 TLS 解析器完整解析的 ClientHello，包含：

**必需字段**：
```
- ClientHello.version = 0x0303 (TLS 1.2，QUIC 只用 TLS 1.3 但版本号写 1.2)
- random (32 字节)
- session_id (0 字节，QUIC 不用)
- cipher_suites: [TLS_AES_128_GCM_SHA256 (0x1301), ...]
- compression_methods: [0x00]
- extensions:
  - server_name (0x0000): SNI = 真实域名（见 §7 SNI 决策项）
  - supported_versions (0x002b): [0x0304] (TLS 1.3)
  - signature_algorithms (0x000d)
  - supported_groups (0x000a): [x25519]
  - key_share (0x0033): X25519 公钥
  - application_layer_protocol_negotiation (0x0010): ALPN = ["h3"]
      # RFC 9001 要求 QUIC 的 ClientHello 带 ALPN，缺了是明显特征
  - quic_transport_parameters (0x0039): QUIC 传输参数（必须有，否则是特征）
  - [自定义扩展]: 藏 Mist AUTH（见下）
```

**注意**：手写最小扩展集本身就是指纹。建议以某个真实客户端（如 Chrome/Cloudflare quiche）的 ClientHello 为模板，照抄它的扩展列表和顺序，只改 SNI 和插入自定义扩展。

**QUIC Transport Parameters**（RFC 9000 §18）是关键——真 QUIC ClientHello 必带，缺了就是特征。最小集合：
```
- max_idle_timeout (0x0001)
- max_udp_payload_size (0x0003) = 1350
- initial_max_data (0x0004)
- initial_max_stream_data_bidi_local (0x0005)
- initial_max_streams_bidi (0x0008)
```

**AUTH 藏匿位置**（二选一）：
- 选项 1：自定义扩展（type 选私有范围 0xFE00–0xFEFF，如 0xFE01），载荷 = Mist AUTH
- 选项 2：session ticket 扩展（0x0023）里藏

推荐选项 1：标准解析器会跳过未知扩展，不报错；DPI 看到的是正常 ClientHello + 一个私有扩展（很多真实 ClientHello 也有 GREASE 扩展，看起来不突兀）。

**实现方式**：
- `crypto/tls` 的 `ClientHelloMsg` 类型没有导出，marshal 这条路行不通。
- 可行做法：用 Go 1.21+ 的 `tls.QUICClient`（签名 `QUICClient(q *tls.QUICConfig)`，**参数是 `*tls.QUICConfig` 不是 `*tls.Config`**）生成真实 ClientHello 字节流。注意三点（2026-10-22 23:43 第五轮评审）：① **ALPN 要自己设** `QUICConfig.NextProtos`（如 `["h3"]`），不是自带；② **transport parameters 要自己调** `QUICConfig.SetTransportParameters`，不会自动带；③ **动手前用 `go doc crypto/tls.QUICConn` 核对**当前 Go 版本的 API。然后在生成的字节流里插入自定义扩展（0xFE01），并修正外层长度字段。
- 注意：新版 Go 默认启用后量子 key_share（X25519MLKEM768），ClientHello 可能超过 1200 字节，要拆成两个 Initial 包。建议先实测生成长度，再决定是否禁用 PQ（`Config.CurvePreferences` 只留 X25519）。

```go
// 伪代码：用 tls.QUICClient 生成 + 插入自定义扩展
func buildClientHello(sni string, authData []byte) []byte {
    // 1. tls.QUICClient 生成真实 ClientHello 字节流
    // 2. 解析 extensions，找到插入点（建议插在末尾）
    // 3. 插入 0xFE01 扩展（type 2 字节 + length 2 字节 + authData）
    // 4. 修正 ClientHello 总长度、Handshake 长度、CRYPTO 帧长度
    // 5. 检查总长，若 >1200 则走双 Initial 包逻辑
}
```

**验证**：用 Wireshark 或 `tshark` 解析生成的 ClientHello，确认无解析错误；确认 ALPN=h3 存在。

**工作量**：0.5–1 人天（比手写短；主要是字节流插入和长度修正的细活，ALPN/transport parameters 需手动配置）

### 模块 5：服务端解密 + AUTH 提取（0.5 人天）

```go
func handleInitialPacket(pkt []byte) {
    // 1. 解析长包头，提取 DCID
    // 2. 按 RFC 9001 派生 "client in" 密钥 → key/iv/hp
    //    注意：解客户端发来的 Initial 必须用 "client in" 派生的密钥，
    //    不是 server_initial_secret。"server in" 只用于服务端发包（AUTH_OK）。
    //    写错会导致集成测试解密失败。
    // 3. 解 header protection，拿到真实包号
    // 4. AES-128-GCM 解密载荷
    // 5. 解析 CRYPTO 帧，提取 ClientHello
    // 6. 从自定义扩展 0xFE01 取出 Mist AUTH
    // 7. 走正常认证流程（§5.2）
    // 8. 认证失败 → 静默丢弃（不回包）
}
```

**工作量**：0.5 人天（解密是模块 2/3 的逆操作，解析 ClientHello 扩展约 100 行）

### 模块 6：集成测试（0.5 人天）

- 客户端发 Initial → 服务端解密 → 提取 AUTH → 认证通过
- 用 Wireshark 抓包，确认 DPI 识别为 QUIC
- 认证失败时服务端静默（无回包）

**工作量**：0.5 人天

### 路线 B 总计

| 模块 | 人天 |
|---|---|
| 1. HKDF-Expand-Label | 0.3 |
| 2. AES-128-GCM | 0.2 |
| 3. AES-ECB Header Protection | 0.3 |
| 4. ClientHello 构造 | 0.5–1.0 |
| 5. 服务端解密+提取 | 0.5 |
| 6. 集成测试 | 0.5 |
| **总计** | **2.8** |

**取整：2.8 人天**（按熟悉 Go 和 TLS 的工程师；若不熟悉 QUIC，加 0.5 天读 RFC）

---

## 3. 路线 A 工作量估算（拷贝 quic-go）

### 需要拷贝的文件

quic-go 的 Initial 相关代码在 `internal/handshake/`：

```
internal/handshake/initial_aead.go      # NewInitialAEAD()，约 80 行
internal/handshake/aead.go              # AEAD 封装，约 120 行
internal/handshake/header_protector.go  # Header protection，约 150 行
internal/handshake/cipher_suite.go      # 密码套件定义，约 80 行
```

**依赖问题**：这些文件 import 了 quic-go 的其他 internal 包：
- `internal/protocol`（ConnectionID、PacketNumber 等类型）
- `internal/qtls`（TLS 1.3 封装，quic-go fork 的 crypto/tls）
- `github.com/quic-go/qtls-go1-21` 等外部依赖

**剥离工作**：
1. 把 `protocol.ConnectionID` 换成 `[]byte`（约 20 处）
2. 把 `qtls` 相关改成标准 `crypto/tls` 或直接删掉（Initial 不需要完整 TLS，只需要 AEAD）
3. 处理 `utils.Logger` 等工具依赖

### 工作量

| 步骤 | 人天 |
|---|---|
| 找齐 4 个文件 + 理清依赖 | 0.5 |
| 剥离 internal/protocol 依赖 | 0.5 |
| 剥离 qtls 依赖 | 0.5–1.0 |
| 适配 Mist 的包头格式 | 0.5 |
| 测试（附录 A 向量） | 0.3 |
| **总计** | **2.8–3.3** |

**取整：3 人天**，但有长期维护负担（quic-go 升级后无法同步，只能自己维护 fork）。

### 路线 A 的隐藏成本

- quic-go 的 `initial_aead.go` 是为完整 QUIC 实现设计的，包含了很多 Mist 不需要的逻辑（如 Retry 包处理）
- 剥离后代码约 300 行，和自己写差不多
- 以后 quic-go 修 bug，无法直接同步

---

## 4. 对比与建议

| 维度 | 路线 A（拷贝） | 路线 B（自己写） |
|---|---|---|
| 工作量 | 3 人天 | 3 人天 |
| 代码量 | ~300 行（剥离后） | ~400 行 |
| 测试向量 | quic-go 自带测试 | RFC 附录 A（更权威） |
| 维护负担 | 高（fork 后无法同步上游） | 低（代码完全自有） |
| 灵活性 | 低（受 quic-go 结构限制） | 高（按 Mist 需求定制） |
| 风险 | 中（剥离可能引入 bug） | 低（每步都有向量验证） |

**建议：路线 B（自己写）**

理由：
1. 工作量相同，但路线 B 没有维护负担
2. RFC 附录 A 的测试向量比 quic-go 的测试更直接（一步步验证派生链）
3. Mist 的 Initial 有特殊需求（藏 AUTH、自定义扩展），自己写更灵活
4. 400 行代码，一天写完，两天调通，风险可控

---

## 5. Phase 1 决策建议

**决定（chan 2026-10-22 23:30 确认）：Phase 1 先做"随机密文 Initial"简化版，但带两个条件。**

### 条件 1：Initial 编解码抽成接口

```go
type InitialCodec interface {
    // 客户端：构造 Initial 载荷（含 AUTH）
    SealInitial(auth *AuthPayload) (header, payload []byte, err error)
    // 服务端：解密 Initial 载荷，提取 AUTH
    OpenInitial(header, payload []byte) (auth *AuthPayload, err error)
    // 服务端：构造 AUTH_OK Initial 载荷
    SealInitialResponse(authOk *AuthOkPayload) (header, payload []byte, err error)
    // 客户端：解密 AUTH_OK Initial 载荷
    OpenInitialResponse(header, payload []byte) (authOk *AuthOkPayload, err error)
}
```

AUTH_OK 方向也必须进接口，否则 Phase 0 做 AUTH_OK 伪装时还得改调用方。

### 条件 2：简化版只用于内测

随机密文 Initial 本身就是特征（DPI 解开看到非法 ClientHello）。**上真实网络之前必须完成 Phase 0**，不是等到 Phase 4 之后。简化版的作用只是让 Phase 1–3 的 UDP 传输逻辑（BBR、可靠性、多路复用）先跑通。

### 简化版与 Phase 0 的关系

| 阶段 | Initial 实现 | 用途 |
|---|---|---|
| Phase 1–3 | 随机密文版（接口） | 内网联调 BBR/可靠性 |
| Phase 0 完成 | 真 QUIC 版（同一接口） | 替换，直接上线 |
| 真实网络 | 必须真 QUIC 版 | 简化版不上线 |

**例外**：如果 chan 认为伪装是 UDP 的核心需求（"高伪装"排第一），则 Phase 1 直接做深度伪装版，总工期 +2.8 天。

---

## 6. AUTH_OK 伪装决策

**决定（chan 2026-10-22 23:30）：Phase 0 不做就不做。如果做，服务端首包至少要是能按公开密钥解开的 Initial。**

### 为什么"攻击者无法主动触发"不够

原评估写"攻击者无法主动触发 AUTH_OK（需要先通过 AUTH），所以暂不伪装"。这个理由只覆盖**主动探测**，不覆盖**被动观察**：

- 对方如果能解密 Initial（公开 salt + DCID，人人可解），会看到客户端每次握手都成功。
- 如果服务端回的首包不是合法 ServerHello（而是"Handshake 包头 + 随机密文"），**每次成功连接都有异常**——被动观察者不需要主动探测，坐在那里看就行。

### 如果做，正确的做法

服务端首包必须是能按公开密钥（"server in"）解开的 Initial，里面是：

```
Initial（server in 加密）
└── CRYPTO 帧
    └── ACK 帧（确认客户端 Initial）+ ServerHello
        ├── ServerHello.version / random / cipher_suite
        ├── supported_versions 扩展（必须，TLS 1.3）
        ├── key_share 扩展（必须，group 与客户端提供的一致，如 X25519）
        └── [可选] 再跟一个 Handshake 包（包头 + 随机密文载荷，encrypted_extensions 放这里）
```

**注意**：`encrypted_extensions` 属于 Handshake 级别，是加密传输的，不能出现在 Initial 里。Initial 里只放 ACK + ServerHello，放进 Initial 反而成了异常。

工作量：约 0.5–1 人天（ServerHello 构造比 ClientHello 简单；ACK 帧格式见 UDP-DESIGN.md §4.1）。

### 决策点

- Phase 0 范围：Initial 伪装（含 ClientHello）。AUTH_OK 伪装作为可选项，单独估 0.5–1 天。
- 若 Initial 决定做、AUTH_OK 不做：文档注明"服务端首包异常"为已知风险，留待后续版本。

---

## 7. 待决策项

### 7.1 SNI 选择（已定，2026-10-22 23:39 chan；具体域名 2026-10-22 23:48 chan 指定）

**决定：用自己的域名，但不是 `mist.*`；SNI 做成配置项，不要写死。**

**已选定：`2pm.198112.xyz`**（A 记录已指到 148.135.10.19，IP/SNI 一致）。

域名必须满足三点：
1. **A 记录真的指向这台 VPS**——IP 和 SNI 一致。
2. **名字中性**——不带 `mist` 这类项目特征，也不用 `.xyz` 这类低价顶级域。这样即使被封，也不会连带别的东西。
3. **备好几个域名**——被封了改配置就能换。

**为什么不选另外两个**：
- **大站域名**（如 www.google.com）：SNI 和 VPS 的 IP 对不上，这是最容易被自动化检测抓到的特征。Initial 密钥人人可算（公开 salt + DCID），对方不需要主动探测就能解开看 SNI。
- **轮换域名**：解决不了 IP 与 SNI 不匹配的问题，还多一份实现复杂度。

**认证失败的 Initial 怎么处理（最优先事项，已定）**：
AUTH 失败（或没有 AUTH）的 Initial，**转发给同机的真实 h3 服务**，由它按 SNI 正常回包。
- 主动探测者看到的是一个**真实的 QUIC 站点**，不是静默的端口。
- SNI 和 IP 的一致性有真实内容撑着。
- 不用自己造"看起来合法的回包"，也就没有放大攻击的顾虑。
- 代价：服务端多一条转发路径，约 0.5–1 人天（未细估）。
- 注：这是原"认证失败静默不回包"问题的解法——两者是同一个问题。真实 QUIC 服务收到合法 Initial 会回包（Initial + Handshake），静默反而是特征。

### 7.2 握手重发逻辑（Phase 1 就会遇到）

UDP-DESIGN.md §5.1 写"1 秒无响应重发 Initial(AUTH)，最多重发 3 次（共 4 次尝试）"。但有个逻辑问题：

- 如果重发的 Initial(AUTH) 内容完全相同（同一 NONCE、同一时间戳），会被服务端的 NONCE 重放缓存拒绝。
- 后果：AUTH_OK 一旦丢包，客户端重发 AUTH → 服务端判重放 → 握手必败。

**解法二选一**（Phase 1 实现前定）：

- **方案 A**：重发时换新 NONCE 和时间戳（AUTH 内容重新生成），**并且每次重发用新的 SCID**。服务端视为新握手，无重放问题。代价：每次重发多一次 X25519（约 0.1ms，可忽略）。新 SCID 是必须的：客户端靠 AUTH_OK 的 DCID 判断它对应哪次尝试，否则迟到的旧 AUTH_OK 会和新一次尝试的密钥对不上。服务端被放弃的那次会话靠空闲超时清理即可。
- **方案 B**：服务端对同一 AUTH（按 CID 或 AUTH 内容哈希索引）缓存已发送的 AUTH_OK，重发时直接重发缓存。代价：服务端多一个"待完成握手"缓存，需 TTL（建议 10 秒）。

推荐方案 A：无状态，服务端不用改。

---

## 8. 风险与注意事项

1. **SNI 选择**：已定（见 §7.1）——用自有中性域名（非 `mist.*`），SNI 做成配置项；认证失败的 Initial 转发给同机真实 h3 服务回包。
2. **QUIC 版本**：固定 `0x00000001`（已定），不要用 grease。
3. **包大小**：Initial 必须 ≥1200 字节（RFC 9001 §14），用 PADDING 帧填充到 1200–1350。
4. **重传**：Initial 丢包时重传，包号递增（按 §6.4 新规则）。
5. **服务端性能**：每个 Initial 都要做 HKDF + AES 解密，DDoS 风险。用 `max_conns_per_ip` 限流（已有）。
