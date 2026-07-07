# DTLCP 数据报传输层密码协议 — 技术设计文档

## 1. 概述

### 1.1 协议定位

DTLCP（Datagram Transport Layer Cryptography Protocol，数据报传输层密码协议）是 GB/T 38636-2020 TLCP（传输层密码协议）在 UDP 传输层上的适配版本，定义于 GM/T 0128-2023。

**协议关系链：**

```
TLS 1.2 (RFC 5246)  ──国密化──▶  TLCP (GB/T 38636-2020)
       │                                │
       │ UDP适配                         │ UDP适配
       ▼                                ▼
DTLS 1.2 (RFC 6347)  ──国密化──▶  DTLCP (GM/T 0128-2023)
```

DTLCP 相对于 DTLS 1.2 的核心变化是：用国密算法（SM2/SM3/SM4）替换国际算法，保留 DTLS 的 UDP 适配机制（显式序列号、分片重组、无状态 Cookie、超时重传）。

### 1.2 设计目标

- 为基于 UDP 的两个应用程序之间提供**保密性**和**数据完整性**
- 应对 UDP 数据报的**丢包、乱序、重复**问题
- 防御基于 UDP 的 **DoS 放大攻击**
- 保持与 TLCP 在密码算法层面的完全兼容

### 1.3 协议版本

| 协议 | 版本号 | 说明 |
|------|--------|------|
| TLCP | `{0x01, 0x01}` | GB/T 38636-2020 |
| DTLCP | `{0x01, 0x01}` | GM/T 0128-2023，与 TLCP 相同 |
| DTLS 1.2 | `{254, 253}` | RFC 6347，采用 1's complement 编码 |

> **设计决策**：DTLCP 使用与 TLCP 相同的版本号 `{0x01, 0x01}` 而非 DTLS 的版本号方案。这是因为 DTLCP 的协议区分不依赖版本号，而是通过记录层版本号 + 传输层特征（TCP/UDP）共同判断。

---

## 2. 协议栈架构

### 2.1 分层结构

```
┌──────────────────────────────────────┐
│            应用数据                    │
├──────────────────────────────────────┤
│         握手协议族                     │
│  ┌──────────┬──────────┬──────────┐   │
│  │ 握手协议  │ 密码规格  │  报警协议  │   │
│  │          │ 变更协议  │          │   │
│  └──────────┴──────────┴──────────┘   │
├──────────────────────────────────────┤
│          记录层协议                    │
│  ┌──────────┬──────────┬──────────┐   │
│  │  分片     │  压缩     │ 加密/MAC │   │
│  │  (≤PMTU) │ (可选)    │          │   │
│  └──────────┴──────────┴──────────┘   │
├──────────────────────────────────────┤
│             UDP                      │
└──────────────────────────────────────┘
```

记录层协议是分层次的，每一层都包含**长度字段、描述字段和内容字段**。处理流程：

- **发送方向**：数据 → 分片 → 压缩（可选）→ 计算 MAC → 加密 → 传输
- **接收方向**：接收 → 解密 → 验证 MAC → 解压缩（可选）→ 重组 → 递交给上层

### 2.2 组件依赖

```
DTLCP
 ├── 记录层协议（6.3）
 │    ├── 连接状态管理
 │    ├── 明文记录 DTLSPlaintext
 │    ├── 压缩记录 DTLSCompressed
 │    └── 密文记录 DTLSCiphertext
 ├── 握手协议族（6.4）
 │    ├── 密码规格变更协议
 │    ├── 报警协议
 │    └── 握手协议
 └── 密钥计算（6.5）
      ├── 主密钥派生
      └── 工作密钥派生
```

---

## 3. DTLCP 与 TLCP 的核心差异

### 3.1 差异总览

| 维度 | TLCP | DTLCP |
|------|------|-------|
| **传输层** | TCP（可靠、有序） | UDP（不可靠、无序） |
| **序列号** | 隐式（64位计数器，不传输） | 显式（epoch + sequence_number 字段） |
| **分片** | TCP 自动处理 | 握手消息手动分片（fragment_offset/length） |
| **重传** | TCP 保证 | 自实现状态机（PREPARING/SENDING/WAITING/FINISHED） |
| **DoS 防护** | 无 | 无状态 Cookie（HelloVerifyRequest） |
| **重放防护** | TCP 序列号天然防护 | 滑动窗口（默认64，最小32） |
| **消息边界** | 流式，可跨 TCP 段 | 单条记录必须在单个 UDP 报文内 |
| **多记录** | 连续流 | 同一 UDP 报文可含多个记录，连续放置 |

### 3.2 记录层新增字段

```
TLCP 记录层：                    DTLCP 记录层：
┌────┬─────┬──────┬────────┐    ┌────┬─────┬───────┬───────────────┬──────┬────────┐
│Type│Ver  │Length│Fragment│    │Type│Ver  │ Epoch │ SequenceNumber│Length│Fragment│
└────┴─────┴──────┴────────┘    └────┴─────┴───────┴───────────────┴──────┴────────┘
                                 ◀── 新增 ──▶◀────── 新增 ──────────▶
```

### 3.3 握手协议新增内容

| 新增 | 说明 |
|------|------|
| `message_seq`（uint16） | 握手消息序号，区分重传与重排序 |
| `fragment_offset`（uint24） | 分片偏移量，支持大消息分片 |
| `fragment_length`（uint24） | 当前分片长度 |
| `HelloVerifyRequest` 消息 | 无状态 Cookie 交换，防 DoS |
| `cookie` 字段（ClientHello） | 客户端携带服务端返回的 Cookie |

---

## 4. 密码算法与密钥体系

### 4.1 密码算法

#### 4.1.1 非对称密码算法

- **算法**：SM2（椭圆曲线公钥密码算法）
- **用途**：身份鉴别、数字签名、密钥交换
- **密钥交换模式**：
  - **ECC**：非前向安全，使用加密证书公钥直接加密预主密钥
  - **ECDHE**：前向安全，使用临时 ECC 密钥对协商预主密钥

#### 4.1.2 分组密码算法

- **算法**：SM4
- **工作模式**：GCM（Galois 计数器模式）或 CBC（密文分组链接模式）
- **用途**：密钥交换数据加密保护、报文数据加密保护

#### 4.1.3 密码杂凑算法

- **算法**：SM3
- **用途**：对称密钥生成、完整性校验（HMAC）

#### 4.1.4 数据扩展函数 P_hash

```
P_hash(secret, seed) = HMAC(secret, A(1) + seed) +
                        HMAC(secret, A(2) + seed) +
                        HMAC(secret, A(3) + seed) + ...
其中：
  A(0) = seed
  A(i) = HMAC(secret, A(i-1))
```

P_hash 可无限扩展输出，直到产生所需长度的密钥素材。

#### 4.1.5 伪随机函数 PRF

```
PRF(secret, label, seed) = P_hash(secret, label + seed)
```

使用 SM3 作为底层 HMAC 杂凑算法。

### 4.2 密码套件

| 优先级 | 密码套件 | 密钥交换 | 加密 | 校验 | 编码值 |
|--------|----------|----------|------|------|--------|
| 1 | ECC_SM4_GCM_SM3 | ECC | SM4-GCM | SM3 | `{0xe0, 0x53}` |
| 2 | ECC_SM4_CBC_SM3 | ECC | SM4-CBC | SM3 | `{0xe0, 0x13}` |
| 3 | ECDHE_SM4_GCM_SM3 | ECDHE | SM4-GCM | SM3 | `{0xe0, 0x51}` |
| 4 | ECDHE_SM4_CBC_SM3 | ECDHE | SM4-CBC | SM3 | `{0xe0, 0x11}` |

> **设计决策**：ECC 模式优先于 ECDHE 模式。ECC 模式下服务端加密证书公钥固定，客户端直接使用公钥加密预主密钥，无需额外握手交互。ECDHE 模式提供前向安全性但需要双方交换临时公钥。

### 4.3 密钥层次结构

```
                      服务端加密公钥
                           │
                    (加密/协商)
                           │
                           ▼
                    预主密钥 (pre_master_secret)
                           │
                    PRF("master secret", client_random + server_random)
                           │
                           ▼
                    主密钥 (master_secret, 48字节)
                           │
                    PRF("key expansion", server_random + client_random)
                           │
          ┌────────────────┼────────────────┐
          ▼                ▼                ▼
     校验密钥          加密密钥        初始向量(IV)
  (MAC key)          (enc key)
```

### 4.4 密钥种类

| 密钥类型 | 说明 |
|----------|------|
| **服务端密钥** | 签名密钥对（身份鉴别）+ 加密密钥对（密钥协商） |
| **客户端密钥** | 签名密钥对（身份鉴别）+ 加密密钥对（密钥协商） |
| **预主密钥** | 双方协商生成的密钥素材，用于生成主密钥 |
| **主密钥** | 48字节，由预主密钥 + 客户端随机数 + 服务端随机数计算 |
| **写密钥** | 发送方使用的工作密钥（加密 + 校验），分 client_write 和 server_write |
| **读密钥** | 接收方使用的工作密钥（解密 + 校验），分 client_write 和 server_write |

---

## 5. 记录层协议

### 5.1 连接状态

与 TLCP 相同，DTLCP 包含四种连接状态：

| 状态 | 说明 |
|------|------|
| 当前读状态 | 当前正在使用的接收方安全参数 |
| 未决读状态 | 握手协商中、待激活的接收方安全参数 |
| 当前写状态 | 当前正在使用的发送方安全参数 |
| 未决写状态 | 握手协商中、待激活的发送方安全参数 |

密码规格变更消息使未决状态变为当前状态。

**连接状态安全参数结构：**

```c
struct {
    ConnectionEnd          entity;                 // server 或 client
    BulkCipherAlgorithm    bulk_cipher_algorithm;  // sm4
    CipherType             cipher_type;            // block 或 aead
    uint8                  key_material_length;    // 密钥材料长度（SM4: 16字节）
    MACAlgorithm           mac_algorithm;          // sm3
    uint8                  hash_size;              // 杂凑输出长度（SM3: 32字节）
    CompressionMethod      compression_algorithm;  // null(0)
    opaque                 master_secret[48];      // 48字节主密钥
    opaque                 client_random[32];      // 客户端32字节随机数
    opaque                 server_random[32];      // 服务端32字节随机数
    uint8                  record_iv_length;       // 记录层IV长度
    uint8                  fixed_iv_length;        // 固定IV长度
    uint8                  mac_length;             // MAC长度
} SecurityParameters;
```

安全参数派生出的工作密钥（由记录层使用）：

| 派生密钥 | 方向 | 用途 |
|----------|------|------|
| `client_write_MAC_secret` | 客户端→服务端 | 客户端发送时的 MAC 密钥 |
| `server_write_MAC_secret` | 服务端→客户端 | 服务端发送时的 MAC 密钥 |
| `client_write_key` | 客户端→服务端 | 客户端发送时的加密密钥 |
| `server_write_key` | 服务端→客户端 | 服务端发送时的加密密钥 |
| `client_write_IV` | 客户端→服务端 | 客户端发送时的初始向量 |
| `server_write_IV` | 服务端→客户端 | 服务端发送时的初始向量 |

> 服务端接收时使用客户端写参数解密，客户端接收时使用服务端写参数解密。

### 5.2 记录层报文结构

#### 5.2.1 DTLSPlaintext（明文记录）

```c
struct {
    ContentType type;              // 记录类型
    ProtocolVersion version;       // 版本号 {0x01, 0x01}
    uint16 epoch;                  // DTLCP新增：密码规格变更计数器
    uint48 sequence_number;        // DTLCP新增：显式序列号
    uint16 length;                 // 数据长度，≤ PMTU
    opaque fragment[DTLSPlaintext.length];
} DTLSPlaintext;
```

**ContentType 枚举：**

```c
enum {
    change_cipher_spec(20),
    alert(21),
    handshake(22),
    application_data(23),
    (255)
} ContentType;
```

#### 5.2.2 epoch 与 sequence_number 的维护规则

- 每个 epoch 开始时 sequence_number 初始化为 0
- 每次发送一个 DTLSPlaintext 记录时 sequence_number 单调递增
- 每次发送 ChangeCipherSpec 时 epoch 单调递增
- **epoch/sequence_number 对必须唯一**：在 2 倍 TCP MSL 时间内 epoch 值不能重用
- 旧 epoch 的记录在收到新 epoch 数据后应丢弃，但密钥素材可保留 MSL 时间用于重排序
- epoch 或 sequence_number 回绕前必须终止连接，重新握手

```mermaid
stateDiagram-v2
    state "epoch=0" as e0
    state "epoch=1" as e1
    state "epoch=2" as e2

    e0 --> e1 : ChangeCipherSpec
    e1 --> e2 : ChangeCipherSpec

    note right of e0 : seq_num: 0,1,2...n
    note right of e1 : seq_num: 0,1,2...m (独立计数)
```

#### 5.2.3 DTLSCompressed（压缩记录）

```c
struct {
    ContentType type;
    ProtocolVersion version;
    uint16 epoch;
    uint48 sequence_number;
    uint16 length;                        // ≤ 2^14 + 1024
    opaque fragment[DTLSCompressed.length];
} DTLSCompressed;
```

默认压缩算法为空算法。压缩后数据长度最多增加 1024 字节。

#### 5.2.4 DTLSCiphertext（密文记录）

```c
struct {
    ContentType type;
    ProtocolVersion version;
    uint16 epoch;
    uint48 sequence_number;
    uint16 length;                        // ≤ 2^14 + 2048
    select (CipherSpec.cipher_type) {
        case block: GenericBlockCipher;
        case aead:  GenericAEADCipher;
    } fragment;
} DTLSCiphertext;
```

### 5.3 MAC 计算

#### 5.3.1 分组密码模式（CBC）

```
MAC = HMAC_hash(
    write_MAC_secret,
    epoch + sequence_number + type + version + length + fragment
)
```

> **与 TLCP 关键差异**：TLCP 使用隐式的 64 位 `seq_num`（不传输），DTLCP 使用显式的 `epoch + sequence_number` 拼接为 64 位值参与 MAC 计算。MAC 计算值与前后记录独立，无关联关系。

#### 5.3.2 AEAD 模式（GCM）

附加鉴别数据（AAD）定义：

```
additional_data = epoch + sequence_number + type + version + length
```

> **与 TLCP 关键差异**：TLCP 的 AAD 使用隐式 64 位 seq_num，DTLCP 使用显式的 `epoch + sequence_number`。

### 5.4 分片规则

- 记录层将数据分成不超过 PMTU 的消息记录
- 每个 DTLCP 消息记录在单个 UDP 报文内
- **多个 DTLCP 记录可放在同一个 UDP 报文中**，连续放置
- UDP 报文载荷的第一个字节必须是 DTLCP 记录的开始
- 记录**不能跨 UDP 报文传输**

**记录长度上限：**

| 结构 | 最大 fragment 长度 | 说明 |
|------|---------------------|------|
| DTLSPlaintext | 2^14 (16384) | 与 TLCP 相同，不含头部 |
| DTLSCompressed | 2^14 + 1024 | 压缩后最多膨胀 1024 字节 |
| DTLSCiphertext | 2^14 + 2048 | 加密后最多膨胀 2048 字节（含 MAC/填充/AEAD tag） |

> **PMTU 感知**：DTLCP 记录层应允许上层协议获取 PMTU 估算值。当 IP 层返回 ICMP "Datagram Too Big" 时，记录层必须通知上层协议。发送方应尝试将记录大小控制在 PMTU 范围内，避免 IP 分片。多次重传无响应且 PMTU 未知时，后续重传应回退到更小的记录大小。

### 5.5 重放保护

采用滑动窗口机制：

| 参数 | 说明 |
|------|------|
| 最小窗口大小 | 32 |
| 默认窗口大小 | 64（推荐） |
| 窗口右边缘 | 当前会话接收到的最高有效序列号 |
| 窗口左边缘 | 右边缘 - 窗口大小 |

处理流程：
1. 接收记录，检查序列号
2. 序列号 < 窗口左边缘 → 丢弃
3. 序列号在窗口内且为新 → 进行 MAC 验证
4. MAC 验证成功 → 更新窗口
5. MAC 验证失败 → 丢弃记录（不更新窗口）

---

## 6. 握手协议族

### 6.1 握手协议概述

握手协议族包含三个子协议：

| 子协议 | ContentType | 说明 |
|--------|-------------|------|
| 密码规格变更协议 | 20 | 通知对方启用新协商的安全参数 |
| 报警协议 | 21 | 错误报告和连接关闭通知 |
| 握手协议 | 22 | 协商安全参数、身份验证 |

### 6.2 密码规格变更协议

```c
struct {
    enum { change_cipher_spec(1), (255) } type;
} ChangeCipherSpec;
```

- 消息体长度为 1 字节，值为 1
- 发送此消息后立即启用写密钥
- 收到此消息后立即启用读密钥
- 在握手结束消息之前发送

### 6.3 报警协议

#### 6.3.1 消息结构

```c
struct {
    AlertLevel level;             // warning(1) 或 fatal(2)
    AlertDescription description; // 报警类型
} Alert;
```

#### 6.3.2 报警级别

| 级别 | 值 | 处理 |
|------|-----|------|
| warning | 1 | 接收方可自行判定严重程度 |
| fatal | 2 | 双方立即关闭连接，废弃会话标识和密钥 |

#### 6.3.3 关键报警类型

| 报警 | 值 | 说明 |
|------|-----|------|
| close_notify | 0 | 关闭通知 |
| unexpected_message | 10 | 不符合上下文关系的消息 |
| bad_record_mac | 20 | MAC 校验错误或解密错误 |
| decryption_failed | 21 | 解密失败（CBC模式；GCM模式使用bad_record_mac） |
| record_overflow | 22 | 记录层报文超过最大长度（2^14+2048字节） |
| decompression_failure | 30 | 解压缩后数据超过最大长度（2^14+1024字节） |
| handshake_failure | 40 | 协商失败 |
| bad_certificate | 42 | 证书被破坏 |
| unsupported_certificate | 43 | 不支持证书类型 |
| certificate_revoked | 44 | 证书被撤销 |
| certificate_expired | 45 | 证书过期 |
| certificate_unknown | 46 | 未知证书错误 |
| illegal_parameter | 47 | 非法参数 |
| unknown_ca | 48 | 未知 CA |
| decode_error | 50 | 消息解码失败 |
| decrypt_error | 51 | 消息解密失败 |
| protocol_version | 70 | 版本不匹配 |
| insufficient_security | 71 | 安全性不足 |
| internal_error | 80 | 内部错误 |

> **DTLCP 特殊处理**：报警消息不重传。MAC 错误时可选择静默丢弃记录（而非立即中断连接），这比 TLCP 更宽容——因为 UDP 可能因网络原因产生偶然错误。

### 6.4 握手协议 — 消息结构

#### 6.4.1 握手消息头部

```c
struct {
    HandshakeType msg_type;        // 消息类型
    uint24 length;                 // 原始消息总长度
    uint16 message_seq;            // DTLCP新增：消息序号
    uint24 fragment_offset;        // DTLCP新增：分片偏移量
    uint24 fragment_length;        // DTLCP新增：当前分片长度
    select (msg_type) {
        case hello_request:          HelloRequest;
        case client_hello:           ClientHello;
        case server_hello:           ServerHello;
        case hello_verify_request:   HelloVerifyRequest;  // DTLCP新增
        case certificate:            Certificate;
        case server_key_exchange:    ServerKeyExchange;
        case certificate_request:    CertificateRequest;
        case server_hello_done:      ServerHelloDone;
        case certificate_verify:     CertificateVerify;
        case client_key_exchange:    ClientKeyExchange;
        case finished:               Finished;
    } body;
} Handshake;
```

#### 6.4.2 消息类型枚举

```c
enum {
    hello_request(0),
    client_hello(1),
    server_hello(2),
    hello_verify_request(3),      // DTLCP新增
    certificate(11),
    server_key_exchange(12),
    certificate_request(13),
    server_hello_done(14),
    certificate_verify(15),
    client_key_exchange(16),
    finished(20),
    (255)
} HandshakeType;
```

#### 6.4.3 message_seq 的维护规则

- 每次握手的第一个消息 `message_seq = 0`
- 每产生一个新消息，`message_seq` 加 1
- **重传时使用相同的 message_seq**
- 重新握手时 HelloRequest 的 `message_seq = 0`，ServerHello 的 `message_seq = 1`
- 接收方维护 `next_receive_seq` 计数器：
  - `message_seq == next_receive_seq` → 处理消息，计数器加 1
  - `message_seq < next_receive_seq` → 丢弃（重复消息）
  - `message_seq > next_receive_seq` → 排队缓存（乱序到达）

### 6.5 握手消息分片与重组

#### 6.5.1 分片机制

当握手消息超过 PMTU 时，发送方将消息分为 N 个连续分片：

```
原始握手消息：[═══════════════════════════════════════]
                        │ 分片
        ┌───────────────┼───────────────┐
        ▼               ▼               ▼
    Fragment 0      Fragment 1      Fragment 2
    offset=0        offset=M        offset=2M
    length=M        length=M        length=last
    msg_seq=s       msg_seq=s       msg_seq=s
```

**关键规则**：
- 所有分片的 `length` 字段都等于原始消息总长度
- 所有分片的 `message_seq` 相同
- `fragment_offset` = 前面所有分片的累计字节数
- `fragment_length` = 当前分片的实际字节数
- 未分片消息：`fragment_offset = 0`，`fragment_length = length`
- **CertificateVerify 的哈希运算和 Finished 的校验数据计算中，必须先重组完整消息再参与运算**

#### 6.5.2 重组处理

- 接收到分片后缓存，直到收集齐所有分片
- 应能处理重叠的分片序列（发送方可能在 PMTU 变化后使用更小的分片重传）

### 6.6 握手流程

#### 6.6.1 完整握手流程（含 DoS 防护）

```
Client                                          Server

ClientHello (cookie为空)    ───────▶           第1轮

                            ◀───────  HelloVerifyRequest (含cookie)   第2轮

ClientHello (带cookie)      ───────▶           第3轮

                            ◀───────  ServerHello                     ┐
                            ◀───────  Certificate                     │
                            ◀───────  ServerKeyExchange*              │第4轮
                            ◀───────  CertificateRequest*             │
                            ◀───────  ServerHelloDone                 ┘

Certificate*                ───────▶                                   ┐
ClientKeyExchange           ───────▶                                   │
CertificateVerify*          ───────▶                                   │第5轮
[ChangeCipherSpec]          ───────▶                                   │
Finished                    ───────▶                                   ┘

                            ◀───────  [ChangeCipherSpec]              ┐第6轮
                            ◀───────  Finished                        ┘

Application Data            ◀──────▶ Application Data
```

> `*` 表示可选消息，`[]` 表示不属于握手协议消息。

#### 6.6.2 会话重用流程（含 DoS 防护）

```
Client                                          Server

ClientHello (cookie为空)    ───────▶           第1轮

                            ◀───────  HelloVerifyRequest (含cookie)   第2轮

ClientHello (带cookie, session_id=旧会话) ───▶ 第3轮

                            ◀───────  ServerHello (相同session_id)    ┐
                            ◀───────  [ChangeCipherSpec]              │第4轮
                            ◀───────  Finished                        ┘

[ChangeCipherSpec]          ───────▶                                   ┐第5轮
Finished                    ───────▶                                   ┘

Application Data            ◀──────▶ Application Data
```

#### 6.6.3 不使用 Cookie 时的握手（与 TLCP 相同）

当不使用无状态 Cookie 时，DTLCP 握手流程与 TLCP 完全一致，不包括 HelloVerifyRequest 交换。

### 6.7 各握手消息详解

#### 6.7.1 ClientHello

```c
struct {
    ProtocolVersion client_version;                    // {0x01, 0x01}
    Random random;                                     // 32字节 (gmt_unix_time + 28字节随机)
    SessionID session_id;                              // 0~32字节，空则新会话
    opaque cookie<0..2^8-1>;                           // DTLCP新增：Cookie
    CipherSuite cipher_suites<2..2^16-1>;
    CompressionMethod compression_methods<1..2^8-1>;
} ClientHello;
```

- 首次发送时 cookie 为空（0 长度）
- 响应 HelloVerifyRequest 时，必须使用与原始 ClientHello 相同的参数
- 服务端用这些参数验证 cookie 合法性

#### 6.7.2 HelloVerifyRequest

```c
struct {
    ProtocolVersion server_version;     // 版本号
    opaque cookie<0..2^8-1>;            // 无状态Cookie
} HelloVerifyRequest;
```

**Cookie 生成算法**：

```
Cookie = HMAC(Secret, Client-IP, Client-Parameters)
```

其中 `Client-Parameters` 包含 ClientHello 中的版本、随机数、会话ID、密码套件、压缩算法。

- 无状态：服务端不存储 Cookie，收到后重新计算验证
- 收到无效 Cookie → 当作无 Cookie 的新 ClientHello 处理（触发新的 HelloVerifyRequest）
- 服务端应始终执行 Cookie 交换以防御 DoS

#### 6.7.3 ServerHello

```c
struct {
    ProtocolVersion server_version;        // {0x01, 0x01}
    Random random;                         // 32字节
    SessionID session_id;                  // 会话标识
    CipherSuite cipher_suite;
    CompressionMethod compression_method;
} ServerHello;
```

- 如果发送了 HelloVerifyRequest，服务端必须先验证 Cookie 再发送 ServerHello
- 客户端收到 ServerHello 后验证服务端版本号是否匹配

#### 6.7.4 Server Certificate

- 格式：X.509 v3，符合 GB/T 20518
- **必须包含双证书**：签名证书在前，加密证书在后
- 密钥交换算法与证书密钥类型对应：

| 密钥交换算法 | 证书密钥类型 |
|-------------|-------------|
| ECC | ECC 公钥，使用加密证书中的公钥 |
| ECDHE | ECC 公钥，使用加密证书中的公钥（签名证书用于签名临时公钥） |
| RSA | RSA 公钥，使用加密证书中的公钥 |
| IBC | 服务端标识 + IBC 公共参数 |
| IBSDH | 服务端标识 + IBC 公共参数 |

#### 6.7.5 ServerKeyExchange

当密钥交换算法需要额外参数时发送（ECDHE 需临时公钥，ECC/RSA 不需）。

**ECDHE 模式**（使用 SM2）：

```c
struct {
    ServerECDHEParams params;            // EC参数 + 临时公钥
    digitally-signed struct {
        opaque client_random[32];
        opaque server_random[32];
        ServerECDHEParams params;
    } signed_params;                     // 服务端对参数的签名
} ServerKeyExchange;
```

**ECC 模式**（不发送 ServerKeyExchange，客户端直接从加密证书获取公钥）。

#### 6.7.6 CertificateRequest

```c
struct {
    ClientCertificateType certificate_types<1..2^8-1>;
    DistinguishedName certificate_authorities<0..2^16-1>;
} CertificateRequest;
```

客户端证书类型：
- `rsa_sign(1)` — RSA 签名证书
- `ecdsa_sign(64)` — ECC 签名证书（SM2）
- `ibc_params(80)` — IBC 公共参数

#### 6.7.7 ServerHelloDone

```c
struct { } ServerHelloDone;   // 空消息，标识 Hello 阶段完成
```

#### 6.7.8 Client Certificate

- 结构同 Server Certificate
- 仅在收到 CertificateRequest 后发送
- 签名证书在前，加密证书在后

#### 6.7.9 ClientKeyExchange

```c
struct {
    select (KeyExchangeAlgorithm) {
        case ECDHE:  opaque ClientECDHEParams<1..2^16-1>;
        case ECC:    opaque ECCEncryptedPreMasterSecret<0..2^16-1>;
        case IBSDH:  opaque ClientIBSDHParams<1..2^16-1>;
        case IBC:    opaque IBCEncryptedPreMasterSecret<0..2^16-1>;
        case RSA:    opaque RSAEncryptedPreMasterSecret<0..2^16-1>;
    } exchange_keys;
} ClientKeyExchange;
```

**ECC 模式下预主密钥结构**：

```c
struct {
    ProtocolVersion client_version;    // 客户端版本号
    opaque random[46];                  // 46字节随机数
} PreMasterSecret;
```

服务端解密后检查 `client_version` 是否与 ClientHello 中的值匹配。

#### 6.7.10 CertificateVerify

```c
struct {
    Signature signature;
} CertificateVerify;
```

- 仅在发送 Client Certificate 后发送
- 签名内容：从 ClientHello 开始到本消息之前（不含）的所有握手消息的 SM3 哈希
- **不包含**：初始 ClientHello（若被 HelloVerifyRequest 替换）和 HelloVerifyRequest
- SM2 签名方法参见 GB/T 35275

#### 6.7.11 Finished

```c
struct {
    opaque verify_data[12];
} Finished;
```

校验数据生成：

```
verify_data = PRF(master_secret, finished_label,
                  SM3(handshake_messages))[0..11]
```

- `finished_label`：客户端用 `"client finished"`，服务端用 `"server finished"`
- `handshake_messages`：从 ClientHello 到本消息之前（不含本消息、CCS、HelloRequest）的所有握手消息
- **不包含**：初始 ClientHello（如被替换）和 HelloVerifyRequest

---

## 7. 超时重传机制

### 7.1 状态机设计

DTLCP 使用基于状态机的超时重传机制，有四个基本状态：

```
                    ┌──────────┐
        ┌──────────▶│PREPARING │◀──────────┐
        │           └────┬─────┘           │
        │                │                 │
        │       发送消息已构造              │ HelloRequest /
        │                │                 │ 收到HelloRequest
        │                ▼                 │
        │           ┌──────────┐           │
        │   ┌───────│ SENDING  │◀──┐       │
        │   │       └────┬─────┘   │       │
        │   │            │         │       │
        │   │    发送完成 │   超时/ │       │ (最后一轮消息)
        │   │            │  收到重传│       │
        │   │            ▼         │       │
        │   │       ┌──────────┐   │       │
        │   └──────▶│ WAITING  │───┘       │
        │           └────┬─────┘           │
        │                │                 │
        │                │ 收到下一轮消息    │
        │                │                 │
        │                ▼                 │
        │           ┌──────────┐           │
        └───────────│ FINISHED │───────────┘
                    └──────────┘
```

### 7.2 状态说明

| 状态 | 行为 |
|------|------|
| **PREPARING** | 构造待发送的消息，缓存用于传输，完成后进入 SENDING |
| **SENDING** | 传输缓存的消息。如果是最后一个消息 → FINISHED；否则设置重传定时器 → WAITING |
| **WAITING** | 等待对端消息。三种退出方式 |
| **FINISHED** | 握手完成。保持 2×MSL 时间响应最后一个报文的重传 |

### 7.3 WAITING 状态的三种退出方式

| 触发条件 | 状态转换 | 行为 |
|----------|----------|------|
| 重传定时器超时 | → SENDING | 整轮重传已发送消息，重置定时器（值加倍），然后回到 WAITING |
| 收到对端重传消息 | → SENDING | 整轮重传已发送消息，重置定时器，然后回到 WAITING |
| 收到下一轮消息 | → FINISHED 或 PREPARING | 如果最后一轮 → FINISHED；否则 → PREPARING 构造新消息 |

### 7.4 重传定时器

| 参数 | 值 | 说明 |
|------|-----|------|
| 初始值 | 1 秒 | 比 DTLS 默认值更短，减少握手延时 |
| 退避策略 | 每次重传加倍 | 指数退避 |
| 最大值 | 64 秒（DTLCP）/ 60 秒（DTLS） | 避免长时间阻塞 |
| 重置条件 | 完成一次无丢包传输，或空闲 ≥ 10×当前值 | 恢复到初始值 |

### 7.5 消息轮次（Flight）定义

| 轮次 | 发送方 | 消息 |
|------|--------|------|
| 第 1 轮 | Client | ClientHello |
| 第 2 轮 | Server | HelloVerifyRequest |
| 第 3 轮 | Client | ClientHello（带 Cookie） |
| 第 4 轮 | Server | ServerHello, Certificate, ServerKeyExchange*, CertificateRequest*, ServerHelloDone |
| 第 5 轮 | Client | Certificate*, ClientKeyExchange, CertificateVerify*, [ChangeCipherSpec], Finished |
| 第 6 轮 | Server | [ChangeCipherSpec], Finished |

> 同一轮的消息在超时重传时作为一个整体全部重传。

### 7.6 死锁预防

- FINISHED 状态保持至少 **2 个默认 TCP MSL** 时间
- 传输最后一个报文的节点（普通握手中为服务端，会话恢复中为客户端）必须响应对端最后一个报文的重传
- 当收到新 epoch 的应用数据报文但未收到 Finished 时 → 立即重传最后一个报文

---

## 8. DoS 防护机制

### 8.1 问题分析

基于 UDP 的协议易受两类 DoS 攻击：

1. **放大攻击**：攻击者伪造源 IP 发送 ClientHello，服务端响应大量数据（证书链等）到受害者
2. **资源耗尽**：攻击者发送大量 ClientHello 迫使服务端维护大量半连接状态

### 8.2 无状态 Cookie 方案

DTLCP 采用 DTLS 的无状态 Cookie 技术：

```
Client                          Server
  │                               │
  │──── ClientHello (空cookie) ──▶│  ① 客户端发起连接
  │                               │  ② 服务端生成无状态Cookie
  │◀── HelloVerifyRequest ───────│    （不分配连接资源）
  │    (含Cookie)                 │
  │                               │
  │──── ClientHello (带Cookie) ──▶│  ③ 客户端回传Cookie
  │                               │  ④ 服务端验证Cookie，验证通过
  │◀── ServerHello ──────────────│     才开始分配连接资源
  │    ...继续握手...              │
```

### 8.3 Cookie 生成与验证

```python
def generate_cookie(secret, client_ip, client_params):
    """服务端生成无状态Cookie"""
    return HMAC_SM3(secret, client_ip + client_params)

def verify_cookie(secret, client_ip, client_params, cookie):
    """服务端验证Cookie - 无状态，重新计算后比对"""
    expected = generate_cookie(secret, client_ip, client_params)
    return constant_time_compare(expected, cookie)
```

- `secret`：服务端随机产生的密钥，定期轮换
- `client_ip`：服务端所见的客户端 IP 地址
- `client_params`：ClientHello 中的版本、随机数、会话ID、密码套件、压缩算法

### 8.4 安全保证

| 攻击类型 | 防御效果 |
|----------|----------|
| 源IP伪造放大攻击 | 攻击者必须能接收 Cookie 响应才能继续握手 |
| 半连接资源耗尽 | Cookie 验证通过前服务端不分配任何连接状态 |
| Cookie 重放 | 服务端定期更换 Secret，旧 Cookie 过期失效 |

---

## 9. 密钥计算

### 9.1 主密钥计算

```
master_secret = PRF(pre_master_secret, "master secret",
                    ClientHello.random + ServerHello.random)[0..47]
```

- 输入：预主密钥（48字节）+ 标签 + 客户端随机数（32字节）+ 服务端随机数（32字节）
- 输出：主密钥（48字节）

### 9.2 工作密钥计算

```
key_block = PRF(SecurityParameters.master_secret, "key expansion",
                SecurityParameters.server_random +
                SecurityParameters.client_random)
```

从 key_block 按顺序切分：

```
client_write_MAC_secret[SecurityParameters.hash_size]
server_write_MAC_secret[SecurityParameters.hash_size]
client_write_key[SecurityParameters.key_material_length]
server_write_key[SecurityParameters.key_material_length]
client_write_IV[SecurityParameters.fixed_iv_length]
server_write_IV[SecurityParameters.fixed_iv_length]
```

> **注意**：PRF 的 seed 参数中 `server_random` 在前，`client_random` 在后（与主密钥计算顺序不同）。

### 9.3 SM4-GCM 密钥长度

| 算法 | key_material_length | fixed_iv_length | 说明 |
|------|---------------------|-----------------|------|
| SM4-GCM | 16 字节 | 4 字节 | IV 共 12 字节：4 字节固定 IV + 8 字节显式 nonce |
| SM4-CBC | 16 字节 | 16 字节 | 完整 16 字节 IV |

---

## 10. 实现要点

### 10.1 关键状态变量

| 变量 | 类型 | 说明 |
|------|------|------|
| `epoch` | uint16 | 当前密码规格计数器 |
| `sequence_number` | uint48 | 当前 epoch 内记录序列号 |
| `message_seq` | uint16 | 当前握手消息序号 |
| `next_receive_seq` | uint16 | 期望的下一个握手消息序号 |
| `replay_window` | bitmap[64] | 重放保护滑动窗口 |
| `retransmit_timer` | timer | 重传定时器，初始 1s |
| `handshake_state` | enum | PREPARING/SENDING/WAITING/FINISHED |
| `flight_buffer` | []Handshake | 当前轮次待发送/重传的消息缓存 |

### 10.2 epoch 与 sequence_number 的生成

```python
def send_record(conn, record):
    """发送记录时维护 epoch 和 sequence_number"""
    record.epoch = conn.write_epoch
    record.sequence_number = conn.write_sequence_number
    conn.write_sequence_number += 1
    # 发送记录...

def change_cipher_spec(conn):
    """密码规格变更时递增 epoch"""
    conn.write_epoch += 1
    conn.write_sequence_number = 0
    # 激活未决写状态为当前写状态...
```

### 10.3 有序消息交付

接收方通过 `next_receive_seq` 确保握手消息有序处理：

```python
def receive_handshake(conn, msg):
    if msg.message_seq == conn.next_receive_seq:
        # 正常顺序，立即处理
        conn.next_receive_seq += 1
        process_message(msg)
        # 检查队列中是否有后续消息可处理
        drain_queue(conn)
    elif msg.message_seq < conn.next_receive_seq:
        # 重复消息，丢弃
        pass
    else:
        # 乱序到达，排队缓存
        conn.message_queue[msg.message_seq] = msg
```

### 10.4 实现约束

1. epoch 在 2×MSL 内不能重用
2. sequence_number 回绕前必须终止连接
3. 分片重组时应能处理重叠分片
4. 应用数据在收到当前 epoch 的 Finished 前应缓存或丢弃
5. MAC 错误可选择静默丢弃（而非立即中断连接）

### 10.5 TLCP → DTLCP 实现迁移映射

基于现有 `gotlcp/tlcp/` 代码结构，DTLCP 实现所需的改动点：

| TLCP 源文件 | DTLCP 改动 | 说明 |
|-------------|-----------|------|
| `common.go` | 新增常量 | DTLCP 版本号（与 TLCP 相同 `0x0101`）、`HelloVerifyRequest(3)` 消息类型 |
| `conn.go` | **重大改动** | 记录层新增 `epoch`、`sequence_number` 字段；MAC/AAD 计算改用显式序列号；添加重放滑动窗口 |
| `handshake_messages.go` | **重大改动** | 握手消息头部新增 `message_seq`、`fragment_offset`、`fragment_length`；新增 `HelloVerifyRequest` 编解码；`ClientHello` 新增 `cookie` 字段；分片/重组逻辑 |
| `handshake_client.go` | **重大改动** | 状态机改为 PREPARING→SENDING→WAITING→FINISHED；支持 HelloVerifyRequest/Cookie 交换；超时重传逻辑；分片发送 |
| `handshake_server.go` | **重大改动** | 同上；Cookie 生成和验证；防 DoS |
| `key_agreement.go` | 极小改动 | 与 TLCP 相同（SM2 ECC/ECDHE） |
| `key_schedule.go` | 无改动 | 与 TLCP 完全相同 |
| `prf.go` | 无改动 | 与 TLCP 完全相同（SM3 PRF） |
| `cipher_suites.go` | 极小改动 | AEAD nonce 构造使用 epoch+seq_num 替代隐式 seq_num |
| `alert.go` | 无改动 | 与 TLCP 相同 |
| `auth.go` | 无改动 | 证书链验证逻辑不变 |
| `tlcp.go` | 接口适配 | `Listen` → `ListenDTLCP`（net.PacketConn）；`Dial` → `DialDTLCP`（UDP）；提供 PMTU 配置接口 |
| `cache.go` | 无改动 | LRU 会话缓存不变 |
| `session.go` | 无改动 | 会话票据不变 |

**改动分级：**

```
无需改动（直接复用）：
  ├── prf.go           — SM3 PRF 完全一致
  ├── key_schedule.go  — 密钥派生完全一致
  ├── alert.go         — 报警协议完全一致
  ├── auth.go          — 证书验证完全一致
  ├── cache.go         — 会话缓存逻辑不变
  └── session.go       — 会话序列化逻辑不变

极小改动（仅参数适配）：
  ├── key_agreement.go — SM2 密钥协商逻辑不变
  └── cipher_suites.go — AEAD nonce 改用 epoch+seq_num

重大改动（核心差异）：
  ├── conn.go               — 记录层增加 epoch/seq_num，滑动窗口
  ├── handshake_messages.go — 新增消息头部字段、HelloVerifyRequest、分片
  ├── handshake_client.go   — 状态机 + Cookie + 重传
  ├── handshake_server.go   — 状态机 + Cookie 生成/验证 + 重传
  └── tlcp.go               — 传输层接口从 TCP 切到 UDP
```

**关键实现顺序建议**：

```
Phase 1: 记录层改造
  conn.go: DTLSPlaintext → DTLSCiphertext 的新增字段编解码
  cipher_suites.go: AEAD nonce 适配

Phase 2: 握手消息改造
  handshake_messages.go: message_seq, fragment_offset/length, HelloVerifyRequest, cookie

Phase 3: 握手状态机
  handshake_client.go: PREPARING/SENDING/WAITING/FINISHED 状态机
  handshake_server.go: Cookie 生成/验证，往返重传

Phase 4: 传输层适配
  tlcp.go: UDP + PMTU 接口

Phase 5: 测试与集成
  端到端握手测试、丢包/乱序/重复场景、DoS防护验证
```

---

## 附录 A：与 DTLS 1.2 的差异对照

| 方面 | DTLS 1.2 (RFC 6347) | DTLCP (GM/T 0128-2023) |
|------|---------------------|------------------------|
| 版本号 | `{254, 253}`（1's complement） | `{0x01, 0x01}` |
| 非对称算法 | RSA/ECDSA | SM2（ECC/ECDHE） |
| 分组密码 | AES（GCM/CBC） | SM4（GCM/CBC） |
| 杂凑算法 | SHA-256 | SM3 |
| PRF | P_SHA256 | P_SM3 |
| 签名算法 | RSA-SHA256, ECDSA-SHA256 | SM2WithSM3 (`0x0704`) |
| 双证书 | 不需要 | 需要（签名证书 + 加密证书） |
| HelloVerifyRequest 版本 | DTLS 1.0 `{254, 255}` | 与协议版本相同 `{0x01, 0x01}` |
| Cookie 最大值 | 255 字节 | 255 字节 |
| 重传定时器最大值 | 60 秒 | 64 秒 |
| 重放窗口默认值 | 64 | 64 |

## 附录 B：参考资料

- GB/T 38636-2020 信息安全技术 传输层密码协议（TLCP）
- GM/T 0128-2023 数据报传输层密码协议规范（DTLCP）
- RFC 6347 Datagram Transport Layer Security Version 1.2
- RFC 5246 The Transport Layer Security (TLS) Protocol Version 1.2
- GB/T 32918 信息安全技术 SM2 椭圆曲线公钥密码算法
- GB/T 32905 信息安全技术 SM3 密码杂凑算法
- GB/T 32907 信息安全技术 SM4 分组密码算法
- GB/T 20518 信息安全技术 公钥基础设施 数字证书格式规范
- GB/T 35275 信息安全技术 SM2 密码算法加密签名消息语法规范
- GB/T 35276 信息安全技术 SM2 密码算法使用规范
