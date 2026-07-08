# DTLCP 配置详解

`dtlcp.Config` 控制 DTLCP 连接的全部行为，覆盖证书、加密套件、超时、防 DoS、重放保护等方面。

---

## 1. Config 字段参考

### 1.1 通用字段（服务端 & 客户端均适用）

| 字段 | 类型 | 默认值 | 作用 |
|------|------|--------|------|
| `Rand` | `io.Reader` | `crypto/rand.Reader` | 随机数源，必须线程安全 |
| `Time` | `func() time.Time` | `time.Now` | 时间源，返回当前时间 |
| `Certificates` | `[]Certificate` | `nil` | 证书列表。服务端需要 `[签名证书, 加密证书]` 2 个；客户端双向认证时需要 1 个签名证书，ECDHE 时需要 2 个 |
| `GetCertificate` | `func(*ClientHelloInfo) (*Certificate, error)` | `nil` | 动态选择签名证书。仅在 `Certificates` 为空时调用 |
| `GetKECertificate` | `func(*ClientHelloInfo) (*Certificate, error)` | `nil` | 动态选择加密证书。仅在 `Certificates` 为空或长度不足 2 时调用 |
| `GetClientCertificate` | `func(*CertificateRequestInfo) (*Certificate, error)` | `nil` | 客户端响应服务端证书请求 |
| `GetClientKECertificate` | `func(*CertificateRequestInfo) (*Certificate, error)` | `nil` | 客户端响应服务端加密证书请求（ECDHE 需要） |
| `GetConfigForClient` | `func(*ClientHelloInfo) (*Config, error)` | `nil` | 服务端根据 ClientHello 动态生成 Config |
| `VerifyPeerCertificate` | `func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error` | `nil` | 自定义对端证书校验 |
| `VerifyConnection` | `func(ConnectionState) error` | `nil` | 证书验证完成后、握手结束前的最后校验 |
| `RootCAs` | `*x509.CertPool` | 系统根证书池 | 客户端验证服务端证书的根证书池 |
| `ClientCAs` | `*x509.CertPool` | `nil` | 服务端验证客户端证书的根证书池 |
| `ClientAuth` | `ClientAuthType` | `NoClientCert` | 服务端对客户端的身份认证策略（见 §1.3） |
| `InsecureSkipVerify` | `bool` | `false` | 跳过证书校验。**仅用于测试，生产环境开启将遭受中间人攻击** |
| `CipherSuites` | `[]uint16` | `nil`（使用全部默认套件） | 密码套件列表，越靠前优先级越高。设为 `nil` 按默认优先级排列 |
| `SessionCache` | `SessionCache` | `nil` | 会话缓存器，启用后支持会话重用，减少握手开销 |
| `MinVersion` / `MaxVersion` | `uint16` | 均为 `0x0101` | 协议版本范围。目前 TLCP/DTLCP 仅一个版本 |
| `CurvePreferences` | `[]CurveID` | `nil` | 椭圆曲线偏好列表 |
| `NextProtos` | `[]string` | `nil` | 支持的应用层协议（ALPN），如 `["h2", "http/1.1"]` |
| `ServerName` | `string` | `""` | 服务端名称（SNI），客户端用于校验证书中的主机名 |
| `OnAlert` | `func(code uint8, conn *Conn)` | `nil` | 告警回调。收到对端 alert 时触发，回调内不要执行耗时操作 |
| `EnableDebug` | `bool` | `false` | 开启调试日志 |
| `ClientECDHEParamsAsVector` | `bool` | `false` | ECDHE 兼容性开关。若与其他 TLCP 实现的 ECDHE 集成测试失败，可尝试设为 `true` |
| `TrustedCAIndications` | `[]TrustedAuthority` | `nil` | 客户端指定信任的 CA 列表，服务端需配合 `GetCertificate`/`GetKECertificate` 使用 |

### 1.2 DTLCP 特有字段

| 字段 | 类型 | 默认值 | 最小值 | 作用 | 适用端 |
|------|------|--------|--------|------|--------|
| `PMTU` | `int` | **1400** | — | 路径 MTU（字节）。握手消息超过此值时自动分片传输。 | 双方 |
| `CookieSecret` | `[]byte` | `nil` | 16 字节（推荐） | HMAC-SM3 Cookie 密钥。`nil` 表示不启用 Cookie 验证。 | 仅服务端 |
| `ReplayWindow` | `int` | **64** | 32 | 重放检测滑动窗口大小。值越大乱序容忍度越高。 | 双方 |
| `InitialRetransmitTimeout` | `time.Duration` | **1s** | — | 握手消息初始重传超时。超时后翻倍重试。 | 双方 |
| `MaxRetransmitTimeout` | `time.Duration` | **64s** | — | 握手消息最大重传超时。指数退避的上限。 | 双方 |
| `NewTimer` | `func(d time.Duration) *TimerHandle` | `defaultNewTimer` | — | 定时器工厂。用于测试时注入 mock 定时器。 | 双方 |

### 1.3 ClientAuth 取值

`ClientAuth` 控制服务端是否以及如何验证客户端证书：

| 常量 | 含义 |
|------|------|
| `NoClientCert` | 不要求客户端证书（默认） |
| `RequestClientCert` | 请求客户端证书，但客户端可不发送 |
| `RequireAnyClientCert` | 要求客户端发送证书，但不验证有效性 |
| `VerifyClientCertIfGiven` | 若客户端提供了证书则验证，否则跳过 |
| `RequireAndVerifyClientCert` | 要求客户端发送证书并验证有效性 |

---

## 2. DTLCP 特有字段详解

### 2.1 PMTU — 路径 MTU

**影响范围**：握手消息分片。应用数据不受 PMTU 影响。

握手消息（如 Certificate）可能超过 PMTU，此时自动拆分为多个片段发送，对端收到后重组。

- **默认 1400 字节**：适用于大多数 UDP 网络（以太网 MTU 1500，减去 IP 头 20 + UDP 头 8 + DTLCP 记录头 13 ≈ 1459 可用，1400 留有余量）
- 若链路支持 jumbo frame（MTU 9000），可调大至 **8000~9000** 以减少分片
- 若网络 MTU 偏小（如 VPN 隧道），可调小至 **1200** 避免 IP 层分片

```go
config := &dtlcp.Config{
    Certificates: []dtlcp.Certificate{sigCert, encCert},
    PMTU:         8000, // jumbo frame 环境
}
```

### 2.2 CookieSecret — 防 DoS Cookie 密钥

服务端收到无 Cookie 的 ClientHello 时，不分配状态，直接返回 HelloVerifyRequest（携带 HMAC-SM3 Cookie）。客户端必须重发带 Cookie 的 ClientHello，服务端验证通过后才继续握手。全程无状态，防止 UDP 源地址伪造放大攻击。

- **`nil`（默认）**：不启用 Cookie 验证。服务端直接进入握手状态机
- 密钥须**随机生成**、妥善保管。建议长度 **≥ 16 字节**
- 客户端无须配置

```go
// 使用 crypto/rand 生成随机 CookieSecret
secret := make([]byte, 32)
if _, err := rand.Read(secret); err != nil {
    panic(err)
}

config := &dtlcp.Config{
    Certificates: []dtlcp.Certificate{sigCert, encCert},
    CookieSecret: secret,
}
```

### 2.3 ReplayWindow — 重放滑动窗口

每条 DTLCP 记录头包含 epoch（2 字节）和 sequence_number（6 字节，48 位）。滑动窗口以同 epoch 内已接收的最大 seq_num 为右边缘：

- `seq_num ≤ 右边缘 - 窗口大小` → 判定为重放，丢弃
- 窗口内已记录 → 判定为重复，丢弃
- 新 seq_num、MAC 验证通过 → 标记并接受

**默认 64**，最小 32。高丢包、高乱序网络可适当增大（如 128）。

```go
config := &dtlcp.Config{
    Certificates: []dtlcp.Certificate{sigCert, encCert},
    ReplayWindow: 128, // 高乱序网络
}
```

### 2.4 InitialRetransmitTimeout / MaxRetransmitTimeout — 重传超时

DTLCP 握手使用四态状态机（PREPARING → SENDING → WAITING → FINISHED）。发送方进入 WAITING 后启动重传定时器：

1. 超时未收到响应 → 重传本轮 Flight + 超时值 ×2
2. 再次超时 → 继续翻倍，直到 `MaxRetransmitTimeout`
3. 收到有效消息 → 重置定时器

**调优建议**：

| 网络环境 | `InitialRetransmitTimeout` | `MaxRetransmitTimeout` |
|----------|---------------------------|------------------------|
| 局域网（低延迟、低丢包） | 300ms ~ 500ms | 8s |
| 广域网（互联网） | 1s ~ 2s | 60s |
| 高丢包/卫星链路 | 500ms ~ 1s | 60s |

```go
config := &dtlcp.Config{
    Certificates:             []dtlcp.Certificate{sigCert, encCert},
    InitialRetransmitTimeout: 500 * time.Millisecond,
    MaxRetransmitTimeout:     8 * time.Second,
}
```

### 2.5 NewTimer — 定时器工厂

默认使用 `time.NewTimer`。测试时可注入 mock 定时器精确控制超时触发时机。

```go
config := &dtlcp.Config{
    NewTimer: func(d time.Duration) *dtlcp.TimerHandle {
        t := time.NewTimer(d)
        return &dtlcp.TimerHandle{
            C:     t.C,
            Stop:  t.Stop,
            Reset: t.Reset,
        }
    },
}
```

---

## 3. 基础场景

### 3.1 单向认证（客户端验证服务端）

最常见的使用模式。服务端提供双证书，客户端验证服务端身份。

**服务端**：

```go
sigCert, _ := dtlcp.X509KeyPair(sigCertPEM, sigKeyPEM)
encCert, _ := dtlcp.X509KeyPair(encCertPEM, encKeyPEM)

config := &dtlcp.Config{
    Certificates: []dtlcp.Certificate{sigCert, encCert},
}
ln, _ := dtlcp.Listen("udp", ":8443", config)
```

**客户端**：

```go
pool := smx509.NewCertPool()
pool.AddCert(rootCert) // 加载服务端根证书

config := &dtlcp.Config{
    RootCAs: pool,
}
conn, _ := dtlcp.Dial("udp", "127.0.0.1:8443", config)
```

> 完整代码：[example/dtlcp/auth/](../example/dtlcp/auth/)

### 3.2 双向认证（双方互相验证）

服务端验证客户端身份，适用于企业内部服务等高安全场景。

**服务端**：

```go
pool := smx509.NewCertPool()
pool.AddCert(clientRootCert)

config := &dtlcp.Config{
    Certificates: []dtlcp.Certificate{sigCert, encCert},
    ClientAuth:   dtlcp.RequireAndVerifyClientCert, // 要求并验证客户端证书
    ClientCAs:    pool,
}
ln, _ := dtlcp.Listen("udp", ":8443", config)
```

**客户端（ECC 套件，单证书）**：

```go
config := &dtlcp.Config{
    RootCAs:      pool,
    Certificates: []dtlcp.Certificate{authCert}, // 仅签名证书
}
```

**客户端（ECDHE 套件，双证书）**：

```go
config := &dtlcp.Config{
    RootCAs:      pool,
    Certificates: []dtlcp.Certificate{authCert, encCert}, // 签名 + 加密
    CipherSuites: []uint16{dtlcp.ECDHE_SM4_GCM_SM3, dtlcp.ECDHE_SM4_CBC_SM3},
}
```

> 完整代码：[example/dtlcp/mutual_auth/](../example/dtlcp/mutual_auth/) 和 [example/dtlcp/ecdhe/](../example/dtlcp/ecdhe/)

### 3.3 跳过证书校验（仅测试）

```go
config := &dtlcp.Config{
    InsecureSkipVerify: true, // 生产环境禁止使用！
}
```

---

## 4. 高级场景

### 4.1 会话重用

频繁短连接时，通过缓存会话减少完整握手开销。

```go
config := &dtlcp.Config{
    Certificates: []dtlcp.Certificate{sigCert, encCert},
    SessionCache: dtlcp.NewLRUSessionCache(128), // 最多缓存 128 个会话
}
```

设置后，第二次 `Dial` 将走重用握手流程，可在 `ConnectionState().DidResume` 中确认：

```go
conn, _ := dtlcp.Dial("udp", addr, config)
if conn.ConnectionState().DidResume {
    fmt.Println("会话重用成功")
}
```

> 完整代码：[example/dtlcp/resume/](../example/dtlcp/resume/)

### 4.2 复用现有 PacketConn

已有 UDP socket 的场景，通过 `dtlcp.Server` 或 `dtlcp.Client` 包装。

**服务端**：

```go
pconn, _ := net.ListenPacket("udp", ":8443")
buf := make([]byte, 1500)
n, addr, _ := pconn.ReadFrom(buf) // 等待客户端首包
// buf[:n] 为首个 DTLCP 握手消息
conn := dtlcp.Server(pconn, addr, config)
defer conn.Close()
// 之后通过 conn.Read/Write 通信
```

**客户端**：

```go
raw, _ := net.Dial("udp", "127.0.0.1:8443")
conn := dtlcp.Client(raw.(net.PacketConn), raw.RemoteAddr(), config)
defer conn.Close()
```

> 完整代码：[example/dtlcp/raw/](../example/dtlcp/raw/)

### 4.3 密码套件选择

默认按优先级启用全部 4 个套件。可通过 `CipherSuites` 限制：

```go
// 仅使用 ECDHE 前向安全套件
config := &dtlcp.Config{
    Certificates: []dtlcp.Certificate{sigCert, encCert},
    CipherSuites: []uint16{
        dtlcp.ECDHE_SM4_GCM_SM3,
        dtlcp.ECDHE_SM4_CBC_SM3,
    },
}
```

可用的密码套件常量：

| 常量 | ID | 密钥交换 | 加密 | 前向安全 |
|------|-----|---------|------|---------|
| `ECC_SM4_GCM_SM3` | `0xe013` | ECC | SM4-GCM | 否 |
| `ECC_SM4_CBC_SM3` | `0xe011` | ECC | SM4-CBC | 否 |
| `ECDHE_SM4_GCM_SM3` | `0xe053` | ECDHE | SM4-GCM | 是 |
| `ECDHE_SM4_CBC_SM3` | `0xe051` | ECDHE | SM4-CBC | 是 |

GCM 为认证加密模式，性能优于 CBC；ECDHE 提供前向安全性，但需客户端双证书。

> 完整代码：[example/dtlcp/cipher_suites/](../example/dtlcp/cipher_suites/)

### 4.4 ALPN 协议协商

```go
config := &dtlcp.Config{
    Certificates: []dtlcp.Certificate{sigCert, encCert},
    NextProtos:   []string{"h2", "http/1.1"},
}
```

握手完成后通过 `conn.ConnectionState().NegotiatedProtocol` 获取协商结果。

> 完整代码：[example/dtlcp/alpn/](../example/dtlcp/alpn/)

### 4.5 证书动态选择（SNI / 多租户）

通过 `GetCertificate` / `GetKECertificate` 回调根据客户端 SNI 或 TrustedCA 选择对应证书：

```go
config := &dtlcp.Config{
    GetCertificate: func(info *dtlcp.ClientHelloInfo) (*dtlcp.Certificate, error) {
        switch info.ServerName {
        case "app1.example.com":
            return &app1SigCert, nil
        case "app2.example.com":
            return &app2SigCert, nil
        }
        return &defaultSigCert, nil
    },
    GetKECertificate: func(info *dtlcp.ClientHelloInfo) (*dtlcp.Certificate, error) {
        switch info.ServerName {
        case "app1.example.com":
            return &app1EncCert, nil
        case "app2.example.com":
            return &app2EncCert, nil
        }
        return &defaultEncCert, nil
    },
}
```

> 完整代码：[example/dtlcp/multi_cert/](../example/dtlcp/multi_cert/)

### 4.6 自定义证书校验

关闭默认校验，通过回调实现自定义验证逻辑：

```go
config := &dtlcp.Config{
    InsecureSkipVerify: true,
    VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*smx509.Certificate) error {
        // 实现自定义验证逻辑
        // rawCerts 为对端证书的 DER 编码字节序列
        if len(rawCerts) == 0 {
            return errors.New("对端未提供证书")
        }
        return nil
    },
}
```

> 完整代码：[example/dtlcp/custom_verify/](../example/dtlcp/custom_verify/)

---

## 5. Read/Write 与 ReadFrom/WriteTo

DTLCP `Conn` 同时实现 `net.Conn` 和 `net.PacketConn` 两套接口。

### 5.1 Read/Write（流式）— net.Conn

```go
conn.Write([]byte("hello"))
buf := make([]byte, 1024)
n, _ := conn.Read(buf)
```

- `Read` 从解密缓冲区消费数据，不保证每次返回一条完整记录
- `Write` 数据过大时自动切分为多条 DTLCP 记录
- 适合：简单请求-响应模式、移植已有 TCP 代码

### 5.2 ReadFrom/WriteTo（数据报）— net.PacketConn

```go
conn.WriteTo([]byte("ping"), remoteAddr)
buf := make([]byte, 1500)
n, addr, _ := conn.ReadFrom(buf)
```

- 每次 `ReadFrom` 返回一条完整 DTLCP 记录（保留消息边界）
- 每次 `WriteTo` 产生一条独立 DTLCP 记录，单条最大 **16384 字节**
- 适合：需保留消息边界的 UDP 应用

### 5.3 选择指南

| 需求 | 推荐接口 |
|------|---------|
| 简单请求-响应（一问一答） | `Read/Write` |
| 移植已有 TCP 代码 | `Read/Write` |
| 需保留消息边界 | `ReadFrom/WriteTo` |
| 与 `net.PacketConn` 生态集成 | `ReadFrom/WriteTo` |

> 完整代码：[example/dtlcp/packetconn/](../example/dtlcp/packetconn/)
