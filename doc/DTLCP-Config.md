# DTLCP 配置与使用指南

## 1. 概述

DTLCP 的 Config 完全独立于 TLCP Config，不依赖 `tlcp` 包。DTLCP 核心差异在于：基于 `net.PacketConn`（UDP）、Cookie 防 DoS、握手重传、重放保护。

## 2. 基础配置

### 2.1 单向身份认证

适用于服务端不需要验证客户端身份，客户端只需安全传输通道的场景。

**服务端配置：**
```go
config := &dtlcp.Config{
    Certificates: []dtlcp.Certificate{sigCert, encCert},
}
ln, _ := dtlcp.Listen("udp", ":8443", config)
```

**客户端配置：**
```go
pool := smx509.NewCertPool()
pool.AddCert(rootCert)
config := &dtlcp.Config{
    RootCAs: pool,
}
conn, _ := dtlcp.Dial("udp", "127.0.0.1:8443", config)
```

完整示例见 [example/dtlcp/auth/](../example/dtlcp/auth/)。

### 2.2 双向身份认证

适用于双方均需身份认证的高安全通信场景。

**服务端配置：**
```go
pool := smx509.NewCertPool()
pool.AddCert(clientRootCert)
config := &dtlcp.Config{
    Certificates: []dtlcp.Certificate{sigCert, encCert},
    ClientAuth:   dtlcp.RequireAndVerifyClientCert,
    ClientCAs:    pool,
}
```

**客户端配置（ECC 套件，单证书）：**
```go
config := &dtlcp.Config{
    RootCAs:      pool,
    Certificates: []dtlcp.Certificate{authCert},
}
```

**客户端配置（ECDHE 套件，双证书）：**
```go
config := &dtlcp.Config{
    RootCAs:      pool,
    Certificates: []dtlcp.Certificate{authCert, encCert},
    CipherSuites: []uint16{dtlcp.ECDHE_SM4_GCM_SM3, dtlcp.ECDHE_SM4_CBC_SM3},
}
```

完整示例见 [example/dtlcp/mutual_auth/](../example/dtlcp/mutual_auth/) 和 [example/dtlcp/ecdhe/](../example/dtlcp/ecdhe/)。

### 2.3 跳过证书校验（仅测试用）

**安全警告：此方式仅用于开发测试，生产环境可能遭受中间人攻击。**

```go
config := &dtlcp.Config{
    InsecureSkipVerify: true,
}
```

完整示例见 [example/dtlcp/skip_verify/](../example/dtlcp/skip_verify/)。

## 3. DTLCP 特有配置

### 3.1 PMTU — 路径 MTU

- 默认值：**1400 字节**
- 影响握手消息分片阈值，消息超过 PMTU 时自动分片
- 若链路支持 jumbo frame（如 9000），可适当调大以减少分片次数

```go
config := &dtlcp.Config{
    Certificates: []dtlcp.Certificate{sigCert, encCert},
    PMTU:         9000, // 启用 jumbo frame
}
```

### 3.2 CookieSecret — 服务端 Cookie 密钥

- 用于 HMAC-SM3 生成 HelloVerifyRequest Cookie，防 DoS
- 仅服务端需要，密钥必须随机且保密，建议至少 16 字节

```go
config := &dtlcp.Config{
    Certificates: []dtlcp.Certificate{sigCert, encCert},
    CookieSecret: []byte("my-random-secret-key-16b"),
}
```

### 3.3 ReplayWindow — 重放滑动窗口大小

- 默认值：**64**，最小 32
- 值越大，包乱序容忍度越高

### 3.4 InitialRetransmitTimeout / MaxRetransmitTimeout

- 初始重传超时：默认 **1 秒**
- 最大重传超时：默认 **64 秒**
- 退避策略：每次超时翻倍，直到上限

```go
config := &dtlcp.Config{
    InitialRetransmitTimeout: 500 * time.Millisecond, // 低延迟网络
    MaxRetransmitTimeout:     8 * time.Second,
}
```

### 3.5 NewTimer — 定时器工厂

默认使用 `time.NewTimer`。测试时可注入 mock 定时器精确控制超时。

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

完整 DTLCP 特有配置示例见 [example/dtlcp/cookie_config/](../example/dtlcp/cookie_config/)。

## 4. 客户端场景

### 4.1 单向认证连接

适用于客户端验证服务端身份的最常见场景。配置 `RootCAs` 验证服务端证书。

示例见 [example/dtlcp/auth/client/](../example/dtlcp/auth/client/)。

### 4.2 双向认证连接

适用于服务端要求客户端身份的场景（如企业内部服务）。

示例见 [example/dtlcp/mutual_auth/client/](../example/dtlcp/mutual_auth/client/)。

### 4.3 ECDHE 前向安全

适用于需要前向安全性的高安全通信。需要客户端同时提供签名和加密双证书。

示例见 [example/dtlcp/ecdhe/](../example/dtlcp/ecdhe/)。

### 4.4 会话重用

适用于频繁短连接的场景，通过缓存会话减少握手开销。

```go
config := &dtlcp.Config{
    RootCAs:      pool,
    SessionCache: dtlcp.NewLRUSessionCache(128),
}
```

示例见 [example/dtlcp/resume/](../example/dtlcp/resume/)。

### 4.5 使用现有 PacketConn

适用于已有 UDP socket 想在其上运行 DTLCP 的场景。

```go
raw, _ := net.ListenPacket("udp", ":0")
conn := dtlcp.Client(raw, serverAddr, config)
defer conn.Close()
```

示例见 [example/dtlcp/raw/](../example/dtlcp/raw/)。

### 4.6 密码套件选择

适用于需要限制特定加密算法的场景。

示例见 [example/dtlcp/cipher_suites/](../example/dtlcp/cipher_suites/)。

## 5. 服务端场景

### 5.1 单向认证监听

适用于对客户端无身份要求的公开服务。

示例见 [example/dtlcp/auth/server/](../example/dtlcp/auth/server/)。

### 5.2 双向认证监听

适用于需要控制客户端准入的内部系统。

示例见 [example/dtlcp/mutual_auth/server/](../example/dtlcp/mutual_auth/server/)。

### 5.3 会话重用

适用于高频客户端连接，通过 `SessionCache` 降低 CPU 开销。

示例见 [example/dtlcp/resume/server/](../example/dtlcp/resume/server/)。

### 5.4 使用现有 PacketConn

适用于将已有 UDP 服务升级为 DTLCP 安全通信的场景。

```go
pconn, _ := net.ListenPacket("udp", ":8443")
// ...收到客户端报文，获取 remoteAddr
conn := dtlcp.Server(pconn, remoteAddr, config)
defer conn.Close()
```

示例见 [example/dtlcp/raw/server/](../example/dtlcp/raw/server/)。

### 5.5 证书动态选择

适用于多证书/多租户/SNI 场景，通过 `GetCertificate`/`GetKECertificate` 回调动态选择证书。

```go
config := &dtlcp.Config{
    GetCertificate: func(info *dtlcp.ClientHelloInfo) (*dtlcp.Certificate, error) {
        if info.ServerName == "app1.example.com" {
            return &app1SigCert, nil
        }
        return &defaultSigCert, nil
    },
    GetKECertificate: func(info *dtlcp.ClientHelloInfo) (*dtlcp.Certificate, error) {
        if info.ServerName == "app1.example.com" {
            return &app1EncCert, nil
        }
        return &defaultEncCert, nil
    },
}
```

示例见 [example/dtlcp/multi_cert/](../example/dtlcp/multi_cert/)。

## 6. net.Conn 与 net.PacketConn 兼容说明

DTLCP `Conn` 同时实现了 `net.Conn` 和 `net.PacketConn` 接口。

### 6.1 Read/Write（流式读写）— net.Conn

- 适用于移植 TCP/TLCP 代码、简单请求-响应模式
- `Read` 从解密缓冲区消费数据，不保证每次返回一条记录
- `Write` 自动切分大数据块为多条 DTLCP 记录

### 6.2 ReadFrom/WriteTo（数据报读写）— net.PacketConn

- 适用于需要保留 UDP 消息边界的场景
- 每条 `ReadFrom` 返回一条完整的 DTLCP 应用数据记录
- 每条 `WriteTo` 产生一条独立的 DTLCP 应用数据记录，单条最大 16384 字节

### 6.3 选择建议

| 需求 | 推荐接口 |
|------|---------|
| 移植已有 TCP (TLCP) 代码 | Read/Write |
| 简单请求-响应 | Read/Write |
| 需要保留消息边界 | ReadFrom/WriteTo |
| 与标准库 net.PacketConn 生态集成 | ReadFrom/WriteTo |

示例见 [example/dtlcp/packetconn/](../example/dtlcp/packetconn/)。

## 7. Cookie 机制说明

DTLCP 通过无状态 Cookie 防止 UDP 源地址伪造的 DoS 攻击：

1. 客户端发送 ClientHello（cookie 为空）
2. 服务端返回 HelloVerifyRequest，携带 HMAC-SM3(CookieSecret, clientAddr || clientHelloParams) 生成的 cookie
3. 客户端重发 ClientHello，携带收到的 cookie
4. 服务端验证 cookie 有效性后继续握手

Cookie 不存储在服务端，完全基于 HMAC-SM3 实时生成和验证。

## 8. 重传与超时调优

DTLCP 握手使用四态状态机（PREPARING → SENDING → WAITING → FINISHED）：

- 发送方在 SENDING 后进入 WAITING，启动重传定时器
- 超时未收到响应 → 重传 flight + 定时器翻倍（最多到 MaxRetransmitTimeout）
- 收到对端重传请求 → 立即重传
- 握手完成 → FINISHED

**生产调优建议：**
- 低延迟局域网：`InitialRetransmitTimeout = 500ms`
- 广域网：`InitialRetransmitTimeout = 2s`
- 高丢包网络：适当降低 `InitialRetransmitTimeout`，加快重传节奏

## 9. 重放保护原理

- 每条 DTLCP 记录头包含 epoch（2 字节）和 sequence_number（6 字节）
- epoch 递增表示密钥更新（如重握手），seq_num 在同一 epoch 内单调递增
- 滑动窗口以 epoch 内已接受的最大 seq_num 为右边缘
- seq_num < 右边缘 - 窗口大小 → 丢弃
- 窗口内已记录 → 丢弃（重复包）
- 新 seq_num → MAC 验证通过后标记

## 10. 关键密钥置零

DTLCP 与 TLCP 使用相同的 `setZero` 机制：

- 预主密钥：主密钥生成后置零
- 主密钥：握手完成后置零
- 工作密钥：连接关闭时置零

置零方法反复将内存写入 0xFF 和 0x00 各 3 遍，设置内存屏障防止编译器优化。
