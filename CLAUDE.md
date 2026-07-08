# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

GoTLCP 是 GB/T 38636-2020《信息安全技术 传输层密码协议》(TLCP，也称 GMSSL) 的 Go 语言实现。代码裁剪自 Go 1.19 `crypto/tls` 模块，国密算法（SM2/SM3/SM4）由 `github.com/emmansun/gmsm` 提供。

模块路径：`gitee.com/Trisia/gotlcp`，Go 版本要求 ≥ 1.24。

## 构建与测试

```bash
# 构建
go build -v ./...

# 运行所有测试
go test -v ./...

# 运行单个包的测试
go test -v ./tlcp/...
go test -v ./dtlcp/...
go test -v ./pa/...

# 运行单个测试函数
go test -v -run TestHandshake ./tlcp/

# CI 用 -short 跳过慢测试
go test -v -short ./...
```

## 包结构与职责

```
gotlcp/
├── tlcp/       # 核心协议实现（流式，TCP）
├── dtlcp/      # 数据报传输层密码协议（DTLCP，UDP）
├── pa/         # 协议适配器（TLCP/TLS 自适应）
├── https/      # TLCP HTTPS 客户端
├── example/    # 示例代码
└── doc/        # 文档
```

### `tlcp/` — 核心协议包

协议层自底向上：

| 文件 | 职责 |
|------|------|
| `common.go` | 常量定义（协议版本 `0x0101`、记录类型、握手消息类型、扩展类型、签名算法 `SM2WithSM3 = 0x0704`）、`Config` 结构体、`Certificate` 结构体、`ConnectionState`、`ClientAuthType` |
| `alert.go` | TLCP 告警（alert）错误码及中文含义 |
| `conn.go` | `Conn` 结构体（实现 `net.Conn`）、记录层读写、加密/解密、MAC 计算 |
| `handshake_messages.go` | 所有握手消息的 marshal/unmarshal（ClientHello、ServerHello、Certificate、ServerKeyExchange、ClientKeyExchange、CertificateVerify、Finished） |
| `handshake_client.go` | 客户端握手状态机 `clientHandshake()` |
| `handshake_server.go` | 服务端握手状态机 `serverHandshake()` |
| `key_agreement.go` | `keyAgreementProtocol` 接口，ECC/ECDHE 两种密钥协商实现 |
| `key_schedule.go` | 密钥派生：`masterSecret` → 工作密钥（MAC key、加密 key、IV） |
| `prf.go` | SM3 伪随机函数 |
| `cipher_suites.go` | 密码套件定义，支持 SM4-GCM 和 SM4-CBC |
| `cache.go` | LRU 会话缓存，用于会话重用 |
| `tlcp.go` | 公开 API：`Dial`、`Listen`、`Server`、`Client`、`LoadX509KeyPair`、`X509KeyPair`、`Dialer` |
| `auth.go` | 证书链验证逻辑 |
| `session.go` | `SessionState` 序列化与会话票据 |

**关键设计差异（相对于标准 TLS）**：
- TLCP 需要**双证书**：签名证书（`Certificates[0]`）+ 加密证书（`Certificates[1]`），服务端必须同时提供
- 密钥协商分 ECC（非前向安全）和 ECDHE（前向安全）两种模式
- 签名算法为 `SM2WithSM3`（而非 ECDSA+SHA256）
- 记录层版本号为 `0x0101`，用于与 TLS 协议版本区分

### `dtlcp/` — 数据报传输层密码协议（UDP）

DTLCP (Datagram TLCP) 遵循 GM/T 0128-2023《数据报传输层密码协议规范》，在 UDP 不可靠传输上实现 TLCP 握手。基于 `net.PacketConn` 而非 `net.Conn`，**不与 TLCP/TLS 互通**。

**与 TLCP（流式）的核心差异**：

| 特性 | TLCP (TCP) | DTLCP (UDP) |
|------|-----------|-------------|
| 传输层 | `net.Conn` | `net.PacketConn` |
| 记录头 | 5 字节 | 13 字节（新增 Epoch[2]+SeqNum[6]）|
| 序列号 | 隐含递增 | 显式 48 位字段 |
| 握手状态机 | `clientHello`→`serverHello`→... | 四态：`Preparing`→`Sending`→`Waiting`→`Finished` |
| 分片 | 无需 | 握手消息分片重组（`fragmentBuffer`）|
| 重传 | 无需 | 指数退避重传定时器（`RetransmitTimer`）|
| DoS 防护 | 无 | HelloVerifyRequest + Cookie 机制 |
| 重放保护 | 无需 | 滑动窗口（`replayWindow`，最小 32 位）|

**四态握手状态机**（`common.go:handshakeState`）：

```
statePreparing → 构造 Flight 消息
stateSending   → 逐个发送 Flight，写完后转入 Waiting
stateWaiting   → 等待对端响应/重传超时
stateFinished  → 握手完成
```

超时触发 `backoff()`（指数退避），收到有效消息后 `reset()`。

| 文件 | 职责 |
|------|------|
| `common.go` | 常量、`Config`、`Certificate`、`ConnectionState`、`uint24`/`uint48` 类型、四态握手状态机定义 |
| `conn.go` | `Conn` 结构体（基于 `PacketConn`）、记录层读写（13 字节头）、分片重组、Flight 发送 |
| `handshake_messages.go` | 握手消息 marshal/unmarshal（含分片偏移/长度字段、`messageSeq`）|
| `handshake_client.go` | 客户端四态握手：发送 ClientHello → 收 HelloVerifyRequest → 重发带 Cookie 的 ClientHello → ... |
| `handshake_server.go` | 服务端四态握手：收 ClientHello → 发送 HelloVerifyRequest + Cookie → 验证 Cookie → ... |
| `key_agreement.go` | `keyAgreementProtocol` 接口，ECC/ECDHE 密钥协商 |
| `key_schedule.go` | 密钥派生 |
| `prf.go` | SM3 伪随机函数 |
| `cipher_suites.go` | 密码套件（同 TLCP）|
| `fragment.go` | `fragmentBuffer`：握手消息分片重组缓冲区 |
| `retransmit.go` | `RetransmitTimer`：指数退避重传定时器（`initial`→`backoff`→`max`）|
| `replay.go` | `replayWindow`：48 位序列号滑动窗口防重放 |
| `cookie.go` | HMAC-SM3 Cookie 生成/验证（无状态 DoS 防护）|
| `alert.go` | DTLCP 告警错误码 |
| `auth.go` | 证书链验证 |
| `cache.go` | LRU 会话缓存 |
| `dtlcp.go` | 公开 API：`Dial`、`Listen`、`Server`、`Client`、`LoadX509KeyPair`、`X509KeyPair` |
| `session.go` | `SessionState` 序列化与会话票据 |

**DTLCP 握手流程**：

```
Client                                  Server
ClientHello          -------->
                      <--------          HelloVerifyRequest (含 Cookie)
ClientHello+Cookie   -------->
                      <--------          ServerHello
                      <--------          Certificate*
                      <--------          ServerKeyExchange*
                      <--------          CertificateRequest*
                      <--------          ServerHelloDone
Certificate*         -------->
ClientKeyExchange    -------->
CertificateVerify*   -------->
[ChangeCipherSpec]   -------->
Finished             -------->
                      <--------          [ChangeCipherSpec]
                      <--------          Finished
```

客户端先发 ClientHello，服务端回应 HelloVerifyRequest（含 HMAC-SM3 Cookie），客户端重发带 Cookie 的 ClientHello，之后流程与 TLCP 相同。`messageSeq` 在重新发送时递增。

**DTLCP 典型用法**：

```go
// 服务端
config := &dtlcp.Config{
    Certificates: []dtlcp.Certificate{sigCert, encCert},
}
ln, _ := dtlcp.Listen("udp", ":8443", config)

// 客户端
conn, _ := dtlcp.Dial("udp", "127.0.0.1:8443", &dtlcp.Config{
    InsecureSkipVerify: true,
})
```

### `pa/` — 协议适配器

利用 TLS/TLCP 记录层头部格式相同的特点，在建立连接后通过记录层版本号判断协议类型，自动分发到对应协议栈。

| 文件 | 职责 |
|------|------|
| `pa.go` | `Listen`/`NewListener`，返回自适应 Listener |
| `conn.go` | `Conn` 包装原始连接，提供双协议切换 |
| `switch_server_conn.go` | 服务端连接切换逻辑，peek 客户端首字节判断协议 |

### `https/` — HTTPS 支持

| 文件 | 职责 |
|------|------|
| `client.go` | `NewHTTPSClient`/`NewHTTPSClientDialer`，返回使用 TLCP 拨号的 `http.Client` |

## 密码套件优先级

1. `ECC_SM4_GCM_SM3` — ECC 密钥交换 + SM4-GCM + SM3（默认优先）
2. `ECC_SM4_CBC_SM3` — ECC 密钥交换 + SM4-CBC + SM3
3. `ECDHE_SM4_GCM_SM3` — ECDHE 密钥交换 + SM4-GCM + SM3（前向安全）
4. `ECDHE_SM4_CBC_SM3` — ECDHE 密钥交换 + SM4-CBC + SM3（前向安全）

## 握手流程

```
Client                                  Server
ClientHello         -------->
                    <--------           ServerHello
                    <--------           Certificate*
                    <--------           ServerKeyExchange*
                    <--------           CertificateRequest*
                    <--------           ServerHelloDone
Certificate*        -------->
ClientKeyExchange   -------->
CertificateVerify*  -------->
[ChangeCipherSpec]  -------->
Finished            -------->
                    <--------           [ChangeCipherSpec]
                    <--------           Finished
Application Data    <------->           Application Data
```

*标注 `*` 的消息为可选/条件发送。双向认证时需要客户端 Certificate 和 CertificateVerify。

## 常用模式

### 创建 TLCP 服务端

```go
config := &tlcp.Config{
    Certificates: []tlcp.Certificate{sigCert, encCert},  // 必须 2 个
}
ln, _ := tlcp.Listen("tcp", ":8443", config)
```

### 创建 TLCP 客户端

```go
conn, _ := tlcp.Dial("tcp", "127.0.0.1:8443", &tlcp.Config{
    InsecureSkipVerify: true,  // 开发测试，生产勿用
})
```

### 协议自适应监听（同时支持 TLCP + TLS）

```go
ln, _ := pa.Listen("tcp", ":9443", tlcpCfg, tlsCfg)
```
