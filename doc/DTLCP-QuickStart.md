# DTLCP 快速入门

DTLCP（Datagram TLCP）遵循 GM/T 0128-2023《数据报传输层密码协议规范》，在 UDP 不可靠传输上实现 TLCP 安全握手。

**与 TLCP 相比**：UDP 替代 TCP，增加 Cookie 防 DoS、握手重传、重放保护机制。适用低延迟、实时通信等非可靠传输场景。

## 准备工作

- Go ≥ 1.24
- 国密 SM2 证书两对：**签名证书**（身份认证）+ **加密证书**（密钥交换）

关于证书加载，参见 [数字证书及密钥](./CertAndKey.md)。

## 服务端

创建 `server.go`：

```go
package main

import (
    "fmt"
    "gitee.com/Trisia/gotlcp/dtlcp"
)

// 内嵌测试用证书（生产环境请从文件加载）
const sigCertPEM = `-----BEGIN CERTIFICATE-----
MIICHTCCAcSgAwIBAgIIAs5iVWOA17swCgYIKoEcz1UBg3UwQjELMAkGA1UEBhMC
Q04xDzANBgNVBAgMBua1meaxnzEPMA0GA1UEBwwG5p2t5beeMREwDwYDVQQKDAjm
tYvor5VDQTAeFw0yMjA3MTUxMzU5MzhaFw0yMzA3MTUxMzU5MzhaMF4xCzAJBgNV
BAYTAmNuMQ8wDQYDVQQIDAbmtZnmsZ8xDzANBgNVBAcMBuadreW3njEQMA4GA1UE
ChMHR08gVExDUDENMAsGA1UECxMEVGVzdDEMMAoGA1UEAxMDMDAxMFkwEwYHKoZI
zj0CAQYIKoEcz1UBgi0DQgAElcuhLnzaqjMbCGBAg6QZTA6iMCsck90kwh4NK0ro
+XY0XwzYaD5PQq7VehcucHGvrUL2VK2d+v16i1J2aD+N5aOBhzCBhDAOBgNVHQ8B
Af8EBAMCBsAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAdBgNV
HQ4EFgQU77hb1KL698m25EqrGuBHdEN8WEswHwYDVR0jBBgwFoAUNpPjFOdFCfrV
7+ovEi3ToZY8wqQwDwYDVR0RBAgwBocEfwAAATAKBggqgRzPVQGDdQNHADBEAiB/
VgNXutPGOqHaaywG6yApn4I5ipd4lQmDzDArHGgPtgIgRtoKKhJzAVknoubSZqKL
6YtPS7P6mYhCzW3974poADA=
-----END CERTIFICATE-----`

const sigKeyPEM = `-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgC1Sw2Ptopr75mxS/
R+lT45og/55WuueomJKSXqTmAfKgCgYIKoEcz1UBgi2hRANCAASVy6EufNqqMxsI
YECDpBlMDqIwKxyT3STCHg0rSuj5djRfDNhoPk9CrtV6Fy5wca+tQvZUrZ36/XqL
UnZoP43l
-----END PRIVATE KEY-----`

const encCertPEM = `-----BEGIN CERTIFICATE-----
MIICHjCCAcSgAwIBAgIIAs5iVWOA9lcwCgYIKoEcz1UBg3UwQjELMAkGA1UEBhMC
Q04xDzANBgNVBAgMBua1meaxnzEPMA0GA1UEBwwG5p2t5beeMREwDwYDVQQKDAjm
tYvor5VDQTAeFw0yMjA3MTUxMzU5MzhaFw0yMzA3MTUxMzU5MzhaMF4xCzAJBgNV
BAYTAmNuMQ8wDQYDVQQIDAbmtZnmsZ8xDzANBgNVBAcMBuadreW3njEQMA4GA1UE
ChMHR08gVExDUDENMAsGA1UECxMEVGVzdDEMMAoGA1UEAxMDMDAxMFkwEwYHKoZI
zj0CAQYIKoEcz1UBgi0DQgAEeiDKvy4amGMSU6lSmohUwcI4oRAVGSW6ktL2v3mq
ps8J9JDEfMskknEVWjfrL7OT+EaYm0rO7tvx6oJqrmUd5qOBhzCBhDAOBgNVHQ8B
Af8EBAMCAzgwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAdBgNV
HQ4EFgQU9SD+JHfBKpsN/+zbSSkZnw1qVdAwHwYDVR0jBBgwFoAUNpPjFOdFCfrV
7+ovEi3ToZY8wqQwDwYDVR0RBAgwBocEfwAAATAKBggqgRzPVQGDdQNIADBFAiAD
29ovbTAIhZgfvAYKXphZSvcMnQ3QdCDyCqb4j8KMQwIhAINoMaInvyMB86C/aa7P
gqBZDVjZd/X+yWxzRGtLG/AT
-----END CERTIFICATE-----`

const encKeyPEM = `-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgpcgOKHIjr+jDTNjc
mfeSZuYZlwi344P7s7bz1ofThjigCgYIKoEcz1UBgi2hRANCAAR6IMq/LhqYYxJT
qVKaiFTBwjihEBUZJbqS0va/eaqmzwn0kMR8yySScRVaN+svs5P4RpibSs7u2/Hq
gmquZR3m
-----END PRIVATE KEY-----`

func main() {
    // 加载签名证书和加密证书
    sigCert, err := dtlcp.X509KeyPair([]byte(sigCertPEM), []byte(sigKeyPEM))
    if err != nil {
        panic(err)
    }
    encCert, err := dtlcp.X509KeyPair([]byte(encCertPEM), []byte(encKeyPEM))
    if err != nil {
        panic(err)
    }

    // 服务端必须同时提供签名证书和加密证书
    config := &dtlcp.Config{
        Certificates: []dtlcp.Certificate{sigCert, encCert},
    }

    ln, err := dtlcp.Listen("udp", ":8443", config)
    if err != nil {
        panic(err)
    }
    defer ln.Close()
    fmt.Println("DTLCP 服务端已启动，监听 :8443")

    for {
        conn, err := ln.Accept()
        if err != nil {
            fmt.Printf("Accept 错误: %v\n", err)
            continue
        }
        go handleConn(conn.(*dtlcp.Conn))
    }
}

func handleConn(conn *dtlcp.Conn) {
    defer conn.Close()
    buf := make([]byte, 1024)
    n, addr, err := conn.ReadFrom(buf)
    if err != nil {
        fmt.Printf("读取错误: %v\n", err)
        return
    }
    fmt.Printf("收到来自 %s: %s\n", addr, buf[:n])
    conn.WriteTo([]byte("Hello DTLCP Client!"), addr)
}
```

## 客户端

创建 `client.go`：

```go
package main

import (
    "fmt"
    "gitee.com/Trisia/gotlcp/dtlcp"
)

func main() {
    // InsecureSkipVerify: true 跳过证书校验，仅用于测试！
    conn, err := dtlcp.Dial("udp", "127.0.0.1:8443", &dtlcp.Config{
        InsecureSkipVerify: true,
    })
    if err != nil {
        panic(err)
    }
    defer conn.Close()

    conn.WriteTo([]byte("Hello DTLCP Server!"), conn.RemoteAddr())

    buf := make([]byte, 1024)
    n, addr, err := conn.ReadFrom(buf)
    if err != nil {
        panic(err)
    }
    fmt.Printf("收到来自 %s: %s\n", addr, buf[:n])
}
```

## 运行

```bash
# 终端 1：启动服务端
go run server.go

# 终端 2：启动客户端
go run client.go
```

客户端输出 `收到: Hello DTLCP Client!` 表示握手和通信成功。

也可以直接运行仓库内的完整示例：

```bash
# 终端 1
go run example/dtlcp/quickstart/server/main.go

# 终端 2
go run example/dtlcp/quickstart/client/main.go
```

## 更多示例

所有示例可编译运行，内嵌测试用证书。各场景入口如下：

### 身份认证

- **单向认证** — [example/dtlcp/auth/](../example/dtlcp/auth/)，客户端验证服务端，最常见模式
- **双向认证** — [example/dtlcp/mutual_auth/](../example/dtlcp/mutual_auth/)，双方互相验证，ECC 套件
- **ECDHE 前向安全** — [example/dtlcp/ecdhe/](../example/dtlcp/ecdhe/)，双向认证 + ECDHE，需双证书
- **跳过证书校验** — [example/dtlcp/skip_verify/](../example/dtlcp/skip_verify/)，仅测试用，不验证证书
- **自定义证书校验** — [example/dtlcp/custom_verify/](../example/dtlcp/custom_verify/)，通过 VerifyPeerCertificate 回调

### 会话与传输

- **会话重用** — [example/dtlcp/resume/](../example/dtlcp/resume/)，缓存会话减少握手开销
- **复用 PacketConn** — [example/dtlcp/raw/](../example/dtlcp/raw/)，在已有 UDP socket 上运行 DTLCP
- **数据报模式** — [example/dtlcp/packetconn/](../example/dtlcp/packetconn/)，ReadFrom/WriteTo 保留消息边界

### 高级特性

- **密码套件选择** — [example/dtlcp/cipher_suites/](../example/dtlcp/cipher_suites/)，手动指定加密套件
- **ALPN 协议协商** — [example/dtlcp/alpn/](../example/dtlcp/alpn/)，协商应用层协议
- **多证书/SNI** — [example/dtlcp/multi_cert/](../example/dtlcp/multi_cert/)，根据域名动态选择证书
- **DTLCP 特有配置** — [example/dtlcp/cookie_config/](../example/dtlcp/cookie_config/)，PMTU、Cookie、重传超时、重放窗口

### 文档

- [DTLCP 配置详解](./DTLCP-Config.md) — 每个配置项的作用、默认值、取值范围
