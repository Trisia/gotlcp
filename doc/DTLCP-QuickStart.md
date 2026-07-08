# DTLCP 快速入门

## 1. 概述

DTLCP（Datagram TLCP）是 TLCP 协议在 UDP 传输层上的适配版本，遵循 GM/T 0128-2023 规范。

与 TLCP 的核心区别：
- **UDP 传输**：基于 `net.PacketConn`，而非 TCP 流
- **Cookie 防 DoS**：服务端通过无状态 Cookie 验证客户端可达性
- **重传机制**：握手消息通过四态状态机和指数退避保证可靠交付
- **重放保护**：基于 epoch + 序列号滑动窗口检测重放攻击

## 2. 准备工作

DTLCP 服务端需要两对国密 SM2 证书和密钥：
- **签名证书** — 用于数字签名、身份认证
- **加密证书** — 用于密钥交换、加密传输

关于证书和密钥的解析构造，请参考 [GoTLCP 数字证书及密钥](./CertAndKey.md)。

## 3. 服务端快速开始

```go
package main

import (
    "fmt"
    "gitee.com/Trisia/gotlcp/dtlcp"
)

// 证书 PEM 内容（签名证书 + 加密证书）
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
-----END CERTIFICATE-----
`
const sigKeyPEM = `-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgC1Sw2Ptopr75mxS/
R+lT45og/55WuueomJKSXqTmAfKgCgYIKoEcz1UBgi2hRANCAASVy6EufNqqMxsI
YECDpBlMDqIwKxyT3STCHg0rSuj5djRfDNhoPk9CrtV6Fy5wca+tQvZUrZ36/XqL
UnZoP43l
-----END PRIVATE KEY-----
`
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
-----END CERTIFICATE-----
`
const encKeyPEM = `-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgpcgOKHIjr+jDTNjc
mfeSZuYZlwi344P7s7bz1ofThjigCgYIKoEcz1UBgi2hRANCAAR6IMq/LhqYYxJT
qVKaiFTBwjihEBUZJbqS0va/eaqmzwn0kMR8yySScRVaN+svs5P4RpibSs7u2/Hq
gmquZR3m
-----END PRIVATE KEY-----
`

func main() {
    sigCert, err := dtlcp.X509KeyPair([]byte(sigCertPEM), []byte(sigKeyPEM))
    if err != nil {
        panic(err)
    }
    encCert, err := dtlcp.X509KeyPair([]byte(encCertPEM), []byte(encKeyPEM))
    if err != nil {
        panic(err)
    }

    config := &dtlcp.Config{
        Certificates: []dtlcp.Certificate{sigCert, encCert},
    }

    ln, err := dtlcp.Listen("udp", ":8443", config)
    if err != nil {
        panic(err)
    }
    defer ln.Close()

    for {
        conn, err := ln.Accept()
        if err != nil {
            panic(err)
        }
        go handleConn(conn.(*dtlcp.Conn))
    }
}

func handleConn(conn *dtlcp.Conn) {
    defer conn.Close()
    buf := make([]byte, 1024)
    n, err := conn.Read(buf)
    if err != nil {
        return
    }
    fmt.Printf(">> %s\n", buf[:n])
    _, err = conn.Write([]byte("Hello DTLCP Client!"))
    if err != nil {
        fmt.Printf("conn.Write error: %v\n", err)
        return
    }
}
```

完整代码见 [example/dtlcp/quickstart/server/main.go](../example/dtlcp/quickstart/server/main.go)。
<!-- 此示例文件将由 Task 6 创建，当前尚不存在。 -->

## 4. 客户端快速开始

```go
package main

import (
    "fmt"
    "gitee.com/Trisia/gotlcp/dtlcp"
)

func main() {
    // InsecureSkipVerify 跳过证书校验（仅用于测试！）
    config := &dtlcp.Config{
        InsecureSkipVerify: true,
    }

    conn, err := dtlcp.Dial("udp", "127.0.0.1:8443", config)
    if err != nil {
        panic(err)
    }
    defer conn.Close()

    _, err = conn.Write([]byte("Hello DTLCP Server!"))
    if err != nil {
        panic(err)
    }

    buf := make([]byte, 1024)
    n, err := conn.Read(buf)
    if err != nil {
        panic(err)
    }
    fmt.Printf(">> %s\n", buf[:n])
}
```

完整代码见 [example/dtlcp/quickstart/client/main.go](../example/dtlcp/quickstart/client/main.go)。
<!-- 此示例文件将由 Task 6 创建，当前尚不存在。 -->

## 5. 运行与验证

```bash
# 终端1：启动服务端
go run example/dtlcp/quickstart/server/main.go

# 终端2：启动客户端
go run example/dtlcp/quickstart/client/main.go
```

客户端应输出服务端返回的 `Hello DTLCP Client!` 消息。

## 6. 下一步

- [DTLCP 配置与使用指南](./DTLCP-Config.md) — 完整配置参考和场景手册
- [example/dtlcp/](../example/dtlcp/) — 所有场景的完整示例代码
