# IBC 快速入门

IBC（Identity-Based Cryptography，标识密码）是 GoTLCP 依据 GM/T 0024-2023 实现的 4 个基于 SM9 的密码套件，**不使用 X.509 证书**，公钥由标识（如 `server@kgc.example`）与 KGC 公共参数直接推导。

> **协议支持：** 4 个套件同时可用于 **TLCP**（TCP，`tlcp` 包）与 **DTLCP**（UDP，`dtlcp` 包）。两个包的 IBC API 名称、类型与配置字段完全一致，差异只在连接建立方式与传输语义，见文末 [DTLCP（UDP）](#dtlcpudp)。

| 套件名 | 密钥交换 | 加密 | 校验 | 值 |
|--------|---------|------|------|-----|
| `IBC_SM4_GCM_SM3` | IBC | SM4-GCM | SM3 | `0xE057` |
| `IBC_SM4_CBC_SM3` | IBC | SM4-CBC | SM3 | `0xE017` |
| `IBSDH_SM4_GCM_SM3` | IBSDH | SM4-GCM | SM3 | `0xE055` |
| `IBSDH_SM4_CBC_SM3` | IBSDH | SM4-CBC | SM3 | `0xE015` |

**默认关闭**：IBC/IBSDH 套件不在默认套件列表中，必须在 `Config.CipherSuites` 中显式指定，并配置 `Config.IBCIdentity` 才会参与协商。

> 全部配置项、信任池与安全模型见 **[IBC 配置与使用指南](./IBC-Config.md)**。

---

## IBC标识

IBC 不使用证书，本端身份由 `IBCIdentity`（TLCP 为 `tlcp.IBCIdentity`，DTLCP 为 `dtlcp.IBCIdentity`）表示：

```go
type IBCIdentity struct {
	Identity              []byte                 // 标识，如 server@kgc.example，对端公钥由它推导
	Parameters            *IBCSysParams          // KGC 公共参数（主公钥与有效期），即信任锚
	SignPrivateKey        *sm9.SignPrivateKey    // 签名私钥，hid=0x01
	EncryptPrivateKey     *sm9.EncryptPrivateKey // 加密私钥，hid=0x03
	KeyExchangePrivateKey *sm9.EncryptPrivateKey // 密钥交换私钥，hid=0x02
}
```

三把用户私钥由 KGC 按标识派生，用途不同、不可互换；服务端与客户端各持有一份自己的 `IBCIdentity`（下方示例中的 `serverIdent` / `clientIdent`）。

> ⚠️ `LoadIBCIdentity` 只做装载，**不校验** `KeyExchangePrivateKey` 的派生 `hid`（应为 `0x02`），请自行保证 KGC 下发的私钥用途正确；装错私钥不会在配置期报错，而会在握手的 `Finished` 阶段以 `bad record MAC` 失败。详见 [IBC 配置与使用指南](./IBC-Config.md) §4.3。

从 KGC 下发的材料装载（入参均为 DER）：

```go
ident, err := tlcp.LoadIBCIdentity(identity, paramsDER, signKeyDER, encKeyDER, keyExchangeKeyDER)
```

> 字段定义、三把私钥的用途与生成/装载细节见 **[数字证书及密钥](./CertAndKey.md) 第 3 章**。

## 服务端

```go
config := &tlcp.Config{
	CipherSuites:       []uint16{tlcp.IBC_SM4_GCM_SM3, tlcp.IBSDH_SM4_GCM_SM3},
	IBCIdentity:        serverIdent, // 服务端标识 + 公共参数 + 私钥
	ClientIBCSysParams: pool,        // 信任的客户端 KGC 公共参数
	ClientAuth:         tlcp.RequireAnyClientCert, // 要求客户端认证
}
ln, err := tlcp.Listen("tcp", ":8443", config)
```

完整示例：[example/ibc/quickstart/server/main.go](../example/ibc/quickstart/server/main.go)

## 客户端

```go
conn, err := tlcp.Dial("tcp", "127.0.0.1:8443", &tlcp.Config{
	CipherSuites:     []uint16{tlcp.IBC_SM4_GCM_SM3, tlcp.IBSDH_SM4_GCM_SM3},
	IBCIdentity:      clientIdent, // 客户端标识 + 公共参数 + 私钥
	RootIBCSysParams: pool,        // 信任的服务端 KGC 公共参数
})
```

完整示例：[example/ibc/quickstart/client/main.go](../example/ibc/quickstart/client/main.go)

## 完整示例

- 密钥生成：[example/ibc/genkey/main.go](../example/ibc/genkey/main.go)
- 服务端：[example/ibc/quickstart/server/main.go](../example/ibc/quickstart/server/main.go)
- 客户端：[example/ibc/quickstart/client/main.go](../example/ibc/quickstart/client/main.go)

## DTLCP（UDP）

DTLCP 使用 `dtlcp` 包中的同名符号（`dtlcp.IBCIdentity`、`dtlcp.IBCPool`、`dtlcp.LoadIBCIdentity`、`dtlcp.IBC_SM4_GCM_SM3` …），配置字段与 TLCP 完全相同；只有建立连接的方式不同：服务端用 `dtlcp.Listen("udp", …)` + `Accept`，或直接对 `net.PacketConn` 调用 `dtlcp.Server`；客户端用 `dtlcp.Dial("udp", …)` 或 `dtlcp.Client`。

```go
// 服务端（UDP）
config := &dtlcp.Config{
	CipherSuites:       []uint16{dtlcp.IBC_SM4_GCM_SM3, dtlcp.IBSDH_SM4_GCM_SM3},
	IBCIdentity:        serverIdent,     // 服务端标识 + 公共参数 + 私钥
	ClientIBCSysParams: pool,            // 信任的客户端 KGC 公共参数
	ClientAuth:         dtlcp.RequireAndVerifyClientCert, // IBSDH 会自动要求客户端认证
}
ln, err := dtlcp.Listen("udp", ":8443", config)

// 客户端（UDP）
conn, err := dtlcp.Dial("udp", "127.0.0.1:8443", &dtlcp.Config{
	CipherSuites:     []uint16{dtlcp.IBC_SM4_GCM_SM3, dtlcp.IBSDH_SM4_GCM_SM3},
	IBCIdentity:      clientIdent,       // 客户端标识 + 公共参数 + 私钥
	RootIBCSysParams: pool,              // 信任的服务端 KGC 公共参数
})
```

DTLCP 下的额外注意点：

1. **握手消息自动分片**：IBC 变体 Certificate 消息携带完整的 `IBCSysParams`（通常数百字节），当超过 `Config.PMTU` 时由 DTLCP 按 RFC 6347 §4.2.3 自动分片传输并在对端重组，无需应用干预；若 `PMTU` 配置过小需保证仍能容纳 12 字节握手消息头。
2. **握手重传**：DTLCP 依赖 `InitialRetransmitTimeout` / `MaxRetransmitTimeout` 进行指数退避重传；对端参数校验失败等致命错误会立即以告警终止握手。
3. **会话重用**：DTLCP 同样支持 IBC 会话重用，需两端配置 `SessionCache`；DTLCP 的会话缓存以对端地址为键，因此同一客户端的地址变化会影响命中（详见 [DTLCP 配置与使用指南](./DTLCP-Config.md)）。
4. **数据报语义**：握手完成后可用 `Read`/`Write`（流式，不保证报文边界）或 `ReadFrom`/`WriteTo`（保留报文边界）收发数据；`ConnectionState().PeerIBCIdentity` / `PeerIBCSysParams` 与 TLCP 一致。

完整示例：[example/dtlcp/ibc/quickstart/server/main.go](../example/dtlcp/ibc/quickstart/server/main.go)、[example/dtlcp/ibc/quickstart/client/main.go](../example/dtlcp/ibc/quickstart/client/main.go)。与 TLCP 示例一致，两个 quickstart 文件内嵌了预置的测试密钥材料（不读写任何密钥文件，可直接运行）；需要更换材料时运行 [example/dtlcp/ibc/genkey/main.go](../example/dtlcp/ibc/genkey/main.go)，把输出的常量块替换进去即可。