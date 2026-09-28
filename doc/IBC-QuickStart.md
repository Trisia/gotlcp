# IBC 快速入门

IBC（Identity-Based Cryptography，标识密码）是 GoTLCP 依据 GM/T 0024-2023 实现的 4 个基于 SM9 的 TLCP 密码套件，**不使用 X.509 证书**，公钥由标识（如 `server@kgc.example`）与 KGC 公共参数直接推导。

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

IBC 不使用证书，本端身份由 `tlcp.IBCIdentity` 表示：

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