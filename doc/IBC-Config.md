# IBC 配置与使用指南

> **标准依据：** GM/T 0024-2023《SSL VPN 技术规范》
> **配套标准：** GM/T 0081-2020《SM9 密码算法加密签名消息语法规范》、GM/T 0090-2020《标识密码应用标识格式规范》、GM/T 0044-2016《SM9 标识密码算法》
> **依赖库：** `github.com/emmansun/gmsm`（SM9 算法）
>
> **兼容性立场：** 本实现**以 GM/T 0024-2023 为唯一实现依据，不兼容 GB/T 38636-2020 的 IBC 报文**。原因见 §2.2。

`tlcp.Config` 中与 IBC 相关的字段、KGC 公共参数与信任池、各场景的配置方式，以及必须了解的安全模型与告警映射，均汇总于本文。

- 想先跑起来：**[IBC 快速入门](./IBC-QuickStart.md)**

---

## 1. 概述

### 1.1 支持的密码套件

GoTLCP 依据 GM/T 0024-2023 表 2 实现以下 4 个基于 SM9 标识密码的 TLCP 密码套件：

| 常量 | 套件名 | 密钥交换 | 加密 | 校验 | 值 |
|------|--------|---------|------|------|-----|
| `IBC_SM4_GCM_SM3` | `IBC_SM4_GCM_SM3` | IBC | SM4-GCM | SM3 | `0xE057` |
| `IBC_SM4_CBC_SM3` | `IBC_SM4_CBC_SM3` | IBC | SM4-CBC | SM3 | `0xE017` |
| `IBSDH_SM4_GCM_SM3` | `IBSDH_SM4_GCM_SM3` | IBSDH | SM4-GCM | SM3 | `0xE055` |
| `IBSDH_SM4_CBC_SM3` | `IBSDH_SM4_CBC_SM3` | IBSDH | SM4-CBC | SM3 | `0xE015` |

**默认关闭：** 这 4 个套件不在 `cipherSuitesPreferenceOrder` 中，`Config.CipherSuites` 为 `nil` 时不会启用。必须同时满足两个条件才会协商成功：

1. `Config.CipherSuites` 中**显式列出** IBC/IBSDH 套件；
2. 本端具备 IBC 能力（`Config.IBCIdentity != nil`，或提供 `GetIBCIdentity` / `GetClientIBCIdentity` 回调）。

任一侧缺少 IBC 能力时，带 `suiteIBC` 标志的套件在**套件选择阶段被跳过**，而不是选中后报错。IBSDH 套件额外要求本端配置了 `KeyExchangePrivateKey`（它应当按 `hid=0x02` 派生，但**本库不校验其派生 hid**，详见 §4.3），缺失时同样在套件选择阶段被跳过（客户端侧仅静态配置时生效，回调场景无法在 ClientHello 阶段预知）。

### 1.2 IBC 与 IBSDH 的区别

| 维度 | IBC | IBSDH |
|------|-----|-------|
| 密钥交换 | 客户端用服务端标识 + 加密主公钥单向加密预主密钥 | 双方执行 SM9 密钥交换协议协商预主密钥 |
| 服务端所需私钥 | 加密私钥（hid=`0x03`） | 密钥交换私钥（hid=`0x02`） |
| 客户端标识传递 | 不需要（`client_id` 扩展被忽略） | **必需**，服务端需据此计算 `R_A` |
| 客户端认证 | 由应用通过 `ClientAuth` 决定 | **自动强制**要求客户端认证（除非显式设为 `RequestClientCert`） |
| 前向安全 | 无 | 有 |

### 1.3 使用前提

- 一个可用的 KGC，能提供**公共参数**与**用户私钥**；
- 公共参数必须通过**带外渠道**预置到对端信任池（`RootIBCSysParams` / `ClientIBCSysParams`），或由校验回调判定。

### 1.4 相关文档

| 文档 | 内容 |
|------|------|
| [IBC 快速入门](./IBC-QuickStart.md) | 单文件可运行示例、运行方式 |
| [客户端配置](./ClientConfig.md) / [服务端配置](./ServerConfig.md) | 通用 Config 字段 |
| [数字证书及密钥](./CertAndKey.md) | 第 1、2 章仅 ECC/ECDHE 套件适用；第 3 章为 SM9/IBC 的密钥与公共参数 |

---

## 2. 标准依据与兼容性立场

### 2.1 报文格式（GM/T 0024-2023）

**Server Key Exchange（6.4.5.4）：**

```
enum { ECDHE, ECC, IBSDH, IBC, RSA } KeyExchangeAlgorithm;

case IBSDH:
    ServerIBSDHParams params;                    // = KeyAgreementInfo 的 DER
    digitally-signed struct {
        opaque client_random[32];
        opaque server_random[32];
        ServerIBSDHParams params;
    } signed_params;

case IBC:
    digitally-signed struct {                    // 注意：无 params、无加密公钥字段
        opaque client_random[32];
        opaque server_random[32];
        opaque ibc_id<1..2^16-1>;                // 服务端标识
    } signed_params;
```

**Client Key Exchange（6.4.5.8）：**

```
case IBSDH:
    opaque ClientIBSDHParams<1..2^16-1>;             // = KeyAgreementInfo 的 DER
case IBC:
    opaque IBCEncryptedPreMasterSecret<0..2^16-1>;   // = SM9Cipher 的 DER
```

**Certificate（IBC 变体，6.4.5.3 / 6.4.5.7）：**

```
opaque ASN.1IBCParam<1..2^24-1>;
struct {
    opaque ibc_id<1..2^16-1>;      // 服务端/客户端标识
    ASN.1IBCParam ibc_parameter;   // = IBCSysParams 的 DER
} Certificate;
```

- `ibc_id`：GM/T 0090-2020 中 `Identifier` 结构的 DER 编码结果，**或由用户自定义的标识信息**；
- `ibc_parameter`：GM/T 0081-2020 附录 A.2 定义的 `IBCSysParams` 的 DER。

**Certificate Request（6.4.5.5）：**
`certificate_types` 取值 `rsa_sign(1), sm2_sign(64), ibc_params(80)`；当为 `ibc_params` 时，`certificate_authorities` 为「IBC 密钥管理中心的信任域名列表」。

**Certificate Verify（6.4.5.9）：** 签名算法 `ibs_sm3`，对「自 ClientHello 起至本消息之前的全部握手消息（含类型与长度域）」的 SM3 摘要做 SM9 签名。

**ClientHello 扩展（附录 A.7）：**

```
opaque ClientID<1..2^16-1>;
```

> 「客户端的 Client Hello 消息的 CipherSuite 包括 **IBSDH** 密钥交换算法时，需要发送 Client ID 扩展，指定客户端的标识信息。」

### 2.2 为什么不兼容 GB/T 38636-2020

GM/T 0024-2023 前言明确修订了两处：s) 增加 `ibc_parameter` 的内容定义；t) **更改** IBC 的 `signed_params` 内容定义。两者在 IBC 报文上互不兼容：

| 项 | GB/T 38636-2020 | GM/T 0024-2023 |
|----|----------------|----------------|
| IBC 的 `ServerKeyExchange` | `ServerIBCSysParams` + `IBCEncryptionKey[1024]` | 仅 `signed_params` |
| IBC 的签名覆盖范围 | `… ‖ ServerIBCSysParams ‖ IBCEncryptionKey` | `… ‖ ibc_id<1..2^16-1>` |
| 服务端加密公钥来源 | `IBCEncryptionKey[1024]` | Certificate 中的 `ibc_parameter` |
| IBSDH 客户端标识传递 | **无机制** | `client_id(66)` 扩展 |

**放弃兼容的理由是 GB/T 38636-2020 本身不完备：**

1. **IBSDH 缺少客户端标识传递机制。** 没有 `client_id` 扩展，服务端作为发起方 A **拿不到客户端标识**，因而无法计算 `R_A = r_A · Q_B`。这是逻辑硬伤，不是缺一个可选字段。
2. **`ServerIBCSysParams` 没有定义。** 标准只说「密钥交换参数格式参见 SM9 算法」，但 SM9 算法标准（GM/T 0044 / GB/T 38635.2）中并无对应的密钥交换参数结构。
3. **`IBCEncryptionKey[1024]` 无法实现。** SM9 加密主公钥未压缩仅 65 字节，而标准要求定长 1024 字节，且未规定填充规则与内容构成。

**实现行为：** 本库不实现 GB/T 38636-2020 的解析与生成分支。遇到不兼容报文时，按 §9 的规则**直接报告无法解析**，不做格式识别，也不在错误信息中涉及该标准。

---

## 3. Config 字段参考

### 3.1 IBC 相关字段

| 字段 | 类型 | 默认值 | 适用端 | 作用 |
|------|------|--------|--------|------|
| `IBCIdentity` | `*IBCIdentity` | `nil` | 双方 | 本端 IBC 身份（标识、公共参数、三把私钥）。IBC 套件生效的前提 |
| `GetIBCIdentity` | `func(*ClientHelloInfo) (*IBCIdentity, error)` | `nil` | 仅服务端 | 按 ClientHello 动态选择 IBC 配置。**仅当 `IBCIdentity` 为空时调用** |
| `GetClientIBCIdentity` | `func(*CertificateRequestInfo) (*IBCIdentity, error)` | `nil` | 仅客户端 | 响应服务端证书请求时动态给出 IBC 配置。**仅当 `IBCIdentity` 为空时调用** |
| `RootIBCSysParams` | `*IBCPool` | `nil` | 仅客户端 | 客户端信任的**服务端** KGC 公共参数池。服务端下发的 `ibc_parameter` 必须命中该池。**未配置（`nil`）时默认以本端 `IBCIdentity.Parameters` 作为信任池，此时要求对端与本端属于同一 KGC** |
| `ClientIBCSysParams` | `*IBCPool` | `nil` | 仅服务端 | 服务端信任的**客户端** KGC 公共参数池，用于校验客户端 `CertificateVerify`。**未配置（`nil`）时默认以本端 `IBCIdentity.Parameters` 作为信任池，此时要求对端与本端属于同一 KGC** |
| `VerifyIBCSysParams` | `func(*IBCSysParams) error` | `nil` | 双方 | 未配置显式信任池时的兜底校验。**回调、信任池、本端公共参数均不可用时，IBC 握手直接失败** |
| `VerifyIBCIdentity` | `func(identity []byte) error` | `nil` | 双方 | 校验对端标识状态（如接标识状态服务）。返回错误触发 `bad_certificate(42)` |

以上字段全部参与 `Config.Clone()`；`IBCIdentity` 在 `Clone` 时做浅复制。

### 3.2 与既有字段的关系

| 既有字段 | 在 IBC 套件下的行为 |
|---------|-------------------|
| `CipherSuites` | **必须显式包含** IBC/IBSDH 套件，否则永不协商 |
| `Certificates` / `GetCertificate` / `GetKECertificate` | IBC 套件**不使用**。服务端在没有任何 X.509 证书时，只要 IBC 配置齐备仍可启动并握手 |
| `RootCAs` / `ClientCAs` / `ClientAuth` / `VerifyPeerCertificate` | 走 X.509 路径，IBC 套件下不生效；IBC 的参数校验由 `RootIBCSysParams` / `ClientIBCSysParams` / `VerifyIBCSysParams` 承担。`ClientAuth` 在 IBC 下仍控制**是否请求客户端认证**（见 §6.3、§6.4） |
| `InsecureSkipVerify` | 客户端置 `true` 时**同时跳过** X.509 验证与 IBC 公共参数校验，详见 §6.10 |
| `SessionCache` | 会话重用同样支持 IBC，详见 §6.8 |
| `ServerName` | IBC 下不参与 X.509 主机名校验，但可用于 `GetIBCIdentity` 的 SNI 选择 |
| `Time` | 用于校验 `IBCSysParams.validity` 与 `issuerID` 有效期 |

### 3.3 `ClientHelloInfo.ClientID`

```go
// ClientHelloInfo 中新增：
// ClientID 客户端在 ClientHello 中通过 client_id(66) 扩展携带的 IBC 标识原始字节。
// 仅当客户端配置了 IBCIdentity 时才会存在（GM/T 0024-2023 附录 A.7）。
ClientID []byte
```

服务端可在 `GetIBCIdentity` / `GetConfigForClient` 中读取该字段，按客户端标识选择对应 KGC 的 `IBCIdentity`。

### 3.4 `ConnectionState` 扩展

```go
// ConnectionState 中新增：
PeerIBCIdentity   []byte         // 对端 IBC 标识（标识内容，非封装字节）
PeerIBCSysParams *IBCSysParams // 对端提供、且已命中本地信任池的 IBC 公共参数
```

两者仅在 IBC/IBSDH 套件下非空，会话重用后仍能正确填充。

---

## 4. IBCIdentity 配置详解

```go
type IBCIdentity struct {
    Identity              []byte
    Parameters            *IBCSysParams
    SignPrivateKey        *sm9.SignPrivateKey    // hid=0x01
    EncryptPrivateKey     *sm9.EncryptPrivateKey // hid=0x03
    KeyExchangePrivateKey *sm9.EncryptPrivateKey // hid=0x02
}
```

`IBCIdentity` 是一套"身份凭据"：本端标识 + 本端公共参数 + 由 KGC 下发的用户私钥。库只负责**装载**，不提供私钥派生能力——三把用户私钥均由 KGC 使用主私钥按 `(Identity, hid)` 派生后下发。

### 4.1 `Identity` — 本端标识

支持两种形式：

| 形式 | 说明 | 推荐度 |
|------|------|--------|
| **裸字节串** | 如 `[]byte("server@kgc.example")` | ✅ 推荐 |
| `Identifier` 的 DER | GM/T 0090 / GM/T 0081 §6.8 结构 | 需要携带有效期、扩展时使用 |

> 推荐裸字节串的原因：`Identifier.validStart` 是必填字段，使用完整结构时需要使用者自行填好 `validStart` / `validEnd`，或通过PEM解析，为了快速入门建议采用罗字节串简化。

协议交互中比对标识时，比对的是**标识内容**：若对端发送的是 `Identifier` DER，则抽取其中的 `identityData` 再比较，而不是比较封装字节。

### 4.2 `Parameters` — 本端公共参数

- 服务端：随 IBC 变体 Certificate 消息下发给对端；
- 客户端：随客户端 Certificate 消息下发（双向认证时）。

对端下发的参数**只作参考**：即使内容一致，最终用于验签与加密的也始终是**本地信任池中命中的那一份**。

### 4.3 三把用户私钥与 `hid`

SM9 的用户公钥由 `H1(uid ‖ hid) · P` 推导，`hid` 不同即得到不同的密钥对，**三把私钥不可互换**（三者都由 KGC 用主私钥派生；签名私钥来自签名主私钥，加密与密钥交换私钥都以加密主私钥为根，仅 `hid` 不同）：

| 字段 | hid | 用途 | 服务端是否必需 | 客户端是否必需 |
|------|-----|------|--------------|--------------|
| `SignPrivateKey` | `0x01` | 对 `signed_params`（服务端）、`CertificateVerify`（客户端）签名 | IBC/IBSDH 均必需 | 双向认证时必需 |
| `KeyExchangePrivateKey` | `0x02` | IBSDH 的 SM9 密钥交换 | IBSDH 必需 | IBSDH 必需 |
| `EncryptPrivateKey` | `0x03` | IBC 套件解密密文形式的预主密钥 | IBC 必需 | 不需要 |

注意：

- **本库不校验 `KeyExchangePrivateKey` 的派生 `hid`**：`LoadIBCIdentity` 只做 DER / PKCS#8 结构解析，不再反推私钥的 `hid`，也不存在 `Validate` 之类的校验入口；私钥是否按 `hid=0x02` 派生由 KGC 派发与本地装载环节自行保证（见下方「`hid` 的来源与校验边界」）；
- **`KeyExchangePrivateKey` 为空表示本端不具备 IBSDH 能力**，此时 IBSDH 套件不参与协商：服务端不会选中该套件，客户端不会在 `ClientHello` 中携带该套件（仅配置 `GetClientIBCIdentity` 回调时无法在 ClientHello 阶段预知凭据，仍会携带，由回调在握手时提供）。

#### `hid` 的来源与校验边界

IBSDH 的 `hid` 由报文承载：服务端在 `ServerIBSDHParams`（`KeyAgreementInfo.hid`）中下发，客户端读取后回填到自己的 `ClientIBSDHParams`。

| 角色 | `hid` 来源 |
|------|-----------|
| 服务端（SM9 密钥交换发起方 A） | 协议固定值 `0x02`，随 `ServerIBSDHParams` 下发 |
| 客户端（SM9 密钥交换响应方 B） | 直接读取对端 `ServerIBSDHParams.hid`（不要求等于 `0x02`） |

**本库不做 `hid` 的取值校验：**

- 装载 `KeyExchangePrivateKey` 时不检测其派生 `hid`，任何 `hid` 派生的 `sm9.EncryptPrivateKey` 都能装入；
- 解析 `ServerIBSDHParams` 时只要求 `hid` 是 1 字节 `OCTET STRING`，不要求等于 `0x02`；
- 服务端处理 `ClientIBSDHParams` 时不比对其中回填的 `hid`（发起方的 `hid` 已由本端决定）。


> ⚠️ **正确性责任在调用方。** 请确保 KGC 按 `hid=0x02` 派发密钥交换私钥、且两端使用同一 `hid`。若装入按其它 `hid` 派生的私钥（例如误用 `hid=0x03` 的加密私钥），密钥交换阶段**不会报错**——`InitKeyExchange` / `RespondKeyExchange` 只做点运算——双方的预主密钥不同，直到 `Finished` 校验失败才以 `bad record MAC` 告终，几乎无法从错误信息定位根因。建议在装载前自行核对 KGC 下发的私钥用途。

### 4.4 密钥装载

只提供装载入口，不提供生成入口：

```go
func LoadIBCIdentity(identity, paramsDER, signKeyDER, encKeyDER, keyExchangeKeyDER []byte) (*IBCIdentity, error)
```

- `identity` 为裸标识字节串或 `Identifier` 的 DER，会被复制保存；
- `paramsDER` 为本端公共参数 `IBCSysParams` 的 **DER 编码**，由 `ParseIBCSysParams` 解析后填入 `IBCIdentity.Parameters`，**可为空**：仅"客户端单向认证"可省（客户端使用对端下发并经信任池校验的参数）；服务端与双向认证的客户端必需，缺失会在下发 Certificate 时报 `bad_ibcparam(203)`。若手上已有解析好的 `*IBCSysParams`，可直接赋值 `ident.Parameters`（或传 `params.Raw`）；
- `signKeyDER` / `encKeyDER` / `keyExchangeKeyDER` 为 **PKCS#8 DER**，由 `smx509.ParsePKCS8PrivateKey` 解析；任一为空表示不提供该用途的私钥；
- `keyExchangeKeyDER` 非空时只按 PKCS#8 解析，不校验其 `hid`（应自行确保按 `hid=0x02` 派生），也不要求 `identity` 非空（标识缺失会在 IBSDH 握手时以 `identity_need(205)` 失败）；
- KGC 侧生成公共参数使用：

```go
func NewIBCSysParamsFromMaster(
    districtName string, districtSerial int, validity ValidityPeriod,
    signMaster *sm9.SignMasterPrivateKey, encMaster *sm9.EncryptMasterPrivateKey,
) (*IBCSysParams, error)
```

### 4.5 动态配置回调

| 回调 | 调用时机 | 典型用途 |
|------|---------|---------|
| `GetIBCIdentity(*ClientHelloInfo)` | 服务端处理 ClientHello 时，且 `IBCIdentity == nil` | 多 KGC、按 SNI / `ClientID` / `TrustedCAIndications` 选择身份 |
| `GetClientIBCIdentity(*CertificateRequestInfo)` | 客户端收到 CertificateRequest 时，且 `IBCIdentity == nil` | 客户端按服务端请求的 KGC 信任域选择身份 |

注意：客户端只有在**也发送了 `client_id` 扩展**时（即 `IBCIdentity != nil`），服务端才能在 IBSDH 下提前拿到客户端标识。若客户端只配置 `GetClientIBCIdentity`，IBSDH 套件下服务端可能因缺少标识而返回 `identity_need(205)`；此时应改用 `IBCIdentity` 静态配置，或选择 IBC 套件。

### 4.6 `Clone` 语义

`IBCIdentity.Clone()` 为浅复制（标识与私钥指针共享），因此可安全地由 `Config.Clone()` 复制配置结构，但**不要**在运行期修改被多个 `Config` 共享的 `IBCIdentity` 内容。

---

## 5. 公共参数与信任池

### 5.1 `IBCSysParams`

对应 GM/T 0081-2020 附录 A.2 的 `IBCSysParams`，是 IBC 报文中 `ibc_parameter` 的载荷：

| 字段 | 类型 | 说明 |
|------|------|------|
| `Raw` | `[]byte` | 原始 DER，透传保留未知字段；`Marshal()` 时若非空则直接返回 |
| `Version` | `int` | 应为 `2` |
| `DistrictName` | `string` | KGC 属地区域名，应以 URI/IRI 编码 |
| `DistrictSerial` | `int` | 同一 `districtName` 下单调递增 |
| `Validity` | `ValidityPeriod` | 参数有效期 |
| `IBCPublicParameters` | `[]IBCPublicParameter` | 多算法式列表，每项含 `IBCAlgorithm` OID 与两层编码的 `PublicParameterData` |
| `IBCIdentityType` | `asn1.ObjectIdentifier` | 标识类型 |
| `IssuerID` | `*Identifier` | 公共参数颁发者 |
| `IBCParamExtensions` | `[]IBCParamExtension` | 参数扩展 |
| `SignMasterPublicKey` | `*sm9.SignMasterPublicKey` | 从 SM9 项解析出的签名主公钥 |
| `EncryptMasterPublicKey` | `*sm9.EncryptMasterPublicKey` | 从 SM9 项解析出的加密主公钥 |

```go
func ParseIBCSysParams(der []byte) (*IBCSysParams, error)
func (p *IBCSysParams) Marshal() ([]byte, error)
func (p *IBCSysParams) VerifyValidity(now time.Time) error
```

解析规则遵循「不发明标准之外的宽容规则；标准本身允许多种形式的地方都要兼容」：

| 项目 | 处理 |
|------|------|
| `version` 缺失 / 值不符 / tag 类型不符 / 必填字段缺失 | **拒绝**（`bad_ibcparam(203)`） |
| `KeyAgreementInfo.hid` | 只校验为 1 字节 `OCTET STRING`，**不校验取值**（不做 `hid == 0x02` 判断，见 §4.3） |
| SEQUENCE 内有剩余字节 | **忽略**，向前兼容 |
| `ibc_id` / `client_id` | **兼容两种**：`Identifier` DER 或裸字节串 |
| `tempKey` | **兼容两种**：`SEQUENCE { BIT STRING }` 或裸 `BIT STRING` |
| `ibcAlgorithm` 非 SM9 / 主公钥不支持 / 无 SM9 项 | **拒绝**（`unsupported_ibcparam(204)`） |
| `Identifier.extensions` 内容 | 扩展项按 `Extension` 读出并保留，`extnValue` 的语义**不解释**（发布服务 `extnID` 是占位符） |

### 5.2 有效期 `ValidityPeriod`

```go
type ValidityPeriod struct {
    NotBefore time.Time
    NotAfter  time.Time
}
func (v ValidityPeriod) IsZero() bool
func (v ValidityPeriod) Contains(t time.Time) bool
```

- **完整握手强制校验** `IBCSysParams.validity` 与 `issuerID` 的有效期，失败回 `unsupported_ibcparam(204)`；
- 任一字段为零值表示该端不限制；
- **会话重用不重新校验** `validity`。

### 5.3 `IBCPool`

语义对称于 `x509.CertPool`：

```go
func NewIBCPool() *IBCPool
func (p *IBCPool) AddParams(params *IBCSysParams) error
func (p *IBCPool) AddParamsDER(der []byte) error
func (p *IBCPool) Lookup(params *IBCSysParams) (*IBCSysParams, bool)
func (p *IBCPool) Contains(params *IBCSysParams) bool
```

- 同一 KGC 由 `(districtName, districtSerial)` 唯一标识；
- 命中判定比对：KGC 身份 + **签名主公钥** + **加密主公钥**；
- `Lookup` 返回**池中**的参数对象，握手后续运算使用该对象；
- `IBCPool` 可被多个 goroutine 并发访问；`AddParams` 会补齐 `Raw`。

### 5.4 信任判定与默认拒绝

`RootIBCSysParams` / `ClientIBCSysParams` 与 `VerifyIBCSysParams` 的组合行为：

| 信任池 | `VerifyIBCSysParams` | 行为 |
|--------|----------------------|------|
| 已配置 | 任意 | 必须命中信任池；命中后使用**池中**参数，不再调用回调 |
| 未配置 | 已配置 | 由回调全权判定 |
| 未配置 | `nil`，且本端有 `IBCIdentity.Parameters` | 以本端公共参数作为**默认信任池**：对端参数必须与本端属于同一 KGC（`districtName` + `districtSerial` + 签名/加密主公钥逐字节相等），命中后使用**本端**参数 |
| 未配置 | `nil`，且本端无公共参数 | **默认拒绝握手**（`handshake_failure(40)`） |

**默认信任池的边界：** 未提供信任池时，默认信任的是**本端自己配置的 `IBCSysParams`**，而不是对端下发的任意参数——对端必须与本端属于同一 KGC（即同一组 `districtName` / `districtSerial` 与同一对主公钥）才能通过校验。跨 KGC 互通仍需显式配置信任池或 `VerifyIBCSysParams`。

**回调优先于默认信任池：** `VerifyIBCSysParams` 是应用显式声明的信任判定，只要配置了它就不会被默认信任池绕过（例如在其中做吊销检查、KGC 白名单的场景仍然生效）。

**默认拒绝而非默认接受：** X.509 场景下没有 `RootCAs` 还能退回系统根证书，IBC 没有「系统级 KGC」；本端连自己的公共参数都没有时（例如只配置了 `GetClientIBCIdentity` 的单向认证客户端），只能要求显式配置信任池或回调，默认接受等于默认不安全。

### 5.5 校验回调

- `VerifyIBCSysParams(params *IBCSysParams) error`：作为信任池的兜底，可在其中做主公钥指纹比对、KGC 白名单等；返回错误会导致握手失败；
- `VerifyIBCIdentity(identity []byte) error`：校验对端**标识状态**，例如查询自有标识状态服务；返回错误触发 `bad_certificate(42)`。

> 本库**不内置标识吊销（IRL）检查**。`Identifier` 的时间有效性是强制校验的，但吊销状态需要应用在 `VerifyIBCIdentity` 中自行实现——**时间有效性与吊销状态是两件事**。

---

## 6. 典型配置

### 6.1 服务端

```go
pool := tlcp.NewIBCPool()
_ = pool.AddParamsDER(paramsDER) // 信任的客户端 KGC 公共参数

config := &tlcp.Config{
    CipherSuites:    []uint16{tlcp.IBC_SM4_GCM_SM3, tlcp.IBSDH_SM4_GCM_SM3},
    IBCIdentity:       serverIBC,   // 服务端标识 + 公共参数 + 私钥
    ClientIBCSysParams: pool,        // IBSDH 强制客户端认证，必需
    // 无需 Certificates：IBC 套件不使用 X.509 证书。
}
ln, _ := tlcp.Listen("tcp", ":8443", config)
```

> 未配置 `ClientIBCSysParams` 时，默认以本端 `IBCIdentity.Parameters` 作为信任池，即只接受与服务端同一 KGC 的客户端；跨 KGC 才需要显式建池。

### 6.2 客户端

```go
pool := tlcp.NewIBCPool()
_ = pool.AddParamsDER(paramsDER) // 信任的服务端 KGC 公共参数

conn, _ := tlcp.Dial("tcp", "127.0.0.1:8443", &tlcp.Config{
    CipherSuites:  []uint16{tlcp.IBC_SM4_GCM_SM3, tlcp.IBSDH_SM4_GCM_SM3},
    IBCIdentity:     clientIBC,
    RootIBCSysParams: pool,           // 服务端下发的 ibc_parameter 必须命中该池
})
```

> 客户端配置了 `IBCIdentity` 且 `Identity` 非空时，会自动在 ClientHello 中携带 `client_id(66)` 扩展，无需手工设置。
>
> 未配置 `RootIBCSysParams` 时，默认以本端 `IBCIdentity.Parameters` 作为信任池：服务端下发的参数必须与本端属于同一 KGC。若客户端不配置 `Parameters`（单向认证的另一种写法），则必须显式配置信任池或 `VerifyIBCSysParams`。

### 6.3 双向认证

服务端显式要求客户端认证（IBC 套件下默认不请求）：

```go
config := &tlcp.Config{
    CipherSuites:    []uint16{tlcp.IBC_SM4_GCM_SM3},
    IBCIdentity:       serverIBC,
    ClientAuth:      tlcp.RequireAndVerifyClientCert, // 请求并验证客户端标识
    ClientIBCSysParams: pool,
}
```

客户端需提供 `SignPrivateKey`（hid=`0x01`）与 `Parameters`，以便回复 `CertificateVerify`。

### 6.4 IBSDH 的强制客户端认证

IBSDH 使用 `genSignature=false` 的 SM9 密钥交换，协议交互中不校验客户端持有加密私钥。因此服务端会**自动**把客户端认证策略提升为 `RequireAndVerifyClientCert`：

```go
// IBSDH 下等效行为（除非显式设为 RequestClientCert）
if suiteID == tlcp.IBSDH_SM4_CBC_SM3 || suiteID == tlcp.IBSDH_SM4_GCM_SM3 {
    authPolice = tlcp.RequireAndVerifyClientCert
}
```

- 服务端必须能校验客户端参数：显式配置 `ClientIBCSysParams`，或依赖默认信任池（本端 `IBCIdentity.Parameters`，要求客户端与本端同一 KGC），或提供 `VerifyIBCSysParams`；
- 客户端必须能提供标识与签名私钥；
- 若显式设置 `ClientAuth: tlcp.RequestClientCert`，则由应用自行承担身份验证责任。

### 6.5 多 KGC / 按 SNI 动态选择

服务端根据 SNI 或客户端标识返回不同 KGC 的身份材料：

```go
config := &tlcp.Config{
    CipherSuites: []uint16{tlcp.IBSDH_SM4_GCM_SM3},
    GetIBCIdentity: func(info *tlcp.ClientHelloInfo) (*tlcp.IBCIdentity, error) {
        switch info.ServerName {
        case "app1.example.com":
            return app1IBC, nil
        case "app2.example.com":
            return app2IBC, nil
        }
        // info.ClientID 中可读到客户端标识
        return defaultIBC, nil
    },
    ClientIBCSysParams: multiKGCPool, // 池中可放多组 (districtName, serial)
}
```

### 6.6 客户端按证书请求动态配置

```go
config := &tlcp.Config{
    CipherSuites: []uint16{tlcp.IBSDH_SM4_GCM_SM3},
    GetClientIBCIdentity: func(cri *tlcp.CertificateRequestInfo) (*tlcp.IBCIdentity, error) {
        // 依据 cri.AcceptableCAs / cri.Version 选择本端身份
        return clientIBC, nil
    },
    RootIBCSysParams: pool,
}
```

### 6.7 只用回调做参数校验

不适合维护信任池的场景（如参数来自集中配置中心），可只提供回调：

> 配置了回调时，默认信任池（本端 `IBCIdentity.Parameters`）不会生效，由回调全权判定。

```go
config := &tlcp.Config{
    CipherSuites: []uint16{tlcp.IBC_SM4_GCM_SM3},
    IBCIdentity:    clientIBC,
    VerifyIBCSysParams: func(p *tlcp.IBCSysParams) error {
        if p.DistrictName != "kgc.example" {
            return errors.New("非预期的 KGC")
        }
        // 建议在此比对主公钥指纹
        return p.VerifyValidity(time.Now())
    },
}
```

### 6.8 会话重用

```go
config := &tlcp.Config{
    CipherSuites:    []uint16{tlcp.IBC_SM4_GCM_SM3},
    IBCIdentity:       serverIBC,
    ClientIBCSysParams: pool,
    SessionCache:    tlcp.NewLRUSessionCache(128),
}
```

- 重用握手交换新的 `client_random` / `server_random` 派生工作密钥，不重新协商预主密钥；
- **不重新校验** `IBCSysParams.validity`；
- 会话状态中缓存了对端标识与公共参数，重用后 `ConnectionState.PeerIBCIdentity` / `PeerIBCSysParams` 仍可读取；
- 可通过 `Conn.ConnectionState().DidResume` 确认是否命中重用。

### 6.9 与 ECC/ECDHE 混合协商

同一监听端口可同时支持证书套件与 IBC 套件：

```go
config := &tlcp.Config{
    Certificates: []tlcp.Certificate{sigCert, encCert}, // ECC/ECDHE 需要
    CipherSuites: []uint16{
        tlcp.ECDHE_SM4_GCM_SM3, // 证书套件
        tlcp.IBC_SM4_GCM_SM3,   // IBC 套件
    },
    IBCIdentity:       serverIBC,
    ClientIBCSysParams: pool,
}
```

- 服务端会跳过本端无 IBC 能力（`IBCIdentity == nil` 且 `GetIBCIdentity == nil`）的 IBC 套件；
- 客户端只要配置了 `IBCIdentity` 就会发送 `client_id` 扩展，服务端**仅在选中 IBSDH 时消费**，选中其它套件时静默忽略。

### 6.10 `InsecureSkipVerify`

在 IBC 套件下，客户端的 `InsecureSkipVerify = true` 会**同时跳过**：

- X.509 证书验证；
- IBC 公共参数的信任池校验与 `VerifyIBCSysParams` 回调；
- 公共参数有效期校验与 `VerifyIBCIdentity` 校验。

> ⚠️ 在 IBC 套件下，`InsecureSkipVerify=true` 会同时跳过 IBC 公共参数校验，连接易受中间人攻击，**仅供测试**。

该开关只影响客户端；服务端始终执行 `ClientIBCSysParams` / `VerifyIBCSysParams` 校验。

---

## 7. 握手流程

### 7.1 IBC

```
Client                                              Server
------                                              ------
ClientHello (IBC 套件)                     -------->
                                          <--------  ServerHello
                                          <--------  Certificate{server_ibc_id, server_ibc_parameter}
                                          <--------  ServerKeyExchange{sig}
                                          <--------  ServerHelloDone
ClientKeyExchange{SM9Cipher(PreMasterSecret)} ----->
[ChangeCipherSpec] / Finished              -------->
                                          <--------  [ChangeCipherSpec] / Finished
应用数据                                             <------->
```

### 7.2 IBSDH

```
Client                                              Server
------                                              ------
ClientHello
  cipher_suites 含 IBSDH 套件
  extension client_id(66) = 客户端标识      -------->
                                          <--------  ServerHello
                                          <--------  Certificate{server_ibc_id, server_ibc_parameter}
                                          <--------  ServerKeyExchange{KeyAgreementInfo(R_A), sig}
                                          <--------  CertificateRequest{certificate_types=[ibc_params]}
                                          <--------  ServerHelloDone
Certificate{client_ibc_id, client_ibc_parameter}  ------>
ClientKeyExchange{KeyAgreementInfo(R_B)}          ------>
CertificateVerify (SM9 签名, hid=0x01)             ------>
[ChangeCipherSpec]                                ------>
Finished                                          ------>
                                          <--------  [ChangeCipherSpec]
                                          <--------  Finished
应用数据                                             <------->
```

**角色映射：** SM9 密钥交换协议中发起方 A 先发 `R_A = r_A · Q_B`，与 TLCP 中服务端先发 `ServerKeyExchange` 的顺序一致，因此 **服务端 = 发起方 A，客户端 = 响应方 B**。预主密钥长度固定 **48 字节**（TLCP 要求；SM9 算法标准默认 16 字节）。

### 7.3 客户端标识的传递

| 载体 | 何时发送 | 内容 | 用途 |
|------|---------|------|------|
| `client_id(66)` 扩展 | 客户端配置了 `IBCIdentity` 时，随 ClientHello 发送 | 裸标识字节串 | 服务端**提前**获得客户端标识以计算 `R_A`（IBSDH 必需） |
| Certificate 消息的 `ibc_id` | 服务端请求客户端证书时 | `Identifier` DER 或裸字节串 | 标准流程要求的标识与公共参数协商 |

**一致性校验：** 两者都出现时，比对**原始标识内容**（若为 `Identifier` 则抽取 `identityData`），不一致回 `illegal_parameter(47)`；需要标识但两者都没有，回 `identity_need(205)`。

---

## 8. 安全模型

### 8.1 信任模型

| 维度 | ECC/ECDHE（X.509） | IBC/IBSDH（SM9） |
|------|-------------------|-----------------|
| 公钥真实性来源 | CA 签名的证书链 | KGC 下发的公共参数 + 标识约定 |
| 信任锚 | `RootCAs` / `ClientCAs` | `RootIBCSysParams` / `ClientIBCSysParams`；未配置时默认取本端 `IBCIdentity.Parameters`（要求同一 KGC） |
| 带外分发 | 根证书 | KGC 公共参数（或主公钥指纹） |
| 标识撤销 | CRL / OCSP | 标准定义了 IRL，但 TLCP 无检查点 |
| 前向安全 | ECDHE 有 | IBC 无；IBSDH 有 |

**绝不允许直接用对端带来的公钥验签或加密**——那等于让对端自己证明自己。实现上始终先命中本地信任池，再用**池中**参数做后续运算；未配置信任池时，本地信任池即本端配置的 `IBCSysParams`，对端参数同样必须与它属于同一 KGC（见 §5.4）。

### 8.2 ⚠️ `ibc_parameter` 没有签名保护（最大风险）

GM/T 0081 定义了参数发布保护结构：

```asn1
IBCSysParamsPublishInfo ::= SEQUENCE {
    ibcSysParams       IBCSysParams,
    signatureAlgorithm OBJECT IDENTIFIER,
    signatureValue     BIT STRING
}
```

但 **GM/T 0024-2023 的 Certificate 消息只传裸 `IBCSysParams`**，没有任何签名。

**攻击路径：** 中间人替换 `ibc_parameter` 中的加密主公钥 →

1. 客户端用**假主公钥**加密预主密钥；
2. 中间人用自己的加密私钥解密，获得预主密钥；
3. 中间人与服务端正常握手，全程转发。

这与「TLS 没有 CA 会怎样」是完全对等的攻击面。TLS 用 CA 签名解决，IBC 在 TLCP 中没有对应机制。

**唯一的缓解是带外预置信任锚。** SM9「无证书」并不意味着「无信任问题」——它只是把 CA 的信任问题**平移**到了 KGC 参数的带外分发。

### 8.3 标识吊销与有效期

| 机制 | 本库行为 |
|------|---------|
| `Identifier.validStart` / `validEnd` 时间有效性 | **强制校验**（完整握手），失败回 `unsupported_ibcparam(204)` |
| IRL（`IdentifierRevocationList`） | **不实现**。TLCP 握手流程中没有撤销检查点，且 IRL 获取地址依赖标准中无法实现的占位符 `extnID` |
| 应用自定义标识状态检查 | 由 `Config.VerifyIBCIdentity` 承担 |

### 8.4 常见配置错误

| 现象 | 原因 |
|------|------|
| 握手报 `handshake_failure`，日志提示无可信 IBC 参数 | 未配置 `RootIBCSysParams` / `ClientIBCSysParams`，也未提供 `VerifyIBCSysParams`，且本端 `IBCIdentity.Parameters` 为空（默认信任池不可用） |
| 握手报 `handshake_failure`，提示对端 IBC 参数不可信 | 对端参数与本端默认信任池（本端 `IBCIdentity.Parameters`）不是同一 KGC：`districtName` / `districtSerial` 或主公钥不一致；跨 KGC 互通需显式配置信任池或 `VerifyIBCSysParams` |
| 始终协商不到 IBC 套件 | `CipherSuites` 未显式列出 IBC 套件，或本端缺 `IBCIdentity`（及回调） |
| 始终协商不到 IBSDH 套件 | 本端未配置 `KeyExchangePrivateKey`（IBSDH 不参与协商，见 §4.3），或套件列表未列出 IBSDH |
| 握手走到最后一步报 `bad record MAC` | 密钥交换私钥的 `hid` 与对端不一致（如误用 hid=0x03 的加密私钥，或两端派生了不同 hid）。装载期**不再校验** `hid`（见 §4.3），请在配置期自行核对 |
| 报 `identity_need(205)` | IBSDH 下服务端未拿到客户端标识：客户端未配置 `IBCIdentity`，或 `Identity` 为空 |
| 报 `illegal_parameter(47)` | `client_id` 扩展与客户端 Certificate 中的标识内容不一致 |
| 报 `unsupported_ibcparam(204)` | 公共参数已过期/尚未生效，或 `ibcAlgorithm` 中没有 SM9 项 |

---

## 9. 告警与错误处理

| 告警 | 值 | 触发条件 |
|------|-----|---------|
| `bad_ibcparam` | 203 | ASN.1 结构不符标准；tag 类型不符；`version` 缺失或值不符（`IBCSysParams` 须为 2，`KeyAgreementInfo` 须为 1）；标准要求的字段缺失；`tempKey` 不是合法 G1 点；`hid` 不是 1 字节 `OCTET STRING`（**不校验取值**） |
| `unsupported_ibcparam` | 204 | 结构合法但语义不支持：`ibcAlgorithm` 对应的不是 SM9；曲线/主公钥不支持；`validity` 已过期或尚未生效 |
| `identity_need` | 205 | IBSDH 下服务端在 ClientHello 中未获得客户端标识；需要对方标识但 Certificate 消息未提供 |
| `illegal_parameter` | 47 | `client_id` 扩展与 Certificate 中的标识内容不一致 |
| `bad_certificate` | 42 | `CertificateVerify` 验签失败；`VerifyIBCIdentity` 回调返回错误 |
| `handshake_failure` | 40 | 客户端公共参数未命中 `ClientIBCSysParams`；服务端参数未命中 `RootIBCSysParams`；对端参数未命中默认信任池（本端 `IBCIdentity.Parameters`）；信任池、回调与本端公共参数均不可用；无共同套件 |

**不兼容报文的处理：** 遇到无法解析的 IBC 报文时，直接返回明确的解析失败错误（例如 `tlcp: failed to parse IBC Certificate message`），**不做格式识别**，不在错误信息中提及其它标准版本；对应告警为 `bad_ibcparam(203)`（解析参数时）或 `decode_error(50)`。

---

## 10. API 速查

| 类型 / 函数 | 作用 |
|------------|------|
| `IBCIdentity` | 本端 IBC 身份：标识、公共参数、三把私钥 |
| `IBCSysParams` | IBC 公共参数（`IBCSysParams`） |
| `IBCPool` | KGC 公共参数信任池 |
| `ValidityPeriod` | 公共参数有效期 |
| `Identifier` | GM/T 0090 标识结构 |
| `NewIBCSysParamsFromMaster` | KGC 侧由主密钥生成公共参数 |
| `ParseIBCSysParams` | 解析 `IBCSysParams` DER |
| `(*IBCSysParams).Marshal` | 编码 `IBCSysParams` DER |
| `(*IBCSysParams).VerifyValidity` | 校验当前时间是否在有效期内 |
| `NewIBCPool` | 创建空信任池 |
| `(*IBCPool).AddParams` / `AddParamsDER` | 加入信任池 |
| `(*IBCPool).Contains` / `Lookup` | 命中判定 / 取出池中参数 |
| `LoadIBCIdentity` | 由 PKCS#8 私钥装载身份（签名 / 加密 / 密钥交换，可分别缺省） |
| `ParseIdentifier` | 解析 `Identifier` DER |


---

## 11. 参考标准

| 标准 | 条款 | 内容 |
|------|------|------|
| GM/T 0024-2023 | 6.4.5.2.2 / 6.4.5.2.3 | `ExtensionType`（含 `client_id(66)`）与 Hello 扩展结构 |
| GM/T 0024-2023 | 6.4.5.3 / 6.4.5.7 | Server / Client Certificate：`ibc_id` + `ibc_parameter` |
| GM/T 0024-2023 | 6.4.5.4 | Server Key Exchange：`ServerIBSDHParams`、IBC 的 `signed_params` 覆盖范围 |
| GM/T 0024-2023 | 6.4.5.5 | Certificate Request：`ibc_params(80)`、KGC 信任域名 |
| GM/T 0024-2023 | 6.4.5.8 | Client Key Exchange：`ClientIBSDHParams` / `IBCEncryptedPreMasterSecret` |
| GM/T 0024-2023 | 6.4.5.9 | Certificate Verify：`ibs_sm3` |
| GM/T 0024-2023 | 6.4.3.3 | 告警：203 / 204 / 205 |
| GM/T 0024-2023 | 附录 A.7 | `client_id(66)` 扩展 |
| GM/T 0081-2020 | §6.8 / §12 / 附录 A.2 | `Identifier`、`KeyAgreementInfo`、`IBCSysParams` 结构 |
| GM/T 0090-2020 | — | 标识密码应用标识格式 |
| GM/T 0044-2016 | — | SM9 算法；`hid` 取值（0x01 / 0x02 / 0x03） |

---

## 附录 A：IBC 相关 ASN.1 结构汇总

本附录把 IBC 用到的**全部 ASN.1 结构**集中列出：先给出各结构在 TLCP 报文中的位置（A.2），再按结构族给出形式定义、字段语义与编码约定（A.3–A.7），最后汇总版本号、`hid`、OID 与解析宽容点（A.8、A.9）。

> 阅读约定：
> - 「出处」中的条款号指向标准原文；`GM/T 0081-2020 附录 A.2` 即 `IBCSysParams` 的定义位置。
> - 「本库实现」只列公开或与解析行为直接相关的类型/函数，内部 wire 类型不逐一列出。
> - 标注 **`[未使用]`** 的结构是标准已定义、但本库不解析也不生成的结构。
> - §2.1 的报文片段与本附录重复时，**以本附录为准**；§5.1 的解析规则表与 A.9 互为补充。

### A.1 结构总览

| # | 结构 | 出处 | 在协议中的位置 | 本库实现 |
|---|------|------|---------------|---------|
| 1 | `Identifier` | GM/T 0081-2020 §6.8（格式源自 GM/T 0090-2020） | `ibc_id`、`client_id` 扩展、`IBCSysParams.issuerID` | `tlcp.Identifier`、`ParseIdentifier` |
| 2 | `Version` | 同上 | `Identifier.version` | 常量 `identifierVersionV1 = 1` |
| 3 | `Extensions` / `Extension` | 同上 | `Identifier.extensions` | `tlcp.Extension`（读出但 `extnValue` 语义不解释） |
| 4 | `DistrictInfo` | 同上 | `Extension.extnValue`（`ibcType` 为 SM9 时） | `tlcp.DistrictInfo`（不解释） |
| 5 | `IBCSysParams` | GM/T 0081-2020 附录 A.2 | Certificate 消息的 `ibc_parameter` | `tlcp.IBCSysParams`、`ParseIBCSysParams`、`(*IBCSysParams).Marshal` |
| 6 | `ValidityPeriod` / `Time` | 同上（按 §6.9 处理） | `IBCSysParams.validity` | `tlcp.ValidityPeriod` |
| 7 | `IBCPublicParameters` / `IBCPublicParameter` | 同上 | `IBCSysParams.ibcPublicParameters` | `tlcp.IBCPublicParameter` |
| 8 | `SM9PublicParameterData` | 同上（内容为 SM9 算法式私有结构） | `IBCPublicParameter.publicParameterData` 的内容（两层编码） | 内部类型 `sm9PublicParameterData` |
| 9 | `IBCParamExtensions` / `IBCParamExtension` | 同上 | `IBCSysParams.ibcParamExtensions` | `tlcp.IBCParamExtension` |
| 10 | `KeyAgreementInfo` | GM/T 0081-2020 §12 | IBSDH 的 `ServerIBSDHParams` / `ClientIBSDHParams` | `tlcp.KeyAgreementInfo` |
| 11 | `SM9MastEncryptPublicKey` | GM/T 0081-2020 §12（见附录 A 或 GM/T 0080） | `KeyAgreementInfo.tempKey`（临时公钥 `R_A` / `R_B`） | `marshalSM9MastEncryptPublicKey` / `parseSM9MastEncryptPublicKey` |
| 12 | `SM9SignMasterPublicKey` | GM/T 0081-2020 附录 A（见 GM/T 0080） | `SM9PublicParameterData.signMastPublicKey` | `gmsm` `MarshalASN1` / `UnmarshalSignMasterPublicKeyASN1` |
| 13 | `SM9EncryptMasterPublicKey` | 同上 | `SM9PublicParameterData.encMastPublicKey` | `gmsm` `MarshalASN1` / `UnmarshalEncryptMasterPublicKeyASN1` |
| 14 | `SM9Signature` | GM/T 0081-2020 消息语法 | `signed_params`（ServerKeyExchange）、`CertificateVerify` | `gmsm` `Sign` / `Verify`（`signIBSHandshake` 等） |
| 15 | `SM9Cipher` | 同上 | IBC 的 `IBCEncryptedPreMasterSecret` | `gmsm` `sm9.EncryptASN1` / `sm9.DecryptASN1` |
| 16 | `SM9SignPrivateKey` / `SM9EncryptPrivateKey` | 同上（经 PKCS#8 装载） | `IBCIdentity` 的签名 / 加密 / 密钥交换私钥 | `smx509.ParsePKCS8PrivateKey`（`LoadIBCIdentity`） |
| 17 | `IBCSysParamsPublishInfo` | GM/T 0081-2020 附录 A | 公共参数发布保护（带签名） | **`[未使用]`**，见 A.7 |
| 18 | `IdentifierRevocationList` | GM/T 0081-2020 附录 A.1 | 标识撤销列表（IRL） | **`[未使用]`**，见 A.7 |
| 19 | `SM9KeyPackage` | GM/T 0081-2020 消息语法 | SM9 密钥封装 | **`[未使用]`**（IBC 套件使用 `SM9Cipher`） |

### A.2 报文中的 ASN.1 载荷位置（GM/T 0024-2023）

以下片段是 TLCP 的报文语法（非 ASN.1），它们**决定了上面各 ASN.1 结构出现的位置与长度域**。字段取值与 §2.1 一致。

```text
// 6.4.5.3 / 6.4.5.7  Certificate（IBC 变体）
opaque ASN.1IBCParam<1..2^24-1>;
struct {
    opaque ibc_id<1..2^16-1>;        // Identifier 的 DER（A.3），或用户自定义裸标识
    ASN.1IBCParam ibc_parameter;     // IBCSysParams 的 DER（A.4），不含发布保护签名
} Certificate;

// 6.4.5.4  Server Key Exchange
enum { ECDHE, ECC, IBSDH, IBC, RSA } KeyExchangeAlgorithm;

case IBSDH:
    ServerIBSDHParams params;        // KeyAgreementInfo 的 DER（A.5）
    digitally-signed struct {
        opaque client_random[32];
        opaque server_random[32];
        ServerIBSDHParams params;
    } signed_params;

case IBC:
    digitally-signed struct {        // 无 params、无加密公钥字段
        opaque client_random[32];
        opaque server_random[32];
        opaque ibc_id<1..2^16-1>;
    } signed_params;

// 6.4.5.5  Certificate Request
enum { rsa_sign(1), sm2_sign(64), ibc_params(80) } ClientCertificateType;
// ibc_params(80) 时，certificate_authorities 为 IBC 密钥管理中心的信任域名列表

// 6.4.5.8  Client Key Exchange
case IBSDH:
    opaque ClientIBSDHParams<1..2^16-1>;             // KeyAgreementInfo 的 DER（A.5）
case IBC:
    opaque IBCEncryptedPreMasterSecret<0..2^16-1>;   // SM9Cipher 的 DER（A.6）

// 6.4.5.9  Certificate Verify：签名算法 ibs_sm3，签名值为 SM9Signature（A.6）

// 附录 A.7  ClientHello 扩展 client_id(66)
opaque ClientID<1..2^16-1>;          // Identifier 的 DER（A.3），或裸标识字节串
```

`signed_params` 与 `CertificateVerify` 的签名结果都是 `SM9Signature`（A.6），使用 `hid=0x01` 的签名私钥。

### A.3 `Identifier` 族（GM/T 0081-2020 §6.8）

用于 `ibc_id`、`client_id` 扩展，以及 `IBCSysParams.issuerID`。

```asn1
Identifier ::= SEQUENCE {
    version      Version DEFAULT v1,
    ibcType      OBJECT IDENTIFIER,          -- SM9 时为 1.2.156.10197.1.302
    ibcTypeAlias [0] OCTET STRING OPTIONAL,
    identityData OCTET STRING,               -- 标识内容
    validStart   UTCTime,                    -- 必填
    validEnd     [1] UTCTime OPTIONAL,
    extensions   [2] Extensions OPTIONAL
}

Version    ::= INTEGER(1)
Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension
Extension  ::= SEQUENCE {
    extnID    OBJECT IDENTIFIER,
    critical  BOOLEAN DEFAULT FALSE,
    extnValue OCTET STRING
}

DistrictInfo ::= SEQUENCE {                  -- ibcType 为 SM9 时 extnValue 的内容
    district   IA5String,
    districtNo INTEGER
}
```

| ASN.1 字段 | 本库字段 | 说明 |
|-----------|---------|------|
| `version` | `Identifier.Version` | 缺省即 v1；出现时**必须**为 1，否则 `bad_ibcparam(203)` |
| `ibcType` | `Identifier.IBCType` | SM9 时为 `1.2.156.10197.1.302` |
| `ibcTypeAlias` | `Identifier.IBCTypeAlias` | 只按隐式标签 `[0]` 读取 |
| `identityData` | `Identifier.IdentityData` | 比对标识时使用的就是该字段，而非封装字节 |
| `validStart` / `validEnd` | `Identifier.ValidStart` / `ValidEnd` | `validEnd` 零值表示不写出；有效期在完整握手中强制校验 |
| `extensions` | `Identifier.Extensions` | 按 `Extension` 逐项读出并保留，但 `extnValue` 的语义（`DistrictInfo`）**不解释**（发布服务的 `extnID` 是占位符） |

### A.4 `IBCSysParams` 族（GM/T 0081-2020 附录 A.2）

即 Certificate 消息中 `ibc_parameter` 的载荷。

```asn1
IBCSysParams ::= SEQUENCE {
    version             INTEGER { v2(2) },        -- 版本值为 2
    districtName        IA5String,                -- 应以 URI / IRI 编码
    districtSerial      INTEGER,                  -- 同一 districtName 下单调递增
    validity            ValidityPeriod,
    ibcPublicParameters IBCPublicParameters,
    ibcIdentityType     OBJECT IDENTIFIER,
    issuerID            Identifier,               -- 公共参数颁发者
    ibcParamExtensions  IBCParamExtensions OPTIONAL
}

ValidityPeriod ::= SEQUENCE {                     -- 标准未在 A.2 给出形式定义，按 §6.9 的 Validity 处理
    notBefore Time,
    notAfter  Time
}
Time ::= CHOICE { utcTime UTCTime, generalTime GeneralizedTime }

IBCPublicParameters ::= SEQUENCE (SIZE(1..MAX)) OF IBCPublicParameter
IBCPublicParameter  ::= SEQUENCE {
    ibcAlgorithm        OBJECT IDENTIFIER,        -- 用于挑选 SM9 那一项
    publicParameterData OCTET STRING              -- 内容为 SM9PublicParameterData 的 DER（两层编码）
}

SM9PublicParameterData ::= SEQUENCE {
    pkgID             OCTET STRING,               -- 私钥生成中心标识
    encMastPublicKey  SM9EncryptMasterPublicKey,  -- 加密主公钥（A.6）
    signMastPublicKey SM9SignMasterPublicKey      -- 签名主公钥（A.6）
}

IBCParamExtensions ::= SEQUENCE OF IBCParamExtension
IBCParamExtension  ::= SEQUENCE {
    ibcParamExtensionOID   OBJECT IDENTIFIER,
    ibcParamExtensionValue OCTET STRING
}
```

**四个实现要点：**

1. **两层编码。** `IBCPublicParameter.publicParameterData` 是 `OCTET STRING`，其**内容**才是 `SM9PublicParameterData` 的 DER，必须二次解码；
2. **多算法式。** `ibcPublicParameters` 是 `SEQUENCE OF`，需按 `ibcAlgorithm` OID 遍历挑选 SM9 项，非 SM9 且无 SM9 项时回 `unsupported_ibcparam(204)`；
3. **`issuerID` 是完整的 `Identifier`**（含有效期与扩展），不是裸标识；
4. **版本值为 2**，与 `Identifier.version`（v1 = 1）、`KeyAgreementInfo.version`（1）都不同。

### A.5 `KeyAgreementInfo`（GM/T 0081-2020 §12）

即 IBSDH 的 `ServerIBSDHParams` 与 `ClientIBSDHParams` 载荷。数据类型 OID：`1.2.156.10197.6.1.4.4.6`。

```asn1
KeyAgreementInfo ::= SEQUENCE {
    version  Version,                    -- Version ::= INTEGER(1)，必填
    tempKey  SM9MastEncryptPublicKey,    -- 临时公钥 R_A（服务端）或 R_B（客户端）
    userID_A OCTET STRING,               -- 发起方（服务端）标识
    userID_B OCTET STRING,               -- 响应方（客户端）标识
    hid      OCTET STRING                -- 算法类型，1 字节；协议取 0x02，本库不校验取值
}

SM9MastEncryptPublicKey ::= SEQUENCE { BIT STRING }   -- 内为 65 字节未压缩 G1 点
```

| ASN.1 字段 | 本库字段 | 取值 / 校验 |
|-----------|---------|------------|
| `version` | `KeyAgreementInfo.Version` | 固定 `1`，不做缺省兼容，否则 `bad_ibcparam(203)` |
| `tempKey` | `KeyAgreementInfo.TempKey` | 写出发送用 `SEQUENCE { BIT STRING }`，解析兼容裸 `BIT STRING`；非法或无穷远 G1 点回 203 |
| `userID_A` / `userID_B` | `KeyAgreementInfo.UserID_A` / `UserID_B` | 服务端 = 发起方 A，客户端 = 响应方 B |
| `hid` | `KeyAgreementInfo.Hid` | 必须为 1 字节 `OCTET STRING`，否则 203；**取值不校验**（由发送方填写，接收方按消息内容参与密钥交换） |

### A.6 SM9 密码算法相关结构

这些结构由 `gmsm` 生成/解析，本库只负责放置到 A.2 的对应载荷中。

```asn1
-- 签名值：signed_params（服务端）与 CertificateVerify（客户端）
SM9Signature ::= SEQUENCE {
    h OCTET STRING,        -- SM3 摘要的模 n 表示（长度 ≤ 32 字节）
    s BIT STRING           -- 65 字节未压缩 G1 点（0x04 ‖ X[32] ‖ Y[32]）
}

-- 密文：IBC 的 IBCEncryptedPreMasterSecret
SM9Cipher ::= SEQUENCE {
    encryptType INTEGER,        -- 加密模式，见下表
    C1          BIT STRING,     -- 65 字节未压缩 G1 点
    C3          OCTET STRING,   -- 32 字节 SM3 校验值
    C2          OCTET STRING    -- 密文数据
}

-- 主公钥（写入 SM9PublicParameterData 与 KeyAgreementInfo）
SM9SignMasterPublicKey    ::= BIT STRING   -- 129 字节未压缩 G2 点
SM9EncryptMasterPublicKey ::= BIT STRING   -- 65 字节未压缩 G1 点

-- 用户私钥（经 PKCS#8 装载，见下）
SM9SignPrivateKey    ::= BIT STRING        -- 65 字节未压缩 G1 点
SM9EncryptPrivateKey ::= BIT STRING        -- 65 字节未压缩 G1 点

-- 未使用（A.7）
SM9KeyPackage ::= SEQUENCE {
    key    OCTET STRING,
    cipher BIT STRING
}
```

| `SM9Cipher.encryptType` | 模式 | 本库用法 |
|------------------------|------|---------|
| `0` | XOR（`DefaultEncrypterOpts`） | **IBC 套件使用**：`sm9.EncryptASN1(..., nil)` 即取该模式，C2 与明文等长 |
| `1` | SM4-ECB（PKCS#7） | 未使用 |
| `2` | SM4-CBC（PKCS#7） | 未使用 |
| `4` | SM4-OFB | 未使用 |
| `8` | SM4-CFB | 未使用 |

**PKCS#8 装载路径（A.1 第 16 项）：** `LoadIBCIdentity` 用 `smx509.ParsePKCS8PrivateKey` 解析三把用户私钥，其结构为

```asn1
PrivateKeyInfo ::= SEQUENCE {
    version             INTEGER,
    privateKeyAlgorithm AlgorithmIdentifier,
    privateKey          OCTET STRING,   -- 内容为 SM9SignPrivateKey / SM9EncryptPrivateKey 的 DER
    attributes          [0] IMPLICIT Attributes OPTIONAL
}
```

- 签名用户私钥的算法 OID 为 `1.2.156.10197.1.302.1`，加密 / 密钥交换用户私钥为 `1.2.156.10197.1.302.3`（`gmsm/smx509` 约定）；
- 私钥内容为 `BIT STRING` 形式的 65 字节 G1 点；`gmsm` 解析同时兼容 `SEQUENCE { BIT STRING [, BIT STRING] }` 包装（第二项为主公钥）；
- 主公钥由 `gmsm` 的 `MarshalASN1()` 写出**裸 `BIT STRING`**（不加 `SEQUENCE` 包装），解析兼容 `SEQUENCE { BIT STRING }`；因此本库生成的 `IBCSysParams` 中主公钥是裸 `BIT STRING`。

### A.7 标准已定义但本库不使用的结构

| 结构 | 出处 | 标准中的用途 | 本库不实现的原因 |
|------|------|-------------|----------------|
| `IBCSysParamsPublishInfo` | GM/T 0081-2020 附录 A | 公共参数的发布保护（带签名） | GM/T 0024-2023 的 Certificate 消息**只传裸 `IBCSysParams`**，握手流程中没有该结构的出现位置；风险与缓解见 §8.2 |
| `IdentifierRevocationList` | GM/T 0081-2020 附录 A.1 | 标识撤销列表（IRL） | TLCP 握手流程无撤销检查点，且 IRL 获取地址依赖标准中无法实现的占位符 `extnID`；吊销检查由 `Config.VerifyIBCIdentity` 承担，见 §8.3 |
| `SM9KeyPackage` | GM/T 0081-2020 消息语法 | SM9 密钥封装（`SEQUENCE { OCTET STRING key, BIT STRING cipher }`） | IBC 套件传的是加密后的预主密钥，使用 `SM9Cipher`；IBSDH 使用 `KeyAgreementInfo`，均不需要密钥封装结构 |

`IBCSysParamsPublishInfo` 的形式定义（本库仅作对照，不解析）：

```asn1
IBCSysParamsPublishInfo ::= SEQUENCE {
    ibcSysParams       IBCSysParams,
    signatureAlgorithm OBJECT IDENTIFIER,
    signatureValue     BIT STRING
}
```

> `IdentifierRevocationList` 的字段定义见标准原文，本库不实现，故此处不转录。

### A.8 版本号、`hid` 与 OID 速查

**版本号：**

| 结构 | 字段 | 取值 | 缺省/校验 |
|------|------|------|----------|
| `Identifier` | `version` | `1`（v1） | `DEFAULT v1`，出现时必须为 1 |
| `IBCSysParams` | `version` | `2`（v2） | 必填，值不符 → `bad_ibcparam(203)` |
| `KeyAgreementInfo` | `version` | `1` | 必填，不做缺省兼容 |

**`hid`（GM/T 0044-2016）：**

| hid | 用途 | 对应私钥字段 |
|-----|------|-------------|
| `0x01` | SM9 签名 / 验签（`signed_params`、`CertificateVerify`） | `IBCIdentity.SignPrivateKey` |
| `0x02` | SM9 密钥交换（`KeyAgreementInfo.hid`，IBSDH） | `IBCIdentity.KeyExchangePrivateKey` |
| `0x03` | SM9 加密 / 解密（IBC 预主密钥） | `IBCIdentity.EncryptPrivateKey` |

> `KeyAgreementInfo.hid` 由发送方填写、接收方直接使用，本库**不校验**其取值，也不校验 `KeyExchangePrivateKey` 的派生 hid；责任划分与失败表现见 §4.3。

**OID：**

| OID | 含义 | 出现位置 |
|-----|------|---------|
| `1.2.156.10197.1.302` | SM9 标识密码算法 | `ibcAlgorithm`、`ibcIdentityType`、`Identifier.ibcType` |
| `1.2.156.10197.6.1.4.4.6` | `KeyAgreementInfo` 的数据类型 OID | GM/T 0081-2020 §12 的数据类型注册 |
| `1.2.156.10197.1.302.1` | SM9 签名用户私钥（PKCS#8 算法 OID） | 私钥 PEM 内层 |
| `1.2.156.10197.1.302.3` | SM9 加密 / 密钥交换用户私钥（PKCS#8 算法 OID） | 私钥 PEM 内层 |

### A.9 编码与解析约定

本库遵循「不发明标准之外的宽容规则；标准本身允许多种形式的地方都要兼容」。与 A.3–A.6 对应的约定如下：

| 项目 | 处理 | 依据 |
|------|------|------|
| ASN.1 tagging 模式 | 写出使用隐式标签（IMPLICIT）；`Identifier.extensions` 解析兼容显式与隐式 | 标准未明确 tagging 模式（§5.1） |
| 时间类型 | 写出时 1950–2049 用 `UTCTime`，其余用 `GeneralizedTime`；解析时两者都接受；`ValidityPeriod` 要求表示到秒 | §6.9 |
| `version` 缺失 / 值不符 / tag 类型不符 / 必填字段缺失 | **拒绝**，`bad_ibcparam(203)` | — |
| `KeyAgreementInfo.hid` | 只要求 1 字节 `OCTET STRING`，**不校验取值**；接收方按消息中的值参与密钥交换 | §4.3 |
| SEQUENCE 内的剩余字节 | **忽略**，向前兼容 | — |
| `ibc_id` / `client_id` | **兼容两种**：`Identifier` 的 DER 或裸标识字节串；比对时抽取 `identityData` | GM/T 0024-2023 6.4.5.3 |
| `tempKey` | **兼容两种**：`SEQUENCE { BIT STRING }` 或裸 `BIT STRING`；必须是合法非无穷远 G1 点 | — |
| 主公钥 | 写出裸 `BIT STRING`，解析兼容 `SEQUENCE { BIT STRING }` | `gmsm` 实现（A.6） |
| `ibcAlgorithm` 非 SM9 / 主公钥不支持 / 无 SM9 项 | **拒绝**，`unsupported_ibcparam(204)` | — |
| `Identifier.extensions` | 扩展项按 `Extension` 读出并保留；`extnValue` 的语义**不解释** | 发布服务 `extnID` 为占位符 |
| 无法解析的 IBC 报文 | 直接返回明确的解析失败错误，**不做格式识别**，不涉及其它标准版本 | §2.2、§9 |

**PEM 封装（本库示例约定）：**

| 内容 | PEM 标签 | 备注 |
|------|---------|------|
| `IBCSysParams` 的 DER | `IBC PARAMETERS` | 非标准标签，示例自用；亦可用 DER 直接传递（§4.4） |
| 三把用户私钥 | `PRIVATE KEY` | 标准 PKCS#8，经 `smx509.ParsePKCS8PrivateKey` 解析 |

告警码与各解析失败场景的对应关系见 §9；信任判定与有效期校验见 §5。
