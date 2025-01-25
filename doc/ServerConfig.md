# GoTLCP 服务端配置

TLCP的服务端配置主要对`tlcp.Config`对象进行配置。

TLCP协议服务端对客户端有如下认证类型：

- 单向身份认证：服务端不验证客户端身份，客户端必须验证服务端身份。
- 双向身份认证：服务端必须验证客户端身份，客户端必须验证服务端身份。

在TLCP协议中身份认证通过 数字证书 与 证书验证消息完成。

- 可信的数字证书保证了认证不会受到中间人攻击。
- 证书验证消息则是采用密码学的原理（如数字签名）保证了真实性、不可抵赖性。

本文将分为两个部分：分别为基础配置部分、高级配置部分

## 1. 基础部分

### 1.1 单向身份认证


单向身份认证指在握手过程中 **客户端对服务端进行身份**，该方式适用于服务端不需要对访问者进行认证，但是客户端期望使用安全的传输通道的情况，是TLCP最常见的应用方式之一。

由于是单向身份认证，服务端不对客户端进行身份认证。

单向身份认证需要如下配置：

1. 配置服务端提供握手需要的签名密钥对、加密密钥对、签名证书、加密证书，通过配置`tlcp.Config`的`Certificates`，提供2对密钥对和证书实现。

```go
package main

import (
    "gitee.com/Trisia/gotlcp/tlcp"
)

func main() {
    config := &tlcp.Config{
        Certificates: []tlcp.Certificate{sigCertKey, encCertKey},
    }
    listen, err := tlcp.Listen("tcp", ":8447", config)
    if err != nil {
        panic(err)
    }
    for {
        conn, err := listen.Accept()
        if err != nil {
            panic(err)
        }
        // do something
    }
}
```

示例见 [server/auth/main.go](../example/server/auth/main.go)

### 1.2 双向身份认证

双向身份认证指在握手过程中 **客户端对服务端进行身份，服务端对客户端进行身份认证**，该方式适用于通信双方均有较高安全性需要。

在双向身份认证过程中，服务端需要对客户端进行身份认证，认证包含：客户端数字证书的校验、客户端签名值的校验。

双向身份认证需要如下配置：

1. 配置服务端提供握手需要的签名密钥对、加密密钥对、签名证书、加密证书，通过配置`tlcp.Config`的`Certificates`，提供2对密钥对和证书实现。
2. 配置用于验证客户端认证证书的根证书列表，通过`tlcp.Config`的`ClientCAs`参数配置，提供客户端根证书列表。
3. 配置客户端认证类型为需要客户端身份认证，通过配置`tlcp.Config`的`ClientAuth`参数为值`tlcp.RequireAndVerifyClientCert`。

```go
package main

import (
    "gitee.com/Trisia/gotlcp/tlcp"
    "github.com/emmansun/gmsm/smx509"
)

func main() {
    pool := smx509.NewCertPool()
    pool.AddCert(rootCert)
    config := &tlcp.Config{
        Certificates: []tlcp.Certificate{sigCertKey, encCertKey},
        ClientAuth:   tlcp.RequireAndVerifyClientCert,
        ClientCAs:    pool,
    }
    listen, err := tlcp.Listen("tcp", ":8449", config)
    if err != nil {
        panic(err)
    }
    for {
        conn, err := listen.Accept()
        if err != nil {
            panic(err)
        }
        // do something...
    }
}
```

示例见 [server/mutual_auth/main.go](../example/server/mutual_auth/main.go)


## 2. 高级配置

### 2.1 会话重用

TLCP协议支持两种握手握手方式：

- 完整握手
- 重用握手

> 关于两种握手方式见 [《关于 TLCP协议》](./AboutTLCP.md)

重用握手方式不需要通过密钥协商，通信双方通过复用上一次握手协商得到的会话密钥和相关密码参数建立连接，提升了连接建立效率，减少握手带来的性能开销。

重用握手流程，需要满足如下条件：

- 服务端支持握手重用。
- 客户端支持握手重用。
- 服务端已经完成与客户端的完整握手，并且客户端与服务端都缓存该会话。
- 客户端Hello使用同样的会话ID。
- 重用握手时，服务端上的会话缓存未过期。
- 重用握手时，客户端上的会话缓存未过期。

服务端配置如下：

1. 根据单向身份认证或双向身份认证完成`tlcp.Config`相关参数，见基础配置部分。
2. 提供会话缓冲器。

```go
package main

import (
    "gitee.com/Trisia/gotlcp/tlcp"
)

func main() {
    config := &tlcp.Config{
        Certificates: []tlcp.Certificate{sigCertKey, encCertKey},
        SessionCache: tlcp.NewLRUSessionCache(128),
    }
    listen, err := tlcp.Listen("tcp", ":8449", config)
    if err != nil {
        panic(err)
    }
    for {
        conn, err := listen.Accept()
        if err != nil {
            panic(err)
        }
        // do something...
    }
}
```

目前GoTLCP基于LRU策略实现了会话缓存器。

如您有自己的缓存策略请在 **保证密钥安全的前提下** 根据 [tlcp.SessionCache](../tlcp/session.go) 接口实现属于您自己的缓存器。

示例见 [server/resume/main.go](../example/server/resume/main.go)


### 2.2 使用现有连接

理论上来说TLCP协议能够工作任何可靠连接的协议之上，在Go中只要是实现了`net.Conn`接口的可靠连接都可以承载TLCP协议，下面以TCP连接示例：

1. 创建一个可靠连接对象，如TCP连接。
2. 通过`tlcp.Server(conn net.Conn, config *Config)` 构造TLCP连接对象。
3. 使用连接通信。

```go
package main

import (
    "gitee.com/Trisia/gotlcp/tlcp"
    "net"
)

func main() {
    listen, err := net.Listen("tcp", ":8450")
    if err != nil {
        panic(err)
    }
    raw, err := listen.Accept()
    if err != nil {
        panic(err)
    }

    conn := tlcp.Server(raw, config)
    defer conn.Close()

    // use conn do something...
}
```

`tlcp.Server(conn net.Conn, config *Config)`接口只要求连接对象实现了`net.Conn`接口，并且提供TLCP相关配置参数就可以作为TLCP服务端使用TLCP协议通信。

可以使用`tlcp.NewListener(inner net.Listener, config *Config) net.Listener`方法来复用现有可靠连接的Listener对象来创建TLCP Listener。

完整示例见 [server/raw/main.go](../example/server/raw/main.go)


### 2.3 密码套件选择

默认情况下 Go TLCP 启用如下密码套件，按照优先级如下：

1. `ECC_SM4_GCM_SM3`
2. `ECC_SM4_CBC_SM3`
3. `ECDHE_SM4_GCM_SM3`
4. `ECDHE_SM4_CBC_SM3`

注意： ECDHE基于SM2密钥交换实现，需要客户端具有认证密钥、加密密钥才有效，服务端将会发证书请求要求客户端验证身份，并通过密钥交换消息协商预主密钥。

可以通过下面方式手动指定握手使用的密码套件：

```go
config := &tlcp.Config{
    // 省略其它无关配置项...
    ClientAuth:   RequireAndVerifyClientCert,
    CipherSuites: []uint16{
        tlcp.ECDHE_SM4_GCM_SM3, 
        tlcp.ECC_SM4_CBC_SM3,   
    },
}
```

完整示例见 [server/mutual_auth_spec/main.go](../example/server/mutual_auth_spec/main.go)

### 2.4 客户端校验策略

服务端具有不同的客户端认证策略，用于实现不同等级的客户端安全校验。

在服务端对客户端证书安全策略通过`tlcp.Config`中的`ClientAuth`参数配置，目前GoTLCP支持以下策略类型：

| 参数值 | 意义 |
| :-- | :-- |
| NoClientCert | 不需要客户端证书。 |
| RequestClientCert | 标识服务端是否在握手过程中向客户端发送证书请求消息，但并不在乎客户端是否发送证书消息。 | 
| RequireAnyClientCert | 要求客户端在握手过程中向服务端发送客户端认证证书，但是不对证书有效性校验。 |
| VerifyClientCertIfGiven | 若客户端提供了客户端证书则校验，否则忽略客户端证书校验。 |
| RequireAndVerifyAnyKeyUsageClientCert | 要求客户端在握手过程中向服务端发送客户端认证证书，并且验证数字证书有效性，证书验证时忽略证书的扩展密钥用法。|
| RequireAndVerifyClientCert | 要求客户端在握手过程中向服务端发送客户端认证证书，并且验证数字证书，且要求客户端证书具有`x509.ExtKeyUsageClientAuth`或`x509.ExtKeyUsageServerAuth`的扩展密钥用法。|


### 2.5 证书校验

若开启`RequestClientCert`及以上的客户端验证，在客户端证书验证失败时将会返回`tlcp.CertificateVerificationError`类型的错误。

通常您可以通过该错误得知证书的验证失败的类型和描述，如下：

```go
err := conn.Read(buf);
if err != nil && errors.As(err, &tlcp.CertificateVerificationError{}) {
    //     错误处理...
}
```

若`tlcp.CertificateVerificationError`类型的错误若难以满足您的需要，您需要可能需要由自己来实现证书验证流程，可以通过如下方式开启自定义证书校验：

1. 配置`tlcp.Config`中的`InsecureSkipVerify`参数为`true`，表示关闭默认证书安全校验。
2. 实现并设置`tlcp.Config`中的`VerifyPeerCertificate`的校验对端证书方法。
   - 函数原型`func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error`。
   - 参数 `rawCerts` 为客户端证书消息中的DER编码的证书数组。
   - 参数 `verifiedChains` 固定为空。
   - 返回值 `nil` 表示有效，非`nil`表示证书校验失败。

示例如下：

```go
config := &tlcp.Config{
    InsecureSkipVerify: true,
    VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*smx509.Certificate) error {
        // 自定证书的验证流程...
        return nil
    },
}
```

### 2.6 根据TrustedCAKey扩展选择证书

在 GM/T0024-2023《SSL VPN技术规范》中支持了Hello消息扩展字段，通过扩展字段中的TrustedCAKeys就可让服务器根据指定的证书信息选择合适的证书。

目前支持一下类型的证书信息参数：

| 参数名称 | 参数值 | 参数意义            |
| :-- | :-- |:----------------|
| IdentifierTypePreAgreed| 0 | Pre-agreed预先协商  |
| IdentifierTypeX509Name|2 | X.509证书名称       |
| IdentifierTypeKeySM3Hash|4 | 密钥SM3哈希         |
| IdentifierTypeCertSM3Hash|5 | 证书SM3哈希         |


默认情况下GoTLCP将会忽略TrustedCAKeys扩展，您需要自己实现相应方法来实现证书的选择，主要为实现 `GetCertificate` 与 `GetKECertificate`方法


```go
config := &tlcp.Config{
    // ...
    GetCertificate: func(info *ClientHelloInfo) (*Certificate, error) {
        if len(info.TrustedCAIndications) > 0 {
            if info.TrustedCAIndications[0].IdentifierType == IdentifierTypeX509Name {
            // 服务端根据客户端提供的CA指示选择签名证书
                if bytes.Compare(info.TrustedCAIndications[0].Identifier, mySigCert.Leaf.RawSubject) == 0 {
                    return &mySigCert, nil
                }
            }
        }
        return &sigCert, nil
    },
    GetKECertificate: func(info *ClientHelloInfo) (*Certificate, error) {
        if len(info.TrustedCAIndications) > 0 {
            if info.TrustedCAIndications[0].IdentifierType == IdentifierTypeX509Name {
                if bytes.Compare(info.TrustedCAIndications[0].Identifier, myEncCert.Leaf.RawSubject) == 0 {
                    return &myEncCert, nil
                }
            }
        }
        return &encCert, nil
    },
}
```

以上示例展示如何通过 **X.509证书名称** 寻找证书返回证书方法。

