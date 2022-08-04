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
