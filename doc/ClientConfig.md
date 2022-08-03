# GoTLCP 客户端配置

TLCP的客户端配置主要是对`tlcp.Config`对象进行配置。

TLCP协议服务端对客户端有如下认证类型：

- 单向身份认证：客户端必须验证服务端身份，服务端不验证客户端身份。
- 双向身份认证：客户端必须验证服务端身份，服务端必须验证客户端身份。

在TLCP协议中身份认证通过 数字证书 与 证书验证消息完成。

- 可信的数字证书保证了认证不会受到中间人攻击。
- 证书验证消息则是采用密码学的原理（如数字签名）保证了真实性、不可抵赖性。

本文将分为两个部分：分别为基础配置部分、高级配置部分

## 1. 基础配置

关于 **数字证书解析、密钥对解析构造** 相关内容请参考 [**《GoTLCP 数字证书及密钥》**](./CertAndKey.md)。

### 1.1 单向身份认证

单向身份认证指在握手过程中 **客户端对服务端进行身份**，该方式适用于服务端不需要对访问者进行认证，但是客户端期望使用安全的传输通道的情况，是TLCP最常见的应用方式之一。

身份认证包含：数字证书的校验、签名值的校验。

单向身份认证需要如下配置：

1. 在客户端用于验证服务服务端数字证书的根证书列表，通过`tlcp.Config`的`RootCAs`参数配置，提供证书列表。

```go
package main

import (
	"github.com/emmansun/gmsm/smx509"
	"github.com/emmansun/gmsm/smx509"
)

func main() {
	// 构造根证书列表
	pool := smx509.NewCertPool()
	pool.AddCert(rootCert)

	config := &tlcp.Config{RootCAs: pool}
	conn, err := tlcp.Dial("tcp", "127.0.0.1:8445", config)
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	// do something...
}
```

示例见 [auth/main.go](../example/client/auth/main.go)

### 1.2 双向身份认证

双向身份认证指在握手过程中 **客户端对服务端进行身份，服务端对客户端进行身份认证**，该方式适用于通信双方均有较高安全性需要。

身份认证包含：数字证书的校验、签名值的校验。

双向身份认证需要如下配置：

1. 在客户端用于验证服务服务端数字证书的根证书列表，通过`tlcp.Config`的`RootCAs`参数配置，提供证书列表。
2. 在客户端提供 **认证密钥对和认证证书**，通过`tlcp.Config`的`Certificates`参数配置，提供证书密钥对。

```go
package main

import (
	"gitee.com/Trisia/gotlcp/tlcp"
	"github.com/emmansun/gmsm/smx509"
)

func main() {
	// 构造根证书列表
	pool := smx509.NewCertPool()
	pool.AddCert(rootCert)

	config := &tlcp.Config{
		RootCAs:      pool,
		Certificates: []tlcp.Certificate{authCertKeypair},
	}
	conn, err := tlcp.Dial("tcp", "127.0.0.1:8445", config)
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	// do something...
}
```

示例见 [mutual_auth/main.go](../example/client/mutual_auth/main.go)


### 1.3 忽略认证 用于测试 

**注意：该方式仅用于测试，在忽略了服务端的身份认证后非常容易遭受中间攻击。**

在测试过程中可能需要忽略服务端的身份验证，此时可以设置 `InsecureSkipVerify`参数为`true`表示不对服务端的证书证书进行校验，跳过服务端身份认证。

注： `InsecureSkipVerify`仅用于跳过服务端的数字证书校验，并不会跳过服务端证书验证（Certificate Verify）消息的校验。

```go
package main

import (
	"gitee.com/Trisia/gotlcp/tlcp"
)

func main() {
	config := &tlcp.Config{InsecureSkipVerify: true}
	conn, err := tlcp.Dial("tcp", "127.0.0.1:8444", config)
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	// do something...
}

```

示例见 [no_auth/main.go](../example/client/no_auth/main.go)

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
- 客户端已经成功完成过一次完整握手，并且客户端缓存该会话。
- 重用握手时，服务端上的会话缓存未过期。
- 重用握手时，客户端上的会话缓存未过期。

客户端配置如下：

```go
package main

import (
	"gitee.com/Trisia/gotlcp/tlcp"
	"github.com/emmansun/gmsm/smx509"
)

func main() {
	// 构造根证书列表
	pool := smx509.NewCertPool()
	pool.AddCert(rootCert)
	config := &tlcp.Config{
		RootCAs:      pool,
		SessionCache: tlcp.NewLRUSessionCache(32),
	}

	// 进行完整握手，并缓存会话
	conn, err := tlcp.Dial("tcp", "127.0.0.1:8448", config)
	if err != nil {
		panic(err)
	}
	// 主动触发完整握手
	err = conn.Handshake()
	if err != nil {
		panic(err)
	}
	_ = conn.Close()

	// 通过同一个配置对象创建新的TLCP 触发重用握手
	conn, err = tlcp.Dial("tcp", "127.0.0.1:8448", config)
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	// do something...
}
```

注：目前GoTLCP基于LRU策略实现了会话缓存器，如您有自己的缓存策略可以通过实现 [tlcp.SessionCache](../tlcp/session.go) 接口来解决。

示例见 [resume/main.go](../example/client/resume/main.go)
