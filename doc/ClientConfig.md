# GoTLCP 客户端配置

TLCP的客户端配置主要对`tlcp.Config`对象进行配置。

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

示例见 [client/auth/main.go](../example/client/auth/main.go)

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

示例见 [client/mutual_auth/main.go](../example/client/mutual_auth/main.go)


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

示例见 [client/no_auth/main.go](../example/client/no_auth/main.go)

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
- 客户端已经完成与服务端的完整握手，并且服务端与客户端都缓存该会话。
- 客户端Hello使用同样的会话ID。
- 重用握手时，服务端上的会话缓存未过期。
- 重用握手时，客户端上的会话缓存未过期。

客户端配置如下：

1. 根据单向身份认证或双向身份认证完成`tlcp.Config`相关参数，见基础配置部分。
2. 提供会话缓冲器。

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

目前GoTLCP基于LRU策略实现了会话缓存器。 

如您有自己的缓存策略请在 **保证密钥安全的前提下** 根据 [tlcp.SessionCache](../tlcp/session.go) 接口实现属于您自己的缓存器。

示例见 [client/resume/main.go](../example/client/resume/main.go)



### 2.2 使用现有连接

理论上来说TLCP协议能够工作任何可靠连接的协议之上，在Go中只要是实现了`net.Conn`接口的可靠连接都可以承载TLCP协议，下面以TCP连接示例：

1. 创建一个可靠连接对象，如TCP连接。
2. 通过`tlcp.Client(conn net.Conn, config *Config)` 构造TLCP连接对象。
3. 使用连接通信。

```go
package main

import (
	"net"
	"gitee.com/Trisia/gotlcp/tlcp"
)

func main() {
    
	// 创建TCP连接
	raw, err := net.Dial("tcp", "127.0.0.1:8447")
	if err != nil {
		panic(err)
	}
	// 使用TCP连接，运行TLCP协议，构造TLCP连接
	conn := tlcp.Client(raw, config)
	defer conn.Close()

    // use conn do something...
}
```

`tlcp.Client(conn net.Conn, config *Config)`接口只要求连接对象实现了`net.Conn`接口，并且提供TLCP相关配置参数就可以作为TLCP客户端使用TLCP协议通信。

可以使用`tlcp.DialWithDialer(dialer *net.Dialer, network, addr string, config *Config) (*Conn, error)`方法来复用现有可靠连接的Dialer对象来创建TLCP Dialer。

完整示例见 [client/raw/main.go](../example/client/raw/main.go)

### 2.3 密码套件选择

默认情况下 Go TLCP 启用如下密码套件，按照优先级如下：

1. `ECC_SM4_GCM_SM3`
2. `ECC_SM4_CBC_SM3`
3. `ECDHE_SM4_GCM_SM3` (试验性)
4. `ECDHE_SM4_CBC_SM3` (试验性)

注意： ECDHE基于SM2密钥交换实现，需要客户端具有认证密钥才启用。

可以通过下面方式手动指定握手使用的密码条件和顺序：

```go
config := &tlcp.Config{
    // 省略其它无关配置项...
	Certificates: []tlcp.Certificate{authCertKeypair},
	CipherSuites: []uint16{
		tlcp.ECDHE_SM4_GCM_SM3, // 最高优先级
		tlcp.ECC_SM4_GCM_SM3,	
		tlcp.ECC_SM4_CBC_SM3,   // 最低优先级
	},
}
```

完整示例见 [client/mutual_auth_spec/main.go](../example/client/mutual_auth_spec/main.go)