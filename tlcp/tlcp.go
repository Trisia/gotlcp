// Copyright (c) 2022 QuanGuanyu
// gotlcp is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package tlcp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

// Server 使用现有连接对象构造一个新的 TLCP 服务端连接对象。
//
// 参数：
//   - conn：已建立的底层可靠连接，作为 TLCP 记录层的承载，不能为 nil。
//   - config：TLCP 配置对象，不能为 nil，且至少提供签名密钥对和签名证书、加密密钥对和加密证书；
//     也可以通过 Config.GetCertificate 与 Config.GetKECertificate 以动态的方式获取相应密钥对与证书；
//     配置缺失不会在构造阶段报错，而是在握手阶段失败。
//
// 返回值：
//   - *Conn：包装后的 TLCP 服务端连接，握手在首次读写时进行。
func Server(conn net.Conn, config *Config) *Conn {
	c := &Conn{
		conn:   conn,
		config: config,
	}
	c.handshakeFn = c.serverHandshake
	return c
}

// Client 使用现有连接对象构造一个新的 TLCP 客户端连接对象。
//
// 参数：
//   - conn：已建立的底层可靠连接，作为 TLCP 记录层的承载，不能为 nil。
//   - config：TLCP 配置对象，不能为 nil；若服务端要求客户端身份认证，还需在 Certificates 中提供签名密钥对和签名证书。
//
// 返回值：
//   - *Conn：包装后的 TLCP 客户端连接，握手在首次读写时进行。
func Client(conn net.Conn, config *Config) *Conn {
	c := &Conn{
		conn:     conn,
		config:   config,
		isClient: true,
	}
	c.handshakeFn = c.clientHandshake
	return c
}

// listener 实现了 net.Listener 接口，用于表示 TLCP的Listener
type listener struct {
	net.Listener
	config *Config
}

// Accept 等待并返还一个TLCP连接对象
// 返回的连接对象为 net.Conn 类型
func (l *listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return Server(c, l.config), nil
}

// NewListener 基于现有的一个可靠连接的 net.Listener 创建 TLCP 的 Listener 对象。
//
// 参数：
//   - inner：底层可靠连接的监听器，负责接受原始连接，不能为 nil。
//   - config：TLCP 配置对象，不能为 nil；本方法不做校验，证书与密钥是否满足服务端要求
//     （至少提供签名密钥对和签名证书、加密密钥对和加密证书）要到握手阶段才会暴露，
//     也可以通过 Config.GetCertificate 与 Config.GetKECertificate 以动态的方式获取相应密钥对与证书。
//
// 返回值：
//   - net.Listener：TLCP 监听器，其 Accept 返回的连接均为 *Conn。
func NewListener(inner net.Listener, config *Config) net.Listener {
	l := new(listener)
	l.Listener = inner
	l.config = config
	return l
}

// Listen 在指定的网络协议上，监听指定地址的端口，创建一个 TLCP 的 Listener 接受 TLCP 客户端连接。
//
// 参数：
//   - network：网络协议名，取值与 net.Listen 一致，例如 "tcp"、"tcp4"、"tcp6"。
//   - laddr：本地监听地址，格式为 "host:port"，例如 ":8443"。
//   - config：TLCP 配置对象，不能为 nil；本方法要求 Certificates、GetCertificate、GetConfigForClient
//     三者至少设置其一，或 IBCIdentity、GetIBCIdentity 至少设置其一（仅使用 IBC/IBSDH 套件、
//     不配置任何 X.509 证书的服务端）。此处不校验证书与密钥的数量：仅当签名证书来源
//     （Certificates[0] 或 GetCertificate）与加密证书来源（Certificates[1] 或 GetKECertificate）
//     同时存在时，服务端才被判定具备 X.509 双证书能力；缺少加密证书来源又未配置 IBC 身份时，
//     握手会以 unrecognized_name 告警结束（见 Config.hasX509Certificates）。
//
// 返回值：
//   - net.Listener：TLCP 监听器，其 Accept 返回的连接均为 *Conn。
//   - error：配置缺失或监听失败时返回非 nil。
func Listen(network, laddr string, config *Config) (net.Listener, error) {
	if config == nil || len(config.Certificates) == 0 &&
		config.GetCertificate == nil && config.GetConfigForClient == nil &&
		config.IBCIdentity == nil && config.GetIBCIdentity == nil {
		return nil, errors.New("tlcp: neither Certificates, GetCertificate, GetConfigForClient, nor IBCIdentity set in Config")
	}
	l, err := net.Listen(network, laddr)
	if err != nil {
		return nil, err
	}
	return NewListener(l, config), nil
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "tlcp: DialWithDialer timed out" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// DialWithDialer 使用提供的 net.Dialer 对象，实现 TLCP 客户端握手，建立 TLCP 连接。
//
// 参数：
//   - dialer：底层可靠连接的拨号器，不能为 nil；其 Timeout 与 Deadline 同时约束握手过程。
//   - network：网络协议名，取值与 net.Dial 一致，例如 "tcp"、"tcp4"、"tcp6"。
//   - addr：服务端地址，格式为 "host:port"。
//   - config：TLCP 配置对象；为 nil 时使用默认配置。
//
// 返回值：
//   - *Conn：握手完成的 TLCP 客户端连接。
//   - error：拨号或握手失败时返回非 nil，此时返回的连接为 nil。
//
// DialWithDialer 内使用 context.Background 上下文，若您需要指定自定义的上下文。
// 请在构造 Dialer 然后调用 Dialer.DialContext 方法设置。
func DialWithDialer(dialer *net.Dialer, network, addr string, config *Config) (*Conn, error) {
	return dial(context.Background(), dialer, network, addr, config)
}

func dial(ctx context.Context, netDialer *net.Dialer, network, addr string, config *Config) (*Conn, error) {
	if netDialer.Timeout != 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, netDialer.Timeout)
		defer cancel()
	}

	if !netDialer.Deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, netDialer.Deadline)
		defer cancel()
	}

	rawConn, err := netDialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	if config == nil {
		config = defaultConfig()
	}

	conn := Client(rawConn, config)
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	return conn, nil
}

// Dial 使用指定类型的网络与目标地址进行 TLCP 客户端侧握手，建立 TLCP 连接。
//
// 参数：
//   - network：网络协议名，取值与 net.Dial 一致，例如 "tcp"、"tcp4"、"tcp6"。
//   - addr：服务端地址，格式为 "host:port"。
//   - config：TLCP 配置对象；为 nil 时使用默认配置。
//
// 返回值：
//   - *Conn：握手完成的 TLCP 客户端连接。
//   - error：拨号或握手失败时返回非 nil，此时返回的连接为 nil。
func Dial(network, addr string, config *Config) (*Conn, error) {
	return DialWithDialer(new(net.Dialer), network, addr, config)
}

// Dialer 通过所给的 net.Dialer 和 Config 配置信息，实现TLCP客户端握手的Dialer对象。
type Dialer struct {
	// NetDialer 可选择 可靠连接的拨号器，用于创建承载TLCP协议的底层连接对象。
	// 若 NetDialer 为空，使用默认的 new(net.Dialer) 创建拨号器
	NetDialer *net.Dialer

	// Config TLCP 配置信息，若为空则使用 空值的 Config{}
	Config *Config
}

// Dial 使用指定类型的网络与目标地址进行 TLCP 客户端侧握手，建立 TLCP 连接。
//
// 参数：
//   - network：网络协议名，取值与 net.Dial 一致，例如 "tcp"、"tcp4"、"tcp6"。
//   - addr：服务端地址，格式为 "host:port"。
//
// 返回值：
//   - net.Conn：握手完成的 TLCP 连接，其实现为 *Conn。
//   - error：拨号或握手失败时返回非 nil。
//
// Dial 内部使用 context.Background 作为上下文，如果需要指定上下文，请使用 DialContext 方法
func (d *Dialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d *Dialer) netDialer() *net.Dialer {
	if d.NetDialer != nil {
		return d.NetDialer
	}
	return new(net.Dialer)
}

// DialContext 在指定上下中，使用指定类型的网络与目标地址进行 TLCP 客户端侧握手，建立 TLCP 连接。
//
// 参数：
//   - ctx：连接与握手的上下文，不能为空；若在连接完成之前上下文过期，将会终止本次连接。
//   - network：网络协议名，取值与 net.Dial 一致，例如 "tcp"、"tcp4"、"tcp6"。
//   - addr：服务端地址，格式为 "host:port"。
//
// 返回值：
//   - net.Conn：握手完成的 TLCP 连接，其实现为 *Conn。
//   - error：拨号或握手失败时返回非 nil。
//
// 一旦连接完成，上下文的过期不会影响到已经连接完成的连接。
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	c, err := dial(ctx, d.netDialer(), network, addr, d.Config)
	if err != nil {
		// Don't return c (a typed nil) in an interface.
		return nil, err
	}
	return c, nil
}

// LoadX509KeyPair 从文件中读取证书和密钥对，并解析 PEM 编码的数字证书、公私钥对。
//
// 参数：
//   - certFile：PEM 编码的证书文件路径，文件中可以包含多张证书。
//   - keyFile：PEM 编码的私钥文件路径，支持 PKCS#8（SM2 或 RSA）与 SM2 椭圆曲线私钥，非 SM2 曲线的私钥会被拒绝。
//
// 返回值：
//   - Certificate：解析得到的证书与私钥对，其中 Leaf 字段已由证书链首张证书解析并填充。
//   - error：读取文件或解析证书、私钥失败时返回非 nil。
func LoadX509KeyPair(certFile, keyFile string) (Certificate, error) {
	certPEMBlock, err := os.ReadFile(certFile)
	if err != nil {
		return Certificate{}, err
	}
	keyPEMBlock, err := os.ReadFile(keyFile)
	if err != nil {
		return Certificate{}, err
	}
	return X509KeyPair(certPEMBlock, keyPEMBlock)
}

// X509KeyPair 解析 PEM 编码的数字证书、公私钥对。
//
// 参数：
//   - certPEMBlock：PEM 编码的证书数据，可以包含多张证书。
//   - keyPEMBlock：PEM 编码的私钥数据，支持 PKCS#8（SM2 或 RSA）与 SM2 椭圆曲线私钥，非 SM2 曲线的私钥会被拒绝。
//
// 返回值：
//   - Certificate：解析得到的证书与私钥对，其中 Leaf 字段已由证书链首张证书解析并填充。
//   - error：解析失败或证书与私钥不匹配时返回非 nil。
func X509KeyPair(certPEMBlock, keyPEMBlock []byte) (Certificate, error) {
	fail := func(err error) (Certificate, error) { return Certificate{}, err }

	var cert Certificate
	var skippedBlockTypes []string
	for {
		var certDERBlock *pem.Block
		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
		} else {
			skippedBlockTypes = append(skippedBlockTypes, certDERBlock.Type)
		}
	}

	if len(cert.Certificate) == 0 {
		if len(skippedBlockTypes) == 0 {
			return fail(errors.New("tlcp: failed to find any PEM data in certificate input"))
		}
		if len(skippedBlockTypes) == 1 && strings.HasSuffix(skippedBlockTypes[0], "PRIVATE KEY") {
			return fail(errors.New("tlcp: failed to find certificate PEM data in certificate input, but did find a private key; PEM inputs may have been switched"))
		}
		return fail(fmt.Errorf("tlcp: failed to find \"CERTIFICATE\" PEM block in certificate input after skipping PEM blocks of the following types: %v", skippedBlockTypes))
	}

	skippedBlockTypes = skippedBlockTypes[:0]
	var keyDERBlock *pem.Block
	for {
		keyDERBlock, keyPEMBlock = pem.Decode(keyPEMBlock)
		if keyDERBlock == nil {
			if len(skippedBlockTypes) == 0 {
				return fail(errors.New("tlcp: failed to find any PEM data in key input"))
			}
			if len(skippedBlockTypes) == 1 && skippedBlockTypes[0] == "CERTIFICATE" {
				return fail(errors.New("tlcp: found a certificate rather than a key in the PEM for the private key"))
			}
			return fail(fmt.Errorf("tlcp: failed to find PEM block with type ending in \"PRIVATE KEY\" in key input after skipping PEM blocks of the following types: %v", skippedBlockTypes))
		}
		if keyDERBlock.Type == "PRIVATE KEY" || strings.HasSuffix(keyDERBlock.Type, " PRIVATE KEY") {
			break
		}
		skippedBlockTypes = append(skippedBlockTypes, keyDERBlock.Type)
	}

	// We don't need to parse the public key for TLS, but we so do anyway
	// to check that it looks sane and matches the private key.
	x509Cert, err := smx509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fail(err)
	}
	cert.Leaf = x509Cert

	cert.PrivateKey, err = parsePrivateKey(keyDERBlock.Bytes)
	if err != nil {
		return fail(err)
	}
	switch pub := x509Cert.PublicKey.(type) {
	case *rsa.PublicKey:
		priv, ok := cert.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			return fail(errors.New("tlcp: private key type does not match public key type"))
		}
		if pub.N.Cmp(priv.N) != 0 {
			return fail(errors.New("tlcp: private key does not match public key"))
		}
	case *ecdsa.PublicKey:
		priv, ok := cert.PrivateKey.(*sm2.PrivateKey)
		if !ok {
			return fail(errors.New("tlcp: private key type does not match public key type"))
		}
		if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
			return fail(errors.New("tlcp: private key does not match public key"))
		}
	default:
		return fail(errors.New("tlcp: unknown public key algorithm"))
	}

	return cert, nil
}

// 解析PKCS8(PEM)格式 SM2密钥对
func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	//if key, err := smx509.ParsePKCS1PrivateKey(der); err == nil {
	//	return key, nil
	//}
	if key, err := smx509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *sm2.PrivateKey: // 这个项目还需要支持RSA吗？目前没有实现RSA密码套件
			return key, nil
		case *ecdsa.PrivateKey:
			return nil, errors.New("tlcp: non-SM2 curve in PKCS#8 private key")
		default:
			return nil, errors.New("tlcp: found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := smx509.ParseTypedECPrivateKey(der); err == nil {
		switch key := key.(type) {
		case *sm2.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("tlcp: non-SM2 curve in EC private key")
		}
	}

	return nil, errors.New("tlcp: failed to parse SM2/RSA private key")
}
