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
	x509 "github.com/emmansun/gmsm/smx509"
)

// Server 使用现有连接对象构造一个新的TLCP服务端连接对象
// 配置参数对象 config 不能为空，且至少提供签名密钥对和加密密钥以及签名证书和加密证书
// 当然也可以通过 Config.GetCertificate与 Config.GetKECertificate以动态的方式获取相应密钥对于证书。
func Server(conn net.Conn, config *Config) *Conn {
	c := &Conn{
		conn:   conn,
		config: config,
	}
	c.handshakeFn = c.serverHandshake
	return c
}

// Client 使用现有连接对象构造一个新的TLCP客户端连接对象
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

// NewListener 基于现有的一个可靠连接的 net.Listener 创建TLCP的Listener对象
// 配置参数对象 config 不能为空，且至少提供签名密钥对和加密密钥以及签名证书和加密证书
// 当然也可以通过 Config.GetCertificate 与 Config.GetKECertificate 以动态的方式获取相应密钥对于证书。
func NewListener(inner net.Listener, config *Config) net.Listener {
	l := new(listener)
	l.Listener = inner
	l.config = config
	return l
}

// Listen 在指定的网络协议上，监听指定地址的端口 创建一个 TLCP的listener接受TLCP客户端连接
// 配置参数对象 config 不能为空，且至少提供签名密钥对和加密密钥以及签名证书和加密证书
// 当然也可以通过 Config.GetCertificate 与 Config.GetKECertificate 以动态的方式获取相应密钥对于证书。
func Listen(network, laddr string, config *Config) (net.Listener, error) {
	if config == nil || len(config.Certificates) == 0 &&
		config.GetCertificate == nil && config.GetConfigForClient == nil {
		return nil, errors.New("tlcp: neither Certificates, GetCertificate, nor GetConfigForClient set in Config")
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

// DialWithDialer 使用提供的 net.Dialer 对象，实现TLCP客户端握手，建立TLCP连接。
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

// Dial 使用指定类型的网络与目标地址进行TLCP客户端侧握手，建立TLCP连接。
func Dial(network, addr string, config *Config) (*Conn, error) {
	return DialWithDialer(new(net.Dialer), network, addr, config)
}

// Dialer 通过所给的 net.Dialer 和 Config 配置信息，实现TLCP客户端握手的Dialer对象。
type Dialer struct {
	// NetDialer 可选择 可靠连接的拨号器，用于创建承载TLCP协议的底层连接对象。
	// 若 NetDialer 为空，使用默认的 new(et.Dialer) 创建拨号器
	NetDialer *net.Dialer

	// Config TLCP 配置信息，若为空则使用 空值的 Config{}
	Config *Config
}

// Dial 使用指定类型的网络与目标地址进行TLCP客户端侧握手，建立TLCP连接。
//
// Dial 方法仅在握手成功时返还 net.Conn对象，其实现为 *Conn。
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

// DialContext 在指定上下中，使用指定类型的网络与目标地址进行TLCP客户端侧握手，建立TLCP连接。
//
// 注意该方法的 ctx 参数不能为空，如果在连接完成之前上下文过期了，将会返还一个错误。
// 一旦连接完成，上下文的过期不会影响到已经连接完成的连接。
//
// Dial 方法仅在握手成功时返还 net.Conn 对象，其实现为 *Conn
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	c, err := dial(ctx, d.netDialer(), network, addr, d.Config)
	if err != nil {
		// Don't return c (a typed nil) in an interface.
		return nil, err
	}
	return c, nil
}

// LoadX509KeyPair 从文件中读取证书和密钥对，并解析 PEM编码的数字证书、公私钥对。
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

// X509KeyPair 解析 PEM编码的数字证书、公私钥对。
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
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
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
	//if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
	//	return key, nil
	//}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *sm2.PrivateKey: // 这个项目还需要支持RSA吗？目前没有实现RSA密码套件
			return key, nil
		case *ecdsa.PrivateKey:
			return nil, errors.New("tlcp: non-SM2 curve in PKCS#8 private key")
		default:
			return nil, errors.New("tlcp: found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseTypedECPrivateKey(der); err == nil {
		switch key := key.(type) {
		case *sm2.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("tlcp: non-SM2 curve in EC private key")
		}
	}

	return nil, errors.New("tlcp: failed to parse SM2/RSA private key")
}
