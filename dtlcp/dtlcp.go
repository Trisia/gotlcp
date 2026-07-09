// Copyright (c) 2025 gotlcp contributors
// gotlcp is licensed under Mulan PSL v2.

// DTLCP 入口点：Server、Client、Dial、Listen

package dtlcp

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
	"time"

	"github.com/emmansun/gmsm/sm2"
	x509 "github.com/emmansun/gmsm/smx509"
)

// Server 基于现有 PacketConn 创建 DTLCP 服务端连接。
// pconn 为底层 UDP 连接，addr 为对端地址，config 为 DTLCP 配置。
// 返回的 Conn 尚未完成握手，首次 Read/Write 时自动触发。
func Server(pconn net.PacketConn, addr net.Addr, config *Config) *Conn {
	c := &Conn{
		pconn:            pconn,
		remoteAddr:       addr,
		config:           config,
		isClient:         false,
		messageSeq:       0,
		nextReceiveSeq:   0,
		writeEpoch:       0,
		readEpoch:        0,
		writeSeq:         0,
		readSeq:          0,
		pendingFragments: make(map[uint16]*fragmentBuffer),
	}
	// 初始化重放窗口：config.ReplayWindow=0 时使用默认值 64
	windowSize := 64
	if config != nil && config.ReplayWindow > 0 {
		windowSize = config.ReplayWindow
	}
	c.replayWindow = newReplayWindow(windowSize)
	c.handshakeFn = c.serverHandshake
	c.initRetransmitTimer(config)
	return c
}

// Client 基于现有 PacketConn 创建 DTLCP 客户端连接。
// pconn 为底层 UDP 连接，addr 为服务端地址，config 为客户端配置。
// 返回的 Conn 尚未完成握手，首次 Read/Write 时自动触发。
func Client(pconn net.PacketConn, addr net.Addr, config *Config) *Conn {
	c := &Conn{
		pconn:            pconn,
		remoteAddr:       addr,
		config:           config,
		isClient:         true,
		messageSeq:       0,
		nextReceiveSeq:   0,
		writeEpoch:       0,
		readEpoch:        0,
		writeSeq:         0,
		readSeq:          0,
		pendingFragments: make(map[uint16]*fragmentBuffer),
	}
	// 初始化重放窗口：config.ReplayWindow=0 时使用默认值 64
	windowSize := 64
	if config != nil && config.ReplayWindow > 0 {
		windowSize = config.ReplayWindow
	}
	c.replayWindow = newReplayWindow(windowSize)
	c.handshakeFn = c.clientHandshake
	c.initRetransmitTimer(config)
	return c
}

// initRetransmitTimer 初始化重传定时器
func (c *Conn) initRetransmitTimer(config *Config) {
	initialTimeout := config.InitialRetransmitTimeout
	if initialTimeout <= 0 {
		initialTimeout = defaultInitialRetransmitTimeout
	}
	maxTimeout := config.MaxRetransmitTimeout
	if maxTimeout <= 0 {
		maxTimeout = defaultMaxRetransmitTimeout
	}
	newTimer := config.NewTimer
	if newTimer == nil {
		newTimer = defaultNewTimer
	}
	c.retransmitTimer = newRetransmitTimer(initialTimeout, maxTimeout, newTimer)
}

const (
	defaultInitialRetransmitTimeout = 1 * time.Second
	defaultMaxRetransmitTimeout     = 60 * time.Second // RFC 6347 §4.2.4 / RFC 6298 max
)

// listener 实现了 net.Listener 接口，用于表示 DTLCP 的 Listener。
// 注意：DTLCP 基于 PacketConn，标准 listener 模式不直接适用，这里提供兼容接口供测试使用。
type listener struct {
	net.Listener
	config *Config
}

// Accept 等待并返还一个 DTLCP 连接对象。
func (l *listener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return Server(conn.(net.PacketConn), conn.RemoteAddr(), l.config), nil
}

// NewListener 基于现有的 net.Listener 创建 DTLCP Listener 对象。
func NewListener(inner net.Listener, config *Config) net.Listener {
	return &listener{Listener: inner, config: config}
}

// Listen 在指定网络地址上创建 DTLCP 监听器。
// network 为网络类型（如 "udp"），laddr 为本地监听地址。
// config 不能为空且至少需要提供签名证书和加密证书（Certificates）。
// 返回的 net.Listener 可用于 Accept DTLCP 连接。
func Listen(network, laddr string, config *Config) (net.Listener, error) {
	if config == nil || len(config.Certificates) == 0 &&
		config.GetCertificate == nil && config.GetConfigForClient == nil {
		return nil, errors.New("dtlcp: neither Certificates, GetCertificate, nor GetConfigForClient set in Config")
	}
	l, err := net.Listen(network, laddr)
	if err != nil {
		return nil, err
	}
	return NewListener(l, config), nil
}

// Dial 使用默认配置发起 DTLCP 客户端连接。
// network 为网络类型（如 "udp"），addr 为服务端地址。
// config 为客户端配置，若为 nil 则使用默认配置。
// 返回已完成握手的 Conn。
func Dial(network, addr string, config *Config) (*Conn, error) {
	return DialContext(context.Background(), network, addr, config)
}

// DialContext 在给定上下文中建立 DTLCP 客户端连接。
// ctx 可用于设置拨号超时。若 ctx 被取消，连接将被关闭。
// 返回已完成握手的 Conn。
func DialContext(ctx context.Context, network, addr string, config *Config) (*Conn, error) {
	rawConn, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	udpConn, ok := rawConn.(net.PacketConn)
	if !ok {
		rawConn.Close()
		return nil, errors.New("dtlcp: dialed connection does not implement PacketConn")
	}
	remoteAddr := rawConn.RemoteAddr()

	if config == nil {
		config = defaultConfig()
	}

	conn := Client(udpConn, remoteAddr, config)
	if err := conn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, err
	}
	return conn, nil
}

// Dialer 是 DTLCP 客户端拨号器，支持配置底层 net.Dialer 和 DTLCP Config。
type Dialer struct {
	// NetDialer 底层网络拨号器，默认使用 net.Dialer。
	NetDialer *net.Dialer
	// Config DTLCP 配置，若为 nil 则使用默认配置。
	Config *Config
}

func (d *Dialer) netDialer() *net.Dialer {
	if d.NetDialer != nil {
		return d.NetDialer
	}
	return new(net.Dialer)
}

// Dial 建立 DTLCP 连接。
func (d *Dialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

// DialContext 在给定上下文中建立 DTLCP 连接。
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return DialContext(ctx, network, addr, d.Config)
}

// LoadX509KeyPair 从文件读取证书和密钥对。
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

// X509KeyPair 解析 PEM 编码的数字证书和私钥。
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
			return fail(errors.New("dtlcp: failed to find any PEM data in certificate input"))
		}
		if len(skippedBlockTypes) == 1 && strings.HasSuffix(skippedBlockTypes[0], "PRIVATE KEY") {
			return fail(errors.New("dtlcp: failed to find certificate PEM data in certificate input, but did find a private key; PEM inputs may have been switched"))
		}
		return fail(fmt.Errorf("dtlcp: failed to find \"CERTIFICATE\" PEM block in certificate input after skipping PEM blocks of the following types: %v", skippedBlockTypes))
	}

	skippedBlockTypes = skippedBlockTypes[:0]
	var keyDERBlock *pem.Block
	for {
		keyDERBlock, keyPEMBlock = pem.Decode(keyPEMBlock)
		if keyDERBlock == nil {
			if len(skippedBlockTypes) == 0 {
				return fail(errors.New("dtlcp: failed to find any PEM data in key input"))
			}
			if len(skippedBlockTypes) == 1 && skippedBlockTypes[0] == "CERTIFICATE" {
				return fail(errors.New("dtlcp: found a certificate rather than a key in the PEM for the private key"))
			}
			return fail(fmt.Errorf("dtlcp: failed to find PEM block with type ending in \"PRIVATE KEY\" in key input after skipping PEM blocks of the following types: %v", skippedBlockTypes))
		}
		if keyDERBlock.Type == "PRIVATE KEY" || strings.HasSuffix(keyDERBlock.Type, " PRIVATE KEY") {
			break
		}
		skippedBlockTypes = append(skippedBlockTypes, keyDERBlock.Type)
	}

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
			return fail(errors.New("dtlcp: private key type does not match public key type"))
		}
		if pub.N.Cmp(priv.N) != 0 {
			return fail(errors.New("dtlcp: private key does not match public key"))
		}
	case *ecdsa.PublicKey:
		priv, ok := cert.PrivateKey.(*sm2.PrivateKey)
		if !ok {
			return fail(errors.New("dtlcp: private key type does not match public key type"))
		}
		if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
			return fail(errors.New("dtlcp: private key does not match public key"))
		}
	default:
		return fail(errors.New("dtlcp: unknown public key algorithm"))
	}

	return cert, nil
}

// parsePrivateKey 解析 PKCS8 格式 SM2 密钥对。
func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *sm2.PrivateKey:
			return key, nil
		case *ecdsa.PrivateKey:
			return nil, errors.New("dtlcp: non-SM2 curve in PKCS#8 private key")
		default:
			return nil, errors.New("dtlcp: found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseTypedECPrivateKey(der); err == nil {
		switch key := key.(type) {
		case *sm2.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("dtlcp: non-SM2 curve in EC private key")
		}
	}
	return nil, errors.New("dtlcp: failed to parse SM2/RSA private key")
}
