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
	"github.com/emmansun/gmsm/smx509"
)

// Server 基于现有 PacketConn 创建 DTLCP 服务端连接。
//
// 参数：
//   - pconn：已建立的底层数据报连接，作为 DTLCP 记录层的承载，不能为 nil。
//   - addr：对端（客户端）地址，用于确定该连接的数据报来源以及发送目标；可以为 nil，此时不校验数据报来源，并把收到的第一个报文地址回填为对端地址（允许 nil 存在来源伪造风险，仅适用于测试或已自行校验来源的场景）。
//   - config：DTLCP 配置对象，不能为 nil，且至少提供签名密钥对和签名证书、加密密钥对和加密证书（Certificates 顺序为 [签名密钥对, 加密密钥对]）；也可以通过 Config.GetCertificate 与 Config.GetKECertificate 动态获取相应密钥对与证书。
//
// 返回值：
//   - *Conn：包装后的 DTLCP 服务端连接，尚未完成握手，首次 Read/Write 时自动触发。
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
	// 初始化重放窗口：config.ReplayWindow=0 时使用默认值
	windowSize := defaultReplayWindowSize
	if config != nil && config.ReplayWindow > 0 {
		windowSize = config.ReplayWindow
	}
	c.replayWindow = newReplayWindow(windowSize)
	c.handshakeFn = c.serverHandshake
	c.initRetransmitTimer(config)
	return c
}

// Client 基于现有 PacketConn 创建 DTLCP 客户端连接。
//
// 参数：
//   - pconn：已建立的底层数据报连接，作为 DTLCP 记录层的承载，不能为 nil。
//   - addr：服务端地址，用于确定握手与数据传输的对端；可以为 nil，此时不校验数据报来源，并把收到的第一个报文地址回填为对端地址（允许 nil 存在来源伪造风险，仅适用于测试或已自行校验来源的场景）。
//   - config：DTLCP 配置对象，不能为 nil；若服务端要求客户端身份认证，还需在 Certificates 中提供签名密钥对和签名证书。
//
// 返回值：
//   - *Conn：包装后的 DTLCP 客户端连接，尚未完成握手，首次 Read/Write 时自动触发。
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
	// 初始化重放窗口：config.ReplayWindow=0 时使用默认值
	windowSize := defaultReplayWindowSize
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
//
// 参数：
//   - inner：底层监听器，负责接受原始连接，不能为 nil；其 Accept 返回的连接需要实现 net.PacketConn（DTLCP 基于数据报传输）。
//   - config：DTLCP 配置对象，将传递给 Accept 产生的服务端连接；通常不能为 nil。
//
// 返回值：
//   - net.Listener：DTLCP 监听器，其 Accept 返回的连接均为 *Conn。
//
// 注意：Accept 会对底层连接做非检查型的 net.PacketConn 类型断言，若 inner.Accept 返回的连接
// 未实现 net.PacketConn（例如 TCP 的 *net.TCPConn），会直接 panic 而不是返回错误；
// 如需在 UDP 上监听，请使用 Listen。
func NewListener(inner net.Listener, config *Config) net.Listener {
	return &listener{Listener: inner, config: config}
}

// Listen 在指定网络地址上创建 DTLCP 监听器。
//
// 参数：
//   - network：网络协议名，DTLCP 面向数据报传输，通常为 "udp"（也支持 "udp4"、"udp6"）；取值语义与 net.ListenPacket 一致。
//   - laddr：本地监听地址，格式为 "host:port"，例如 ":8443"。
//   - config：DTLCP 配置对象，不能为 nil，且 Certificates、GetCertificate、GetConfigForClient 三者至少设置其一，否则返回错误；本方法不校验加密证书（Certificates[1] 或 GetKECertificate 缺失要到握手阶段才失败）。
//
// 返回值：
//   - net.Listener：DTLCP 监听器，其 Accept 返回的连接均为 *Conn，可用于接受 DTLCP 连接。
//   - error：配置缺失或底层监听失败时返回非 nil，此时监听器为 nil。
//
// 实现说明：监听器内部用单个 net.PacketConn 承载所有客户端，并按数据报的来源地址分发；
// 每个首次出现的来源地址经 Accept 得到一个独立的 *Conn，各连接只会读取属于自己的数据报，
// 因此同一个监听端口可以同时服务多个客户端。Conn.Close 只注销对应客户端，不会关闭监听 socket。
func Listen(network, laddr string, config *Config) (net.Listener, error) {
	if config == nil || len(config.Certificates) == 0 &&
		config.GetCertificate == nil && config.GetConfigForClient == nil {
		return nil, errors.New("dtlcp: neither Certificates, GetCertificate, nor GetConfigForClient set in Config")
	}
	pconn, err := net.ListenPacket(network, laddr)
	if err != nil {
		return nil, err
	}
	return newPacketListener(pconn, config), nil
}

// Dial 使用默认配置发起 DTLCP 客户端连接。
//
// 参数：
//   - network：网络协议名，例如 "udp"；取值语义与 net.Dial 一致。
//   - addr：服务端地址，格式为 "host:port"。
//   - config：DTLCP 配置对象，若为 nil 则使用默认配置。
//
// 返回值：
//   - *Conn：已完成握手的 DTLCP 客户端连接。
//   - error：拨号或握手失败时返回非 nil，此时返回的连接为 nil。
func Dial(network, addr string, config *Config) (*Conn, error) {
	return DialContext(context.Background(), network, addr, config)
}

// DialContext 在给定上下文中建立 DTLCP 客户端连接。
//
// 参数：
//   - ctx：握手的上下文，不能为 nil；ctx 只约束握手阶段（通过 conn.HandshakeContext 生效），拨号与 DNS 解析阶段使用 net.Dial，不响应 ctx 取消；若握手期间 ctx 被取消或超时，连接将被关闭并返回错误。
//   - network：网络协议名，例如 "udp"；取值语义与 net.Dial 一致。
//   - addr：服务端地址，格式为 "host:port"。
//   - config：DTLCP 配置对象，若为 nil 则使用默认配置。
//
// 返回值：
//   - *Conn：已完成握手的 DTLCP 客户端连接。
//   - error：拨号、底层连接类型断言或握手失败时返回非 nil，此时返回的连接为 nil。
func DialContext(ctx context.Context, network, addr string, config *Config) (*Conn, error) {
	rawConn, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	udpConn, ok := rawConn.(*net.UDPConn)
	if !ok {
		rawConn.Close()
		return nil, errors.New("dtlcp: dialed connection is not a UDP connection")
	}
	remoteAddr := rawConn.RemoteAddr()

	if config == nil {
		config = defaultConfig()
	}

	// 已连接的 UDP socket 不能再调用 WriteTo（会返回 ErrWriteToConnected），
	// 这里通过 connectedPacketConn 把 WriteTo 转换为 Write。
	conn := Client(&connectedPacketConn{UDPConn: udpConn}, remoteAddr, config)
	if err := conn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, err
	}
	return conn, nil
}

// Dialer 是 DTLCP 客户端拨号器，支持配置底层 net.Dialer 和 DTLCP Config。
type Dialer struct {
	// NetDialer 底层网络拨号器；当前实现中 (*Dialer).DialContext 直接调用包级 DialContext（内部使用 net.Dial），该字段无调用点、完全不生效，其超时、LocalAddr 等设置均不会应用。
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
//
// 参数：
//   - network：网络协议名，例如 "udp"；取值语义与 net.Dial 一致。
//   - addr：服务端地址，格式为 "host:port"。
//
// 返回值：
//   - net.Conn：已完成握手的 DTLCP 连接，其实现为 *Conn。
//   - error：拨号或握手失败时返回非 nil。
//
// Dial 内部使用 context.Background 作为上下文，如果需要指定上下文，请使用 DialContext 方法。
func (d *Dialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

// DialContext 在给定上下文中建立 DTLCP 连接。
//
// 参数：
//   - ctx：连接与握手的上下文，不能为 nil；若在握手完成之前上下文过期，将会终止本次连接。
//   - network：网络协议名，例如 "udp"；取值语义与 net.Dial 一致。
//   - addr：服务端地址，格式为 "host:port"。
//
// 返回值：
//   - net.Conn：已完成握手的 DTLCP 连接，其实现为 *Conn。
//   - error：拨号或握手失败时返回非 nil。
//
// 本方法使用 Dialer 的 Config 字段作为 DTLCP 配置，该字段为 nil 时使用默认配置。
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return DialContext(ctx, network, addr, d.Config)
}

// LoadX509KeyPair 从文件读取证书和密钥对，并解析 PEM 编码的数字证书、公私钥对。
//
// 参数：
//   - certFile：PEM 编码的证书文件路径，文件中可以包含多张证书。
//   - keyFile：PEM 编码的私钥文件路径。
//
// 返回值：
//   - Certificate：解析得到的证书与私钥对。
//   - error：读取文件失败或解析证书、私钥失败时返回非 nil。
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
//
// 参数：
//   - certPEMBlock：PEM 编码的证书数据，可以包含多张证书。
//   - keyPEMBlock：PEM 编码的私钥数据。
//
// 返回值：
//   - Certificate：解析得到的证书与私钥对，并填充 Leaf 与 PrivateKey 字段。
//   - error：未找到证书或私钥 PEM 块、解析失败、或证书与私钥不匹配时返回非 nil。
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
	if key, err := smx509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *sm2.PrivateKey:
			return key, nil
		case *ecdsa.PrivateKey:
			return nil, errors.New("dtlcp: non-SM2 curve in PKCS#8 private key")
		default:
			return nil, errors.New("dtlcp: found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := smx509.ParseTypedECPrivateKey(der); err == nil {
		switch key := key.(type) {
		case *sm2.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("dtlcp: non-SM2 curve in EC private key")
		}
	}
	return nil, errors.New("dtlcp: failed to parse SM2/RSA private key")
}
