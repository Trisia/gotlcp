package pa

import (
	"crypto/tls"
	"errors"
	"gitee.com/Trisia/gotlcp/tlcp"
	"net"
)

type ProtocolNotSupportError struct{}

func (ProtocolNotSupportError) Error() string   { return "pa: unknown protocol version" }
func (ProtocolNotSupportError) Timeout() bool   { return false }
func (ProtocolNotSupportError) Temporary() bool { return false }

var notSupportError = &ProtocolNotSupportError{}

// listener tlcp/tls协议自适应监听器， 实现了 net.Listener 接口，用于表示自适应连接选择监听器
type listener struct {
	net.Listener              // 端口监听器
	tlcpCfg      *tlcp.Config // TLCP连接配置对象
	tlsCfg       *tls.Config  // TLS 连接配置对象
}

// Accept 等待并返还一个自适应选择完成后的连接对象
// 每次Accept内部都将会自动选择
// 返回的连接对象实现 net.Conn 接口，可能为 tlcp.Conn 对象或 tls.Conn
func (l *listener) Accept() (net.Conn, error) {
	rawConn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return NewProtocolSwitchServerConn(l, rawConn), nil
}

// NewListener tlcp/tls协议自适应，基于现有的一个可靠连接的 net.Listener 创建TLCP的Listener对象
// 配置参数对象 tlcpCfg 或 tlsCfg 两者不能全为空，
// 当其中一方为空时工作工作模式切换至单一的一种协议。
//
// 对于tlcpCfg对象至少提供签名密钥对和加密密钥以及签名证书和加密证书
// 当然也可以通过 tlcp.Config.GetCertificate 与 tlcp.Config.GetKECertificate 以动态的方式获取相应密钥对于证书。
func NewListener(inner net.Listener, tlcpCfg *tlcp.Config, tlsCfg *tls.Config) net.Listener {
	if inner == nil || (tlcpCfg == nil && tlsCfg == nil) {
		return nil
	}

	l := new(listener)
	l.Listener = inner
	l.tlcpCfg = tlcpCfg
	l.tlsCfg = tlsCfg
	return l
}

// Listen tlcp/tls协议自适应，在指定的网络协议上，监听指定地址的端口 创建一个 TLCP的listener接受客户端连接
// 配置参数对象 tlcpCfg 或 tlsCfg 两者不能全为空，
// 当其中一方为空时工作工作模式切换至单一的一种协议。
//
// 对于tlcpCfg对象至少提供签名密钥对和加密密钥以及签名证书和加密证书
// 当然也可以通过 Config.GetCertificate 与 Config.GetKECertificate 以动态的方式获取相应密钥对于证书。
func Listen(network, laddr string, tlcpCfg *tlcp.Config, tlsCfg *tls.Config) (net.Listener, error) {
	if tlcpCfg == nil && tlsCfg == nil {
		return nil, errors.New("pa: neither tlcp config, tls config is nil")
	}
	if tlcpCfg == nil || len(tlcpCfg.Certificates) == 0 &&
		tlcpCfg.GetCertificate == nil && tlcpCfg.GetConfigForClient == nil {
		return nil, errors.New("tlcp: neither Certificates, GetCertificate, nor GetConfigForClient set in Config")
	}
	l, err := net.Listen(network, laddr)
	if err != nil {
		return nil, err
	}
	return NewListener(l, tlcpCfg, tlsCfg), nil
}
