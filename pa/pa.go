package pa

import (
	"crypto/tls"
	"errors"
	"gitee.com/Trisia/gotlcp/tlcp"
	"net"
)

type ProtocolNotSupportError struct{}

// Error 返回协议不支持的错误描述，满足 error 接口。
//
// 返回值：
//   - string：固定错误文本 "pa: unknown protocol version"。
func (ProtocolNotSupportError) Error() string { return "pa: unknown protocol version" }

// Timeout 返回该错误是否属于超时错误，满足 net.Error 接口。
//
// 返回值：
//   - bool：始终为 false，客户端记录层版本号不受支持与超时无关。
func (ProtocolNotSupportError) Timeout() bool { return false }

// Temporary 返回该错误是否属于临时性错误，满足 net.Error 接口。
//
// 返回值：
//   - bool：始终为 false，协议版本不受支持不是可重试的临时错误。
func (ProtocolNotSupportError) Temporary() bool { return false }

var notSupportError = &ProtocolNotSupportError{}

// listener tlcp/tls协议自适应监听器， 实现了 net.Listener 接口，用于表示自适应连接选择监听器
type listener struct {
	net.Listener              // 端口监听器
	tlcpCfg      *tlcp.Config // TLCP连接配置对象
	tlsCfg       *tls.Config  // TLS 连接配置对象
}

// Accept 等待并返回一个协议自适应监听器接受的连接对象，实现 net.Listener 接口。
//
// 返回值：
//   - net.Conn：包装原始连接得到的 *ProtocolSwitchServerConn，实现 net.Conn 接口；此时两种协议的连接都尚未建立，协议探测被推迟到该连接首次 Read 或 Write 时。
//   - error：底层监听器接受连接失败时返回非 nil，此时连接为 nil。
//
// 每次 Accept 都会为新接受的原始连接创建一个独立的协议切换连接对象，并将在其首次读写时按客户端记录层版本号自动选择协议，
// 探测完成后由对应的 tlcp.Conn 或 tls.Conn 处理后续数据。
func (l *listener) Accept() (net.Conn, error) {
	rawConn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return NewProtocolSwitchServerConn(l, rawConn), nil
}

// NewListener 基于现有的一个可靠连接的 net.Listener 创建 TLCP/TLS 协议自适应的 Listener 对象。
//
// 参数：
//   - inner：底层可靠连接的监听器，负责接受原始连接，不能为 nil。
//   - tlcpCfg：TLCP 连接配置对象，可为 nil，但不能与 tlsCfg 同时为 nil；为 nil 时该监听器仍会接受连接并完成协议探测，只是在探测判定为 TLCP 后由探测逻辑返回 "pa: tlcp config not set" 错误，该连接不可用；非 nil 时正常应至少提供签名密钥对和加密密钥以及签名证书和加密证书，当然也可以通过 tlcp.Config.GetCertificate 与 tlcp.Config.GetKECertificate 以动态的方式获取相应密钥对于证书，本函数不校验这些内容。
//   - tlsCfg：TLS 连接配置对象，可为 nil，但不能与 tlcpCfg 同时为 nil；为 nil 时该监听器仅支持 TLCP 协议。
//
// 返回值：
//   - net.Listener：协议自适应监听器，其 Accept 返回的连接为 *ProtocolSwitchServerConn，在首次读写时按客户端记录层版本号自动选择协议；当 inner 为 nil 或 tlcpCfg 与 tlsCfg 同时为 nil 时返回 nil。
//
// 配置参数对象 tlcpCfg 或 tlsCfg 两者不能全为空，
// 当其中一方为空时工作模式切换至单一的一种协议。
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

// Listen 在指定的网络协议上，监听指定地址的端口，创建一个 TLCP/TLS 协议自适应的 listener 接受客户端连接。
//
// 参数：
//   - network：网络协议名，取值与 net.Listen 一致，例如 "tcp"、"tcp4"、"tcp6"。
//   - laddr：本地监听地址，格式为 "host:port"，例如 ":9443"。
//   - tlcpCfg：TLCP 连接配置对象，不能为 nil，且至少提供签名密钥对和加密密钥以及签名证书和加密证书，也可以通过 GetCertificate 动态获取证书；实现校验的是 Certificates 非空或 GetCertificate、GetConfigForClient 之一非 nil，三者均未设置时直接返回错误，GetKECertificate 不参与该校验，仅配置它同样会被拒绝。
//   - tlsCfg：TLS 连接配置对象，可为 nil；为 nil 时监听器仅支持 TLCP 协议。
//
// 返回值：
//   - net.Listener：协议自适应监听器，其 Accept 返回的连接为 *ProtocolSwitchServerConn。
//   - error：tlcpCfg 与 tlsCfg 同时为 nil、tlcpCfg 为 nil 或未提供证书且未设置 GetCertificate/GetConfigForClient、或底层 net.Listen 失败时返回非 nil，此时监听器为 nil。
//
// 配置参数对象 tlcpCfg 或 tlsCfg 两者不能全为空，
// 当其中一方为空时工作模式切换至单一的一种协议。
// 注意：当前实现中 tlcpCfg 为 nil 时会直接返回错误，若需仅使用 TLS 协议，请改用 NewListener 封装监听器。
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
