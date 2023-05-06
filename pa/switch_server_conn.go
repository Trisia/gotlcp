package pa

import (
	"crypto/tls"
	"fmt"
	"gitee.com/Trisia/gotlcp/tlcp"
	"net"
	"sync"
)

// ProtocolSwitchServerConn 自适应协议切换连接对象
type ProtocolSwitchServerConn struct {
	net.Conn

	lock    *sync.Mutex         // 防止并发调用
	p       *ProtocolDetectConn // 协议检测对象
	ln      *listener           // 监听器上下文
	wrapped net.Conn            // 包装后的连接对象
}

// NewProtocolSwitchServerConn 创建一个自适应协议切换连接对象
// ln: 监听器上下文
// rawConn: 原始连接对象
func NewProtocolSwitchServerConn(ln *listener, rawConn net.Conn) *ProtocolSwitchServerConn {
	p := &ProtocolDetectConn{Conn: rawConn}
	return &ProtocolSwitchServerConn{
		Conn:    rawConn,
		ln:      ln,
		p:       p,
		lock:    new(sync.Mutex),
		wrapped: nil,
	}
}

// 推断连接类型
func (c *ProtocolSwitchServerConn) detect() error {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.wrapped != nil {
		return nil
	}

	err := c.p.ReadFirstHeader()
	if err != nil {
		return err
	}
	// 根据连接的记录层协议主版本号判断连接类型
	switch c.p.major {
	case 0x01:
		// TLCP major version 0x01
		if c.ln.tlcpCfg == nil {
			return fmt.Errorf("pa: tlcp config not set")
		}
		c.wrapped = tlcp.Server(c.p, c.ln.tlcpCfg)
	case 0x03:
		// SSL/TLS major version 0x03
		if c.ln.tlsCfg == nil {
			return fmt.Errorf("pa: tls config not set")
		}
		c.wrapped = tls.Server(c.p, c.ln.tlsCfg)
	default:
		return notSupportError
	}
	return nil
}

// ProtectedConn 返回被保护的连接对象
func (c *ProtocolSwitchServerConn) ProtectedConn() net.Conn {
	return c.wrapped
}

func (c *ProtocolSwitchServerConn) Read(b []byte) (n int, err error) {
	if c.wrapped == nil {
		err = c.detect()
		if err != nil {
			return 0, err
		}
	}
	return c.wrapped.Read(b)
}

func (c *ProtocolSwitchServerConn) Write(b []byte) (n int, err error) {
	if c.wrapped == nil {
		err = c.detect()
		if err != nil {
			return 0, err
		}
	}
	return c.wrapped.Write(b)
}
