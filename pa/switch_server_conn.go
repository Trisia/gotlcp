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

// NewProtocolSwitchServerConn 创建一个自适应协议切换连接对象。
//
// 参数：
//   - ln：监听器上下文，来自 pa.NewListener 返回的 net.Listener（其实际类型为包内未导出的 *listener），
//     用于在探测出协议后取出 tlcpCfg 或 tlsCfg，构造对应协议的服务端连接；不能为 nil，且其中至少应配置 tlcpCfg 或 tlsCfg 之一。
//   - rawConn：已建立的原始连接对象，不能为 nil。
//
// 返回值：
//   - *ProtocolSwitchServerConn：协议切换连接对象；此时尚未进行协议探测，首次 Read 或 Write 时才探测。
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

// ProtectedConn 返回被保护的连接对象。
//
// 返回值：
//   - net.Conn：协议探测成功后包装得到的受保护连接，可能为 *tlcp.Conn 或 *tls.Conn；若尚未通过 Read/Write 触发协议探测，或探测失败，则返回 nil。
//
// 该连接没有独立的 error 返回通道，探测失败的原因只能从后续 Read/Write 返回的错误中获得，调用方使用返回值前需自行判空。
func (c *ProtocolSwitchServerConn) ProtectedConn() net.Conn {
	return c.wrapped
}

// Read 从协议切换连接中读取应用数据，实现 io.Reader 接口。
//
// 参数：
//   - b：接收数据的缓冲区。
//
// 返回值：
//   - n：本次读取的字节数。
//   - error：读取失败时返回非 nil；若协议探测失败，返回探测错误（如未配置对应协议时的 "pa: tlcp config not set"/"pa: tls config not set"，或 ProtocolNotSupportError），此时 n 为 0。
//
// 当 wrapped 尚未建立时会先根据客户端首个记录层消息的协议版本号完成协议探测；探测失败时 wrapped 保持 nil，
// 因此之后每次调用 Read 都会重新探测，并重新调用 ReadFirstHeader 读取、覆盖上次缓存的 5 字节头部；
// 但首次探测已从底层连接消费了 5 字节，重试读到的不再是客户端 Hello 的起始字节，因此通常无法通过重试恢复；
// 探测成功后，读取由对应的 tlcp.Conn 或 tls.Conn 处理。
func (c *ProtocolSwitchServerConn) Read(b []byte) (n int, err error) {
	if c.wrapped == nil {
		err = c.detect()
		if err != nil {
			return 0, err
		}
	}
	return c.wrapped.Read(b)
}

// Write 向协议切换连接写入应用数据，实现 io.Writer 接口。
//
// 参数：
//   - b：待写入的数据。
//
// 返回值：
//   - n：本次写入的字节数。
//   - error：写入失败时返回非 nil；若协议探测失败，返回探测错误（如未配置对应协议时的 "pa: tlcp config not set"/"pa: tls config not set"，或 ProtocolNotSupportError），此时 n 为 0。
//
// 当 wrapped 尚未建立时会先根据客户端首个记录层消息的协议版本号完成协议探测；探测失败时 wrapped 保持 nil，
// 因此之后每次调用 Write 都会重新探测，并重新调用 ReadFirstHeader 读取、覆盖上次缓存的 5 字节头部；
// 但首次探测已从底层连接消费了 5 字节，重试读到的不再是客户端 Hello 的起始字节，因此通常无法通过重试恢复；
// 探测成功后，写入由对应的 tlcp.Conn 或 tls.Conn 处理。
func (c *ProtocolSwitchServerConn) Write(b []byte) (n int, err error) {
	if c.wrapped == nil {
		err = c.detect()
		if err != nil {
			return 0, err
		}
	}
	return c.wrapped.Write(b)
}
