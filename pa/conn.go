package pa

import (
	"io"
	"net"
)

// ProtocolDetectConn 连接类型检测连接
// 该类型连接对象将会对连接到来的客户端Hello消息进行分析解析出连接协议，
// 并缓存收到的消息，将自己作为原始连接对象。
type ProtocolDetectConn struct {
	net.Conn
	major, minor uint8  // 协议版本
	recordHeader []byte // 客户端Hello消息的记录层协议头部
}

// protocolVersion 连接所使用的协议版本
func (c *ProtocolDetectConn) protocolVersion() (major uint8, minor uint8) {
	return c.major, c.minor
}

// Raw 返回 ProtocolDetectConn 所包装的原始连接对象。
//
// 返回值：
//   - net.Conn：构造时嵌入的底层原始连接，即未经协议探测包装的连接。
func (c *ProtocolDetectConn) Raw() net.Conn {
	return c.Conn
}

// ReadFirstHeader 从原始连接读取第 1 个记录层消息的头部，并解析出协议版本号。
//
// 返回值：
//   - error：io.ReadFull 未读满 5 字节时返回非 nil（例如 io.EOF、io.ErrUnexpectedEOF）。
//
// 实现是无条件地从缓冲区第 2、3 字节写入版本号的，即使 io.ReadFull 一个字节都没有读到（缓冲区全为 0）也会把版本号记为 0, 0，
// 因此读取失败时该版本号可能无效。
// 记录层头部的格式为：内容类型（1 字节）、协议版本（2 字节）、长度（2 字节），共 5 字节。
// 读取到的头部随后被缓存在该连接对象中，之后调用 Read 时会优先返回这部分缓存数据。
func (c *ProtocolDetectConn) ReadFirstHeader() error {
	// struct {
	//  ContentType     type;							// 1 Byte
	//  ProtocolVersion version;						// 2 Byte
	//  uint16          length;							// 2 Byte
	//  opaque          fragment[TLSPlaintext.length];  // length Byte
	//}
	c.recordHeader = make([]byte, 5)
	_, err := io.ReadFull(c.Conn, c.recordHeader)
	c.major, c.minor = c.recordHeader[1], c.recordHeader[2]
	return err
}

// Read 读取协议检测连接上的数据，实现 io.Reader 接口。
//
// 参数：
//   - b：接收数据的缓冲区，长度可以为 0。
//
// 返回值：
//   - n：本次读取的字节数，可能小于 len(b)；当 n > 0 时也可能同时返回非 nil 的 error，此时应优先处理已读取的数据。
//   - error：读取失败时返回非 nil，通常是底层原始连接返回的错误；连接正常读完时为 io.EOF。
//
// 若 ReadFirstHeader 已读取并缓存了记录层头部，Read 会先返回这部分缓存数据，缓存可能跨越多次调用返回，
// 缓存耗尽后再直接从底层原始连接读取；若未读取过头部，则直接委托底层原始连接读取。
func (c *ProtocolDetectConn) Read(b []byte) (n int, err error) {
	if len(c.recordHeader) == 0 {
		return c.Conn.Read(b)
	}

	if len(b) >= len(c.recordHeader) {
		n = copy(b, c.recordHeader)
		c.recordHeader = nil
		if len(b) > n {
			var n1 = 0
			n1, err = c.Conn.Read(b[n:])
			n += n1
			if err != nil {
				return n, err
			}
		}
		return n, nil
	} else {
		p := c.recordHeader[:len(b)]
		n = len(b)
		copy(b, p)
		c.recordHeader = c.recordHeader[len(b):]
		if len(c.recordHeader) == 0 {
			c.recordHeader = nil
		}
		return n, nil
	}
}
