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

// Raw 返回原始连接对象
func (c *ProtocolDetectConn) Raw() net.Conn {
	return c.Conn
}

// ReadFirstHeader 读取第1个记录层消息的头部
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
