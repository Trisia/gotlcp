package pa

import (
	"bytes"
	"net"
	"testing"
	"time"
)

type mockConn struct {
	*bytes.Buffer
}

func (m *mockConn) Close() error {
	return nil
}

func (m *mockConn) LocalAddr() net.Addr {
	panic("implement me")
}

func (m *mockConn) RemoteAddr() net.Addr {
	panic("implement me")
}

func (m *mockConn) SetDeadline(t time.Time) error {
	panic("implement me")
}

func (m *mockConn) SetReadDeadline(t time.Time) error {
	panic("implement me")
}

func (m *mockConn) SetWriteDeadline(t time.Time) error {
	panic("implement me")
}

func TestTypeDetectConn_Read(t *testing.T) {

	raw := &mockConn{Buffer: bytes.NewBuffer([]byte{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
	})}

	conn := &ProtocolDetectConn{Conn: raw}

	// CASE 1 无内容，直接读取
	buf := make([]byte, 10)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 10 {
		t.Fatalf("should be read 10 bytes,but not %d", n)
	}
	if !bytes.Equal(buf[:n], []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}) {
		t.Fatalf("result not match expect, %02X", buf)
	}
	// CASE 2 内容长度 大于 读取长度
	conn.recordHeader = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	buf = make([]byte, 4)
	n, err = conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], []byte{0xFF, 0xFF, 0xFF, 0xFF}) {
		t.Fatalf("result not match expect, %02X", buf)
	}
	// CASE 3 读取长度 大于 内容长度
	buf = make([]byte, 8)
	n, err = conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01, 0x02, 0x03}) {
		t.Fatalf("result not match expect, %02X", buf)
	}
}
