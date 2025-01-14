package tlcp

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// pipeConn 实现了 net.Conn 接口
type pipeConn struct {
	readCh    chan []byte
	writeCh   chan []byte
	closed    <-chan struct{}
	buffer    []byte
	closedInt int32
	cancel    context.CancelFunc
}

// NewMockConn 创建两个 pipeConn 对象，一个用于客户端，一个用于服务器端
func mockPipe() (cli net.Conn, svr net.Conn) {
	readCh := make(chan []byte, 1)
	writeCh := make(chan []byte, 1)
	ctx, cancel := context.WithCancel(context.Background())
	return &pipeConn{
			readCh:  readCh,
			writeCh: writeCh,
			closed:  ctx.Done(),
			cancel:  cancel,
		}, &pipeConn{
			readCh:  writeCh,
			writeCh: readCh,
			closed:  ctx.Done(),
			cancel:  cancel,
		}
}

// Read 实现了 net.Conn 接口的 Read 方法
func (c *pipeConn) Read(b []byte) (n int, err error) {
	if atomic.LoadInt32(&c.closedInt) == 1 {
		err = io.EOF
		return
	}
	if len(c.buffer) > 0 {
		n = copy(b, c.buffer)
		c.buffer = c.buffer[n:]
		return n, nil
	}

	select {
	case data := <-c.readCh:
		n = copy(b, data)
		if n < len(data) {
			c.buffer = data[n:]
		}
	case <-c.closed:
		err = io.EOF
	}
	return
}

// Write 实现了 net.Conn 接口的 Write 方法
func (c *pipeConn) Write(b []byte) (n int, err error) {
	if atomic.LoadInt32(&c.closedInt) == 1 {
		err = io.EOF
		return
	}
	select {
	case c.writeCh <- b:
		n = len(b)
	case <-c.closed:
		err = io.EOF
	}
	return
}

// Close 实现了 net.Conn 接口的 Close 方法
func (c *pipeConn) Close() error {
	if atomic.CompareAndSwapInt32(&c.closedInt, 0, 1) {
		c.cancel()
	}
	return nil
}

// LocalAddr 实现了 net.Conn 接口的 LocalAddr 方法
func (c *pipeConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
}

// RemoteAddr 实现了 net.Conn 接口的 RemoteAddr 方法
func (c *pipeConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8081}
}

// SetDeadline 实现了 net.Conn 接口的 SetDeadline 方法
func (c *pipeConn) SetDeadline(t time.Time) error {
	return nil // 这里没有实现超时逻辑
}

// SetReadDeadline 实现了 net.Conn 接口的 SetReadDeadline 方法
func (c *pipeConn) SetReadDeadline(t time.Time) error {
	return nil // 这里没有实现超时逻辑
}

// SetWriteDeadline 实现了 net.Conn 接口的 SetWriteDeadline 方法
func (c *pipeConn) SetWriteDeadline(t time.Time) error {
	return nil // 这里没有实现超时逻辑
}

func Test_pipeConn(t *testing.T) {
	cli, svr := mockPipe()
	defer cli.Close()
	defer svr.Close()

	data := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	go func() {
		time.Sleep(100 * time.Millisecond)
		_, _ = svr.Write(data)
	}()
	buf := make([]byte, 10)
	n, err := cli.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 10 {
		t.Fatalf("should be read 10 bytes,but not %d", n)
	}
	if !bytes.Equal(buf[:n], data) {
		t.Fatalf("result not match expect, %02X", buf)
	}
}
