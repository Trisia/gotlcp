package tlcp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
	"io"
	"math/big"
	"net"
	"os"
	"sync"
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

const RootPrv = `-----BEGIN SM2 PRIVATE KEY-----
MHcCAQEEINi9llASP5IpPDorVE5bZnv5UDpXdtp3oyqPRd6XsIdNoAoGCCqBHM9V
AYItoUQDQgAEyxhvORdkf1Rm9tTaCbzAO+m3V6O4wCLXNdjK7LE6YvXqlbhEK3iR
VpN5jvBZbUO9okJjxjR0DSo+oXCBqrxqog==
-----END SM2 PRIVATE KEY-----
`

func TestGenSelfSignedCert(t *testing.T) {
	prvDER, _ := pem.Decode([]byte(RootPrv))
	rootPrv, _ := smx509.ParseSM2PrivateKey(prvDER.Bytes)
	rootCert, _ := smx509.ParseCertificatePEM([]byte(ROOT_CERT_PEM))

	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	//certTpl := smx509.Certificate{
	//	SerialNumber:          new(big.Int).SetInt64(1),
	//	Subject:               pkix.Name{Country: []string{"CN"}, CommonName: "TEST_CA"},
	//	NotBefore:             time.Now().AddDate(0, 0, -1),
	//	NotAfter:              time.Now().AddDate(30, 0, 0),
	//	KeyUsage:              smx509.KeyUsageCertSign | smx509.KeyUsageCRLSign,
	//	BasicConstraintsValid: true,
	//	IsCA:                  true,
	//}
	certTpl := smx509.Certificate{
		SerialNumber: new(big.Int).SetInt64(time.Now().Unix()),
		Issuer:       rootCert.Subject,
		Subject:      pkix.Name{Country: []string{"CN"}, Province: []string{"浙江"}, Locality: []string{"杭州"}, CommonName: "Entity_CERT"},
		NotBefore:    runtimeTime().Add(-time.Hour * 24),
		NotAfter:     time.Now().AddDate(30, 0, 0),
		KeyUsage:     smx509.KeyUsageDigitalSignature | smx509.KeyUsageKeyEncipherment | smx509.KeyUsageDataEncipherment | smx509.KeyUsageKeyAgreement,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost", "test.com"},
	}

	certificate, err := smx509.CreateCertificate(rand.Reader, &certTpl, rootCert, key.Public(), rootPrv)
	if err != nil {
		panic(err)
	}

	privateKey, _ := smx509.MarshalSM2PrivateKey(key)
	_ = pem.Encode(os.Stdout, &pem.Block{Type: "SM2 PRIVATE KEY", Bytes: privateKey})
	_ = pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: certificate})
}

// svrConn 让服务端监听器与连接绑定，以便在关闭连接时关闭监听器
type svrConn struct {
	l net.Listener
	net.Conn
}

func (s *svrConn) Close() error {
	err := s.Conn.Close()
	if s.l != nil {
		return s.l.Close()
	}
	return err
}

func tcpPipe(port ...int) (cli net.Conn, svr net.Conn) {
	addr := ""
	if len(port) > 0 {
		addr = fmt.Sprintf(":%d", port[0])
	}

	listen, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		conn, err := listen.Accept()
		if err != nil {
			return
		}
		// 服务端监听器与连接绑定，以便在关闭连接时关闭监听器
		svr = &svrConn{Conn: conn, l: listen}
	}()
	go func() {
		defer wg.Done()
		conn, err := net.Dial("tcp", listen.Addr().String())
		if err != nil {
			return
		}
		cli = conn
	}()
	wg.Wait()
	return
}
