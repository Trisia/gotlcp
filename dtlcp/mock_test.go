// Copyright (c) 2025 gotlcp contributors
// gotlcp is licensed under Mulan PSL v2.

package dtlcp

import (
	"bytes"
	"crypto/rand"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/emmansun/gmsm/sm2"
	x509 "github.com/emmansun/gmsm/smx509"
)

// =============================================================================
// mockPacketConn — 基于内存的 net.PacketConn 实现，用于测试
// =============================================================================

// mockDatagram 表示一个数据报（数据 + 地址）
type mockDatagram struct {
	data []byte
	addr net.Addr
}

// timeoutError 模拟网络超时错误
type timeoutError struct{}

func (e *timeoutError) Error() string   { return "mock: i/o timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

// mockPacketConn 实现 net.PacketConn，用于内存测试。
// 两个 mockPacketConn 交叉连接后，一方写入的数据会出现在另一方的读取队列中。
type mockPacketConn struct {
	mu         sync.Mutex
	readCh     chan mockDatagram
	writeCh    chan mockDatagram
	closeCh    chan struct{} // 关闭时关闭此 channel，解阻塞 ReadFrom
	localAddr  net.Addr
	closed     bool
	readDeadline  time.Time
	writeDeadline time.Time
}

// newMockPacketConn 创建一对交叉连接的 mockPacketConn。
// a 的写入会出现在 b 的读取中，b 的写入会出现在 a 的读取中。
func newMockPacketConn() (a, b *mockPacketConn) {
	// 使用带缓冲的通道，避免读写双方严格同步
	aCh := make(chan mockDatagram, 500)
	bCh := make(chan mockDatagram, 500)

	a = &mockPacketConn{
		readCh:    aCh,
		writeCh:   bCh,
		closeCh:   make(chan struct{}),
		localAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10000},
	}
	b = &mockPacketConn{
		readCh:    bCh,
		writeCh:   aCh,
		closeCh:   make(chan struct{}),
		localAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 20000},
	}
	return a, b
}

// ReadFrom 从连接中读取一个数据报。
// 如果设置了读取截止时间，超过截止时间未读到数据则返回超时错误。
func (m *mockPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return 0, nil, errors.New("mock: use of closed network connection")
	}
	deadline := m.readDeadline
	m.mu.Unlock()

	// 检查截止时间是否已过
	if !deadline.IsZero() {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0, nil, &timeoutError{}
		}

		// 使用 select 等待数据或超时或关闭
		select {
		case d := <-m.readCh:
			n = copy(p, d.data)
			return n, d.addr, nil
		case <-time.After(remaining):
			return 0, nil, &timeoutError{}
		case <-m.closeCh:
			return 0, nil, errors.New("mock: use of closed network connection")
		}
	}

	// 无截止时间，阻塞等待，支持通过 closeCh 解阻塞
	select {
	case d := <-m.readCh:
		n = copy(p, d.data)
		return n, d.addr, nil
	case <-m.closeCh:
		return 0, nil, errors.New("mock: use of closed network connection")
	}
}

// WriteTo 向连接写入一个数据报。
// 注意：返回的地址应该是发送方的本地地址，而非参数 addr。
// 这样模拟真实 UDP 语义：ReadFrom 返回数据报的来源地址。
func (m *mockPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return 0, errors.New("mock: use of closed network connection")
	}
	// 将数据复制一份，避免外部修改
	data := make([]byte, len(p))
	copy(data, p)
	// 使用发送方的本地地址作为来源地址
	srcAddr := m.localAddr
	m.mu.Unlock()

	select {
	case m.writeCh <- mockDatagram{data: data, addr: srcAddr}:
		return len(p), nil
	default:
		return 0, errors.New("mock: write buffer full")
	}
}

// Close 关闭连接，解阻塞正在 ReadFrom 上等待的调用。
func (m *mockPacketConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	close(m.closeCh)
	return nil
}

// LocalAddr 返回本地地址。
func (m *mockPacketConn) LocalAddr() net.Addr {
	return m.localAddr
}

// SetDeadline 设置读取和写入截止时间。
func (m *mockPacketConn) SetDeadline(t time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.readDeadline = t
	m.writeDeadline = t
	return nil
}

// SetReadDeadline 设置读取截止时间。
func (m *mockPacketConn) SetReadDeadline(t time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.readDeadline = t
	return nil
}

// SetWriteDeadline 设置写入截止时间。
func (m *mockPacketConn) SetWriteDeadline(t time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writeDeadline = t
	return nil
}

// =============================================================================
// mockTimer — 手动控制的定时器，用于测试重传逻辑
// =============================================================================

// mockTimerRegistry 保存所有 mock 定时器的可写 channel 端。
// 由于 TimerHandle.C 是只读 channel，需要通过注册表实现手动触发。
var (
	mockTimerMu       sync.Mutex
	mockTimerRegistry = make(map[*TimerHandle]chan<- time.Time)
)

// newMockTimer 返回一个手动控制的 TimerHandle。
// 创建的定时器不会自动触发，需要通过 fireMockTimer 手动触发。
func newMockTimer(d time.Duration) *TimerHandle {
	ch := make(chan time.Time, 1)
	th := &TimerHandle{
		C: ch,
		Stop: func() bool {
			select {
			case <-ch:
				return true
			default:
				return true
			}
		},
		Reset: func(d time.Duration) bool {
			// 清空 channel
			select {
			case <-ch:
			default:
			}
			return true
		},
	}
	mockTimerMu.Lock()
	mockTimerRegistry[th] = ch
	mockTimerMu.Unlock()
	return th
}

// fireMockTimer 手动触发 mock 定时器（向 channel 发送当前时间）。
func fireMockTimer(t *TimerHandle) {
	mockTimerMu.Lock()
	ch, ok := mockTimerRegistry[t]
	mockTimerMu.Unlock()
	if !ok {
		return
	}
	select {
	case ch <- time.Now():
	default:
	}
}

// =============================================================================
// 测试用共享数据
// =============================================================================

var mockFF32 = []byte{
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
}

var mockOne32 = []byte{
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
}

// =============================================================================
// 测试用证书
// =============================================================================

// testCerts 持有测试所需的所有证书和密钥。
type testCerts struct {
	rootCert *x509.Certificate  // 根 CA 证书
	rootKey  *sm2.PrivateKey   // 根 CA 私钥

	sigCert Certificate  // 签名证书（服务器）
	encCert Certificate  // 加密证书（服务器）
}

var (
	globalTestCerts *testCerts
	onceCerts       sync.Once
)

// initTestCerts 初始化测试证书（只执行一次）。
// 返回包含根CA、签名证书和加密证书的结构体，所有证书使用 SM2 算法。
func initTestCerts() *testCerts {
	onceCerts.Do(func() {
		globalTestCerts = newTestCerts()
	})
	return globalTestCerts
}

func newTestCerts() *testCerts {
	// 1. 生成根 CA 密钥
	rootKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	// 2. 创建根 CA 证书模板
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Country: []string{"CN"}, Organization: []string{"Test CA"}, CommonName: "TEST_ROOT_CA"},
		NotBefore:             time.Now().AddDate(0, -1, 0),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		panic(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		panic(err)
	}

	// 3. 生成签名证书密钥对
	sigKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	sigTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{Country: []string{"CN"}, Organization: []string{"Test Server"}, CommonName: "TEST_SIG_CERT"},
		NotBefore:    time.Now().AddDate(0, -1, 0),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	sigDER, err := x509.CreateCertificate(rand.Reader, sigTemplate, rootCert, &sigKey.PublicKey, rootKey)
	if err != nil {
		panic(err)
	}

	// 4. 生成加密证书密钥对
	encKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	encTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{Country: []string{"CN"}, Organization: []string{"Test Server"}, CommonName: "TEST_ENC_CERT"},
		NotBefore:    time.Now().AddDate(0, -1, 0),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	encDER, err := x509.CreateCertificate(rand.Reader, encTemplate, rootCert, &encKey.PublicKey, rootKey)
	if err != nil {
		panic(err)
	}

	sigCert := Certificate{
		Certificate: [][]byte{sigDER},
		PrivateKey:  sigKey,
	}
	encCert := Certificate{
		Certificate: [][]byte{encDER},
		PrivateKey:  encKey,
	}

	// 设置 Leaf 字段以减少握手证书解析时间
	sigCert.Leaf, _ = x509.ParseCertificate(sigDER)
	encCert.Leaf, _ = x509.ParseCertificate(encDER)

	return &testCerts{
		rootCert: rootCert,
		rootKey:  rootKey,
		sigCert:  sigCert,
		encCert:  encCert,
	}
}

// =============================================================================
// 测试辅助函数
// =============================================================================

// bytesEqual 判断两个字节切片是否相等。
func bytesEqual(a, b []byte) bool {
	return bytes.Equal(a, b)
}
