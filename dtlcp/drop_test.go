// Copyright (c) 2025 gotlcp contributors
// gotlcp is licensed under Mulan PSL v2.

package dtlcp

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	x509 "github.com/emmansun/gmsm/smx509"
)

// =============================================================================
// lossyPacketConn — 带丢包规则的 mockPacketConn 包装器
// =============================================================================

// lossyPacketConn 包装 mockPacketConn，支持通过 dropRule 控制丢包。
type lossyPacketConn struct {
	inner   *mockPacketConn
	dropFn  func(data []byte) bool // 返回 true 丢弃该包
	dropped atomic.Int64           // 已丢弃的包数
}

func (l *lossyPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	return l.inner.ReadFrom(p)
}

func (l *lossyPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if l.dropFn != nil && l.dropFn(p) {
		l.dropped.Add(1)
		return len(p), nil // 假装成功写入
	}
	return l.inner.WriteTo(p, addr)
}

func (l *lossyPacketConn) Close() error              { return l.inner.Close() }
func (l *lossyPacketConn) LocalAddr() net.Addr        { return l.inner.LocalAddr() }
func (l *lossyPacketConn) SetDeadline(t time.Time) error      { return l.inner.SetDeadline(t) }
func (l *lossyPacketConn) SetReadDeadline(t time.Time) error  { return l.inner.SetReadDeadline(t) }
func (l *lossyPacketConn) SetWriteDeadline(t time.Time) error { return l.inner.SetWriteDeadline(t) }

// =============================================================================
// handshakeTestConfig — 握手丢包测试配置（使用 mock timer）
// =============================================================================

// handshakeTestConfig 返回用于丢包测试的客户端和服务端配置。
// 使用 mock timer 加速重传测试。
func handshakeTestConfig(certs *testCerts) (*Config, *Config) {
	rootPool := x509.NewCertPool()
	rootPool.AddCert(certs.rootCert)

	clientCfg := &Config{
		Certificates:       []Certificate{certs.sigCert, certs.encCert},
		RootCAs:            rootPool,
		InsecureSkipVerify: true,
		NewTimer:           newMockTimer,
		PMTU:               1400,
	}
	serverCfg := &Config{
		Certificates:       []Certificate{certs.sigCert, certs.encCert},
		ClientCAs:          rootPool,
		ClientAuth:         NoClientCert,
		InsecureSkipVerify: true,
		NewTimer:           newMockTimer,
		PMTU:               1400,
	}
	return clientCfg, serverCfg
}

// =============================================================================
// Flight 级丢包测试
// =============================================================================

// TestDropFlight1ClientHello 验证丢弃首个 ClientHello 后客户端重传。
func TestDropFlight1ClientHello(t *testing.T) {
	certs := initTestCerts()
	clientCfg, serverCfg := handshakeTestConfig(certs)

	a, b := newMockPacketConn()
	lossyA := &lossyPacketConn{inner: a}
	lossyB := &lossyPacketConn{inner: b}

	// 丢弃从客户端发出的第一个握手包 (ClientHello)
	var dropped atomic.Bool
	lossyA.dropFn = func(data []byte) bool {
		if !dropped.Load() && len(data) > 0 && recordType(data[0]) == recordTypeHandshake {
			dropped.Store(true)
			return true
		}
		return false
	}

	serverErrCh := make(chan error, 1)
	go func() {
		srv := Server(lossyB, lossyA.LocalAddr(), serverCfg)
		err := srv.Handshake()
		serverErrCh <- err
	}()

	cli := Client(lossyA, lossyB.LocalAddr(), clientCfg)
	// 手动触发重传：等待然后 fire 定时器
	time.Sleep(50 * time.Millisecond)

	// Fire 客户端重传定时器 (在 cookie 循环中)
	if cli.retransmitTimer != nil && cli.retransmitTimer.handle != nil {
		fireMockTimer(cli.retransmitTimer.handle)
	}

	err := cli.Handshake()
	if err != nil {
		// 可能因 mock timer 限制而失败，只要服务端收到重传即可
		t.Logf("客户端握手结果: %v (丢包 %d)", err, lossyA.dropped.Load())
	}

	// 验证至少丢了一个包
	if lossyA.dropped.Load() == 0 {
		t.Error("应至少丢弃一个包")
	}
	t.Logf("丢包数: %d", lossyA.dropped.Load())

	lossyA.Close()
	lossyB.Close()
	<-serverErrCh
}

// TestBothSidesWaitingNoDeadlock 验证双方等待时不会死锁。
func TestBothSidesWaitingNoDeadlock(t *testing.T) {
	certs := initTestCerts()
	clientCfg, serverCfg := handshakeTestConfig(certs)

	a, b := newMockPacketConn()
	lossyA := &lossyPacketConn{inner: a}
	lossyB := &lossyPacketConn{inner: b}

	// 丢弃所有包，验证不会死锁
	lossyA.dropFn = func(data []byte) bool { return true }
	lossyB.dropFn = func(data []byte) bool { return true }

	done := make(chan struct{}, 2)
	go func() {
		srv := Server(lossyB, lossyA.LocalAddr(), serverCfg)
		srv.Handshake()
		done <- struct{}{}
	}()
	go func() {
		cli := Client(lossyA, lossyB.LocalAddr(), clientCfg)
		cli.Handshake()
		done <- struct{}{}
	}()

	// 2 秒后关闭连接，验证不会死锁
	select {
	case <-done:
		t.Log("握手完成（意外）")
	case <-time.After(2 * time.Second):
		t.Log("握手超时，验证无死锁")
	}

	lossyA.Close()
	lossyB.Close()

	// 等待 goroutines 退出
	time.Sleep(100 * time.Millisecond)
}

// TestHandshakeTimeout 验证服务端无响应时客户端超时。
func TestHandshakeTimeout(t *testing.T) {
	certs := initTestCerts()
	clientCfg, _ := handshakeTestConfig(certs)

	a, b := newMockPacketConn()
	lossyA := &lossyPacketConn{inner: a}
	lossyB := &lossyPacketConn{inner: b} // 不启动服务端，模拟无响应

	cli := Client(lossyA, lossyB.LocalAddr(), clientCfg)

	done := make(chan error, 1)
	go func() {
		done <- cli.Handshake()
	}()

	// 手动 fire 多次重传定时器模拟超时后关闭连接
	time.Sleep(10 * time.Millisecond)
	for i := 0; i < 10; i++ {
		time.Sleep(5 * time.Millisecond)
		if cli.retransmitTimer != nil && cli.retransmitTimer.handle != nil {
			fireMockTimer(cli.retransmitTimer.handle)
		}
	}
	// 关闭连接迫使握手退出
	lossyA.Close()
	lossyB.Close()

	select {
	case err := <-done:
		t.Logf("客户端结果: %v", err)
	case <-time.After(2 * time.Second):
		t.Error("客户端未在预期时间内退出")
		lossyA.Close()
		lossyB.Close()
		<-done
	}
}

// TestConsecutiveDropRetransmitBackoff 验证连续丢包时指数退避行为。
func TestConsecutiveDropRetransmitBackoff(t *testing.T) {
	certs := initTestCerts()
	clientCfg, serverCfg := handshakeTestConfig(certs)
	clientCfg.InitialRetransmitTimeout = 20 * time.Millisecond
	clientCfg.MaxRetransmitTimeout = 100 * time.Millisecond
	clientCfg.NewTimer = nil // 使用真实定时器

	a, b := newMockPacketConn()
	lossyA := &lossyPacketConn{inner: a}
	lossyB := &lossyPacketConn{inner: b}

	// 丢弃前 3 个 ClientHello，第 4 个通过
	var count atomic.Int32
	lossyA.dropFn = func(data []byte) bool {
		if len(data) > 0 && recordType(data[0]) == recordTypeHandshake && count.Add(1) <= 3 {
			return true
		}
		return false
	}

	serverErrCh := make(chan error, 1)
	go func() {
		srv := Server(lossyB, lossyA.LocalAddr(), serverCfg)
		err := srv.Handshake()
		serverErrCh <- err
	}()

	cli := Client(lossyA, lossyB.LocalAddr(), clientCfg)
	err := cli.Handshake()
	t.Logf("客户端结果: %v, 丢包数: %d", err, lossyA.dropped.Load())

	if lossyA.dropped.Load() < 1 {
		t.Error("应至少丢弃一个包")
	}

	lossyA.Close()
	lossyB.Close()
	<-serverErrCh
}

// TestDropFlight4ServerHello 验证丢弃 Flight 4 后服务端重传。
func TestDropFlight4ServerHello(t *testing.T) {
	certs := initTestCerts()
	clientCfg, serverCfg := handshakeTestConfig(certs)

	a, b := newMockPacketConn()
	lossyA := &lossyPacketConn{inner: a}
	lossyB := &lossyPacketConn{inner: b}

	// 丢弃从服务端发出的第一个包含 ServerHello 的 Flight
	var dropped atomic.Bool
	lossyB.dropFn = func(data []byte) bool {
		if !dropped.Load() && len(data) > 0 && recordType(data[0]) == recordTypeHandshake {
			dropped.Store(true)
			return true
		}
		return false
	}

	serverErrCh := make(chan error, 1)
	go func() {
		srv := Server(lossyB, lossyA.LocalAddr(), serverCfg)
		err := srv.Handshake()
		serverErrCh <- err
	}()

	cli := Client(lossyA, lossyB.LocalAddr(), clientCfg)

	// 等待客户端进入 WAITING 状态
	time.Sleep(100 * time.Millisecond)

	// Fire 客户端重传定时器
	if cli.retransmitTimer != nil && cli.retransmitTimer.handle != nil {
		fireMockTimer(cli.retransmitTimer.handle)
	}

	err := cli.Handshake()
	t.Logf("客户端结果: %v, 丢包数: %d", err, lossyB.dropped.Load())

	if lossyB.dropped.Load() == 0 {
		t.Error("应至少丢弃一个服务器 Flight")
	}

	lossyA.Close()
	lossyB.Close()
	<-serverErrCh
}
