// Copyright (c) 2025 gotlcp contributors
// gotlcp is licensed under Mulan PSL v2.

package dtlcp

import (
	"runtime"
	"sync"
	"testing"
	"time"
)

// =============================================================================
// 阶段二：外部并发测试 —— 多 Conn 并发使用
// =============================================================================

// TestManyConnections 测试大量连接对同时握手和传输。
// 验证库级并发安全，无全局状态竞态，无 goroutine 泄漏。
func TestManyConnections(t *testing.T) {
	certs := initTestCerts()
	clientCfg, serverCfg := testConfigPair(certs)

	const numConns = 50
	numGoroutinesBefore := runtime.NumGoroutine()

	var wg sync.WaitGroup

	for i := 0; i < numConns; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			cli, svr := testHandshakePair(t, clientCfg, serverCfg)

			// 并发握手
			var hsWg sync.WaitGroup
			hsWg.Add(2)
			var cliErr, svrErr error

			go func() {
				defer hsWg.Done()
				cliErr = cli.Handshake()
			}()
			go func() {
				defer hsWg.Done()
				svrErr = svr.Handshake()
			}()
			hsWg.Wait()

			if cliErr != nil || svrErr != nil {
				t.Errorf("conn %d 握手失败: cli=%v, svr=%v", id, cliErr, svrErr)
				cli.Close()
				svr.Close()
				return
			}

			// 传输若干条消息
			buf := make([]byte, 256)
			for j := 0; j < 10; j++ {
				msg := []byte{byte(id), byte(j), 'h', 'e', 'l', 'l', 'o'}
				if _, err := cli.Write(msg); err != nil {
					t.Errorf("conn %d msg %d 写入失败: %v", id, j, err)
					return
				}
				n, err := svr.Read(buf)
				if err != nil || n != len(msg) {
					t.Errorf("conn %d msg %d 读取失败: n=%d, err=%v", id, j, n, err)
					return
				}
			}

			cli.Close()
			svr.Close()
		}(i)
	}

	wg.Wait()

	// 等待 goroutine 清理
	time.Sleep(100 * time.Millisecond)
	numGoroutinesAfter := runtime.NumGoroutine()

	t.Logf("goroutine 数: before=%d, after=%d", numGoroutinesBefore, numGoroutinesAfter)
	if numGoroutinesAfter > numGoroutinesBefore+10 {
		t.Errorf("可能存在 goroutine 泄漏: before=%d, after=%d", numGoroutinesBefore, numGoroutinesAfter)
	}
}

// TestSingleServerMultiClient 测试单个服务端同时处理多个客户端连接。
func TestSingleServerMultiClient(t *testing.T) {
	certs := initTestCerts()
	_, serverCfg := testConfigPair(certs)
	clientCfg := &Config{
		InsecureSkipVerify:       true,
		NewTimer:                 newMockTimer,
		Time:                     time.Now,
		InitialRetransmitTimeout: 200 * time.Millisecond,
		MaxRetransmitTimeout:     1 * time.Second,
	}

	const numClients = 20

	numGoroutinesBefore := runtime.NumGoroutine()

	var wg sync.WaitGroup

	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// 每个客户端有独立的 mockPacketConn 对
			clientPConn, serverPConn := newMockPacketConn()

			cli := Client(clientPConn, serverPConn.LocalAddr(), clientCfg)
			svr := Server(serverPConn, clientPConn.LocalAddr(), serverCfg)

			// 并发握手
			var hsWg sync.WaitGroup
			hsWg.Add(2)
			var cliErr, svrErr error

			go func() {
				defer hsWg.Done()
				cliErr = cli.Handshake()
			}()
			go func() {
				defer hsWg.Done()
				svrErr = svr.Handshake()
			}()
			hsWg.Wait()

			if cliErr != nil || svrErr != nil {
				t.Errorf("client %d 握手失败: cli=%v, svr=%v", id, cliErr, svrErr)
				return
			}

			// 双向通信
			msg := []byte{byte(id), 'd', 'a', 't', 'a'}
			if _, err := cli.Write(msg); err != nil {
				t.Errorf("client %d write: %v", id, err)
				return
			}
			buf := make([]byte, 1024)
			n, err := svr.Read(buf)
			if err != nil || n != len(msg) {
				t.Errorf("client %d server read: n=%d err=%v", id, n, err)
				return
			}

			// 服务端回显
			if _, err := svr.Write(buf[:n]); err != nil {
				t.Errorf("client %d server write: %v", id, err)
				return
			}
			n2, err2 := cli.Read(buf)
			if err2 != nil || n2 != n {
				t.Errorf("client %d client read: n=%d err=%v", id, n2, err2)
				return
			}

			cli.Close()
			svr.Close()
		}(i)
	}

	wg.Wait()

	time.Sleep(100 * time.Millisecond)
	numGoroutinesAfter := runtime.NumGoroutine()

	t.Logf("goroutine 数: before=%d, after=%d", numGoroutinesBefore, numGoroutinesAfter)
	if numGoroutinesAfter > numGoroutinesBefore+10 {
		t.Errorf("可能存在 goroutine 泄漏: before=%d, after=%d", numGoroutinesBefore, numGoroutinesAfter)
	}
}

// TestDialListenConcurrency 测试基于真实 UDP 的并发 Dial/Listen。
// 验证 NewListener 和 Dial 在并发调用下无竞态。
func TestDialListenConcurrency(t *testing.T) {
	certs := initTestCerts()

	serverCfg := &Config{
		Certificates:             []Certificate{certs.sigCert, certs.encCert},
		InitialRetransmitTimeout: 500 * time.Millisecond,
		MaxRetransmitTimeout:     2 * time.Second,
	}
	clientCfg := &Config{
		InsecureSkipVerify:       true,
		InitialRetransmitTimeout: 500 * time.Millisecond,
		MaxRetransmitTimeout:     2 * time.Second,
	}

	// 使用真实 UDP 监听
	ln, err := Listen("udp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Skipf("无法监听 UDP: %v", err)
		return
	}
	defer ln.Close()

	addr := ln.Addr().String()
	t.Logf("监听地址: %s", addr)

	const numClients = 10

	var wg sync.WaitGroup

	// 服务端接受 goroutine
	var serverErrs sync.Map
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < numClients; i++ {
			conn, err := ln.Accept()
			if err != nil {
				msg := err.Error()
				serverErrs.Store(i, &msg)
				return
			}
			go func(c *Conn, id int) {
				buf := make([]byte, 128)
				c.Read(buf)
				c.Write([]byte("ack"))
				c.Close()
			}(conn.(*Conn), i)
		}
	}()

	// 客户端并发 Dial
	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			conn, err := Dial("udp", addr, clientCfg)
			if err != nil {
				t.Errorf("client %d dial 失败: %v", id, err)
				return
			}
			defer conn.Close()

			conn.Write([]byte("ping"))
			buf := make([]byte, 128)
			n, err := conn.Read(buf)
			if err != nil || n == 0 {
				t.Errorf("client %d read 失败: n=%d, err=%v", id, n, err)
			}
		}(i)
	}

	wg.Wait()

	serverErrs.Range(func(key, value interface{}) bool {
		t.Errorf("server accept 错误: %v", *value.(*string))
		return true
	})
}
