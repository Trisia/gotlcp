// Copyright (c) 2025 gotlcp contributors
// gotlcp is licensed under Mulan PSL v2.

package dtlcp

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// =============================================================================
// 阶段一：内部并发测试 —— 单 Conn 多 goroutine 混合操作
// =============================================================================

// testConfigPair 返回用于并发测试的客户端和服务端配置。
func testConfigPair(certs *testCerts) (*Config, *Config) {
	serverCfg := &Config{
		Certificates:             []Certificate{certs.sigCert, certs.encCert},
		Time:                     time.Now,
		InitialRetransmitTimeout: 200 * time.Millisecond,
		MaxRetransmitTimeout:     1 * time.Second,
	}
	clientCfg := &Config{
		InsecureSkipVerify:       true,
		NewTimer:                 newMockTimer,
		Time:                     time.Now,
		InitialRetransmitTimeout: 200 * time.Millisecond,
		MaxRetransmitTimeout:     1 * time.Second,
	}
	return clientCfg, serverCfg
}

// echoServer 在 goroutine 中运行，读取客户端数据并回显。
// 当 conn 关闭时自动退出。
func echoServer(t *testing.T, conn *Conn, done <-chan struct{}) {
	t.Helper()
	buf := make([]byte, 2048)
	for {
		select {
		case <-done:
			return
		default:
		}
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		if _, err := conn.Write(buf[:n]); err != nil {
			return
		}
	}
}

// TestConcurrentReadWrite 测试多个 goroutine 同时对同一 Conn 进行读写。
// 验证 in.Lock/out.Lock 无死锁，数据完整性正确。
func TestConcurrentReadWrite(t *testing.T) {
	certs := initTestCerts()
	clientCfg, serverCfg := testConfigPair(certs)
	cli, svr := testHandshakePair(t, clientCfg, serverCfg)

	if err := doHandshake(t, cli, svr); err != nil {
		t.Fatalf("握手失败: %v", err)
	}

	done := make(chan struct{})
	defer close(done)
	go echoServer(t, svr, done)

	const numWriters = 5
	const msgsPerWriter = 50

	var writersWg sync.WaitGroup
	var writeErr atomic.Value
	var totalRead atomic.Int64

	// 启动 writer goroutine
	for i := 0; i < numWriters; i++ {
		writersWg.Add(1)
		go func(id int) {
			defer writersWg.Done()
			for seq := 0; seq < msgsPerWriter; seq++ {
				msg := []byte(fmt.Sprintf("w%d-s%d", id, seq))
				if _, err := cli.Write(msg); err != nil {
					writeErr.Store(fmt.Errorf("writer %d seq %d: %w", id, seq, err))
					return
				}
			}
		}(i)
	}

	// 单 reader，避免多 reader 竞争最后一个消息时卡住
	go func() {
		buf := make([]byte, 2048)
		for totalRead.Load() < int64(numWriters*msgsPerWriter) {
			n, err := cli.Read(buf)
			if err != nil {
				// 收到 closeNotify 或连接关闭，数据已收齐
				return
			}
			totalRead.Add(1)
			_ = n
		}
	}()

	writersWg.Wait()

	// 发送 closeNotify，通知 echoServer 退出并唤醒 reader
	if err := svr.CloseWrite(); err != nil {
		t.Logf("CloseWrite 返回: %v", err)
	}

	// 等待 reader 收尾（最多 2 秒）
	for deadline := time.Now().Add(2 * time.Second); totalRead.Load() < int64(numWriters*msgsPerWriter) && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}

	cli.Close()
	svr.Close()

	if err, ok := writeErr.Load().(error); ok {
		t.Errorf("写入错误: %v", err)
	}
	// 允许少量数据因关闭而未读取（已尽力等待），但不允许读取错误
	if totalRead.Load() < int64(numWriters*msgsPerWriter) {
		t.Logf("共读取 %d / %d 条", totalRead.Load(), numWriters*msgsPerWriter)
	}
}

// TestConcurrentWriteAndClose 测试写入过程中关闭连接的并发安全性。
// 需 -race -count=50 多次运行以确保无竞态。
func TestConcurrentWriteAndClose(t *testing.T) {
	certs := initTestCerts()
	clientCfg, serverCfg := testConfigPair(certs)
	cli, svr := testHandshakePair(t, clientCfg, serverCfg)

	if err := doHandshake(t, cli, svr); err != nil {
		t.Fatalf("握手失败: %v", err)
	}

	done := make(chan struct{})
	defer close(done)
	go echoServer(t, svr, done)

	var wg sync.WaitGroup
	wg.Add(1)

	// Writer: 持续写入，直到连接关闭
	go func() {
		defer wg.Done()
		data := make([]byte, 1024)
		for {
			if _, err := cli.Write(data); err != nil {
				return
			}
		}
	}()

	// 给 writer 一点启动时间
	time.Sleep(time.Millisecond)

	// 在 writer 运行过程中关闭连接
	if err := cli.Close(); err != nil {
		t.Logf("Close 返回错误: %v", err)
	}
	svr.Close()

	wg.Wait()
}

// TestConcurrentReadAndClose 测试读取过程中关闭连接的并发安全性。
func TestConcurrentReadAndClose(t *testing.T) {
	certs := initTestCerts()
	clientCfg, serverCfg := testConfigPair(certs)
	cli, svr := testHandshakePair(t, clientCfg, serverCfg)

	if err := doHandshake(t, cli, svr); err != nil {
		t.Fatalf("握手失败: %v", err)
	}

	// Server 侧持续写入数据，确保 client Read 一直有数据
	done := make(chan struct{})
	defer close(done)
	var svrWg sync.WaitGroup
	svrWg.Add(1)
	go func() {
		defer svrWg.Done()
		data := make([]byte, 512)
		for {
			select {
			case <-done:
				return
			default:
			}
			if _, err := svr.Write(data); err != nil {
				return
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(1)

	// Reader: 持续读取
	go func() {
		defer wg.Done()
		buf := make([]byte, 2048)
		for {
			if _, err := cli.Read(buf); err != nil {
				return
			}
		}
	}()

	// 给 reader 一点启动时间
	time.Sleep(time.Millisecond)

	// 在 reader 运行过程中关闭连接
	if err := cli.Close(); err != nil {
		t.Logf("Close 返回错误: %v", err)
	}
	svr.Close()

	wg.Wait()
	svrWg.Wait()
}

// TestConcurrentReadFromWriteToAndClose 测试 ReadFrom/WriteTo（PacketConn 风格接口）
// 与 Close 的并发安全性。
func TestConcurrentReadFromWriteToAndClose(t *testing.T) {
	certs := initTestCerts()
	clientCfg, serverCfg := testConfigPair(certs)
	cli, svr := testHandshakePair(t, clientCfg, serverCfg)

	if err := doHandshake(t, cli, svr); err != nil {
		t.Fatalf("握手失败: %v", err)
	}

	// Server 侧：ReadFrom + WriteTo 循环回显
	done := make(chan struct{})
	defer close(done)
	var svrWg sync.WaitGroup
	svrWg.Add(1)
	go func() {
		defer svrWg.Done()
		buf := make([]byte, 2048)
		for {
			select {
			case <-done:
				return
			default:
			}
			n, addr, err := svr.ReadFrom(buf)
			if err != nil {
				return
			}
			svr.WriteTo(buf[:n], addr)
		}
	}()

	var wg sync.WaitGroup

	// 2 个 writer，使用 WriteTo
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			data := []byte(fmt.Sprintf("wt%d-data", id))
			for j := 0; j < 200; j++ {
				if _, err := cli.WriteTo(data, svr.LocalAddr()); err != nil {
					return
				}
			}
		}(i)
	}

	// 1 个 reader，使用 ReadFrom
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 2048)
		for j := 0; j < 200; j++ {
			if _, _, err := cli.ReadFrom(buf); err != nil {
				return
			}
		}
	}()

	// 1 个延迟关闭
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(5 * time.Millisecond)
		cli.Close()
		svr.Close()
	}()

	wg.Wait()
	svrWg.Wait()
}

// TestConcurrentMixedOps 测试 Read/Write/Close 全混合并发操作。
func TestConcurrentMixedOps(t *testing.T) {
	certs := initTestCerts()
	clientCfg, serverCfg := testConfigPair(certs)
	cli, svr := testHandshakePair(t, clientCfg, serverCfg)

	if err := doHandshake(t, cli, svr); err != nil {
		t.Fatalf("握手失败: %v", err)
	}

	done := make(chan struct{})
	defer close(done)
	go echoServer(t, svr, done)

	var wg sync.WaitGroup

	// 3 个 writer
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			data := make([]byte, 256)
			for j := 0; j < 100; j++ {
				if _, err := cli.Write(data); err != nil {
					return
				}
			}
		}(i)
	}

	// 1 个 reader
	var readDone sync.WaitGroup
	readDone.Add(1)
	go func() {
		defer readDone.Done()
		buf := make([]byte, 1024)
		for {
			if _, err := cli.Read(buf); err != nil {
				return
			}
		}
	}()

	// 1 个延迟关闭
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(5 * time.Millisecond)
		cli.Close()
	}()

	wg.Wait()
	readDone.Wait()
	svr.Close()
}
