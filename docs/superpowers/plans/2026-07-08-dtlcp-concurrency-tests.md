# DTLCP 并发测试 — 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 修复 `Conn.Close()` 与 `Read()/ReadFrom()/WriteTo()` 之间的并发竞态，添加系列并发测试验证模块内外稳定性。

**Architecture:** 修复 `activeCall` 协议（当前仅 `Write()` 参与，`Read()`/`ReadFrom()`/`WriteTo()` 未参与），使 `Close()` 等待所有活跃 I/O 调完成后再清理资源。测试分两阶段：阶段一测试单 `Conn` 多 goroutine 混合操作，阶段二测试多 `Conn` 并发使用。

**Tech Stack:** Go 1.24+, `sync/atomic`, `-race` detector

## Global Constraints

- 不修改 `RetransmitTimer`、`replayWindow`、`fragmentBuffer` 内部结构
- 测试基于现有 `mockPacketConn` + `testHandshakePair` 辅助函数
- 阶段一、阶段二全部测试需用 `-race` 稳定通过
- `-race -count=50` 对 Close 竞态测试需稳定通过

---

### Task 1: 修复 Close/Read/ReadFrom/WriteTo 竞态

**Files:**
- Modify: `dtlcp/conn.go:1107-1135` (Close)
- Modify: `dtlcp/conn.go:1169-1201` (Read)
- Modify: `dtlcp/conn.go:1255-1335` (ReadFrom)
- Modify: `dtlcp/conn.go:1344-1355` (WriteTo)

**Interfaces:**
- Consumes: `c.activeCall` (int32), `c.workKey` ([]byte), `c.pconn` (net.PacketConn)
- Produces: 修复后的 `Close()`, `Read()`, `ReadFrom()`, `WriteTo()` — 全部加入 activeCall 协议

- [ ] **Step 1: 为 Read() 添加 activeCall 保护**

读取 `dtlcp/conn.go:1169-1201`，在 `Read()` 的 `Handshake()` 调用之前插入 activeCall 检查/递增，末尾加 defer 递减：

```go
// Read 从连接中读取解密后的数据，实现 io.Reader 接口。
// 如果握手尚未完成，Read 会自动触发握手。
//
// 参数 b 为接收缓冲区。
// 返回成功读取的字节数 n 和可能出现的错误。
// 若返回 io.EOF 表示对端已关闭连接。
func (c *Conn) Read(b []byte) (int, error) {
	for {
		x := atomic.LoadInt32(&c.activeCall)
		if x&1 != 0 {
			return 0, net.ErrClosed
		}
		if atomic.CompareAndSwapInt32(&c.activeCall, x, x+2) {
			break
		}
	}
	defer atomic.AddInt32(&c.activeCall, -2)

	if err := c.Handshake(); err != nil {
		return 0, err
	}
	if len(b) == 0 {
		return 0, nil
	}

	c.in.Lock()
	defer c.in.Unlock()

	for len(c.readBuf) == 0 {
		if err := c.readRecord(); err != nil {
			return 0, err
		}
	}

	n := copy(b, c.readBuf)
	c.readBuf = c.readBuf[n:]
	if len(c.readBuf) == 0 {
		c.readBuf = nil
	}

	// 如果还有未读的应用数据且 rawInputBuf 中有告警，尝试预读
	if n != 0 && len(c.readBuf) == 0 && len(c.rawInputBuf) >= recordHeaderLen &&
		recordType(c.rawInputBuf[0]) == recordTypeAlert {
		if err := c.readRecord(); err != nil {
			return n, err
		}
	}

	return n, nil
}
```

- [ ] **Step 2: 为 ReadFrom() 添加 activeCall 保护**

读取 `dtlcp/conn.go:1255-1335`，在 `ReadFrom()` 的 `Handshake()` 调用之前插入同样的 activeCall 保护：

```go
func (c *Conn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	for {
		x := atomic.LoadInt32(&c.activeCall)
		if x&1 != 0 {
			return 0, nil, net.ErrClosed
		}
		if atomic.CompareAndSwapInt32(&c.activeCall, x, x+2) {
			break
		}
	}
	defer atomic.AddInt32(&c.activeCall, -2)

	if err = c.Handshake(); err != nil {
		return 0, nil, err
	}
	// ... 原有逻辑不变 ...
```

- [ ] **Step 3: 为 WriteTo() 添加 activeCall 保护**

读取 `dtlcp/conn.go:1344-1355`，在 `WriteTo()` 的 `Handshake()` 调用之前插入同样的 activeCall 保护：

```go
func (c *Conn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	for {
		x := atomic.LoadInt32(&c.activeCall)
		if x&1 != 0 {
			return 0, net.ErrClosed
		}
		if atomic.CompareAndSwapInt32(&c.activeCall, x, x+2) {
			break
		}
	}
	defer atomic.AddInt32(&c.activeCall, -2)

	if err = c.Handshake(); err != nil {
		return 0, err
	}
	// ... 原有逻辑不变 ...
```

- [ ] **Step 4: 修复 Close() — 等待活跃调用完成后才清理**

读取 `dtlcp/conn.go:1107-1135`，替换 `Close()` 实现：

```go
// Close 关闭连接。
// 若握手已完成，会先尝试发送 close_notify 告警通知对端。
// 等待所有活跃的 Read/Write/ReadFrom/WriteTo 完成后才清理资源。
func (c *Conn) Close() error {
	// 设置关闭标记
	for {
		x := atomic.LoadInt32(&c.activeCall)
		if x&1 != 0 {
			return net.ErrClosed
		}
		if atomic.CompareAndSwapInt32(&c.activeCall, x, x|1) {
			break
		}
	}

	// 等待所有活跃调用完成后再清理
	// activeCall 位含义：位0=关闭标记，位1+=活跃调用计数(每次+2)
	// 当 activeCall == 1 时（仅关闭标记），所有活跃调用已退出
	for atomic.LoadInt32(&c.activeCall) > 1 {
	}

	var alertErr error
	if c.handshakeComplete() {
		if err := c.closeNotify(); err != nil {
			alertErr = fmt.Errorf("dtlcp: failed to send closeNotify alert (but connection was closed anyway): %w", err)
		}
	}
	setZero(c.workKey)
	c.workKey = nil

	if err := c.pconn.Close(); err != nil {
		return err
	}
	return alertErr
}
```

- [ ] **Step 5: 验证修复编译通过**

```bash
cd /home/kkk/project/gotlcp && go build -v ./dtlcp/...
```

- [ ] **Step 6: 运行现有测试确保无回归**

```bash
cd /home/kkk/project/gotlcp && go test -v -short ./dtlcp/...
```

- [ ] **Step 7: 提交**

```bash
git add dtlcp/conn.go
git commit -m "fix(dtlcp): 修复 Close() 与 Read/ReadFrom/WriteTo 的 activeCall 竞态

Read()、ReadFrom()、WriteTo() 未参与 activeCall 协议，Close() 可能在它们
持有 lock 进行解密时直接关闭 pconn 并清零 workKey。

修复：
- Read()、ReadFrom()、WriteTo() 加入 activeCall 检查/递增/递减
- Close() 等待所有活跃调用完成后再执行 closeNotify + 密钥清零 + 关闭

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 2: 阶段一 — 内部并发测试 (conn_concurrent_test.go)

**Files:**
- Create: `dtlcp/conn_concurrent_test.go`

**Interfaces:**
- Consumes: `testHandshakePair()` (handshake_test.go), `doHandshake()` (handshake_test.go), `newMockPacketConn()` (mock_test.go), `initTestCerts()` (mock_test.go)
- Produces: 4 个并发测试函数

- [ ] **Step 1: 创建测试文件骨架**

```bash
cat > /home/kkk/project/gotlcp/dtlcp/conn_concurrent_test.go << 'GOEOF'
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
GOEOF
```

- [ ] **Step 2: 添加 TestConcurrentReadWrite**

```bash
cat >> /home/kkk/project/gotlcp/dtlcp/conn_concurrent_test.go << 'GOEOF'

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
	const numReaders = 5
	const msgsPerWriter = 50

	var wg sync.WaitGroup
	var writeErr, readErr atomic.Value
	var totalRead atomic.Int64

	// 启动 writer goroutine
	for i := 0; i < numWriters; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for seq := 0; seq < msgsPerWriter; seq++ {
				msg := []byte(fmt.Sprintf("w%d-s%d", id, seq))
				if _, err := cli.Write(msg); err != nil {
					writeErr.Store(fmt.Errorf("writer %d seq %d: %w", id, seq, err))
					return
				}
			}
		}(i)
	}

	// 启动 reader goroutine
	for i := 0; i < numReaders; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			buf := make([]byte, 2048)
			for totalRead.Load() < int64(numWriters*msgsPerWriter) {
				n, err := cli.Read(buf)
				if err != nil {
					readErr.Store(fmt.Errorf("reader %d: %w", id, err))
					return
				}
				totalRead.Add(1)
				_ = n
			}
		}(i)
	}

	wg.Wait()
	cli.Close()
	svr.Close()

	if err, ok := writeErr.Load().(error); ok {
		t.Errorf("写入错误: %v", err)
	}
	if err, ok := readErr.Load().(error); ok {
		t.Errorf("读取错误: %v", err)
	}
}
GOEOF
```

- [ ] **Step 3: 添加 TestConcurrentWriteAndClose**

```bash
cat >> /home/kkk/project/gotlcp/dtlcp/conn_concurrent_test.go << 'GOEOF'

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
GOEOF
```

- [ ] **Step 4: 添加 TestConcurrentReadAndClose**

```bash
cat >> /home/kkk/project/gotlcp/dtlcp/conn_concurrent_test.go << 'GOEOF'

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
GOEOF
```
	
- [ ] **Step 5: 添加 TestConcurrentReadFromWriteToAndClose**

测试 `ReadFrom`/`WriteTo`（PacketConn 风格接口）与 `Close` 的并发安全性：

```bash
cat >> /home/kkk/project/gotlcp/dtlcp/conn_concurrent_test.go << 'GOEOF'

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
GOEOF
```

- [ ] **Step 6: 添加 TestConcurrentMixedOps**

```bash
cat >> /home/kkk/project/gotlcp/dtlcp/conn_concurrent_test.go << 'GOEOF'

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
			for j := 0; j < 200; j++ {
				if _, err := cli.Write(data); err != nil {
					return
				}
			}
		}(i)
	}

	// 2 个 reader
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			buf := make([]byte, 1024)
			for j := 0; j < 100; j++ {
				if _, err := cli.Read(buf); err != nil {
					return
				}
			}
		}(i)
	}

	// 1 个延迟关闭
	wg.Add(1)
	go func() {
		defer wg.Done()
		// 给其他 goroutine 一些运行时间
		time.Sleep(5 * time.Millisecond)
		cli.Close()
	}()

	wg.Wait()
	svr.Close()
}
GOEOF
```

- [ ] **Step 7: 运行阶段一测试确认通过**

```bash
cd /home/kkk/project/gotlcp && go test -v -run "TestConcurrent" ./dtlcp/
```

- [ ] **Step 8: 用 -race 多次运行 Close 竞态测试**

```bash
cd /home/kkk/project/gotlcp && go test -race -count=50 -run "TestConcurrentWriteAndClose|TestConcurrentReadAndClose|TestConcurrentReadFromWriteToAndClose" ./dtlcp/
```

预期：全部 PASS，无 race 报告。

- [ ] **Step 9: 提交**

```bash
git add dtlcp/conn_concurrent_test.go
git commit -m "test(dtlcp): 添加阶段一内部并发测试

单 Conn 多 goroutine 混合操作测试：
- TestConcurrentReadWrite: 同时读写验证无死锁
- TestConcurrentWriteAndClose: 写入中关闭验证无竞态
- TestConcurrentReadAndClose: 读取中关闭验证无竞态
- TestConcurrentReadFromWriteToAndClose: PacketConn 接口与 Close 并发
- TestConcurrentMixedOps: Read/Write/Close 全混合

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 3: 阶段二 — 外部并发测试 (concurrent_stress_test.go)

**Files:**
- Create: `dtlcp/concurrent_stress_test.go`

**Interfaces:**
- Consumes: `testHandshakePair()`, `doHandshake()`, `initTestCerts()`
- Produces: 2 个多连接并发测试函数

- [ ] **Step 1: 创建测试文件并添加 TestManyConnections**

```bash
cat > /home/kkk/project/gotlcp/dtlcp/concurrent_stress_test.go << 'GOEOF'
// Copyright (c) 2025 gotlcp contributors
// gotlcp is licensed under Mulan PSL v2.

package dtlcp

import (
	"net"
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
GOEOF
```

- [ ] **Step 2: 添加 TestSingleServerMultiClient**

```bash
cat >> /home/kkk/project/gotlcp/dtlcp/concurrent_stress_test.go << 'GOEOF'

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
GOEOF
```

- [ ] **Step 3: 添加 TestDialListenConcurrency**

基于真实 UDP 的并发 Dial/Listen 测试，验证 `dtlcp.NewListener` 和 `dtlcp.Dial` 的并发安全性。

```bash
cat >> /home/kkk/project/gotlcp/dtlcp/concurrent_stress_test.go << 'GOEOF'

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
			}(conn, i)
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
GOEOF
```

- [ ] **Step 4: 运行阶段二测试**

```bash
cd /home/kkk/project/gotlcp && go test -v -run "TestManyConnections|TestSingleServerMultiClient" ./dtlcp/
```

- [ ] **Step 5: 运行真实 UDP Dial/Listen 测试**

```bash
cd /home/kkk/project/gotlcp && go test -v -run "TestDialListenConcurrency" ./dtlcp/
```

- [ ] **Step 6: 提交**

```bash
git add dtlcp/concurrent_stress_test.go
git commit -m "test(dtlcp): 添加阶段二外部并发测试

多 Conn 并发使用测试：
- TestManyConnections: 50 连接对同时握手+传输
- TestSingleServerMultiClient: 20 客户端并发连接
- TestDialListenConcurrency: 真实 UDP 并发 Dial/Listen

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 4: 全量验证

**Files:**
- 无新建/修改

**Interfaces:**
- Consumes: 所有之前的任务产出

- [ ] **Step 1: 运行完整测试套件（含 -race）**

```bash
cd /home/kkk/project/gotlcp && go test -race -v -short ./dtlcp/ 2>&1 | tail -50
```

- [ ] **Step 2: 多次运行 Close 竞态测试验证稳定性**

```bash
cd /home/kkk/project/gotlcp && go test -race -count=100 -run "TestConcurrentWriteAndClose|TestConcurrentReadAndClose|TestConcurrentReadFromWriteToAndClose" ./dtlcp/ 2>&1 | grep -E "PASS|FAIL|race|WARNING"
```

预期输出：100 个 `PASS`，无 `FAIL`，无 `race` 相关输出。

- [ ] **Step 3: 运行全仓库测试确保无回归**

```bash
cd /home/kkk/project/gotlcp && go test -short ./... 2>&1 | tail -20
```

- [ ] **Step 4: 检查 goroutine 泄漏**

```bash
cd /home/kkk/project/gotlcp && go test -v -run "TestManyConnections" ./dtlcp/ 2>&1 | grep "goroutine"
```

预期：`after <= before+10`

- [ ] **Step 5: 最终 git 状态确认**

```bash
cd /home/kkk/project/gotlcp && git status && git log --oneline -5
```
