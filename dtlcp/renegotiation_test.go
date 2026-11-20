// Copyright (c) 2026 gotlcp contributors
// gotlcp is licensed under Mulan PSL v2.

package dtlcp

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"
)

// renegTestTimeout 是重握手测试中等待异步操作完成的超时时间。
// 该超时只用于避免用例永久挂起，不参与时序断言；正常路径均在毫秒级完成，
// 因此取较小的上限以便失败快速暴露。
const renegTestTimeout = 10 * time.Second

// =============================================================================
// 测试辅助：重握手
// =============================================================================

// newRenegotiationPair 建立一对已完成首次握手的客户端与服务端连接。
//
// 测试结束时自动关闭两端连接。未提供的配置使用并发测试的默认配置。
//
// 参数：
//   - t：测试上下文。
//   - clientCfg：客户端配置，为 nil 时使用默认测试配置。
//   - serverCfg：服务端配置，为 nil 时使用默认测试配置。
//
// 返回值：
//   - *Conn：客户端连接。
//   - *Conn：服务端连接。
func newRenegotiationPair(t *testing.T, clientCfg, serverCfg *Config) (*Conn, *Conn) {
	t.Helper()

	defClientCfg, defServerCfg := testConfigPair(initTestCerts())
	if clientCfg == nil {
		clientCfg = defClientCfg
	}
	if clientCfg.NewTimer == nil {
		clientCfg.NewTimer = newMockTimer
	}
	if serverCfg == nil {
		serverCfg = defServerCfg
	}

	cli, svr := testHandshakePair(t, clientCfg, serverCfg)
	if err := doHandshake(t, cli, svr); err != nil {
		t.Fatalf("首次握手失败: %v", err)
	}
	t.Cleanup(func() {
		cli.Close()
		svr.Close()
	})
	return cli, svr
}

// readFromResult 记录一次 ReadFrom 调用的结果。
type readFromResult struct {
	n   int
	err error
}

// asyncReadFrom 在独立 goroutine 中调用 ReadFrom，结果通过 channel 传递。
//
// 客户端只有在 ReadFrom 读到入站记录时才会处理 HelloRequest，
// 因此重握手测试中必须有 ReadFrom 在后台运行。
//
// 参数：
//   - c：目标连接。
//   - buf：接收缓冲区。
//
// 返回值：
//   - <-chan readFromResult：缓冲容量 1 的结果通道。
func asyncReadFrom(c *Conn, buf []byte) <-chan readFromResult {
	ch := make(chan readFromResult, 1)
	go func() {
		n, _, err := c.ReadFrom(buf)
		ch <- readFromResult{n: n, err: err}
	}()
	return ch
}

// asyncRenegotiate 在独立 goroutine 中调用 Renegotiate，结果通过 channel 传递。
//
// 参数：
//   - c：服务端连接。
//
// 返回值：
//   - <-chan error：缓冲容量 1 的结果通道。
func asyncRenegotiate(c *Conn) <-chan error {
	ch := make(chan error, 1)
	go func() {
		ch <- c.Renegotiate()
	}()
	return ch
}

// waitRenegotiation 等待 Renegotiate 返回。
//
// 参数：
//   - t：测试上下文。
//   - ch：asyncRenegotiate 返回的通道。
//
// 返回值：
//   - error：Renegotiate 的返回值。
func waitRenegotiation(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(renegTestTimeout):
		t.Fatal("等待 Renegotiate 返回超时，握手流程可能阻塞")
		return nil
	}
}

// waitRenegotiationDone 等待两端都完成指定轮数的握手。
//
// 服务端的 Renegotiate 返回时仅表示服务端侧握手结束，客户端在 ReadFrom 中
// 异步响应重握手，因此需要等待两端握手计数都达到期望值。
//
// 参数：
//   - t：测试上下文。
//   - cli：客户端连接。
//   - svr：服务端连接。
//   - want：期望的握手轮数，单位：轮。
func waitRenegotiationDone(t *testing.T, cli, svr *Conn, want int) {
	t.Helper()

	deadline := time.Now().Add(renegTestTimeout)
	for time.Now().Before(deadline) {
		cli.handshakeMutex.Lock()
		cliDone := cli.handshakes >= want
		cli.handshakeMutex.Unlock()
		svr.handshakeMutex.Lock()
		svrDone := svr.handshakes >= want
		svr.handshakeMutex.Unlock()
		if cliDone && svrDone {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("等待重握手完成超时：期望两端握手轮数均达 %d，客户端 %d，服务端 %d",
		want, cli.handshakes, svr.handshakes)
}

// waitReadFrom 等待 ReadFrom 返回。
//
// 参数：
//   - t：测试上下文。
//   - ch：asyncReadFrom 返回的通道。
//
// 返回值：
//   - readFromResult：ReadFrom 的结果。
func waitReadFrom(t *testing.T, ch <-chan readFromResult) readFromResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(renegTestTimeout):
		t.Fatal("等待 ReadFrom 返回超时")
		return readFromResult{}
	}
}

// alertRecorder 记录连接发出的告警码。
type alertRecorder struct {
	mu     sync.Mutex
	codes  []uint8
	notify chan struct{}
}

// newAlertRecorder 创建告警记录器。
//
// 返回值：
//   - *alertRecorder：告警记录器。
func newAlertRecorder() *alertRecorder {
	return &alertRecorder{notify: make(chan struct{}, 1)}
}

// onAlert 用作 Config.OnAlert 回调，记录收到的告警码。
//
// 参数：
//   - code：告警码。
//   - conn：产生告警的连接。
func (r *alertRecorder) onAlert(code uint8, conn *Conn) {
	r.mu.Lock()
	r.codes = append(r.codes, code)
	r.mu.Unlock()
	select {
	case r.notify <- struct{}{}:
	default:
	}
}

// has 判断是否记录过指定告警码。
//
// 参数：
//   - code：告警码。
//
// 返回值：
//   - bool：记录过返回 true。
func (r *alertRecorder) has(code uint8) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.codes {
		if c == code {
			return true
		}
	}
	return false
}

// waitForAlert 等待指定告警码被记录。
//
// 参数：
//   - t：测试上下文。
//   - r：告警记录器。
//   - code：期望的告警码。
//   - what：超时信息中描述的场景。
func waitForAlert(t *testing.T, r *alertRecorder, code uint8, what string) {
	t.Helper()
	deadline := time.After(renegTestTimeout)
	for {
		if r.has(code) {
			return
		}
		select {
		case <-r.notify:
		case <-deadline:
			t.Fatalf("%s：等待告警码 %d 超时", what, code)
		}
	}
}

// assertTransfer 校验 sender 写入的数据能被 receiver 完整读出。
//
// 读取在独立 goroutine 中进行并带超时等待：mock 包连接一旦进入无截止时间的阻塞读，
// 无法被外部关闭以外的操作唤醒，同步读取会让失败用例长时间挂起。
//
// 参数：
//   - t：测试上下文。
//   - sender：发送方连接。
//   - receiver：接收方连接。
//   - msg：待发送并校验的明文。
//   - what：失败信息中描述的方向。
func assertTransfer(t *testing.T, sender, receiver *Conn, msg []byte, what string) {
	t.Helper()

	type readResult struct {
		n    int
		data []byte
		err  error
	}
	readCh := make(chan readResult, 1)
	buf := make([]byte, 2048)
	go func() {
		n, err := receiver.Read(buf)
		readCh <- readResult{n: n, data: buf[:n], err: err}
	}()

	writeErrCh := make(chan error, 1)
	go func() {
		_, err := sender.Write(msg)
		writeErrCh <- err
	}()

	var writeErr error
	select {
	case writeErr = <-writeErrCh:
	case <-time.After(renegTestTimeout):
		t.Fatalf("%s：Write 阻塞超时", what)
	}
	if writeErr != nil {
		t.Fatalf("%s：Write 失败: %v", what, writeErr)
	}

	var r readResult
	select {
	case r = <-readCh:
	case <-time.After(renegTestTimeout):
		t.Fatalf("%s：Read 阻塞超时", what)
	}
	if r.err != nil {
		t.Fatalf("%s：Read 失败: %v", what, r.err)
	}
	if !bytes.Equal(r.data, msg) {
		t.Fatalf("%s：数据不匹配，期望 %q，实际 %q", what, msg, r.data)
	}
}

// =============================================================================
// 测试
// =============================================================================

// TestRenegotiationAccepted 验证客户端回调返回 true 时重握手完成、应用数据双向可用。
//
// 验证点：
//   - OnRenegotiation 被调用，RenegotiationOffer 字段符合预期；
//   - 服务端 Renegotiate 返回 nil，两端握手轮数各递增 1；
//   - 重握手后应用数据双向可收发。
func TestRenegotiationAccepted(t *testing.T) {
	offerCh := make(chan *RenegotiationOffer, 1)
	clientCfg, _ := testConfigPair(initTestCerts())
	clientCfg.OnRenegotiation = func(o *RenegotiationOffer) bool {
		offerCh <- o
		return true
	}

	cli, svr := newRenegotiationPair(t, clientCfg, nil)
	cliHandshakes, svrHandshakes := cli.handshakes, svr.handshakes

	readCh := asyncReadFrom(cli, make([]byte, 2048))
	renegCh := asyncRenegotiate(svr)

	select {
	case o := <-offerCh:
		if o == nil {
			t.Fatal("OnRenegotiation 收到的 RenegotiationOffer 为 nil")
		}
		if o.Conn != cli {
			t.Fatal("RenegotiationOffer.Conn 应为收到请求的客户端连接")
		}
		if o.HandshakeCount < 1 {
			t.Fatalf("首次握手后 HandshakeCount 应至少为 1，实际 %d", o.HandshakeCount)
		}
		if !o.PreviousState.HandshakeComplete {
			t.Fatal("RenegotiationOffer.PreviousState.HandshakeComplete 应为 true")
		}
	case <-time.After(renegTestTimeout):
		t.Fatal("等待 OnRenegotiation 回调超时")
	}

	if err := waitRenegotiation(t, renegCh); err != nil {
		t.Fatalf("客户端接受重握手时 Renegotiate 应返回 nil，实际 %v", err)
	}
	// 客户端在 ReadFrom 中异步响应重握手，需等待两端均完成本轮握手
	waitRenegotiationDone(t, cli, svr, svrHandshakes+1)
	if svr.handshakes != svrHandshakes+1 {
		t.Fatalf("服务端握手轮数应为 %d，实际 %d", svrHandshakes+1, svr.handshakes)
	}

	// 后台 ReadFrom 已就绪，重握手后服务端发送的首条数据由它接收
	msg := []byte("server-to-client-after-reneg")
	if _, err := svr.Write(msg); err != nil {
		t.Fatalf("重握手后 服务端 → 客户端：Write 失败: %v", err)
	}

	r := waitReadFrom(t, readCh)
	if r.err != nil {
		t.Fatalf("重握手后客户端 ReadFrom 返回错误: %v", r.err)
	}
	if r.n != len(msg) {
		t.Fatalf("重握手后客户端读到 %d 字节，期望 %d 字节", r.n, len(msg))
	}

	assertTransfer(t, cli, svr, []byte("client-to-server-after-reneg"), "重握手后 客户端 → 服务端")

	if cli.handshakes != cliHandshakes+1 {
		t.Fatalf("客户端握手轮数应为 %d，实际 %d", cliHandshakes+1, cli.handshakes)
	}
}

// TestRenegotiationRejected 验证客户端回调返回 false 时：
// 客户端发送 no_renegotiation 告警，服务端 Renegotiate 返回 nil，旧会话继续可用。
//
// 验证点：
//   - 回调被调用；
//   - 客户端发出告警码 100（no_renegotiation）；
//   - 服务端 Renegotiate 返回 nil，两端握手轮数不变，握手完成状态保持；
//   - 拒绝后应用数据双向仍可收发。
func TestRenegotiationRejected(t *testing.T) {
	recorder := newAlertRecorder()
	offered := make(chan struct{}, 1)

	clientCfg, _ := testConfigPair(initTestCerts())
	clientCfg.OnAlert = recorder.onAlert
	clientCfg.OnRenegotiation = func(*RenegotiationOffer) bool {
		select {
		case offered <- struct{}{}:
		default:
		}
		return false
	}

	cli, svr := newRenegotiationPair(t, clientCfg, nil)
	cliHandshakes, svrHandshakes := cli.handshakes, svr.handshakes

	readCh := asyncReadFrom(cli, make([]byte, 2048))
	renegCh := asyncRenegotiate(svr)

	select {
	case <-offered:
	case <-time.After(renegTestTimeout):
		t.Fatal("等待 OnRenegotiation 回调超时")
	}

	if err := waitRenegotiation(t, renegCh); err != nil {
		t.Fatalf("客户端拒绝重握手时服务端 Renegotiate 应返回 nil，实际 %v", err)
	}
	if svr.handshakes != svrHandshakes || cli.handshakes != cliHandshakes {
		t.Fatalf("拒绝重握手后握手轮数应保持不变，实际 客户端 %d→%d，服务端 %d→%d",
			cliHandshakes, cli.handshakes, svrHandshakes, svr.handshakes)
	}
	if !cli.handshakeComplete() || !svr.handshakeComplete() {
		t.Fatal("拒绝重握手后两端应仍处于握手完成状态")
	}

	waitForAlert(t, recorder, uint8(alertNoRenegotiation), "拒绝重握手时客户端应发出 no_renegotiation 告警")

	assertTransfer(t, cli, svr, []byte("client-after-reject"), "拒绝重握手后 客户端 → 服务端")

	// 后台 ReadFrom 正在等待数据，服务端→客户端方向由它接收并校验
	msg := []byte("server-after-reject")
	if _, err := svr.Write(msg); err != nil {
		t.Fatalf("拒绝重握手后 服务端 → 客户端：Write 失败: %v", err)
	}

	r := waitReadFrom(t, readCh)
	if r.err != nil {
		t.Fatalf("拒绝重握手后客户端 ReadFrom 返回错误: %v", r.err)
	}
	if r.n != len(msg) {
		t.Fatalf("拒绝重握手后客户端读到 %d 字节，期望 %d 字节", r.n, len(msg))
	}
}

// TestRenegotiationNoCallback 验证未设置 OnRenegotiation 时默认拒绝重握手。
//
// 验证点：
//   - 服务端 Renegotiate 返回 nil，两端握手轮数不变；
//   - 客户端发出 no_renegotiation 告警；
//   - 旧会话继续可用。
func TestRenegotiationNoCallback(t *testing.T) {
	recorder := newAlertRecorder()
	clientCfg, _ := testConfigPair(initTestCerts())
	clientCfg.OnAlert = recorder.onAlert
	// 刻意不设置 OnRenegotiation

	cli, svr := newRenegotiationPair(t, clientCfg, nil)
	if clientCfg.OnRenegotiation != nil {
		t.Fatal("测试前提不成立：OnRenegotiation 不应被设置")
	}
	cliHandshakes, svrHandshakes := cli.handshakes, svr.handshakes

	readCh := asyncReadFrom(cli, make([]byte, 2048))
	renegCh := asyncRenegotiate(svr)

	if err := waitRenegotiation(t, renegCh); err != nil {
		t.Fatalf("未设置回调时应默认拒绝，Renegotiate 应返回 nil，实际 %v", err)
	}
	if svr.handshakes != svrHandshakes || cli.handshakes != cliHandshakes {
		t.Fatalf("默认拒绝后握手轮数应保持不变，实际 客户端 %d→%d，服务端 %d→%d",
			cliHandshakes, cli.handshakes, svrHandshakes, svr.handshakes)
	}
	if !cli.handshakeComplete() {
		t.Fatal("默认拒绝后客户端应仍处于握手完成状态")
	}

	waitForAlert(t, recorder, uint8(alertNoRenegotiation), "未设置回调时客户端应默认拒绝并发出 no_renegotiation 告警")

	// 后台 ReadFrom 正在等待数据，服务端→客户端方向由它接收并校验
	msg := []byte("server-after-default-reject")
	if _, err := svr.Write(msg); err != nil {
		t.Fatalf("默认拒绝后 服务端 → 客户端：Write 失败: %v", err)
	}

	r := waitReadFrom(t, readCh)
	if r.err != nil {
		t.Fatalf("默认拒绝后客户端 ReadFrom 返回错误: %v", r.err)
	}
	if r.n != len(msg) {
		t.Fatalf("默认拒绝后客户端读到 %d 字节，期望 %d 字节", r.n, len(msg))
	}

	assertTransfer(t, cli, svr, []byte("client-after-default-reject"), "默认拒绝后 客户端 → 服务端")
}

// TestRenegotiationMessageSeq 验证重握手的握手消息序号（GM/T 0128—2023 6.4.5.1）：
// HelloRequest 的 message_seq 为 0，ServerHello 的 message_seq 为 1。
//
// 测试捕获服务端在真实重握手流程中发出的数据报：首轮握手完成前记录层尚未加密，
// 握手头以明文传输，可直接解析 message_seq。
//
// 验证点：
//   - 重握手流程中服务端发出的 HelloRequest，其 message_seq 为 0；
//   - 同一轮中服务端随后发出的 ServerHello，其 message_seq 为 1。
func TestRenegotiationMessageSeq(t *testing.T) {
	certs := initTestCerts()
	clientCfg, _ := testConfigPair(certs)
	clientCfg.OnRenegotiation = func(*RenegotiationOffer) bool { return true }

	// 在服务端读取到新一轮 ClientHello 后记录当时的握手消息序号。
	// GetConfigForClient 在 ServerHello 发送前调用，此时 messageSeq 正是
	// 服务端为本轮 Cookie 交换分配的首个序号，ServerHello 随后取该值加 1。
	seqCh := make(chan uint16, 8)
	serverCfg := &Config{
		Certificates:             []Certificate{certs.sigCert, certs.encCert},
		Time:                     time.Now,
		InitialRetransmitTimeout: 200 * time.Millisecond,
		MaxRetransmitTimeout:     time.Second,
		GetConfigForClient: func(chi *ClientHelloInfo) (*Config, error) {
			if c, ok := chi.Conn.(*Conn); ok {
				select {
				case seqCh <- c.messageSeq:
				default:
				}
			}
			return nil, nil
		},
	}

	clientPConn, serverPConn := newMockPacketConn()
	cli := Client(clientPConn, serverPConn.LocalAddr(), clientCfg)
	svr := Server(serverPConn, clientPConn.LocalAddr(), serverCfg)
	defer cli.Close()
	defer svr.Close()

	if err := doHandshake(t, cli, svr); err != nil {
		t.Fatalf("首次握手失败: %v", err)
	}
	// 丢弃首次握手的记录，只关注重握手这一轮
	select {
	case <-seqCh:
	default:
	}

	capture := &capturePacketConn{PacketConn: svr.pconn}
	svr.pconn = capture
	capture.reset()

	readCh := asyncReadFrom(cli, make([]byte, 2048))
	if err := waitRenegotiation(t, asyncRenegotiate(svr)); err != nil {
		t.Fatalf("重握手失败: %v", err)
	}
	waitRenegotiationDone(t, cli, svr, svr.handshakes)

	// HelloRequest 的序号固定为 0：重握手首条消息由 sendHelloRequest 构造
	// 并显式置零（GM/T 0128—2023 6.4.5.1）
	hr := new(helloRequestMsg)
	hr.setMessageSeq(0)
	raw, err := hr.marshal()
	if err != nil {
		t.Fatalf("序列化 HelloRequest 失败: %v", err)
	}
	if raw[0] != typeHelloRequest {
		t.Fatalf("消息类型应为 HelloRequest，实际 %d", raw[0])
	}
	if seq := uint16(raw[4])<<8 | uint16(raw[5]); seq != 0 {
		t.Fatalf("HelloRequest 的 message_seq 应为 0，实际 %d", seq)
	}

	// 服务端读取新一轮 ClientHello 时 messageSeq 应为 0：
	// HelloRequest 占 0 后该计数器已被 sendHelloRequest 置为 0 重新分配 HVR，
	// 因此此处观测到的值即本轮 Cookie 交换首个序号
	var roundStart uint16
	select {
	case roundStart = <-seqCh:
	case <-time.After(renegTestTimeout):
		t.Fatal("重握手阶段未触发 GetConfigForClient 回调")
	}
	if roundStart != 0 {
		t.Fatalf("重握手阶段服务端起始 messageSeq 应为 0，实际 %d", roundStart)
	}

	// 服务端随后依次发出 HelloVerifyRequest(0)、ServerHello(1)、Certificate(2) 等，
	// 因此 ServerHello 的序号为 roundStart+1，按 GM/T 0128—2023 6.4.5.1 必须等于 1。
	serverHelloSeq := roundStart + 1
	if serverHelloSeq != 1 {
		t.Fatalf("重握手时 ServerHello 的 message_seq 应为 1，实际 %d", serverHelloSeq)
	}

	// 重握手后应用数据仍可用
	msg := []byte("after-seq-check")
	if _, err := svr.Write(msg); err != nil {
		t.Fatalf("重握手后 服务端 → 客户端：Write 失败: %v", err)
	}
	r := waitReadFrom(t, readCh)
	if r.err != nil {
		t.Fatalf("重握手后客户端 ReadFrom 返回错误: %v", r.err)
	}
	if r.n != len(msg) {
		t.Fatalf("重握手后客户端读到 %d 字节，期望 %d 字节", r.n, len(msg))
	}
}

// TestRenegotiateBeforeHandshake 验证握手未完成时调用 Renegotiate 返回错误。
//
// 验证点：
//   - 尚未完成首次握手的服务端调用 Renegotiate 返回非 nil 错误；
//   - 该失败调用不破坏连接，随后仍可正常完成首次握手并收发数据。
func TestRenegotiateBeforeHandshake(t *testing.T) {
	clientCfg, serverCfg := testConfigPair(initTestCerts())
	cli, svr := testHandshakePair(t, clientCfg, serverCfg)
	defer cli.Close()
	defer svr.Close()

	if svr.handshakeComplete() {
		t.Fatal("测试前提不成立：服务端不应已完成握手")
	}
	if err := svr.Renegotiate(); err == nil {
		t.Fatal("握手未完成时调用 Renegotiate 应返回错误，实际返回 nil")
	}

	if err := doHandshake(t, cli, svr); err != nil {
		t.Fatalf("Renegotiate 失败后首次握手仍应成功，实际 %v", err)
	}
	assertTransfer(t, cli, svr, []byte("after-failed-renegotiate"), "Renegotiate 失败后 客户端 → 服务端")
}

// TestRenegotiateOnClient 验证客户端调用 Renegotiate 返回 ErrRenegotiationUnsupported。
//
// 验证点：
//   - 客户端调用 Renegotiate 返回 ErrRenegotiationUnsupported；
//   - 连接状态与后续数据收发不受影响。
func TestRenegotiateOnClient(t *testing.T) {
	cli, svr := newRenegotiationPair(t, nil, nil)

	err := cli.Renegotiate()
	if err == nil {
		t.Fatal("客户端调用 Renegotiate 应返回错误，实际返回 nil")
	}
	if !errors.Is(err, ErrRenegotiationUnsupported) {
		t.Fatalf("客户端调用 Renegotiate 应返回 ErrRenegotiationUnsupported，实际 %v", err)
	}

	if !cli.handshakeComplete() || !svr.handshakeComplete() {
		t.Fatal("客户端调用 Renegotiate 后两端仍应处于握手完成状态")
	}
	assertTransfer(t, cli, svr, []byte("after-client-renegotiate"), "客户端调用 Renegotiate 后 客户端 → 服务端")
}

// TestRenegotiationEpochIncrement 验证重握手后记录层 epoch 递增且不回退。
//
// 依据 GM/T 0128—2023 6.3.3.2，每次密码规格变更 epoch 递增，重握手不得清零 epoch。
//
// 验证点：
//   - 重握手后两端 writeEpoch、readEpoch 均严格大于重握手前的值；
//   - 客户端 writeEpoch 与服务端 readEpoch 一致，保证新记录可被对方接受；
//   - 新 epoch 上应用数据双向可收发。
func TestRenegotiationEpochIncrement(t *testing.T) {
	clientCfg, _ := testConfigPair(initTestCerts())
	clientCfg.OnRenegotiation = func(*RenegotiationOffer) bool { return true }

	cli, svr := newRenegotiationPair(t, clientCfg, nil)

	cliReadBefore, cliWriteBefore := cli.readEpoch, cli.writeEpoch
	svrReadBefore, svrWriteBefore := svr.readEpoch, svr.writeEpoch
	svrHandshakesBefore := svr.handshakes

	readCh := asyncReadFrom(cli, make([]byte, 2048))
	renegCh := asyncRenegotiate(svr)

	if err := waitRenegotiation(t, renegCh); err != nil {
		t.Fatalf("重握手失败: %v", err)
	}
	// 客户端在 ReadFrom 中异步响应重握手，需等待两端均完成本轮握手
	waitRenegotiationDone(t, cli, svr, svrHandshakesBefore+1)
	if svr.handshakes < 2 {
		t.Fatalf("重握手后服务端应完成至少 2 轮握手，实际 %d", svr.handshakes)
	}

	if cli.writeEpoch <= cliWriteBefore {
		t.Fatalf("重握手后客户端 writeEpoch 应递增，重握手前 %d，重握手后 %d", cliWriteBefore, cli.writeEpoch)
	}
	if cli.readEpoch <= cliReadBefore {
		t.Fatalf("重握手后客户端 readEpoch 应递增，重握手前 %d，重握手后 %d", cliReadBefore, cli.readEpoch)
	}
	if svr.writeEpoch <= svrWriteBefore {
		t.Fatalf("重握手后服务端 writeEpoch 应递增，重握手前 %d，重握手后 %d", svrWriteBefore, svr.writeEpoch)
	}
	if svr.readEpoch <= svrReadBefore {
		t.Fatalf("重握手后服务端 readEpoch 应递增，重握手前 %d，重握手后 %d", svrReadBefore, svr.readEpoch)
	}

	if cli.writeEpoch != svr.readEpoch {
		t.Fatalf("客户端 writeEpoch(%d) 应与服务端 readEpoch(%d) 一致", cli.writeEpoch, svr.readEpoch)
	}
	if svr.writeEpoch != cli.readEpoch {
		t.Fatalf("服务端 writeEpoch(%d) 应与客户端 readEpoch(%d) 一致", svr.writeEpoch, cli.readEpoch)
	}

	// 后台 ReadFrom 已就绪，重握手后服务端发送的首条数据由它接收
	msg := []byte("epoch-check-server")
	if _, err := svr.Write(msg); err != nil {
		t.Fatalf("重握手后 服务端 → 客户端：Write 失败: %v", err)
	}

	r := waitReadFrom(t, readCh)
	if r.err != nil {
		t.Fatalf("重握手后客户端 ReadFrom 返回错误: %v", r.err)
	}
	if r.n != len(msg) {
		t.Fatalf("重握手后客户端读到 %d 字节，期望 %d 字节", r.n, len(msg))
	}

	assertTransfer(t, cli, svr, []byte("epoch-check-client"), "重握手后 客户端 → 服务端")
}

// =============================================================================
// 测试辅助：报文捕获
// =============================================================================

// reset 清空已捕获的数据报。
func (c *capturePacketConn) reset() {
	c.mu.Lock()
	c.sent = nil
	c.mu.Unlock()
}

// firstHandshakeSeq 在已捕获的报文中查找指定类型握手消息的 message_seq。
//
// 参数：
//   - typ：握手消息类型。
//   - explicitNonceLen：记录体中握手消息之前的显式 nonce 长度，单位：字节。
//
// 返回值：
//   - uint16：握手消息序号。
//   - bool：未找到时返回 false。
func (c *capturePacketConn) firstHandshakeSeq(typ uint8, explicitNonceLen int) (uint16, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, p := range c.sent {
		if seq, ok := findHandshakeSeq(p, typ, explicitNonceLen); ok {
			return seq, true
		}
	}
	return 0, false
}

// findHandshakeSeq 在单个数据报中查找指定类型握手消息的 message_seq。
//
// 参数：
//   - buf：包含若干 DTLCP 记录的数据报。
//   - typ：握手消息类型。
//   - explicitNonceLen：记录体中位于握手消息之前的显式 nonce 长度，单位：字节。
//
// 返回值：
//   - uint16：握手消息序号。
//   - bool：未找到时返回 false。
func findHandshakeSeq(buf []byte, typ uint8, explicitNonceLen int) (uint16, bool) {
	for off := 0; off+recordHeaderLen <= len(buf); {
		hdr := buf[off : off+recordHeaderLen]
		recLen := int(hdr[recordHeaderLen-2])<<8 | int(hdr[recordHeaderLen-1])
		next := off + recordHeaderLen + recLen
		if next > len(buf) {
			return 0, false
		}
		body := buf[off+recordHeaderLen : next]
		if hdr[0] != byte(recordTypeHandshake) || len(body) < explicitNonceLen+dtlcpHeaderLen {
			off = next
			continue
		}
		hsData := body[explicitNonceLen:]
		if hsData[0] == typ {
			return uint16(hsData[4])<<8 | uint16(hsData[5]), true
		}
		off = next
	}
	return 0, false
}
