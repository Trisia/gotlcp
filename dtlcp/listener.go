package dtlcp

import (
	"errors"
	"net"
	"os"
	"sync"
	"time"
)

// 本文件实现基于单个 net.PacketConn 的 DTLCP 监听器。
//
// DTLCP 面向数据报传输，一个 UDP socket 会收到来自多个客户端的数据报，而 *Conn 是
// 按「单个对端」建模的（内部按 remoteAddr 过滤来源）。packetListener 用一个后台读循环
// 把数据报按来源地址分发到各客户端独立的接收队列，从而让 net.Listener.Accept 的语义
// 在 UDP 上成立：每个首次出现的来源地址视为一个新连接，Accept 返回的 *Conn 只会看到
// 属于该地址的数据报。
//
// 所有 *Conn 共享同一个底层 socket，因此 Conn.Close 只注销该客户端（同一地址之后再次
// 收到数据报会被当作新连接重新 Accept），不会关闭整个监听 socket。

const (
	// packetListenerClientQueue 是单个客户端接收队列的容量，单位为数据报条数。
	// 队列满时丢弃最旧的数据报，符合 UDP 的丢弃语义（DTLCP 自身有重传机制兜底）。
	packetListenerClientQueue = 64
	// packetListenerAcceptQueue 是等待 Accept 的新客户端队列容量。
	packetListenerAcceptQueue = 128
)

// packetListener 基于单个 net.PacketConn 实现 net.Listener。
type packetListener struct {
	pconn  net.PacketConn
	config *Config

	mu        sync.Mutex
	clients   map[string]*packetConn
	closed    bool
	closeErr  error
	closeOnce sync.Once
	done      chan struct{}
	acceptCh  chan *packetConn
}

// newPacketListener 创建监听器并启动读循环。
func newPacketListener(pconn net.PacketConn, config *Config) *packetListener {
	l := &packetListener{
		pconn:    pconn,
		config:   config,
		clients:  make(map[string]*packetConn),
		done:     make(chan struct{}),
		acceptCh: make(chan *packetConn, packetListenerAcceptQueue),
	}
	go l.readLoop()
	return l
}

// readLoop 持续读取底层 socket，并把数据报分发给对应的客户端。
// 同一个缓冲区会被复用，dispatch 内部会把数据报复制到客户端队列。
func (l *packetListener) readLoop() {
	buf := make([]byte, maxCiphertext+recordHeaderLen)
	for {
		n, addr, err := l.pconn.ReadFrom(buf)
		if err != nil {
			l.shutdown(err)
			return
		}
		if n == 0 || addr == nil {
			continue
		}
		l.dispatch(addr, buf[:n])
	}
}

// dispatch 把一条数据报投递给 addr 对应的客户端；地址首次出现时创建客户端并唤醒 Accept。
func (l *packetListener) dispatch(addr net.Addr, payload []byte) {
	key := addr.String()

	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	pc, existed := l.clients[key]
	if !existed {
		pc = newPacketConn(l, addr)
		l.clients[key] = pc
	}
	l.mu.Unlock()

	// 先缓存数据报再通知 Accept，保证 Accept 返回后 Read 能立刻读到该客户端的首个报文。
	pc.enqueue(payload)
	if !existed {
		select {
		case l.acceptCh <- pc:
		default:
			// Accept 队列已满：不阻塞读循环，报文仍在该客户端队列中等待 Accept。
		}
	}
}

// Accept 等待一个新的客户端，并返回绑定该客户端的 DTLCP 服务端连接。
func (l *packetListener) Accept() (net.Conn, error) {
	select {
	case pc := <-l.acceptCh:
		if err := pc.closedError(); err != nil {
			return nil, err
		}
		return Server(pc, pc.remoteAddr, l.config), nil
	case <-l.done:
		return nil, l.closeError()
	}
}

// Addr 返回监听器的本地地址。
func (l *packetListener) Addr() net.Addr {
	return l.pconn.LocalAddr()
}

// Close 关闭监听器：关闭底层 socket、唤醒所有 Accept，并终止全部已接受的连接。
func (l *packetListener) Close() error {
	l.shutdown(net.ErrClosed)
	return nil
}

// closeError 返回监听器关闭时对外暴露的错误。
func (l *packetListener) closeError() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closeErr != nil {
		return l.closeErr
	}
	return net.ErrClosed
}

// shutdown 幂等地关闭监听器，err 为导致关闭的原因（如 net.ErrClosed 或 socket 读取错误）。
func (l *packetListener) shutdown(err error) {
	l.closeOnce.Do(func() {
		l.mu.Lock()
		l.closed = true
		l.closeErr = err
		clients := make([]*packetConn, 0, len(l.clients))
		for _, pc := range l.clients {
			clients = append(clients, pc)
		}
		l.clients = make(map[string]*packetConn)
		l.mu.Unlock()

		close(l.done)
		_ = l.pconn.Close()
		for _, pc := range clients {
			pc.closeWithError(err)
		}
	})
}

// remove 注销一个客户端，使同一地址后续的数据报可以被当作新连接重新 Accept。
func (l *packetListener) remove(pc *packetConn) {
	l.mu.Lock()
	if cur, ok := l.clients[pc.key]; ok && cur == pc {
		delete(l.clients, pc.key)
	}
	l.mu.Unlock()
}

// packetConn 是某个对端地址在共享 PacketConn 上的视图，实现 net.PacketConn。
// 它只读取分发到本地址的数据报，写入则直接使用共享 socket 发往本地址。
type packetConn struct {
	ln         *packetListener
	remoteAddr net.Addr
	key        string

	queue chan []byte

	mu         sync.Mutex
	closed     bool
	closeErr   error
	readDl     time.Time
	writeDl    time.Time
	deadlineCh chan struct{}

	done chan struct{}
}

// newPacketConn 创建某个对端地址的 PacketConn 视图。
func newPacketConn(l *packetListener, addr net.Addr) *packetConn {
	return &packetConn{
		ln:         l,
		remoteAddr: addr,
		key:        addr.String(),
		queue:      make(chan []byte, packetListenerClientQueue),
		deadlineCh: make(chan struct{}),
		done:       make(chan struct{}),
	}
}

// enqueue 把一条数据报复制到接收队列；队列已满时丢弃最旧的一条。
func (c *packetConn) enqueue(payload []byte) {
	if c.closedError() != nil {
		return
	}
	buf := make([]byte, len(payload))
	copy(buf, payload)
	select {
	case c.queue <- buf:
	default:
		select {
		case <-c.queue:
		default:
		}
		select {
		case c.queue <- buf:
		default:
		}
	}
}

// ReadFrom 读取一条属于本地址的数据报，实现 net.PacketConn。
// 设置了读截止时间时，超时返回 os.ErrDeadlineExceeded；截止时间在阻塞等待期间被修改会立即生效。
func (c *packetConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		c.mu.Lock()
		if c.closed {
			err := c.closeErr
			c.mu.Unlock()
			if err == nil {
				err = net.ErrClosed
			}
			return 0, nil, err
		}
		dl := c.readDl
		deadlineCh := c.deadlineCh
		c.mu.Unlock()

		var timer *time.Timer
		var timeoutCh <-chan time.Time
		if !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				return 0, nil, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(d)
			timeoutCh = timer.C
		}

		select {
		case buf := <-c.queue:
			stopTimer(timer)
			return copy(p, buf), c.remoteAddr, nil
		case <-timeoutCh:
			return 0, nil, os.ErrDeadlineExceeded
		case <-deadlineCh:
			stopTimer(timer)
		case <-c.done:
			stopTimer(timer)
			return 0, nil, c.err()
		}
	}
}

// WriteTo 经由共享 socket 向本视图对应的地址发送数据报，实现 net.PacketConn。
// addr 为 nil 或与本视图地址不一致时返回错误。
// 写截止时间会被记录但不会生效：数据报写入共享 socket 不会长时间阻塞，且修改它会影响其它客户端。
func (c *packetConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if addr != nil && addr.String() != c.key {
		return 0, errors.New("dtlcp: packet conn for " + c.key + " cannot write to " + addr.String())
	}
	if err := c.closedError(); err != nil {
		return 0, err
	}
	return c.ln.pconn.WriteTo(p, c.remoteAddr)
}

// Close 注销本客户端，实现 net.PacketConn。它不会关闭共享的底层 socket。
func (c *packetConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()

	close(c.done)
	c.ln.remove(c)
	return nil
}

// closeWithError 由监听器在关闭时调用，使阻塞中的 ReadFrom 立即返回。
func (c *packetConn) closeWithError(err error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.closeErr = err
	c.mu.Unlock()

	close(c.done)
}

// closedError 在视图已关闭时返回关闭原因，否则返回 nil。
func (c *packetConn) closedError() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		return nil
	}
	if c.closeErr != nil {
		return c.closeErr
	}
	return net.ErrClosed
}

// err 返回本视图的关闭原因。
func (c *packetConn) err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closeErr != nil {
		return c.closeErr
	}
	return net.ErrClosed
}

// LocalAddr 返回共享 socket 的本地地址，实现 net.PacketConn。
func (c *packetConn) LocalAddr() net.Addr {
	return c.ln.pconn.LocalAddr()
}

// SetDeadline 同时设置读、写截止时间，实现 net.PacketConn。
func (c *packetConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDl = t
	c.writeDl = t
	c.bumpDeadlineLocked()
	c.mu.Unlock()
	return nil
}

// SetReadDeadline 设置读截止时间，实现 net.PacketConn。
func (c *packetConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDl = t
	c.bumpDeadlineLocked()
	c.mu.Unlock()
	return nil
}

// SetWriteDeadline 设置写截止时间，实现 net.PacketConn。
func (c *packetConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDl = t
	c.bumpDeadlineLocked()
	c.mu.Unlock()
	return nil
}

// bumpDeadlineLocked 关闭并重建 deadlineCh，用于唤醒正在等待的 ReadFrom 重新计算截止时间。
// 调用方必须持有 c.mu。
func (c *packetConn) bumpDeadlineLocked() {
	close(c.deadlineCh)
	c.deadlineCh = make(chan struct{})
}

// stopTimer 安全地停止定时器。
func stopTimer(t *time.Timer) {
	if t != nil {
		t.Stop()
	}
}

// connectedPacketConn 把 net.Dial 返回的已连接 UDP socket 适配为 net.PacketConn。
//
// 已连接的 UDP socket 调用 WriteTo 会返回 "use of WriteTo with pre-connected connection"，
// 而 DTLCP 的连接实现统一用 WriteTo(..., remoteAddr) 发送数据报，因此这里把 WriteTo
// 转换为 Write；目标地址与已连接对端不一致时返回错误。
type connectedPacketConn struct {
	*net.UDPConn
}

// WriteTo 把数据报写入已连接的对端，实现 net.PacketConn。
func (c *connectedPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if addr != nil {
		if remote := c.RemoteAddr(); remote != nil && addr.String() != remote.String() {
			return 0, errors.New("dtlcp: connected packet conn cannot write to " + addr.String())
		}
	}
	return c.Write(b)
}
