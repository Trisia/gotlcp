// Copyright (c) 2025 gotlcp contributors
// gotlcp is licensed under Mulan PSL v2.

// DTLCP 记录层实现
//
// 基于 net.PacketConn (UDP)，记录头 13 字节：
//   [Type:1][Version:2][Epoch:2][SeqNum:6][Length:2]

package dtlcp

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/emmansun/gmsm/smx509"
)

// =============================================================================
// Conn — DTLCP 连接对象
// =============================================================================

// Conn 表示一个 DTLCP 安全连接，基于 net.PacketConn (UDP) 实现。
//
// Conn 同时实现了 net.Conn 和 net.PacketConn 接口：
//   - Read/Write：流式读写，兼容 net.Conn。适用于简单请求-响应模式。
//   - ReadFrom/WriteTo：数据报读写，兼容 net.PacketConn。ReadFrom 每次返回一条应用数据记录；WriteTo 每次独立发送其数据，通常不与相邻调用合并，数据超过单条记录可承载的最大载荷时会按 PMTU 拆分为多条记录。
//
// Conn 在首次 Read/Write/ReadFrom/WriteTo 时自动触发握手，
// 也可通过 Handshake 或 HandshakeContext 显式触发。
type Conn struct {
	// 传输层
	pconn       net.PacketConn              // 底层 UDP socket
	remoteAddr  net.Addr                    // 对端地址
	isClient    bool                        // 是否是客户端
	handshakeFn func(context.Context) error // 握手实现（Phase 4 实现）

	// 握手状态
	handshakeMutex sync.Mutex
	handshakeErr   error
	vers           uint16 // 协商出的协议版本
	haveVers       bool   // 是否已收到版本信息
	config         *Config
	didResume      bool   // 会话重用
	cipherSuite    uint16 // 密码套件 ID
	handshakes     int    // 握手次数

	// 记录层（输入/输出）
	in, out halfConn

	// 重放保护
	replayWindow *replayWindow

	// 2*MSL 驻留期 (RFC 6347 §4.2.4)
	dwellDeadline    time.Time // 驻留截止时间，零值表示不在驻留期
	flightRetransmit []byte    // 最后一 flight 数据，用于驻留重传

	// DTLCP 四态握手状态机
	hsState        atomic.Int32 // handshakeState: statePreparing/stateSending/stateWaiting/stateFinished
	flightBuffer   []handshakeMessage
	messageSeq     uint16
	nextReceiveSeq uint16

	// 重传
	retransmitTimer *RetransmitTimer

	// 分片重组
	pendingFragments map[uint16]*fragmentBuffer

	// 缓冲区
	rawInputBuf []byte       // 单个 UDP 报文缓冲区
	handBuf     bytes.Buffer // 握手数据
	readBuf     []byte       // 解密后的应用数据（等待 Read 消费）

	// 证书
	peerCertificates  []*smx509.Certificate
	verifiedChains    [][]*smx509.Certificate
	activeCertHandles []*activeCert

	// peerIBCIdentity / peerIBCSysParams 仅 IBC/IBSDH 套件下非空，
	// peerIBCIdentity 为对端标识内容（identityData），peerIBCSysParams 为命中的本地信任池参数。
	peerIBCIdentity  []byte
	peerIBCSysParams *IBCSysParams

	// 其他
	clientFinished [12]byte
	serverFinished [12]byte
	serverName     string
	clientProtocol string
	workKey        []byte
	cookieSecret   []byte // 随机生成的 cookie 密钥（Config.CookieSecret 为空时使用）

	closeNotifySent bool
	closeNotifyErr  error
	activeCall      int32
	retryCount      int
	tmp             [16]byte

	// 序列号（DTLCP 显式 epoch + seq_num）
	writeEpoch uint16
	readEpoch  uint16
	writeSeq   uint48
	readSeq    uint48

	// 发送缓冲
	buffering bool
	sendBuf   []byte
}

// =============================================================================
// halfConn — 单向记录层连接（发送或接收方向）
// =============================================================================

// halfConn 代表一个传输方向（发送/接收）的记录层协议连接。
// seq 编码：epoch(2B, big-endian) || seq_num(6B, big-endian)，共 8 字节。
type halfConn struct {
	sync.Mutex

	err     error       // 第一个永久错误
	version uint16      // 协议版本
	cipher  interface{} // 密码算法
	mac     hash.Hash
	seq     [8]byte // 8字节序列号：epoch(2) + seq_num(6)

	scratchBuf [13]byte // 避免 allocs 的临时缓冲区

	nextCipher interface{} // 下一个加密状态
	nextMac    hash.Hash   // 下一个 MAC 算法
	// deferredCCS 延迟执行标志：
	// 当 CKE+CCS+Finished 打包在同一 UDP 数据报时，readRecord 按序读取记录，读到 CCS
	// 时 nextCipher 尚未就绪（establishKeys 还未处理 CKE），无法立即切换密钥。
	// 此时将 deferredCCS 置为 true，CCS 视为已从数据报中消费（避免阻塞后续 Finished 读取），
	// 但实际密钥切换延迟到 readChangeCipherSpec 调用时执行（此时 nextCipher 已就绪）。
	// readChangeCipherSpec 检查此标志：若为 true，直接调用 changeCipherSpec 完成密钥切换；
	// 若为 false（CCS 独立到达的正常路径），则从网络读取并处理 CCS。
	deferredCCS bool
}

func (hc *halfConn) setErrorLocked(err error) error {
	hc.err = err
	return hc.err
}

// prepareCipherSpec 设置后续 changeCipherSpec 将使用的加密和 MAC 状态。
func (hc *halfConn) prepareCipherSpec(version uint16, cipher interface{}, mac hash.Hash) {
	hc.version = version
	hc.nextCipher = cipher
	hc.nextMac = mac
}

// changeCipherSpec 将加密和 MAC 状态切换为 prepareCipherSpec 预先设置的值。
func (hc *halfConn) changeCipherSpec() error {
	if hc.nextCipher == nil {
		return alertInternalError
	}
	hc.cipher = hc.nextCipher
	hc.mac = hc.nextMac
	hc.nextCipher = nil
	hc.nextMac = nil
	for i := range hc.seq {
		hc.seq[i] = 0
	}
	return nil
}

// explicitNonceLen 返回每条记录中包含的显式 nonce/IV 字节数。
func (hc *halfConn) explicitNonceLen() int {
	if hc.cipher == nil {
		return 0
	}
	switch c := hc.cipher.(type) {
	case cipher.Stream:
		return 0
	case aead:
		return c.explicitNonceLen()
	case cbcMode:
		return c.BlockSize()
	default:
		panic("unknown cipher type")
	}
}

// extractPadding 常数时间提取填充长度。返回要删除的字节数和一个表示填充是否有效的 good 字节。
func extractPadding(payload []byte) (toRemove int, good byte) {
	if len(payload) < 1 {
		return 0, 0
	}

	paddingLen := payload[len(payload)-1]
	t := uint(len(payload)-1) - uint(paddingLen)
	good = byte(int32(^t) >> 31)

	toCheck := 256
	if toCheck > len(payload) {
		toCheck = len(payload)
	}

	for i := 0; i < toCheck; i++ {
		t := uint(paddingLen) - uint(i)
		mask := byte(int32(^t) >> 31)
		b := payload[len(payload)-1-i]
		good &^= mask&paddingLen ^ mask&b
	}

	good &= good << 4
	good &= good << 2
	good &= good << 1
	good = uint8(int8(good) >> 7)

	paddingLen &= good
	toRemove = int(paddingLen) + 1
	return
}

func roundUp(a, b int) int {
	return a + (b-a%b)%b
}

// cbcMode 是使用 CBC 模式的分组密码接口。
type cbcMode interface {
	cipher.BlockMode
	SetIV([]byte)
}

// decrypt 验证并解密记录（如果当前阶段启用了加密保护）。
// 返回的明文可能与输入重叠。
func (hc *halfConn) decrypt(record []byte) ([]byte, recordType, error) {
	var plaintext []byte
	typ := recordType(record[0])
	payload := record[recordHeaderLen:]

	paddingGood := byte(255)
	paddingLen := 0

	explicitNonceLen := hc.explicitNonceLen()

	if hc.cipher != nil {
		switch c := hc.cipher.(type) {
		case cipher.Stream:
			c.XORKeyStream(payload, payload)
		case aead:
			if len(payload) < explicitNonceLen {
				return nil, 0, alertBadRecordMAC
			}
			nonce := payload[:explicitNonceLen]
			if len(nonce) == 0 {
				nonce = hc.seq[:]
			}
			payload = payload[explicitNonceLen:]

			// DTLCP: additional_data = epoch(2) + seq_num(6) + type(1) + version(2) + length(2)
			additionalData := append(hc.scratchBuf[:0], hc.seq[:]...)
			additionalData = append(additionalData, record[0])            // type
			additionalData = append(additionalData, record[1], record[2]) // version
			n := len(payload) - c.Overhead()
			additionalData = append(additionalData, byte(n>>8), byte(n)) // length

			var err error
			plaintext, err = c.Open(payload[:0], nonce, payload, additionalData)
			if err != nil {
				return nil, 0, alertBadRecordMAC
			}
		case cbcMode:
			blockSize := c.BlockSize()
			minPayload := explicitNonceLen + roundUp(hc.mac.Size()+1, blockSize)
			if len(payload)%blockSize != 0 || len(payload) < minPayload {
				return nil, 0, alertBadRecordMAC
			}

			if explicitNonceLen > 0 {
				c.SetIV(payload[:explicitNonceLen])
				payload = payload[explicitNonceLen:]
			}
			c.CryptBlocks(payload, payload)

			// In a limited attempt to protect against CBC padding oracles like
			// Lucky13, the data past paddingLen (which is secret) is passed to
			// the MAC function as extra data, to be fed into the HMAC after
			// computing the digest.
			paddingLen, paddingGood = extractPadding(payload)
		default:
			panic("unknown cipher type")
		}
	} else {
		plaintext = payload
	}

	if hc.mac != nil {
		macSize := hc.mac.Size()
		if len(payload) < macSize {
			return nil, 0, alertBadRecordMAC
		}

		n := len(payload) - macSize - paddingLen
		n = subtle.ConstantTimeSelect(int(uint32(n)>>31), 0, n) // if n < 0 { n = 0 }
		remoteMAC := payload[n : n+macSize]
		// DTLCP MAC header: type(1) + version(2) + length(2)
		macHeader := []byte{record[0], record[1], record[2], byte(n >> 8), byte(n)}
		localMAC := tls10MAC(hc.mac, hc.scratchBuf[:0], hc.seq[:], macHeader, payload[:n], payload[n+macSize:])

		macAndPaddingGood := subtle.ConstantTimeCompare(localMAC, remoteMAC) & int(paddingGood)
		if macAndPaddingGood != 1 {
			return nil, 0, alertBadRecordMAC
		}

		plaintext = payload[:n]
	}

	// DTLCP: seq 是显式的，无需递增
	return plaintext, typ, nil
}

// sliceForAppend 将输入切片扩展 n 个字节。head 是完整的扩展切片，
// tail 是附加的部分。如果原始切片有足够的容量，则不会分配新内存。
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}

// encrypt 加密 payload，添加适当的 nonce 和/或 MAC，
// 并追加到 record 之后，record 必须已包含记录头。
func (hc *halfConn) encrypt(record, payload []byte, rand io.Reader) ([]byte, error) {
	if hc.cipher == nil {
		return append(record, payload...), nil
	}

	var explicitNonce []byte
	if explicitNonceLen := hc.explicitNonceLen(); explicitNonceLen > 0 {
		record, explicitNonce = sliceForAppend(record, explicitNonceLen)
		if _, isCBC := hc.cipher.(cbcMode); !isCBC && explicitNonceLen < 16 {
			copy(explicitNonce, hc.seq[:])
		} else {
			if _, err := io.ReadFull(rand, explicitNonce); err != nil {
				return nil, err
			}
		}
	}

	var dst []byte
	switch c := hc.cipher.(type) {
	case cipher.Stream:
		// DTLCP MAC header: type(1) + version(2) + length(2)
		macHeader := []byte{record[0], record[1], record[2], record[recordHeaderLen-2], record[recordHeaderLen-1]}
		mac := tls10MAC(hc.mac, hc.scratchBuf[:0], hc.seq[:], macHeader, payload, nil)
		record, dst = sliceForAppend(record, len(payload)+len(mac))
		c.XORKeyStream(dst[:len(payload)], payload)
		c.XORKeyStream(dst[len(payload):], mac)
	case aead:
		nonce := explicitNonce
		if len(nonce) == 0 {
			nonce = hc.seq[:]
		}
		additionalData := append(hc.scratchBuf[:0], hc.seq[:]...)
		// DTLCP: additional_data = epoch(2) + seq_num(6) + type(1) + version(2) + length(2)
		additionalData = append(additionalData, record[0])                                 // type
		additionalData = append(additionalData, record[1], record[2])                      // version
		additionalData = append(additionalData, byte(len(payload)>>8), byte(len(payload))) // length
		record = c.Seal(record, nonce, payload, additionalData)
	case cbcMode:
		// DTLCP MAC header: type(1) + version(2) + length(2)
		macHeader := []byte{record[0], record[1], record[2], record[recordHeaderLen-2], record[recordHeaderLen-1]}
		mac := tls10MAC(hc.mac, hc.scratchBuf[:0], hc.seq[:], macHeader, payload, nil)
		blockSize := c.BlockSize()
		plaintextLen := len(payload) + len(mac)
		paddingLen := blockSize - plaintextLen%blockSize
		record, dst = sliceForAppend(record, plaintextLen+paddingLen)
		copy(dst, payload)
		copy(dst[len(payload):], mac)
		for i := plaintextLen; i < len(dst); i++ {
			dst[i] = byte(paddingLen - 1)
		}
		if len(explicitNonce) > 0 {
			c.SetIV(explicitNonce)
		}
		c.CryptBlocks(dst, dst)
	default:
		panic("unknown cipher type")
	}

	// DTLCP: length 字段在 record[recordHeaderLen-2 : recordHeaderLen-1]
	n := len(record) - recordHeaderLen
	record[recordHeaderLen-2] = byte(n >> 8)
	record[recordHeaderLen-1] = byte(n)
	// DTLCP: seq 是显式的，无需递增

	return record, nil
}

// =============================================================================
// outBufPool — 写记录用 scratch buffer 池
// =============================================================================

// outBufPool — 写记录用 scratch buffer 池。
// 预分配 PMTU 大小匹配 DTLCP over UDP 实际记录上限，避免写路径上的堆分配。
var outBufPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 0, 1500)
		return &buf
	},
}

// =============================================================================
// atLeastReader — 读取至少 N 字节的辅助 reader
// =============================================================================

type atLeastReader struct {
	R io.Reader
	N int64
}

func (r *atLeastReader) Read(p []byte) (int, error) {
	if r.N <= 0 {
		return 0, io.EOF
	}
	n, err := r.R.Read(p)
	r.N -= int64(n)
	if r.N > 0 && err == io.EOF {
		return n, io.ErrUnexpectedEOF
	}
	if r.N <= 0 && err == nil {
		return n, io.EOF
	}
	return n, err
}

// =============================================================================
// RecordHeaderError — 记录头错误
// =============================================================================

// RecordHeaderError 记录层头部解析错误，包含导致错误的 13 字节头部和地址信息。
type RecordHeaderError struct {
	// Msg 错误描述。
	Msg string
	// RecordHeader 导致错误的 DTLCP 记录头（13 字节）。
	RecordHeader [13]byte
	// Addr 对端地址。
	Addr net.Addr
}

// Error 返回记录头错误的文本描述，满足 error 接口。
//
// 返回值：
//   - string：由固定前缀 "dtlcp: " 与 RecordHeaderError.Msg 拼接而成的错误文本。
func (e RecordHeaderError) Error() string { return "dtlcp: " + e.Msg }

func (c *Conn) newRecordHeaderError(addr net.Addr, msg string) (err RecordHeaderError) {
	err.Msg = msg
	err.Addr = addr
	copy(err.RecordHeader[:], c.rawInputBuf)
	return err
}

// =============================================================================
// Conn — 序列号管理
// =============================================================================

// setWriteSeq 将 Conn 级别的 writeEpoch + writeSeq 编码到 out.seq 中，
// 供 encrypt 方法中的 MAC/AAD 使用。
func (c *Conn) setWriteSeq() {
	c.out.seq[0] = byte(c.writeEpoch >> 8)
	c.out.seq[1] = byte(c.writeEpoch)
	c.out.seq[2] = byte(c.writeSeq >> 40)
	c.out.seq[3] = byte(c.writeSeq >> 32)
	c.out.seq[4] = byte(c.writeSeq >> 24)
	c.out.seq[5] = byte(c.writeSeq >> 16)
	c.out.seq[6] = byte(c.writeSeq >> 8)
	c.out.seq[7] = byte(c.writeSeq)
}

// =============================================================================
// Conn — 寻址与超时
// =============================================================================

// LocalAddr 返回连接本地的网络地址。
//
// 返回值：
//   - net.Addr：底层 net.PacketConn 的本地地址，即本端 UDP socket 的绑定地址。
func (c *Conn) LocalAddr() net.Addr {
	return c.pconn.LocalAddr()
}

// RemoteAddr 返回连接对端的网络地址。
//
// 返回值：
//   - net.Addr：对端地址，通常由 Server/Client 构造时传入，或在首次收到报文时确定；若两者都未提供则可能为 nil。
func (c *Conn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

// SetDeadline 设置连接读取或写入的截止时间。
// 该时间同时作用于底层 net.PacketConn 的读与写操作，因而会影响 Read/ReadFrom/Write/WriteTo 以及握手过程中的收发。
//
// 参数：
//   - t：截止时间；零值 time.Time{} 表示不设置超时。
//
// 返回值：
//   - error：设置失败时返回非 nil，错误由底层 net.PacketConn 透传。
func (c *Conn) SetDeadline(t time.Time) error {
	return c.pconn.SetDeadline(t)
}

// SetReadDeadline 设置读取截止时间，仅影响接收方向的操作（Read/ReadFrom 以及握手时的读取）。
//
// 参数：
//   - t：读取截止时间；零值 time.Time{} 表示读取不超时。
//
// 返回值：
//   - error：设置失败时返回非 nil，错误由底层 net.PacketConn 透传。
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.pconn.SetReadDeadline(t)
}

// SetWriteDeadline 设置写入截止时间，仅影响发送方向的操作（Write/WriteTo 以及握手时的写入）。
//
// 参数：
//   - t：写入截止时间；零值 time.Time{} 表示写入不超时。
//
// 返回值：
//   - error：设置失败时返回非 nil，错误由底层 net.PacketConn 透传。
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.pconn.SetWriteDeadline(t)
}

// NetConn 返回被 DTLCP 包装的底层 net.PacketConn。
//
// 返回值：
//   - net.PacketConn：底层 UDP 连接对象；直接读写该对象会绕过 DTLCP 的记录层加解密、序列号与重放保护，应仅在必要时使用。
func (c *Conn) NetConn() net.PacketConn {
	return c.pconn
}

// PeerCertificates 返回对端证书链，握手完成后可用。
//
// 返回值：
//   - []*smx509.Certificate：对端提供的证书链，顺序与对端发送顺序一致；握手尚未完成或对端未提供证书时可能为 nil 或空。
func (c *Conn) PeerCertificates() []*smx509.Certificate {
	return c.peerCertificates
}

// IsClient 返回当前连接是否为客户端。
//
// 返回值：
//   - bool：true 表示由 Client 构造的客户端连接，false 表示由 Server 构造的服务端连接。
func (c *Conn) IsClient() bool {
	return c.isClient
}

// =============================================================================
// Conn — 数据报读取
// =============================================================================

// readDatagram 从底层 UDP socket 读取一个完整的数据报。
func (c *Conn) readDatagram() error {
	buf := make([]byte, maxCiphertext+recordHeaderLen)
	n, addr, err := c.pconn.ReadFrom(buf)
	if err != nil {
		return err
	}
	// 验证地址：只接受对端地址的数据报
	if c.remoteAddr != nil && addr.String() != c.remoteAddr.String() {
		return c.readDatagram() // 忽略非对端报文，继续读
	}
	if c.remoteAddr == nil {
		c.remoteAddr = addr // 首次收到报文时设置对端地址
	}
	c.rawInputBuf = buf[:n]
	return nil
}

// =============================================================================
// Conn — 记录层读取
// =============================================================================

// readRecord 读取并处理一条记录（非 CCS 模式）。
func (c *Conn) readRecord() error {
	return c.readRecordOrCCS(false)
}

// readChangeCipherSpec 读取并处理一条记录（CCS 模式）。
// 若 CCS 已在同数据报中被消耗，则直接完成密钥切换。
func (c *Conn) readChangeCipherSpec() error {
	if c.in.deferredCCS {
		c.in.deferredCCS = false
		if err := c.in.changeCipherSpec(); err != nil {
			return c.in.setErrorLocked(c.sendAlert(err.(alert)))
		}
		c.readEpoch++
		c.readSeq = 0
		windowSize := defaultReplayWindowSize
		if c.config != nil && c.config.ReplayWindow > 0 {
			windowSize = c.config.ReplayWindow
		}
		c.replayWindow = newReplayWindow(windowSize)
		return nil
	}
	return c.readRecordOrCCS(true)
}

// readRecordOrCCS 从连接中读取一条或多条 DTLCP 记录并更新记录层状态。
//
// 在握手期间，以下情况之一会发生：
//   - c.handBuf 增长
//   - c.in.changeCipherSpec 被调用
//   - 返回错误
//
// 握手完成后：
//   - c.handBuf 增长
//   - c.readBuf 被设置
//   - 返回错误
func (c *Conn) readRecordOrCCS(expectChangeCipherSpec bool) error {
	if c.in.err != nil {
		return c.in.err
	}
	handshakeComplete := c.handshakeComplete()

	if len(c.readBuf) != 0 {
		return c.in.setErrorLocked(errors.New("dtlcp: internal error: attempted to read record with pending application data"))
	}

	// 循环处理数据报中的所有记录（DTLS/DTLCP 允许一个数据报包含多条记录）
	for {
		c.readBuf = nil

		// 如果没有待处理数据，读取一个新的 UDP 数据报
		if len(c.rawInputBuf) < recordHeaderLen {
			if err := c.readDatagram(); err != nil {
				if e, ok := err.(net.Error); !ok || !e.Timeout() {
					c.in.setErrorLocked(err)
				}
				return err
			}
		}

		if len(c.rawInputBuf) < recordHeaderLen {
			return c.in.setErrorLocked(errors.New("dtlcp: record too short"))
		}

		hdr := c.rawInputBuf[:recordHeaderLen]
		typ := recordType(hdr[0])

		vers := uint16(hdr[1])<<8 | uint16(hdr[2])
		epoch := uint16(hdr[3])<<8 | uint16(hdr[4])
		seqNum := uint48(hdr[5])<<40 | uint48(hdr[6])<<32 | uint48(hdr[7])<<24 |
			uint48(hdr[8])<<16 | uint48(hdr[9])<<8 | uint48(hdr[10])
		n := int(hdr[11])<<8 | int(hdr[12])

		// 版本检查
		if c.haveVers && vers != c.vers {
			c.sendAlert(alertProtocolVersion)
			msg := fmt.Sprintf("received record with version %x when expecting version %x", vers, c.vers)
			return c.in.setErrorLocked(c.newRecordHeaderError(c.remoteAddr, msg))
		}
		if !c.haveVers {
			// 协议识别启发式：首次收到记录时，通过版本号区分 DTLCP/TLCP 与 DTLS。
			// DTLCP 沿用 TLCP 版本号 0x0101，TLS 为 0x0301~0x0304，均 < 0x1000；
			// DTLS 1.0(0xFEFF)/1.2(0xFEFD) 均 >= 0x1000。
			// 配合首条记录必须为 Alert 或 Handshake 的类型检查，可有效防止 DTLS 客户端误连。
			//
			// 判定只针对连接的首条记录（epoch=0 且 seq_num=0）：会话重用时服务端会把
			// ServerHello 与随后的 CCS/Finished 合并到同一个 UDP 数据报中，这些后续记录
			// 出现在同一个 rawInputBuf 里，此时 haveVers 尚未设置，不能按首记录判定。
			if epoch == 0 && seqNum == 0 &&
				((typ != recordTypeAlert && typ != recordTypeHandshake) || vers >= 0x1000) {
				return c.in.setErrorLocked(c.newRecordHeaderError(c.remoteAddr, "first record does not look like a TLCP handshake"))
			}
		}

		// 长度检查
		if n > maxCiphertext {
			c.sendAlert(alertRecordOverflow)
			msg := fmt.Sprintf("oversized record received with length %d", n)
			return c.in.setErrorLocked(c.newRecordHeaderError(c.remoteAddr, msg))
		}
		if recordHeaderLen+n > len(c.rawInputBuf) {
			return c.in.setErrorLocked(c.newRecordHeaderError(c.remoteAddr, fmt.Sprintf("record length %d exceeds datagram", n)))
		}

		// 将 epoch + seq_num 写入 in.seq（供 decrypt 中的 MAC/AAD 使用）
		c.in.seq[0] = hdr[3]
		c.in.seq[1] = hdr[4]
		c.in.seq[2] = hdr[5]
		c.in.seq[3] = hdr[6]
		c.in.seq[4] = hdr[7]
		c.in.seq[5] = hdr[8]
		c.in.seq[6] = hdr[9]
		c.in.seq[7] = hdr[10]

		// 解密 + MAC 验证
		record := c.rawInputBuf[:recordHeaderLen+n]
		data, typ, err := c.in.decrypt(record)
		if err != nil {
			return c.in.setErrorLocked(c.sendAlert(err.(alert)))
		}

		// 重放检查（解密成功后执行，RFC 6347 §4.1.2.6）
		if epoch < c.readEpoch {
			// 旧 epoch：静默丢弃，继续下一条记录
			c.rawInputBuf = c.rawInputBuf[recordHeaderLen+n:]
			continue
		}
		if epoch > c.readEpoch {
			c.readEpoch = epoch
			c.readSeq = 0
			windowSize := defaultReplayWindowSize
			if c.config != nil && c.config.ReplayWindow > 0 {
				windowSize = c.config.ReplayWindow
			}
			c.replayWindow = newReplayWindow(windowSize)
		}
		if !c.replayWindow.check(seqNum) {
			// 重放检测：静默丢弃
			c.rawInputBuf = c.rawInputBuf[recordHeaderLen+n:]
			continue
		}

		if len(data) > maxPlaintext {
			return c.in.setErrorLocked(c.sendAlert(alertRecordOverflow))
		}

		// 应用数据必须总是受保护的
		if c.in.cipher == nil && typ == recordTypeApplicationData {
			return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
		}

		if typ != recordTypeAlert && typ != recordTypeChangeCipherSpec && len(data) > 0 {
			c.retryCount = 0
		}

		// 消费当前记录，将 rawInputBuf 指针前移
		c.rawInputBuf = c.rawInputBuf[recordHeaderLen+n:]

		switch typ {
		default:
			return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))

		case recordTypeAlert:
			if len(data) != 2 {
				return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
			}
			if alert(data[1]) == alertCloseNotify {
				return c.in.setErrorLocked(io.EOF)
			}
			switch data[0] {
			case alertLevelWarning:
				c.rawInputBuf = nil
				return c.retryReadRecord(expectChangeCipherSpec)
			case alertLevelError:
				return c.in.setErrorLocked(&net.OpError{Op: "remote error", Err: alert(data[1])})
			default:
				return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
			}

		case recordTypeChangeCipherSpec:
			if len(data) != 1 || data[0] != 1 {
				return c.in.setErrorLocked(c.sendAlert(alertDecodeError))
			}
			// 2*MSL 驻留：握手完成后收到旧 epoch CCS，重传最后一 flight
			if handshakeComplete && !c.dwellDeadline.IsZero() {
				if time.Now().Before(c.dwellDeadline) && len(c.flightRetransmit) > 0 {
					c.pconn.WriteTo(c.flightRetransmit, c.remoteAddr)
					continue
				}
				c.dwellDeadline = time.Time{}
				c.flightRetransmit = nil
			}
			// 非期望 CCS 且 handBuf 有待处理数据：延迟 CCS。
			// CKE+CCS+Finished 同数据报时，CCS 应在 establishKeys 之后
			// 由 readChangeCipherSpec 处理，避免 nextCipher 未就绪。
			if !expectChangeCipherSpec && c.handBuf.Len() > 0 {
				c.in.deferredCCS = true
				return nil
			}
			if !expectChangeCipherSpec {
				return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
			}
			if err := c.in.changeCipherSpec(); err != nil {
				return c.in.setErrorLocked(c.sendAlert(err.(alert)))
			}
			expectChangeCipherSpec = false
			c.readEpoch++
			c.readSeq = 0
			// epoch 变更后重建重放窗口，避免新旧 epoch 序列号混淆
			windowSize := defaultReplayWindowSize
			if c.config != nil && c.config.ReplayWindow > 0 {
				windowSize = c.config.ReplayWindow
			}
			c.replayWindow = newReplayWindow(windowSize)
			// CCS 后如果还有数据（如 Finished 在同一数据报中），继续处理
			if len(c.rawInputBuf) > 0 {
				continue
			}
			return nil

		case recordTypeApplicationData:
			if !handshakeComplete || expectChangeCipherSpec {
				return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
			}
			// 收到应用数据，退出 2*MSL 驻留期
			if !c.dwellDeadline.IsZero() {
				c.dwellDeadline = time.Time{}
				c.flightRetransmit = nil
			}
			if len(data) == 0 {
				continue
			}
			c.readBuf = data
			return nil

		case recordTypeHandshake:
			// 2*MSL 驻留：握手完成后收到重传 Finished，重传最后一 flight
			if handshakeComplete && !c.dwellDeadline.IsZero() && time.Now().Before(c.dwellDeadline) {
				if len(c.flightRetransmit) > 0 {
					c.pconn.WriteTo(c.flightRetransmit, c.remoteAddr)
				}
				continue
			}
			if len(data) == 0 || expectChangeCipherSpec {
				return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
			}
			c.handBuf.Write(data)
			// 如果还有未处理记录，继续循环处理
			if len(c.rawInputBuf) > 0 {
				continue
			}
			return nil
		}
	}
}

// retryReadRecord 递归进入 readRecordOrCCS 以丢弃非推进记录。
func (c *Conn) retryReadRecord(expectChangeCipherSpec bool) error {
	c.retryCount++
	if c.retryCount > maxUselessRecords {
		c.sendAlert(alertUnexpectedMessage)
		return c.in.setErrorLocked(errors.New("dtlcp: too many ignored records"))
	}
	return c.readRecordOrCCS(expectChangeCipherSpec)
}

// =============================================================================
// Conn — 发送与刷新
// =============================================================================

// write 将数据写入底层 UDP socket。
func (c *Conn) write(data []byte) (int, error) {
	if c.buffering {
		c.sendBuf = append(c.sendBuf, data...)
		return len(data), nil
	}
	n, err := c.pconn.WriteTo(data, c.remoteAddr)
	return n, err
}

// flush 刷新发送缓冲区。
func (c *Conn) flush() (int, error) {
	if len(c.sendBuf) == 0 {
		return 0, nil
	}
	n, err := c.pconn.WriteTo(c.sendBuf, c.remoteAddr)
	c.sendBuf = nil
	c.buffering = false
	return n, err
}

// =============================================================================
// Conn — 记录层写入
// =============================================================================

// maxPayloadSizeForWrite 返回下一次写入的最大 payload 长度。
// DTLCP 使用 PMTU 代替 TCP MSS。
func (c *Conn) maxPayloadSizeForWrite(typ recordType) int {
	pmtu := c.config.PMTU
	if pmtu <= 0 {
		pmtu = 1400
	}
	maxPayload := pmtu - recordHeaderLen - c.out.explicitNonceLen()
	// AEAD overhead
	if c.out.cipher != nil {
		switch ciph := c.out.cipher.(type) {
		case aead:
			maxPayload -= ciph.Overhead()
		case cbcMode:
			maxPayload -= c.out.mac.Size()
		}
	}
	if maxPayload > maxPlaintext {
		maxPayload = maxPlaintext
	}
	if maxPayload < 1 {
		maxPayload = 1
	}
	return maxPayload
}

// writeRecordLocked 写入一条 DTLCP 记录并更新记录层状态。
func (c *Conn) writeRecordLocked(typ recordType, data []byte) (int, error) {
	outBufPtr := outBufPool.Get().(*[]byte)
	outBuf := *outBufPtr
	defer func() {
		*outBufPtr = outBuf
		outBufPool.Put(outBufPtr)
	}()

	var n int
	for len(data) > 0 {
		m := len(data)
		if maxPayload := c.maxPayloadSizeForWrite(typ); m > maxPayload {
			m = maxPayload
		}

		// 记录头由后续逐字节填充，直接复用池中 buffer
		outBuf = outBuf[:recordHeaderLen]

		// 先编码 epoch + seq 到 out.seq（供 encrypt 中的 MAC/AAD 使用）
		c.setWriteSeq()

		vers := c.vers
		if vers == 0 {
			vers = VersionTLCP
		}

		// 写入 13 字节 DTLCP 头
		outBuf[0] = byte(typ)
		outBuf[1] = byte(vers >> 8)
		outBuf[2] = byte(vers)
		outBuf[3] = byte(c.writeEpoch >> 8)
		outBuf[4] = byte(c.writeEpoch)
		outBuf[5] = byte(c.writeSeq >> 40)
		outBuf[6] = byte(c.writeSeq >> 32)
		outBuf[7] = byte(c.writeSeq >> 24)
		outBuf[8] = byte(c.writeSeq >> 16)
		outBuf[9] = byte(c.writeSeq >> 8)
		outBuf[10] = byte(c.writeSeq)
		outBuf[11] = byte(m >> 8)
		outBuf[12] = byte(m)

		var err error
		outBuf, err = c.out.encrypt(outBuf, data[:m], c.config.rand())
		if err != nil {
			return n, err
		}

		// 加密后长度字段更新为实际载荷长度（包含显式 nonce、密文和 AEAD 标签）。
		// DTLCP 长度字段不在 AAD 范围内（record[:11]），可在加密后安全更新。
		encLen := len(outBuf) - recordHeaderLen
		if encLen != m {
			outBuf[11] = byte(encLen >> 8)
			outBuf[12] = byte(encLen)
		}

		if _, err := c.write(outBuf); err != nil {
			return n, err
		}
		n += m
		c.writeSeq++
		data = data[m:]
	}

	// 发送 CCS 后更换密码参数
	if typ == recordTypeChangeCipherSpec {
		if err := c.out.changeCipherSpec(); err != nil {
			return n, c.sendAlertLocked(err.(alert))
		}
		c.writeEpoch++
		c.writeSeq = 0
	}

	return n, nil
}

// =============================================================================
// Conn — 握手记录层辅助方法（Phase 4 完善）
// =============================================================================

// writeHandshakeRecord 写入一条握手记录，支持自动分片（RFC 6347 §4.2.3）。
// 消息超过 PMTU 时自动拆分为多个带 fragment_offset/fragment_length 的分片记录。
func (c *Conn) writeHandshakeRecord(msg handshakeMessage, transcript transcriptHash) (int, error) {
	c.out.Lock()
	defer c.out.Unlock()

	data, err := msg.marshal()
	if err != nil {
		return 0, err
	}
	// 转录哈希始终使用完整消息（未分片时的格式）
	if transcript != nil {
		transcript.Write(data)
	}

	// 检查是否需要分片
	maxPayload := c.maxPayloadSizeForWrite(recordTypeHandshake)
	if len(data) <= maxPayload {
		n, err := c.writeRecordLocked(recordTypeHandshake, data)
		if c.config.EnableDebug {
			fmt.Printf("[write] %v, len=%v, success=%v\n", HandshakeMessageTypeName(msg.messageType()), len(data), err == nil)
			msg.debug()
		}
		return n, err
	}

	// 握手消息太大，需要分片
	// data 格式: [msgType:1][bodyLen:3][msgSeq:2][fragOff:3][fragLen:3][body:N]
	if len(data) <= dtlcpHeaderLen {
		return 0, errors.New("dtlcp: handshake message too short for fragmentation")
	}
	hdr := data[:dtlcpHeaderLen] // 12 字节：msgType[1]+bodyLen[3]+msgSeq[2]+fragOff[3]+fragLen[3]
	body := data[dtlcpHeaderLen:]
	bodyLen := uint24(len(body))
	msgSeq := uint16(hdr[4])<<8 | uint16(hdr[5])

	maxFragBody := maxPayload - dtlcpHeaderLen
	if maxFragBody <= 0 {
		return 0, errors.New("dtlcp: PMTU too small for handshake fragment header")
	}

	var totalN int
	msgType := hdr[0]
	for offset := uint24(0); offset < bodyLen; {
		fragEnd := offset + uint24(maxFragBody)
		if fragEnd > bodyLen {
			fragEnd = bodyLen
		}
		fragLen := fragEnd - offset
		fragBody := body[offset:fragEnd]

		// 构造分片握手消息头
		var fragHdr [dtlcpHeaderLen]byte
		fragHdr[0] = msgType
		fragHdr[1] = byte(bodyLen >> 16)
		fragHdr[2] = byte(bodyLen >> 8)
		fragHdr[3] = byte(bodyLen)
		fragHdr[4] = byte(msgSeq >> 8)
		fragHdr[5] = byte(msgSeq)
		fragHdr[6] = byte(offset >> 16)
		fragHdr[7] = byte(offset >> 8)
		fragHdr[8] = byte(offset)
		fragHdr[9] = byte(fragLen >> 16)
		fragHdr[10] = byte(fragLen >> 8)
		fragHdr[11] = byte(fragLen)

		fragData := append(fragHdr[:], fragBody...)
		n, err := c.writeRecordLocked(recordTypeHandshake, fragData)
		totalN += n
		if err != nil {
			return totalN, err
		}
		offset = fragEnd
	}

	if c.config.EnableDebug {
		fmt.Printf("[write] %v (fragmented, body=%d, fragments=%d), success=%v\n",
			HandshakeMessageTypeName(msg.messageType()), bodyLen, (bodyLen+uint24(maxFragBody)-1)/uint24(maxFragBody), err == nil)
	}
	return totalN, nil
}

// writeChangeCipherRecord 写入 ChangeCipherSpec 记录并切换密码参数。
func (c *Conn) writeChangeCipherRecord() error {
	c.out.Lock()
	defer c.out.Unlock()
	_, err := c.writeRecordLocked(recordTypeChangeCipherSpec, []byte{1})
	return err
}

// readHandshake 从记录层读取下一个 DTLCP 握手消息（支持分片重组）。
//
// 使用迭代循环替代递归，防止恶意对端通过大量微小分片触发栈溢出。
// fragmentReads 计数器限制单条消息的最大分片迭代次数，超过 maxHandshakeFragments 时返回错误。
func (c *Conn) readHandshake(transcript transcriptHash) (interface{}, error) {
	fragmentReads := 0
	for {
		fragmentReads++
		if fragmentReads > maxHandshakeFragments {
			c.sendAlertLocked(alertUnexpectedMessage)
			return nil, c.in.setErrorLocked(errors.New("dtlcp: too many fragment reads for a single handshake message"))
		}

		for c.handBuf.Len() < dtlcpHeaderLen {
			if err := c.readRecord(); err != nil {
				return nil, err
			}
		}

		data := c.handBuf.Bytes()
		bodyLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
		fragOff := int(data[6])<<16 | int(data[7])<<8 | int(data[8])
		fragLen := int(data[9])<<16 | int(data[10])<<8 | int(data[11])

		if bodyLen > maxHandshake {
			c.sendAlertLocked(alertInternalError)
			return nil, c.in.setErrorLocked(fmt.Errorf("dtlcp: handshake message of length %d bytes exceeds maximum of %d bytes", bodyLen, maxHandshake))
		}
		if fragOff+fragLen > bodyLen {
			c.sendAlertLocked(alertDecodeError)
			return nil, c.in.setErrorLocked(fmt.Errorf("dtlcp: fragment out of bounds: offset %d + length %d > total %d", fragOff, fragLen, bodyLen))
		}

		// 等待足够的分片数据
		for c.handBuf.Len() < dtlcpHeaderLen+fragLen {
			if err := c.readRecord(); err != nil {
				return nil, err
			}
		}

		data = c.handBuf.Next(dtlcpHeaderLen + fragLen)
		if c.config.EnableDebug {
			fmt.Printf("[read] %v, len=%v\n", HandshakeMessageTypeName(data[0]), len(data))
		}

		// 分片重组支持（非分片消息直接处理）
		if fragLen < bodyLen || fragOff > 0 {
			// 清理过期分片缓冲区
			c.cleanupStaleFragments(fragmentTimeout)

			// 消息被分片，存到 pendingFragments 中
			msgSeq := uint16(data[4])<<8 | uint16(data[5])
			fb, exists := c.pendingFragments[msgSeq]
			if !exists {
				fb = newFragmentBuffer(uint24(bodyLen))
				c.pendingFragments[msgSeq] = fb
			}
			fb.addFragment(uint24(fragOff), uint24(fragLen), data[dtlcpHeaderLen:])
			if !fb.complete() {
				// 分片未收齐，继续迭代读取
				continue
			}
			// 分片收齐，重组消息
			fragmentData := fb.assembled()
			// 用原始头部的 type + msgSeq + fragOff/fragLen 重新构造完整消息
			fullHeader := make([]byte, dtlcpHeaderLen, dtlcpHeaderLen+len(fragmentData))
			fullHeader[0] = data[0]
			fullHeader[1] = data[1]
			fullHeader[2] = data[2]
			fullHeader[3] = data[3]
			fullHeader[4] = data[4]
			fullHeader[5] = data[5]
			// fragOff=0, fragLen=bodyLen
			fullHeader[6] = 0
			fullHeader[7] = 0
			fullHeader[8] = 0
			fullHeader[9] = data[1]
			fullHeader[10] = data[2]
			fullHeader[11] = data[3]
			data = append(fullHeader, fragmentData...)
			delete(c.pendingFragments, msgSeq)
		}

		var m handshakeMessage
		switch data[0] {
		case typeClientHello:
			m = new(clientHelloMsg)
		case typeHelloVerifyRequest:
			m = new(helloVerifyRequestMsg)
		case typeServerHello:
			m = new(serverHelloMsg)
		case typeCertificate:
			// IBC 套件使用同类型的 IBC 变体 Certificate 消息，
			// 报文结构与 X.509 版本不同，按已协商的密码套件区分。
			if cipherSuiteIsIBC(c.cipherSuite) {
				m = new(ibcCertificateMsg)
			} else {
				m = new(certificateMsg)
			}
		case typeServerKeyExchange:
			m = new(serverKeyExchangeMsg)
		case typeCertificateRequest:
			m = new(certificateRequestMsg)
		case typeServerHelloDone:
			m = new(serverHelloDoneMsg)
		case typeClientKeyExchange:
			m = new(clientKeyExchangeMsg)
		case typeCertificateVerify:
			m = new(certificateVerifyMsg)
		case typeFinished:
			m = new(finishedMsg)
		default:
			return nil, c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
		}

		data = append([]byte(nil), data...)

		if !m.unmarshal(data) {
			return nil, c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
		}
		if transcript != nil {
			transcript.Write(data)
		}
		if c.config.EnableDebug {
			m.debug()
		}
		return m, nil
	}
}

// fragmentTimeout 是待重组分片的超时时间。
// 超过此时间未收齐的分片序列将被清理。
const fragmentTimeout = 30 * time.Second

// cleanupStaleFragments 清理 pendingFragments 中过期的分片重组缓冲区。
// 每次进入分片重组路径时调用，防止不完整分片永久占用内存。
func (c *Conn) cleanupStaleFragments(timeout time.Duration) {
	now := time.Now()
	for seq, fb := range c.pendingFragments {
		if now.Sub(fb.receivedAt) > timeout {
			delete(c.pendingFragments, seq)
		}
	}
}

// clearPendingFragments 清空所有等待重组的分片缓冲区。
// 在握手完成时调用，释放不需要的内存。
func (c *Conn) clearPendingFragments() {
	for k := range c.pendingFragments {
		delete(c.pendingFragments, k)
	}
}

// =============================================================================
// Conn — 报警发送
// =============================================================================

// sendAlertLocked 发送一条 DTLCP 告警消息（需持有 out.Lock）。
func (c *Conn) sendAlertLocked(err alert) error {
	switch err {
	case alertNoRenegotiation, alertCloseNotify:
		c.tmp[0] = alertLevelWarning
	default:
		c.tmp[0] = alertLevelError
	}
	c.tmp[1] = byte(err)

	_, writeErr := c.writeRecordLocked(recordTypeAlert, c.tmp[0:2])
	if err == alertCloseNotify {
		return writeErr
	}

	return c.out.setErrorLocked(&net.OpError{Op: "local error", Err: err})
}

// sendAlert 发送 DTLCP 告警。
func (c *Conn) sendAlert(err alert) error {
	c.out.Lock()
	defer c.out.Unlock()
	if c.config != nil && c.config.OnAlert != nil {
		c.config.OnAlert(uint8(err), c)
	}
	return c.sendAlertLocked(err)
}

// =============================================================================
// Conn — 关闭
// =============================================================================

var errShutdown = errors.New("dtlcp: protocol is shutdown")
var errEarlyCloseWrite = errors.New("dtlcp: CloseWrite called before handshake complete")

// Close 关闭连接。
// 实现顺序为：先关闭底层 pconn 以解阻塞正在 I/O 中的 Read/ReadFrom/Write/WriteTo，
// 再等待所有活跃调用退出后清理资源；若握手已完成，最后调用 closeNotify 尝试发送 close_notify
// 告警通知对端，但由于此时 pconn 已先被关闭，该发送通常必然失败（代码注释亦承认这一点）。
//
// 返回值：
//   - error：连接此前已被关闭时返回 net.ErrClosed；若握手已完成，通常会返回包装后的 close_notify 发送失败错误（连接仍已被关闭）；其余情况返回 nil。
func (c *Conn) Close() error {
	// 设置关闭标记，阻止新调用进入
	for {
		x := atomic.LoadInt32(&c.activeCall)
		if x&1 != 0 {
			return net.ErrClosed
		}
		if atomic.CompareAndSwapInt32(&c.activeCall, x, x|1) {
			break
		}
	}

	// 先关闭底层连接，解阻塞正在 pconn.ReadFrom()/pconn.WriteTo() 上等待的 I/O 调用
	c.pconn.Close()

	// 等待所有活跃调用退出（短暂等待，因为 I/O 已被解阻塞）
	for atomic.LoadInt32(&c.activeCall) > 1 {
	}

	// closeNotify 在 pconn 已关闭后调用会失败，但非致命
	var alertErr error
	if c.handshakeComplete() {
		if err := c.closeNotify(); err != nil {
			alertErr = fmt.Errorf("dtlcp: failed to send closeNotify alert (but connection was closed anyway): %w", err)
		}
	}
	setZero(c.workKey)
	c.workKey = nil

	return alertErr
}

// CloseWrite 发送 close_notify 告警以标记写入结束，仅握手完成后可调用，读取方向不受影响。
// 调用后 Write 会因 close_notifySent 标记返回 "dtlcp: protocol is shutdown" 而失败，但 WriteTo 不检查该标记、仍可继续发送数据报，且发送 close_notify 也不会设置 out.err；如需彻底停止发送，请直接调用 Close。
//
// 返回值：
//   - error：握手尚未完成时返回 "dtlcp: CloseWrite called before handshake complete"；否则返回 close_notify 的发送结果，发送成功为 nil，重复调用返回首次发送时的错误。
func (c *Conn) CloseWrite() error {
	if !c.handshakeComplete() {
		return errEarlyCloseWrite
	}
	return c.closeNotify()
}

func (c *Conn) closeNotify() error {
	c.out.Lock()
	defer c.out.Unlock()

	if !c.closeNotifySent {
		c.SetWriteDeadline(time.Now().Add(time.Second * 5))
		c.closeNotifyErr = c.sendAlertLocked(alertCloseNotify)
		c.closeNotifySent = true
		c.SetWriteDeadline(time.Now())
	}
	return c.closeNotifyErr
}

// =============================================================================
// Conn — 数据读写（net.Conn 接口）
// =============================================================================

// Read 从连接中读取解密后的数据，实现 io.Reader 接口。
// 如果握手尚未完成，Read 会自动触发握手。
// Read 以 DTLCP 记录为消费单位：读取并解密一条应用数据记录后复制到 b，未能复制的剩余明文保留到下次读取。
//
// 参数：
//   - b：接收缓冲区；长度为 0 时返回 (0, nil)，不读取任何数据；该判断位于自动握手之后，因此未握手时会先触发握手，握手失败则返回握手错误。
//
// 返回值：
//   - int：成功读取并复制到 b 的字节数，可能小于 len(b)，未复制的部分不会丢失。
//   - error：读取失败时返回非 nil；连接已关闭时返回 net.ErrClosed，对端发送 close_notify 时返回 io.EOF，底层超时等错误原样返回；当本轮已复制数据且缓冲区中已缓存告警记录时，可能在 n > 0 的同时返回对应错误。
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

// Write 加密数据并写入连接，实现 io.Writer 接口。
// 如果握手尚未完成，Write 会自动触发握手。
// Write 会将大块数据自动切分为多条 DTLCP 记录发送。
//
// 参数：
//   - b：待发送数据，长度不受限制；超过单条记录可承载的最大载荷时会按底层 PMTU 自动切分为多条记录依次发送。
//
// 返回值：
//   - int：成功写入底层连接的明文字节数，发生错误时可能小于 len(b)。
//   - error：写入失败时返回非 nil；连接已关闭时返回 net.ErrClosed；握手未完成时返回内部错误；已发送过 close_notify 时返回 "dtlcp: protocol is shutdown"；记录层已存在永久错误时返回该错误。
func (c *Conn) Write(b []byte) (int, error) {
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

	c.out.Lock()
	defer c.out.Unlock()

	if err := c.out.err; err != nil {
		return 0, err
	}

	if !c.handshakeComplete() {
		return 0, alertInternalError
	}

	if c.closeNotifySent {
		return 0, errShutdown
	}

	n, err := c.writeRecordLocked(recordTypeApplicationData, b)
	return n, c.out.setErrorLocked(err)
}

// =============================================================================
// Conn — ReadFrom / WriteTo（net.PacketConn 风格接口）
// =============================================================================

// ReadFrom 解密一条 DTLCP 记录并返回明文和发送方地址，实现 net.PacketConn 接口。
// 如果握手尚未完成，ReadFrom 会自动触发握手。
// 每次调用都会重新读取一个数据报：同一数据报内若含多条应用记录，只有第一条会被返回，其余不会保留。
// 非应用数据记录（握手、告警）、解密或 MAC 校验失败的记录、重放报文、旧 epoch 报文以及来自其他地址的数据报都会被静默丢弃，并继续等待下一条应用数据。
//
// 参数：
//   - p：接收缓冲区，需足够大以容纳单条记录的明文（明文上限 maxPlaintext，16384 字节）；但明文长度上限校验只在 readRecordOrCCS 中进行，ReadFrom 只校验不超过数据报大小，因此缓冲区过小时多余明文会被 copy 静默截断丢弃且不返回错误。
//
// 返回值：
//   - int：复制到 p 的明文字节数，可能小于该条记录的明文长度。
//   - net.Addr：对端地址，即握手协商的对端地址，而非本条数据报的发送方地址。
//   - error：读取失败时返回非 nil；连接已关闭时返回 net.ErrClosed；对端发送 close_notify 告警时返回 io.EOF；底层超时等错误原样返回；解密或 MAC 校验失败的记录不会返回错误，而是被静默丢弃并继续读取。
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

	c.in.Lock()
	defer c.in.Unlock()

	for {
		if err = c.readDatagram(); err != nil {
			return 0, nil, err
		}

		if len(c.rawInputBuf) < recordHeaderLen {
			continue
		}

		hdr := c.rawInputBuf[:recordHeaderLen]
		_ = uint16(hdr[1])<<8 | uint16(hdr[2])
		epoch := uint16(hdr[3])<<8 | uint16(hdr[4])
		seqNum := uint48(hdr[5])<<40 | uint48(hdr[6])<<32 | uint48(hdr[7])<<24 |
			uint48(hdr[8])<<16 | uint48(hdr[9])<<8 | uint48(hdr[10])
		recLen := int(hdr[11])<<8 | int(hdr[12])

		if recordHeaderLen+recLen > len(c.rawInputBuf) {
			continue
		}

		// 设置 in.seq 供 decrypt 使用
		c.in.seq[0] = hdr[3]
		c.in.seq[1] = hdr[4]
		c.in.seq[2] = hdr[5]
		c.in.seq[3] = hdr[6]
		c.in.seq[4] = hdr[7]
		c.in.seq[5] = hdr[8]
		c.in.seq[6] = hdr[9]
		c.in.seq[7] = hdr[10]

		record := c.rawInputBuf[:recordHeaderLen+recLen]
		plaintext, actualTyp, err := c.in.decrypt(record)
		if err != nil {
			continue
		}

		// 重放检查（解密成功后执行，RFC 6347 §4.1.2.6）
		if epoch < c.readEpoch {
			// 旧 epoch：静默丢弃
			continue
		}
		if epoch > c.readEpoch {
			c.readEpoch = epoch
			c.readSeq = 0
			windowSize := defaultReplayWindowSize
			if c.config != nil && c.config.ReplayWindow > 0 {
				windowSize = c.config.ReplayWindow
			}
			c.replayWindow = newReplayWindow(windowSize)
		}
		if !c.replayWindow.check(seqNum) {
			// 重放检测：静默丢弃
			continue
		}

		if actualTyp != recordTypeApplicationData {
			// 非应用数据由内部处理
			switch actualTyp {
			case recordTypeAlert:
				if len(plaintext) == 2 && alert(plaintext[1]) == alertCloseNotify {
					return 0, c.remoteAddr, io.EOF
				}
			case recordTypeHandshake:
				c.handBuf.Write(plaintext)
			}
			continue
		}

		addr = c.remoteAddr
		n = copy(p, plaintext)
		return n, addr, nil
	}
}

// WriteTo 加密并发送一条 DTLCP 应用数据记录到指定地址，实现 net.PacketConn 接口。
// 如果握手尚未完成，WriteTo 会自动触发握手。
// 每次 WriteTo 调用独立发送其数据，通常不会与相邻调用合并；当数据超过单条记录可承载的最大载荷时会被拆分为多条记录。
//
// 参数：
//   - p：待发送数据，长度不受限制，但不应超过接收端的缓冲区容量。
//   - addr：目标地址，不能为 nil（实现会调用 addr.String()，为 nil 会 panic）；其字符串形式必须与握手协商的对端地址完全一致，否则返回错误。
//
// 返回值：
//   - int：成功写入底层连接的明文字节数，发生错误时可能小于 len(p)。
//   - error：写入失败时返回非 nil；addr 与对端地址不一致时返回 "dtlcp: WriteTo addr mismatch"；连接已关闭时返回 net.ErrClosed。
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
	if addr.String() != c.remoteAddr.String() {
		return 0, errors.New("dtlcp: WriteTo addr mismatch")
	}

	c.out.Lock()
	defer c.out.Unlock()
	return c.writeRecordLocked(recordTypeApplicationData, p)
}

// =============================================================================
// Conn — 握手
// =============================================================================

// Handshake 运行客户端或服务端握手协议（如果尚未完成）。
// 大多数情况下无需显式调用——Read/Write/ReadFrom/WriteTo 会自动触发握手。
// Handshake 内部使用 context.Background 作为上下文，如需取消或超时控制请使用 HandshakeContext。
//
// 返回值：
//   - error：握手失败时返回非 nil；握手已完成时返回 nil；一旦某次握手失败，后续调用会返回相同的错误。
func (c *Conn) Handshake() error {
	return c.HandshakeContext(context.Background())
}

// HandshakeContext 在给定上下文中运行握手协议。
// 若握手已经完成，直接返回 nil。
//
// 参数：
//   - ctx：握手上下文，不能为空；可用于取消握手或设置超时，若 ctx 被取消，底层 net.PacketConn 会被关闭，该连接将不可再使用。
//
// 返回值：
//   - error：握手失败时返回非 nil；握手已完成时返回 nil；一旦某次握手失败，后续调用会返回相同的错误。
func (c *Conn) HandshakeContext(ctx context.Context) error {
	return c.handshakeContext(ctx)
}

func (c *Conn) handshakeContext(ctx context.Context) (ret error) {
	if c.handshakeComplete() {
		return nil
	}

	if c.handshakeFn == nil {
		return errors.New("dtlcp: handshake not implemented (Phase 4)")
	}

	handshakeCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	if ctx.Done() != nil {
		done := make(chan struct{})
		interruptRes := make(chan error, 1)
		defer func() {
			close(done)
			if ctxErr := <-interruptRes; ctxErr != nil {
				ret = ctxErr
			}
		}()
		go func() {
			select {
			case <-handshakeCtx.Done():
				c.pconn.Close()
				interruptRes <- handshakeCtx.Err()
			case <-done:
				interruptRes <- nil
			}
		}()
	}

	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	if err := c.handshakeErr; err != nil {
		return err
	}
	if c.handshakeComplete() {
		return nil
	}

	c.in.Lock()
	defer c.in.Unlock()

	c.handshakeErr = c.handshakeFn(handshakeCtx)
	if c.handshakeErr == nil {
		c.handshakes++
		c.clearPendingFragments()
	} else {
		c.flush()
	}

	if c.handshakeErr == nil && !c.handshakeComplete() {
		c.handshakeErr = errors.New("dtlcp: internal error: handshake should have had a result")
	}
	if c.handshakeErr != nil && c.handshakeComplete() {
		panic("dtlcp: internal error: handshake returned an error but is marked successful")
	}

	return c.handshakeErr
}

// handshakeComplete 返回握手是否已完成。
func (c *Conn) handshakeComplete() bool {
	return c.hsState.Load() == int32(stateFinished)
}

// =============================================================================
// Conn — 连接状态
// =============================================================================

// ConnectionState 返回连接的基本 DTLCP 详情，包括协议版本、密码套件、对端证书等。
// 该方法是快照，不会触发握手。
//
// 返回值：
//   - ConnectionState：连接状态快照；握手未完成时多数字段为零值，其中 HandshakeComplete 表示握手是否已完成，Version/CipherSuite/NegotiatedProtocol/PeerCertificates/VerifiedChains 需握手完成后才有意义。
func (c *Conn) ConnectionState() ConnectionState {
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()
	return c.connectionStateLocked()
}

func (c *Conn) connectionStateLocked() ConnectionState {
	var state ConnectionState
	state.HandshakeComplete = c.handshakeComplete()
	state.Version = c.vers
	state.DidResume = c.didResume
	state.ServerName = c.serverName
	state.CipherSuite = c.cipherSuite
	state.NegotiatedProtocol = c.clientProtocol
	state.PeerCertificates = c.peerCertificates
	state.VerifiedChains = c.verifiedChains
	state.PeerIBCIdentity = c.peerIBCIdentity
	state.PeerIBCSysParams = c.peerIBCSysParams
	return state
}

// VerifyHostname 检查对端证书链对指定主机名是否有效。
// 仅客户端可调用，且要求握手已完成并通过证书链验证；实际使用对端证书链中的首张（叶子）证书进行匹配。
//
// 参数：
//   - host：要验证的主机名，可为 DNS 名称，也可为 IP 地址字面量（IPv6 地址可用方括号包裹）；应与证书 SAN 中的 DNS 名或 IP 地址一致，传空字符串通常会导致匹配失败。
//
// 返回值：
//   - error：在服务端连接上调用返回 "dtlcp: VerifyHostname called on DTLCP server connection"；握手尚未完成返回 "dtlcp: handshake has not yet been performed"；握手未验证证书链（如 InsecureSkipVerify）返回 "dtlcp: handshake did not verify certificate chain"；host 与证书不匹配时返回证书校验错误。
func (c *Conn) VerifyHostname(host string) error {
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()
	if !c.isClient {
		return errors.New("dtlcp: VerifyHostname called on DTLCP server connection")
	}
	if !c.handshakeComplete() {
		return errors.New("dtlcp: handshake has not yet been performed")
	}
	if len(c.verifiedChains) == 0 {
		return errors.New("dtlcp: handshake did not verify certificate chain")
	}
	return c.peerCertificates[0].VerifyHostname(host)
}
