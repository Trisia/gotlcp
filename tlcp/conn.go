// Copyright (c) 2022 QuanGuanyu
// gotlcp is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

// TLCP 底层连接对象 以及 记录层对象

package tlcp

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

// Conn 表示一个TLCP连接，实现了 net.Conn 接口
type Conn struct {
	// constant
	conn        net.Conn                    // 原始连接对象
	isClient    bool                        // 是否是客户端
	handshakeFn func(context.Context) error // 握手实现 clientHandshake or serverHandshake

	// handshakeStatus is 1 if the connection is currently transferring
	// application data (i.e. is not currently processing a handshake).
	// handshakeStatus == 1 implies handshakeErr == nil.
	// This field is only to be accessed with sync/atomic.
	handshakeStatus uint32
	// constant after handshake; protected by handshakeMutex
	handshakeMutex sync.Mutex
	handshakeErr   error   // error resulting from handshake
	vers           uint16  // TLCP 版本号
	haveVers       bool    // 被协商出的TLCP版本号
	config         *Config // TLCP连接配置
	// handshakes counts the number of handshakes performed on the
	// connection so far. If renegotiation is disabled then this is either
	// zero or one.
	handshakes        int
	didResume         bool                  // 表示是否为会话重用
	cipherSuite       uint16                // 密码套件ID
	activeCertHandles []*activeCert         // 证书缓存引用，在运行期间持有该引用维持缓存，用于减少重复的DER证书解析造成而外性能损耗。
	peerCertificates  []*smx509.Certificate // 对端数字证书列表
	// verifiedChains 用于验证对端证书的根证书链
	verifiedChains [][]*smx509.Certificate
	// peerIBCIdentity / peerIBCSysParams 仅 IBC/IBSDH 套件下非空，
	// peerIBCIdentity 为对端标识内容（identityData），peerIBCSysParams 为命中的本地信任池参数。
	peerIBCIdentity  []byte
	peerIBCSysParams *IBCSysParams
	// serverName 由客户端Hello消息SNI扩展中指定的服务器名（域名）
	serverName string

	// closeNotifyErr is any error from sending the alertCloseNotify record.
	closeNotifyErr error
	// closeNotifySent is true if the Conn attempted to send an
	// alertCloseNotify record.
	closeNotifySent bool

	// clientFinished 和 serverFinished 包含了客户端或服务端最近一次握手发送的 Finished 消息。
	clientFinished [12]byte
	serverFinished [12]byte

	// clientProtocol  协商出的应用层协议
	clientProtocol string

	// 单向连接 输入/输出 （加密/解密）
	in, out   halfConn
	workKey   []byte       // TLCP工作密钥，用于在断开连接时对密钥置零
	rawInput  bytes.Buffer // 原始输入数据，以记录层(record)的头开始
	input     bytes.Reader // application data waiting to be read, from rawInput.Next
	hand      bytes.Buffer // handshake data waiting to be read
	buffering bool         // whether records are buffered in sendBuf
	sendBuf   []byte       // a buffer of records waiting to be sent

	// bytesSent 连接总共发送数据字节数(byte)
	// packetsSent counts packets. 连接总共发送数据包数量
	bytesSent   int64
	packetsSent int64

	// retryCount counts the number of consecutive non-advancing records
	// received by Conn.readRecord. That is, records that neither advance the
	// handshake, nor deliver application data. Protected by in.Mutex.
	retryCount int

	// activeCall is an atomic int32; the low bit is whether Close has
	// been called. the rest of the bits are the number of goroutines
	// in Conn.Write.
	activeCall int32

	tmp [16]byte
}

// LocalAddr 返回连接本地的网络地址。
//
// 返回值：
//   - net.Addr：底层网络连接的本地地址，其具体类型由底层连接实现决定，如 *net.TCPAddr。
func (c *Conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr 返回连接对端的网络地址。
//
// 返回值：
//   - net.Addr：底层网络连接的对端地址，其具体类型由底层连接实现决定，如 *net.TCPAddr。
func (c *Conn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline 设置对连接 读取或写入 终止时间。
//
// 参数：
//   - t：终止时间；若 t 为 0 表示不会超时。
//
// 返回值：
//   - error：由底层连接的 SetDeadline 返回，设置失败时返回非 nil。
//
// 读超时属于临时错误（net.Error 且 Temporary 为 true），不会破坏连接状态；
// 写超时后 TLCP 连接状态将被破坏，后续所有写入都会返回同一个错误。
func (c *Conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline 设置底层连接的读取终止时间。
//
// 参数：
//   - t：读取终止时间；若 t 为 0 表示 Read 不会超时。
//
// 返回值：
//   - error：由底层连接的 SetReadDeadline 返回，设置失败时返回非 nil。
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline 设置底层连接的写入终止时间。
//
// 参数：
//   - t：写入终止时间；若 t 为 0 表示 Write 不会超时。
//
// 返回值：
//   - error：由底层连接的 SetWriteDeadline 返回，设置失败时返回非 nil。
//
// 在某次 Write 超时后，TLCP 连接状态将被破坏，之后所有的写入都会返回同样的错误。
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// NetConn 返回被TLCP包装的原始的网络连接对象，如：TCP连接对象。
//
// 返回值：
//   - net.Conn：底层的原始网络连接对象，其具体类型由创建该 TLCP 连接时传入的实现决定。
//
// 注意直接读写该连接对象将会导致会话终止。
func (c *Conn) NetConn() net.Conn {
	return c.conn
}

// PeerCertificates 返回握手过程中记录的对端证书列表。
//
// 返回值：
//   - []*smx509.Certificate：对端数字证书列表；客户端侧为服务端证书且顺序为 [签名证书, 加密证书]，服务端侧为客户端提供的证书，握手未完成或对端未提供证书时可能为 nil。
func (c *Conn) PeerCertificates() []*smx509.Certificate {
	return c.peerCertificates
}

// IsClient 返回该连接是否为客户端。
//
// 返回值：
//   - bool：true 表示客户端；false 表示服务端。
func (c *Conn) IsClient() bool {
	return c.isClient
}

// halfConn 代表一个传输方向(发送/接收) 的记录层协议连接
type halfConn struct {
	sync.Mutex

	err     error       // first permanent error
	version uint16      // protocol version
	cipher  interface{} // cipher algorithm
	mac     hash.Hash
	seq     [8]byte // 64-bit sequence number

	scratchBuf [13]byte // to avoid allocs; interface method args escape

	nextCipher interface{} // next encryption state
	nextMac    hash.Hash   // next MAC algorithm

	trafficSecret []byte // current TLS 1.3 traffic secret
}

type permanentError struct {
	err net.Error
}

func (e *permanentError) Error() string   { return e.err.Error() }
func (e *permanentError) Unwrap() error   { return e.err }
func (e *permanentError) Timeout() bool   { return e.err.Timeout() }
func (e *permanentError) Temporary() bool { return false }

func (hc *halfConn) setErrorLocked(err error) error {
	if e, ok := err.(net.Error); ok {
		hc.err = &permanentError{err: e}
	} else {
		hc.err = err
	}
	return hc.err
}

// prepareCipherSpec sets the encryption and MAC states
// that a subsequent changeCipherSpec will use.
func (hc *halfConn) prepareCipherSpec(version uint16, cipher interface{}, mac hash.Hash) {
	hc.version = version
	hc.nextCipher = cipher
	hc.nextMac = mac
}

// changeCipherSpec changes the encryption and MAC states
// to the ones previously passed to prepareCipherSpec.
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

// incSeq 递增TLCP包序列号
func (hc *halfConn) incSeq() {
	for i := 7; i >= 0; i-- {
		hc.seq[i]++
		if hc.seq[i] != 0 {
			return
		}
	}

	// Not allowed to let sequence number wrap.
	// Instead, must renegotiate before it does.
	// Not likely enough to bother.
	panic("tlcp: sequence number wraparound")
}

// explicitNonceLen returns the number of bytes of explicit nonce or IV included
// in each record. Explicit nonces are present only in CBC modes after TLS 1.0
// and in certain AEAD modes in TLS 1.2.
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

// extractPadding returns, in constant time, the length of the padding to remove
// from the end of payload. It also returns a byte which is equal to 255 if the
// padding was valid and 0 otherwise. See RFC 2246, Section 6.2.3.2.
func extractPadding(payload []byte) (toRemove int, good byte) {
	if len(payload) < 1 {
		return 0, 0
	}

	paddingLen := payload[len(payload)-1]
	t := uint(len(payload)-1) - uint(paddingLen)
	// if len(payload) >= (paddingLen - 1) then the MSB of t is zero
	good = byte(int32(^t) >> 31)

	// The maximum possible padding length plus the actual length field
	toCheck := 256
	// The length of the padded data is public, so we can use an if here
	if toCheck > len(payload) {
		toCheck = len(payload)
	}

	for i := 0; i < toCheck; i++ {
		t := uint(paddingLen) - uint(i)
		// if i <= paddingLen then the MSB of t is zero
		mask := byte(int32(^t) >> 31)
		b := payload[len(payload)-1-i]
		good &^= mask&paddingLen ^ mask&b
	}

	// We AND together the bits of good and replicate the result across
	// all the bits.
	good &= good << 4
	good &= good << 2
	good &= good << 1
	good = uint8(int8(good) >> 7)

	// Zero the padding length on error. This ensures any unchecked bytes
	// are included in the MAC. Otherwise, an attacker that could
	// distinguish MAC failures from padding failures could mount an attack
	// similar to POODLE in SSL 3.0: given a good ciphertext that uses a
	// full block's worth of padding, replace the final block with another
	// block. If the MAC check passed but the padding check failed, the
	// last byte of that block decrypted to the block size.
	//
	// See also macAndPaddingGood logic below.
	paddingLen &= good

	toRemove = int(paddingLen) + 1
	return
}

func roundUp(a, b int) int {
	return a + (b-a%b)%b
}

// cbcMode is an interface for block ciphers using cipher block chaining.
type cbcMode interface {
	cipher.BlockMode
	SetIV([]byte)
}

// decrypt authenticates and decrypts the record if protection is active at
// this stage. The returned plaintext might overlap with the input.
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

			var additionalData []byte
			additionalData = append(hc.scratchBuf[:0], hc.seq[:]...)
			additionalData = append(additionalData, record[:3]...)
			n := len(payload) - c.Overhead()
			additionalData = append(additionalData, byte(n>>8), byte(n))

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
			// computing the digest. This makes the MAC roughly constant time as
			// long as the digest computation is constant time and does not
			// affect the subsequent write, modulo cache effects.
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
		record[3] = byte(n >> 8)
		record[4] = byte(n)
		remoteMAC := payload[n : n+macSize]
		localMAC := tls10MAC(hc.mac, hc.scratchBuf[:0], hc.seq[:], record[:recordHeaderLen], payload[:n], payload[n+macSize:])

		// This is equivalent to checking the MACs and paddingGood
		// separately, but in constant-time to prevent distinguishing
		// padding failures from MAC failures. Depending on what value
		// of paddingLen was returned on bad padding, distinguishing
		// bad MAC from bad padding can lead to an attack.
		//
		// See also the logic at the end of extractPadding.
		macAndPaddingGood := subtle.ConstantTimeCompare(localMAC, remoteMAC) & int(paddingGood)
		if macAndPaddingGood != 1 {
			return nil, 0, alertBadRecordMAC
		}

		plaintext = payload[:n]
	}

	hc.incSeq()
	return plaintext, typ, nil
}

// sliceForAppend extends the input slice by n bytes. head is the full extended
// slice, while tail is the appended part. If the original slice has sufficient
// capacity no allocation is performed.
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

// encrypt encrypts payload, adding the appropriate nonce and/or MAC, and
// appends it to record, which must already contain the record header.
func (hc *halfConn) encrypt(record, payload []byte, rand io.Reader) ([]byte, error) {
	if hc.cipher == nil {
		return append(record, payload...), nil
	}

	var explicitNonce []byte
	if explicitNonceLen := hc.explicitNonceLen(); explicitNonceLen > 0 {
		record, explicitNonce = sliceForAppend(record, explicitNonceLen)
		if _, isCBC := hc.cipher.(cbcMode); !isCBC && explicitNonceLen < 16 {
			// The AES-GCM construction in TLS has an explicit nonce so that the
			// nonce can be random. However, the nonce is only 8 bytes which is
			// too small for a secure, random nonce. Therefore we use the
			// sequence number as the nonce. The 3DES-CBC construction also has
			// an 8 bytes nonce but its nonces must be unpredictable (see RFC
			// 5246, Appendix F.3), forcing us to use randomness. That's not
			// 3DES' biggest problem anyway because the birthday bound on block
			// collision is reached first due to its similarly small block size
			// (see the Sweet32 attack).
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
		mac := tls10MAC(hc.mac, hc.scratchBuf[:0], hc.seq[:], record[:recordHeaderLen], payload, nil)
		record, dst = sliceForAppend(record, len(payload)+len(mac))
		c.XORKeyStream(dst[:len(payload)], payload)
		c.XORKeyStream(dst[len(payload):], mac)
	case aead:
		nonce := explicitNonce
		if len(nonce) == 0 {
			nonce = hc.seq[:]
		}
		additionalData := append(hc.scratchBuf[:0], hc.seq[:]...)
		additionalData = append(additionalData, record[:recordHeaderLen]...)
		record = c.Seal(record, nonce, payload, additionalData)
	case cbcMode:
		mac := tls10MAC(hc.mac, hc.scratchBuf[:0], hc.seq[:], record[:recordHeaderLen], payload, nil)
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

	// Update length to include nonce, MAC and any block padding needed.
	n := len(record) - recordHeaderLen
	record[3] = byte(n >> 8)
	record[4] = byte(n)
	hc.incSeq()

	return record, nil
}

// RecordHeaderError 当TLCP记录层协议(record)的头非法时返回该错误。
type RecordHeaderError struct {
	// Msg 包含了人可读的错误描述信息
	Msg string
	// RecordHeader 包含导致了该错误的 TLCP记录层头 5字节(byte)
	RecordHeader [5]byte

	// Conn 底层的连接对象
	// 若已经有过一次握手或发送了报警消息，那么该参数可能为空。
	Conn net.Conn
}

// Error 返回记录层头部非法错误的描述文本，满足 error 接口。
//
// 返回值：
//   - string：由 Msg 字段加上 "tlcp: " 前缀构成的错误描述。
func (e RecordHeaderError) Error() string { return "tlcp: " + e.Msg }

func (c *Conn) newRecordHeaderError(conn net.Conn, msg string) (err RecordHeaderError) {
	err.Msg = msg
	err.Conn = conn
	copy(err.RecordHeader[:], c.rawInput.Bytes())
	return err
}

func (c *Conn) readRecord() error {
	return c.readRecordOrCCS(false)
}

func (c *Conn) readChangeCipherSpec() error {
	return c.readRecordOrCCS(true)
}

// readRecordOrCCS reads one or more TLS records from the connection and
// updates the record layer state. Some invariants:
//   - c.in must be locked
//   - c.input must be empty
//
// During the handshake one and only one of the following will happen:
//   - c.hand grows
//   - c.in.changeCipherSpec is called
//   - an error is returned
//
// After the handshake one and only one of the following will happen:
//   - c.hand grows
//   - c.input is set
//   - an error is returned
func (c *Conn) readRecordOrCCS(expectChangeCipherSpec bool) error {
	if c.in.err != nil {
		return c.in.err
	}
	handshakeComplete := c.handshakeComplete()

	// This function modifies c.rawInput, which owns the c.input memory.
	if c.input.Len() != 0 {
		return c.in.setErrorLocked(errors.New("tlcp: internal error: attempted to read record with pending application data"))
	}
	c.input.Reset(nil)

	// Read header, payload.
	if err := c.readFromUntil(c.conn, recordHeaderLen); err != nil {
		// RFC 8446, Section 6.1 suggests that EOF without an alertCloseNotify
		// is an error, but popular web sites seem to do this, so we accept it
		// if and only if at the record boundary.
		if err == io.ErrUnexpectedEOF && c.rawInput.Len() == 0 {
			err = io.EOF
		}
		if e, ok := err.(net.Error); !ok || !e.Temporary() {
			c.in.setErrorLocked(err)
		}
		return err
	}
	hdr := c.rawInput.Bytes()[:recordHeaderLen]
	typ := recordType(hdr[0])

	// No valid TLS record has a type of 0x80, however SSLv2 handshakes
	// start with a uint16 length where the MSB is set and the first record
	// is always < 256 bytes long. Therefore typ == 0x80 strongly suggests
	// an SSLv2 client.
	if !handshakeComplete && typ == 0x80 {
		_ = c.sendAlert(alertProtocolVersion)
		return c.in.setErrorLocked(c.newRecordHeaderError(nil, "unsupported SSLv2 handshake received"))
	}

	vers := uint16(hdr[1])<<8 | uint16(hdr[2])
	n := int(hdr[3])<<8 | int(hdr[4])
	//if c.haveVers && c.vers != VersionTLS13 && vers != c.vers {
	if c.haveVers && vers != c.vers {
		_ = c.sendAlert(alertProtocolVersion)
		msg := fmt.Sprintf("received record with version %x when expecting version %x", vers, c.vers)
		return c.in.setErrorLocked(c.newRecordHeaderError(nil, msg))
	}
	if !c.haveVers {
		// First message, be extra suspicious: this might not be a TLS
		// client. Bail out before reading a full 'body', if possible.
		// The current max version is 3.3 so if the version is >= 16.0,
		// it's probably not real.
		if (typ != recordTypeAlert && typ != recordTypeHandshake) || vers >= 0x1000 {
			return c.in.setErrorLocked(c.newRecordHeaderError(c.conn, "first record does not look like a TLS handshake"))
		}
	}
	//if c.vers == VersionTLS13 && n > maxCiphertextTLS13 || n > maxCiphertext {
	//	c.sendAlert(alertRecordOverflow)
	//	msg := fmt.Sprintf("oversized record received with length %d", n)
	//	return c.in.setErrorLocked(c.newRecordHeaderError(nil, msg))
	//}
	if n > maxCiphertext {
		_ = c.sendAlert(alertRecordOverflow)
		msg := fmt.Sprintf("oversized record received with length %d", n)
		return c.in.setErrorLocked(c.newRecordHeaderError(nil, msg))
	}
	if err := c.readFromUntil(c.conn, recordHeaderLen+n); err != nil {
		if e, ok := err.(net.Error); !ok || !e.Temporary() {
			c.in.setErrorLocked(err)
		}
		return err
	}

	// Process message.
	record := c.rawInput.Next(recordHeaderLen + n)
	data, typ, err := c.in.decrypt(record)
	if err != nil {
		return c.in.setErrorLocked(c.sendAlert(err.(alert)))
	}
	if len(data) > maxPlaintext {
		return c.in.setErrorLocked(c.sendAlert(alertRecordOverflow))
	}

	// Application Data messages are always protected.
	if c.in.cipher == nil && typ == recordTypeApplicationData {
		return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
	}

	if typ != recordTypeAlert && typ != recordTypeChangeCipherSpec && len(data) > 0 {
		// This is a state-advancing message: reset the retry count.
		c.retryCount = 0
	}

	//// Handshake messages MUST NOT be interleaved with other record types in TLS 1.3.
	//if c.vers == VersionTLS13 && typ != recordTypeHandshake && c.hand.Len() > 0 {
	//	return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
	//}

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
		//if c.vers == VersionTLS13 {
		//	return c.in.setErrorLocked(&net.OpError{Op: "remote error", Err: alert(data[1])})
		//}
		switch data[0] {
		case alertLevelWarning:
			// Drop the record on the floor and retry.
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
		// Handshake messages are not allowed to fragment across the CCS.
		if c.hand.Len() > 0 {
			return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
		}

		if !expectChangeCipherSpec {
			return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
		}
		if err := c.in.changeCipherSpec(); err != nil {
			return c.in.setErrorLocked(c.sendAlert(err.(alert)))
		}

	case recordTypeApplicationData:
		if !handshakeComplete || expectChangeCipherSpec {
			return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
		}
		// Some OpenSSL servers send empty records in order to randomize the
		// CBC IV. Ignore a limited number of empty records.
		if len(data) == 0 {
			return c.retryReadRecord(expectChangeCipherSpec)
		}
		// Note that data is owned by c.rawInput, following the Next call above,
		// to avoid copying the plaintext. This is safe because c.rawInput is
		// not read from or written to until c.input is drained.
		c.input.Reset(data)

	case recordTypeHandshake:
		if len(data) == 0 || expectChangeCipherSpec {
			return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
		}
		c.hand.Write(data)
	}

	return nil
}

// retryReadRecord recurs into readRecordOrCCS to drop a non-advancing record, like
// a warning alert, empty application_data, or a change_cipher_spec in TLS 1.3.
func (c *Conn) retryReadRecord(expectChangeCipherSpec bool) error {
	c.retryCount++
	if c.retryCount > maxUselessRecords {
		c.sendAlert(alertUnexpectedMessage)
		return c.in.setErrorLocked(errors.New("tlcp: too many ignored records"))
	}
	return c.readRecordOrCCS(expectChangeCipherSpec)
}

// atLeastReader reads from R, stopping with EOF once at least N bytes have been
// read. It is different from an io.LimitedReader in that it doesn't cut short
// the last Read call, and in that it considers an early EOF an error.
type atLeastReader struct {
	R io.Reader
	N int64
}

func (r *atLeastReader) Read(p []byte) (int, error) {
	if r.N <= 0 {
		return 0, io.EOF
	}
	n, err := r.R.Read(p)
	r.N -= int64(n) // won't underflow unless len(p) >= n > 9223372036854775809
	if r.N > 0 && err == io.EOF {
		return n, io.ErrUnexpectedEOF
	}
	if r.N <= 0 && err == nil {
		return n, io.EOF
	}
	return n, err
}

// readFromUntil reads from r into c.rawInput until c.rawInput contains
// at least n bytes or else returns an error.
func (c *Conn) readFromUntil(r io.Reader, n int) error {
	if c.rawInput.Len() >= n {
		return nil
	}
	needs := n - c.rawInput.Len()
	// There might be extra input waiting on the wire. Make a best effort
	// attempt to fetch it so that it can be used in (*Conn).Read to
	// "predict" closeNotify alerts.
	c.rawInput.Grow(needs + bytes.MinRead)
	_, err := c.rawInput.ReadFrom(&atLeastReader{r, int64(needs)})
	return err
}

// sendAlert sends a TLS alert message.
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
		// closeNotify is a special case in that it isn't an error.
		return writeErr
	}

	return c.out.setErrorLocked(&net.OpError{Op: "local error", Err: err})
}

// sendAlert 发送TLCP报警
func (c *Conn) sendAlert(err alert) error {
	c.out.Lock()
	defer c.out.Unlock()
	// 报警回调
	if c.config != nil && c.config.OnAlert != nil {
		c.config.OnAlert(uint8(err), c)
	}
	return c.sendAlertLocked(err)
}

// sendAlertForError 发送 err 携带的 TLCP 告警并原样返回 err；
// err 未携带告警码时使用 fallback。
func (c *Conn) sendAlertForError(err error, fallback alert) error {
	if err == nil {
		return nil
	}
	_ = c.sendAlert(alertForError(err, fallback))
	return err
}

const (
	// tcpMSSEstimate is a conservative estimate of the TCP maximum segment
	// size (MSS). A constant is used, rather than querying the kernel for
	// the actual MSS, to avoid complexity. The value here is the IPv6
	// minimum MTU (1280 bytes) minus the overhead of an IPv6 header (40
	// bytes) and a TCP header with timestamps (32 bytes).
	tcpMSSEstimate = 1208

	// recordSizeBoostThreshold is the number of bytes of application data
	// sent after which the TLS record size will be increased to the
	// maximum.
	recordSizeBoostThreshold = 128 * 1024
)

// maxPayloadSizeForWrite returns the maximum TLS payload size to use for the
// next application data record. There is the following trade-off:
//
//   - For latency-sensitive applications, such as web browsing, each TLS
//     record should fit in one TCP segment.
//   - For throughput-sensitive applications, such as large file transfers,
//     larger TLS records better amortize framing and encryption overheads.
//
// A simple heuristic that works well in practice is to use small records for
// the first 1MB of data, then use larger records for subsequent data, and
// reset back to smaller records after the connection becomes idle. See "High
// Performance Web Networking", Chapter 4, or:
// https://www.igvita.com/2013/10/24/optimizing-tls-record-size-and-buffering-latency/
//
// In the interests of simplicity and determinism, this code does not attempt
// to reset the record size once the connection is idle, however.
func (c *Conn) maxPayloadSizeForWrite(typ recordType) int {
	if c.config.DynamicRecordSizingDisabled || typ != recordTypeApplicationData {
		return maxPlaintext
	}

	if c.bytesSent >= recordSizeBoostThreshold {
		return maxPlaintext
	}

	// Subtract TLS overheads to get the maximum payload size.
	payloadBytes := tcpMSSEstimate - recordHeaderLen - c.out.explicitNonceLen()
	if c.out.cipher != nil {
		switch ciph := c.out.cipher.(type) {
		case cipher.Stream:
			payloadBytes -= c.out.mac.Size()
		case cipher.AEAD:
			payloadBytes -= ciph.Overhead()
		case cbcMode:
			blockSize := ciph.BlockSize()
			// The payload must fit in a multiple of blockSize, with
			// room for at least one padding byte.
			payloadBytes = (payloadBytes & ^(blockSize - 1)) - 1
			// The MAC is appended before padding so affects the
			// payload size directly.
			payloadBytes -= c.out.mac.Size()
		default:
			panic("unknown cipher type")
		}
	}

	// Allow packet growth in arithmetic progression up to max.
	pkt := c.packetsSent
	c.packetsSent++
	if pkt > 1000 {
		return maxPlaintext // avoid overflow in multiply below
	}

	n := payloadBytes * int(pkt+1)
	if n > maxPlaintext {
		n = maxPlaintext
	}
	return n
}

func (c *Conn) write(data []byte) (int, error) {
	if c.buffering {
		c.sendBuf = append(c.sendBuf, data...)
		return len(data), nil
	}

	n, err := c.conn.Write(data)
	c.bytesSent += int64(n)
	return n, err
}

func (c *Conn) flush() (int, error) {
	if len(c.sendBuf) == 0 {
		return 0, nil
	}

	n, err := c.conn.Write(c.sendBuf)
	c.bytesSent += int64(n)
	c.sendBuf = nil
	c.buffering = false
	return n, err
}

// outBufPool pools the record-sized scratch buffers used by writeRecordLocked.
var outBufPool = sync.Pool{
	New: func() interface{} {
		return new([]byte)
	},
}

// writeRecordLocked writes a TLS record with the given type and payload to the
// connection and updates the record layer state.
func (c *Conn) writeRecordLocked(typ recordType, data []byte) (int, error) {
	outBufPtr := outBufPool.Get().(*[]byte)
	outBuf := *outBufPtr
	defer func() {
		// You might be tempted to simplify this by just passing &outBuf to Put,
		// but that would make the local copy of the outBuf slice header escape
		// to the heap, causing an allocation. Instead, we keep around the
		// pointer to the slice header returned by Get, which is already on the
		// heap, and overwrite and return that.
		*outBufPtr = outBuf
		outBufPool.Put(outBufPtr)
	}()

	var n int
	for len(data) > 0 {
		m := len(data)
		if maxPayload := c.maxPayloadSizeForWrite(typ); m > maxPayload {
			m = maxPayload
		}

		_, outBuf = sliceForAppend(outBuf[:0], recordHeaderLen)
		outBuf[0] = byte(typ)
		vers := c.vers
		if vers == 0 {
			// Some TLS servers fail if the record version is
			// greater than TLS 1.0 for the initial ClientHello.
			vers = VersionTLCP
		}

		outBuf[1] = byte(vers >> 8)
		outBuf[2] = byte(vers)
		outBuf[3] = byte(m >> 8)
		outBuf[4] = byte(m)

		var err error
		outBuf, err = c.out.encrypt(outBuf, data[:m], c.config.rand())
		if err != nil {
			return n, err
		}
		if _, err := c.write(outBuf); err != nil {
			return n, err
		}
		n += m
		data = data[m:]
	}

	//if typ == recordTypeChangeCipherSpec && c.vers != VersionTLS13 {
	if typ == recordTypeChangeCipherSpec {
		if err := c.out.changeCipherSpec(); err != nil {
			return n, c.sendAlertLocked(err.(alert))
		}
	}

	return n, nil
}

// writeHandshakeRecord writes a handshake message to the connection and updates
// the record layer state. If transcript is non-nil the marshalled message is
// written to it.
func (c *Conn) writeHandshakeRecord(msg handshakeMessage, transcript transcriptHash) (int, error) {
	c.out.Lock()
	defer c.out.Unlock()

	data, err := msg.marshal()
	if err != nil {
		return 0, err
	}
	if transcript != nil {
		transcript.Write(data)
	}

	n, err := c.writeRecordLocked(recordTypeHandshake, data)

	if c.config.EnableDebug {
		fmt.Printf("[write] %v, len=%v, success=%v\n", HandshakeMessageTypeName(msg.messageType()), len(data), err == nil)
		msg.debug()
	}
	return n, err
}

// writeChangeCipherRecord writes a ChangeCipherSpec message to the connection and
// updates the record layer state.
func (c *Conn) writeChangeCipherRecord() error {
	c.out.Lock()
	defer c.out.Unlock()
	_, err := c.writeRecordLocked(recordTypeChangeCipherSpec, []byte{1})
	return err
}

// readHandshake 从记录层读取下一个握手消息。如果transcript不为nil，则将消息写入传递的transcriptHash。
func (c *Conn) readHandshake(transcript transcriptHash) (interface{}, error) {
	for c.hand.Len() < 4 {
		if err := c.readRecord(); err != nil {
			return nil, err
		}
	}

	data := c.hand.Bytes()
	n := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if n > maxHandshake {
		c.sendAlertLocked(alertInternalError)
		return nil, c.in.setErrorLocked(fmt.Errorf("tlcp: handshake message of length %d bytes exceeds maximum of %d bytes", n, maxHandshake))
	}
	for c.hand.Len() < 4+n {
		if err := c.readRecord(); err != nil {
			return nil, err
		}
	}
	data = c.hand.Next(4 + n)
	if c.config.EnableDebug {
		fmt.Printf("[read] %v, len=%v\n", HandshakeMessageTypeName(data[0]), len(data))
	}
	var m handshakeMessage
	switch data[0] {
	case typeClientHello:
		m = new(clientHelloMsg)
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

	// The handshake message unmarshalers
	// expect to be able to keep references to data,
	// so pass in a fresh copy that won't be overwritten.
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

var (
	errShutdown = errors.New("tlcp: protocol is shutdown")
)

// Write 将数据作为应用层数据记录写入连接。
//
// 参数：
//   - b：待写入的应用层明文数据，长度可以为 0；数据会被切分为不超过记录层最大明文载荷的记录后写入。
//
// 返回值：
//   - int：成功写入的明文字节数；发生错误时可能小于 len(b)。
//   - error：握手失败、连接已关闭、已发送 close_notify 或记录层已存在永久错误时返回非 nil。
//
// 由于 Write 会调用 Handshake，在握手尚未完成时，为了避免无限期阻塞，必须在调用 Write 之前
// 同时为 Read 和 Write 设置截止时间，参见 SetDeadline、SetReadDeadline 与 SetWriteDeadline。
func (c *Conn) Write(b []byte) (int, error) {
	// interlock with Close below
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
	//return n + m, c.out.setErrorLocked(err)
}

// Read 从连接中读取应用层数据。
//
// 参数：
//   - b：用于接收明文的缓冲区；长度可以为 0，此时仅执行握手并返回 (0, nil)。
//
// 返回值：
//   - int：本次读取到的明文字节数，可以为 0。
//   - error：握手失败或读取失败时返回非 nil；收到对端的 close_notify 报警时返回 io.EOF，此时可能同时返回了已读到的明文（n > 0），调用方应先处理这 n 个字节再判定连接结束。
//
// 由于 Read 会调用 Handshake，在握手尚未完成时，为了避免无限期阻塞，必须在调用 Read 之前
// 同时为 Read 和 Write 设置截止时间，参见 SetDeadline、SetReadDeadline 与 SetWriteDeadline。
func (c *Conn) Read(b []byte) (int, error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}
	if len(b) == 0 {
		// Put this after Handshake, in case people were calling
		// Read(nil) for the side effect of the Handshake.
		return 0, nil
	}

	c.in.Lock()
	defer c.in.Unlock()

	for c.input.Len() == 0 {
		if err := c.readRecord(); err != nil {
			return 0, err
		}
	}
	n, _ := c.input.Read(b)

	// If a close-notify alert is waiting, read it so that we can return (n,
	// EOF) instead of (n, nil), to signal to the HTTP response reading
	// goroutine that the connection is now closed. This eliminates a race
	// where the HTTP response reading goroutine would otherwise not observe
	// the EOF until its next read, by which time a client goroutine might
	// have already tried to reuse the HTTP connection for a new request.
	// See https://golang.org/cl/76400046 and https://golang.org/issue/3514
	if n != 0 && c.input.Len() == 0 && c.rawInput.Len() > 0 &&
		recordType(c.rawInput.Bytes()[0]) == recordTypeAlert {
		if err := c.readRecord(); err != nil {
			return n, err // will be io.EOF on closeNotify
		}
	}

	return n, nil
}

// Close 关闭连接。
//
// 返回值：
//   - error：连接已进入关闭流程时返回 net.ErrClosed；有 Write 正在进行时仅关闭底层连接并返回其错误；握手已完成但发送 close_notify 报警失败时返回包装了该失败的告警错误（连接仍会被关闭）；关闭底层连接失败时返回底层错误。
//
// 当发送 close_notify 失败而随后关闭底层连接也失败时，返回的是底层关闭错误，告警错误会被丢弃。
func (c *Conn) Close() error {
	// Interlock with Conn.Write above.
	var x int32
	for {
		x = atomic.LoadInt32(&c.activeCall)
		if x&1 != 0 {
			return net.ErrClosed
		}
		if atomic.CompareAndSwapInt32(&c.activeCall, x, x|1) {
			break
		}
	}
	if x != 0 {
		// io.Writer and io.Closer should not be used concurrently.
		// If Close is called while a Write is currently in-flight,
		// interpret that as a sign that this Close is really just
		// being used to break the Write and/or clean up resources and
		// avoid sending the alertCloseNotify, which may block
		// waiting on handshakeMutex or the c.out mutex.
		return c.conn.Close()
	}

	var alertErr error
	if c.handshakeComplete() {
		if err := c.closeNotify(); err != nil {
			alertErr = fmt.Errorf("tlcp: failed to send closeNotify alert (but connection was closed anyway): %w", err)
		}
	}
	// 对工作密钥置零
	setZero(c.workKey)
	c.workKey = nil

	if err := c.conn.Close(); err != nil {
		return err
	}
	return alertErr
}

var errEarlyCloseWrite = errors.New("tlcp: CloseWrite called before handshake complete")

// CloseWrite 关闭连接的写入方向。它只应在握手完成之后调用，且不会对底层连接调用 CloseWrite，大多数调用者直接使用 Close 即可。
//
// 返回值：
//   - error：握手尚未完成时返回错误 errEarlyCloseWrite；发送 close_notify 报警失败时返回该错误。
//
// 调用后该连接的 TLCP 写方向永久不可用（实现会把写截止时间置为当前时刻），后续 Write 会直接失败。
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
		// Set a Write Deadline to prevent possibly blocking forever.
		c.SetWriteDeadline(time.Now().Add(time.Second * 5))
		c.closeNotifyErr = c.sendAlertLocked(alertCloseNotify)
		c.closeNotifySent = true
		// Any subsequent writes will fail.
		c.SetWriteDeadline(time.Now())
	}
	return c.closeNotifyErr
}

// Handshake 若尚未执行过握手，则执行客户端或服务端的握手协议。
//
// 返回值：
//   - error：握手失败时返回非 nil；一旦某次握手失败，后续调用会返回同一个错误。
//
// 本包的大多数使用方式无需显式调用 Handshake：首次 Read 或 Write 会自动调用它。
// 若需要取消握手或为其设置超时，请改用 HandshakeContext 或 Dialer 的 DialContext 方法。
func (c *Conn) Handshake() error {
	return c.HandshakeContext(context.Background())
}

// HandshakeContext 若尚未执行过握手，则在指定上下文中执行客户端或服务端的握手协议。
//
// 参数：
//   - ctx：握手使用的上下文，不能为 nil；若握手完成之前上下文被取消，握手会被中断并返回错误。
//
// 返回值：
//   - error：握手失败时返回非 nil；上下文在握手完成前被取消时返回上下文错误。
//
// 注意：上下文在握手完成前被取消时，实现会直接关闭底层连接，该连接此后不可再使用。
// 一旦握手完成，上下文的取消不会影响该连接。
// 本包的大多数使用方式无需显式调用 HandshakeContext：首次 Read 或 Write 会自动调用它。
func (c *Conn) HandshakeContext(ctx context.Context) error {
	// Delegate to unexported method for named return
	// without confusing documented signature.
	return c.handshakeContext(ctx)
}

func (c *Conn) handshakeContext(ctx context.Context) (ret error) {
	// Fast sync/atomic-based exit if there is no handshake in flight and the
	// last one succeeded without an error. Avoids the expensive context setup
	// and mutex for most Read and Write calls.
	if c.handshakeComplete() {
		return nil
	}

	handshakeCtx, cancel := context.WithCancel(ctx)
	// Note: defer this before starting the "interrupter" goroutine
	// so that we can tell the difference between the input being canceled and
	// this cancellation. In the former case, we need to close the connection.
	defer cancel()

	// Start the "interrupter" goroutine, if this context might be canceled.
	// (The background context cannot).
	//
	// The interrupter goroutine waits for the input context to be done and
	// closes the connection if this happens before the function returns.
	if ctx.Done() != nil {
		done := make(chan struct{})
		interruptRes := make(chan error, 1)
		defer func() {
			close(done)
			if ctxErr := <-interruptRes; ctxErr != nil {
				// Return context error to user.
				ret = ctxErr
			}
		}()
		go func() {
			select {
			case <-handshakeCtx.Done():
				// Close the connection, discarding the error
				_ = c.conn.Close()
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
	} else {
		// If an error occurred during the handshake try to flush the
		// alert that might be left in the buffer.
		c.flush()
	}

	if c.handshakeErr == nil && !c.handshakeComplete() {
		c.handshakeErr = errors.New("tlcp: internal error: handshake should have had a result")
	}
	if c.handshakeErr != nil && c.handshakeComplete() {
		panic("tlcp: internal error: handshake returned an error but is marked successful")
	}

	return c.handshakeErr
}

// ConnectionState 返回该连接的基本 TLCP 详情。
//
// 返回值：
//   - ConnectionState：连接状态的快照，包含协议版本、是否完成握手、是否为会话重用、密码套件、协商出的应用层协议、服务端名称、对端证书与证书链以及 IBC 相关上下文等字段；该调用不会触发握手，握手未完成（HandshakeComplete 为 false）时这些字段可能为零值，也可能保留握手过程中已写入的部分取值，不应视为完整可信。
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

// VerifyHostname 检查对端证书链对于连接到 host 是否有效。若有效返回 nil；否则返回描述问题的错误。
//
// 参数：
//   - host：待校验的主机名，通常为不含端口的域名。
//
// 返回值：
//   - error：在服务端连接上调用、握手尚未完成、握手未验证对端证书链，或证书链对 host 无效时返回非 nil。
func (c *Conn) VerifyHostname(host string) error {
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()
	if !c.isClient {
		return errors.New("tlcp: VerifyHostname called on TLS server connection")
	}
	if !c.handshakeComplete() {
		return errors.New("tlcp: handshake has not yet been performed")
	}
	if len(c.verifiedChains) == 0 {
		return errors.New("tlcp: handshake did not verify certificate chain")
	}
	return c.peerCertificates[0].VerifyHostname(host)
}

func (c *Conn) handshakeComplete() bool {
	return atomic.LoadUint32(&c.handshakeStatus) == 1
}
