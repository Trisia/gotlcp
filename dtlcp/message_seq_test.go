// Copyright (c) 2026 gotlcp contributors
// gotlcp is licensed under Mulan PSL v2.

package dtlcp

import (
	"net"
	"sync"
	"testing"
	"time"
)

// identityBlockMode 是恒等的分组密码模式，用于在测试中让记录体保持明文。
type identityBlockMode struct{ blockSize int }

// BlockSize 返回分组长度，单位：字节。
func (m identityBlockMode) BlockSize() int { return m.blockSize }

// CryptBlocks 保持数据不变。
func (identityBlockMode) CryptBlocks(dst, src []byte) { copy(dst, src) }

// SetIV 接收 IV，测试中不做任何处理。
func (identityBlockMode) SetIV(iv []byte) {}

// =============================================================================
// 测试辅助
// =============================================================================

// capturePacketConn 记录写入的所有数据报，用于检查客户端实际发出的字节。
type capturePacketConn struct {
	net.PacketConn
	mu   sync.Mutex
	sent [][]byte
}

// WriteTo 记录数据报后转发给底层连接。
func (c *capturePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	c.sent = append(c.sent, append([]byte(nil), p...))
	c.mu.Unlock()
	return c.PacketConn.WriteTo(p, addr)
}

// findFinishedSeq 在缓冲区中查找 Completed 握手消息（Finished）的 message_seq。
//
// 参数：
//   - buf：包含若干 DTLCP 记录的数据报。
//   - explicitNonceLen：记录体中位于握手消息之前的显式 IV/nonce 长度，单位：字节。
//
// 返回值：
//   - uint16：Finished 消息序号。
//   - bool：未找到时返回 false。
func findFinishedSeq(buf []byte, explicitNonceLen int) (uint16, bool) {
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
		if hsData[0] == typeFinished {
			return uint16(hsData[4])<<8 | uint16(hsData[5]), true
		}
		off = next
	}
	return 0, false
}

// =============================================================================
// 测试
// =============================================================================

// TestClientFinishedMessageSeq 验证客户端发送 Finished 时使用递增的 message_seq。
//
// 依据 GM/T 0128—2023 6.4.5.1，首次握手消息的 message_seq 从 0 开始，
// 每生成一条新消息加 1。服务端 sendFinished 已按此规则设置序号，客户端应保持一致。
//
// 测试直接构造客户端握手状态调用 sendFinished，以便在握手头仍为明文时观测序号。
func TestClientFinishedMessageSeq(t *testing.T) {
	clientPConn, serverPConn := newMockPacketConn()
	defer clientPConn.Close()
	defer serverPConn.Close()

	capture := &capturePacketConn{PacketConn: clientPConn}

	cfg := &Config{
		InsecureSkipVerify:       true,
		NewTimer:                 newMockTimer,
		Time:                     time.Now,
		InitialRetransmitTimeout: 200 * time.Millisecond,
		MaxRetransmitTimeout:     time.Second,
	}
	c := Client(capture, serverPConn.LocalAddr(), cfg)
	c.vers = VersionTLCP

	// 客户端在 sendFinished 前已完成密钥协商（establishKeys），此处补齐输出密码规格，
	// 使 writeChangeCipherRecord 能够正常切换密码规格。测试使用恒等的分组模式，
	// 以便直接读取 Finished 的握手消息头（生产环境下该头部位于加密记录内）。
	suite := cipherSuites[ECC_SM4_CBC_SM3]
	key := make([]byte, suite.keyLen)
	c.out.prepareCipherSpec(VersionTLCP, identityBlockMode{blockSize: 16}, suite.mac(key))

	// 模拟已完成 Cookie 交换与 Flight 5 的客户端：已发送 ClientHello(0)、
	// 携带 cookie 的 ClientHello(1)、ClientKeyExchange(2)。
	c.messageSeq = 3

	hs := &clientHandshakeState{
		c:            c,
		finishedHash: newFinishedHash(VersionTLCP, suite),
	}

	if err := hs.sendFinished(make([]byte, 12)); err != nil {
		t.Fatalf("sendFinished 失败: %v", err)
	}

	capture.mu.Lock()
	defer capture.mu.Unlock()

	var got uint16
	var found bool
	for _, p := range capture.sent {
		if seq, ok := findFinishedSeq(p, 16); ok {
			got, found = seq, true
		}
	}
	if !found {
		t.Fatalf("客户端发送的报文中未找到 Finished 消息，共捕获 %d 个数据报", len(capture.sent))
	}
	if got != 3 {
		t.Fatalf("客户端 Finished 的 message_seq 应为 3，实际 %d", got)
	}
	if c.messageSeq != 4 {
		t.Fatalf("发送 Finished 后 messageSeq 应为 4，实际 %d", c.messageSeq)
	}
}
