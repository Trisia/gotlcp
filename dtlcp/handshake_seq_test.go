// Copyright (c) 2026 gotlcp contributors
// gotlcp is licensed under Mulan PSL v2.

package dtlcp

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"
)

// =============================================================================
// 测试辅助：握手消息序号校验
// =============================================================================

// makeTestHandshakeMsg 构造一条带指定类型与 message_seq 的完整握手消息。
//
// 消息体含 4 字节身份标记（由 seq 派生），用于验证按序取出的内容未发生错位。
//
// 参数：
//   - typ：握手消息类型，如 typeFinished。
//   - seq：握手消息序号 message_seq。
//
// 返回值：
//   - []byte：12 字节握手头 + 4 字节消息体。
func makeTestHandshakeMsg(typ uint8, seq uint16) []byte {
	const bodyLen = 4
	data := make([]byte, dtlcpHeaderLen+bodyLen)
	data[0] = typ
	data[1] = byte(bodyLen >> 16)
	data[2] = byte(bodyLen >> 8)
	data[3] = byte(bodyLen)
	data[4] = byte(seq >> 8)
	data[5] = byte(seq)
	// fragOff 为 0
	data[9] = byte(bodyLen >> 16)
	data[10] = byte(bodyLen >> 8)
	data[11] = byte(bodyLen)
	for i := 0; i < bodyLen; i++ {
		data[dtlcpHeaderLen+i] = byte(seq)
	}
	return data
}

// testHandshakeSeqConn 创建一个未握手的连接，用于直接驱动 readHandshake。
//
// 连接不经过网络读写，握手消息由测试预置到 handBuf 中。
//
// 返回值：
//   - *Conn：新建的客户端连接。
func testHandshakeSeqConn() *Conn {
	pconn, _ := newMockPacketConn()
	c := Client(pconn, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 30000}, &Config{
		InsecureSkipVerify:       true,
		NewTimer:                 newMockTimer,
		Time:                     time.Now,
		InitialRetransmitTimeout: 200 * time.Millisecond,
		MaxRetransmitTimeout:     time.Second,
	})
	c.vers = VersionTLCP
	return c
}

// fillHandshakeBuf 把握手消息依次写入 handBuf，模拟它们按给定顺序到达。
//
// 参数：
//   - c：目标连接。
//   - msgs：按到达顺序排列的握手消息。
func fillHandshakeBuf(c *Conn, msgs ...[]byte) {
	c.handBuf.Reset()
	for _, m := range msgs {
		c.handBuf.Write(m)
	}
}

// newTestTranscript 返回用于序号校验测试的握手消息哈希对象。
//
// 返回值：
//   - *finishedHash：SM3 消息哈希。
func newTestTranscript() transcriptHash {
	h := newFinishedHash(VersionTLCP, cipherSuites[ECC_SM4_CBC_SM3])
	return &h
}

// drainHandshakeMsg 从 handBuf 取出一条完整握手消息，模拟 readHandshake 的取消息动作。
//
// 参数：
//   - c：目标连接。
//
// 返回值：
//   - []byte：完整的握手消息（含 12 字节握手头）。
func drainHandshakeMsg(t *testing.T, c *Conn) []byte {
	t.Helper()
	if c.handBuf.Len() < dtlcpHeaderLen {
		t.Fatalf("handBuf 中剩余数据不足一个握手头：%d 字节", c.handBuf.Len())
	}
	head := c.handBuf.Bytes()
	bodyLen := int(head[1])<<16 | int(head[2])<<8 | int(head[3])
	if c.handBuf.Len() < dtlcpHeaderLen+bodyLen {
		t.Fatalf("handBuf 中剩余数据不足一条握手消息：需要 %d 字节，实际 %d 字节",
			dtlcpHeaderLen+bodyLen, c.handBuf.Len())
	}
	return append([]byte(nil), c.handBuf.Next(dtlcpHeaderLen+bodyLen)...)
}

// =============================================================================
// 测试
// =============================================================================

// TestHandshakeSeqOutOfOrder 验证乱序到达的握手消息先被缓存，
// 前序消息补齐后按 next_receive_seq 顺序取出处理（GM/T 0128—2023 6.4.5.1）。
//
// 验证点：
//   - message_seq 大于 next_receive_seq 的消息存入 pendingHandshake 且不立即返回；
//   - 前序消息到达后，此前缓存的消息被按序取出，序号连续；
//   - next_receive_seq 随处理推进，缓存被取空。
func TestHandshakeSeqOutOfOrder(t *testing.T) {
	c := testHandshakeSeqConn()

	// 按序到达 message_seq = 0，立即处理
	fillHandshakeBuf(c, makeTestHandshakeMsg(typeFinished, 0))
	_, err := c.readHandshake(newTestTranscript())
	if err != nil {
		t.Fatalf("读取序号 0 的握手消息失败: %v", err)
	}
	if c.nextReceiveSeq != 1 {
		t.Fatalf("处理序号 0 后 nextReceiveSeq 应为 1，实际 %d", c.nextReceiveSeq)
	}

	// 乱序到达：先来序号 2，再来序号 1
	fillHandshakeBuf(c,
		makeTestHandshakeMsg(typeFinished, 2),
		makeTestHandshakeMsg(typeFinished, 1),
	)

	if _, done, err := c.sequencedHandshakeData(drainHandshakeMsg(t, c)); err != nil {
		t.Fatalf("缓存序号 2 的乱序消息失败: %v", err)
	} else if done {
		t.Fatal("序号 2 的乱序消息不应被立即处理")
	}
	if len(c.pendingHandshake) != 1 {
		t.Fatalf("序号 2 应进入乱序缓存，实际缓存 %d 条", len(c.pendingHandshake))
	}
	if _, exists := c.pendingHandshake[2]; !exists {
		t.Fatalf("乱序缓存应以序号 2 为键，实际键为 %v", pendingHandshakeKeys(c))
	}

	if _, done, err := c.sequencedHandshakeData(drainHandshakeMsg(t, c)); err != nil {
		t.Fatalf("处理序号 1 的握手消息失败: %v", err)
	} else if !done {
		t.Fatal("序号 1 与 nextReceiveSeq 相同，应被立即处理")
	}
	if c.nextReceiveSeq != 2 {
		t.Fatalf("处理序号 1 后 nextReceiveSeq 应为 2，实际 %d", c.nextReceiveSeq)
	}

	// 前序补齐后，序号 2 应可按序取出，且内容未错位
	cached, ok := c.nextCachedHandshake()
	if !ok {
		t.Fatal("序号 2 已满足连续性，nextCachedHandshake 应能取出该消息")
	}
	if !bytes.Equal(cached, makeTestHandshakeMsg(typeFinished, 2)) {
		t.Fatal("从乱序缓存取出的消息内容与原始序号 2 的消息不一致")
	}
	if c.nextReceiveSeq != 3 {
		t.Fatalf("取出序号 2 后 nextReceiveSeq 应为 3，实际 %d", c.nextReceiveSeq)
	}
	if len(c.pendingHandshake) != 0 {
		t.Fatalf("按序取出后乱序缓存应清空，实际剩余 %d 条", len(c.pendingHandshake))
	}
}

// pendingHandshakeKeys 返回乱序缓存中当前的所有序号，用于失败信息展示。
//
// 参数：
//   - c：目标连接。
//
// 返回值：
//   - []uint16：缓存中的序号列表，顺序不确定。
func pendingHandshakeKeys(c *Conn) []uint16 {
	keys := make([]uint16, 0, len(c.pendingHandshake))
	for k := range c.pendingHandshake {
		keys = append(keys, k)
	}
	return keys
}

// TestHandshakeSeqDuplicate 验证序号小于 next_receive_seq 的消息被判为对端重传：
// 不重复处理、不推进序号，readHandshake 返回 errPeerRetransmit，
// 由等待方据此整轮重传（GM/T 0128—2023 6.4.5.3 b)）。
//
// 验证点：
//   - 重复序号消息使 readHandshake 返回 errPeerRetransmit；
//   - peerRetransmit 被置位，takePeerRetransmit 消费一次后复位；
//   - next_receive_seq 不推进，重复消息不进入乱序缓存。
func TestHandshakeSeqDuplicate(t *testing.T) {
	c := testHandshakeSeqConn()

	// 先按序处理 message_seq = 0
	fillHandshakeBuf(c, makeTestHandshakeMsg(typeFinished, 0))
	if _, err := c.readHandshake(newTestTranscript()); err != nil {
		t.Fatalf("读取序号 0 的握手消息失败: %v", err)
	}
	if c.nextReceiveSeq != 1 {
		t.Fatalf("处理序号 0 后 nextReceiveSeq 应为 1，实际 %d", c.nextReceiveSeq)
	}

	// 对端重传了序号 0
	fillHandshakeBuf(c, makeTestHandshakeMsg(typeFinished, 0))
	msg, err := c.readHandshake(newTestTranscript())
	if !errors.Is(err, errPeerRetransmit) {
		t.Fatalf("收到重传的序号 0 应返回 errPeerRetransmit，实际返回 %v（消息 %T）", err, msg)
	}
	if !c.peerRetransmit {
		t.Fatal("收到重传消息后 peerRetransmit 应被置位")
	}
	if c.nextReceiveSeq != 1 {
		t.Fatalf("重传消息不应推进 nextReceiveSeq，期望 1，实际 %d", c.nextReceiveSeq)
	}
	if len(c.pendingHandshake) != 0 {
		t.Fatalf("重传消息不应进入乱序缓存，实际缓存 %d 条", len(c.pendingHandshake))
	}

	// 重传标记只消费一次
	if !c.takePeerRetransmit() {
		t.Fatal("takePeerRetransmit 首次调用应返回 true")
	}
	if c.takePeerRetransmit() {
		t.Fatal("重传标记已被消费，takePeerRetransmit 第二次调用应返回 false")
	}
}

// TestHandshakePendingOverflow 验证乱序缓存达到 maxPendingHandshake 上限后报错，
// 防止恶意对端用海量乱序消息耗尽内存（GM/T 0128—2023 6.4.5.1）。
//
// 验证点：
//   - 缓存数量达到上限时仍接受新序号的乱序消息；
//   - 第 maxPendingHandshake+1 条不同序号的乱序消息触发错误；
//   - 同一序号重复到达按覆盖处理，不触发溢出；
//   - readHandshake 路径同样把溢出错误上报给调用方。
func TestHandshakePendingOverflow(t *testing.T) {
	c := testHandshakeSeqConn()

	// nextReceiveSeq 保持 0，序号 1..maxPendingHandshake 全部乱序入缓存
	var msgs [][]byte
	for i := 1; i <= maxPendingHandshake; i++ {
		msgs = append(msgs, makeTestHandshakeMsg(typeFinished, uint16(i)))
	}
	fillHandshakeBuf(c, msgs...)

	for i := 1; i <= maxPendingHandshake; i++ {
		if _, done, err := c.sequencedHandshakeData(drainHandshakeMsg(t, c)); err != nil {
			t.Fatalf("缓存第 %d 条乱序消息时不应报错: %v", i, err)
		} else if done {
			t.Fatalf("序号 %d 大于 nextReceiveSeq，不应被立即处理", i)
		}
	}
	if len(c.pendingHandshake) != maxPendingHandshake {
		t.Fatalf("乱序缓存应达到上限 %d 条，实际 %d 条", maxPendingHandshake, len(c.pendingHandshake))
	}

	// 同序号覆盖不占新额度，也不报错
	if _, _, err := c.sequencedHandshakeData(makeTestHandshakeMsg(typeFinished, 1)); err != nil {
		t.Fatalf("同序号消息重发应按覆盖处理，不应报错，实际 %v", err)
	}

	// 缓存已满，新序号消息应报错
	overflowSeq := uint16(maxPendingHandshake + 1)
	overflow := makeTestHandshakeMsg(typeFinished, overflowSeq)
	if _, _, err := c.sequencedHandshakeData(overflow); err == nil {
		t.Fatalf("乱序缓存超过 %d 条时 sequencedHandshakeData 应报错，实际未报错", maxPendingHandshake)
	}

	// readHandshake 路径同样暴露该错误
	fillHandshakeBuf(c, overflow)
	if _, err := c.readHandshake(newTestTranscript()); err == nil {
		t.Fatal("乱序缓存溢出时 readHandshake 应返回错误，实际返回 nil")
	}
	if c.in.err == nil {
		t.Fatal("readHandshake 溢出错误应记录到读取侧错误状态 in.err")
	}
}