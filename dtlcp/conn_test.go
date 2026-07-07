// Copyright (c) 2025 gotlcp contributors
// gotlcp is licensed under Mulan PSL v2.

package dtlcp

import (
	"bytes"
	"strings"
	"testing"
)

// =============================================================================
// 记录头常量测试
// =============================================================================

// TestRecordHeaderLen 测试记录头长度常量。
func TestRecordHeaderLen(t *testing.T) {
	if recordHeaderLen != 13 {
		t.Fatalf("recordHeaderLen 应为 13，实际 %d", recordHeaderLen)
	}
}

// TestMaxPlaintext 测试最大明文长度常量。
func TestMaxPlaintext(t *testing.T) {
	if maxPlaintext != 16384 {
		t.Fatalf("maxPlaintext 应为 16384，实际 %d", maxPlaintext)
	}
}

// =============================================================================
// 序列号编码测试
// =============================================================================

// TestSetWriteSeq 测试 setWriteSeq 方法正确编码 epoch 和序列号。
func TestSetWriteSeq(t *testing.T) {
	c := &Conn{
		writeEpoch: 0,
		writeSeq:   0,
	}
	c.out.seq = [8]byte{}
	c.setWriteSeq()

	// epoch=0, seq=0 => 全 0
	expected := [8]byte{0, 0, 0, 0, 0, 0, 0, 0}
	if c.out.seq != expected {
		t.Fatalf("seq(0,0) 应为全 0，实际 %x", c.out.seq)
	}

	// epoch=1, seq=1
	c.writeEpoch = 1
	c.writeSeq = 1
	c.setWriteSeq()

	if c.out.seq[0] != 0 || c.out.seq[1] != 1 {
		t.Fatalf("epoch 编码错误: [0:2]=%x", c.out.seq[:2])
	}
	if c.out.seq[7] != 1 {
		t.Fatalf("seq 编码错误: [7]=%x", c.out.seq[7])
	}
}

// TestSetWriteSeqLarge 测试大 epoch 和序列号的编码。
func TestSetWriteSeqLarge(t *testing.T) {
	c := &Conn{
		writeEpoch: 0xABCD,
		writeSeq:   0x123456789ABC,
	}
	c.out.seq = [8]byte{}
	c.setWriteSeq()

	expected := [8]byte{0xAB, 0xCD, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}
	if !bytes.Equal(c.out.seq[:], expected[:]) {
		t.Fatalf("seq 编码错误: 期望 %x，实际 %x", expected, c.out.seq)
	}
}

// =============================================================================
// halfConn 基础功能测试
// =============================================================================

// TestPrepareCipherSpec 测试 prepareCipherSpec 设置 nextCipher 和 nextMac。
func TestPrepareCipherSpec(t *testing.T) {
	var hc halfConn

	// 无加密时
	if hc.explicitNonceLen() != 0 {
		t.Fatalf("无加密时 explicitNonceLen 应为 0，实际 %d", hc.explicitNonceLen())
	}

	// prepareCipherSpec 设置后，未 changeCipherSpec 前不应生效
	hc.prepareCipherSpec(VersionTLCP, nil, nil)
	if hc.cipher != nil {
		t.Fatal("prepareCipherSpec 后 cipher 应仍为 nil")
	}
	if hc.nextCipher != nil {
		t.Fatal("nextCipher 应被设置为 nil（参数为 nil）")
	}
}

// TestChangeCipherSpec 测试 changeCipherSpec 切换密码参数。
func TestChangeCipherSpec(t *testing.T) {
	var hc halfConn

	// 未 prepare 时直接 change 应报错
	err := hc.changeCipherSpec()
	if err == nil {
		t.Fatal("未 prepare 时 changeCipherSpec 应返回错误")
	}
	if !strings.Contains(err.Error(), "internal error") {
		t.Fatalf("错误消息应包含 internal error，实际: %v", err)
	}

	// prepare 后 change 应成功
	hc.prepareCipherSpec(VersionTLCP, "test-cipher", nil)
	err = hc.changeCipherSpec()
	if err != nil {
		t.Fatalf("changeCipherSpec 失败: %v", err)
	}

	if hc.cipher != "test-cipher" {
		t.Fatal("cipher 应切换到 test-cipher")
	}
	if hc.mac != nil {
		t.Fatal("mac 应为 nil")
	}
	if hc.nextCipher != nil {
		t.Fatal("nextCipher 应被清空")
	}
	if hc.nextMac != nil {
		t.Fatal("nextMac 应被清空")
	}
}

// TestChangeCipherSpecResetsSeq 测试 changeCipherSpec 重置序列号。
func TestChangeCipherSpecResetsSeq(t *testing.T) {
	var hc halfConn
	hc.seq[0] = 0xAB
	hc.seq[7] = 0xCD

	hc.prepareCipherSpec(VersionTLCP, "test-cipher", nil)
	_ = hc.changeCipherSpec()

	for i, b := range hc.seq {
		if b != 0 {
			t.Fatalf("changeCipherSpec 后 seq[%d] 应为 0，实际 %d", i, b)
		}
	}
}

// =============================================================================
// 记录类型常量测试
// =============================================================================

// TestRecordTypeValues 测试记录类型常量值。
func TestRecordTypeValues(t *testing.T) {
	if recordTypeChangeCipherSpec != 20 {
		t.Fatalf("recordTypeChangeCipherSpec 应为 20，实际 %d", recordTypeChangeCipherSpec)
	}
	if recordTypeAlert != 21 {
		t.Fatalf("recordTypeAlert 应为 21，实际 %d", recordTypeAlert)
	}
	if recordTypeHandshake != 22 {
		t.Fatalf("recordTypeHandshake 应为 22，实际 %d", recordTypeHandshake)
	}
	if recordTypeApplicationData != 23 {
		t.Fatalf("recordTypeApplicationData 应为 23，实际 %d", recordTypeApplicationData)
	}
}

// =============================================================================
// maxPayloadSizeForWrite 测试
// =============================================================================

// TestMaxPayloadSizeForWrite 测试最大 payload 大小计算。
func TestMaxPayloadSizeForWrite(t *testing.T) {
	c := &Conn{
		config: &Config{PMTU: 1400},
	}

	// 无加密时
	maxSize := c.maxPayloadSizeForWrite(recordTypeHandshake)
	// PMTU(1400) - recordHeaderLen(13) = 1387
	if maxSize != 1387 {
		t.Fatalf("无加密预期 1387，实际 %d", maxSize)
	}
}

// TestMaxPayloadSizeForWriteSmallPMTU 测试小 PMTU 下的最大 payload 大小。
func TestMaxPayloadSizeForWriteSmallPMTU(t *testing.T) {
	c := &Conn{
		config: &Config{PMTU: 100},
	}

	maxSize := c.maxPayloadSizeForWrite(recordTypeHandshake)
	// PMTU(100) - recordHeaderLen(13) = 87
	if maxSize != 87 {
		t.Fatalf("PMTU=100 预期 87，实际 %d", maxSize)
	}
}

// TestMaxPayloadSizeForWriteDefaultPMTU 测试默认 PMTU（0）时的最大 payload 大小。
func TestMaxPayloadSizeForWriteDefaultPMTU(t *testing.T) {
	c := &Conn{
		config: &Config{PMTU: 0}, // 默认 1400
	}

	maxSize := c.maxPayloadSizeForWrite(recordTypeHandshake)
	// PMTU(1400) - recordHeaderLen(13) = 1387
	if maxSize != 1387 {
		t.Fatalf("默认 PMTU 预期 1387，实际 %d", maxSize)
	}
}

// TestRecordHeaderEncode 测试 DTLCP 记录头编码格式。
func TestRecordHeaderEncode(t *testing.T) {
	// DTLCP 记录头：Type(1) + Version(2) + Epoch(2) + SeqNum(6) + Length(2) = 13
	hdr := make([]byte, recordHeaderLen)

	hdr[0] = byte(recordTypeHandshake)
	versVal := uint16(VersionTLCP)
	hdr[1] = byte(versVal >> 8)
	hdr[2] = byte(versVal)
	hdr[3] = 0 // epoch hi
	hdr[4] = 0 // epoch lo
	hdr[5] = 0 // seq num
	hdr[6] = 0
	hdr[7] = 0
	hdr[8] = 0
	hdr[9] = 0
	hdr[10] = 1 // seq = 1
	hdr[11] = byte(100 >> 8)
	hdr[12] = byte(100)

	// 验证结构
	if hdr[0] != 22 { // recordTypeHandshake
		t.Fatalf("Type 应为 22(Handshake)，实际 %d", hdr[0])
	}
	vers := uint16(hdr[1])<<8 | uint16(hdr[2])
	if vers != VersionTLCP {
		t.Fatalf("Version 应为 0x%04x，实际 0x%04x", VersionTLCP, vers)
	}
	epoch := uint16(hdr[3])<<8 | uint16(hdr[4])
	if epoch != 0 {
		t.Fatalf("Epoch 应为 0，实际 %d", epoch)
	}
	seq := uint48(hdr[5])<<40 | uint48(hdr[6])<<32 | uint48(hdr[7])<<24 |
		uint48(hdr[8])<<16 | uint48(hdr[9])<<8 | uint48(hdr[10])
	if seq != 1 {
		t.Fatalf("Seq 应为 1，实际 %d", seq)
	}
	length := int(hdr[11])<<8 | int(hdr[12])
	if length != 100 {
		t.Fatalf("Length 应为 100，实际 %d", length)
	}
}
