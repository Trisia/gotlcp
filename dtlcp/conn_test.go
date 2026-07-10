// Copyright (c) 2025 gotlcp contributors
// gotlcp is licensed under Mulan PSL v2.

package dtlcp

import (
	"bytes"
	"crypto/rand"
	"strings"
	"sync"
	"testing"
	"time"
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

// =============================================================================
// 记录层加解密往返测试
// =============================================================================

// makeRecordHeader 构造 DTLCP 13字节记录头并同步 halfConn.seq。
// 返回包含完整记录头的切片。
func makeRecordHeader(hc *halfConn, typ recordType, vers uint16, epoch uint16, seqNum uint48, payloadLen int) []byte {
	record := make([]byte, recordHeaderLen)
	record[0] = byte(typ)
	record[1] = byte(vers >> 8)
	record[2] = byte(vers)
	record[3] = byte(epoch >> 8)
	record[4] = byte(epoch)
	record[5] = byte(seqNum >> 40)
	record[6] = byte(seqNum >> 32)
	record[7] = byte(seqNum >> 24)
	record[8] = byte(seqNum >> 16)
	record[9] = byte(seqNum >> 8)
	record[10] = byte(seqNum)
	record[11] = byte(payloadLen >> 8)
	record[12] = byte(payloadLen)
	// 同步 halfConn.seq：epoch(2) + seq_num(6)
	hc.seq[0] = record[3]
	hc.seq[1] = record[4]
	hc.seq[2] = record[5]
	hc.seq[3] = record[6]
	hc.seq[4] = record[7]
	hc.seq[5] = record[8]
	hc.seq[6] = record[9]
	hc.seq[7] = record[10]
	return record
}

// TestAEADRoundTrip 测试 SM4-GCM 加密后解密的往返正确性。
func TestAEADRoundTrip(t *testing.T) {
	key := make([]byte, 16)
	implicitNonce := make([]byte, 4)
	aeadCipher := aeadSM4GCM(key, implicitNonce)

	hc := &halfConn{}
	hc.prepareCipherSpec(VersionTLCP, aeadCipher, nil)
	if err := hc.changeCipherSpec(); err != nil {
		t.Fatalf("changeCipherSpec 失败: %v", err)
	}

	plaintext := []byte("Hello DTLCP AEAD Round Trip Test!")
	record := makeRecordHeader(hc, recordTypeApplicationData, VersionTLCP, 0, 1, len(plaintext))

	encrypted, err := hc.encrypt(record, plaintext, rand.Reader)
	if err != nil {
		t.Fatalf("encrypt 失败: %v", err)
	}

	// 解密：重建相同参数的 halfConn（读方向）
	hc2 := &halfConn{}
	aeadCipher2 := aeadSM4GCM(key, implicitNonce)
	hc2.prepareCipherSpec(VersionTLCP, aeadCipher2, nil)
	if err := hc2.changeCipherSpec(); err != nil {
		t.Fatalf("changeCipherSpec(hc2) 失败: %v", err)
	}
	hc2.seq = hc.seq

	decrypted, typ, err := hc2.decrypt(encrypted)
	if err != nil {
		t.Fatalf("decrypt 失败: %v", err)
	}
	if typ != recordTypeApplicationData {
		t.Fatalf("记录类型应为 %d，实际 %d", recordTypeApplicationData, typ)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("往返明文不匹配:\n  原始: %x\n  解密: %x", plaintext, decrypted)
	}
}

// TestCBCOneWay 测试 SM4-CBC + SM3 HMAC 加密后解密的正确性。
func TestCBCRoundTrip(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 16)
	macKey := make([]byte, 32)

	encCipher := cipherSM4(key, iv, false).(cbcMode)
	macHash := macSM3(macKey)

	hcEnc := &halfConn{}
	hcEnc.prepareCipherSpec(VersionTLCP, encCipher, macHash)
	if err := hcEnc.changeCipherSpec(); err != nil {
		t.Fatalf("changeCipherSpec(enc) 失败: %v", err)
	}

	plaintext := []byte("Hello DTLCP CBC Round Trip Test!")
	record := makeRecordHeader(hcEnc, recordTypeApplicationData, VersionTLCP, 0, 1, len(plaintext))

	encrypted, err := hcEnc.encrypt(record, plaintext, rand.Reader)
	if err != nil {
		t.Fatalf("encrypt 失败: %v", err)
	}

	hcDec := &halfConn{}
	decCipher2 := cipherSM4(key, iv, true).(cbcMode)
	macHash2 := macSM3(macKey)
	hcDec.prepareCipherSpec(VersionTLCP, decCipher2, macHash2)
	if err := hcDec.changeCipherSpec(); err != nil {
		t.Fatalf("changeCipherSpec(dec) 失败: %v", err)
	}
	hcDec.seq = hcEnc.seq

	decrypted, typ, err := hcDec.decrypt(encrypted)
	if err != nil {
		t.Fatalf("decrypt 失败: %v", err)
	}
	if typ != recordTypeApplicationData {
		t.Fatalf("记录类型应为 %d，实际 %d", recordTypeApplicationData, typ)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("往返明文不匹配:\n  原始: %x\n  解密: %x", plaintext, decrypted)
	}
}

// TestAEADTamperDetection 测试篡改密文被 AEAD 认证标签检测到。
func TestAEADTamperDetection(t *testing.T) {
	key := make([]byte, 16)
	implicitNonce := make([]byte, 4)
	aeadCipher := aeadSM4GCM(key, implicitNonce)

	hc := &halfConn{}
	hc.prepareCipherSpec(VersionTLCP, aeadCipher, nil)
	hc.changeCipherSpec()

	plaintext := []byte("Tamper Detection Test Payload")
	record := makeRecordHeader(hc, recordTypeApplicationData, VersionTLCP, 0, 42, len(plaintext))

	encrypted, err := hc.encrypt(record, plaintext, rand.Reader)
	if err != nil {
		t.Fatalf("encrypt 失败: %v", err)
	}

	// 篡改密文最后一个字节
	tampered := make([]byte, len(encrypted))
	copy(tampered, encrypted)
	tampered[len(tampered)-1] ^= 0x01

	hc2 := &halfConn{}
	aeadCipher2 := aeadSM4GCM(key, implicitNonce)
	hc2.prepareCipherSpec(VersionTLCP, aeadCipher2, nil)
	hc2.changeCipherSpec()
	hc2.seq = hc.seq

	_, _, err = hc2.decrypt(tampered)
	if err == nil {
		t.Fatal("篡改密文应被检测到，但 decrypt 成功返回")
	}
	if alertErr, ok := err.(alert); !ok || alertErr != alertBadRecordMAC {
		t.Fatalf("期望 alertBadRecordMAC(20)，实际 %v", err)
	}
}

// TestCBCTamperDetection 测试篡改密文被 CBC MAC 检测到。
func TestCBCTamperDetection(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 16)
	macKey := make([]byte, 32)

	encCipher := cipherSM4(key, iv, false).(cbcMode)
	macHash := macSM3(macKey)

	hcEnc := &halfConn{}
	hcEnc.prepareCipherSpec(VersionTLCP, encCipher, macHash)
	hcEnc.changeCipherSpec()

	plaintext := []byte("CBC Tamper Detection Test")
	record := makeRecordHeader(hcEnc, recordTypeApplicationData, VersionTLCP, 0, 7, len(plaintext))

	encrypted, err := hcEnc.encrypt(record, plaintext, rand.Reader)
	if err != nil {
		t.Fatalf("encrypt 失败: %v", err)
	}

	// 篡改密文内容
	tampered := make([]byte, len(encrypted))
	copy(tampered, encrypted)
	tampered[recordHeaderLen+1] ^= 0xFF

	hcDec := &halfConn{}
	decCipher := cipherSM4(key, iv, true).(cbcMode)
	macHash2 := macSM3(macKey)
	hcDec.prepareCipherSpec(VersionTLCP, decCipher, macHash2)
	hcDec.changeCipherSpec()
	hcDec.seq = hcEnc.seq

	_, _, err = hcDec.decrypt(tampered)
	if err == nil {
		t.Fatal("篡改密文应被检测到，但 decrypt 成功返回")
	}
	if alertErr, ok := err.(alert); !ok || alertErr != alertBadRecordMAC {
		t.Fatalf("期望 alertBadRecordMAC(20)，实际 %v", err)
	}
}

// TestAEADSeqTamperDetection 测试解密侧 seq 与加密侧不匹配时被 AEAD AAD 检测到。
// 验证 AAD 正确绑定了 hc.seq（epoch+seq_num），防止跨序列号伪造。
func TestAEADSeqTamperDetection(t *testing.T) {
	key := make([]byte, 16)
	implicitNonce := make([]byte, 4)
	aeadCipher := aeadSM4GCM(key, implicitNonce)

	hc := &halfConn{}
	hc.prepareCipherSpec(VersionTLCP, aeadCipher, nil)
	hc.changeCipherSpec()

	plaintext := []byte("Seq Tamper Test")
	record := makeRecordHeader(hc, recordTypeApplicationData, VersionTLCP, 0, 100, len(plaintext))

	encrypted, err := hc.encrypt(record, plaintext, rand.Reader)
	if err != nil {
		t.Fatalf("encrypt 失败: %v", err)
	}

	// 解密侧使用不同的 seq，模拟重放攻击
	hc2 := &halfConn{}
	aeadCipher2 := aeadSM4GCM(key, implicitNonce)
	hc2.prepareCipherSpec(VersionTLCP, aeadCipher2, nil)
	hc2.changeCipherSpec()
	hc2.seq = hc.seq
	hc2.seq[7] ^= 0x01 // 翻转 seq_num 最低位，与加密侧不同

	_, _, err = hc2.decrypt(encrypted)
	if err == nil {
		t.Fatal("seq 不匹配应被 AAD 检测到，但 decrypt 成功返回")
	}
}

// TestAEADTypeTamperDetection 测试篡改记录类型被 AEAD AAD 检测到。
func TestAEADTypeTamperDetection(t *testing.T) {
	key := make([]byte, 16)
	implicitNonce := make([]byte, 4)
	aeadCipher := aeadSM4GCM(key, implicitNonce)

	hc := &halfConn{}
	hc.prepareCipherSpec(VersionTLCP, aeadCipher, nil)
	hc.changeCipherSpec()

	plaintext := []byte("Type Tamper Test")
	record := makeRecordHeader(hc, recordTypeApplicationData, VersionTLCP, 0, 1, len(plaintext))

	encrypted, err := hc.encrypt(record, plaintext, rand.Reader)
	if err != nil {
		t.Fatalf("encrypt 失败: %v", err)
	}

	// 篡改记录类型 23(ApplicationData) → 22(Handshake)
	tampered := make([]byte, len(encrypted))
	copy(tampered, encrypted)
	tampered[0] = byte(recordTypeHandshake)

	hc2 := &halfConn{}
	aeadCipher2 := aeadSM4GCM(key, implicitNonce)
	hc2.prepareCipherSpec(VersionTLCP, aeadCipher2, nil)
	hc2.changeCipherSpec()
	hc2.seq = hc.seq

	_, _, err = hc2.decrypt(tampered)
	if err == nil {
		t.Fatal("篡改 type 应被 AAD 检测到，但 decrypt 成功返回")
	}
}

// TestAEADVersionTamperDetection 测试篡改记录版本号被 AEAD AAD 检测到。
// 验证 AAD 正确绑定了 version 字段，防止版本降级攻击。
func TestAEADVersionTamperDetection(t *testing.T) {
	key := make([]byte, 16)
	implicitNonce := make([]byte, 4)
	aeadCipher := aeadSM4GCM(key, implicitNonce)

	hc := &halfConn{}
	hc.prepareCipherSpec(VersionTLCP, aeadCipher, nil)
	hc.changeCipherSpec()

	plaintext := []byte("Version Tamper Detection Test")
	record := makeRecordHeader(hc, recordTypeApplicationData, VersionTLCP, 0, 1, len(plaintext))

	encrypted, err := hc.encrypt(record, plaintext, rand.Reader)
	if err != nil {
		t.Fatalf("encrypt 失败: %v", err)
	}

	// 篡改记录头中的 version 字段
	tampered := make([]byte, len(encrypted))
	copy(tampered, encrypted)
	tampered[2] ^= 0x01 // 翻转 version 低字节

	hc2 := &halfConn{}
	aeadCipher2 := aeadSM4GCM(key, implicitNonce)
	hc2.prepareCipherSpec(VersionTLCP, aeadCipher2, nil)
	hc2.changeCipherSpec()
	hc2.seq = hc.seq

	_, _, err = hc2.decrypt(tampered)
	if err == nil {
		t.Fatal("篡改 version 应被 AAD 检测到，但 decrypt 成功返回")
	}
}

// TestAEADEmptyPayload 测试空 payload 的 AEAD 加解密。
func TestAEADEmptyPayload(t *testing.T) {
	key := make([]byte, 16)
	implicitNonce := make([]byte, 4)
	aeadCipher := aeadSM4GCM(key, implicitNonce)

	hc := &halfConn{}
	hc.prepareCipherSpec(VersionTLCP, aeadCipher, nil)
	hc.changeCipherSpec()

	plaintext := []byte{}
	record := makeRecordHeader(hc, recordTypeApplicationData, VersionTLCP, 0, 0, 0)

	encrypted, err := hc.encrypt(record, plaintext, rand.Reader)
	if err != nil {
		t.Fatalf("encrypt(空) 失败: %v", err)
	}

	hc2 := &halfConn{}
	aeadCipher2 := aeadSM4GCM(key, implicitNonce)
	hc2.prepareCipherSpec(VersionTLCP, aeadCipher2, nil)
	hc2.changeCipherSpec()
	hc2.seq = hc.seq

	decrypted, typ, err := hc2.decrypt(encrypted)
	if err != nil {
		t.Fatalf("decrypt(空) 失败: %v", err)
	}
	if typ != recordTypeApplicationData {
		t.Fatalf("记录类型应为 %d，实际 %d", recordTypeApplicationData, typ)
	}
	if len(decrypted) != 0 {
		t.Fatalf("解密后应为空，实际长度 %d", len(decrypted))
	}
}

// TestAEADLargePayload 测试接近 maxPlaintext 大小的 AEAD 加解密。
func TestAEADLargePayload(t *testing.T) {
	key := make([]byte, 16)
	implicitNonce := make([]byte, 4)
	aeadCipher := aeadSM4GCM(key, implicitNonce)

	hc := &halfConn{}
	hc.prepareCipherSpec(VersionTLCP, aeadCipher, nil)
	hc.changeCipherSpec()

	plaintext := make([]byte, maxPlaintext)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}
	record := makeRecordHeader(hc, recordTypeApplicationData, VersionTLCP, 0, 0xFFFFFFFFFFFF, len(plaintext))

	encrypted, err := hc.encrypt(record, plaintext, rand.Reader)
	if err != nil {
		t.Fatalf("encrypt(大) 失败: %v", err)
	}

	hc2 := &halfConn{}
	aeadCipher2 := aeadSM4GCM(key, implicitNonce)
	hc2.prepareCipherSpec(VersionTLCP, aeadCipher2, nil)
	hc2.changeCipherSpec()
	hc2.seq = hc.seq

	decrypted, _, err := hc2.decrypt(encrypted)
	if err != nil {
		t.Fatalf("decrypt(大) 失败: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("大 payload 往返不匹配，长度: 期望 %d，实际 %d", len(plaintext), len(decrypted))
	}
}

// TestAEADMultipleEpochs 测试不同 epoch 下的 AEAD 往返。
func TestAEADMultipleEpochs(t *testing.T) {
	key := make([]byte, 16)
	implicitNonce := make([]byte, 4)
	aeadCipher := aeadSM4GCM(key, implicitNonce)

	hc := &halfConn{}
	hc.prepareCipherSpec(VersionTLCP, aeadCipher, nil)
	hc.changeCipherSpec()

	epochs := []uint16{0, 1, 2, 255, 65535}
	for _, epoch := range epochs {
		plaintext := []byte("Epoch Test")
		record := makeRecordHeader(hc, recordTypeApplicationData, VersionTLCP, epoch, uint48(epoch)*100, len(plaintext))

		encrypted, err := hc.encrypt(record, plaintext, rand.Reader)
		if err != nil {
			t.Fatalf("epoch=%d encrypt 失败: %v", epoch, err)
		}

		hc2 := &halfConn{}
		aeadCipher2 := aeadSM4GCM(key, implicitNonce)
		hc2.prepareCipherSpec(VersionTLCP, aeadCipher2, nil)
		hc2.changeCipherSpec()
		hc2.seq = hc.seq

		decrypted, _, err := hc2.decrypt(encrypted)
		if err != nil {
			t.Fatalf("epoch=%d decrypt 失败: %v", epoch, err)
		}
		if !bytes.Equal(decrypted, plaintext) {
			t.Fatalf("epoch=%d 往返不匹配", epoch)
		}
	}
}

// TestCBCMultipleEpochs 测试不同 epoch 下的 CBC 往返。
func TestCBCMultipleEpochs(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 16)
	macKey := make([]byte, 32)

	epochs := []uint16{0, 1, 2, 255, 65535}
	for _, epoch := range epochs {
		encCipher := cipherSM4(key, iv, false).(cbcMode)
		macHash := macSM3(macKey)

		hcEnc := &halfConn{}
		hcEnc.prepareCipherSpec(VersionTLCP, encCipher, macHash)
		hcEnc.changeCipherSpec()

		plaintext := []byte("CBC Epoch Varied")
		record := makeRecordHeader(hcEnc, recordTypeApplicationData, VersionTLCP, epoch, uint48(epoch)*42, len(plaintext))

		encrypted, err := hcEnc.encrypt(record, plaintext, rand.Reader)
		if err != nil {
			t.Fatalf("epoch=%d encrypt 失败: %v", epoch, err)
		}

		hcDec := &halfConn{}
		decCipher := cipherSM4(key, iv, true).(cbcMode)
		macHash2 := macSM3(macKey)
		hcDec.prepareCipherSpec(VersionTLCP, decCipher, macHash2)
		hcDec.changeCipherSpec()
		hcDec.seq = hcEnc.seq

		decrypted, _, err := hcDec.decrypt(encrypted)
		if err != nil {
			t.Fatalf("epoch=%d decrypt 失败: %v", epoch, err)
		}
		if !bytes.Equal(decrypted, plaintext) {
			t.Fatalf("epoch=%d 往返不匹配", epoch)
		}
	}
}

// TestNoEncryptRoundTrip 测试无加密保护的记录读写（握手阶段）。
func TestNoEncryptRoundTrip(t *testing.T) {
	hc := &halfConn{}

	plaintext := []byte("Unprotected Handshake Data")
	record := makeRecordHeader(hc, recordTypeHandshake, VersionTLCP, 0, 0, len(plaintext))

	encrypted, err := hc.encrypt(record, plaintext, rand.Reader)
	if err != nil {
		t.Fatalf("encrypt(无加密) 失败: %v", err)
	}

	hc2 := &halfConn{}
	hc2.seq = hc.seq

	decrypted, typ, err := hc2.decrypt(encrypted)
	if err != nil {
		t.Fatalf("decrypt(无加密) 失败: %v", err)
	}
	if typ != recordTypeHandshake {
		t.Fatalf("记录类型应为 %d，实际 %d", recordTypeHandshake, typ)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("无加密往返不匹配:\n  原始: %s\n  解密: %s", plaintext, decrypted)
	}
}

// =============================================================================
// 握手消息分片测试 (RFC 6347 §4.2.3)
// =============================================================================

// TestHandshakeFragmentSmallMessage 验证小消息不分片。
func TestHandshakeFragmentSmallMessage(t *testing.T) {
	// 创建一个证书消息（模拟大消息的基础结构）
	certMsg := &certificateMsg{
		certificates: make([][]byte, 1),
	}
	certMsg.certificates[0] = make([]byte, 100) // 小证书

	// 验证 marshal 产生的数据较小
	data, err := certMsg.marshal()
	if err != nil {
		t.Fatalf("marshal 失败: %v", err)
	}
	// 100 字节证书 + 报文头应远小于默认 PMTU(1400)
	if len(data) > 1400 {
		t.Fatalf("100B 证书消息不应超过 PMTU: len=%d", len(data))
	}
}

// TestHandshakeFragmentLargeMessage 验证大消息被正确分片。
func TestHandshakeFragmentLargeMessage(t *testing.T) {
	// 创建一个大证书消息，强制分片
	certMsg := &certificateMsg{
		certificates: make([][]byte, 1),
	}
	certMsg.certificates[0] = make([]byte, 3000) // 超过默认 PMTU 的证书

	data, err := certMsg.marshal()
	if err != nil {
		t.Fatalf("marshal 失败: %v", err)
	}
	if len(data) <= 1400 {
		t.Fatalf("3000B 证书消息应超过 PMTU: len=%d", len(data))
	}

	// 验证消息头结构正确
	msgType, bodyLen, msgSeq, fragOff, fragLen, body, ok := dtlcpUnmarshalHeader(data)
	if !ok {
		t.Fatal("dtlcpUnmarshalHeader 失败")
	}
	if msgType != typeCertificate {
		t.Fatalf("msgType 应为 %d，实际 %d", typeCertificate, msgType)
	}
	// 证书消息的 bodyLen 包含 3 字节证书链长度 + 各证书的 3 字节长度前缀 + 证书数据
	if bodyLen == 0 {
		t.Fatal("bodyLen 不应为 0")
	}
	if fragOff != 0 {
		t.Fatalf("完整消息的 fragOff 应为 0，实际 %d", fragOff)
	}
	// fragLen 在 marshal 时设为 0 会被 dtlcpMarshalHeader 填充为 len(body)
	if fragLen != uint24(len(body)) {
		t.Fatalf("完整消息的 fragLen 应等于 body 长度 %d，实际 %d", len(body), fragLen)
	}
	_ = msgSeq
}

// TestHandshakeFragmentRoundTrip 测试分片发送→重组接收的完整流程。
func TestHandshakeFragmentRoundTrip(t *testing.T) {
	// 使用小 PMTU 强制分片
	c := &Conn{
		config: &Config{PMTU: 200},
	}
	// 确保 maxPayload 足够小以触发分片
	maxPayload := c.maxPayloadSizeForWrite(recordTypeHandshake)
	if maxPayload >= 300 {
		t.Fatalf("PMTU=200 时 maxPayload 应 < 300，实际 %d", maxPayload)
	}

	// 构造大证书消息
	certMsg := &certificateMsg{
		certificates: make([][]byte, 1),
	}
	certMsg.certificates[0] = make([]byte, 500) // 远超 PMTU=200
	certMsg.setMessageSeq(0)

	data, _ := certMsg.marshal()
	if len(data) <= maxPayload {
		t.Fatalf("消息应需要分片: len=%d > maxPayload=%d", len(data), maxPayload)
	}

	// 验证分片逻辑：通过 dtlcpUnmarshalHeader 检查每个分片头的正确性
	bodyLen := uint24(len(data) - dtlcpHeaderLen)
	maxFragBody := maxPayload - dtlcpHeaderLen
	if maxFragBody <= 0 {
		t.Fatal("PMTU 不足以容纳握手消息头")
	}

	fragmentCount := 0
	var lastOffset uint24
	for offset := uint24(0); offset < bodyLen; {
		fragEnd := offset + uint24(maxFragBody)
		if fragEnd > bodyLen {
			fragEnd = bodyLen
		}
		fragLen := fragEnd - offset

		// 模拟构造分片（header + body）
		fragBody := data[dtlcpHeaderLen+int(offset):dtlcpHeaderLen+int(fragEnd)]
		var fragHdr [dtlcpHeaderLen]byte
		fragHdr[0] = typeCertificate
		fragHdr[1] = byte(bodyLen >> 16)
		fragHdr[2] = byte(bodyLen >> 8)
		fragHdr[3] = byte(bodyLen)
		fragHdr[4] = 0 // msgSeq hi
		fragHdr[5] = 0 // msgSeq lo
		fragHdr[6] = byte(offset >> 16)
		fragHdr[7] = byte(offset >> 8)
		fragHdr[8] = byte(offset)
		fragHdr[9] = byte(fragLen >> 16)
		fragHdr[10] = byte(fragLen >> 8)
		fragHdr[11] = byte(fragLen)

		// 验证分片头可被正确解析 (dtlcpUnmarshalHeader 需要完整分片)
		fullFrag := append(fragHdr[:], fragBody...)
		parsedType, parsedBodyLen, _, parsedOff, parsedFragLen, _, ok := dtlcpUnmarshalHeader(fullFrag)
		if !ok {
			t.Fatalf("分片 %d: 头解析失败", fragmentCount)
		}
		if parsedType != typeCertificate {
			t.Fatalf("分片 %d: msgType 应为 %d，实际 %d", fragmentCount, typeCertificate, parsedType)
		}
		if parsedBodyLen != uint32(bodyLen) {
			t.Fatalf("分片 %d: bodyLen 应为 %d，实际 %d", fragmentCount, bodyLen, parsedBodyLen)
		}
		if parsedOff != offset {
			t.Fatalf("分片 %d: offset 应为 %d，实际 %d", fragmentCount, offset, parsedOff)
		}
		if parsedFragLen != fragLen {
			t.Fatalf("分片 %d: fragLen 应为 %d，实际 %d", fragmentCount, fragLen, parsedFragLen)
		}

		lastOffset = offset
		fragmentCount++
		offset = fragEnd
	}

	if fragmentCount <= 1 {
		t.Fatalf("应产生多个分片，实际 %d", fragmentCount)
	}
	t.Logf("产生 %d 个分片 (bodyLen=%d, maxFragBody=%d)", fragmentCount, bodyLen, maxFragBody)
	_ = lastOffset
}

// TestHandshakeFragmentReassembly 验证分片接收端能正确重组。
func TestHandshakeFragmentReassembly(t *testing.T) {
	bodyLen := uint24(500)
	fb := newFragmentBuffer(bodyLen)

	// 模拟发送 3 个分片
	fragments := []struct {
		offset, length uint24
		data           []byte
	}{
		{0, 200, make([]byte, 200)},
		{200, 200, make([]byte, 200)},
		{400, 100, make([]byte, 100)},
	}
	// 填充可区分的模式
	for i := range fragments[0].data {
		fragments[0].data[i] = byte(i % 256)
	}
	for i := range fragments[1].data {
		fragments[1].data[i] = byte((i + 200) % 256)
	}
	for i := range fragments[2].data {
		fragments[2].data[i] = byte((i + 400) % 256)
	}

	// 乱序添加（测试重组能力）
	fb.addFragment(fragments[2].offset, fragments[2].length, fragments[2].data) // 最后一片先到
	fb.addFragment(fragments[0].offset, fragments[0].length, fragments[0].data) // 第一片后到
	fb.addFragment(fragments[1].offset, fragments[1].length, fragments[1].data) // 中间片最后到

	if !fb.complete() {
		t.Fatal("所有分片到达后应 complete")
	}

	assembled := fb.assembled()
	expected := make([]byte, 500)
	for i := range expected {
		expected[i] = byte(i % 256)
	}
	if !bytes.Equal(assembled, expected) {
		t.Fatal("重组数据与预期不匹配")
	}
}

// =============================================================================
// 握手后大数据传输测试 — 覆盖 writeRecordLocked 循环与 pool buffer 复用路径
// =============================================================================

// TestLargeAppDataAfterHandshake 握手后发送接近 PMTU 大小的应用数据。
// 覆盖 writeRecordLocked 单轮循环路径。
func TestLargeAppDataAfterHandshake(t *testing.T) {
	certs := initTestCerts()
	serverCfg := &Config{
		Certificates:             []Certificate{certs.sigCert, certs.encCert},
		Time:                     time.Now,
		InitialRetransmitTimeout: 200 * time.Millisecond,
		MaxRetransmitTimeout:     1 * time.Second,
	}
	clientCfg := &Config{
		InsecureSkipVerify: true,
		Time:               time.Now,
	}

	cli, svr := testHandshakePair(t, clientCfg, serverCfg)
	if err := doHandshake(t, cli, svr); err != nil {
		t.Fatalf("握手失败: %v", err)
	}

	// 发送接近 PMTU 的应用数据（1300 字节 — 单条记录）
	payload := make([]byte, 1300)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 2048)
		n, err := svr.Read(buf)
		if err != nil {
			t.Errorf("服务端 Read 失败: %v", err)
			return
		}
		if n != len(payload) {
			t.Errorf("读取长度不匹配: 期望 %d, 实际 %d", len(payload), n)
		}
		if !bytes.Equal(buf[:n], payload) {
			t.Error("数据不一致")
		}
	}()

	n, err := cli.Write(payload)
	if err != nil {
		t.Fatalf("客户端 Write 失败: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("Write 长度不匹配: 期望 %d, 实际 %d", len(payload), n)
	}
	wg.Wait()
}

// TestHugeAppDataMultiRecord 握手后发送超大用户数据（64KB），触发多轮分片循环。
// 验证 writeRecordLocked 中 pool buffer 在循环迭代间正确复用。
func TestHugeAppDataMultiRecord(t *testing.T) {
	certs := initTestCerts()
	serverCfg := &Config{
		Certificates:             []Certificate{certs.sigCert, certs.encCert},
		Time:                     time.Now,
		InitialRetransmitTimeout: 200 * time.Millisecond,
		MaxRetransmitTimeout:     1 * time.Second,
	}
	clientCfg := &Config{
		InsecureSkipVerify: true,
		Time:               time.Now,
	}

	cli, svr := testHandshakePair(t, clientCfg, serverCfg)
	if err := doHandshake(t, cli, svr); err != nil {
		t.Fatalf("握手失败: %v", err)
	}

	// 64KB 数据，远超 PMTU，触发几十轮 writeRecordLocked 循环
	payload := make([]byte, 65536)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	var received []byte
	go func() {
		defer wg.Done()
		buf := make([]byte, 8192)
		for len(received) < len(payload) {
			n, err := svr.Read(buf)
			if err != nil {
				t.Errorf("服务端 Read 失败: %v", err)
				return
			}
			received = append(received, buf[:n]...)
		}
	}()

	n, err := cli.Write(payload)
	if err != nil {
		t.Fatalf("客户端 Write 失败: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("Write 长度不匹配: 期望 %d, 实际 %d", len(payload), n)
	}
	wg.Wait()

	if len(received) != len(payload) {
		t.Fatalf("接收长度不匹配: 期望 %d, 实际 %d", len(payload), len(received))
	}
	if !bytes.Equal(received, payload) {
		t.Error("数据不一致")
	}
}

// TestConsecutiveLargeAppData 握手后连续多次发送大数据，验证 pool buffer 跨
// writeRecordLocked 调用正确复用。
func TestConsecutiveLargeAppData(t *testing.T) {
	certs := initTestCerts()
	serverCfg := &Config{
		Certificates:             []Certificate{certs.sigCert, certs.encCert},
		Time:                     time.Now,
		InitialRetransmitTimeout: 200 * time.Millisecond,
		MaxRetransmitTimeout:     1 * time.Second,
	}
	clientCfg := &Config{
		InsecureSkipVerify: true,
		Time:               time.Now,
	}

	cli, svr := testHandshakePair(t, clientCfg, serverCfg)
	if err := doHandshake(t, cli, svr); err != nil {
		t.Fatalf("握手失败: %v", err)
	}

	const numChunks = 4
	const chunkSize = 16384 // 每段 16KB
	payloads := make([][]byte, numChunks)
	for i := range payloads {
		payloads[i] = make([]byte, chunkSize)
		if _, err := rand.Read(payloads[i]); err != nil {
			t.Fatal(err)
		}
	}

	totalExpected := numChunks * chunkSize
	expected := make([]byte, totalExpected)
	for i, p := range payloads {
		copy(expected[i*chunkSize:], p)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	var received []byte
	go func() {
		defer wg.Done()
		buf := make([]byte, 8192)
		for len(received) < totalExpected {
			n, err := svr.Read(buf)
			if err != nil {
				t.Errorf("服务端 Read 失败: %v", err)
				return
			}
			received = append(received, buf[:n]...)
		}
	}()

	for i, p := range payloads {
		n, err := cli.Write(p)
		if err != nil {
			t.Fatalf("客户端 Write[%d] 失败: %v", i, err)
		}
		if n != len(p) {
			t.Fatalf("Write[%d] 长度不匹配: 期望 %d, 实际 %d", i, len(p), n)
		}
	}
	wg.Wait()

	if len(received) != totalExpected {
		t.Fatalf("接收长度不匹配: 期望 %d, 实际 %d", totalExpected, len(received))
	}
	if !bytes.Equal(received, expected) {
		t.Error("数据不一致")
	}
}

// TestHandshakeFragmentMaxBodySize 验证极端 PMTU 下 maxFragBody 为正。
func TestHandshakeFragmentMinPMTU(t *testing.T) {
	c := &Conn{
		config: &Config{PMTU: 100}, // 极小 PMTU
	}
	maxPayload := c.maxPayloadSizeForWrite(recordTypeHandshake)
	maxFragBody := maxPayload - dtlcpHeaderLen
	if maxFragBody <= 0 {
		t.Fatalf("PMTU=100 时 maxFragBody 应为正: maxPayload=%d, maxFragBody=%d", maxPayload, maxFragBody)
	}
}

// =============================================================================
// 分片重组迭代测试 — 验证 readHandshake 迭代循环
// =============================================================================

// TestReadHandshakeFragmentIterationReassembly 验证迭代循环在正常多分片场景下正确重组消息。
//
// 使用 mockPacketConn 注入三个分片组成的 typeFinished 消息，
// 验证 readHandshake 通过迭代（而非递归）正确重组并返回完整消息。
func TestReadHandshakeFragmentIterationReassembly(t *testing.T) {
	mockA, mockB := newMockPacketConn()
	defer mockA.Close()
	defer mockB.Close()

	clientCfg := &Config{}
	cli := Client(mockA, mockB.LocalAddr(), clientCfg)
	cli.vers = VersionTLCP
	cli.haveVers = true
	cli.replayWindow = newReplayWindow(defaultReplayWindowSize)

	// 构造 typeFinished 消息体（finishedMsg.unmarshal 始终返回 true）
	msgType := byte(typeFinished)
	bodyLen := 500
	body := make([]byte, bodyLen)
	for i := range body {
		body[i] = byte(i % 256)
	}

	// 分为 3 片: 0-200, 200-200, 400-100
	splitPoints := []struct{ off, length int }{
		{0, 200},
		{200, 200},
		{400, 100},
	}

	for i, sp := range splitPoints {
		fragBody := body[sp.off : sp.off+sp.length]
		fragLen := len(fragBody)

		// 构造 DTLCP 握手头 (12B)
		var hdr [dtlcpHeaderLen]byte
		hdr[0] = msgType
		hdr[1] = byte(bodyLen >> 16)
		hdr[2] = byte(bodyLen >> 8)
		hdr[3] = byte(bodyLen)
		// msgSeq=0，未显式设置即为 0
		hdr[6] = byte(sp.off >> 16)
		hdr[7] = byte(sp.off >> 8)
		hdr[8] = byte(sp.off)
		hdr[9] = byte(fragLen >> 16)
		hdr[10] = byte(fragLen >> 8)
		hdr[11] = byte(fragLen)

		// 构造 DTLCP 记录 (13B 头 + 12B 握手头 + 分片数据)
		payloadLen := dtlcpHeaderLen + fragLen
		record := make([]byte, recordHeaderLen+payloadLen)
		record[0] = byte(recordTypeHandshake)
		record[1] = byte(VersionTLCP >> 8)
		record[2] = byte(VersionTLCP & 0xFF)
		// epoch=0，未显式设置即为 0
		// seqNum=i (6B big-endian，低位字节)
		record[10] = byte(i)
		record[11] = byte(payloadLen >> 8)
		record[12] = byte(payloadLen)
		copy(record[recordHeaderLen:], hdr[:])
		copy(record[recordHeaderLen+dtlcpHeaderLen:], fragBody)

		// 通过 mockB 注入数据报（模拟对端发送）
		if _, err := mockB.WriteTo(record, mockA.LocalAddr()); err != nil {
			t.Fatalf("WriteTo fragment %d: %v", i, err)
		}
	}

	// 调用 readHandshake 读取并重组
	msg, err := cli.readHandshake(nil)
	if err != nil {
		t.Fatalf("readHandshake: %v", err)
	}

	finished, ok := msg.(*finishedMsg)
	if !ok {
		t.Fatalf("expected *finishedMsg, got %T", msg)
	}
	if len(finished.verifyData) != bodyLen {
		t.Fatalf("verifyData length mismatch: %d != %d", len(finished.verifyData), bodyLen)
	}
	if !bytes.Equal(finished.verifyData, body) {
		t.Fatal("reassembled data does not match original")
	}
}

// TestReadHandshakeTinyFragmentAttack 验证单字节分片攻击被 maxHandshakeFragments 限制拦截。
//
// 注入 300 个单字节分片（超过 maxHandshakeFragments=256），
// 验证 readHandshake 返回 "too many fragment reads" 错误而非栈溢出。
func TestReadHandshakeTinyFragmentAttack(t *testing.T) {
	mockA, mockB := newMockPacketConn()
	defer mockA.Close()
	defer mockB.Close()

	clientCfg := &Config{}
	cli := Client(mockA, mockB.LocalAddr(), clientCfg)
	cli.vers = VersionTLCP
	cli.haveVers = true
	cli.replayWindow = newReplayWindow(defaultReplayWindowSize)

	bodyLen := 300 // 需要 > maxHandshakeFragments(256) 次迭代
	msgType := byte(typeCertificate)

	// 注入 300 个单字节分片
	for i := 0; i < bodyLen; i++ {
		fragBody := []byte{byte(i % 256)}

		var hdr [dtlcpHeaderLen]byte
		hdr[0] = msgType
		hdr[1] = byte(bodyLen >> 16)
		hdr[2] = byte(bodyLen >> 8)
		hdr[3] = byte(bodyLen)
		hdr[6] = byte(i >> 16)
		hdr[7] = byte(i >> 8)
		hdr[8] = byte(i)
		hdr[9] = 0
		hdr[10] = 0
		hdr[11] = 1 // fragLen=1

		payloadLen := dtlcpHeaderLen + 1
		record := make([]byte, recordHeaderLen+payloadLen)
		record[0] = byte(recordTypeHandshake)
		record[1] = byte(VersionTLCP >> 8)
		record[2] = byte(VersionTLCP & 0xFF)
		record[10] = byte(i)
		record[11] = byte(payloadLen >> 8)
		record[12] = byte(payloadLen)
		copy(record[recordHeaderLen:], hdr[:])
		copy(record[recordHeaderLen+dtlcpHeaderLen:], fragBody)

		if _, err := mockB.WriteTo(record, mockA.LocalAddr()); err != nil {
			t.Fatalf("WriteTo fragment %d: %v", i, err)
		}
	}

	// 调用 readHandshake——应在第 257 次迭代时报错
	msg, err := cli.readHandshake(nil)
	if err == nil {
		t.Fatal("expected error for too many fragments, got nil")
	}
	if msg != nil {
		t.Errorf("expected nil message on error, got %T", msg)
	}
	if !strings.Contains(err.Error(), "too many fragment reads") {
		t.Errorf("expected 'too many fragment reads' in error, got: %v", err)
	}
	t.Logf("单字节分片攻击被正确拦截: %v (注入 %d 分片)", err, bodyLen)
}
