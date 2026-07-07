// Copyright (c) 2025 gotlcp contributors
// gotlcp is licensed under Mulan PSL v2.

package dtlcp

import (
	"bytes"
	"testing"
)

// =============================================================================
// DTLCP 握手消息头测试
// =============================================================================

// TestHandshakeHeaderRoundtrip 测试 DTLCP 12 字节握手消息头的 marshal/unmarshal。
func TestHandshakeHeaderRoundtrip(t *testing.T) {
	msgType := uint8(typeClientHello)
	body := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	msgSeq := uint16(42)
	fragOff := uint24(0)
	fragLen := uint24(5)

	data, err := dtlcpMarshalHeader(msgType, body, msgSeq, fragOff, fragLen)
	if err != nil {
		t.Fatalf("dtlcpMarshalHeader 失败: %v", err)
	}

	if len(data) != dtlcpHeaderLen+5 {
		t.Fatalf("期望长度 %d，实际 %d", dtlcpHeaderLen+5, len(data))
	}

	parsedType, parsedLen, parsedSeq, parsedOff, parsedLenFrag, parsedBody, ok := dtlcpUnmarshalHeader(data)
	if !ok {
		t.Fatal("dtlcpUnmarshalHeader 失败")
	}

	if parsedType != msgType {
		t.Fatalf("消息类型不匹配：期望 %d，实际 %d", msgType, parsedType)
	}
	if parsedSeq != msgSeq {
		t.Fatalf("消息序列号不匹配：期望 %d，实际 %d", msgSeq, parsedSeq)
	}
	if parsedOff != fragOff {
		t.Fatalf("分片偏移不匹配：期望 %d，实际 %d", fragOff, parsedOff)
	}
	if parsedLenFrag != fragLen {
		t.Fatalf("分片长度不匹配：期望 %d，实际 %d", fragLen, parsedLenFrag)
	}
	if parsedLen != 5 {
		t.Fatalf("消息体长度不匹配：期望 5，实际 %d", parsedLen)
	}
	if !bytes.Equal(parsedBody, body) {
		t.Fatal("消息体不匹配")
	}
}

// TestHandshakeHeaderMsgSeqAndFrag 测试 DTLCP 握手消息头的消息序列号和分片字段。
func TestHandshakeHeaderMsgSeqAndFrag(t *testing.T) {
	body := []byte{0x01, 0x02, 0x03, 0x04, 0x05}

	// 测试非分片消息（fragOff=0, fragLen=len(body)）
	data, err := dtlcpMarshalHeader(typeServerKeyExchange, body, uint16(7), uint24(0), uint24(5))
	if err != nil {
		t.Fatalf("dtlcpMarshalHeader 失败: %v", err)
	}

	msgType, bodyLen, seq, off, fragLen, parsedBody, ok := dtlcpUnmarshalHeader(data)
	if !ok {
		t.Fatal("dtlcpUnmarshalHeader 失败")
	}
	if msgType != typeServerKeyExchange {
		t.Fatalf("消息类型应为 %d", typeServerKeyExchange)
	}
	if bodyLen != 5 {
		t.Fatalf("消息体长度应为 5，实际 %d", bodyLen)
	}
	if seq != 7 {
		t.Fatalf("序列号应为 7，实际 %d", seq)
	}
	if off != 0 {
		t.Fatalf("分片偏移应为 0，实际 %d", off)
	}
	if fragLen != 5 {
		t.Fatalf("分片长度应为 5，实际 %d", fragLen)
	}
	if !bytes.Equal(parsedBody, body) {
		t.Fatal("消息体数据不匹配")
	}
}

// TestHandshakeHeaderInvalidData 测试非法头部数据。
func TestHandshakeHeaderInvalidData(t *testing.T) {
	// 数据太短
	_, _, _, _, _, _, ok := dtlcpUnmarshalHeader([]byte{0x01, 0x02})
	if ok {
		t.Fatal("过短数据应解析失败")
	}

	// 空的
	_, _, _, _, _, _, ok = dtlcpUnmarshalHeader(nil)
	if ok {
		t.Fatal("空数据应解析失败")
	}
}

// =============================================================================
// clientHelloMsg 测试（DTLCP 特有：cookie 字段）
// =============================================================================

// TestClientHelloMarshalDTLCP 测试包含 cookie 的 ClientHello marshal/unmarshal。
func TestClientHelloMarshalDTLCP(t *testing.T) {
	hello := &clientHelloMsg{
		vers:               VersionTLCP,
		random:             mockFF32,
		compressionMethods: []uint8{compressionNone},
		cipherSuites:       []uint16{ECC_SM4_GCM_SM3},
		serverName:         "example.com",
		cookie:             []byte{0xAA, 0xBB, 0xCC},
	}

	data, err := hello.marshal()
	if err != nil {
		t.Fatalf("marshal 失败: %v", err)
	}

	hello2 := new(clientHelloMsg)
	if !hello2.unmarshal(data) {
		t.Fatal("unmarshal 失败")
	}

	if !bytes.Equal(hello2.cookie, hello.cookie) {
		t.Fatalf("cookie 不匹配: 期望 %x，实际 %x", hello.cookie, hello2.cookie)
	}
	if hello2.serverName != hello.serverName {
		t.Fatalf("serverName 不匹配: 期望 %q，实际 %q", hello.serverName, hello2.serverName)
	}
	if len(hello2.cipherSuites) != 1 || hello2.cipherSuites[0] != ECC_SM4_GCM_SM3 {
		t.Fatal("cipherSuites 不匹配")
	}
}

// TestClientHelloMarshalEmptyCookie 测试 cookie 为空时的 ClientHello marshal/unmarshal。
func TestClientHelloMarshalEmptyCookie(t *testing.T) {
	hello := &clientHelloMsg{
		vers:               VersionTLCP,
		random:             mockFF32,
		compressionMethods: []uint8{compressionNone},
		cipherSuites:       []uint16{ECC_SM4_GCM_SM3},
		cookie:             []byte{},
	}

	data, err := hello.marshal()
	if err != nil {
		t.Fatalf("marshal 失败: %v", err)
	}

	hello2 := new(clientHelloMsg)
	if !hello2.unmarshal(data) {
		t.Fatal("unmarshal 失败")
	}

	if len(hello2.cookie) != 0 {
		t.Fatalf("空 cookie 不匹配: %x", hello2.cookie)
	}
}

// TestClientHelloMarshalSupportedCurves 测试带支持的椭圆曲线扩展的 ClientHello。
func TestClientHelloMarshalSupportedCurves(t *testing.T) {
	hello := &clientHelloMsg{
		vers:               VersionTLCP,
		random:             mockFF32,
		compressionMethods: []uint8{compressionNone},
		cipherSuites:       []uint16{ECC_SM4_GCM_SM3},
		supportedCurves:    []CurveID{CurveSM2},
		cookie:             []byte{0x01},
	}

	data, err := hello.marshal()
	if err != nil {
		t.Fatalf("marshal 失败: %v", err)
	}

	hello2 := new(clientHelloMsg)
	if !hello2.unmarshal(data) {
		t.Fatal("unmarshal 失败")
	}

	if len(hello2.supportedCurves) != 1 || hello2.supportedCurves[0] != CurveSM2 {
		t.Fatal("supportedCurves 不匹配")
	}
	if !bytes.Equal(hello2.cookie, hello.cookie) {
		t.Fatal("cookie 不匹配")
	}
}

// TestClientHelloMarshalSignatureAlgorithms 测试带签名算法扩展的 ClientHello。
func TestClientHelloMarshalSignatureAlgorithms(t *testing.T) {
	hello := &clientHelloMsg{
		vers:                         VersionTLCP,
		random:                       mockFF32,
		compressionMethods:           []uint8{compressionNone},
		cipherSuites:                 []uint16{ECC_SM4_GCM_SM3},
		supportedSignatureAlgorithms: []SignatureScheme{SM2WithSM3},
		cookie:                       []byte{0xDE, 0xAD},
	}

	data, err := hello.marshal()
	if err != nil {
		t.Fatalf("marshal 失败: %v", err)
	}

	hello2 := new(clientHelloMsg)
	if !hello2.unmarshal(data) {
		t.Fatal("unmarshal 失败")
	}

	if len(hello2.supportedSignatureAlgorithms) != 1 || hello2.supportedSignatureAlgorithms[0] != SM2WithSM3 {
		t.Fatal("supportedSignatureAlgorithms 不匹配")
	}
}

// TestClientHelloMarshalALPN 测试带 ALPN 扩展的 ClientHello。
func TestClientHelloMarshalALPN(t *testing.T) {
	hello := &clientHelloMsg{
		vers:               VersionTLCP,
		random:             mockFF32,
		compressionMethods: []uint8{compressionNone},
		cipherSuites:       []uint16{ECC_SM4_CBC_SM3},
		alpnProtocols:      []string{"h2", "http/1.1"},
		cookie:             []byte{0x01, 0x02},
	}

	data, err := hello.marshal()
	if err != nil {
		t.Fatalf("marshal 失败: %v", err)
	}

	hello2 := new(clientHelloMsg)
	if !hello2.unmarshal(data) {
		t.Fatal("unmarshal 失败")
	}

	if len(hello2.alpnProtocols) != 2 {
		t.Fatalf("ALPN 协议数量不匹配: 期望 2，实际 %d", len(hello2.alpnProtocols))
	}
	if hello2.alpnProtocols[0] != "h2" || hello2.alpnProtocols[1] != "http/1.1" {
		t.Fatal("ALPN 协议值不匹配")
	}
}

// =============================================================================
// helloVerifyRequestMsg 测试
// =============================================================================

// TestHelloVerifyRequestMarshal 测试 HelloVerifyRequest 消息 marshal/unmarshal。
func TestHelloVerifyRequestMarshal(t *testing.T) {
	hvr := &helloVerifyRequestMsg{
		serverVersion: VersionTLCP,
		cookie:        []byte{0x11, 0x22, 0x33, 0x44, 0x55},
	}
	hvr.setMessageSeq(uint16(0))

	data, err := hvr.marshal()
	if err != nil {
		t.Fatalf("marshal 失败: %v", err)
	}

	hvr2 := new(helloVerifyRequestMsg)
	if !hvr2.unmarshal(data) {
		t.Fatal("unmarshal 失败")
	}

	if hvr2.serverVersion != VersionTLCP {
		t.Fatalf("serverVersion 不匹配: 期望 0x%04x，实际 0x%04x", VersionTLCP, hvr2.serverVersion)
	}
	if !bytes.Equal(hvr2.cookie, hvr.cookie) {
		t.Fatalf("cookie 不匹配: 期望 %x，实际 %x", hvr.cookie, hvr2.cookie)
	}
}

// TestHelloVerifyRequestMarshalEmptyCookie 测试空 cookie 的 HelloVerifyRequest。
func TestHelloVerifyRequestMarshalEmptyCookie(t *testing.T) {
	hvr := &helloVerifyRequestMsg{
		serverVersion: VersionTLCP,
		cookie:        []byte{},
	}
	hvr.setMessageSeq(uint16(0))

	data, err := hvr.marshal()
	if err != nil {
		t.Fatalf("marshal 失败: %v", err)
	}

	hvr2 := new(helloVerifyRequestMsg)
	if !hvr2.unmarshal(data) {
		t.Fatal("unmarshal 失败")
	}

	if len(hvr2.cookie) != 0 {
		t.Fatalf("cookie 应为空，实际长度 %d", len(hvr2.cookie))
	}
}

// TestHelloVerifyRequestMsgSequence 测试 HelloVerifyRequest 消息序列号。
func TestHelloVerifyRequestMsgSequence(t *testing.T) {
	hvr := &helloVerifyRequestMsg{
		serverVersion: VersionTLCP,
		cookie:        []byte{0xAA},
	}
	hvr.setMessageSeq(uint16(5))

	if hvr.getMessageSeq() != 5 {
		t.Fatalf("messageSeq 应为 5，实际 %d", hvr.getMessageSeq())
	}

	data, err := hvr.marshal()
	if err != nil {
		t.Fatalf("marshal 失败: %v", err)
	}

	hvr2 := new(helloVerifyRequestMsg)
	if !hvr2.unmarshal(data) {
		t.Fatal("unmarshal 失败")
	}
	if hvr2.getMessageSeq() != 5 {
		t.Fatalf("unmarshal 后 messageSeq 应为 5，实际 %d", hvr2.getMessageSeq())
	}
}

// =============================================================================
// serverHelloMsg 测试
// =============================================================================

// TestServerHelloMarshalDTLCP 测试 ServerHello marshal/unmarshal。
func TestServerHelloMarshalDTLCP(t *testing.T) {
	hello := &serverHelloMsg{
		vers:              VersionTLCP,
		random:            mockFF32,
		sessionId:         []byte{0x01, 0x02, 0x03},
		cipherSuite:       ECC_SM4_GCM_SM3,
		compressionMethod: compressionNone,
	}

	data, err := hello.marshal()
	if err != nil {
		t.Fatalf("marshal 失败: %v", err)
	}

	hello2 := new(serverHelloMsg)
	if !hello2.unmarshal(data) {
		t.Fatal("unmarshal 失败")
	}

	if hello2.vers != VersionTLCP {
		t.Fatal("vers 不匹配")
	}
	if hello2.cipherSuite != ECC_SM4_GCM_SM3 {
		t.Fatal("cipherSuite 不匹配")
	}
}

// TestServerHelloMarshalOCSP 测试带 OCSP 响应的 ServerHello。
func TestServerHelloMarshalOCSP(t *testing.T) {
	hello := &serverHelloMsg{
		vers:              VersionTLCP,
		random:            mockFF32,
		sessionId:         []byte{},
		cipherSuite:       ECC_SM4_CBC_SM3,
		compressionMethod: compressionNone,
		ocspStapling:      true,
		ocspResponse:      []byte{0x01, 0x02, 0x03, 0x04},
	}

	data, err := hello.marshal()
	if err != nil {
		t.Fatalf("marshal 失败: %v", err)
	}

	hello2 := new(serverHelloMsg)
	if !hello2.unmarshal(data) {
		t.Fatal("unmarshal 失败")
	}

	if !hello2.ocspStapling {
		t.Fatal("ocspStapling 应为 true")
	}
	if !bytes.Equal(hello2.ocspResponse, hello.ocspResponse) {
		t.Fatal("ocspResponse 不匹配")
	}
}

// TestServerHelloUnmarshal 测试从 marshal 后的数据正确解组 ServerHello。
func TestServerHelloUnmarshal(t *testing.T) {
	hello := &serverHelloMsg{
		vers:              VersionTLCP,
		random:            mockFF32,
		sessionId:         []byte{},
		cipherSuite:       ECC_SM4_GCM_SM3,
		compressionMethod: compressionNone,
	}

	data, err := hello.marshal()
	if err != nil {
		t.Fatalf("marshal 失败: %v", err)
	}

	hello2 := new(serverHelloMsg)
	if ok := hello2.unmarshal(data); !ok {
		t.Fatalf("unmarshal 失败")
	}
	if hello2.vers != VersionTLCP {
		t.Fatal("vers 不匹配")
	}
	if hello2.cipherSuite != ECC_SM4_GCM_SM3 {
		t.Fatal("cipherSuite 不匹配")
	}
	if !bytes.Equal(hello2.random, mockFF32) {
		t.Fatal("random 不匹配")
	}
}

// =============================================================================
// 消息序列号测试
// =============================================================================

// TestMessageSeqAssignment 测试 setMessageSeq 和 getMessageSeq 方法。
func TestMessageSeqAssignment(t *testing.T) {
	tests := []struct {
		name string
		msg  handshakeMessage
		seq  uint16
	}{
		{
			"ClientHello",
			&clientHelloMsg{
				random:             mockFF32,
				compressionMethods: []uint8{compressionNone},
				cipherSuites:       []uint16{ECC_SM4_GCM_SM3},
			},
			0,
		},
		{
			"HelloVerifyRequest",
			&helloVerifyRequestMsg{
				serverVersion: VersionTLCP,
				cookie:        []byte{0xAA},
			},
			1,
		},
		{
			"ServerHello",
			&serverHelloMsg{
				random:            mockFF32,
				compressionMethod: compressionNone,
				sessionId:         []byte{},
				cipherSuite:       ECC_SM4_GCM_SM3,
			},
			2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.msg.setMessageSeq(tt.seq)
			if got := tt.msg.getMessageSeq(); got != tt.seq {
				t.Fatalf("messageSeq: 期望 %d，实际 %d", tt.seq, got)
			}

			// marshal 后 unmarshal，验证序列号保留
			data, err := tt.msg.marshal()
			if err != nil {
				t.Fatalf("marshal 失败: %v", err)
			}

			var parsed handshakeMessage
			switch tt.msg.(type) {
			case *clientHelloMsg:
				parsed = new(clientHelloMsg)
			case *helloVerifyRequestMsg:
				parsed = new(helloVerifyRequestMsg)
			case *serverHelloMsg:
				parsed = new(serverHelloMsg)
			}

			if !parsed.unmarshal(data) {
				t.Fatal("unmarshal 失败")
			}
			if parsed.getMessageSeq() != tt.seq {
				t.Fatalf("unmarshal 后 messageSeq: 期望 %d，实际 %d", tt.seq, parsed.getMessageSeq())
			}
		})
	}
}

// TestMessageTypeValues 测试消息类型常量。
func TestMessageTypeValues(t *testing.T) {
	hello := &clientHelloMsg{}
	if hello.messageType() != typeClientHello {
		t.Fatalf("ClientHello 消息类型应为 %d", typeClientHello)
	}
	hvr := &helloVerifyRequestMsg{}
	if hvr.messageType() != typeHelloVerifyRequest {
		t.Fatalf("HelloVerifyRequest 消息类型应为 %d", typeHelloVerifyRequest)
	}
	serverHello := &serverHelloMsg{}
	if serverHello.messageType() != typeServerHello {
		t.Fatalf("ServerHello 消息类型应为 %d", typeServerHello)
	}
}
