package dtlcp

import (
	"testing"
)

// TestMarshalFragmentLength 验证 marshal 后的 DTLCP 头部中 fragment_length 不为 0。
// DTLCP 协议规定非分片消息的 fragment_length 应等于 body 长度。
func TestMarshalFragmentLength(t *testing.T) {
	tests := []struct {
		name string
		msg  handshakeMessage
	}{
		{
			"ClientHello",
			&clientHelloMsg{
				vers:               VersionTLCP,
				random:             mockFF32,
				compressionMethods: []uint8{compressionNone},
				cipherSuites:       []uint16{ECC_SM4_GCM_SM3},
			},
		},
		{
			"HelloVerifyRequest",
			&helloVerifyRequestMsg{
				serverVersion: VersionTLCP,
				cookie:        []byte{0x01, 0x02, 0x03},
			},
		},
		{
			"ServerHello",
			&serverHelloMsg{
				vers:              VersionTLCP,
				random:            mockFF32,
				sessionId:         []byte{},
				cipherSuite:       ECC_SM4_GCM_SM3,
				compressionMethod: compressionNone,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.msg.marshal()
			if err != nil {
				t.Fatalf("marshal 失败: %v", err)
			}

			if len(data) < dtlcpHeaderLen {
				t.Fatalf("数据太短: %d", len(data))
			}

			// DTLCP 头部格式:
			// [0]: msgType (1)
			// [1-3]: bodyLen (3)
			// [4-5]: messageSeq (2)
			// [6-8]: fragmentOffset (3)
			// [9-11]: fragmentLength (3)
			bodyLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
			msgSeq := uint16(data[4])<<8 | uint16(data[5])
			fragOff := uint24(data[6])<<16 | uint24(data[7])<<8 | uint24(data[8])
			fragLen := uint24(data[9])<<16 | uint24(data[10])<<8 | uint24(data[11])

			if fragLen == 0 {
				t.Errorf("fragmentLength = 0，应为 %d (bodyLen)", bodyLen)
			}
			if fragLen != uint24(bodyLen) {
				t.Errorf("fragmentLength = %d，应等于 bodyLen = %d", fragLen, bodyLen)
			}
			if fragOff != 0 {
				t.Errorf("fragmentOffset = %d，应等于 0", fragOff)
			}
			_ = msgSeq
		})
	}
}
