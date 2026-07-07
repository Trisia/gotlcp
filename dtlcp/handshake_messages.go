// Copyright (c) 2025 gotlcp contributors
// gotlcp is licensed under Mulan PSL v2.

// DTLCP 握手消息实现
//
// 基于 tlcp 握手消息，适配 DTLCP 12 字节消息头：
//
//	[Type:1][Length:3][MsgSeq:2][FragOff:3][FragLen:3][body]
//
// 新增 clientHelloMsg.cookie 字段和 helloVerifyRequestMsg 类型。

package dtlcp

import (
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"

	x509 "github.com/emmansun/gmsm/smx509"
	"golang.org/x/crypto/cryptobyte"
)

// =============================================================================
// cryptobyte 辅助函数
// =============================================================================

// marshalingFunction 是用于将普通函数作为 cryptobyte.MarshalingValue 使用的适配器。
type marshalingFunction func(b *cryptobyte.Builder) error

func (f marshalingFunction) Marshal(b *cryptobyte.Builder) error {
	return f(b)
}

// addBytesWithLength 向 cryptobyte.Builder 中追加指定长度的字节序列。
// 如果字节序列长度与指定值不匹配，则返回错误。
func addBytesWithLength(b *cryptobyte.Builder, v []byte, n int) {
	b.AddValue(marshalingFunction(func(b *cryptobyte.Builder) error {
		if len(v) != n {
			return fmt.Errorf("invalid value length: expected %d, got %d", n, len(v))
		}
		b.AddBytes(v)
		return nil
	}))
}

// addUint64 向 cryptobyte.Builder 中追加大端序 64 位值。
func addUint64(b *cryptobyte.Builder, v uint64) {
	b.AddUint32(uint32(v >> 32))
	b.AddUint32(uint32(v))
}

// readUint64 从 cryptobyte.String 中解码大端序 64 位值。
func readUint64(s *cryptobyte.String, out *uint64) bool {
	var hi, lo uint32
	if !s.ReadUint32(&hi) || !s.ReadUint32(&lo) {
		return false
	}
	*out = uint64(hi)<<32 | uint64(lo)
	return true
}

// readUint8LengthPrefixed 读取单字节长度前缀的字节序列到 []byte。
func readUint8LengthPrefixed(s *cryptobyte.String, out *[]byte) bool {
	return s.ReadUint8LengthPrefixed((*cryptobyte.String)(out))
}

// readUint16LengthPrefixed 读取双字节长度前缀的字节序列到 []byte。
func readUint16LengthPrefixed(s *cryptobyte.String, out *[]byte) bool {
	return s.ReadUint16LengthPrefixed((*cryptobyte.String)(out))
}

// readUint24LengthPrefixed 读取三字节长度前缀的字节序列到 []byte。
func readUint24LengthPrefixed(s *cryptobyte.String, out *[]byte) bool {
	return s.ReadUint24LengthPrefixed((*cryptobyte.String)(out))
}

// =============================================================================
// transcriptHash — 握手消息哈希接口
// =============================================================================

// transcriptHash 用于在握手过程中累积消息哈希。
type transcriptHash interface {
	Write([]byte) (int, error)
	Sum() []byte
}

// =============================================================================
// transcriptMsg — 辅助函数
// =============================================================================

// transcriptMsg 用于对通常不在线路上写入的消息进行序列化和哈希。
func transcriptMsg(msg handshakeMessage, h transcriptHash) error {
	data, err := msg.marshal()
	if err != nil {
		return err
	}
	h.Write(data)
	return nil
}

// =============================================================================
// dtlcpMarshalHeader / dtlcpUnmarshalHeader — DTLCP 12 字节头辅助
// =============================================================================

// dtlcpHeaderLen DTLCP 握手消息头长度
const dtlcpHeaderLen = 12

// dtlcpMarshalHeader 构造 DTLCP 12 字节握手消息头。
// 返回追加了 body 后的完整字节序列。
func dtlcpMarshalHeader(msgType uint8, body []byte, msgSeq uint16, fragOff, fragLen uint24) ([]byte, error) {
	if fragLen == 0 {
		fragLen = uint24(len(body))
	}
	var b cryptobyte.Builder
	b.AddUint8(msgType)
	b.AddUint24(uint32(len(body)))
	b.AddUint16(msgSeq)
	b.AddUint24(uint32(fragOff))
	b.AddUint24(uint32(fragLen))
	b.AddBytes(body)
	return b.Bytes()
}

// dtlcpUnmarshalHeader 解析 DTLCP 12 字节握手消息头。
// 返回 msgType、bodyLen、messageSeq、fragmentOffset、fragmentLength 和 body 数据。
func dtlcpUnmarshalHeader(data []byte) (msgType uint8, bodyLen uint32, messageSeq uint16, fragmentOffset, fragmentLength uint24, body []byte, ok bool) {
	s := cryptobyte.String(data)
	if !s.ReadUint8(&msgType) ||
		!s.ReadUint24((*uint32)(&bodyLen)) ||
		!s.ReadUint16(&messageSeq) ||
		!s.ReadUint24((*uint32)(&fragmentOffset)) ||
		!s.ReadUint24((*uint32)(&fragmentLength)) {
		return 0, 0, 0, 0, 0, nil, false
	}
	if fragmentLength > 0 {
			if int(fragmentLength) > len(s) {
				return 0, 0, 0, 0, 0, nil, false
			}
			body = []byte(s[:fragmentLength])
		} else {
			body = []byte(s)
		}
	return msgType, bodyLen, messageSeq, fragmentOffset, fragmentLength, body, true
}

// =============================================================================
// clientHelloMsg
// =============================================================================

type clientHelloMsg struct {
	raw                []byte
	vers               uint16
	random             []byte          // 32 字节
	sessionId          []byte          // 会话标识
	cookie             []byte          // DTLCP 新增：cookie<0..2^8-1>
	cipherSuites       []uint16        // 密码套件列表
	compressionMethods []uint8         // 压缩方法

	// GM/T 0024-2023 6.4.5.2.3 Hello消息扩展字段
	serverName                   string             // 服务器名称
	trustedAuthorities           []TrustedAuthority  // 信任的CA证书信息
	ocspStapling                 bool                // 证书状态请求
	supportedCurves              []CurveID           // 支持的椭圆曲线
	supportedSignatureAlgorithms []SignatureScheme   // 支持的签名算法
	alpnProtocols                []string            // 支持的应用层协议
	ibsdhClientID                []byte              // IBSDH密钥交换 客户端标识

	// DTLCP 分片字段
	messageSeq     uint16
	fragmentOffset uint24
	fragmentLength uint24
}

func (m *clientHelloMsg) marshal() ([]byte, error) {
	if m.raw != nil {
		return m.raw, nil
	}

	// 构建扩展字段
	var exts cryptobyte.Builder
	if len(m.serverName) > 0 {
		exts.AddUint16(extensionServerName)
		exts.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint8(0) // host_name
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddBytes([]byte(m.serverName))
				})
			})
		})
	}
	if len(m.trustedAuthorities) > 0 {
		exts.AddUint16(extensionTrustedCAKeys)
		exts.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				for _, ta := range m.trustedAuthorities {
					b.AddUint8(ta.IdentifierType)
					switch ta.IdentifierType {
					case IdentifierTypePreAgreed:
					case IdentifierTypeKeySM3Hash, IdentifierTypeCertSM3Hash:
						b.AddBytes(ta.Identifier)
					case IdentifierTypeX509Name:
						b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
							b.AddBytes(ta.Identifier)
						})
					}
				}
			})
		})
	}
	if m.ocspStapling {
		exts.AddUint16(extensionStatusRequest)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint8(1)  // status_type = ocsp
			exts.AddUint16(0) // empty responder_id_list
			exts.AddUint16(0) // empty request_extensions
		})
	}
	if len(m.supportedCurves) > 0 {
		exts.AddUint16(extensionSupportedCurves)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				for _, curve := range m.supportedCurves {
					exts.AddUint16(uint16(curve))
				}
			})
		})
	}
	if len(m.supportedSignatureAlgorithms) > 0 {
		exts.AddUint16(extensionSignatureAlgorithms)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				for _, sigAlgo := range m.supportedSignatureAlgorithms {
					exts.AddUint16(uint16(sigAlgo))
				}
			})
		})
	}
	if len(m.alpnProtocols) > 0 {
		exts.AddUint16(extensionALPN)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				for _, proto := range m.alpnProtocols {
					exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
						exts.AddBytes([]byte(proto))
					})
				}
			})
		})
	}
	if len(m.ibsdhClientID) > 0 {
		exts.AddUint16(extensionClientID)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddBytes(m.ibsdhClientID)
			})
		})
	}

	extBytes, err := exts.Bytes()
	if err != nil {
		return nil, err
	}

	// 构建消息体
	var body cryptobyte.Builder
	body.AddUint16(m.vers)
	addBytesWithLength(&body, m.random, 32)
	body.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(m.sessionId)
	})
	body.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(m.cookie)
	})
	body.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, suite := range m.cipherSuites {
			b.AddUint16(suite)
		}
	})
	body.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(m.compressionMethods)
	})
	if len(extBytes) > 0 {
		body.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(extBytes)
		})
	}

	bodyBytes, err := body.Bytes()
	if err != nil {
		return nil, err
	}

	// DTLCP 12 字节头 + body
	m.raw, err = dtlcpMarshalHeader(m.messageType(), bodyBytes, m.messageSeq, m.fragmentOffset, m.fragmentLength)
	return m.raw, err
}

func (m *clientHelloMsg) unmarshal(data []byte) bool {
	*m = clientHelloMsg{raw: data}
	msgType, bodyLen, messageSeq, fragmentOffset, fragmentLength, body, ok := dtlcpUnmarshalHeader(data)
	if !ok || msgType != typeClientHello {
		return false
	}
	m.messageSeq = messageSeq
	m.fragmentOffset = fragmentOffset
	m.fragmentLength = fragmentLength

	s := cryptobyte.String(body)
	if !s.ReadUint16(&m.vers) || !s.ReadBytes(&m.random, 32) ||
		!readUint8LengthPrefixed(&s, &m.sessionId) ||
		!readUint8LengthPrefixed(&s, &m.cookie) {
		return false
	}

	var cipherSuites cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cipherSuites) {
		return false
	}
	m.cipherSuites = []uint16{}
	for !cipherSuites.Empty() {
		var suite uint16
		if !cipherSuites.ReadUint16(&suite) {
			return false
		}
		m.cipherSuites = append(m.cipherSuites, suite)
	}

	if !readUint8LengthPrefixed(&s, &m.compressionMethods) {
		return false
	}

	// 忽略长度检查：bodyLen 是消息体总长，但 s 是截取后的 body 数据
	_ = bodyLen

	if s.Empty() {
		return true
	}

	// 解析扩展字段
	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return false
	}

	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return false
		}

		switch extension {
		case extensionServerName:
			var nameList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&nameList) || nameList.Empty() {
				return false
			}
			for !nameList.Empty() {
				var nameType uint8
				var serverName cryptobyte.String
				if !nameList.ReadUint8(&nameType) ||
					!nameList.ReadUint16LengthPrefixed(&serverName) ||
					serverName.Empty() {
					return false
				}
				if nameType != 0 {
					continue
				}
				if len(m.serverName) != 0 {
					continue
				}
				m.serverName = string(serverName)
				if strings.HasSuffix(m.serverName, ".") {
					return false
				}
			}

		case extensionTrustedCAKeys:
			var taList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&taList) || taList.Empty() {
				return false
			}
			for !taList.Empty() {
				var ta TrustedAuthority
				if !taList.ReadUint8(&ta.IdentifierType) {
					return false
				}
				switch ta.IdentifierType {
				case IdentifierTypePreAgreed:
					ta.Identifier = []byte{}
				case IdentifierTypeKeySM3Hash, IdentifierTypeCertSM3Hash:
					ta.Identifier = make([]byte, 32)
					if !taList.ReadBytes(&ta.Identifier, 32) {
						return false
					}
				case IdentifierTypeX509Name:
					if !readUint16LengthPrefixed(&taList, &ta.Identifier) {
						return false
					}
				default:
					continue
				}
				m.trustedAuthorities = append(m.trustedAuthorities, ta)
			}

		case extensionStatusRequest:
			var statusType uint8
			var ignored cryptobyte.String
			if !extData.ReadUint8(&statusType) ||
				!extData.ReadUint16LengthPrefixed(&ignored) ||
				!extData.ReadUint16LengthPrefixed(&ignored) {
				return false
			}
			m.ocspStapling = statusType == 1

		case extensionSupportedGroups:
			var curves cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&curves) || curves.Empty() {
				return false
			}
			for !curves.Empty() {
				var curve uint16
				if !curves.ReadUint16(&curve) {
					return false
				}
				m.supportedCurves = append(m.supportedCurves, CurveID(curve))
			}

		case extensionSignatureAlgorithm:
			var sigAndAlgs cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&sigAndAlgs) || sigAndAlgs.Empty() {
				return false
			}
			for !sigAndAlgs.Empty() {
				var sigAndAlg uint16
				if !sigAndAlgs.ReadUint16(&sigAndAlg) {
					return false
				}
				m.supportedSignatureAlgorithms = append(
					m.supportedSignatureAlgorithms, SignatureScheme(sigAndAlg),
				)
			}

		case extensionALPN:
			var protoList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&protoList) || protoList.Empty() {
				return false
			}
			for !protoList.Empty() {
				var proto cryptobyte.String
				if !protoList.ReadUint8LengthPrefixed(&proto) || proto.Empty() {
					return false
				}
				m.alpnProtocols = append(m.alpnProtocols, string(proto))
			}

		case extensionClientID:
			if !readUint16LengthPrefixed(&extData, &m.ibsdhClientID) {
				return false
			}

		default:
			continue
		}

		if !extData.Empty() {
			return false
		}
	}

	return true
}

func (m *clientHelloMsg) messageType() uint8 {
	return typeClientHello
}

func (m *clientHelloMsg) String() string {
	s1 := fmt.Sprintf("Random: bytes=%s\nSession ID: %s\nCookie: %s\nCipher Suites: ",
		hex.EncodeToString(m.random), hex.EncodeToString(m.sessionId), hex.EncodeToString(m.cookie))
	for _, c := range m.cipherSuites {
		s1 += CipherSuiteName(c) + ", "
	}
	return fmt.Sprintf("%s\nCompression Methods: %v", s1, m.compressionMethods)
}

func (m *clientHelloMsg) debug() {
	fmt.Printf(">>> ClientHello\n")
	fmt.Printf("%v\n", m)
	fmt.Printf("<<<\n")
}

func (m *clientHelloMsg) setMessageSeq(seq uint16) {
	m.messageSeq = seq
	// raw 缓存需要清空，因为消息序号变了
	m.raw = nil
}

func (m *clientHelloMsg) getMessageSeq() uint16 {
	return m.messageSeq
}

// =============================================================================
// helloVerifyRequestMsg — DTLCP 新增消息类型
// =============================================================================

type helloVerifyRequestMsg struct {
	raw            []byte
	serverVersion  uint16   // 0x0101
	cookie         []byte   // cookie<0..255>
	messageSeq     uint16
	fragmentOffset uint24
	fragmentLength uint24
}

func (m *helloVerifyRequestMsg) marshal() ([]byte, error) {
	if m.raw != nil {
		return m.raw, nil
	}

	var body cryptobyte.Builder
	body.AddUint16(m.serverVersion)
	body.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(m.cookie)
	})

	bodyBytes, err := body.Bytes()
	if err != nil {
		return nil, err
	}

	m.raw, err = dtlcpMarshalHeader(m.messageType(), bodyBytes, m.messageSeq, m.fragmentOffset, m.fragmentLength)
	return m.raw, err
}

func (m *helloVerifyRequestMsg) unmarshal(data []byte) bool {
	*m = helloVerifyRequestMsg{raw: data}
	msgType, _, messageSeq, fragmentOffset, fragmentLength, body, ok := dtlcpUnmarshalHeader(data)
	if !ok || msgType != typeHelloVerifyRequest {
		return false
	}
	m.messageSeq = messageSeq
	m.fragmentOffset = fragmentOffset
	m.fragmentLength = fragmentLength

	s := cryptobyte.String(body)
	return s.ReadUint16(&m.serverVersion) &&
		readUint8LengthPrefixed(&s, &m.cookie) && s.Empty()
}

func (m *helloVerifyRequestMsg) messageType() uint8 {
	return typeHelloVerifyRequest
}

func (m *helloVerifyRequestMsg) debug() {
	fmt.Printf(">>> HelloVerifyRequest\n")
	fmt.Printf("ServerVersion: 0x%04X, Cookie: %s\n", m.serverVersion, hex.EncodeToString(m.cookie))
	fmt.Printf("<<<\n")
}

func (m *helloVerifyRequestMsg) setMessageSeq(seq uint16) {
	m.messageSeq = seq
	m.raw = nil
}

func (m *helloVerifyRequestMsg) getMessageSeq() uint16 {
	return m.messageSeq
}

// =============================================================================
// serverHelloMsg
// =============================================================================

type serverHelloMsg struct {
	raw    []byte
	vers   uint16
	random []byte
	// sessionId 服务端使用的会话标识
	sessionId         []byte
	cipherSuite       uint16
	compressionMethod uint8

	// GM/T 0024-2023 扩展字段
	ocspStapling  bool    // 证书状态请求
	ocspResponse  []byte  // OCSP应答内容DER
	alpnProtocol  string  // 应用层协议
	serverNameAck bool    // 服务器名称确认

	// DTLCP 分片字段
	messageSeq     uint16
	fragmentOffset uint24
	fragmentLength uint24
}

func (m *serverHelloMsg) marshal() ([]byte, error) {
	if m.raw != nil {
		return m.raw, nil
	}

	var exts cryptobyte.Builder
	if m.ocspStapling && len(m.ocspResponse) > 0 {
		exts.AddUint16(extensionStatusRequest)
		exts.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint8(1) // status_type = ocsp
			b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(m.ocspResponse)
			})
		})
	}
	if m.alpnProtocol != "" {
		exts.AddUint16(extensionALPN)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddBytes([]byte(m.alpnProtocol))
				})
			})
		})
	}
	if m.serverNameAck {
		exts.AddUint16(extensionServerName)
		exts.AddUint16(0)
	}

	extBytes, err := exts.Bytes()
	if err != nil {
		return nil, err
	}

	var body cryptobyte.Builder
	body.AddUint16(m.vers)
	addBytesWithLength(&body, m.random, 32)
	body.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(m.sessionId)
	})
	body.AddUint16(m.cipherSuite)
	body.AddUint8(m.compressionMethod)
	if len(extBytes) > 0 {
		body.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(extBytes)
		})
	}

	bodyBytes, err := body.Bytes()
	if err != nil {
		return nil, err
	}

	m.raw, err = dtlcpMarshalHeader(m.messageType(), bodyBytes, m.messageSeq, m.fragmentOffset, m.fragmentLength)
	return m.raw, err
}

func (m *serverHelloMsg) unmarshal(data []byte) bool {
	*m = serverHelloMsg{raw: data}
	msgType, _, messageSeq, fragmentOffset, fragmentLength, body, ok := dtlcpUnmarshalHeader(data)
	if !ok || msgType != typeServerHello {
		return false
	}
	m.messageSeq = messageSeq
	m.fragmentOffset = fragmentOffset
	m.fragmentLength = fragmentLength

	s := cryptobyte.String(body)
	if !s.ReadUint16(&m.vers) || !s.ReadBytes(&m.random, 32) ||
		!readUint8LengthPrefixed(&s, &m.sessionId) ||
		!s.ReadUint16(&m.cipherSuite) ||
		!s.ReadUint8(&m.compressionMethod) {
		return false
	}

	if s.Empty() {
		return true
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return false
	}

	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return false
		}

		switch extension {
		case extensionStatusRequest:
			var statusType uint8
			if !extData.ReadUint8(&statusType) {
				return false
			}
			if statusType != 1 {
				return false
			}
			m.ocspStapling = true
			if !readUint24LengthPrefixed(&extData, &m.ocspResponse) {
				return false
			}
		case extensionALPN:
			var protoList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&protoList) || protoList.Empty() {
				return false
			}
			var proto cryptobyte.String
			if !protoList.ReadUint8LengthPrefixed(&proto) ||
				proto.Empty() || !protoList.Empty() {
				return false
			}
			m.alpnProtocol = string(proto)
		case extensionServerName:
			if len(extData) != 0 {
				return false
			}
			m.serverNameAck = true
		default:
			continue
		}

		if !extData.Empty() {
			return false
		}
	}
	return true
}

func (m *serverHelloMsg) messageType() uint8 {
	return typeServerHello
}

func (m *serverHelloMsg) String() string {
	return fmt.Sprintf("Random: bytes=%s\nSession ID: %s\nCipher Suite: %v\nCompression Method: %v",
		hex.EncodeToString(m.random), hex.EncodeToString(m.sessionId),
		CipherSuiteName(m.cipherSuite), m.compressionMethod)
}

func (m *serverHelloMsg) debug() {
	fmt.Printf(">>> ServerHello\n")
	fmt.Printf("%v\n", m)
	fmt.Printf("<<<\n")
}

func (m *serverHelloMsg) setMessageSeq(seq uint16) {
	m.messageSeq = seq
	m.raw = nil
}

func (m *serverHelloMsg) getMessageSeq() uint16 {
	return m.messageSeq
}

// =============================================================================
// certificateMsg
// =============================================================================

type certificateMsg struct {
	raw          []byte
	certificates [][]byte

	// DTLCP 分片字段
	messageSeq     uint16
	fragmentOffset uint24
	fragmentLength uint24
}

func (m *certificateMsg) marshal() ([]byte, error) {
	if m.raw != nil {
		return m.raw, nil
	}

	var i int
	for _, slice := range m.certificates {
		i += len(slice)
	}

	bodyLength := 3 + 3*len(m.certificates) + i
	fragLen := m.fragmentLength
	if fragLen == 0 {
		fragLen = uint24(bodyLength)
	}
	x := make([]byte, dtlcpHeaderLen+bodyLength)
	x[0] = typeCertificate
	x[1] = uint8(bodyLength >> 16)
	x[2] = uint8(bodyLength >> 8)
	x[3] = uint8(bodyLength)
	x[4] = uint8(m.messageSeq >> 8)
	x[5] = uint8(m.messageSeq)
	x[6] = uint8(m.fragmentOffset >> 16)
	x[7] = uint8(m.fragmentOffset >> 8)
	x[8] = uint8(m.fragmentOffset)
	x[9] = uint8(fragLen >> 16)
	x[10] = uint8(fragLen >> 8)
	x[11] = uint8(fragLen)

	certificateOctets := bodyLength - 3
	x[12] = uint8(certificateOctets >> 16)
	x[13] = uint8(certificateOctets >> 8)
	x[14] = uint8(certificateOctets)

	y := x[15:]
	for _, slice := range m.certificates {
		y[0] = uint8(len(slice) >> 16)
		y[1] = uint8(len(slice) >> 8)
		y[2] = uint8(len(slice))
		copy(y[3:], slice)
		y = y[3+len(slice):]
	}

	m.raw = x
	return m.raw, nil
}

func (m *certificateMsg) unmarshal(data []byte) bool {
	if len(data) < dtlcpHeaderLen+3 {
		return false
	}

	m.raw = data
	m.messageSeq = uint16(data[4])<<8 | uint16(data[5])
	m.fragmentOffset = uint24(data[6])<<16 | uint24(data[7])<<8 | uint24(data[8])
	m.fragmentLength = uint24(data[9])<<16 | uint24(data[10])<<8 | uint24(data[11])

	certsLen := uint32(data[12])<<16 | uint32(data[13])<<8 | uint32(data[14])
	if uint32(len(data)) != certsLen+uint32(dtlcpHeaderLen)+3 {
		return false
	}

	numCerts := 0
	d := data[dtlcpHeaderLen+3:]
	for certsLen > 0 {
		if len(d) < 4 {
			return false
		}
		certLen := uint32(d[0])<<16 | uint32(d[1])<<8 | uint32(d[2])
		if uint32(len(d)) < 3+certLen {
			return false
		}
		d = d[3+certLen:]
		certsLen -= 3 + certLen
		numCerts++
	}

	m.certificates = make([][]byte, numCerts)
	d = data[dtlcpHeaderLen+3:]
	for i := 0; i < numCerts; i++ {
		certLen := uint32(d[0])<<16 | uint32(d[1])<<8 | uint32(d[2])
		m.certificates[i] = d[3 : 3+certLen]
		d = d[3+certLen:]
	}

	return true
}

func (m *certificateMsg) messageType() uint8 {
	return typeCertificate
}

func (m *certificateMsg) debug() {
	fmt.Printf(">>> Certificates\n")
	for i, cert := range m.certificates {
		fmt.Printf("Cert[%v]:\n", i)
		block := &pem.Block{Bytes: cert, Type: "CERTIFICATE"}
		fmt.Printf("%v", string(pem.EncodeToMemory(block)))
	}
	fmt.Printf("<<<\n")
}

func (m *certificateMsg) setMessageSeq(seq uint16) {
	m.messageSeq = seq
	m.raw = nil
}

func (m *certificateMsg) getMessageSeq() uint16 {
	return m.messageSeq
}

// =============================================================================
// serverKeyExchangeMsg
// =============================================================================

type serverKeyExchangeMsg struct {
	raw []byte
	key []byte

	// DTLCP 分片字段
	messageSeq     uint16
	fragmentOffset uint24
	fragmentLength uint24
}

func (m *serverKeyExchangeMsg) marshal() ([]byte, error) {
	if m.raw != nil {
		return m.raw, nil
	}
	length := len(m.key)
	fragLen := m.fragmentLength
	if fragLen == 0 {
		fragLen = uint24(length)
	}
	x := make([]byte, dtlcpHeaderLen+length)
	x[0] = typeServerKeyExchange
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	x[4] = uint8(m.messageSeq >> 8)
	x[5] = uint8(m.messageSeq)
	x[6] = uint8(m.fragmentOffset >> 16)
	x[7] = uint8(m.fragmentOffset >> 8)
	x[8] = uint8(m.fragmentOffset)
	x[9] = uint8(fragLen >> 16)
	x[10] = uint8(fragLen >> 8)
	x[11] = uint8(fragLen)
	copy(x[dtlcpHeaderLen:], m.key)

	m.raw = x
	return x, nil
}

func (m *serverKeyExchangeMsg) unmarshal(data []byte) bool {
	if len(data) < dtlcpHeaderLen {
		return false
	}
	m.raw = data
	m.messageSeq = uint16(data[4])<<8 | uint16(data[5])
	m.fragmentOffset = uint24(data[6])<<16 | uint24(data[7])<<8 | uint24(data[8])
	m.fragmentLength = uint24(data[9])<<16 | uint24(data[10])<<8 | uint24(data[11])
	m.key = make([]byte, len(data)-dtlcpHeaderLen)
	copy(m.key, data[dtlcpHeaderLen:])
	return true
}

func (m *serverKeyExchangeMsg) messageType() uint8 {
	return typeServerKeyExchange
}

func (m *serverKeyExchangeMsg) debug() {
}

func (m *serverKeyExchangeMsg) setMessageSeq(seq uint16) {
	m.messageSeq = seq
	m.raw = nil
}

func (m *serverKeyExchangeMsg) getMessageSeq() uint16 {
	return m.messageSeq
}

// =============================================================================
// certificateRequestMsg
// =============================================================================

type certificateRequestMsg struct {
	raw []byte

	certificateTypes        []byte
	certificateAuthorities  [][]byte

	// DTLCP 分片字段
	messageSeq     uint16
	fragmentOffset uint24
	fragmentLength uint24
}

func (m *certificateRequestMsg) marshal() ([]byte, error) {
	if m.raw != nil {
		return m.raw, nil
	}

	length := 1 + len(m.certificateTypes) + 2
	casLength := 0
	for _, ca := range m.certificateAuthorities {
		casLength += 2 + len(ca)
	}
	length += casLength

fragLen := m.fragmentLength
if fragLen == 0 {
	fragLen = uint24(length)
}
	x := make([]byte, dtlcpHeaderLen+length)
	x[0] = typeCertificateRequest
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	x[4] = uint8(m.messageSeq >> 8)
	x[5] = uint8(m.messageSeq)
	x[6] = uint8(m.fragmentOffset >> 16)
	x[7] = uint8(m.fragmentOffset >> 8)
	x[8] = uint8(m.fragmentOffset)
	x[9] = uint8(fragLen >> 16)
	x[10] = uint8(fragLen >> 8)
	x[11] = uint8(fragLen)

	x[12] = uint8(len(m.certificateTypes))
	copy(x[13:], m.certificateTypes)
	y := x[13+len(m.certificateTypes):]

	y[0] = uint8(casLength >> 8)
	y[1] = uint8(casLength)
	y = y[2:]
	for _, ca := range m.certificateAuthorities {
		y[0] = uint8(len(ca) >> 8)
		y[1] = uint8(len(ca))
		y = y[2:]
		copy(y, ca)
		y = y[len(ca):]
	}

	m.raw = x
	return x, nil
}

func (m *certificateRequestMsg) unmarshal(data []byte) bool {
	m.raw = data

	if len(data) < dtlcpHeaderLen+1 {
		return false
	}

	m.messageSeq = uint16(data[4])<<8 | uint16(data[5])
	m.fragmentOffset = uint24(data[6])<<16 | uint24(data[7])<<8 | uint24(data[8])
	m.fragmentLength = uint24(data[9])<<16 | uint24(data[10])<<8 | uint24(data[11])

	length := uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	if uint32(len(data))-uint32(dtlcpHeaderLen) != length {
		return false
	}

	numCertTypes := int(data[dtlcpHeaderLen])
	body := data[dtlcpHeaderLen+1:]
	if numCertTypes == 0 || len(body) <= numCertTypes {
		return false
	}

	m.certificateTypes = make([]byte, numCertTypes)
	if copy(m.certificateTypes, body) != numCertTypes {
		return false
	}

	body = body[numCertTypes:]

	if len(body) < 2 {
		return false
	}
	casLength := uint16(body[0])<<8 | uint16(body[1])
	body = body[2:]
	if len(body) < int(casLength) {
		return false
	}
	cas := make([]byte, casLength)
	copy(cas, body)
	body = body[casLength:]

	m.certificateAuthorities = nil
	for len(cas) > 0 {
		if len(cas) < 2 {
			return false
		}
		caLen := uint16(cas[0])<<8 | uint16(cas[1])
		cas = cas[2:]
		if len(cas) < int(caLen) {
			return false
		}
		m.certificateAuthorities = append(m.certificateAuthorities, cas[:caLen])
		cas = cas[caLen:]
	}

	return len(body) == 0
}

func (m *certificateRequestMsg) messageType() uint8 {
	return typeCertificateRequest
}

func (m *certificateRequestMsg) debug() {
	fmt.Printf(">>> Certificate Request\n")
	fmt.Print("Certificate Types: ")
	for i, t := range m.certificateTypes {
		switch t {
		case 1:
			fmt.Print("RSA")
		case 2:
			fmt.Print("DSS")
		case 64:
			fmt.Print("ECDSA")
		case 80:
			fmt.Print("IBC")
		default:
			fmt.Printf("%v", t)
		}
		if i < len(m.certificateTypes)-1 {
			fmt.Print(", ")
		}
	}
	fmt.Printf("\nCertificate Authorities:\n")
	for i, rawIssuer := range m.certificateAuthorities {
		fmt.Printf("Issuer[%v]:\n", i)
		issuerRDNs, err := x509.ParseName(rawIssuer)
		if err == nil {
			fmt.Printf("%v\n", issuerRDNs)
		} else {
			fmt.Printf("%v\n", string(rawIssuer))
		}
	}
	fmt.Printf("<<<\n")
}

func (m *certificateRequestMsg) setMessageSeq(seq uint16) {
	m.messageSeq = seq
	m.raw = nil
}

func (m *certificateRequestMsg) getMessageSeq() uint16 {
	return m.messageSeq
}

// =============================================================================
// serverHelloDoneMsg
// =============================================================================

type serverHelloDoneMsg struct {
	raw []byte

	// DTLCP 分片字段
	messageSeq     uint16
	fragmentOffset uint24
	fragmentLength uint24
}

func (m *serverHelloDoneMsg) marshal() ([]byte, error) {
	if m.raw != nil {
		return m.raw, nil
	}
	x := make([]byte, dtlcpHeaderLen)
	x[0] = typeServerHelloDone
	// length = 0 (空消息体)
	x[4] = uint8(m.messageSeq >> 8)
	x[5] = uint8(m.messageSeq)
	// fragmentOffset 和 fragmentLength 默认为 0
	m.raw = x
	return x, nil
}

func (m *serverHelloDoneMsg) unmarshal(data []byte) bool {
	if len(data) < dtlcpHeaderLen {
		return false
	}
	m.raw = data
	m.messageSeq = uint16(data[4])<<8 | uint16(data[5])
	m.fragmentOffset = uint24(data[6])<<16 | uint24(data[7])<<8 | uint24(data[8])
	m.fragmentLength = uint24(data[9])<<16 | uint24(data[10])<<8 | uint24(data[11])

	// 验证 body 为空
	bodyLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	return bodyLen == 0 && data[0] == typeServerHelloDone
}

func (m *serverHelloDoneMsg) messageType() uint8 {
	return typeServerHelloDone
}

func (m *serverHelloDoneMsg) debug() {
}

func (m *serverHelloDoneMsg) setMessageSeq(seq uint16) {
	m.messageSeq = seq
	m.raw = nil
}

func (m *serverHelloDoneMsg) getMessageSeq() uint16 {
	return m.messageSeq
}

// =============================================================================
// clientKeyExchangeMsg
// =============================================================================

type clientKeyExchangeMsg struct {
	raw        []byte
	ciphertext []byte

	// DTLCP 分片字段
	messageSeq     uint16
	fragmentOffset uint24
	fragmentLength uint24
}

func (m *clientKeyExchangeMsg) marshal() ([]byte, error) {
	if m.raw != nil {
		return m.raw, nil
	}
	length := len(m.ciphertext)
	fragLen := m.fragmentLength
	if fragLen == 0 {
		fragLen = uint24(length)
	}
	x := make([]byte, dtlcpHeaderLen+length)
	x[0] = typeClientKeyExchange
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	x[4] = uint8(m.messageSeq >> 8)
	x[5] = uint8(m.messageSeq)
	x[6] = uint8(m.fragmentOffset >> 16)
	x[7] = uint8(m.fragmentOffset >> 8)
	x[8] = uint8(m.fragmentOffset)
	x[9] = uint8(fragLen >> 16)
	x[10] = uint8(fragLen >> 8)
	x[11] = uint8(fragLen)
	copy(x[dtlcpHeaderLen:], m.ciphertext)

	m.raw = x
	return x, nil
}

func (m *clientKeyExchangeMsg) unmarshal(data []byte) bool {
	if len(data) < dtlcpHeaderLen {
		return false
	}
	m.raw = data
	m.messageSeq = uint16(data[4])<<8 | uint16(data[5])
	m.fragmentOffset = uint24(data[6])<<16 | uint24(data[7])<<8 | uint24(data[8])
	m.fragmentLength = uint24(data[9])<<16 | uint24(data[10])<<8 | uint24(data[11])

	l := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if l != len(data)-dtlcpHeaderLen {
		return false
	}
	m.ciphertext = make([]byte, l)
	copy(m.ciphertext, data[dtlcpHeaderLen:])
	return true
}

func (m *clientKeyExchangeMsg) messageType() uint8 {
	return typeClientKeyExchange
}

func (m *clientKeyExchangeMsg) debug() {
}

func (m *clientKeyExchangeMsg) setMessageSeq(seq uint16) {
	m.messageSeq = seq
	m.raw = nil
}

func (m *clientKeyExchangeMsg) getMessageSeq() uint16 {
	return m.messageSeq
}

// =============================================================================
// certificateVerifyMsg
// =============================================================================

type certificateVerifyMsg struct {
	raw       []byte
	signature []byte

	// DTLCP 分片字段
	messageSeq     uint16
	fragmentOffset uint24
	fragmentLength uint24
}

func (m *certificateVerifyMsg) marshal() ([]byte, error) {
	if m.raw != nil {
		return m.raw, nil
	}

	// 构建消息体：sig_length(2) + signature
	var body cryptobyte.Builder
	body.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(m.signature)
	})

	bodyBytes, err := body.Bytes()
	if err != nil {
		return nil, err
	}

	m.raw, err = dtlcpMarshalHeader(m.messageType(), bodyBytes, m.messageSeq, m.fragmentOffset, m.fragmentLength)
	return m.raw, err
}

func (m *certificateVerifyMsg) unmarshal(data []byte) bool {
	m.raw = data
	msgType, _, messageSeq, fragmentOffset, fragmentLength, body, ok := dtlcpUnmarshalHeader(data)
	if !ok || msgType != typeCertificateVerify {
		return false
	}
	m.messageSeq = messageSeq
	m.fragmentOffset = fragmentOffset
	m.fragmentLength = fragmentLength

	s := cryptobyte.String(body)
	return readUint16LengthPrefixed(&s, &m.signature) && s.Empty()
}

func (m *certificateVerifyMsg) messageType() uint8 {
	return typeCertificateVerify
}

func (m *certificateVerifyMsg) debug() {
}

func (m *certificateVerifyMsg) setMessageSeq(seq uint16) {
	m.messageSeq = seq
	m.raw = nil
}

func (m *certificateVerifyMsg) getMessageSeq() uint16 {
	return m.messageSeq
}

// =============================================================================
// finishedMsg
// =============================================================================

type finishedMsg struct {
	raw        []byte
	verifyData []byte

	// DTLCP 分片字段
	messageSeq     uint16
	fragmentOffset uint24
	fragmentLength uint24
}

func (m *finishedMsg) marshal() ([]byte, error) {
	if m.raw != nil {
		return m.raw, nil
	}

	var body cryptobyte.Builder
	body.AddBytes(m.verifyData)

	bodyBytes, err := body.Bytes()
	if err != nil {
		return nil, err
	}

	m.raw, err = dtlcpMarshalHeader(m.messageType(), bodyBytes, m.messageSeq, m.fragmentOffset, m.fragmentLength)
	return m.raw, err
}

func (m *finishedMsg) unmarshal(data []byte) bool {
	m.raw = data
	msgType, bodyLen, messageSeq, fragmentOffset, fragmentLength, body, ok := dtlcpUnmarshalHeader(data)
	if !ok || msgType != typeFinished {
		return false
	}
	m.messageSeq = messageSeq
	m.fragmentOffset = fragmentOffset
	m.fragmentLength = fragmentLength

	if bodyLen > maxHandshake {
		return false
	}
	m.verifyData = make([]byte, bodyLen)
	copy(m.verifyData, body)
	return true
}

func (m *finishedMsg) messageType() uint8 {
	return typeFinished
}

func (m *finishedMsg) debug() {
	fmt.Printf(">>> Finished\n")
	fmt.Printf("verify_data: %v\n", m.verifyData)
	fmt.Printf("<<<\n")
}

func (m *finishedMsg) setMessageSeq(seq uint16) {
	m.messageSeq = seq
	m.raw = nil
}

func (m *finishedMsg) getMessageSeq() uint16 {
	return m.messageSeq
}
