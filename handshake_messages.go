// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tlcp

import (
	"fmt"
	"golang.org/x/crypto/cryptobyte"
)

// The marshalingFunction type is an adapter to allow the use of ordinary
// functions as cryptobyte.MarshalingValue.
type marshalingFunction func(b *cryptobyte.Builder) error

func (f marshalingFunction) Marshal(b *cryptobyte.Builder) error {
	return f(b)
}

// addBytesWithLength appends a sequence of bytes to the cryptobyte.Builder. If
// the length of the sequence is not the value specified, it produces an error.
func addBytesWithLength(b *cryptobyte.Builder, v []byte, n int) {
	b.AddValue(marshalingFunction(func(b *cryptobyte.Builder) error {
		if len(v) != n {
			return fmt.Errorf("invalid value length: expected %d, got %d", n, len(v))
		}
		b.AddBytes(v)
		return nil
	}))
}

// addUint64 appends a big-endian, 64-bit value to the cryptobyte.Builder.
func addUint64(b *cryptobyte.Builder, v uint64) {
	b.AddUint32(uint32(v >> 32))
	b.AddUint32(uint32(v))
}

// readUint64 decodes a big-endian, 64-bit value into out and advances over it.
// It reports whether the read was successful.
func readUint64(s *cryptobyte.String, out *uint64) bool {
	var hi, lo uint32
	if !s.ReadUint32(&hi) || !s.ReadUint32(&lo) {
		return false
	}
	*out = uint64(hi)<<32 | uint64(lo)
	return true
}

// readUint8LengthPrefixed acts like s.ReadUint8LengthPrefixed, but targets a
// []byte instead of a cryptobyte.String.
func readUint8LengthPrefixed(s *cryptobyte.String, out *[]byte) bool {
	return s.ReadUint8LengthPrefixed((*cryptobyte.String)(out))
}

// readUint16LengthPrefixed acts like s.ReadUint16LengthPrefixed, but targets a
// []byte instead of a cryptobyte.String.
func readUint16LengthPrefixed(s *cryptobyte.String, out *[]byte) bool {
	return s.ReadUint16LengthPrefixed((*cryptobyte.String)(out))
}

// readUint24LengthPrefixed acts like s.ReadUint24LengthPrefixed, but targets a
// []byte instead of a cryptobyte.String.
func readUint24LengthPrefixed(s *cryptobyte.String, out *[]byte) bool {
	return s.ReadUint24LengthPrefixed((*cryptobyte.String)(out))
}

type clientHelloMsg struct {
	raw    []byte
	vers   uint16
	random []byte
	// sessionId 是一个可变长字段,其值由服务端决定。如果没有可重用的会话标识或希望协商
	// 安全参数,该字段应为空,否则表示客户端希望重用该会话。这个会话标识可能是之前的连接
	// 标识、当前连接标识、或其他处于连接状态的连接标识。会话标识生成后应一直保持到被超时
	// 删除或与这个会话相关的连接遇到致命错误被关闭。一个会话失效或被关闭时则与其相关的
	// 连接都应被强制关闭。
	sessionId          []byte
	cipherSuites       []uint16
	compressionMethods []uint8
}

func (m *clientHelloMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}

	var b cryptobyte.Builder
	b.AddUint8(typeClientHello)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(m.vers)
		addBytesWithLength(b, m.random, 32)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(m.sessionId)
		})
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, suite := range m.cipherSuites {
				b.AddUint16(suite)
			}
		})
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(m.compressionMethods)
		})

		// 由于GB/T 38636-2016 不支持扩展，因此忽略
	})

	m.raw = b.BytesOrPanic()
	return m.raw
}

func (m *clientHelloMsg) unmarshal(data []byte) bool {
	*m = clientHelloMsg{raw: data}
	s := cryptobyte.String(data)

	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint16(&m.vers) || !s.ReadBytes(&m.random, 32) ||
		!readUint8LengthPrefixed(&s, &m.sessionId) {
		return false
	}

	var cipherSuites cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cipherSuites) {
		return false
	}
	m.cipherSuites = []uint16{}
	//m.secureRenegotiationSupported = false
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

	// GM/T 38636-2016 不支持扩展，忽略剩余的扩展字段
	return true
}

type serverHelloMsg struct {
	raw    []byte
	vers   uint16
	random []byte
	// sessionId 服务端使用的会话标识,如果客户端hello消息中的会话标识不为空,且服务端存在匹配的会
	// 话标识,则服务端重用与该标识对应的会话建立新连接,并在回应的服务端hello消息中带上
	// 与客户端一致的会话标识,否则服务端产生一个新的会话标识,用来建立一个新的会话。
	sessionId         []byte
	cipherSuite       uint16
	compressionMethod uint8
}

func (m *serverHelloMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}

	var b cryptobyte.Builder
	b.AddUint8(typeServerHello)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(m.vers)
		addBytesWithLength(b, m.random, 32)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(m.sessionId)
		})
		b.AddUint16(m.cipherSuite)
		b.AddUint8(m.compressionMethod)
		// 由于GB/T 38636-2016 不支持扩展，因此忽略
	})

	m.raw = b.BytesOrPanic()
	return m.raw
}

func (m *serverHelloMsg) unmarshal(data []byte) bool {
	*m = serverHelloMsg{raw: data}
	s := cryptobyte.String(data)

	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint16(&m.vers) || !s.ReadBytes(&m.random, 32) ||
		!readUint8LengthPrefixed(&s, &m.sessionId) ||
		!s.ReadUint16(&m.cipherSuite) ||
		!s.ReadUint8(&m.compressionMethod) {
		return false
	}

	// 由于GB/T 38636-2016 不支持扩展，因此忽略

	return true
}

//
//type encryptedExtensionsMsg struct {
//	raw          []byte
//	alpnProtocol string
//}
//
//func (m *encryptedExtensionsMsg) marshal() []byte {
//	if m.raw != nil {
//		return m.raw
//	}
//
//	var b cryptobyte.Builder
//	b.AddUint8(typeEncryptedExtensions)
//	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
//		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
//			if len(m.alpnProtocol) > 0 {
//				b.AddUint16(extensionALPN)
//				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
//					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
//						b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
//							b.AddBytes([]byte(m.alpnProtocol))
//						})
//					})
//				})
//			}
//		})
//	})
//
//	m.raw = b.BytesOrPanic()
//	return m.raw
//}
//
//func (m *encryptedExtensionsMsg) unmarshal(data []byte) bool {
//	*m = encryptedExtensionsMsg{raw: data}
//	s := cryptobyte.String(data)
//
//	var extensions cryptobyte.String
//	if !s.Skip(4) || // message type and uint24 length field
//		!s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
//		return false
//	}
//
//	for !extensions.Empty() {
//		var extension uint16
//		var extData cryptobyte.String
//		if !extensions.ReadUint16(&extension) ||
//			!extensions.ReadUint16LengthPrefixed(&extData) {
//			return false
//		}
//
//		switch extension {
//		case extensionALPN:
//			var protoList cryptobyte.String
//			if !extData.ReadUint16LengthPrefixed(&protoList) || protoList.Empty() {
//				return false
//			}
//			var proto cryptobyte.String
//			if !protoList.ReadUint8LengthPrefixed(&proto) ||
//				proto.Empty() || !protoList.Empty() {
//				return false
//			}
//			m.alpnProtocol = string(proto)
//		default:
//			// Ignore unknown extensions.
//			continue
//		}
//
//		if !extData.Empty() {
//			return false
//		}
//	}
//
//	return true
//}
//
//type endOfEarlyDataMsg struct{}
//
//func (m *endOfEarlyDataMsg) marshal() []byte {
//	x := make([]byte, 4)
//	x[0] = typeEndOfEarlyData
//	return x
//}
//
//func (m *endOfEarlyDataMsg) unmarshal(data []byte) bool {
//	return len(data) == 4
//}
//
//type keyUpdateMsg struct {
//	raw             []byte
//	updateRequested bool
//}
//
//func (m *keyUpdateMsg) marshal() []byte {
//	if m.raw != nil {
//		return m.raw
//	}
//
//	var b cryptobyte.Builder
//	b.AddUint8(typeKeyUpdate)
//	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
//		if m.updateRequested {
//			b.AddUint8(1)
//		} else {
//			b.AddUint8(0)
//		}
//	})
//
//	m.raw = b.BytesOrPanic()
//	return m.raw
//}
//
//func (m *keyUpdateMsg) unmarshal(data []byte) bool {
//	m.raw = data
//	s := cryptobyte.String(data)
//
//	var updateRequested uint8
//	if !s.Skip(4) || // message type and uint24 length field
//		!s.ReadUint8(&updateRequested) || !s.Empty() {
//		return false
//	}
//	switch updateRequested {
//	case 0:
//		m.updateRequested = false
//	case 1:
//		m.updateRequested = true
//	default:
//		return false
//	}
//	return true
//}

//type newSessionTicketMsgTLS13 struct {
//	raw          []byte
//	lifetime     uint32
//	ageAdd       uint32
//	nonce        []byte
//	label        []byte
//	maxEarlyData uint32
//}
//
//func (m *newSessionTicketMsgTLS13) marshal() []byte {
//	if m.raw != nil {
//		return m.raw
//	}
//
//	var b cryptobyte.Builder
//	b.AddUint8(typeNewSessionTicket)
//	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
//		b.AddUint32(m.lifetime)
//		b.AddUint32(m.ageAdd)
//		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
//			b.AddBytes(m.nonce)
//		})
//		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
//			b.AddBytes(m.label)
//		})
//
//		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
//			if m.maxEarlyData > 0 {
//				b.AddUint16(extensionEarlyData)
//				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
//					b.AddUint32(m.maxEarlyData)
//				})
//			}
//		})
//	})
//
//	m.raw = b.BytesOrPanic()
//	return m.raw
//}
//
//func (m *newSessionTicketMsgTLS13) unmarshal(data []byte) bool {
//	*m = newSessionTicketMsgTLS13{raw: data}
//	s := cryptobyte.String(data)
//
//	var extensions cryptobyte.String
//	if !s.Skip(4) || // message type and uint24 length field
//		!s.ReadUint32(&m.lifetime) ||
//		!s.ReadUint32(&m.ageAdd) ||
//		!readUint8LengthPrefixed(&s, &m.nonce) ||
//		!readUint16LengthPrefixed(&s, &m.label) ||
//		!s.ReadUint16LengthPrefixed(&extensions) ||
//		!s.Empty() {
//		return false
//	}
//
//	for !extensions.Empty() {
//		var extension uint16
//		var extData cryptobyte.String
//		if !extensions.ReadUint16(&extension) ||
//			!extensions.ReadUint16LengthPrefixed(&extData) {
//			return false
//		}
//
//		switch extension {
//		case extensionEarlyData:
//			if !extData.ReadUint32(&m.maxEarlyData) {
//				return false
//			}
//		default:
//			// Ignore unknown extensions.
//			continue
//		}
//
//		if !extData.Empty() {
//			return false
//		}
//	}
//
//	return true
//}

//
//type certificateRequestMsgTLS13 struct {
//	raw                              []byte
//	ocspStapling                     bool
//	scts                             bool
//	supportedSignatureAlgorithms     []SignatureScheme
//	supportedSignatureAlgorithmsCert []SignatureScheme
//	certificateAuthorities           [][]byte
//}
//
//func (m *certificateRequestMsgTLS13) marshal() []byte {
//	if m.raw != nil {
//		return m.raw
//	}
//
//	var b cryptobyte.Builder
//	b.AddUint8(typeCertificateRequest)
//	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
//		// certificate_request_context (SHALL be zero length unless used for
//		// post-handshake authentication)
//		b.AddUint8(0)
//
//		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
//			if m.ocspStapling {
//				b.AddUint16(extensionStatusRequest)
//				b.AddUint16(0) // empty extension_data
//			}
//			if m.scts {
//				// RFC 8446, Section 4.4.2.1 makes no mention of
//				// signed_certificate_timestamp in CertificateRequest, but
//				// "Extensions in the Certificate message from the client MUST
//				// correspond to extensions in the CertificateRequest message
//				// from the server." and it appears in the table in Section 4.2.
//				b.AddUint16(extensionSCT)
//				b.AddUint16(0) // empty extension_data
//			}
//			if len(m.supportedSignatureAlgorithms) > 0 {
//				b.AddUint16(extensionSignatureAlgorithms)
//				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
//					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
//						for _, sigAlgo := range m.supportedSignatureAlgorithms {
//							b.AddUint16(uint16(sigAlgo))
//						}
//					})
//				})
//			}
//			if len(m.supportedSignatureAlgorithmsCert) > 0 {
//				b.AddUint16(extensionSignatureAlgorithmsCert)
//				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
//					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
//						for _, sigAlgo := range m.supportedSignatureAlgorithmsCert {
//							b.AddUint16(uint16(sigAlgo))
//						}
//					})
//				})
//			}
//			if len(m.certificateAuthorities) > 0 {
//				b.AddUint16(extensionCertificateAuthorities)
//				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
//					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
//						for _, ca := range m.certificateAuthorities {
//							b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
//								b.AddBytes(ca)
//							})
//						}
//					})
//				})
//			}
//		})
//	})
//
//	m.raw = b.BytesOrPanic()
//	return m.raw
//}
//
//func (m *certificateRequestMsgTLS13) unmarshal(data []byte) bool {
//	*m = certificateRequestMsgTLS13{raw: data}
//	s := cryptobyte.String(data)
//
//	var context, extensions cryptobyte.String
//	if !s.Skip(4) || // message type and uint24 length field
//		!s.ReadUint8LengthPrefixed(&context) || !context.Empty() ||
//		!s.ReadUint16LengthPrefixed(&extensions) ||
//		!s.Empty() {
//		return false
//	}
//
//	for !extensions.Empty() {
//		var extension uint16
//		var extData cryptobyte.String
//		if !extensions.ReadUint16(&extension) ||
//			!extensions.ReadUint16LengthPrefixed(&extData) {
//			return false
//		}
//
//		switch extension {
//		case extensionStatusRequest:
//			m.ocspStapling = true
//		case extensionSCT:
//			m.scts = true
//		case extensionSignatureAlgorithms:
//			var sigAndAlgs cryptobyte.String
//			if !extData.ReadUint16LengthPrefixed(&sigAndAlgs) || sigAndAlgs.Empty() {
//				return false
//			}
//			for !sigAndAlgs.Empty() {
//				var sigAndAlg uint16
//				if !sigAndAlgs.ReadUint16(&sigAndAlg) {
//					return false
//				}
//				m.supportedSignatureAlgorithms = append(
//					m.supportedSignatureAlgorithms, SignatureScheme(sigAndAlg))
//			}
//		case extensionSignatureAlgorithmsCert:
//			var sigAndAlgs cryptobyte.String
//			if !extData.ReadUint16LengthPrefixed(&sigAndAlgs) || sigAndAlgs.Empty() {
//				return false
//			}
//			for !sigAndAlgs.Empty() {
//				var sigAndAlg uint16
//				if !sigAndAlgs.ReadUint16(&sigAndAlg) {
//					return false
//				}
//				m.supportedSignatureAlgorithmsCert = append(
//					m.supportedSignatureAlgorithmsCert, SignatureScheme(sigAndAlg))
//			}
//		case extensionCertificateAuthorities:
//			var auths cryptobyte.String
//			if !extData.ReadUint16LengthPrefixed(&auths) || auths.Empty() {
//				return false
//			}
//			for !auths.Empty() {
//				var ca []byte
//				if !readUint16LengthPrefixed(&auths, &ca) || len(ca) == 0 {
//					return false
//				}
//				m.certificateAuthorities = append(m.certificateAuthorities, ca)
//			}
//		default:
//			// Ignore unknown extensions.
//			continue
//		}
//
//		if !extData.Empty() {
//			return false
//		}
//	}
//
//	return true
//}

type certificateMsg struct {
	raw          []byte
	certificates [][]byte
}

func (m *certificateMsg) marshal() (x []byte) {
	if m.raw != nil {
		return m.raw
	}

	var i int
	for _, slice := range m.certificates {
		i += len(slice)
	}

	length := 3 + 3*len(m.certificates) + i
	x = make([]byte, 4+length)
	x[0] = typeCertificate
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)

	certificateOctets := length - 3
	x[4] = uint8(certificateOctets >> 16)
	x[5] = uint8(certificateOctets >> 8)
	x[6] = uint8(certificateOctets)

	y := x[7:]
	for _, slice := range m.certificates {
		y[0] = uint8(len(slice) >> 16)
		y[1] = uint8(len(slice) >> 8)
		y[2] = uint8(len(slice))
		copy(y[3:], slice)
		y = y[3+len(slice):]
	}

	m.raw = x
	return
}

func (m *certificateMsg) unmarshal(data []byte) bool {
	if len(data) < 7 {
		return false
	}

	m.raw = data
	certsLen := uint32(data[4])<<16 | uint32(data[5])<<8 | uint32(data[6])
	if uint32(len(data)) != certsLen+7 {
		return false
	}

	numCerts := 0
	d := data[7:]
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
	d = data[7:]
	for i := 0; i < numCerts; i++ {
		certLen := uint32(d[0])<<16 | uint32(d[1])<<8 | uint32(d[2])
		m.certificates[i] = d[3 : 3+certLen]
		d = d[3+certLen:]
	}

	return true
}

//
//type certificateMsgTLS13 struct {
//	raw          []byte
//	certificate  Certificate
//	ocspStapling bool
//	scts         bool
//}
//
//func (m *certificateMsgTLS13) marshal() []byte {
//	if m.raw != nil {
//		return m.raw
//	}
//
//	var b cryptobyte.Builder
//	b.AddUint8(typeCertificate)
//	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
//		b.AddUint8(0) // certificate_request_context
//
//		certificate := m.certificate
//		if !m.ocspStapling {
//			certificate.OCSPStaple = nil
//		}
//		if !m.scts {
//			certificate.SignedCertificateTimestamps = nil
//		}
//		marshalCertificate(b, certificate)
//	})
//
//	m.raw = b.BytesOrPanic()
//	return m.raw
//}
//
//func marshalCertificate(b *cryptobyte.Builder, certificate Certificate) {
//	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
//		for i, sigCert := range certificate.Certificate {
//			b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
//				b.AddBytes(sigCert)
//			})
//			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
//				if i > 0 {
//					// This library only supports OCSP and SCT for leaf certificates.
//					return
//				}
//				if certificate.OCSPStaple != nil {
//					b.AddUint16(extensionStatusRequest)
//					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
//						b.AddUint8(statusTypeOCSP)
//						b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
//							b.AddBytes(certificate.OCSPStaple)
//						})
//					})
//				}
//				if certificate.SignedCertificateTimestamps != nil {
//					b.AddUint16(extensionSCT)
//					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
//						b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
//							for _, sct := range certificate.SignedCertificateTimestamps {
//								b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
//									b.AddBytes(sct)
//								})
//							}
//						})
//					})
//				}
//			})
//		}
//	})
//}
//
//func (m *certificateMsgTLS13) unmarshal(data []byte) bool {
//	*m = certificateMsgTLS13{raw: data}
//	s := cryptobyte.String(data)
//
//	var context cryptobyte.String
//	if !s.Skip(4) || // message type and uint24 length field
//		!s.ReadUint8LengthPrefixed(&context) || !context.Empty() ||
//		!unmarshalCertificate(&s, &m.certificate) ||
//		!s.Empty() {
//		return false
//	}
//
//	m.scts = m.certificate.SignedCertificateTimestamps != nil
//	m.ocspStapling = m.certificate.OCSPStaple != nil
//
//	return true
//}
//
//func unmarshalCertificate(s *cryptobyte.String, certificate *Certificate) bool {
//	var certList cryptobyte.String
//	if !s.ReadUint24LengthPrefixed(&certList) {
//		return false
//	}
//	for !certList.Empty() {
//		var sigCert []byte
//		var extensions cryptobyte.String
//		if !readUint24LengthPrefixed(&certList, &sigCert) ||
//			!certList.ReadUint16LengthPrefixed(&extensions) {
//			return false
//		}
//		certificate.Certificate = append(certificate.Certificate, sigCert)
//		for !extensions.Empty() {
//			var extension uint16
//			var extData cryptobyte.String
//			if !extensions.ReadUint16(&extension) ||
//				!extensions.ReadUint16LengthPrefixed(&extData) {
//				return false
//			}
//			if len(certificate.Certificate) > 1 {
//				// This library only supports OCSP and SCT for leaf certificates.
//				continue
//			}
//
//			switch extension {
//			case extensionStatusRequest:
//				var statusType uint8
//				if !extData.ReadUint8(&statusType) || statusType != statusTypeOCSP ||
//					!readUint24LengthPrefixed(&extData, &certificate.OCSPStaple) ||
//					len(certificate.OCSPStaple) == 0 {
//					return false
//				}
//			case extensionSCT:
//				var sctList cryptobyte.String
//				if !extData.ReadUint16LengthPrefixed(&sctList) || sctList.Empty() {
//					return false
//				}
//				for !sctList.Empty() {
//					var sct []byte
//					if !readUint16LengthPrefixed(&sctList, &sct) ||
//						len(sct) == 0 {
//						return false
//					}
//					certificate.SignedCertificateTimestamps = append(
//						certificate.SignedCertificateTimestamps, sct)
//				}
//			default:
//				// Ignore unknown extensions.
//				continue
//			}
//
//			if !extData.Empty() {
//				return false
//			}
//		}
//	}
//	return true
//}

type serverKeyExchangeMsg struct {
	raw []byte
	key []byte
}

func (m *serverKeyExchangeMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}
	length := len(m.key)
	x := make([]byte, length+4)
	x[0] = typeServerKeyExchange
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	copy(x[4:], m.key)

	m.raw = x
	return x
}

func (m *serverKeyExchangeMsg) unmarshal(data []byte) bool {
	m.raw = data
	if len(data) < 4 {
		return false
	}
	m.key = data[4:]
	return true
}

//
//type certificateStatusMsg struct {
//	raw      []byte
//	response []byte
//}
//
//func (m *certificateStatusMsg) marshal() []byte {
//	if m.raw != nil {
//		return m.raw
//	}
//
//	var b cryptobyte.Builder
//	b.AddUint8(typeCertificateStatus)
//	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
//		b.AddUint8(statusTypeOCSP)
//		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
//			b.AddBytes(m.response)
//		})
//	})
//
//	m.raw = b.BytesOrPanic()
//	return m.raw
//}
//
//func (m *certificateStatusMsg) unmarshal(data []byte) bool {
//	m.raw = data
//	s := cryptobyte.String(data)
//
//	var statusType uint8
//	if !s.Skip(4) || // message type and uint24 length field
//		!s.ReadUint8(&statusType) || statusType != statusTypeOCSP ||
//		!readUint24LengthPrefixed(&s, &m.response) ||
//		len(m.response) == 0 || !s.Empty() {
//		return false
//	}
//	return true
//}

type serverHelloDoneMsg struct{}

func (m *serverHelloDoneMsg) marshal() []byte {
	x := make([]byte, 4)
	x[0] = typeServerHelloDone
	return x
}

func (m *serverHelloDoneMsg) unmarshal(data []byte) bool {
	return len(data) == 4
}

type clientKeyExchangeMsg struct {
	raw        []byte
	ciphertext []byte
}

func (m *clientKeyExchangeMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}
	length := len(m.ciphertext)
	x := make([]byte, length+4)
	x[0] = typeClientKeyExchange
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	copy(x[4:], m.ciphertext)

	m.raw = x
	return x
}

func (m *clientKeyExchangeMsg) unmarshal(data []byte) bool {
	m.raw = data
	if len(data) < 4 {
		return false
	}
	l := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if l != len(data)-4 {
		return false
	}
	m.ciphertext = data[4:]
	return true
}

type finishedMsg struct {
	raw        []byte
	verifyData []byte
}

func (m *finishedMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}

	var b cryptobyte.Builder
	b.AddUint8(typeFinished)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(m.verifyData)
	})

	m.raw = b.BytesOrPanic()
	return m.raw
}

func (m *finishedMsg) unmarshal(data []byte) bool {
	m.raw = data
	s := cryptobyte.String(data)
	return s.Skip(1) &&
		readUint24LengthPrefixed(&s, &m.verifyData) &&
		s.Empty()
}

type certificateRequestMsg struct {
	raw []byte

	certificateTypes []byte
	//supportedSignatureAlgorithms []SignatureScheme
	certificateAuthorities [][]byte
}

func (m *certificateRequestMsg) marshal() (x []byte) {
	if m.raw != nil {
		return m.raw
	}

	// See RFC 4346, Section 7.4.4.
	length := 1 + len(m.certificateTypes) + 2
	casLength := 0
	for _, ca := range m.certificateAuthorities {
		casLength += 2 + len(ca)
	}
	length += casLength

	x = make([]byte, 4+length)
	x[0] = typeCertificateRequest
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)

	x[4] = uint8(len(m.certificateTypes))

	copy(x[5:], m.certificateTypes)
	y := x[5+len(m.certificateTypes):]

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
	return
}

func (m *certificateRequestMsg) unmarshal(data []byte) bool {
	m.raw = data

	if len(data) < 5 {
		return false
	}

	length := uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	if uint32(len(data))-4 != length {
		return false
	}

	numCertTypes := int(data[4])
	data = data[5:]
	if numCertTypes == 0 || len(data) <= numCertTypes {
		return false
	}

	m.certificateTypes = make([]byte, numCertTypes)
	if copy(m.certificateTypes, data) != numCertTypes {
		return false
	}

	data = data[numCertTypes:]

	if len(data) < 2 {
		return false
	}
	casLength := uint16(data[0])<<8 | uint16(data[1])
	data = data[2:]
	if len(data) < int(casLength) {
		return false
	}
	cas := make([]byte, casLength)
	copy(cas, data)
	data = data[casLength:]

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

	return len(data) == 0
}

type certificateVerifyMsg struct {
	raw       []byte
	signature []byte
}

func (m *certificateVerifyMsg) marshal() (x []byte) {
	if m.raw != nil {
		return m.raw
	}

	var b cryptobyte.Builder
	b.AddUint8(typeCertificateVerify)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(m.signature)
		})
	})

	m.raw = b.BytesOrPanic()
	return m.raw
}

func (m *certificateVerifyMsg) unmarshal(data []byte) bool {
	m.raw = data
	s := cryptobyte.String(data)

	if !s.Skip(4) { // message type and uint24 length field
		return false
	}
	return readUint16LengthPrefixed(&s, &m.signature) && s.Empty()
}

//type helloRequestMsg struct {
//}
//
//func (*helloRequestMsg) marshal() []byte {
//	return []byte{typeHelloRequest, 0, 0, 0}
//}
//
//func (*helloRequestMsg) unmarshal(data []byte) bool {
//	return len(data) == 4
//}
