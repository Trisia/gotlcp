// Copyright (c) 2022 QuanGuanyu
// gotlcp is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package tlcp

import (
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"

	x509 "github.com/emmansun/gmsm/smx509"
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

	// GM/T 0024-2023 6.4.5.2.3 Hello消息扩展字段
	serverName                   string             // 服务器名称
	trustedAuthorities           []TrustedAuthority // 信任的CA证书信息
	ocspStapling                 bool               // 证书状态请求
	supportedCurves              []CurveID          // 支持的椭圆曲线
	supportedSignatureAlgorithms []SignatureScheme  // 支持的签名算法
	alpnProtocols                []string           // 支持的应用层协议
	ibsdhClientID                []byte             // IBSDH密钥交换 客户端标识
}

func (m *clientHelloMsg) marshal() ([]byte, error) {
	if m.raw != nil {
		return m.raw, nil
	}
	var exts cryptobyte.Builder
	if len(m.serverName) > 0 {
		/*
			// GM/T 0024-2023 A.1 SNI服务器名称指示
			struct {
			  ServerName server_name_list<1..2^16-1>
			} ServerNameList;
			struct {
			  NameType name_type;
			  select (name_type) {
			    case host_name: HostName;
			  } name;
			} ServerName;
			enum {
			  host_name(0), (255)
			} NameType;
			opaque HostName<1..2^16-1>;
		*/
		exts.AddUint16(extensionServerName)
		exts.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				// NameType { host_name(0), (255)}
				b.AddUint8(0)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddBytes([]byte(m.serverName))
				})
			})
		})
	}
	if len(m.trustedAuthorities) > 0 {
		// 客户端指定其信任的CA，从服务器端可根据客户端所信任的CA发送服务器证书给客户端。
		/*
			// GM/T 0024-2023 A.2 Trusted CA Indication 信任的CA指示
			struct {
				TrustedAuthority trusted_authority_list<1..2^16-1>;
			} TrustedAuthorities;
			struct {
			    IdentifierType identifier_type;
			    select (identifier_type) {
					case pre_agreed: struct {};
					case key_sm3_hash: SM3Hash;
			        case x509_name: DistinguishedName;
					case cert_sm3_hash: SM3Hash;
			    } identifier;
			} TrustedAuthority;
			enum {
				pre_agreed(0),x509_name(2),key_sm3_hash(4), cert_sm3_hash(5), (255)
			} IdentifierType;

			// 参考 RFC 3546
			opaque SM3Hash[32];
			// DER-encoded X.509 DistinguishedName of the CA.
			opaque DistinguishedName<1..2^16-1>;
		*/
		exts.AddUint16(extensionTrustedCAKeys)
		exts.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				for _, ta := range m.trustedAuthorities {
					b.AddUint8(ta.IdentifierType)
					switch ta.IdentifierType {
					case IdentifierTypePreAgreed:
						// case pre_agreed: struct {};
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
		// GM/T 0024-2023 A.3 OCSP Status Request OCSP状态请求
		/*
				struct {
					CertificateStatusType status_type;
					select (status_type) {
						case ocsp: OCSPStatusRequest;
					} request;
				} CertificateStatusRequest;
				enum { ocsp(1), (255) } CertificateStatusType;

				struct {
					ResponderID responder_id_list<1..2^16-1>;
					Extensions  request_extensions;
				} OCSPStatusRequest;

				opaque ResponderID<1..2^16-1>;
				opaque Extensions<0..2^16-1>;

				// RFC 6960 4.2.1.  ASN.1 Specification of the OCSP Response (ASN.1)
				ResponderID ::= CHOICE {
			      byName               [1] Name,
			      byKey                [2] KeyHash }
				KeyHash ::= OCTET STRING // SHA-1 hash of responder's public key
		*/

		// RFC 4366, Section 3.6
		// ResponderIDs提供了客户机信任的OCSP响应者列表。
		// ResponderIDs 长度为零的序列具有特殊含义，即响应者被服务器隐式地知道，例如，通过事先安排。“Extensions"是OCSP请求扩展的DER编码。
		exts.AddUint16(extensionStatusRequest)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint8(1)  // status_type = ocsp
			exts.AddUint16(0) // empty responder_id_list
			exts.AddUint16(0) // empty request_extensions
		})
	}
	if len(m.supportedCurves) > 0 {
		// GM/T 0024-2023 A.4 Supported Elliptic Curves 支持的椭圆曲线
		/*
			struct {
				NamedCurve curve_list<1..2^16-1>;
			} SupportedEllipticCurves;
			enum {
				deprecated(1..22)
				SM2Curve(41),
				reserved(0xFE00..0xFEFF),
				deprecated(0xFF01..0xFF02),
				(0xFFFF)
			} NamedCurve;
		*/
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
		// GM/T 0024-2023 A.5 Supported Signature Algorithms 签名算法
		/*
			SignatureAndHashAlgorithm  supported_signature_algorithms<1..2^16-1>;
			struct {
				HashAlgorithm hash;
				SignatureAlgorithm signature;
			} SignatureAndHashAlgorithm;
			enum {
				none(0), sha224(3), sha256(4), sha384(5),
				sha512(6), sm3(7), (255)
			} HashAlgorithm;
			enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), sm2(4), (255) }

			// 客户端在使用商用密码算法进行协商时，应发 SignatureAndHashAlgorithm 扩展并指定HashAlgorithm为SM3，
			// 指定SignatureAlgorithm为SM2。 => 0x0704
		*/
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
		// GM/T 0024-2023 A.6 Application-Layer Protocol Negotiation (ALPN) 应用层协议协商
		/*
			struct {
				ProtocolName protocol_name_list<1..2^16-1>;
			} ProtocolNameList;
			opaque ProtocolName<1..2^8-1>;
			// 其中 ProtocolName的定义和IANA保持一致：https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
		*/
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
		// GM/T 0024-2023 A.7 IBSDH Client ID
		/*
			opaque ClientID<1..2^16-1>;
		*/
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

		// GM/T 0024-2023 支持扩展 6.4.5.2.1 Client Hello 消息
		if len(extBytes) > 0 {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(extBytes)
			})
		}
	})

	m.raw, err = b.Bytes()
	return m.raw, err
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

	if s.Empty() {
		// 客户端Hello消息中扩展字段为可选字段，如果没有扩展字段则直接返回
		return true
	}

	// GM/T 0024-2023 6.4.5.2.3 Hello消息扩展字段
	/*
		struct {
			...
			Extension extensions<0..2^16-1>;
		} ClientHello;
	*/
	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return false
	}

	for !extensions.Empty() {
		// 解析扩展字段
		/*
			struct {
				ExtensionType extension_type;
				opaque extension_data<0..2^16-1>;
			} Extension;
			enum {... ,(65535)} ExtensionType;
		*/
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return false
		}

		switch extension {
		case extensionServerName:
			// GM/T 0024-2023 A.1 SNI服务器名称指示
			/*
				struct {
				  ServerName server_name_list<1..2^16-1>
				} ServerNameList;
			*/
			var nameList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&nameList) || nameList.Empty() {
				return false
			}
			for !nameList.Empty() {
				/*
					struct {
					  NameType name_type;
					  select (name_type) {
					    case host_name: HostName;
					  } name;
					} ServerName;
					enum {
					  host_name(0), (255)
					} NameType;
					opaque HostName<1..2^16-1>;
				*/
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
					// 忽略多个SNI，只处理第一个
					continue
				}
				m.serverName = string(serverName)
				// An SNI value may not include a trailing dot.
				if strings.HasSuffix(m.serverName, ".") {
					return false
				}
			}

		case extensionTrustedCAKeys:
			// GM/T 0024-2023 A.2 Trusted CA Indication 信任的CA指示
			/*
				struct {
					TrustedAuthority trusted_authority_list<1..2^16-1>;
				} TrustedAuthorities;
			*/
			var taList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&taList) || taList.Empty() {
				return false
			}
			for !taList.Empty() {
				/*
					struct {
					    IdentifierType identifier_type;
					    select (identifier_type) {
							case pre_agreed: struct {};
							case key_sm3_hash: SM3Hash;
					        case x509_name: DistinguishedName;
							case cert_sm3_hash: SM3Hash;
					    } identifier;
					} TrustedAuthority;
				*/
				var ta TrustedAuthority
				if !taList.ReadUint8(&ta.IdentifierType) {
					return false
				}
				/*
					enum {
						pre_agreed(0),x509_name(2),key_sm3_hash(4), cert_sm3_hash(5), (255)
					} IdentifierType;
				*/
				switch ta.IdentifierType {
				case IdentifierTypePreAgreed:
					// case pre_agreed: struct {};
					ta.Identifier = []byte{}
				case IdentifierTypeKeySM3Hash, IdentifierTypeCertSM3Hash:
					// case key_sm3_hash: SM3Hash;
					// case cert_sm3_hash: SM3Hash;
					//
					// 参考 RFC 3546
					// opaque SM3Hash[32];
					ta.Identifier = make([]byte, 32)
					if !taList.ReadBytes(&ta.Identifier, 32) {
						return false
					}
				case IdentifierTypeX509Name:
					// case x509_name: DistinguishedName;
					//
					// 参考 RFC 3546
					// opaque DistinguishedName<1..2^16-1>;
					if !readUint16LengthPrefixed(&taList, &ta.Identifier) {
						return false
					}
				default:
					// 忽略未知的标识类型
					continue
				}
				m.trustedAuthorities = append(m.trustedAuthorities, ta)
			}

		case extensionStatusRequest:
			// GM/T 0024-2023 A.3 OCSP Status Request OCSP状态请求
			/*
				struct {
					CertificateStatusType status_type;
					select (status_type) {
						case ocsp: OCSPStatusRequest;
					} request;
				} CertificateStatusRequest;
			*/
			var statusType uint8
			var ignored cryptobyte.String
			// 不处理 OCSPStatusRequest
			if !extData.ReadUint8(&statusType) ||
				!extData.ReadUint16LengthPrefixed(&ignored) ||
				!extData.ReadUint16LengthPrefixed(&ignored) {
				return false
			}
			// enum { ocsp(1), (255) } CertificateStatusType;
			m.ocspStapling = statusType == 1

		case extensionSupportedGroups:
			// GM/T 0024-2023 A.4 Supported Elliptic Curves 支持的椭圆曲线
			/*
				struct {
					NamedCurve curve_list<1..2^16-1>;
				} SupportedEllipticCurves;
			*/
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
			// GM/T 0024-2023 A.5 Supported Signature Algorithms 签名算法
			/*
				SignatureAndHashAlgorithm  supported_signature_algorithms<1..2^16-1>;
			*/
			// RFC 5246, Section 7.4.1.4.1
			var sigAndAlgs cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&sigAndAlgs) || sigAndAlgs.Empty() {
				return false
			}
			for !sigAndAlgs.Empty() {
				/*
					struct {
						HashAlgorithm hash; // 8 bits
						SignatureAlgorithm signature; // 8 bits
					} SignatureAndHashAlgorithm;
					enum {
						none(0), sha224(3), sha256(4), sha384(5),
						sha512(6), sm3(7), (255)
					} HashAlgorithm;
					enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), sm2(4), (255) }
				*/
				var sigAndAlg uint16
				if !sigAndAlgs.ReadUint16(&sigAndAlg) {
					return false
				}
				m.supportedSignatureAlgorithms = append(
					m.supportedSignatureAlgorithms, SignatureScheme(sigAndAlg),
				)
			}

		case extensionALPN:
			// GM/T 0024-2023 A.6 Application-Layer Protocol Negotiation (ALPN) 应用层协议协商
			/*
				struct {
					ProtocolName protocol_name_list<1..2^16-1>;
				} ProtocolNameList;
				opaque ProtocolName<1..2^8-1>;
			*/
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
			// GM/T 0024-2023 A.7 IBSDH Client ID
			/*
				opaque ClientID<1..2^16-1>;
			*/
			if !readUint16LengthPrefixed(&extData, &m.ibsdhClientID) {
				return false
			}
		default:
			// Ignore unknown extensions.
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
	s1 := fmt.Sprintf("Random: bytes=%s\nSession ID: %s\nCipher Suites: ", hex.EncodeToString(m.random), hex.EncodeToString(m.sessionId))
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

	// GM/T 0024-2023 扩展字段
	ocspStapling  bool   // 证书状态请求
	ocspResponse  []byte // OCSP应答内容DER，由于GM/T 0024-2023 中没有定义 CertificateStatus 类型握手消息，所以只能通过扩展字段来传递 OCSP 响应。
	alpnProtocol  string // 应用层协议
	serverNameAck bool   // 服务器名称确认，若客户端发送了SNI扩展，服务端找到了对应的证书，则返回该扩展，内容为空
}

func (m *serverHelloMsg) marshal() ([]byte, error) {
	if m.raw != nil {
		return m.raw, nil
	}

	var exts cryptobyte.Builder
	if m.ocspStapling && len(m.ocspResponse) > 0 {
		// GM/T 0024-2023 A.3 OCSP Status Request OCSP状态请求
		/*
			struct {
				CertificateStatusType status_type;
				select (status_type) {
					case ocsp: OCSPStatusResponse;
				} response;
			} CertificateStatusRequest;
			enum { ocsp(1), (255) } CertificateStatusType;
			opaque OCSPStatusResponse<1..2^24-1>;
		*/
		exts.AddUint16(extensionStatusRequest)
		exts.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint8(1) // status_type = ocsp
			b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
				// !!! 由于GM/T 0024-2023 中没有定义 CertificateStatus 类型握手消息，所以只能通过扩展字段来传递 OCSP 响应。
				b.AddBytes(m.ocspResponse)
			})
		})
	}

	if m.alpnProtocol != "" {
		// GM/T 0024-2023 A.6 Application-Layer Protocol Negotiation (ALPN) 应用层协议协商
		/*
			struct {
				ProtocolName protocol_name_list<1..2^16-1>;
			} ProtocolNameList;
			opaque ProtocolName<1..2^8-1>;
		*/
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
		// RFC6066 3. Server Name Indication
		// 若客户端发送了SNI扩展，服务端找到了对应的证书，则返回该扩展，内容为空
		exts.AddUint16(extensionServerName)
		exts.AddUint16(0)
	}

	extBytes, err := exts.Bytes()
	if err != nil {
		return nil, err
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

		// GM/T 0024-2023 支持扩展
		if len(extBytes) > 0 {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(extBytes)
			})
		}
	})
	m.raw, err = b.Bytes()
	return m.raw, err
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

	if s.Empty() {
		// 没有扩展字段
		return true
	}

	// GM/T 0024-2023 扩展字段
	/*
		struct {
			...
			Extension extensions<0..2^16-1>;
		} ServerHello;
	*/
	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return false
	}

	for !extensions.Empty() {
		/*
			struct {
				ExtensionType extension_type;
				opaque extension_data<0..2^16-1>;
			} Extension;
		*/
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return false
		}

		switch extension {
		case extensionStatusRequest:
			// GM/T 0024-2023 A.3 OCSP Status Request OCSP状态请求
			/*
				struct {
					CertificateStatusType status_type;
					select (status_type) {
						case ocsp: OCSPStatusResponse;
					} response;
				} CertificateStatusRequest;
				enum { ocsp(1), (255) } CertificateStatusType;
				opaque OCSPStatusResponse<1..2^24-1>;
			*/
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
			// GM/T 0024-2023 A.6 Application-Layer Protocol Negotiation (ALPN) 应用层协议协商
			/*
				struct {
					ProtocolName protocol_name_list<1..2^16-1>;
				} ProtocolNameList;
				opaque ProtocolName<1..2^8-1>;
			*/
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
			// RFC6066 3. Server Name Indication
			// 若客户端发送了SNI扩展，服务端找到了对应的证书，则返回该扩展，内容为空
			if len(extData) != 0 {
				return false
			}
			m.serverNameAck = true
		default:
			// 忽略未知的扩展字段
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
	return fmt.Sprintf("Random: bytes=%s\nSession ID: %s\nCipher Suite: %v\nCompression Method: %v", hex.EncodeToString(m.random), hex.EncodeToString(m.sessionId), CipherSuiteName(m.cipherSuite), m.compressionMethod)
}

func (m *serverHelloMsg) debug() {
	fmt.Printf(">>> ServerHello\n")
	fmt.Printf("%v\n", m)
	fmt.Printf("<<<\n")
}

type certificateMsg struct {
	raw          []byte
	certificates [][]byte
}

func (m *certificateMsg) marshal() ([]byte, error) {
	if m.raw != nil {
		return m.raw, nil
	}

	var i int
	for _, slice := range m.certificates {
		i += len(slice)
	}

	length := 3 + 3*len(m.certificates) + i
	x := make([]byte, 4+length)
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
	return m.raw, nil
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

type serverKeyExchangeMsg struct {
	raw []byte
	key []byte
}

func (m *serverKeyExchangeMsg) marshal() ([]byte, error) {
	if m.raw != nil {
		return m.raw, nil
	}
	length := len(m.key)
	x := make([]byte, length+4)
	x[0] = typeServerKeyExchange
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	copy(x[4:], m.key)

	m.raw = x
	return x, nil
}

func (m *serverKeyExchangeMsg) unmarshal(data []byte) bool {
	m.raw = data
	if len(data) < 4 {
		return false
	}
	m.key = data[4:]
	return true
}

func (m *serverKeyExchangeMsg) messageType() uint8 {
	return typeServerKeyExchange
}

func (m *serverKeyExchangeMsg) debug() {
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

func (m *serverHelloDoneMsg) marshal() ([]byte, error) {
	x := make([]byte, 4)
	x[0] = typeServerHelloDone
	return x, nil
}

func (m *serverHelloDoneMsg) unmarshal(data []byte) bool {
	return len(data) == 4
}

func (m *serverHelloDoneMsg) messageType() uint8 {
	return typeServerHelloDone
}

func (m *serverHelloDoneMsg) debug() {
}

type clientKeyExchangeMsg struct {
	raw        []byte
	ciphertext []byte
}

func (m *clientKeyExchangeMsg) marshal() ([]byte, error) {
	if m.raw != nil {
		return m.raw, nil
	}
	length := len(m.ciphertext)
	x := make([]byte, length+4)
	x[0] = typeClientKeyExchange
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	copy(x[4:], m.ciphertext)

	m.raw = x
	return x, nil
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

func (m *clientKeyExchangeMsg) messageType() uint8 {
	return typeClientKeyExchange
}

func (m *clientKeyExchangeMsg) debug() {
}

type finishedMsg struct {
	raw        []byte
	verifyData []byte
}

func (m *finishedMsg) marshal() ([]byte, error) {
	if m.raw != nil {
		return m.raw, nil
	}

	var b cryptobyte.Builder
	b.AddUint8(typeFinished)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(m.verifyData)
	})

	var err error
	m.raw, err = b.Bytes()
	return m.raw, err
}

func (m *finishedMsg) unmarshal(data []byte) bool {
	m.raw = data
	s := cryptobyte.String(data)
	return s.Skip(1) &&
		readUint24LengthPrefixed(&s, &m.verifyData) &&
		s.Empty()
}

func (m *finishedMsg) messageType() uint8 {
	return typeFinished
}

func (m *finishedMsg) debug() {
	fmt.Printf(">>> Finished\n")
	fmt.Printf("verify_data: %v\n", m.verifyData)
	fmt.Printf("<<<\n")
}

type certificateRequestMsg struct {
	raw []byte

	certificateTypes []byte
	//supportedSignatureAlgorithms []SignatureScheme
	certificateAuthorities [][]byte
}

func (m *certificateRequestMsg) marshal() ([]byte, error) {
	if m.raw != nil {
		return m.raw, nil
	}

	// See RFC 4346, Section 7.4.4.
	length := 1 + len(m.certificateTypes) + 2
	casLength := 0
	for _, ca := range m.certificateAuthorities {
		casLength += 2 + len(ca)
	}
	length += casLength

	x := make([]byte, 4+length)
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
	return x, nil
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

type certificateVerifyMsg struct {
	raw       []byte
	signature []byte
}

func (m *certificateVerifyMsg) marshal() ([]byte, error) {
	if m.raw != nil {
		return m.raw, nil
	}

	var b cryptobyte.Builder
	b.AddUint8(typeCertificateVerify)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(m.signature)
		})
	})
	var err error
	m.raw, err = b.Bytes()
	return m.raw, err
}

func (m *certificateVerifyMsg) unmarshal(data []byte) bool {
	m.raw = data
	s := cryptobyte.String(data)

	if !s.Skip(4) { // message type and uint24 length field
		return false
	}
	return readUint16LengthPrefixed(&s, &m.signature) && s.Empty()
}

func (m *certificateVerifyMsg) messageType() uint8 {
	return typeCertificateVerify
}

func (m *certificateVerifyMsg) debug() {
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

type transcriptHash interface {
	Write([]byte) (int, error)
}

// transcriptMsg is a helper used to marshal and hash messages which typically
// are not written to the wire, and as such aren't hashed during Conn.writeRecord.
func transcriptMsg(msg handshakeMessage, h transcriptHash) error {
	data, err := msg.marshal()
	if err != nil {
		return err
	}
	h.Write(data)
	return nil
}
