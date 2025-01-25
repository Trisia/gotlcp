// Copyright (c) 2022 Quan Guanyu
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
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	x509 "github.com/emmansun/gmsm/smx509"
)

const (
	VersionTLCP = 0x0101 // GM/T 38636-2016
)

const (
	maxPlaintext      = 16384        // maximum plaintext payload length
	maxCiphertext     = 16384 + 2048 // maximum ciphertext payload length
	recordHeaderLen   = 5            // record header length
	maxHandshake      = 65536        // maximum handshake we support (protocol max is 16 MB)
	maxUselessRecords = 16           // maximum number of consecutive non-advancing records
)

// TLCP record 类型
type recordType uint8

// TLCP GB/T 38636-2016 6.3.3.2 a) Type
const (
	recordTypeChangeCipherSpec recordType = 20
	recordTypeAlert            recordType = 21
	recordTypeHandshake        recordType = 22
	recordTypeApplicationData  recordType = 23
)

// TLCP GB/T 38636-2016 6.4.5.1 握手消息类型定义
const (
	typeClientHello        uint8 = 1
	typeServerHello        uint8 = 2
	typeCertificate        uint8 = 11
	typeServerKeyExchange  uint8 = 12
	typeCertificateRequest uint8 = 13
	typeServerHelloDone    uint8 = 14
	typeCertificateVerify  uint8 = 15
	typeClientKeyExchange  uint8 = 16
	typeFinished           uint8 = 20
)

func HandshakeMessageTypeName(id uint8) string {
	switch id {
	case typeClientHello:
		return "Client Hello"
	case typeServerHello:
		return "Server Hello"
	case typeCertificate:
		return "Certificate"
	case typeServerKeyExchange:
		return "Server Key Exchange"
	case typeCertificateRequest:
		return "Certificate Request"
	case typeServerHelloDone:
		return "Server Hello Done"
	case typeCertificateVerify:
		return "Certificate Verify"
	case typeClientKeyExchange:
		return "Client Key Exchange"
	case typeFinished:
		return "Finished"
	}
	return fmt.Sprintf("0x%02X", id)
}

// GM/T0024-2023 6.4.5.2.3 Hello 消息扩展字段 a)
const (
	extensionServerName                          uint16 = 0  // SNI服务器名称指示
	extensionTrustedCAKeys                       uint16 = 3  // Trusted CA indication受信任的CA指示
	extensionStatusRequest                       uint16 = 5  // Certificate Status Request证书状态请求
	extensionSupportedGroups                     uint16 = 10 // Supported Elliptic Curves支持的椭圆曲线
	extensionSupportedCurves                     uint16 = 10 // Supported Elliptic Curves支持的椭圆曲线
	extensionSignatureAlgorithm                  uint16 = 13 // Signature Algorithms签名算法
	extensionSignatureAlgorithms                 uint16 = 13 // Signature Algorithms签名算法
	extensionALPN                                uint16 = 16 // Application-Layer Protocol Negotiation应用层协议协商
	extensionApplicationLayerProtocolNegotiation uint16 = 16 // Application-Layer Protocol Negotiation应用层协议协商
	extensionClientID                            uint16 = 66 // Client ID客户端标识
)

// GM/T0024-2023 A.2 Trusted CA indication受信任的CA指示
const (
	IdentifierTypePreAgreed   uint8 = 0 // Pre-agreed预先协商
	IdentifierTypeX509Name    uint8 = 2 // X.509证书名称
	IdentifierTypeKeySM3Hash  uint8 = 4 // 密钥SM3哈希
	IdentifierTypeCertSM3Hash uint8 = 5 // 证书SM3哈希
)

// TrustedAuthority GM/T0024-2023  A.2 Trusted CA indication受信任的CA指示 结构
//
//	struct {
//	    IdentifierType identifier_type;
//	    select (identifier_type) {
//			case pre_agreed: struct {};
//			case key_sm3_hash: SM3Hash;
//	        case x509_name: DistinguishedName;
//			case cert_sm3_hash: SM3Hash;
//	    } identifier;
//	} TrustedAuthority;
//	enum {
//		pre_agreed(0),x509_name(2),key_sm3_hash(4), cert_sm3_hash(5), (255)
//	} IdentifierType;
//
//	// 参考 RFC 3546
//	opaque SM3Hash[32];
//	// DER-encoded X.509 DistinguishedName of the CA.
//	opaque DistinguishedName<1..2^16-1>;
type TrustedAuthority struct {
	IdentifierType uint8  // 证书标识类型
	Identifier     []byte // 证书标识
}

// TLCP 压缩类型
const (
	compressionNone uint8 = 0
)

// CurveID 命名曲线ID，ID由 IANA分配，详见
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-8.
type CurveID uint16

const (
	// CurveSM2 命名曲线ID  见 RFC 8998 第2章
	// https://www.rfc-editor.org/rfc/rfc8998.html
	CurveSM2 CurveID = 41
)

// SignatureScheme GM/T 0024-2023 A.5 Signature Algorithms签名算法
//
//	struct {
//		HashAlgorithm hash;
//		SignatureAlgorithm signature;
//	} SignatureAndHashAlgorithm;
//	enum {
//		none(0), sha224(3), sha256(4), sha384(5),
//		sha512(6), sm3(7), (255)
//	} HashAlgorithm;
//	enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), sm2(4), (255) }
type SignatureScheme uint16

func (s SignatureScheme) String() string {
	switch s {
	case SM2WithSM3:
		return "SM2WithSM3"
	default:
		return "SignatureScheme(" + strconv.FormatInt(int64(s), 10) + ")"
	}
}

const (
	// SM2WithSM3 指定HashAlgorithm为SM3，指定SignatureAlgorithm为SM2。 => 0x0704
	SM2WithSM3 SignatureScheme = 0x0704
)

// Certificate types (for certificateRequestMsg)
// 见 GB/T 38636-2016 6.4.5.5 a) certificate_types
const (
	certTypeRSASign   = 1
	certTypeECDSASign = 64 // ECDSA or EdDSA keys, see RFC 8422, Section 3.
	certTypeIbcParams = 80
)

// ConnectionState 关于TLCP连接的详细信息
type ConnectionState struct {
	// Version 连接的TLCP协议版本号
	Version uint16

	// HandshakeComplete true 表示完成握手
	HandshakeComplete bool

	// DidResume true 表示这个连接是从之前的会话中重用了会话密钥
	DidResume bool

	// CipherSuite 该连接所使用的密码套件ID
	CipherSuite uint16

	// NegotiatedProtocol 协商出的应用层协议
	NegotiatedProtocol string

	// ServerName 服务端端名称
	ServerName string

	// PeerCertificates 对端数字证书对象
	//
	// 在客户端侧，改参数不会为空，表示服务端的签名证书和加密证书
	// 在服务端侧，若  Config.ClientAuth 不为 RequireAnyClientCert 或 RequireAndVerifyClientCert 那么则可能为空。
	PeerCertificates []*x509.Certificate

	// VerifiedChains 验证对端证书的证书链
	//
	// 在客户端侧证书链中的证书来自于 Config.RootCAs
	// 在服务端侧证书链中的证书来自于 Config.ClientCAs
	//
	// 若启用了 Config.InsecureSkipVerify 参数则不会存在改参数。
	VerifiedChains [][]*x509.Certificate
}

// ClientAuthType 服务端对客户单的认证策略，用于客户端身份认证配置
type ClientAuthType int

const (
	// NoClientCert indicates that no client certificate should be requested
	// during the handshake, and if any certificates are sent they will not
	// be verified.
	NoClientCert ClientAuthType = iota
	// RequestClientCert indicates that a client certificate should be requested
	// during the handshake, but does not require that the client send any
	// certificates.
	RequestClientCert
	// RequireAnyClientCert indicates that a client certificate should be requested
	// during the handshake, and that at least one certificate is required to be
	// sent by the client, but that certificate is not required to be valid.
	RequireAnyClientCert
	// VerifyClientCertIfGiven indicates that a client certificate should be requested
	// during the handshake, but does not require that the client sends a
	// certificate. If the client does send a certificate it is required to be
	// valid.
	VerifyClientCertIfGiven
	// RequireAndVerifyClientCert indicates that a client certificate should be requested
	// during the handshake, and that at least one valid certificate is required
	// to be sent by the client.
	RequireAndVerifyClientCert
	// RequireAndVerifyAnyKeyUsageClientCert 要求客户端提供客户端数字证书，并且验证数字证书，但是忽略客户端数字证书的密钥用法。
	RequireAndVerifyAnyKeyUsageClientCert
)

// requiresClientCert 判断 ClientAuthType 是否需要客户端提供客户端证书
func requiresClientCert(c ClientAuthType) bool {
	switch c {
	case RequireAnyClientCert, RequireAndVerifyClientCert, RequireAndVerifyAnyKeyUsageClientCert:
		return true
	default:
		return false
	}
}

// ClientHelloInfo contains information from a ClientHello message in order to
// guide application logic in the GetCertificate and GetConfigForClient callbacks.
type ClientHelloInfo struct {

	// CipherSuites 客户端支持的密码套件ID列表
	CipherSuites []uint16

	// ServerName 客户端扩展中SNI指定的服务端名称，可以用于实现虚拟机主机。
	ServerName string

	// SupportedVersions 客户端支持的TLCP版本，目前只有 0x0101
	SupportedVersions []uint16

	// TrustedCAIndications 客户端信任的CA列表
	// 注意该参数为可选参数，在客户端发送TrustedAuthority扩展字段时才会存在。
	// 服务端可以使用该参数选择合适的证书，做到证书的动态选择。
	TrustedCAIndications []TrustedAuthority

	// Conn 底层连接对象，请不要读写该对象，否则会导致TLCP连接异常
	Conn net.Conn

	// config TLCP配置参数
	config *Config

	// ctx 握手过程中的上下文
	ctx context.Context
}

// Context 返回握手过程中的上下文
func (c *ClientHelloInfo) Context() context.Context {
	return c.ctx
}

// CertificateRequestInfo 服务端的证书请求信息
type CertificateRequestInfo struct {

	// AcceptableCAs 包含0或多个的 DER编码的 X.509 DN名称
	// 这些DN名称来自于服务端信任的根证书列表，客户端应根据这些DN名称选择合适的数字证书
	AcceptableCAs [][]byte

	// Version TLCP协议版本
	Version uint16

	// ctx 握手过程中的上下文
	ctx context.Context
}

// Context 返回握手过程中的上下文
func (c *CertificateRequestInfo) Context() context.Context {
	return c.ctx
}

// Config TLCP配置对象，用于配置TLCP客户端或服务端，一旦该参数被TLCP使用，那么
// 该参数内部的值不应在改变。
//
// Config 根据情况可以复用。
type Config struct {
	// Rand 外部随机源，若不配置则默认使用 crypto/rand 作为随机源
	// 随机源必须线程安全，能够被多goroutines访问。
	Rand io.Reader

	// Time 外部时间源，返回当前的时间
	Time func() time.Time

	// Certificates TLCP握手过程中的证书密钥对，数组中每一个元素表示一对密钥以及一张证书
	//
	// TLCP协议中服务端需要2对密钥对，1对签名密钥对和签名证书、1对加密密钥对和加密证书，
	// TLCP协议中客户端在需要身份认证的场景下也需要1对签名密钥对和签名证书。
	//
	// 服务端：至少2对密钥对和证书，按照顺序[签名密钥对, 加密密钥对]
	// 客户端：若不需要客户端身份认证则可以为空，否则至少1对密钥对。
	//
	// 特别的也可以使用动态方法获取证书，使该参数为空
	// 服务端需实现： GetCertificate GetKECertificate
	// 客户端需实现： GetClientCertificate
	Certificates []Certificate

	// GetCertificate 仅在 Certificates 为空时，
	// 基于客户端Hello消息返还密钥对和证书
	GetCertificate func(*ClientHelloInfo) (*Certificate, error)

	// GetKECertificate 获取密钥交换证书（加密证书）
	// 这个方法只有在使用Config中Certificates为空或长度小于2时，才会被调用。
	// 如果该方法为空，则默认从证书列表中 Certificates 取出第二个位置的证书，也就是加密证书。
	// 该方法只有TLCP流程中才会调用。
	GetKECertificate func(*ClientHelloInfo) (*Certificate, error)

	// GetClientCertificate 根据服务端的证书请求消息，返回客户端用于认证的密钥和证书
	//
	// 如果 GetClientCertificate 返回空那么连接将会被中断，因此即便没有证书和密钥对
	// 也需要返回一个空的 Certificate 对象，这样客户端可以发送一个空的证书消息给服务端。
	GetClientCertificate func(*CertificateRequestInfo) (*Certificate, error)

	// GetClientKECertificate 根据服务端的证书请求消息，返回客户端用于密钥交换的密钥和证书
	// 如果客户端想要支持ECDHE，就必须要同时提供签名和加密证书。
	GetClientKECertificate func(*CertificateRequestInfo) (*Certificate, error)

	// GetConfigForClient 【可选】 根据客户端Hello消息，生成TLCP配置对象
	// 如果该方法不为空，将会在接受到客户端的 ClientHello 消息后调用。
	//
	// 通过该方法你可以在针对该次连接生成自定义的配置对象来完成特殊的应用需要。
	GetConfigForClient func(*ClientHelloInfo) (*Config, error)

	// VerifyPeerCertificate 【可选】 验证对端证书
	// 若改参数不为空，将会在客户端或服务端的证书验证结束阶段后被调用。
	//
	// 该方法接收 rawCerts 对端发来的 原始的 ASN.1（DER） 的证书序列
	// 以及 verifiedChains 验证该证书相关的根证书链序列
	//
	// InsecureSkipVerify 与 ClientAuth 参数不会影响该函数运行。
	VerifyPeerCertificate func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error

	// VerifyConnection 【可选】如果该方法不会空，那么将会在证书验证完成后，
	// 如果 VerifyPeerCertificate 存在则会在其后运行
	// 在该方法中您可以对连接上下文中的相关参数进行校验 如提取对端数字证书信息、所使用的密码套件等。
	//
	// 如果该方法返回值不为空，将会终止握手。
	//
	// InsecureSkipVerify 与 ClientAuth 的设置不会影响该方法的运行。
	VerifyConnection func(ConnectionState) error

	// RootCAs 根证书列表，客户端使用该列表的证书验证服务端证书是否有效
	// 如果这个字段为空，则使用主机上的根证书集合（从操作系统中加载）
	RootCAs *x509.CertPool

	// NextProtos 支持的应用层协议列表。
	// 列表中的顺序代表支持协议的优先级索引越小越优先。
	// 如果对端也支持ALPN，对端将会发送ALPN扩展，并从支持列表中选择出一个协议。
	// 但是若对端不支持ALPN中的协议，将会导致连接失败。
	// 若双方中任意一方 NextProtos 为空则表示不进行协议选择，连接将不会收到影响。
	// 在协商成功后可以在 ConnectionState.NegotiatedProtocol 中获取到协商的协议。
	NextProtos []string

	// ServerName 【可选】如果不为空，则强制校验证书中的DNS或IP是否存在。
	// 用于验证主机名与数字证书中的主机名是否匹配
	// 如果 InsecureSkipVerify 为 true 则跳过该验证
	ServerName string

	// ClientAuth 服务端对客户端身份认证策略
	// 默认值为 NoClientCert 不验证客户端身份
	ClientAuth ClientAuthType

	// ClientCAs 服务端侧根证书列表，这些根证书将用于验证客户端证书消息中的证书
	// 客户端证书的验证策略由  ClientAuth 参数配置。
	ClientCAs *x509.CertPool

	// InsecureSkipVerify 用于控制客户端是否跳过 服务端的证书有效性 和 证书与主机名 的匹配。
	//
	// 如果 InsecureSkipVerify 参数为 true，那么客户端不对服务端证书做任何验证，注意在这种模式下
	// TLCP容易受到中间人攻击，这个配置仅用于测试。
	//
	// 若您配置了 VerifyConnection 或 VerifyPeerCertificate 可以根据情况设置该参数为 true
	InsecureSkipVerify bool

	// CipherSuites 密码套件ID列表，用于手动指定在握手过程中的密码套件
	// 数组约靠前的密码套件优先级越高。
	//
	// 如果 CipherSuites 为 nil，那么使用默认的算法套件列表进行握手。
	CipherSuites []uint16

	// SessionCache 会话状态缓存，用于连接重用
	//
	// 若需要开启服务端或客户端的重用握手流程，则请配置该参数。
	// 若无特殊缓存需要可采用默认的 NewLRUSessionCache 实现会话缓存
	SessionCache SessionCache

	// MinVersion 最低支持的TLCP协议版本，目前TLCP只有一个版本
	MinVersion uint16

	// MaxVersion 最高支持的TLCP协议版本，目前TLCP只有一个版本
	MaxVersion uint16

	// CurvePreferences 椭圆曲线ID列表，用于指定客户端和服务端支持的椭圆曲线
	CurvePreferences []CurveID

	// DynamicRecordSizingDisabled disables adaptive sizing of TLS records.
	// When true, the largest possible TLS record size is always used. When
	// false, the size of TLS records may be adjusted in an attempt to
	// improve latency.
	DynamicRecordSizingDisabled bool

	// OnAlert 在发生报警时回调该方法，在该方法内请不要执行耗时操作！
	OnAlert func(code uint8, conn *Conn)

	// mutex protects sessionTicketKeys and autoSessionTicketKeys.
	mutex sync.RWMutex

	// EnableDebug, 是否打开debug
	EnableDebug bool

	// ClientECDHEParamAsVector, 把ClientECDHEParams当作structure还是变长向量。
	// 这个配置用于客户端使用ECDHE密码套件时与其他实现进行兼容，如果你在进行ECDHE密码套件的集成测试时失败，可以尝试配置这个变量。
	// 默认当作structure，起始无两字节长度。
	ClientECDHEParamsAsVector bool

	// TrustedCAIndications 授信CA指示 Trusted CA Indications
	// 该参数仅客户端使用，用于指定客户端信任的CA列表，ClientHello 扩展字段的方式发送。
	// 服务端可选的从该列表中选择一张匹配的证书，以证书消息的方式发送。
	// 注意：在GoTLCP默认不会使用该参数！
	// 若需要在服务端识别并且使用该参数，请实现 GetCertificate 与 GetKECertificate 方法，
	// 从 ClientHelloInfo 中获取扩展字段，然后根据扩展字段选择合适的证书。
	TrustedCAIndications []TrustedAuthority
}

// Clone 复制一个新的连接配置对象
// 复制配置信息时，您任然可以客户端或服务器同时使用 Config 对象。
func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return &Config{
		Rand:                        c.Rand,
		Time:                        c.Time,
		Certificates:                c.Certificates,
		GetCertificate:              c.GetCertificate,
		GetKECertificate:            c.GetKECertificate,
		GetClientCertificate:        c.GetClientCertificate,
		GetClientKECertificate:      c.GetClientKECertificate,
		GetConfigForClient:          c.GetConfigForClient,
		VerifyPeerCertificate:       c.VerifyPeerCertificate,
		VerifyConnection:            c.VerifyConnection,
		RootCAs:                     c.RootCAs,
		NextProtos:                  c.NextProtos,
		ServerName:                  c.ServerName,
		ClientECDHEParamsAsVector:   c.ClientECDHEParamsAsVector,
		ClientAuth:                  c.ClientAuth,
		ClientCAs:                   c.ClientCAs,
		InsecureSkipVerify:          c.InsecureSkipVerify,
		CipherSuites:                c.CipherSuites,
		SessionCache:                c.SessionCache,
		MinVersion:                  c.MinVersion,
		MaxVersion:                  c.MaxVersion,
		CurvePreferences:            c.CurvePreferences,
		DynamicRecordSizingDisabled: c.DynamicRecordSizingDisabled,
		OnAlert:                     c.OnAlert,
		EnableDebug:                 c.EnableDebug,
		TrustedCAIndications:        c.TrustedCAIndications,
	}
}

func (c *Config) rand() io.Reader {
	r := c.Rand
	if r == nil {
		return rand.Reader
	}
	return r
}

func (c *Config) time() time.Time {
	t := c.Time
	if t == nil {
		t = time.Now
	}
	return t()
}

func (c *Config) cipherSuites() []uint16 {
	if c.CipherSuites != nil {
		return c.CipherSuites
	}
	return defaultCipherSuites
}

// 支持的协议版本列表
var supportedVersions = []uint16{
	VersionTLCP,
}

// roleClient and roleServer are meant to call supportedVersions and parents
// with more readability at the callsite.
const roleClient = true
const roleServer = false

func (c *Config) supportedVersions(isClient bool) []uint16 {
	versions := make([]uint16, 0, len(supportedVersions))
	for _, v := range supportedVersions {
		if c != nil && c.MinVersion != 0 && v < c.MinVersion {
			continue
		}
		if c != nil && c.MaxVersion != 0 && v > c.MaxVersion {
			continue
		}
		versions = append(versions, v)
	}
	return versions
}

func (c *Config) maxSupportedVersion(isClient bool) uint16 {
	supportedVersions := c.supportedVersions(isClient)
	if len(supportedVersions) == 0 {
		return 0
	}
	return supportedVersions[0]
}

// supportedVersionsFromMax 返回最大支持的TLCP协议版本号列表
func supportedVersionsFromMax(maxVersion uint16) []uint16 {
	versions := make([]uint16, 0, len(supportedVersions))
	// 不支持TLS 以及 SSL协议版本号
	if (maxVersion & 0xFF00) == 0x0300 {
		return versions
	}
	for _, v := range supportedVersions {
		if v > maxVersion {
			continue
		}
		versions = append(versions, v)
	}
	return versions
}

// mutualVersion returns the protocol version to use given the advertised
// versions of the peer. Priority is given to the peer preference order.
func (c *Config) mutualVersion(isClient bool, peerVersions []uint16) (uint16, bool) {
	supportedVersions := c.supportedVersions(isClient)
	for _, peerVersion := range peerVersions {
		for _, v := range supportedVersions {
			if v == peerVersion {
				return v, true
			}
		}
	}
	return 0, false
}

var errNoCertificates = errors.New("tlcp: no certificates configured")

// getCertificate 根据 客户端Hello消息中的信息选择最佳的数字证书
// 默认返还 Config.Certificates[0] 的数字证书
func (c *Config) getCertificate(clientHello *ClientHelloInfo) (*Certificate, error) {
	if c.GetCertificate != nil && len(c.Certificates) == 0 {
		cert, err := c.GetCertificate(clientHello)
		if cert != nil || err != nil {
			return cert, err
		}
	}

	if len(c.Certificates) == 0 {
		return nil, errNoCertificates
	}

	//
	// 域名证书主机名验证交由证书验证阶段完成
	//
	// 如果服务端名称不为空，那么验证证书是否匹配
	//if clientHello.ServerName != "" {
	//	err := c.Certificates[0].Leaf.VerifyHostname(clientHello.ServerName)
	//	if err != nil {
	//		return nil, errNoCertificates
	//	}
	//}

	return &c.Certificates[0], nil
}

// getCertificate 返回密钥交换使用的证书及密钥
// 该方法只有GMSSL会调用
// 如果 Certificates 长度大于等于2时，默认返回第2个证书密钥
// 如果 Certificates 为空或不足2时，调用 GetEKCertificate 方法获取。
func (c *Config) getEKCertificate(clientHello *ClientHelloInfo) (*Certificate, error) {
	if c.GetKECertificate != nil && (len(c.Certificates) < 2) {
		cert, err := c.GetKECertificate(clientHello)
		if cert != nil || err != nil {
			return cert, err
		}
	}
	if len(c.Certificates) < 2 {
		return nil, errNoCertificates
	}
	return &c.Certificates[1], nil
}

// SupportsCertificate returns nil if the provided certificate is supported by
// the server that sent the CertificateRequest. Otherwise, it returns an error
// describing the reason for the incompatibility.
func (cri *CertificateRequestInfo) SupportsCertificate(c *Certificate) error {
	if len(cri.AcceptableCAs) == 0 {
		return nil
	}

	for j, cert := range c.Certificate {
		x509Cert := c.Leaf
		// Parse the certificate if this isn't the leaf node, or if
		// chain.Leaf was nil.
		if j != 0 || x509Cert == nil {
			var err error
			if x509Cert, err = x509.ParseCertificate(cert); err != nil {
				return fmt.Errorf("failed to parse certificate #%d in the chain: %w", j, err)
			}
		}

		for _, ca := range cri.AcceptableCAs {
			if bytes.Equal(x509Cert.RawIssuer, ca) {
				return nil
			}
		}
	}
	return errors.New("chain is not signed by an acceptable CA")
}

// Certificate 密钥对以及相关的数字证书
type Certificate struct {
	// Certificate DER编码的X.509数字证书，在TLCP协议中该数组只会存在1张证书。（无证书链）
	// Certificate 中的元素可以使用 smx509.ParseCertificate 方法解析为 *smx509.Certificate
	Certificate [][]byte

	// PrivateKey 私钥实现，根据密钥用法的不同
	// 签名密钥对需要实现 crypto.Signer 接口
	// 加密密钥对需要实现 crypto.Decrypter 接口
	PrivateKey crypto.PrivateKey

	// OCSPStaple 包含一个可选的OCSP响应，该响应将提供给含OCSP请求扩展的客户端
	OCSPStaple []byte

	// Leaf 握手x509证书对象，默认为空
	//
	// 可以通过 smx509.ParseCertificate 解析 Certificate.Certificate 中的第一个元素解析设置，
	// 通过该种方式可以减少在握手环节的证书解析的时间。
	Leaf *x509.Certificate
}

// leaf 返还 Certificate.Certificate[0] 的解析结果。
func (c *Certificate) leaf() (*x509.Certificate, error) {
	if c.Leaf != nil {
		return c.Leaf, nil
	}
	return x509.ParseCertificate(c.Certificate[0])
}

type handshakeMessage interface {
	marshal() ([]byte, error)
	unmarshal([]byte) bool
	messageType() uint8
	debug()
}

// emptyConfig 默认的空配置对象
var emptyConfig Config

// 返回默认的空配置对象
func defaultConfig() *Config {
	return &emptyConfig
}

func unexpectedMessageError(wanted, got interface{}) error {
	return fmt.Errorf("tlcp: received unexpected handshake message of type %T when waiting for %T", got, wanted)
}

// CertificateVerificationError is returned when certificate verification fails during the handshake.
type CertificateVerificationError struct {
	// UnverifiedCertificates and its contents should not be modified.
	UnverifiedCertificates []*x509.Certificate
	Err                    error
}

func (e *CertificateVerificationError) Error() string {
	return fmt.Sprintf("tlcp: failed to verify certificate: %s", e.Err)
}

func (e *CertificateVerificationError) Unwrap() error {
	return e.Err
}
