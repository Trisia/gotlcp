// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tlcp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	x509 "github.com/emmansun/gmsm/smx509"
	"io"
	"net"
	"sync"
	"time"
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

// TLCP record types.
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

// TLCP compression types.
const (
	compressionNone uint8 = 0
)

// CurveID is the type of a TLS identifier for an elliptic curve. See
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-8.
//
// In TLS 1.3, this type is called NamedGroup, but at this time this library
// only supports Elliptic Curve based groups. See RFC 8446, Section 4.2.7.
type CurveID uint16

const (
	CurveP256 CurveID = 23
	CurveP384 CurveID = 24
	CurveP521 CurveID = 25
	X25519    CurveID = 29
)

// TLS Elliptic Curve Point Formats
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-9
const (
	pointFormatUncompressed uint8 = 0
)

// Certificate types (for certificateRequestMsg)
// 见 GB/T 38636-2016 6.4.5.5 a) certificate_types
const (
	certTypeRSASign   = 1
	certTypeECDSASign = 64 // ECDSA or EdDSA keys, see RFC 8422, Section 3.
	certTypeIbcParams = 80 //
)

// ConnectionState records basic TLS details about the connection.
type ConnectionState struct {
	// Version is the TLS version used by the connection (e.g. VersionTLS12).
	Version uint16

	// HandshakeComplete is true if the handshake has concluded.
	HandshakeComplete bool

	// DidResume is true if this connection was successfully resumed from a
	// previous session with a session ticket or similar mechanism.
	DidResume bool

	// CipherSuite is the cipher suite negotiated for the connection (e.g.
	// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_AES_128_GCM_SHA256).
	CipherSuite uint16

	//// NegotiatedProtocol is the application protocol negotiated with ALPN.
	//NegotiatedProtocol string

	// ServerName is the value of the Server Name Indication extension sent by
	// the client. It's available both on the server and on the client side.
	ServerName string

	// PeerCertificates are the parsed certificates sent by the peer, in the
	// order in which they were sent. The first element is the leaf certificate
	// that the connection is verified against.
	//
	// On the client side, it can't be empty. On the server side, it can be
	// empty if Config.ClientAuth is not RequireAnyClientCert or
	// RequireAndVerifyClientCert.
	PeerCertificates []*x509.Certificate

	// VerifiedChains is a list of one or more chains where the first element is
	// PeerCertificates[0] and the last element is from Config.RootCAs (on the
	// client side) or Config.ClientCAs (on the server side).
	//
	// On the client side, it's set if Config.InsecureSkipVerify is false. On
	// the server side, it's set if Config.ClientAuth is VerifyClientCertIfGiven
	// (and the peer provided a certificate) or RequireAndVerifyClientCert.
	VerifiedChains [][]*x509.Certificate
}

// ClientAuthType declares the policy the server will follow for
// TLCP Client Authentication.
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
)

// requiresClientCert reports whether the ClientAuthType requires a client
// certificate to be provided.
func requiresClientCert(c ClientAuthType) bool {
	switch c {
	case RequireAnyClientCert, RequireAndVerifyClientCert:
		return true
	default:
		return false
	}
}

// ClientHelloInfo contains information from a ClientHello message in order to
// guide application logic in the GetCertificate and GetConfigForClient callbacks.
type ClientHelloInfo struct {
	// CipherSuites lists the CipherSuites supported by the client (e.g.
	// TLS_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256).
	CipherSuites []uint16

	// ServerName indicates the name of the server requested by the client
	// in order to support virtual hosting. ServerName is only set if the
	// client is using SNI (see RFC 4366, Section 3.1).
	ServerName string

	//// SupportedCurves lists the elliptic curves supported by the client.
	//// SupportedCurves is set only if the Supported Elliptic Curves
	//// Extension is being used (see RFC 4492, Section 5.1.1).
	//SupportedCurves []CurveID

	//// SupportedPoints lists the point formats supported by the client.
	//// SupportedPoints is set only if the Supported Point Formats Extension
	//// is being used (see RFC 4492, Section 5.1.2).
	//SupportedPoints []uint8

	//// SignatureSchemes lists the signature and hash schemes that the client
	//// is willing to verify. SignatureSchemes is set only if the Signature
	//// Algorithms Extension is being used (see RFC 5246, Section 7.4.1.4.1).
	//SignatureSchemes []SignatureScheme

	//// SupportedProtos lists the application protocols supported by the client.
	//// SupportedProtos is set only if the Application-Layer Protocol
	//// Negotiation Extension is being used (see RFC 7301, Section 3.1).
	////
	//// Servers can select a protocol by setting Config.NextProtos in a
	//// GetConfigForClient return value.
	//SupportedProtos []string

	// SupportedVersions lists the TLCP versions supported by the client.
	// For TLCP versions less than 1.3, this is extrapolated from the max
	// version advertised by the client, so values other than the greatest
	// might be rejected if used.
	SupportedVersions []uint16

	// Conn is the underlying net.Conn for the connection. Do not read
	// from, or write to, this connection; that will cause the TLCP
	// connection to fail.
	Conn net.Conn

	// config is embedded by the GetCertificate or GetConfigForClient caller,
	// for use with SupportsCertificate.
	config *Config

	// ctx is the context of the handshake that is in progress.
	ctx context.Context
}

// Context returns the context of the handshake that is in progress.
// This context is a child of the context passed to HandshakeContext,
// if any, and is canceled when the handshake concludes.
func (c *ClientHelloInfo) Context() context.Context {
	return c.ctx
}

// CertificateRequestInfo contains information from a server's
// CertificateRequest message, which is used to demand a certificate and proof
// of control from a client.
type CertificateRequestInfo struct {
	// AcceptableCAs contains zero or more, DER-encoded, X.501
	// Distinguished Names. These are the names of root or intermediate CAs
	// that the server wishes the returned certificate to be signed by. An
	// empty slice indicates that the server has no preference.
	AcceptableCAs [][]byte

	//// SignatureSchemes lists the signature schemes that the server is
	//// willing to verify.
	//SignatureSchemes []SignatureScheme

	// Version is the TLCP version that was negotiated for this connection.
	Version uint16

	// ctx is the context of the handshake that is in progress.
	ctx context.Context
}

// Context returns the context of the handshake that is in progress.
// This context is a child of the context passed to HandshakeContext,
// if any, and is canceled when the handshake concludes.
func (c *CertificateRequestInfo) Context() context.Context {
	return c.ctx
}

// A Config structure is used to configure a TLCP client or server.
// After one has been passed to a TLCP function it must not be
// modified. A Config may be reused; the tlcp package will also not
// modify it.
type Config struct {
	// Rand 外部随机源，若不配置则默认使用 crypto/rand 作为随机源
	// 随机源必须线程安全，能够被多goroutines访问。
	Rand io.Reader

	// Time returns the current time as the number of seconds since the epoch.
	// If Time is nil, TLCP uses time.Now.
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

	// GetConfigForClient, if not nil, is called after a ClientHello is
	// received from a client. It may return a non-nil Config in order to
	// change the Config that will be used to handle this connection. If
	// the returned Config is nil, the original Config will be used. The
	// Config returned by this callback may not be subsequently modified.
	//
	// If GetConfigForClient is nil, the Config passed to Server() will be
	// used for all connections.
	//
	// If SessionTicketKey was explicitly set on the returned Config, or if
	// SetSessionTicketKeys was called on the returned Config, those keys will
	// be used. Otherwise, the original Config keys will be used (and possibly
	// rotated if they are automatically managed).
	GetConfigForClient func(*ClientHelloInfo) (*Config, error)

	// VerifyPeerCertificate, if not nil, is called after normal
	// certificate verification by either a TLCP client or server. It
	// receives the raw ASN.1 certificates provided by the peer and also
	// any verified chains that normal processing found. If it returns a
	// non-nil error, the handshake is aborted and that error results.
	//
	// If normal verification fails then the handshake will abort before
	// considering this callback. If normal verification is disabled by
	// setting InsecureSkipVerify, or (for a server) when ClientAuth is
	// RequestClientCert or RequireAnyClientCert, then this callback will
	// be considered but the verifiedChains argument will always be nil.
	VerifyPeerCertificate func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error

	// VerifyConnection, if not nil, is called after normal certificate
	// verification and after VerifyPeerCertificate by either a TLCP client
	// or server. If it returns a non-nil error, the handshake is aborted
	// and that error results.
	//
	// If normal verification fails then the handshake will abort before
	// considering this callback. This callback will run for all connections
	// regardless of InsecureSkipVerify or ClientAuth settings.
	VerifyConnection func(ConnectionState) error

	// RootCAs 根证书列表，客户端使用该列表的证书验证服务端证书是否有效
	// 如果这个字段为空，则使用主机上的根证书集合（从操作系统中加载）
	RootCAs *x509.CertPool

	// ServerName 用于验证主机名与数字证书中的主机名是否匹配
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

	// MinVersion contains the minimum TLCP version that is acceptable.
	//
	// By default, TLS 1.2 is currently used as the minimum when acting as a
	// client, and TLS 1.0 when acting as a server. TLS 1.0 is the minimum
	// supported by this package, both as a client and as a server.
	//
	// The client-side default can temporarily be reverted to TLS 1.0 by
	// including the value "x509sha1=1" in the GODEBUG environment variable.
	// Note that this option will be removed in Go 1.19 (but it will still be
	// possible to set this field to VersionTLS10 explicitly).
	MinVersion uint16

	// MaxVersion contains the maximum TLS version that is acceptable.
	//
	// By default, the maximum version supported by this package is used,
	// which is currently TLS 1.3.
	MaxVersion uint16

	// CurvePreferences contains the elliptic curves that will be used in
	// an ECDHE handshake, in preference order. If empty, the default will
	// be used. The client will use the first preference as the type for
	// its key share in TLS 1.3. This may change in the future.
	CurvePreferences []CurveID

	// DynamicRecordSizingDisabled disables adaptive sizing of TLS records.
	// When true, the largest possible TLS record size is always used. When
	// false, the size of TLS records may be adjusted in an attempt to
	// improve latency.
	DynamicRecordSizingDisabled bool

	// mutex protects sessionTicketKeys and autoSessionTicketKeys.
	mutex sync.RWMutex
}

// Clone returns a shallow clone of c or nil if c is nil. It is safe to clone a Config that is
// being used concurrently by a TLS client or server.
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
		GetClientCertificate:        c.GetClientCertificate,
		GetConfigForClient:          c.GetConfigForClient,
		VerifyPeerCertificate:       c.VerifyPeerCertificate,
		VerifyConnection:            c.VerifyConnection,
		RootCAs:                     c.RootCAs,
		ServerName:                  c.ServerName,
		ClientAuth:                  c.ClientAuth,
		ClientCAs:                   c.ClientCAs,
		InsecureSkipVerify:          c.InsecureSkipVerify,
		CipherSuites:                c.CipherSuites,
		SessionCache:                c.SessionCache,
		MinVersion:                  c.MinVersion,
		MaxVersion:                  c.MaxVersion,
		CurvePreferences:            c.CurvePreferences,
		DynamicRecordSizingDisabled: c.DynamicRecordSizingDisabled,
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

// getCertificate returns the best certificate for the given ClientHelloInfo,
// defaulting to the first element of c.Certificates.
func (c *Config) getCertificate(clientHello *ClientHelloInfo) (*Certificate, error) {
	if c.GetCertificate != nil &&
		(len(c.Certificates) == 0 || len(clientHello.ServerName) > 0) {
		cert, err := c.GetCertificate(clientHello)
		if cert != nil || err != nil {
			return cert, err
		}
	}

	if len(c.Certificates) == 0 {
		return nil, errNoCertificates
	}
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

//const (
//	keyLogLabelTLS12           = "CLIENT_RANDOM"
//	keyLogLabelClientHandshake = "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
//	keyLogLabelServerHandshake = "SERVER_HANDSHAKE_TRAFFIC_SECRET"
//	keyLogLabelClientTraffic   = "CLIENT_TRAFFIC_SECRET_0"
//	keyLogLabelServerTraffic   = "SERVER_TRAFFIC_SECRET_0"
//)

//func (c *Config) writeKeyLog(label string, clientRandom, secret []byte) error {
//	if c.KeyLogWriter == nil {
//		return nil
//	}
//
//	logLine := []byte(fmt.Sprintf("%s %x %x\n", label, clientRandom, secret))
//
//	writerMutex.Lock()
//	_, err := c.KeyLogWriter.Write(logLine)
//	writerMutex.Unlock()
//
//	return err
//}

//// writerMutex protects all KeyLogWriters globally. It is rarely enabled,
//// and is only for debugging, so a global mutex saves space.
//var writerMutex sync.Mutex

// A Certificate is a chain of one or more certificates, leaf first.
type Certificate struct {
	Certificate [][]byte
	// PrivateKey contains the private key corresponding to the public key in
	// Leaf. This must implement crypto.Signer with an RSA, ECDSA or Ed25519 PublicKey.
	// For a server up to TLS 1.2, it can also implement crypto.Decrypter with
	// an RSA PublicKey.
	PrivateKey crypto.PrivateKey

	// Leaf is the parsed form of the leaf certificate, which may be initialized
	// using x509.ParseCertificate to reduce per-handshake processing. If nil,
	// the leaf certificate will be parsed as needed.
	Leaf *x509.Certificate
}

// leaf returns the parsed leaf certificate, either from c.Leaf or by parsing
// the corresponding c.Certificate[0].
func (c *Certificate) leaf() (*x509.Certificate, error) {
	if c.Leaf != nil {
		return c.Leaf, nil
	}
	return x509.ParseCertificate(c.Certificate[0])
}

type handshakeMessage interface {
	marshal() []byte
	unmarshal([]byte) bool
}

var emptyConfig Config

func defaultConfig() *Config {
	return &emptyConfig
}

func unexpectedMessageError(wanted, got interface{}) error {
	return fmt.Errorf("tlcp: received unexpected handshake message of type %T when waiting for %T", got, wanted)
}
