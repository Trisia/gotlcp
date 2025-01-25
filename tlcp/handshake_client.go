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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"net"
	"strings"
	"sync/atomic"
	"time"

	x509 "github.com/emmansun/gmsm/smx509"
)

// clientHandshakeState 客户端握手上下文参数
// 包含了客户端在握手过程需要的上下文，在握手结束该参数应该被舍弃。
type clientHandshakeState struct {
	c                *Conn               // 连接对象
	ctx              context.Context     // 上下文
	serverHello      *serverHelloMsg     // 服务端 Hello消息
	hello            *clientHelloMsg     // 客户端 Hello消息
	suite            *cipherSuite        // 密码套件实现
	finishedHash     finishedHash        // 生成结束验证消息
	masterSecret     []byte              // 主密钥
	session          *SessionState       // 会话状态
	authCert         *Certificate        // 客户端认证密钥对
	encCert          *Certificate        // 客户端加密证书
	peerCertificates []*x509.Certificate // 服务端证书，依次为签名证书、加密证书
}

func (c *Conn) makeClientHello() (*clientHelloMsg, error) {
	config := c.config

	supportVers := config.supportedVersions(roleClient)
	if len(supportVers) == 0 {
		return nil, errors.New("tlcp: no supported versions satisfy MinVersion and MaxVersion")
	}

	clientHelloVersion := config.maxSupportedVersion(roleClient)

	hello := &clientHelloMsg{
		vers:               clientHelloVersion,
		compressionMethods: []uint8{compressionNone},
		random:             make([]byte, 32),
		serverName:         hostnameInSNI(config.ServerName),
	}

	// 若用户指定了椭圆曲线偏好，则使用用户指定的椭圆曲线
	if config.CurvePreferences != nil {
		hello.supportedCurves = config.CurvePreferences
	} else {
		// 未指定时默认使用SM2
		hello.supportedCurves = []CurveID{CurveSM2}
	}
	// 若用户指定了授信CA指示，则发送 trusted_ca_keys类型扩展
	if len(config.TrustedCAIndications) > 0 {
		// 发送扩展
		hello.trustedAuthorities = config.TrustedCAIndications
	}

	// 若用户指定应用层协议，则发送ALPN类型扩展
	if len(config.NextProtos) > 0 {
		hello.alpnProtocols = config.NextProtos
	}

	hasAuthKeyPair := false
	if len(config.Certificates) > 0 || config.GetClientCertificate != nil {
		hasAuthKeyPair = true
	}

	hasEncKeyPair := false
	if len(config.Certificates) > 1 || config.GetClientKECertificate != nil {
		hasEncKeyPair = true
	}

	preferenceOrder := cipherSuitesPreferenceOrder
	configCipherSuites := config.cipherSuites()
	hello.cipherSuites = make([]uint16, 0, len(configCipherSuites))
	// 选择匹配的密码套件
	for _, suiteId := range preferenceOrder {
		suite := mutualCipherSuite(configCipherSuites, suiteId)
		if suite == nil {
			continue
		}
		// SM2 ECDHE 必须要求客户端具有认证密钥对
		if (suiteId == ECDHE_SM4_GCM_SM3 || suiteId == ECDHE_SM4_CBC_SM3) && !(hasAuthKeyPair && hasEncKeyPair) {
			continue
		}
		hello.cipherSuites = append(hello.cipherSuites, suiteId)
	}
	// GM/T0024-2023 A.5 Signature Algorithms 签名算法
	// 客户端在使用商用密码算法进行协商时，应发送 Signature Algorithms 扩展，以指定 HashAlgorithm 为SM3 和 SignatureAlgorithm 为 SM2。
	for _, sigAlg := range hello.cipherSuites {
		if sigAlg == ECDHE_SM4_GCM_SM3 ||
			sigAlg == ECDHE_SM4_CBC_SM3 ||
			sigAlg == ECC_SM4_CBC_SM3 ||
			sigAlg == ECC_SM4_GCM_SM3 {
			hello.supportedSignatureAlgorithms = []SignatureScheme{SM2WithSM3}
			break
		}
	}

	// 生成客户端随机数
	var err error
	hello.random, err = c.tlcpRand()
	if err != nil {
		return nil, errors.New("tlcp: short read from Rand: " + err.Error())
	}

	return hello, nil
}

func (c *Conn) clientHandshake(ctx context.Context) (err error) {
	if c.config == nil {
		c.config = defaultConfig()
	}

	// This may be a renegotiation handshake, in which case some fields
	// need to be reset.
	c.didResume = false

	hello, err := c.makeClientHello()
	if err != nil {
		return err
	}
	c.serverName = c.config.ServerName

	dst := c.conn.RemoteAddr().String()
	// 加载会话，如果存在
	sessionId, session := c.loadSession(dst, hello)
	defer func() {
		// 按照 GB/T 38636-2020 6.4.5.2.1 Client Hello 消息 c) session_id 要求
		// 会话标识生成后应一直保持到超时删除 或 这个会话相关的连接遇到致命错误被关闭。
		if session != nil && err != nil {
			// 删除会话
			c.config.SessionCache.Put(dst, nil)
			c.config.SessionCache.Put(sessionId, nil)
		}
	}()

	if _, err = c.writeHandshakeRecord(hello, nil); err != nil {
		return err
	}

	// serverHelloMsg is not included in the transcript
	msg, err := c.readHandshake(nil)
	if err != nil {
		return err
	}

	serverHello, ok := msg.(*serverHelloMsg)
	if !ok {
		_ = c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(serverHello, msg)
	}

	if err = c.pickProtocolVersion(serverHello); err != nil {
		return err
	}

	hs := &clientHandshakeState{
		c:           c,
		ctx:         ctx,
		serverHello: serverHello,
		hello:       hello,
		session:     session,
	}

	if err = hs.handshake(); err != nil {
		return err
	}

	return nil
}

// 加载会话，如果存在
// dest: 目的地址
// hello: 客户端Hello消息
func (c *Conn) loadSession(dest string, hello *clientHelloMsg) (cacheKey string, session *SessionState) {
	if c.config.SessionCache == nil {
		return
	}
	var ok = false

	// 通过目的主机地址尝试获取会话
	session, ok = c.config.SessionCache.Get(dest)
	if !ok || session == nil {
		return cacheKey, nil
	}
	// 设置客户端Hello 会话ID
	hello.sessionId = session.sessionId
	cacheKey = hex.EncodeToString(session.sessionId)

	return cacheKey, session
}

// 根据服务端消息选择客户端协议版本
func (c *Conn) pickProtocolVersion(serverHello *serverHelloMsg) error {
	peerVersion := serverHello.vers

	vers, ok := c.config.mutualVersion(roleClient, []uint16{peerVersion})
	if !ok {
		_ = c.sendAlert(alertProtocolVersion)
		return fmt.Errorf("tlcp: server selected unsupported protocol version %x", peerVersion)
	}

	c.vers = vers
	c.haveVers = true
	c.in.version = vers
	c.out.version = vers

	return nil
}

// Does the handshake, either a full one or resumes old session. Requires hs.c,
// hs.hello, hs.serverHello, and, optionally, hs.session to be set.
func (hs *clientHandshakeState) handshake() error {
	c := hs.c

	isResume, err := hs.processServerHello()
	if err != nil {
		return err
	}

	hs.finishedHash = newFinishedHash(c.vers, hs.suite)

	// - 握手重用不需要计算客户端验证消息
	// - 完整的握手流程中如果客户端采用单向身份认证（没有证书和密钥对）那么也不需要计算客户端验证消息的签名值
	if isResume || (len(c.config.Certificates) == 0 && c.config.GetClientCertificate == nil) {
		hs.finishedHash.discardHandshakeBuffer()
	}

	if err = transcriptMsg(hs.hello, &hs.finishedHash); err != nil {
		return err
	}
	if err = transcriptMsg(hs.serverHello, &hs.finishedHash); err != nil {
		return err
	}

	c.buffering = true
	c.didResume = isResume
	if isResume {
		if err = hs.establishKeys(); err != nil {
			return err
		}
		if err = hs.readFinished(c.serverFinished[:]); err != nil {
			return err
		}
		// 握手重用时可以通过连接验证再次验证连接相关的信息
		if c.config.VerifyConnection != nil {
			if err = c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
				_ = c.sendAlert(alertBadCertificate)
				return err
			}
		}
		if err = hs.sendFinished(c.clientFinished[:]); err != nil {
			return err
		}
		if _, err = c.flush(); err != nil {
			return err
		}
	} else {
		if err = hs.doFullHandshake(); err != nil {
			return err
		}
		if err = hs.establishKeys(); err != nil {
			return err
		}
		if err = hs.sendFinished(c.clientFinished[:]); err != nil {
			return err
		}
		if _, err = c.flush(); err != nil {
			return err
		}
		if err = hs.createNewSession(); err != nil {
			return err
		}
		if err = hs.readFinished(c.serverFinished[:]); err != nil {
			return err
		}
	}

	atomic.StoreUint32(&c.handshakeStatus, 1)

	return nil
}

func (hs *clientHandshakeState) pickCipherSuite() error {
	if hs.suite = mutualCipherSuite(hs.hello.cipherSuites, hs.serverHello.cipherSuite); hs.suite == nil {
		_ = hs.c.sendAlert(alertHandshakeFailure)
		return errors.New("tlcp: server chose an unconfigured cipher suite")
	}

	hs.c.cipherSuite = hs.suite.id
	return nil
}

func (hs *clientHandshakeState) doFullHandshake() error {
	c := hs.c

	msg, err := c.readHandshake(&hs.finishedHash)
	if err != nil {
		return err
	}
	certMsg, ok := msg.(*certificateMsg)
	if !ok || len(certMsg.certificates) == 0 {
		_ = c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(certMsg, msg)
	}

	msg, err = c.readHandshake(&hs.finishedHash)
	if err != nil {
		return err
	}

	if c.handshakes == 0 {
		// If this is the first handshake on a connection, process and
		// (optionally) verify the server's certificates.
		if err = c.verifyServerCertificate(certMsg.certificates); err != nil {
			return err
		}
	} else {
		// This is a renegotiation handshake. We require that the
		// server's identity (i.e. leaf certificate) is unchanged and
		// thus any previous trust decision is still valid.
		//
		// See https://mitls.org/pages/attacks/3SHAKE for the
		// motivation behind this requirement.
		if !bytes.Equal(c.peerCertificates[0].Raw, certMsg.certificates[0]) {
			_ = c.sendAlert(alertBadCertificate)
			return errors.New("tlcp: server's identity changed during renegotiation")
		}
	}
	hs.peerCertificates = c.peerCertificates

	keyAgreement := hs.suite.ka(c.vers)

	skx, ok := msg.(*serverKeyExchangeMsg)
	if ok {
		err = keyAgreement.processServerKeyExchange(hs, skx)
		if err != nil {
			_ = c.sendAlert(alertUnexpectedMessage)
			return err
		}

		msg, err = c.readHandshake(&hs.finishedHash)
		if err != nil {
			return err
		}
	}

	var clientAuthCert *Certificate
	var clientEncCert *Certificate
	var certRequested bool
	certReq, ok := msg.(*certificateRequestMsg)
	if ok {
		certRequested = true

		cri := &CertificateRequestInfo{AcceptableCAs: certReq.certificateAuthorities, Version: c.vers, ctx: hs.ctx}
		if clientAuthCert, err = c.getClientCertificate(cri); err != nil {
			_ = c.sendAlert(alertInternalError)
			return err
		}
		// 尝试尝试获取客户端加密证书，如果存在
		if clientEncCert, err = c.getClientKECertificate(cri); err != nil {
			// 特殊的 ECDHE 仅支持双向身份认证若没有加密证书则认为无法协商。
			if c.cipherSuite == ECDHE_SM4_CBC_SM3 || c.cipherSuite == ECDHE_SM4_GCM_SM3 {
				_ = c.sendAlert(alertInternalError)
				return err
			}
		}

		hs.authCert = clientAuthCert
		hs.encCert = clientEncCert

		msg, err = c.readHandshake(&hs.finishedHash)
		if err != nil {
			return err
		}
	}

	shd, ok := msg.(*serverHelloDoneMsg)
	if !ok {
		_ = c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(shd, msg)
	}

	// 如果服务端发送了证书请求消息，那么必须发送证书消息（客户端）
	// 即便客户端没有证书，也需要发一条空证书的证书消息到服务端。
	if certRequested {
		certMsg = new(certificateMsg)
		if clientAuthCert != nil && len(clientAuthCert.Certificate) > 0 {
			certMsg.certificates = append(certMsg.certificates, clientAuthCert.Certificate[0])
		}
		// 若存在客户端加密证书则一同发送该证书。
		//
		// 特别的：ECDHE系列套件出签名证书外，还需要客户端额外发送加密证书
		// 加密证书将用于SM2密钥交换协商密钥。
		if clientEncCert != nil && len(clientEncCert.Certificate) > 0 {
			certMsg.certificates = append(certMsg.certificates, clientEncCert.Certificate[0])
		}

		if _, err = c.writeHandshakeRecord(certMsg, &hs.finishedHash); err != nil {
			return err
		}
	}

	preMasterSecret, ckx, err := keyAgreement.generateClientKeyExchange(hs)
	if err != nil {
		_ = c.sendAlert(alertInternalError)
		return err
	}
	if ckx != nil {
		if _, err = c.writeHandshakeRecord(ckx, &hs.finishedHash); err != nil {
			return err
		}
	}

	// 准备 客户端证书验证消息
	if clientAuthCert != nil && len(clientAuthCert.Certificate) > 0 {
		certVerify := &certificateVerifyMsg{}

		// 根据算法套件获取签名算法类型
		sigType, newHash, err := typeAndHashFrom(hs.suite.id)
		if err != nil {
			_ = c.sendAlert(alertInternalError)
			return err
		}
		// 计算从Hello开始至今的握手消息Hash
		signed := hs.finishedHash.Sum()
		// 根据算法套件使用密钥签名
		certVerify.signature, err = signHandshake(c, sigType, clientAuthCert.PrivateKey, newHash, signed)
		if err != nil {
			_ = c.sendAlert(alertInternalError)
			return err
		}

		if _, err := c.writeHandshakeRecord(certVerify, &hs.finishedHash); err != nil {
			return err
		}
	}
	hs.masterSecret = masterFromPreMasterSecret(c.vers, hs.suite, preMasterSecret, hs.hello.random, hs.serverHello.random)
	hs.finishedHash.discardHandshakeBuffer()

	return nil
}

func (hs *clientHandshakeState) establishKeys() error {
	c := hs.c

	clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
		keysFromMasterSecret(c.vers, hs.suite, hs.masterSecret, hs.hello.random, hs.serverHello.random, hs.suite.macLen, hs.suite.keyLen, hs.suite.ivLen)
	var clientCipher, serverCipher interface{}
	var clientHash, serverHash hash.Hash
	if hs.suite.cipher != nil {
		clientCipher = hs.suite.cipher(clientKey, clientIV, false /* not for reading */)
		clientHash = hs.suite.mac(clientMAC)
		serverCipher = hs.suite.cipher(serverKey, serverIV, true /* for reading */)
		serverHash = hs.suite.mac(serverMAC)
	} else {
		clientCipher = hs.suite.aead(clientKey, clientIV)
		serverCipher = hs.suite.aead(serverKey, serverIV)
	}

	c.in.prepareCipherSpec(c.vers, serverCipher, serverHash)
	c.out.prepareCipherSpec(c.vers, clientCipher, clientHash)
	return nil
}

func (hs *clientHandshakeState) serverResumedSession() bool {
	// 如果服务端返回session id 不为空且与 客户端发送的session id 一致，那么重用会话
	return hs.session != nil &&
		hs.hello.sessionId != nil &&
		len(hs.serverHello.sessionId) > 0 &&
		bytes.Equal(hs.serverHello.sessionId, hs.hello.sessionId)
}

// 处理服务端握手消息
// return: 握手重用（true-启用；false-不启用）;
func (hs *clientHandshakeState) processServerHello() (bool, error) {
	c := hs.c

	// 选择匹配的密码套件
	if err := hs.pickCipherSuite(); err != nil {
		return false, err
	}

	if hs.serverHello.compressionMethod != compressionNone {
		_ = c.sendAlert(alertUnexpectedMessage)
		return false, errors.New("tlcp: server selected unsupported compression format")
	}

	// 检查服务端的应用层协议是否在客户端支持，若不支持的报错。
	if err := checkALPN(hs.hello.alpnProtocols, hs.serverHello.alpnProtocol); err != nil {
		_ = c.sendAlert(alertUnsupportedExtension)
		return false, err
	}
	c.clientProtocol = hs.serverHello.alpnProtocol

	if !hs.serverResumedSession() {
		return false, nil
	}

	if hs.session.vers != c.vers {
		_ = c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tlcp: server resumed a session with a different version")
	}

	if hs.session.cipherSuite != hs.suite.id {
		_ = c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tlcp: server resumed a session with a different cipher suite")
	}

	// 根据会话恢复 会话密钥 以及 证书
	hs.masterSecret = hs.session.masterSecret
	c.peerCertificates = hs.session.peerCertificates
	return true, nil
}

func (hs *clientHandshakeState) readFinished(out []byte) error {
	c := hs.c

	if err := c.readChangeCipherSpec(); err != nil {
		return err
	}

	// finishedMsg is included in the transcript, but not until after we
	// check the client version, since the state before this message was
	// sent is used during verification.
	msg, err := c.readHandshake(nil)
	if err != nil {
		return err
	}
	serverFinished, ok := msg.(*finishedMsg)
	if !ok {
		_ = c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(serverFinished, msg)
	}

	verify := hs.finishedHash.serverSum(hs.masterSecret)
	if len(verify) != len(serverFinished.verifyData) ||
		subtle.ConstantTimeCompare(verify, serverFinished.verifyData) != 1 {
		_ = c.sendAlert(alertHandshakeFailure)
		return errors.New("tlcp: server's Finished message was incorrect")
	}
	if err := transcriptMsg(serverFinished, &hs.finishedHash); err != nil {
		return err
	}
	copy(out, verify)
	return nil
}

// 生成Session会话信息，用于握手重用
func (hs *clientHandshakeState) createNewSession() error {
	if hs.c.config.SessionCache == nil {
		return nil
	}

	sessionKey := hex.EncodeToString(hs.serverHello.sessionId)
	cs := &SessionState{
		sessionId:        hs.serverHello.sessionId,
		vers:             hs.serverHello.vers,
		cipherSuite:      hs.serverHello.cipherSuite,
		masterSecret:     hs.masterSecret,
		createdAt:        time.Now(),
		peerCertificates: hs.peerCertificates,
	}
	dst := hs.c.conn.RemoteAddr().String()
	hs.c.config.SessionCache.Put(sessionKey, cs)
	hs.c.config.SessionCache.Put(dst, cs)
	return nil
}

func (hs *clientHandshakeState) sendFinished(out []byte) error {
	c := hs.c

	if err := c.writeChangeCipherRecord(); err != nil {
		return err
	}

	finished := new(finishedMsg)
	finished.verifyData = hs.finishedHash.clientSum(hs.masterSecret)
	if _, err := c.writeHandshakeRecord(finished, &hs.finishedHash); err != nil {
		return err
	}
	copy(out, finished.verifyData)
	return nil
}

// verifyServerCertificate 解析并验证服务端证书（签名,加密）
// c.verifiedChains and c.peerCertificates or sending the appropriate alert.
func (c *Conn) verifyServerCertificate(certificates [][]byte) error {
	activeHandles := make([]*activeCert, len(certificates))
	certs := make([]*x509.Certificate, len(certificates))
	for i, asn1Data := range certificates {
		cert, err := clientCertCache.newCert(asn1Data)
		if err != nil {
			_ = c.sendAlert(alertBadCertificate)
			return errors.New("tlcp: failed to parse certificate from server: " + err.Error())
		}
		activeHandles[i] = cert
		certs[i] = cert.cert
	}

	if len(certs) < 2 {
		_ = c.sendAlert(alertBadCertificate)
		return errors.New("tlcp: need two of certificate one for sign one for encrypt")
	}

	if !c.config.InsecureSkipVerify {
		opts := x509.VerifyOptions{
			Roots:         c.config.RootCAs,
			CurrentTime:   c.config.time(),
			DNSName:       c.config.ServerName,
			Intermediates: x509.NewCertPool(),
		}

		for _, cert := range certs[2:] {
			opts.Intermediates.AddCert(cert)
		}

		var err error

		// 验证签名证书
		c.verifiedChains, err = certs[0].Verify(opts)
		if err != nil {
			_ = c.sendAlert(alertBadCertificate)
			return &CertificateVerificationError{UnverifiedCertificates: certs, Err: err}
		}
		// 验证加密证书
		_, err = certs[1].Verify(opts)
		if err != nil {
			_ = c.sendAlert(alertBadCertificate)
			return &CertificateVerificationError{UnverifiedCertificates: certs, Err: err}
		}
	}

	switch certs[0].PublicKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
		break
	default:
		_ = c.sendAlert(alertUnsupportedCertificate)
		return fmt.Errorf("tlcp: server's certificate contains an unsupported type of public key: %T", certs[0].PublicKey)
	}

	c.activeCertHandles = activeHandles
	c.peerCertificates = certs

	if c.config.VerifyPeerCertificate != nil {
		if err := c.config.VerifyPeerCertificate(certificates, c.verifiedChains); err != nil {
			_ = c.sendAlert(alertBadCertificate)
			return err
		}
	}

	if c.config.VerifyConnection != nil {
		if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
			_ = c.sendAlert(alertBadCertificate)
			return err
		}
	}

	return nil
}

// 通过证书请求信息的Subject获取匹配的数字证书
func (c *Conn) getClientCertificate(cri *CertificateRequestInfo) (*Certificate, error) {
	if c.config.GetClientCertificate != nil {
		return c.config.GetClientCertificate(cri)
	}

	if len(c.config.Certificates) > 0 {
		if err := cri.SupportsCertificate(&c.config.Certificates[0]); err == nil {
			return &c.config.Certificates[0], nil
		}
	}

	// No acceptable certificate found. Don't send a certificate.
	return new(Certificate), nil
}

func (c *Conn) getClientKECertificate(cri *CertificateRequestInfo) (*Certificate, error) {
	if c.config.GetClientKECertificate != nil {
		return c.config.GetClientKECertificate(cri)
	}
	if len(c.config.Certificates) > 1 {
		if err := cri.SupportsCertificate(&c.config.Certificates[1]); err == nil {
			return &c.config.Certificates[1], nil
		}
	}

	// No acceptable certificate found. Don't send a certificate.
	return nil, errNoCertificates
}

// hostnameInSNI converts name into an appropriate hostname for SNI.
// Literal IP addresses and absolute FQDNs are not permitted as SNI values.
// See RFC 6066, Section 3.
func hostnameInSNI(name string) string {
	host := name
	if len(host) > 0 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	if i := strings.LastIndex(host, "%"); i > 0 {
		host = host[:i]
	}
	if net.ParseIP(host) != nil {
		return ""
	}
	for len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	return name
}

// checkALPN 检查服务端响应的ALPN协议为客户端列表中的协议
func checkALPN(clientProtos []string, serverProto string) error {
	if serverProto == "" {
		return nil
	}
	if len(clientProtos) == 0 {
		return errors.New("tls: server advertised unrequested ALPN extension")
	}
	for _, proto := range clientProtos {
		if proto == serverProto {
			return nil
		}
	}
	return errors.New("tls: server selected unadvertised ALPN protocol")
}
