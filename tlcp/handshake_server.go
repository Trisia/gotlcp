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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"sync/atomic"
	"time"

	x509 "github.com/emmansun/gmsm/smx509"
)

// serverHandshakeState 服务端握手上下文，包含了服务端握手过程中需要的上下文参数
// 在握手结束后上下文参数应该被弃用。
type serverHandshakeState struct {
	c                *Conn               // 连接对象
	ctx              context.Context     // 上下文
	clientHello      *clientHelloMsg     // 服务端 Hello消息
	hello            *serverHelloMsg     // 客户端 Hello消息
	suite            *cipherSuite        // 密码套件实现
	ecdheOk          bool                // 密钥状态 支持SM2密钥交换
	ecSignOk         bool                // 密钥状态 支持SM2签名
	ecDecryptOk      bool                // 密钥状态 支持SM2解密
	rsaDecryptOk     bool                // 密钥状态 支持RSA解密
	rsaSignOk        bool                // 密钥状态 支持RSA签名
	sessionState     *SessionState       // 会话状态
	finishedHash     finishedHash        // 生成结束验证消息
	masterSecret     []byte              // 主密钥
	sigCert          *Certificate        // 签名证书
	encCert          *Certificate        // 加密证书
	peerCertificates []*x509.Certificate // 客户端证书，可能为空
}

// serverHandshake performs a TLCP handshake as a server.
func (c *Conn) serverHandshake(ctx context.Context) error {
	clientHello, err := c.readClientHello(ctx)
	if err != nil {
		return err
	}

	hs := serverHandshakeState{
		c:           c,
		ctx:         ctx,
		clientHello: clientHello,
	}
	return hs.handshake()
}

func (hs *serverHandshakeState) handshake() error {
	var err error
	c := hs.c

	if err = hs.processClientHello(); err != nil {
		return err
	}

	// TLCP 握手协议见 GB/T 38636-2020
	c.buffering = true
	if hs.checkForResumption() {
		c.didResume = true
		if err = hs.doResumeHandshake(); err != nil {
			return err
		}
		if err = hs.establishKeys(); err != nil {
			return err
		}
		if err = hs.sendFinished(c.serverFinished[:]); err != nil {
			return err
		}
		if _, err = c.flush(); err != nil {
			return err
		}
		if err = hs.readFinished(nil); err != nil {
			return err
		}
	} else {
		if err = hs.pickCipherSuite(); err != nil {
			return err
		}
		if err = hs.doFullHandshake(); err != nil {
			return err
		}
		if err = hs.establishKeys(); err != nil {
			return err
		}
		if err = hs.readFinished(c.clientFinished[:]); err != nil {
			return err
		}
		c.buffering = true
		// 创建会话缓存
		hs.createSessionState()
		if err := hs.sendFinished(nil); err != nil {
			return err
		}
		if _, err := c.flush(); err != nil {
			return err
		}
	}
	atomic.StoreUint32(&c.handshakeStatus, 1)

	return nil
}

// readClientHello reads a ClientHello message and selects the protocol version.
func (c *Conn) readClientHello(ctx context.Context) (*clientHelloMsg, error) {
	// clientHelloMsg is included in the transcript, but we haven't initialized
	// it yet. The respective handshake functions will record it themselves.
	msg, err := c.readHandshake(nil)
	if err != nil {
		return nil, err
	}
	clientHello, ok := msg.(*clientHelloMsg)
	if !ok {
		_ = c.sendAlert(alertUnexpectedMessage)
		return nil, unexpectedMessageError(clientHello, msg)
	}

	var configForClient *Config
	if c.config.GetConfigForClient != nil {
		chi := clientHelloInfo(ctx, c, clientHello)
		if configForClient, err = c.config.GetConfigForClient(chi); err != nil {
			_ = c.sendAlert(alertInternalError)
			return nil, err
		} else if configForClient != nil {
			c.config = configForClient
		}
	}

	clientVersions := supportedVersionsFromMax(clientHello.vers)
	// 客户端支持的协议版本 与 服务端支持的服务版本 进行匹配
	c.vers, ok = c.config.mutualVersion(roleServer, clientVersions)
	if !ok {
		_ = c.sendAlert(alertProtocolVersion)
		return nil, fmt.Errorf("tlcp: client offered only unsupported versions: %x", clientVersions)
	}
	c.haveVers = true
	c.in.version = c.vers
	c.out.version = c.vers

	return clientHello, nil
}

func (hs *serverHandshakeState) processClientHello() error {
	c := hs.c

	hs.hello = new(serverHelloMsg)
	hs.hello.vers = c.vers

	foundCompression := false
	// We only support null compression, so check that the client offered it.
	for _, compression := range hs.clientHello.compressionMethods {
		if compression == compressionNone {
			foundCompression = true
			break
		}
	}

	if !foundCompression {
		_ = c.sendAlert(alertHandshakeFailure)
		return errors.New("tlcp: client does not support uncompressed connections")
	}
	var err error
	if hs.hello.random, err = c.tlcpRand(); err != nil {
		_ = c.sendAlert(alertInternalError)
		return err
	}

	hs.hello.compressionMethod = compressionNone
	if len(hs.clientHello.serverName) > 0 {
		c.serverName = hs.clientHello.serverName
	}

	// 协商出客户端与服务端都支持的应用层协议。
	// 若双方均任意一端不支持ALPN，则不做协议选择
	// 若双方都没有适配的协议，则发出错误。
	selectedProto, err := negotiateALPN(c.config.NextProtos, hs.clientHello.alpnProtocols)
	if err != nil {
		c.sendAlert(alertNoApplicationProtocol)
		return err
	}
	hs.hello.alpnProtocol = selectedProto
	c.clientProtocol = selectedProto

	// 选择服务端签名证书
	helloInfo := clientHelloInfo(hs.ctx, c, hs.clientHello)
	hs.sigCert, err = c.config.getCertificate(helloInfo)
	if err != nil {
		if err == errNoCertificates {
			_ = c.sendAlert(alertUnrecognizedName)
		} else {
			_ = c.sendAlert(alertInternalError)
		}
		return err
	}
	if hs.clientHello.serverName != "" && hs.sigCert != nil {
		// 服务端证书中的主机名与客户端提供的主机名匹配
		// 设置主机名ACK标志，发送ACK
		hs.hello.serverNameAck = true
	}

	// 选择服务端加密证书
	hs.encCert, err = c.config.getEKCertificate(helloInfo)
	if err != nil {
		if err == errNoCertificates {
			_ = c.sendAlert(alertUnrecognizedName)
		} else {
			_ = c.sendAlert(alertInternalError)
		}
		return err
	}

	if hs.encCert == nil || hs.sigCert == nil {
		_ = c.sendAlert(alertInternalError)
	}

	if priv, ok := hs.sigCert.PrivateKey.(crypto.Signer); ok {
		switch priv.Public().(type) {
		case *ecdsa.PublicKey:
			hs.ecSignOk = true
		case *rsa.PublicKey:
			hs.rsaSignOk = true
		default:
			_ = c.sendAlert(alertInternalError)
			return fmt.Errorf("tlcp: unsupported signing key type (%T)", priv.Public())
		}
	}
	if priv, ok := hs.encCert.PrivateKey.(crypto.Decrypter); ok {
		switch priv.Public().(type) {
		case *ecdsa.PublicKey:
			hs.ecDecryptOk = true
		case *rsa.PublicKey:
			hs.rsaDecryptOk = true
		default:
			_ = c.sendAlert(alertInternalError)
			return fmt.Errorf("tlcp: unsupported decryption key type (%T)", priv.Public())
		}
	}

	return nil
}

func (hs *serverHandshakeState) pickCipherSuite() error {
	c := hs.c

	preferenceOrder := cipherSuitesPreferenceOrder
	configCipherSuites := c.config.cipherSuites()
	preferenceList := make([]uint16, 0, len(configCipherSuites))
	for _, suiteID := range preferenceOrder {
		for _, id := range configCipherSuites {
			if id == suiteID {
				preferenceList = append(preferenceList, id)
				break
			}
		}
	}

	hs.suite = selectCipherSuite(preferenceList, hs.clientHello.cipherSuites, hs.cipherSuiteOk)
	if hs.suite == nil {
		_ = c.sendAlert(alertHandshakeFailure)
		return errors.New("tlcp: no cipher suite supported by both client and server")
	}
	c.cipherSuite = hs.suite.id
	return nil
}

func (hs *serverHandshakeState) cipherSuiteOk(c *cipherSuite) bool {
	if c.flags&suiteECSign != 0 {
		if !hs.ecSignOk {
			return false
		}
		if !hs.ecDecryptOk {
			return false
		}
	} else if c.flags&suiteECDHE != 0 {
		if !hs.ecdheOk {
			return false
		}
		if c.flags&suiteECSign != 0 {
			if !hs.ecSignOk {
				return false
			}
		} else if !hs.rsaSignOk {
			return false
		}
	} else if !hs.rsaDecryptOk {
		return false
	}
	return true
}

// checkForResumption 检查是否需要会话重用
func (hs *serverHandshakeState) checkForResumption() bool {
	c := hs.c
	if hs.c.config.SessionCache == nil {
		return false
	}
	// 客户端hello消息中的会话标识不为空,且服务端存在匹配的会话标识
	// 则服务端重用与该标识对应的会话建立新连接,并在回应的服务端hello消息中带上
	// 与客户端一致的会话标识，否则服务端产生一个新的会话标识,用来建立一个新的会话。
	if len(hs.clientHello.sessionId) == 0 {
		return false
	}
	sessionKey := hex.EncodeToString(hs.clientHello.sessionId)
	// 检查缓存中是存在
	var ok bool
	hs.sessionState, ok = hs.c.config.SessionCache.Get(sessionKey)
	if !ok {
		return false
	}

	if c.vers != hs.sessionState.vers {
		return false
	}
	cipherSuiteOk := false
	// 检查客户端的密码套件是否任然提供会话中的套件。
	for _, id := range hs.clientHello.cipherSuites {
		if id == hs.sessionState.cipherSuite {
			cipherSuiteOk = true
			break
		}
	}
	if !cipherSuiteOk {
		return false
	}
	// 通过套件的ID从配置和预设的密码套件中选出密码套件实现
	hs.suite = selectCipherSuite([]uint16{hs.sessionState.cipherSuite},
		c.config.cipherSuites(), hs.cipherSuiteOk)
	if hs.suite == nil {
		return false
	}
	return true
}

func (hs *serverHandshakeState) doResumeHandshake() error {
	c := hs.c

	hs.hello.cipherSuite = hs.suite.id
	c.cipherSuite = hs.suite.id
	// 回应的服务端hello消息中带上与客户端一致的会话标识
	hs.hello.sessionId = hs.clientHello.sessionId
	hs.finishedHash = newFinishedHash(c.vers, hs.suite)
	hs.finishedHash.discardHandshakeBuffer()
	if err := transcriptMsg(hs.clientHello, &hs.finishedHash); err != nil {
		return err
	}
	if _, err := c.writeHandshakeRecord(hs.hello, &hs.finishedHash); err != nil {
		return err
	}

	c.peerCertificates = hs.sessionState.peerCertificates

	if c.config.VerifyConnection != nil {
		if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
			_ = c.sendAlert(alertBadCertificate)
			return err
		}
	}

	hs.masterSecret = hs.sessionState.masterSecret

	return nil
}

func (hs *serverHandshakeState) doFullHandshake() error {
	c := hs.c

	if hs.clientHello.ocspStapling && len(hs.sigCert.OCSPStaple) > 0 {
		// !!! 由于GM/T 0024-2023 中没有定义 CertificateStatus 类型握手消息，所以只能通过扩展字段来传递 OCSP 响应。
		hs.hello.ocspStapling = true
		hs.hello.ocspResponse = hs.sigCert.OCSPStaple
	}

	hs.hello.cipherSuite = hs.suite.id
	hs.hello.sessionId = make([]byte, 32)
	// 服务端产生一个新的会话标识,用来建立一个新的会话。
	if _, err := io.ReadFull(c.config.rand(), hs.hello.sessionId); err != nil {
		return errors.New("tlcp: error in generate server side session id, " + err.Error())
	}
	// 客户端认证策略
	authPolice := c.config.ClientAuth
	// 特别的根据  GM/T 38636-2016  6.4.5.8 要求：使用ECDHE算法时，要求客户端发送证书。
	if hs.suite.id == ECDHE_SM4_CBC_SM3 || hs.suite.id == ECDHE_SM4_GCM_SM3 {
		if authPolice != RequestClientCert {
			authPolice = RequireAndVerifyClientCert
		}
	}

	hs.finishedHash = newFinishedHash(hs.c.vers, hs.suite)
	if authPolice == NoClientCert {
		// No need to keep a full record of the handshake if client
		// certificates won't be used.
		hs.finishedHash.discardHandshakeBuffer()
	}
	if err := transcriptMsg(hs.clientHello, &hs.finishedHash); err != nil {
		return err
	}
	if _, err := hs.c.writeHandshakeRecord(hs.hello, &hs.finishedHash); err != nil {
		return err
	}

	certMsg := new(certificateMsg)
	certMsg.certificates = [][]byte{
		hs.sigCert.Certificate[0], hs.encCert.Certificate[0],
	}
	// sign cert should have same cert chain with encrypt cert.
	// we consider sign cert chain as high priority.
	if len(hs.sigCert.Certificate) > 1 {
		certMsg.certificates = append(certMsg.certificates, hs.sigCert.Certificate[1:]...)
	} else if len(hs.encCert.Certificate) > 1 {
		certMsg.certificates = append(certMsg.certificates, hs.encCert.Certificate[1:]...)
	}
	if _, err := hs.c.writeHandshakeRecord(certMsg, &hs.finishedHash); err != nil {
		return err
	}

	keyAgreement := hs.suite.ka(c.vers)
	skx, err := keyAgreement.generateServerKeyExchange(hs)
	if err != nil {
		_ = c.sendAlert(alertHandshakeFailure)
		return err
	}
	if skx != nil {
		if _, err := hs.c.writeHandshakeRecord(skx, &hs.finishedHash); err != nil {
			return err
		}
	}

	var certReq *certificateRequestMsg
	if authPolice >= RequestClientCert {
		// Request a client certificate
		certReq = new(certificateRequestMsg)
		certReq.certificateTypes = []byte{
			byte(certTypeRSASign),
			byte(certTypeECDSASign),
		}
		// An empty list of certificateAuthorities signals to
		// the client that it may send any certificate in response
		// to our request. When we know the CAs we trust, then
		// we can send them down, so that the client can choose
		// an appropriate certificate to give to us.
		if c.config.ClientCAs != nil {
			certReq.certificateAuthorities = c.config.ClientCAs.Subjects()
		}
		if _, err := hs.c.writeHandshakeRecord(certReq, &hs.finishedHash); err != nil {
			return err
		}
	}

	helloDone := new(serverHelloDoneMsg)
	if _, err := hs.c.writeHandshakeRecord(helloDone, &hs.finishedHash); err != nil {
		return err
	}

	if _, err := c.flush(); err != nil {
		return err
	}

	var pub crypto.PublicKey // public key for client auth, if any

	msg, err := c.readHandshake(&hs.finishedHash)
	if err != nil {
		return err
	}

	// If we requested a client certificate, then the client must send a
	// certificate message, even if it's empty.
	if authPolice >= RequestClientCert {
		clientCertMsg, ok := msg.(*certificateMsg)
		if !ok {
			_ = c.sendAlert(alertUnexpectedMessage)
			return unexpectedMessageError(clientCertMsg, msg)
		}

		if err := c.processCertsFromClient(Certificate{Certificate: clientCertMsg.certificates}); err != nil {
			return err
		}
		if len(clientCertMsg.certificates) != 0 {
			pub = c.peerCertificates[0].PublicKey
		}
		hs.peerCertificates = c.peerCertificates
		msg, err = c.readHandshake(&hs.finishedHash)
		if err != nil {
			return err
		}
	}
	if c.config.VerifyConnection != nil {
		if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
			_ = c.sendAlert(alertBadCertificate)
			return err
		}
	}

	// Get client key exchange
	ckx, ok := msg.(*clientKeyExchangeMsg)
	if !ok {
		_ = c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(ckx, msg)
	}

	preMasterSecret, err := keyAgreement.processClientKeyExchange(hs, ckx)
	if err != nil {
		_ = c.sendAlert(alertHandshakeFailure)
		return err
	}
	hs.masterSecret = masterFromPreMasterSecret(c.vers, hs.suite, preMasterSecret, hs.clientHello.random, hs.hello.random)

	// If we received a client sigCert in response to our certificate request message,
	// the client will send us a certificateVerifyMsg immediately after the
	// clientKeyExchangeMsg. This message is a digest of all preceding
	// handshake-layer messages that is signed using the private key corresponding
	// to the client's certificate. This allows us to verify that the client is in
	// possession of the private key of the certificate.
	if len(c.peerCertificates) > 0 {
		// certificateVerifyMsg is included in the transcript, but not until
		// after we verify the handshake signature, since the state before
		// this message was sent is used.
		msg, err = c.readHandshake(nil)
		if err != nil {
			return err
		}
		certVerify, ok := msg.(*certificateVerifyMsg)
		if !ok {
			_ = c.sendAlert(alertUnexpectedMessage)
			return unexpectedMessageError(certVerify, msg)
		}

		// 根据算法套件确定签名算法和Hash算法
		sigType, newHash, err := typeAndHashFrom(hs.suite.id)
		if err != nil {
			_ = c.sendAlert(alertIllegalParameter)
			return err
		}

		// GM/T 38636-2016 6.4.5.9 sm3_hash 和 sha256_hash 是指 hash 运算的结果，
		// 运算内容时自客户端hello消息开始直到本消息为止（不包括本消息）的所有与握手有关的消息（加密证书要包括在签名计算中），
		// 包括握手消息的类型和长度域。
		signed := hs.finishedHash.Sum()
		if err := verifyHandshakeSignature(sigType, pub, newHash, signed, certVerify.signature); err != nil {
			_ = c.sendAlert(alertDecryptError)
			return errors.New("tlcp: invalid signature by the client certificate: " + err.Error())
		}

		if err := transcriptMsg(certVerify, &hs.finishedHash); err != nil {
			return err
		}
	}

	hs.finishedHash.discardHandshakeBuffer()

	return nil
}

func (hs *serverHandshakeState) establishKeys() error {
	c := hs.c

	clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
		keysFromMasterSecret(c.vers, hs.suite, hs.masterSecret, hs.clientHello.random, hs.hello.random, hs.suite.macLen, hs.suite.keyLen, hs.suite.ivLen)

	var clientCipher, serverCipher interface{}
	var clientHash, serverHash hash.Hash

	if hs.suite.aead == nil {
		clientCipher = hs.suite.cipher(clientKey, clientIV, true /* for reading */)
		clientHash = hs.suite.mac(clientMAC)
		serverCipher = hs.suite.cipher(serverKey, serverIV, false /* not for reading */)
		serverHash = hs.suite.mac(serverMAC)
	} else {
		clientCipher = hs.suite.aead(clientKey, clientIV)
		serverCipher = hs.suite.aead(serverKey, serverIV)
	}

	c.in.prepareCipherSpec(c.vers, clientCipher, clientHash)
	c.out.prepareCipherSpec(c.vers, serverCipher, serverHash)

	return nil
}

func (hs *serverHandshakeState) readFinished(out []byte) error {
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
	clientFinished, ok := msg.(*finishedMsg)
	if !ok {
		_ = c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(clientFinished, msg)
	}

	verify := hs.finishedHash.clientSum(hs.masterSecret)
	if len(verify) != len(clientFinished.verifyData) ||
		subtle.ConstantTimeCompare(verify, clientFinished.verifyData) != 1 {
		_ = c.sendAlert(alertHandshakeFailure)
		return errors.New("tlcp: client's Finished message is incorrect")
	}

	if err := transcriptMsg(clientFinished, &hs.finishedHash); err != nil {
		return err
	}
	copy(out, verify)
	return nil
}

func (hs *serverHandshakeState) sendFinished(out []byte) error {
	c := hs.c

	if err := c.writeChangeCipherRecord(); err != nil {
		return err
	}

	finished := new(finishedMsg)
	finished.verifyData = hs.finishedHash.serverSum(hs.masterSecret)
	if _, err := hs.c.writeHandshakeRecord(finished, &hs.finishedHash); err != nil {
		return err
	}

	copy(out, finished.verifyData)

	return nil
}

// 创建新的会话缓存
func (hs *serverHandshakeState) createSessionState() {
	if hs.c.config.SessionCache == nil {
		return
	}

	sessionKey := hex.EncodeToString(hs.hello.sessionId)
	cs := &SessionState{
		sessionId:        hs.hello.sessionId,
		vers:             hs.hello.vers,
		cipherSuite:      hs.hello.cipherSuite,
		masterSecret:     hs.masterSecret,
		peerCertificates: hs.peerCertificates,
		createdAt:        time.Now(),
	}
	hs.c.config.SessionCache.Put(sessionKey, cs)
}

// processCertsFromClient takes a chain of client certificates either from a
// Certificates message or from a sessionState and verifies them. It returns
// the public key of the leaf certificate.
// TODO: 需要进一步调整
func (c *Conn) processCertsFromClient(certificate Certificate) error {
	certificates := certificate.Certificate
	certs := make([]*x509.Certificate, len(certificates))
	var err error
	for i, asn1Data := range certificates {
		if certs[i], err = x509.ParseCertificate(asn1Data); err != nil {
			_ = c.sendAlert(alertBadCertificate)
			return errors.New("tlcp: failed to parse client certificate: " + err.Error())
		}
	}

	if len(certs) == 0 && requiresClientCert(c.config.ClientAuth) {
		_ = c.sendAlert(alertBadCertificate)
		return errors.New("tlcp: client didn't provide a certificate")
	}

	isECDHE := (c.cipherSuite == ECDHE_SM4_CBC_SM3 || c.cipherSuite == ECDHE_SM4_GCM_SM3)
	if len(certs) < 2 && isECDHE {
		_ = c.sendAlert(alertBadCertificate)
		return errors.New("tlcp: client didn't provide both sign/enc certificates for ECDHE suite")
	}

	if c.config.ClientAuth >= VerifyClientCertIfGiven && len(certs) > 0 {
		keyUsages := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
		if c.config.ClientAuth == RequireAndVerifyAnyKeyUsageClientCert {
			keyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
		}
		opts := x509.VerifyOptions{
			Roots:         c.config.ClientCAs,
			CurrentTime:   c.config.time(),
			Intermediates: x509.NewCertPool(),
			KeyUsages:     keyUsages,
		}

		// handle possbile intermediates
		start := 1
		if isECDHE {
			start = 2
		}
		for _, cert := range certs[start:] {
			opts.Intermediates.AddCert(cert)
		}

		// verfiy auth/sign certificate
		chains, err := certs[0].Verify(opts)
		if err != nil {
			var errCertificateInvalid x509.CertificateInvalidError
			if errors.As(err, &x509.UnknownAuthorityError{}) {
				_ = c.sendAlert(alertUnknownCA)
			} else if errors.As(err, &errCertificateInvalid) && errCertificateInvalid.Reason == x509.Expired {
				_ = c.sendAlert(alertCertificateExpired)
			} else {
				_ = c.sendAlert(alertBadCertificate)
			}
			return &CertificateVerificationError{UnverifiedCertificates: certs, Err: err}
		}

		// verify enc certificate, do we need to further check certificate's key usage (certs[1].KeyUsage)?
		if isECDHE {
			_, err = certs[1].Verify(opts)
			if err != nil {
				var errCertificateInvalid x509.CertificateInvalidError
				if errors.As(err, &x509.UnknownAuthorityError{}) {
					_ = c.sendAlert(alertUnknownCA)
				} else if errors.As(err, &errCertificateInvalid) && errCertificateInvalid.Reason == x509.Expired {
					_ = c.sendAlert(alertCertificateExpired)
				} else {
					_ = c.sendAlert(alertBadCertificate)
				}
				return &CertificateVerificationError{UnverifiedCertificates: certs, Err: err}
			}
		}

		c.verifiedChains = chains
	}

	c.peerCertificates = certs

	if len(certs) > 0 {
		switch certs[0].PublicKey.(type) {
		case *ecdsa.PublicKey, *rsa.PublicKey:
		default:
			_ = c.sendAlert(alertUnsupportedCertificate)
			return fmt.Errorf("tlcp: client auth certificate contains an unsupported public key of type %T", certs[0].PublicKey)
		}
		if isECDHE {
			switch certs[1].PublicKey.(type) {
			case *ecdsa.PublicKey, *rsa.PublicKey:
			default:
				_ = c.sendAlert(alertUnsupportedCertificate)
				return fmt.Errorf("tlcp: client enc certificate contains an unsupported public key of type %T", certs[1].PublicKey)
			}
		}
	}

	if c.config.VerifyPeerCertificate != nil {
		if err := c.config.VerifyPeerCertificate(certificates, c.verifiedChains); err != nil {
			_ = c.sendAlert(alertBadCertificate)
			return err
		}
	}

	return nil
}

func clientHelloInfo(ctx context.Context, c *Conn, clientHello *clientHelloMsg) *ClientHelloInfo {
	supportedVers := supportedVersionsFromMax(clientHello.vers)
	return &ClientHelloInfo{
		CipherSuites:         clientHello.cipherSuites,
		ServerName:           clientHello.serverName,
		SupportedVersions:    supportedVers,
		TrustedCAIndications: clientHello.trustedAuthorities,
		Conn:                 c.conn,
		config:               c.config,
		ctx:                  ctx,
	}
}

// 国密类型的随机数 4 byte unix time 28 byte random
// 见 GM/T 38636-2016 6.4.5.2.1 b) random
func (c *Conn) tlcpRand() ([]byte, error) {
	rd := make([]byte, 32)
	_, err := io.ReadFull(c.config.rand(), rd)
	if err != nil {
		return nil, err
	}
	var unixTime int64
	if c.config.Time != nil {
		unixTime = c.config.Time().Unix()
	} else {
		unixTime = time.Now().Unix()
	}
	rd[0] = uint8(unixTime >> 24)
	rd[1] = uint8(unixTime >> 16)
	rd[2] = uint8(unixTime >> 8)
	rd[3] = uint8(unixTime)
	return rd, nil
}

// negotiateALPN 按照顺序从客户端的ALPN列表中选择一个双方都支持的协议。
// 如果客户端或服务端任意一方不支持ALPN则返回空""，不会返回错误。
func negotiateALPN(serverProtos, clientProtos []string) (string, error) {
	if len(serverProtos) == 0 || len(clientProtos) == 0 {
		return "", nil
	}
	var http11fallback bool
	for _, s := range serverProtos {
		for _, c := range clientProtos {
			if s == c {
				return s, nil
			}
			if s == "h2" && c == "http/1.1" {
				http11fallback = true
			}
		}
	}

	// 当客户端协议为 http/1.1 服务端支持http2协议时，
	// 采取兼容让http2服务端做控制而不是切断连接。
	if http11fallback {
		return "", nil
	}
	return "", fmt.Errorf("tls: client requested unsupported application protocols (%s)", clientProtos)
}
