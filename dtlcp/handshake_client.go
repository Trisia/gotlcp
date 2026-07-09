// Copyright (c) 2022 QuanGuanyu
// gotlcp is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package dtlcp

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
	"io"
	"net"
	"strings"
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
	// DTLCP 特有字段
	cookie       []byte           // 从 HelloVerifyRequest 收到的 cookie
	initialHello *clientHelloMsg  // 保存初始 ClientHello（cookie 为空时），用于重传
	flightData   []byte           // Flight 5 原始字节缓存，用于超时重传
}

// =============================================================================
// 辅助函数（DTLCP 状态机）
// =============================================================================

// =============================================================================
// tlcpRand — 生成 32 字节 TLCP 随机数（4 字节 unix time + 28 字节随机）
// =============================================================================

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

// =============================================================================
// makeClientHello — 构建 ClientHello 消息（支持 DTLCP cookie 字段）
// =============================================================================

func (c *Conn) makeClientHello() (*clientHelloMsg, error) {
	config := c.config

	supportVers := config.supportedVersions(roleClient)
	if len(supportVers) == 0 {
		return nil, errors.New("dtlcp: no supported versions satisfy MinVersion and MaxVersion")
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
		if (suiteId == ECDHE_SM4_GCM_SM3 || suiteId == ECDHE_SM4_CBC_SM3) && !(hasAuthKeyPair && hasEncKeyPair) {
			continue
		}
		hello.cipherSuites = append(hello.cipherSuites, suiteId)
	}
	// GM/T0024-2023 A.5 Signature Algorithms
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
		return nil, errors.New("dtlcp: short read from Rand: " + err.Error())
	}

	return hello, nil
}

// =============================================================================
// clientHandshake — DTLCP 客户端握手入口（四态状态机 + Cookie 交换）
// =============================================================================

func (c *Conn) clientHandshake(ctx context.Context) (err error) {
	if c.config == nil {
		c.config = defaultConfig()
	}

	c.didResume = false

	hello, err := c.makeClientHello()
	if err != nil {
		return err
	}
	c.serverName = c.config.ServerName

	dst := c.remoteAddr.String()
	// 加载会话
	sessionId, session := c.loadSession(dst, hello)
	defer func() {
		if session != nil && err != nil {
			c.config.SessionCache.Put(dst, nil)
			c.config.SessionCache.Put(sessionId, nil)
		}
	}()

		// 保存初始 ClientHello 引用（用于重传）
	initialHello := &clientHelloMsg{}
	*initialHello = *hello
	initialHello.raw = nil

	// ===== Cookie 交换阶段 (Flight 1 ↔ Flight 2 ↔ Flight 3) =====
	//
	// 首次发送 ClientHello（cookie=""），收到 HelloVerifyRequest 后保存 cookie 并重发。
	var serverHello *serverHelloMsg

	for {
		c.hsState.Store(int32(stateSending))
		hello.setMessageSeq(c.messageSeq)
		c.messageSeq++

		// 写入 ClientHello，不加入 transcript
		if _, err = c.writeHandshakeRecord(hello, nil); err != nil {
			return err
		}
		if _, err = c.flush(); err != nil {
			return err
		}

		c.hsState.Store(int32(stateWaiting))
		c.retransmitTimer.reset()

		// 读循环：接收响应，处理超时和对端重传
		for {
			// 设置读取超时
			c.pconn.SetReadDeadline(time.Now().Add(c.retransmitTimer.current))

			msg, readErr := c.readHandshake(nil)
			if readErr != nil {
				if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
					// 超时：指数退避并重传
					c.retransmitTimer.backoff()
					c.hsState.Store(int32(stateSending))
					break
				}
				return readErr
			}

			switch m := msg.(type) {
			case *helloVerifyRequestMsg:
				// 检查是否已设置 cookie（对端重传检测）
				if len(hello.cookie) > 0 {
					// 对端重传了 HelloVerifyRequest，我们重传 ClientHello
					c.hsState.Store(int32(stateSending))
					break
				}

				// 正常 cookie 交换：保存 cookie
				hello.cookie = append([]byte(nil), m.cookie...)
				hello.raw = nil // 强制重新 marshaling
				c.handBuf.Reset()
				c.hsState.Store(int32(stateSending))
				break

			case *serverHelloMsg:
				// Cookie 交换完成
				serverHello = m
				c.retransmitTimer.stop()
				c.pconn.SetReadDeadline(time.Time{})
				break

			default:
				_ = c.sendAlert(alertUnexpectedMessage)
				return unexpectedMessageError(serverHello, msg)
			}

			if serverHello != nil {
				break
			}
		}

		if serverHello != nil {
			break
		}
	}

	// 清除读取超时
	c.pconn.SetReadDeadline(time.Time{})

	// 协议版本协商
	if err = c.pickProtocolVersion(serverHello); err != nil {
		return err
	}

	hs := &clientHandshakeState{
		c:            c,
		ctx:          ctx,
		serverHello:  serverHello,
		hello:        hello,
		session:      session,
		cookie:       hello.cookie,
		initialHello: initialHello,
	}

	// 执行完整握手流程（Flight 4-6）
	if err = hs.handshake(); err != nil {
		return err
	}

	return nil
}

// =============================================================================
// loadSession — 加载会话缓存
// =============================================================================

func (c *Conn) loadSession(dest string, hello *clientHelloMsg) (cacheKey string, session *SessionState) {
	if c.config.SessionCache == nil {
		return
	}
	var ok = false

	session, ok = c.config.SessionCache.Get(dest)
	if !ok || session == nil {
		return cacheKey, nil
	}
	hello.sessionId = session.sessionId
	cacheKey = hex.EncodeToString(session.sessionId)

	return cacheKey, session
}

// =============================================================================
// pickProtocolVersion — 版本协商
// =============================================================================

func (c *Conn) pickProtocolVersion(serverHello *serverHelloMsg) error {
	peerVersion := serverHello.vers

	vers, ok := c.config.mutualVersion(roleClient, []uint16{peerVersion})
	if !ok {
		_ = c.sendAlert(alertProtocolVersion)
		return fmt.Errorf("dtlcp: server selected unsupported protocol version %x", peerVersion)
	}

	c.vers = vers
	c.haveVers = true
	c.in.version = vers
	c.out.version = vers

	return nil
}

// =============================================================================
// handshake — 客户端主握手流程（四态状态机）
// =============================================================================

func (hs *clientHandshakeState) handshake() error {
	c := hs.c

	isResume, err := hs.processServerHello()
	if err != nil {
		return err
	}

	hs.finishedHash = newFinishedHash(c.vers, hs.suite)

	if isResume || (len(c.config.Certificates) == 0 && c.config.GetClientCertificate == nil) {
		hs.finishedHash.discardHandshakeBuffer()
	}

	// 将 ClientHello 和 ServerHello 加入 transcript
	if err = transcriptMsg(hs.hello, &hs.finishedHash); err != nil {
		return err
	}
	if err = transcriptMsg(hs.serverHello, &hs.finishedHash); err != nil {
		return err
	}

	c.buffering = true
	c.didResume = isResume

	if isResume {
		// === 会话恢复 ===
		if err = hs.establishKeys(); err != nil {
			return err
		}
		if err = hs.readFinished(c.serverFinished[:]); err != nil {
			return err
		}
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
		// === 全握手 ===
		// Flight 4: 接收 Certificate + ServerKeyExchange* + CertificateRequest* + ServerHelloDone
		// Flight 5: Certificate* + ClientKeyExchange + CertificateVerify* 写入缓冲区（c.buffering 已为 true）
		if err = hs.doFullHandshake(); err != nil {
			return err
		}

		// 构造完整 Flight 5：CKE + CCS + Finished，单数据报发送 (RFC 6347 §4.2.4)
		if err = hs.establishKeys(); err != nil {
			return err
		}

		// 将 CCS + Finished 追加到 Flight 5
		if err = hs.sendFinished(c.clientFinished[:]); err != nil {
			return err
		}

		// 保存整个 Flight 5 用于超时重传
		hs.flightData = append([]byte(nil), c.sendBuf...)

		// 单次 flush 发送完整 Flight 5
		c.hsState.Store(int32(stateSending))
		if _, err = c.flush(); err != nil {
			return err
		}

		// 进入等待状态，接收 Flight 6
		c.hsState.Store(int32(stateWaiting))
		c.retransmitTimer.reset()

		// 创建会话
		if err = hs.createNewSession(); err != nil {
			return err
		}

		// 读取 Flight 6（CCS + Finished），支持超时重传
		if err = hs.readFinished(c.serverFinished[:]); err != nil {
			return err
		}
	}

	c.hsState.Store(int32(stateFinished))

	setZero(hs.masterSecret)
	hs.masterSecret = nil

	return nil
}

// =============================================================================
// pickCipherSuite — 选择密码套件
// =============================================================================

func (hs *clientHandshakeState) pickCipherSuite() error {
	if hs.suite = mutualCipherSuite(hs.hello.cipherSuites, hs.serverHello.cipherSuite); hs.suite == nil {
		_ = hs.c.sendAlert(alertHandshakeFailure)
		return errors.New("dtlcp: server chose an unconfigured cipher suite")
	}

	hs.c.cipherSuite = hs.suite.id
	return nil
}

// =============================================================================
// doFullHandshake — 全握手：读取 Flight 4 并处理
// =============================================================================

func (hs *clientHandshakeState) doFullHandshake() error {
	c := hs.c

	// 读取 Certificate（Flight 4 的第二条消息）
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
		if err = c.verifyServerCertificate(certMsg.certificates); err != nil {
			return err
		}
	} else {
		if !bytes.Equal(c.peerCertificates[0].Raw, certMsg.certificates[0]) {
			_ = c.sendAlert(alertBadCertificate)
			return errors.New("dtlcp: server's identity changed during renegotiation")
		}
	}
	hs.peerCertificates = c.peerCertificates

	keyAgreement := hs.suite.ka(c.vers)

	// ServerKeyExchange（可选）
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

	// CertificateRequest（可选）
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
		if clientEncCert, err = c.getClientKECertificate(cri); err != nil {
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

	// ServerHelloDone
	shd, ok := msg.(*serverHelloDoneMsg)
	if !ok {
		_ = c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(shd, msg)
	}

	// 发送 Flight 5 的握手消息（在 handshake() 中统一发送）
	if certRequested {
		certMsg = new(certificateMsg)
		if clientAuthCert != nil && len(clientAuthCert.Certificate) > 0 {
			certMsg.certificates = append(certMsg.certificates, clientAuthCert.Certificate[0])
		}
		if clientEncCert != nil && len(clientEncCert.Certificate) > 0 {
			certMsg.certificates = append(certMsg.certificates, clientEncCert.Certificate[0])
		}

		certMsg.setMessageSeq(c.messageSeq)
		c.messageSeq++
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
		ckx.setMessageSeq(c.messageSeq)
		c.messageSeq++
		if _, err = c.writeHandshakeRecord(ckx, &hs.finishedHash); err != nil {
			return err
		}
	}

	// CertificateVerify
	if clientAuthCert != nil && len(clientAuthCert.Certificate) > 0 {
		certVerify := &certificateVerifyMsg{}

		sigType, newHash, err := typeAndHashFrom(hs.suite.id)
		if err != nil {
			_ = c.sendAlert(alertInternalError)
			return err
		}
		signed := hs.finishedHash.Sum()
		certVerify.signature, err = signHandshake(c, sigType, clientAuthCert.PrivateKey, newHash, signed)
		if err != nil {
			_ = c.sendAlert(alertInternalError)
			return err
		}

		certVerify.setMessageSeq(c.messageSeq)
		c.messageSeq++
		if _, err := c.writeHandshakeRecord(certVerify, &hs.finishedHash); err != nil {
			return err
		}
	}

	hs.masterSecret = masterFromPreMasterSecret(c.vers, hs.suite, preMasterSecret, hs.hello.random, hs.serverHello.random)
	setZero(preMasterSecret)

	hs.finishedHash.discardHandshakeBuffer()

	return nil
}

// =============================================================================
// establishKeys — 建立密钥
// =============================================================================

func (hs *clientHandshakeState) establishKeys() error {
	c := hs.c

	workKey, clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
		keysFromMasterSecret(c.vers, hs.suite, hs.masterSecret, hs.hello.random, hs.serverHello.random, hs.suite.macLen, hs.suite.keyLen, hs.suite.ivLen)
	c.workKey = workKey
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

// =============================================================================
// serverResumedSession — 检查服务端是否恢复会话
// =============================================================================

func (hs *clientHandshakeState) serverResumedSession() bool {
	return hs.session != nil &&
		hs.hello.sessionId != nil &&
		len(hs.serverHello.sessionId) > 0 &&
		bytes.Equal(hs.serverHello.sessionId, hs.hello.sessionId)
}

// =============================================================================
// processServerHello — 处理 ServerHello
// =============================================================================

func (hs *clientHandshakeState) processServerHello() (bool, error) {
	c := hs.c

	if err := hs.pickCipherSuite(); err != nil {
		return false, err
	}

	if hs.serverHello.compressionMethod != compressionNone {
		_ = c.sendAlert(alertUnexpectedMessage)
		return false, errors.New("dtlcp: server selected unsupported compression format")
	}

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
		return false, errors.New("dtlcp: server resumed a session with a different version")
	}

	if hs.session.cipherSuite != hs.suite.id {
		_ = c.sendAlert(alertHandshakeFailure)
		return false, errors.New("dtlcp: server resumed a session with a different cipher suite")
	}

	if len(hs.session.masterSecret) > 0 {
		hs.masterSecret = make([]byte, len(hs.session.masterSecret))
		copy(hs.masterSecret, hs.session.masterSecret)
	} else {
		_ = c.sendAlert(alertInternalError)
		return false, errors.New("dtlcp: server resumed a session without a master secret")
	}

	c.peerCertificates = hs.session.peerCertificates
	return true, nil
}

// =============================================================================
// readFinished — 读取并验证 Flight 6 的 CCS + Finished
// =============================================================================

func (hs *clientHandshakeState) readFinished(out []byte) error {
	c := hs.c

	for {
		// 设置读取超时，使用当前重传定时器值
		c.pconn.SetReadDeadline(time.Now().Add(c.retransmitTimer.current))

		if err := c.readChangeCipherSpec(); err != nil {
			// 超时处理：重传 Flight 5
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				c.retransmitTimer.backoff()
				// 重传缓存的 Flight 5 原始字节
				if len(hs.flightData) > 0 {
					if _, writeErr := c.pconn.WriteTo(hs.flightData, c.remoteAddr); writeErr != nil {
						return writeErr
					}
				}
				continue
			}
			return err
		}

		// 清除读取超时
		c.pconn.SetReadDeadline(time.Time{})

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
			return errors.New("dtlcp: server's Finished message was incorrect")
		}
		if err := transcriptMsg(serverFinished, &hs.finishedHash); err != nil {
			return err
		}
		copy(out, verify)
		return nil
	}
}

// =============================================================================
// createNewSession — 创建新会话
// =============================================================================

func (hs *clientHandshakeState) createNewSession() error {
	if hs.c.config.SessionCache == nil {
		return nil
	}

	sessionKey := hex.EncodeToString(hs.serverHello.sessionId)
	masterSecretCopy := make([]byte, len(hs.masterSecret))
	copy(masterSecretCopy, hs.masterSecret)
	cs := &SessionState{
		sessionId:        hs.serverHello.sessionId,
		vers:             hs.serverHello.vers,
		cipherSuite:      hs.serverHello.cipherSuite,
		masterSecret:     masterSecretCopy,
		createdAt:        time.Now(),
		peerCertificates: hs.peerCertificates,
	}
	dst := hs.c.remoteAddr.String()
	hs.c.config.SessionCache.Put(sessionKey, cs)
	hs.c.config.SessionCache.Put(dst, cs)
	return nil
}

// =============================================================================
// sendFinished — 发送 CCS + Finished（Flight 5/6 的结束部分）
// =============================================================================

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

// =============================================================================
// verifyServerCertificate — 验证服务端证书
// =============================================================================

func (c *Conn) verifyServerCertificate(certificates [][]byte) error {
	activeHandles := make([]*activeCert, len(certificates))
	certs := make([]*x509.Certificate, len(certificates))
	for i, asn1Data := range certificates {
		cert, err := clientCertCache.newCert(asn1Data)
		if err != nil {
			_ = c.sendAlert(alertBadCertificate)
			return errors.New("dtlcp: failed to parse certificate from server: " + err.Error())
		}
		activeHandles[i] = cert
		certs[i] = cert.cert
	}

	if len(certs) < 2 {
		_ = c.sendAlert(alertBadCertificate)
		return errors.New("dtlcp: need two of certificate one for sign one for encrypt")
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

		c.verifiedChains, err = certs[0].Verify(opts)
		if err != nil {
			_ = c.sendAlert(alertBadCertificate)
			return &CertificateVerificationError{UnverifiedCertificates: certs, Err: err}
		}
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
		return fmt.Errorf("dtlcp: server's certificate contains an unsupported type of public key: %T", certs[0].PublicKey)
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

// =============================================================================
// getClientCertificate / getClientKECertificate — 获取客户端证书
// =============================================================================

func (c *Conn) getClientCertificate(cri *CertificateRequestInfo) (*Certificate, error) {
	if c.config.GetClientCertificate != nil {
		return c.config.GetClientCertificate(cri)
	}

	if len(c.config.Certificates) > 0 {
		if err := cri.SupportsCertificate(&c.config.Certificates[0]); err == nil {
			return &c.config.Certificates[0], nil
		}
	}

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

	return nil, errNoCertificates
}

// =============================================================================
// hostnameInSNI — SNI 主机名处理
// =============================================================================

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

// =============================================================================
// checkALPN — ALPN 协议检查
// =============================================================================

func checkALPN(clientProtos []string, serverProto string) error {
	if serverProto == "" {
		return nil
	}
	if len(clientProtos) == 0 {
		return errors.New("dtlcp: server advertised unrequested ALPN extension")
	}
	for _, proto := range clientProtos {
		if proto == serverProto {
			return nil
		}
	}
	return errors.New("dtlcp: server selected unadvertised ALPN protocol")
}
