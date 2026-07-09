// Copyright (c) 2025 gotlcp contributors
// gotlcp is licensed under Mulan PSL v2.

// DTLCP 服务端握手状态机实现 (Phase 4)
//
// 基于 GB/T 38636-2020《信息安全技术 传输层密码协议》(TLCP) 的服务端握手实现，
// 适配 DTLCP 无状态 cookie 验证、握手消息序列号、分片重组和重传机制。
//
// 飞行（Flight）定义：
//   Flight 2: Server -> HelloVerifyRequest
//   Flight 4: Server -> ServerHello + Certificate + ServerKeyExchange* + CertificateRequest* + ServerHelloDone
//   Flight 6: Server -> ChangeCipherSpec + Finished
//
// 四态握手状态机：PREPARING → SENDING → WAITING → FINISHED
//
// 退出 WAITING 状态的三种方式：
//   1. 重传定时器超时 → 进入 SENDING（重发当前飞行）
//   2. 收到对端重传（ClientHello）→ 进入 SENDING（重发当前飞行）
//   3. 收到下一飞行消息 → 处理消息

package dtlcp

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
	"net"
	"time"

	x509 "github.com/emmansun/gmsm/smx509"
)

// =============================================================================
// serverHandshakeState — 服务端握手上下文
// =============================================================================

// serverHandshakeState 服务端握手上下文，包含了握手过程中需要的上下文参数。
// 握手结束后该上下文应被弃用。
type serverHandshakeState struct {
	c                *Conn               // 连接对象
	ctx              context.Context     // 上下文
	clientHello      *clientHelloMsg     // 客户端 Hello 消息（已通过 cookie 验证）
	hello            *serverHelloMsg     // 服务端 Hello 消息
	suite            *cipherSuite        // 密码套件实现
	ecdheOk          bool                // 支持 ECDHE 密钥交换
	ecSignOk         bool                // 支持 SM2 签名
	ecDecryptOk      bool                // 支持 SM2 解密
	rsaDecryptOk     bool                // 支持 RSA 解密
	rsaSignOk        bool                // 支持 RSA 签名
	sessionState     *SessionState       // 会话状态（用于会话重用）
	finishedHash     finishedHash        // 结束验证消息哈希
	masterSecret     []byte              // 主密钥
	sigCert          *Certificate        // 签名证书
	encCert          *Certificate        // 加密证书
	peerCertificates []*x509.Certificate // 客户端证书，可能为空
	// DTLCP 特有字段
	cookieVerified bool   // cookie 是否已验证通过
	flightData     []byte // 当前 flight 的发送数据，用于重传
}

// =============================================================================
// serverHandshake — 服务端握手入口
// =============================================================================

// serverHandshake 执行 DTLCP 服务端握手协议。
// 状态机流程：
//   Phase 1: 读取 ClientHello，cookie 交换
//   Phase 2: 发送 Flight 4（ServerHello + Certificate + ... + ServerHelloDone）
//   Phase 3: 接收 Flight 5（客户端消息 + CCS + Finished）
//   Phase 4: 发送 Flight 6（CCS + Finished）
//
// 参数:
//   ctx - 握手上下文，用于取消握手
// 返回:
//   error - 握手过程中的错误
func (c *Conn) serverHandshake(ctx context.Context) error {
	// 第一阶段：读取 ClientHello 并进行 cookie 验证交换
	clientHello, err := c.readClientHello(ctx)
	if err != nil {
		return err
	}

	// Cookie 验证交换循环
	// DTLCP 使用无状态 cookie 来防止 DOS 攻击（类似 DTLS）
	// 流程：
	//   1. 客户端发送无 cookie 的 ClientHello
	//   2. 服务端生成并返回 HelloVerifyRequest（含 cookie）
	//   3. 客户端重发含 cookie 的 ClientHello
	//   4. 服务端验证 cookie 后继续握手
	for {
		params := clientHello.marshalForCookie()
		secret := c.effectiveCookieSecret()

		if len(clientHello.cookie) == 0 || !verifyCookie(secret, c.remoteAddr.String(), params, clientHello.cookie) {
			// 需要发送 HelloVerifyRequest
			cookie := generateCookie(secret, c.remoteAddr.String(), params)
			hvr := &helloVerifyRequestMsg{
				serverVersion: VersionTLCP,
				cookie:        cookie,
			}
			hvr.setMessageSeq(c.messageSeq)
			c.messageSeq++

			c.hsState.Store(int32(stateSending))
			if _, err := c.writeHandshakeRecord(hvr, nil); err != nil {
				return err
			}
			c.hsState.Store(int32(stateWaiting))
			if _, err := c.flush(); err != nil {
				return err
			}

			// 读取下一个 ClientHello（含 cookie），带超时重传处理
			clientHello, err = c.readNextClientHello(ctx)
			if err != nil {
				return err
			}
			continue
		}

		// Cookie 验证通过
		break
	}

	// 第二阶段：执行完整握手
	hs := &serverHandshakeState{
		c:              c,
		ctx:            ctx,
		clientHello:    clientHello,
		cookieVerified: true,
	}
	return hs.handshake()
}

// effectiveCookieSecret 返回有效的 cookie 密钥。
// 如果 Config.CookieSecret 已设置，使用配置的密钥。
// 否则生成随机会话级密钥（连接内有效，重启后失效）。
func (c *Conn) effectiveCookieSecret() []byte {
	if secret := c.config.CookieSecret; len(secret) > 0 {
		return secret
	}
	// 使用随机密钥替代硬编码默认值，防止生产环境漏配导致 cookie 可被伪造
	if len(c.cookieSecret) == 0 {
		c.cookieSecret = make([]byte, 32)
		if _, err := io.ReadFull(c.config.rand(), c.cookieSecret); err != nil {
			// rand 失败时回退到伪随机（仅在极端环境下发生）
			for i := range c.cookieSecret {
				c.cookieSecret[i] = byte(i) ^ 0xA5
			}
		}
	}
	return c.cookieSecret
}

// readNextClientHello 读取下一个 ClientHello 消息，支持超时重传。
// 在发送 HelloVerifyRequest 后调用，等待客户端重发带 cookie 的 ClientHello。
func (c *Conn) readNextClientHello(ctx context.Context) (*clientHelloMsg, error) {
	initialTO := c.config.InitialRetransmitTimeout
	if initialTO <= 0 {
		initialTO = time.Second
	}
	maxTO := c.config.MaxRetransmitTimeout
	if maxTO <= 0 {
		maxTO = 64 * time.Second
	}

	timeout := initialTO
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		c.pconn.SetReadDeadline(time.Now().Add(timeout))
		msg, err := c.readHandshake(nil)
		if err == nil {
			c.pconn.SetReadDeadline(time.Time{})
			if _, ok := msg.(*clientHelloMsg); !ok {
				_ = c.sendAlert(alertUnexpectedMessage)
				return nil, unexpectedMessageError((*clientHelloMsg)(nil), msg)
			}
			return msg.(*clientHelloMsg), nil
		}

		// 超时则指数退避重新发送 HelloVerifyRequest
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			timeout *= 2
			if timeout > maxTO {
				timeout = maxTO
			}
			continue
		}
		return nil, err
	}
}

// =============================================================================
// handshake — 主握手流程
// =============================================================================

// handshake 是服务端握手的主流程，类似于 TLCP 的 handshake() 方法。
// 支持会话重用（resumption）和完整握手（full handshake）。
func (hs *serverHandshakeState) handshake() error {
	var err error
	c := hs.c

	if err = hs.processClientHello(); err != nil {
		return err
	}

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
		// 保存 Flight 数据用于重传（会话恢复路径）
		hs.flightData = make([]byte, len(c.sendBuf))
		copy(hs.flightData, c.sendBuf)
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
		// 创建会话缓存
		hs.createSessionState()
		c.buffering = true
		if err = hs.sendFinished(nil); err != nil {
			return err
		}
		// 保存 Flight 6 数据，用于 2*MSL 驻留期重传 (RFC 6347 §4.2.4)
		c.flightRetransmit = make([]byte, len(c.sendBuf))
		copy(c.flightRetransmit, c.sendBuf)
		if _, err = c.flush(); err != nil {
			return err
		}
		// 进入 2*MSL 驻留期：握手完成后 120s 内响应对端重传
		c.dwellDeadline = time.Now().Add(dwellPeriod)
	}

	c.hsState.Store(int32(stateFinished))

	// 握手成功，对主密钥置零
	setZero(hs.masterSecret)
	hs.masterSecret = nil

	return nil
}

// =============================================================================
// readClientHello — 读取并处理 ClientHello
// =============================================================================

// readClientHello 读取一个 ClientHello 消息，并进行版本协商和配置选择。
func (c *Conn) readClientHello(ctx context.Context) (*clientHelloMsg, error) {
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

	// 仅在首次收到 ClientHello 时进行版本协商
	if !c.haveVers {
		clientVersions := supportedVersionsFromMax(clientHello.vers)
		var ok bool
		c.vers, ok = c.config.mutualVersion(roleServer, clientVersions)
		if !ok {
			_ = c.sendAlert(alertProtocolVersion)
			return nil, fmt.Errorf("dtlcp: client offered only unsupported versions: %x", clientVersions)
		}
		c.haveVers = true
		c.in.version = c.vers
		c.out.version = c.vers
	}

	return clientHello, nil
}

// =============================================================================
// processClientHello — 处理 ClientHello 消息
// =============================================================================

// processClientHello 处理 ClientHello 消息，包括：
//   - 设置服务端随机数
//   - 协商 ALPN 协议
//   - 选择签名证书和加密证书
//   - 确定密钥类型支持
func (hs *serverHandshakeState) processClientHello() error {
	c := hs.c

	hs.hello = new(serverHelloMsg)
	hs.hello.vers = c.vers

	foundCompression := false
	for _, compression := range hs.clientHello.compressionMethods {
		if compression == compressionNone {
			foundCompression = true
			break
		}
	}
	if !foundCompression {
		_ = c.sendAlert(alertHandshakeFailure)
		return errors.New("dtlcp: client does not support uncompressed connections")
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

	// 协商应用层协议
	selectedProto, err := negotiateALPN(c.config.NextProtos, hs.clientHello.alpnProtocols)
	if err != nil {
		_ = c.sendAlert(alertNoApplicationProtocol)
		return err
	}
	hs.hello.alpnProtocol = selectedProto
	c.clientProtocol = selectedProto

	// 选择签名证书
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
		hs.hello.serverNameAck = true
	}

	// 选择加密证书
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
		return errors.New("dtlcp: no valid certificates configured")
	}

	// 确定签名密钥类型
	if priv, ok := hs.sigCert.PrivateKey.(crypto.Signer); ok {
		switch priv.Public().(type) {
		case *ecdsa.PublicKey:
			hs.ecSignOk = true
		case *rsa.PublicKey:
			hs.rsaSignOk = true
		default:
			_ = c.sendAlert(alertInternalError)
			return fmt.Errorf("dtlcp: unsupported signing key type (%T)", priv.Public())
		}
	}

	// 确定解密密钥类型
	if priv, ok := hs.encCert.PrivateKey.(crypto.Decrypter); ok {
		switch priv.Public().(type) {
		case *ecdsa.PublicKey:
			hs.ecDecryptOk = true
		case *rsa.PublicKey:
			hs.rsaDecryptOk = true
		default:
			_ = c.sendAlert(alertInternalError)
			return fmt.Errorf("dtlcp: unsupported decryption key type (%T)", priv.Public())
		}
	}

	return nil
}

// =============================================================================
// pickCipherSuite — 选择密码套件
// =============================================================================

// pickCipherSuite 根据客户端提供的密码套件列表和服务端配置，选择合适的密码套件。
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
		return errors.New("dtlcp: no cipher suite supported by both client and server")
	}
	c.cipherSuite = hs.suite.id
	return nil
}

// cipherSuiteOk 检查密码套件是否与当前密钥类型兼容。
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

// =============================================================================
// checkForResumption — 检查会话重用
// =============================================================================

// checkForResumption 检查是否可以重用之前的会话。
// 仅在 SessionCache 已配置且客户端提供了匹配的会话 ID 时返回 true。
func (hs *serverHandshakeState) checkForResumption() bool {
	c := hs.c
	if c.config.SessionCache == nil {
		return false
	}
	if len(hs.clientHello.sessionId) == 0 {
		return false
	}
	sessionKey := hex.EncodeToString(hs.clientHello.sessionId)
	var ok bool
	hs.sessionState, ok = c.config.SessionCache.Get(sessionKey)
	if !ok {
		return false
	}
	if c.vers != hs.sessionState.vers {
		return false
	}
	cipherSuiteOk := false
	for _, id := range hs.clientHello.cipherSuites {
		if id == hs.sessionState.cipherSuite {
			cipherSuiteOk = true
			break
		}
	}
	if !cipherSuiteOk {
		return false
	}
	hs.suite = selectCipherSuite([]uint16{hs.sessionState.cipherSuite},
		c.config.cipherSuites(), hs.cipherSuiteOk)
	if hs.suite == nil {
		return false
	}
	return true
}

// =============================================================================
// doResumeHandshake — 执行会话重用握手
// =============================================================================

// doResumeHandshake 执行会话重用握手流程。
// 在会话重用模式下，服务端复用之前的会话参数，跳过完整握手。
func (hs *serverHandshakeState) doResumeHandshake() error {
	c := hs.c

	hs.hello.cipherSuite = hs.suite.id
	c.cipherSuite = hs.suite.id
	hs.hello.sessionId = hs.clientHello.sessionId

	hs.finishedHash = newFinishedHash(c.vers, hs.suite)
	hs.finishedHash.discardHandshakeBuffer()
	if err := transcriptMsg(hs.clientHello, &hs.finishedHash); err != nil {
		return err
	}
	hs.hello.setMessageSeq(c.messageSeq)
	c.messageSeq++
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

	if len(hs.sessionState.masterSecret) > 0 {
		hs.masterSecret = make([]byte, len(hs.sessionState.masterSecret))
		copy(hs.masterSecret, hs.sessionState.masterSecret)
	} else {
		_ = c.sendAlert(alertInternalError)
		return errors.New("dtlcp: invalid master secret in session state")
	}

	return nil
}

// =============================================================================
// doFullHandshake — 执行完整握手
// =============================================================================

// doFullHandshake 执行完整握手流程（非会话重用），发送 Flight 4 并接收 Flight 5。
//
// Flight 4（服务端发送）:
//   ServerHello + Certificate + ServerKeyExchange* + CertificateRequest* + ServerHelloDone
//
// Flight 5（客户端发送）:
//   Certificate* + ClientKeyExchange + CertificateVerify* + CCS + Finished
func (hs *serverHandshakeState) doFullHandshake() error {
	c := hs.c

	// OCSP stapling 支持
	if hs.clientHello.ocspStapling && len(hs.sigCert.OCSPStaple) > 0 {
		hs.hello.ocspStapling = true
		hs.hello.ocspResponse = hs.sigCert.OCSPStaple
	}

	hs.hello.cipherSuite = hs.suite.id
	hs.hello.sessionId = make([]byte, 32)
	if _, err := io.ReadFull(c.config.rand(), hs.hello.sessionId); err != nil {
		return errors.New("dtlcp: error in generate server side session id, " + err.Error())
	}

	// 客户端认证策略
	authPolice := c.config.ClientAuth
	// GM/T 38636-2016 6.4.5.8：使用ECDHE算法时，要求客户端发送证书
	if hs.suite.id == ECDHE_SM4_CBC_SM3 || hs.suite.id == ECDHE_SM4_GCM_SM3 {
		if authPolice != RequestClientCert {
			authPolice = RequireAndVerifyClientCert
		}
	}

	// 初始化消息哈希
	hs.finishedHash = newFinishedHash(c.vers, hs.suite)
	if authPolice == NoClientCert {
		hs.finishedHash.discardHandshakeBuffer()
	}
	// 将已验证 cookie 的 ClientHello 加入哈希
	if err := transcriptMsg(hs.clientHello, &hs.finishedHash); err != nil {
		return err
	}

	// === 开始缓冲 Flight 4 ===
	c.buffering = true

	// 发送 ServerHello
	hs.hello.setMessageSeq(c.messageSeq)
	c.messageSeq++
	if _, err := c.writeHandshakeRecord(hs.hello, &hs.finishedHash); err != nil {
		return err
	}

	// 发送 Certificate
	certMsg := new(certificateMsg)
	certMsg.certificates = [][]byte{
		hs.sigCert.Certificate[0], hs.encCert.Certificate[0],
	}
	if len(hs.sigCert.Certificate) > 1 {
		certMsg.certificates = append(certMsg.certificates, hs.sigCert.Certificate[1:]...)
	} else if len(hs.encCert.Certificate) > 1 {
		certMsg.certificates = append(certMsg.certificates, hs.encCert.Certificate[1:]...)
	}
	certMsg.setMessageSeq(c.messageSeq)
	c.messageSeq++
	if _, err := c.writeHandshakeRecord(certMsg, &hs.finishedHash); err != nil {
		return err
	}

	// 发送 ServerKeyExchange
	keyAgreement := hs.suite.ka(c.vers)
	skx, err := keyAgreement.generateServerKeyExchange(hs)
	if err != nil {
		_ = c.sendAlert(alertHandshakeFailure)
		return err
	}
	if skx != nil {
		skx.setMessageSeq(c.messageSeq)
		c.messageSeq++
		if _, err := c.writeHandshakeRecord(skx, &hs.finishedHash); err != nil {
			return err
		}
	}

	// 发送 CertificateRequest（可选）
	var certReq *certificateRequestMsg
	if authPolice >= RequestClientCert {
		certReq = new(certificateRequestMsg)
		certReq.certificateTypes = []byte{
			byte(certTypeRSASign),
			byte(certTypeECDSASign),
		}
		if c.config.ClientCAs != nil {
			certReq.certificateAuthorities = c.config.ClientCAs.Subjects()
		}
		certReq.setMessageSeq(c.messageSeq)
		c.messageSeq++
		if _, err := c.writeHandshakeRecord(certReq, &hs.finishedHash); err != nil {
			return err
		}
	}

	// 发送 ServerHelloDone
	helloDone := new(serverHelloDoneMsg)
	helloDone.setMessageSeq(c.messageSeq)
	c.messageSeq++
	if _, err := c.writeHandshakeRecord(helloDone, &hs.finishedHash); err != nil {
		return err
	}

	// 保存 Flight 4 数据用于重传
	hs.flightData = make([]byte, len(c.sendBuf))
	copy(hs.flightData, c.sendBuf)
	flightData := hs.flightData

	// 刷新缓冲区，实际发送 Flight 4
	c.hsState.Store(int32(stateWaiting))
	if _, err := c.flush(); err != nil {
		return err
	}
	// 启动重传定时器
	c.retransmitTimer.reset()

	// === 读取 Flight 5（客户端响应）===

	var pub crypto.PublicKey // 用于客户端认证的公钥

	// 读取客户端证书（如果请求了客户端证书）
	if authPolice >= RequestClientCert {
		msg, err := c.readNextFlightMsg(flightData)
		if err != nil {
			return err
		}
		clientCertMsg, ok := msg.(*certificateMsg)
		if !ok {
			_ = c.sendAlert(alertUnexpectedMessage)
			return unexpectedMessageError(clientCertMsg, msg)
		}
		if err := transcriptMsg(clientCertMsg, &hs.finishedHash); err != nil {
			return err
		}

		if err := c.processCertsFromClient(Certificate{Certificate: clientCertMsg.certificates}); err != nil {
			return err
		}
		if len(clientCertMsg.certificates) != 0 {
			pub = c.peerCertificates[0].PublicKey
		}
		hs.peerCertificates = c.peerCertificates
	}

	if c.config.VerifyConnection != nil {
		if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
			_ = c.sendAlert(alertBadCertificate)
			return err
		}
	}

	// 读取客户端密钥交换消息
	msg, err := c.readNextFlightMsg(flightData)
	if err != nil {
		return err
	}
	ckx, ok := msg.(*clientKeyExchangeMsg)
	if !ok {
		_ = c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(ckx, msg)
	}
	if err := transcriptMsg(ckx, &hs.finishedHash); err != nil {
		return err
	}

	// 计算预主密钥和主密钥
	preMasterSecret, err := keyAgreement.processClientKeyExchange(hs, ckx)
	if err != nil {
		_ = c.sendAlert(alertHandshakeFailure)
		return err
	}
	hs.masterSecret = masterFromPreMasterSecret(c.vers, hs.suite, preMasterSecret, hs.clientHello.random, hs.hello.random)
	setZero(preMasterSecret)

	// 读取客户端 CertificateVerify（如果客户端发送了证书）
	if len(c.peerCertificates) > 0 {
		msg, err := c.readNextFlightMsg(flightData)
		if err != nil {
			return err
		}
		certVerify, ok := msg.(*certificateVerifyMsg)
		if !ok {
			_ = c.sendAlert(alertUnexpectedMessage)
			return unexpectedMessageError(certVerify, msg)
		}

		sigType, newHash, err := typeAndHashFrom(hs.suite.id)
		if err != nil {
			_ = c.sendAlert(alertIllegalParameter)
			return err
		}

		// 验证客户端签名
		signed := hs.finishedHash.Sum()
		if err := verifyHandshakeSignature(sigType, pub, newHash, signed, certVerify.signature); err != nil {
			_ = c.sendAlert(alertDecryptError)
			return errors.New("dtlcp: invalid signature by the client certificate: " + err.Error())
		}

		if err := transcriptMsg(certVerify, &hs.finishedHash); err != nil {
			return err
		}
	}

	hs.finishedHash.discardHandshakeBuffer()
	return nil
}

// =============================================================================
// readNextFlightMsg — 带重传支持的握手消息读取
// =============================================================================

// readNextFlightMsg 读取下一条握手消息，支持重传处理。
// 在发送 Flight 4 后等待 Flight 5 时使用，处理以下情况：
//   1. 重传定时器超时：重发当前飞行数据
//   2. 收到 ClientHello：对端重传，重发当前飞行数据
//   3. 收到有效消息：正常处理
//
// 参数:
//   flightData - 当前飞行（Flight 4）的原始字节数据，用于重传
// 返回:
//   interface{} - 握手消息对象（非 ClientHello）
//   error - 错误信息
func (c *Conn) readNextFlightMsg(flightData []byte) (interface{}, error) {
	for {
		// 检查重传定时器
		if c.retransmitTimer.fired() {
			// 重发当前飞行
			if len(flightData) > 0 {
				if _, err := c.pconn.WriteTo(flightData, c.remoteAddr); err != nil {
					return nil, err
				}
			}
			c.retransmitTimer.backoff()
		}

		// 设置读取超时
		c.pconn.SetReadDeadline(time.Now().Add(c.retransmitTimer.current))

		msg, err := c.readHandshake(nil)
		if err == nil {
			// 成功读取消息，清除超时
			c.pconn.SetReadDeadline(time.Time{})

			// 检查是否收到对端重传（ClientHello）
			if _, ok := msg.(*clientHelloMsg); ok {
				// 对端从 Flight 1/3 重传，我们重发 Flight 4
				if len(flightData) > 0 {
					if _, err := c.pconn.WriteTo(flightData, c.remoteAddr); err != nil {
						return nil, err
					}
				}
				c.retransmitTimer.backoff()
				continue
			}

			c.retransmitTimer.stop()
			return msg, nil
		}

		// 超时处理
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			continue
		}
		return nil, err
	}
}

// =============================================================================
// establishKeys — 建立加密密钥
// =============================================================================

// establishKeys 根据主密钥派生工作密钥，设置输入输出加密状态。
func (hs *serverHandshakeState) establishKeys() error {
	c := hs.c

	workKey, clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
		keysFromMasterSecret(c.vers, hs.suite, hs.masterSecret, hs.clientHello.random, hs.hello.random, hs.suite.macLen, hs.suite.keyLen, hs.suite.ivLen)
	c.workKey = workKey

	var clientCipher, serverCipher interface{}
	var clientHash, serverHash hash.Hash

	if hs.suite.aead == nil {
		clientCipher = hs.suite.cipher(clientKey, clientIV, true)
		clientHash = hs.suite.mac(clientMAC)
		serverCipher = hs.suite.cipher(serverKey, serverIV, false)
		serverHash = hs.suite.mac(serverMAC)
	} else {
		clientCipher = hs.suite.aead(clientKey, clientIV)
		serverCipher = hs.suite.aead(serverKey, serverIV)
	}

	c.in.prepareCipherSpec(c.vers, clientCipher, clientHash)
	c.out.prepareCipherSpec(c.vers, serverCipher, serverHash)

	return nil
}

// =============================================================================
// sendFinished — 发送 CCS + Finished（Flight 6）
// =============================================================================

// sendFinished 发送 ChangeCipherSpec 和 Finished 消息。
// 参数 out 用于保存 verify_data，供后续验证使用。
func (hs *serverHandshakeState) sendFinished(out []byte) error {
	c := hs.c

	if err := c.writeChangeCipherRecord(); err != nil {
		return err
	}

	finished := new(finishedMsg)
	finished.verifyData = hs.finishedHash.serverSum(hs.masterSecret)
	finished.setMessageSeq(c.messageSeq)
	c.messageSeq++
	if _, err := c.writeHandshakeRecord(finished, &hs.finishedHash); err != nil {
		return err
	}

	copy(out, finished.verifyData)
	return nil
}

// =============================================================================
// readFinished — 读取客户端 CCS + Finished
// =============================================================================

// readFinished 读取客户端的 ChangeCipherSpec 和 Finished 消息，并验证 verify_data。
// 参数 out 用于保存客户端的 verify_data。
func (hs *serverHandshakeState) readFinished(out []byte) error {
	c := hs.c
	flightData := hs.flightData // 保存的 flight 数据，用于重传

	// 读取 ChangeCipherSpec
	for {
		if c.retransmitTimer.fired() {
			if len(flightData) > 0 {
				c.pconn.WriteTo(flightData, c.remoteAddr)
			}
			c.retransmitTimer.backoff()
		}
		c.pconn.SetReadDeadline(time.Now().Add(c.retransmitTimer.current))
		if err := c.readChangeCipherSpec(); err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return err
		}
		c.pconn.SetReadDeadline(time.Time{})
		c.retransmitTimer.stop()
		break
	}

	// 读取客户端的 Finished 消息（此时已切换解密密钥）
	// finishedMsg 不会加入哈希，直到验证通过
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
		return errors.New("dtlcp: client's Finished message is incorrect")
	}

	if err := transcriptMsg(clientFinished, &hs.finishedHash); err != nil {
		return err
	}
	copy(out, verify)
	return nil
}

// =============================================================================
// createSessionState — 创建会话缓存
// =============================================================================

// createSessionState 将会话参数保存到 SessionCache 中，用于后续会话重用。
func (hs *serverHandshakeState) createSessionState() {
	if hs.c.config.SessionCache == nil {
		return
	}

	sessionKey := hex.EncodeToString(hs.hello.sessionId)
	masterSecretCopy := make([]byte, len(hs.masterSecret))
	copy(masterSecretCopy, hs.masterSecret)
	cs := &SessionState{
		sessionId:        hs.hello.sessionId,
		vers:             hs.hello.vers,
		cipherSuite:      hs.hello.cipherSuite,
		masterSecret:     masterSecretCopy,
		peerCertificates: hs.peerCertificates,
		createdAt:        time.Now(),
	}
	hs.c.config.SessionCache.Put(sessionKey, cs)
}

// =============================================================================
// processCertsFromClient — 处理客户端证书
// =============================================================================

// processCertsFromClient 处理客户端证书链，进行证书验证。
func (c *Conn) processCertsFromClient(certificate Certificate) error {
	certificates := certificate.Certificate
	certs := make([]*x509.Certificate, len(certificates))
	var err error
	for i, asn1Data := range certificates {
		if certs[i], err = x509.ParseCertificate(asn1Data); err != nil {
			_ = c.sendAlert(alertBadCertificate)
			return errors.New("dtlcp: failed to parse client certificate: " + err.Error())
		}
	}

	if len(certs) == 0 && requiresClientCert(c.config.ClientAuth) {
		_ = c.sendAlert(alertBadCertificate)
		return errors.New("dtlcp: client didn't provide a certificate")
	}

	isECDHE := (c.cipherSuite == ECDHE_SM4_CBC_SM3 || c.cipherSuite == ECDHE_SM4_GCM_SM3)
	if len(certs) < 2 && isECDHE {
		_ = c.sendAlert(alertBadCertificate)
		return errors.New("dtlcp: client didn't provide both sign/enc certificates for ECDHE suite")
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

		start := 1
		if isECDHE {
			start = 2
		}
		for _, cert := range certs[start:] {
			opts.Intermediates.AddCert(cert)
		}

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

		if isECDHE && len(certs) > 1 {
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
			return fmt.Errorf("dtlcp: client auth certificate contains an unsupported public key of type %T", certs[0].PublicKey)
		}
		if isECDHE && len(certs) > 1 {
			switch certs[1].PublicKey.(type) {
			case *ecdsa.PublicKey, *rsa.PublicKey:
			default:
				_ = c.sendAlert(alertUnsupportedCertificate)
				return fmt.Errorf("dtlcp: client enc certificate contains an unsupported public key of type %T", certs[1].PublicKey)
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

// =============================================================================
// clientHelloInfo — 创建 ClientHelloInfo
// =============================================================================

// clientHelloInfo 根据 ClientHello 消息创建 ClientHelloInfo 结构，
// 用于 GetCertificate 和 GetConfigForClient 回调。
func clientHelloInfo(ctx context.Context, c *Conn, clientHello *clientHelloMsg) *ClientHelloInfo {
	supportedVers := supportedVersionsFromMax(clientHello.vers)
	return &ClientHelloInfo{
		CipherSuites:         clientHello.cipherSuites,
		ServerName:           clientHello.serverName,
		SupportedVersions:    supportedVers,
		TrustedCAIndications: clientHello.trustedAuthorities,
		Conn:                 c,
		config:               c.config,
		ctx:                  ctx,
	}
}

// =============================================================================
// negotiateALPN — 协商应用层协议
// =============================================================================

// negotiateALPN 按照服务端优先级从客户端的 ALPN 列表中选择一个双方都支持的协议。
//
// 参数:
//   serverProtos - 服务端支持的协议列表（按优先级顺序）
//   clientProtos - 客户端支持的协议列表
// 返回:
//   string - 协商出的协议，若双方都不支持 ALPN 则返回空字符串
//   error  - 若客户端请求的协议都不被服务端支持则返回错误
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
	if http11fallback {
		return "", nil
	}
	return "", fmt.Errorf("dtlcp: client requested unsupported application protocols (%s)", clientProtos)
}

// =============================================================================
// marshalForCookie — ClientHello cookie 序列化
// =============================================================================

// marshalForCookie 将 ClientHello 的字段（不含 cookie）序列化为字节序列，
// 用于 cookie 的生成和验证。序列化顺序：
//   version(2) + random(32) + sessionId(1+len) + cipherSuites(2+len*2) + compression(1+len)
//
// 返回:
//   []byte - 序列化后的字节序列
func (m *clientHelloMsg) marshalForCookie() []byte {
	total := 2 + 32 + 1 + len(m.sessionId) + 2 + len(m.cipherSuites)*2 + 1 + len(m.compressionMethods)
	b := make([]byte, 0, total)
	b = append(b, byte(m.vers>>8), byte(m.vers))
	b = append(b, m.random...)
	b = append(b, byte(len(m.sessionId)))
	b = append(b, m.sessionId...)
	b = append(b, byte(len(m.cipherSuites)>>8), byte(len(m.cipherSuites)))
	for _, cs := range m.cipherSuites {
		b = append(b, byte(cs>>8), byte(cs))
	}
	b = append(b, byte(len(m.compressionMethods)))
	b = append(b, m.compressionMethods...)
	return b
}
