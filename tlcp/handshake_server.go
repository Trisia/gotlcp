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

	"github.com/emmansun/gmsm/smx509"
)

// serverHandshakeState 服务端握手上下文，包含了服务端握手过程中需要的上下文参数
// 在握手结束后上下文参数应该被弃用。
type serverHandshakeState struct {
	c            *Conn           // 连接对象
	ctx          context.Context // 上下文
	clientHello  *clientHelloMsg // 服务端 Hello消息
	hello        *serverHelloMsg // 客户端 Hello消息
	suite        *cipherSuite    // 密码套件实现
	ecdheOk      bool            // 密钥状态 支持SM2密钥交换
	ecSignOk     bool            // 密钥状态 支持SM2签名
	ecDecryptOk  bool            // 密钥状态 支持SM2解密
	rsaDecryptOk bool            // 密钥状态 支持RSA解密
	rsaSignOk    bool            // 密钥状态 支持RSA签名
	sessionState *SessionState   // 会话状态
	finishedHash finishedHash    // 生成结束验证消息
	masterSecret []byte          // 主密钥
	// hasX509Cert 本端是否具备可用的 X.509 双证书。
	// 先由配置静态判定（见 Config.hasX509Certificates），再按证书选择的实际结果修正；
	// 非 IBC 套件必须以它为协商前提，仅有 IBC 身份时为 false。
	hasX509Cert      bool
	sigCert          *Certificate          // 签名证书
	encCert          *Certificate          // 加密证书
	peerCertificates []*smx509.Certificate // 客户端证书，可能为空

	// IBC 相关上下文，仅 IBC/IBSDH 套件下使用。
	ibcIdentity      *IBCIdentity  // 本端 IBC 配置
	ibcClientIDRaw   []byte        // client_id(66) 扩展中的原始标识字节
	peerIBCIdentity  []byte        // 客户端标识内容（identityData）
	peerIBCSysParams *IBCSysParams // 已命中本地信任池的客户端公共参数
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

	// 握手成功，对主密钥置零，握手重用基于会话缓存中的主密钥
	setZero(hs.masterSecret)
	hs.masterSecret = nil

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

	// client_id(66) 扩展：IBSDH 下服务端需要它来计算 R_A = r_A · Q_B。
	// 若最终选中的不是 IBSDH 套件，则该扩展被静默忽略。
	hs.ibcClientIDRaw = hs.clientHello.ibsdhClientID

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

	helloInfo := clientHelloInfo(hs.ctx, c, hs.clientHello)

	// 选择 IBC 配置：IBCIdentity 优先，其次向应用索取。
	if c.config.IBCIdentity != nil {
		hs.ibcIdentity = c.config.IBCIdentity
	} else if c.config.GetIBCIdentity != nil {
		ibcCfg, err := c.config.GetIBCIdentity(helloInfo)
		if err != nil {
			_ = c.sendAlert(alertInternalError)
			return err
		}
		hs.ibcIdentity = ibcCfg
	}

	// 凭据能力判定与证书选择。
	//
	// 本端是否具备 X.509 双证书能力由配置静态决定（Certificates / GetCertificate /
	// GetKECertificate），因此这里先判定能力、再按能力选择证书；不再通过
	// getCertificate 返回 errNoCertificates 后结合 ibcIdentity 是否非空来吞掉错误，
	// 也不再依赖 cipherSuiteOk 中 ecSignOk/ecDecryptOk 为 false 的副作用反推可用套件。
	hs.hasX509Cert = c.config.hasX509Certificates()
	if hs.hasX509Cert {
		// 证书选择回调可基于 SNI 拒绝提供证书，此时 selected 为 false，转入仅 IBC 模式。
		if hs.hasX509Cert, err = hs.selectX509Certificates(helloInfo); err != nil {
			return err
		}
	}
	if !hs.hasX509Cert && hs.ibcIdentity == nil {
		// 既无 X.509 双证书，也无 IBC 身份凭据，本次握手没有可用凭据。
		_ = c.sendAlert(alertUnrecognizedName)
		return errNoCertificates
	}

	return nil
}

// selectX509Certificates 选择服务端的签名证书与加密证书，并记录二者私钥的算法能力。
//
// 调用前应先用 Config.hasX509Certificates 判定配置中存在完整的 X.509 双证书来源。
// 与直接调用 Config.getCertificate/Config.getEKCertificate 的区别在于：
//   - 不把 errNoCertificates 当作致命错误，而是通过返回值 selected=false 报告
//     "证书来源本次未提供证书"（例如 GetCertificate 回调按 SNI 拒绝），
//     由调用方决定是转入仅 IBC 模式还是终止握手；
//   - 返回 selected=true 时保证 hs.sigCert 与 hs.encCert 均非 nil。
//
// 参数：
//   - helloInfo：客户端 Hello 消息信息，供证书选择回调使用。
//
// 返回值：
//   - selected：是否选出了可用的双证书；为 false 时 err 必为 nil。
//   - error：证书选择回调返回其它错误，或证书私钥算法不受支持时返回非 nil。
func (hs *serverHandshakeState) selectX509Certificates(helloInfo *ClientHelloInfo) (selected bool, err error) {
	c := hs.c

	sigCert, err := c.config.getCertificate(helloInfo)
	if err != nil {
		if err == errNoCertificates {
			return false, nil
		}
		_ = c.sendAlert(alertInternalError)
		return false, err
	}
	encCert, err := c.config.getEKCertificate(helloInfo)
	if err != nil {
		if err == errNoCertificates {
			return false, nil
		}
		_ = c.sendAlert(alertInternalError)
		return false, err
	}
	if sigCert == nil || encCert == nil {
		// 证书来源未报错却没有给出证书，按"本次未提供"处理。
		return false, nil
	}
	hs.sigCert, hs.encCert = sigCert, encCert

	if hs.clientHello.serverName != "" {
		// 服务端证书中的主机名与客户端提供的主机名匹配
		// 设置主机名ACK标志，发送ACK
		hs.hello.serverNameAck = true
	}

	if priv, ok := hs.sigCert.PrivateKey.(crypto.Signer); ok {
		switch priv.Public().(type) {
		case *ecdsa.PublicKey:
			hs.ecSignOk = true
		case *rsa.PublicKey:
			hs.rsaSignOk = true
		default:
			_ = c.sendAlert(alertInternalError)
			return false, fmt.Errorf("tlcp: unsupported signing key type (%T)", priv.Public())
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
			return false, fmt.Errorf("tlcp: unsupported decryption key type (%T)", priv.Public())
		}
	}

	return true, nil
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
	// IBC/IBSDH 套件不进默认推荐顺序，仅当服务端显式配置时参与协商。
	for _, id := range configCipherSuites {
		if cipherSuites[id].isIBC() && !containsUint16(preferenceList, id) {
			preferenceList = append(preferenceList, id)
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
	if c.flags&suiteIBC != 0 {
		// IBC 套件不依赖 X.509 证书，但要求本端具备 IBC 身份凭据；
		// IBSDH 还要求配置了密钥交换私钥（应为按 hid=0x02 派生的那一把，
		// 本库不校验派生 hid）。
		if hs.ibcIdentity == nil {
			return false
		}
		if c.flags&suiteIBSDH != 0 {
			return hs.ibcIdentity.canKeyExchange()
		}
		return true
	}
	// 非 IBC 套件都要求服务端提供 X.509 双证书。证书能力由 hasX509Cert 显式表达，
	// 不再借助 ecSignOk/ecDecryptOk 为 false 来隐式拒绝。
	if !hs.hasX509Cert {
		return false
	}
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

	// 恢复 IBC 上下文，用于填充 ConnectionState。
	// 重用握手不重新校验 IBCSysParams.validity。
	if len(hs.sessionState.ibcSysParams) > 0 {
		params, err := ParseIBCSysParams(hs.sessionState.ibcSysParams)
		if err != nil {
			_ = c.sendAlert(alertInternalError)
			return errors.New("tlcp: invalid IBC parameters in session state")
		}
		hs.peerIBCSysParams = params
		hs.peerIBCIdentity = hs.sessionState.ibcPeerIdentity
		c.peerIBCIdentity = hs.peerIBCIdentity
		c.peerIBCSysParams = params
	}

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
		return errors.New("tlcp: invalid master secret in session state")
	}

	return nil
}

func (hs *serverHandshakeState) doFullHandshake() error {
	c := hs.c

	if hs.sigCert != nil && hs.clientHello.ocspStapling && len(hs.sigCert.OCSPStaple) > 0 {
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
	if hs.suite.isIBC() {
		// GM/T 0024-2023 + 方案 §6.3：IBSDH 的密钥交换（genSignature=false）
		// 本身不校验客户端持有加密私钥，必须由 CertificateVerify 补齐。
		if hs.suite.id == IBSDH_SM4_CBC_SM3 || hs.suite.id == IBSDH_SM4_GCM_SM3 {
			if authPolice != RequestClientCert {
				authPolice = RequireAndVerifyClientCert
			}
		}
	} else if hs.suite.id == ECDHE_SM4_CBC_SM3 || hs.suite.id == ECDHE_SM4_GCM_SM3 {
		// 特别的根据  GM/T 38636-2016  6.4.5.8 要求：使用ECDHE算法时，要求客户端发送证书。
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

	if hs.suite.isIBC() {
		// GM/T 0024-2023 6.4.5.3：IBC 变体 Certificate 消息。
		ibcCertMsg, err := hs.ibcCertificateMessage()
		if err != nil {
			return c.sendAlertForError(err, alertInternalError)
		}
		if _, err := hs.c.writeHandshakeRecord(ibcCertMsg, &hs.finishedHash); err != nil {
			return err
		}
	} else {
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
	}

	keyAgreement := hs.suite.ka(c.vers)
	skx, err := keyAgreement.generateServerKeyExchange(hs)
	if err != nil {
		return c.sendAlertForError(err, alertHandshakeFailure)
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
		if hs.suite.isIBC() {
			// GM/T 0024-2023 6.4.5.5：certificate_types 取 ibc_params(80)，
			// certificate_authorities 为 IBC 密钥管理中心的信任域名列表。
			certReq.certificateTypes = []byte{byte(certTypeIbcParams)}
		} else {
			certReq.certificateTypes = []byte{
				byte(certTypeRSASign),
				byte(certTypeECDSASign),
			}
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
		if hs.suite.isIBC() {
			clientCertMsg, ok := msg.(*ibcCertificateMsg)
			if !ok {
				_ = c.sendAlert(alertUnexpectedMessage)
				return unexpectedMessageError(clientCertMsg, msg)
			}
			if err := hs.processClientIBCCertificate(clientCertMsg, requiresClientCert(authPolice)); err != nil {
				return err
			}
		} else {
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
		}
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

	// 对预主密钥进行内存清零
	setZero(preMasterSecret)

	// If we received a client sigCert in response to our certificate request message,
	// the client will send us a certificateVerifyMsg immediately after the
	// clientKeyExchangeMsg. This message is a digest of all preceding
	// handshake-layer messages that is signed using the private key corresponding
	// to the client's certificate. This allows us to verify that the client is in
	// possession of the private key of the certificate.
	if hs.suite.isIBC() {
		if len(c.peerIBCIdentity) > 0 {
			msg, err = c.readHandshake(nil)
			if err != nil {
				return err
			}
			certVerify, ok := msg.(*certificateVerifyMsg)
			if !ok {
				_ = c.sendAlert(alertUnexpectedMessage)
				return unexpectedMessageError(certVerify, msg)
			}
			// GM/T 0024-2023 6.4.5.9：对自 ClientHello 起至本消息之前的全部
			// 握手消息的 SM3 摘要做 SM9 签名（ibs_sm3）。
			signed := hs.finishedHash.Sum()
			if hs.peerIBCSysParams == nil {
				_ = c.sendAlert(alertHandshakeFailure)
				return errors.New("tlcp: missing client IBC parameters")
			}
			if err := verifyIBSHandshakeSignature(hs.peerIBCSysParams.SignMasterPublicKey, c.peerIBCIdentity, signed, certVerify.signature); err != nil {
				_ = c.sendAlert(alertBadCertificate)
				return errors.New("tlcp: invalid signature by the client identity: " + err.Error())
			}
			if err := transcriptMsg(certVerify, &hs.finishedHash); err != nil {
				return err
			}
		}
	} else if len(c.peerCertificates) > 0 {
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

	workKey, clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
		keysFromMasterSecret(c.vers, hs.suite, hs.masterSecret, hs.clientHello.random, hs.hello.random, hs.suite.macLen, hs.suite.keyLen, hs.suite.ivLen)
	c.workKey = workKey

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
	masterSecretCopy := make([]byte, len(hs.masterSecret))
	copy(masterSecretCopy, hs.masterSecret)
	cs := &SessionState{
		sessionId:        hs.hello.sessionId,
		vers:             hs.hello.vers,
		cipherSuite:      hs.hello.cipherSuite,
		masterSecret:     masterSecretCopy,
		peerCertificates: hs.peerCertificates,
		createdAt:        time.Now(),
		ibcPeerIdentity:  hs.peerIBCIdentity,
	}
	if hs.peerIBCSysParams != nil {
		cs.ibcSysParams = hs.peerIBCSysParams.Raw
	}
	hs.c.config.SessionCache.Put(sessionKey, cs)
}

// processCertsFromClient takes a chain of client certificates either from a
// Certificates message or from a sessionState and verifies them. It returns
// the public key of the leaf certificate.
// TODO: 需要进一步调整
func (c *Conn) processCertsFromClient(certificate Certificate) error {
	certificates := certificate.Certificate
	certs := make([]*smx509.Certificate, len(certificates))
	var err error
	for i, asn1Data := range certificates {
		if certs[i], err = smx509.ParseCertificate(asn1Data); err != nil {
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
		keyUsages := []smx509.ExtKeyUsage{smx509.ExtKeyUsageClientAuth, smx509.ExtKeyUsageServerAuth}
		if c.config.ClientAuth == RequireAndVerifyAnyKeyUsageClientCert {
			keyUsages = []smx509.ExtKeyUsage{smx509.ExtKeyUsageAny}
		}
		opts := smx509.VerifyOptions{
			Roots:         c.config.ClientCAs,
			CurrentTime:   c.config.time(),
			Intermediates: smx509.NewCertPool(),
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
			var errCertificateInvalid smx509.CertificateInvalidError
			if errors.As(err, &smx509.UnknownAuthorityError{}) {
				_ = c.sendAlert(alertUnknownCA)
			} else if errors.As(err, &errCertificateInvalid) && errCertificateInvalid.Reason == smx509.Expired {
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
				var errCertificateInvalid smx509.CertificateInvalidError
				if errors.As(err, &smx509.UnknownAuthorityError{}) {
					_ = c.sendAlert(alertUnknownCA)
				} else if errors.As(err, &errCertificateInvalid) && errCertificateInvalid.Reason == smx509.Expired {
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

// ibcCertificateMessage 构造服务端的 IBC 变体 Certificate 消息。
func (hs *serverHandshakeState) ibcCertificateMessage() (*ibcCertificateMsg, error) {
	if hs.ibcIdentity == nil {
		return nil, newIBCError(alertHandshakeFailure, "missing local IBC configuration")
	}
	if len(hs.ibcIdentity.Identity) == 0 {
		return nil, newIBCError(alertIdentityNeed, "missing local IBC identity")
	}
	if hs.ibcIdentity.Parameters == nil {
		return nil, newIBCError(alertBadIbcparam, "missing local IBC parameters")
	}
	der, err := hs.ibcIdentity.Parameters.Marshal()
	if err != nil {
		return nil, err
	}
	return &ibcCertificateMsg{ibcID: hs.ibcIdentity.Identity, ibcParameter: der}, nil
}

// processClientIBCCertificate 处理客户端回复的 IBC 变体 Certificate 消息。
//
// 客户端公共参数必须命中 Config.ClientIBCSysParams（或由回调判定）；
// 当 client_id(66) 扩展与 Certificate 中的标识同时出现时，比对标识内容，
// 不一致回 illegal_parameter(47)。
func (hs *serverHandshakeState) processClientIBCCertificate(certMsg *ibcCertificateMsg, required bool) error {
	c := hs.c
	if certMsg == nil || len(certMsg.ibcID) == 0 || len(certMsg.ibcParameter) == 0 {
		// 空标识/空参数表示客户端没有提供 IBC 证书。
		if required {
			_ = c.sendAlert(alertBadCertificate)
			return errors.New("tlcp: client didn't provide an IBC identity")
		}
		return nil
	}
	params, err := c.verifyPeerIBCSysParams(certMsg.ibcParameter, certMsg.ibcID, false,
		hs.ibcIdentity.sysParams())
	if err != nil {
		return err
	}
	identity := certMsg.identityContent()
	if len(hs.ibcClientIDRaw) > 0 {
		clientID := identityDataOf(hs.ibcClientIDRaw)
		if !bytes.Equal(clientID, identity) {
			_ = c.sendAlert(alertIllegalParameter)
			return newIBCError(alertIllegalParameter, "client_id extension and Certificate identity mismatch")
		}
	}
	hs.peerIBCIdentity = identity
	hs.peerIBCSysParams = params
	c.peerIBCIdentity = identity
	c.peerIBCSysParams = params
	return nil
}

func clientHelloInfo(ctx context.Context, c *Conn, clientHello *clientHelloMsg) *ClientHelloInfo {
	supportedVers := supportedVersionsFromMax(clientHello.vers)
	return &ClientHelloInfo{
		CipherSuites:         clientHello.cipherSuites,
		ServerName:           clientHello.serverName,
		SupportedVersions:    supportedVers,
		TrustedCAIndications: clientHello.trustedAuthorities,
		ClientID:             clientHello.ibsdhClientID,
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
