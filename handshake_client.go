// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tlcp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"fmt"
	x509 "github.com/emmansun/gmsm/smx509"
	"hash"
	"io"
	"sync/atomic"
)

type clientHandshakeState struct {
	c            *Conn
	ctx          context.Context
	serverHello  *serverHelloMsg
	hello        *clientHelloMsg
	suite        *cipherSuite
	finishedHash finishedHash
	masterSecret []byte
	session      *SessionState
}

func (c *Conn) makeClientHello() (*clientHelloMsg, error) {
	config := c.config
	if len(config.ServerName) == 0 && !config.InsecureSkipVerify {
		return nil, errors.New("tlcp: either ServerName or InsecureSkipVerify must be specified in the tls.Config")
	}

	supportVers := config.supportedVersions(roleClient)
	if len(supportVers) == 0 {
		return nil, errors.New("tlcp: no supported versions satisfy MinVersion and MaxVersion")
	}

	clientHelloVersion := config.maxSupportedVersion(roleClient)

	hello := &clientHelloMsg{
		vers:               clientHelloVersion,
		compressionMethods: []uint8{compressionNone},
		random:             make([]byte, 32),
		sessionId:          make([]byte, 32),
	}

	//if c.handshakes > 0 {
	//	hello.secureRenegotiation = c.clientFinished[:]
	//}

	preferenceOrder := cipherSuitesPreferenceOrder
	configCipherSuites := config.cipherSuites()
	hello.cipherSuites = make([]uint16, 0, len(configCipherSuites))

	for _, suiteId := range preferenceOrder {
		suite := mutualCipherSuite(configCipherSuites, suiteId)
		if suite == nil {
			continue
		}
		hello.cipherSuites = append(hello.cipherSuites, suiteId)
	}

	var err error
	hello.random, err = c.tlcpRand()
	if err != nil {
		return nil, errors.New("tlcp: short read from Rand: " + err.Error())
	}

	// A random session ID is used to detect when the server accepted a ticket
	// and is resuming a session (see RFC 5077). In TLS 1.3, it's always set as
	// a compatibility measure (see RFC 8446, Section 4.1.2).
	if _, err := io.ReadFull(config.rand(), hello.sessionId); err != nil {
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

	// TODO: 连接重用
	//cacheKey, session, earlySecret, binderKey := c.loadSession(hello)
	//if cacheKey != "" && session != nil {
	//	defer func() {
	//		// If we got a handshake failure when resuming a session, throw away
	//		// the session ticket. See RFC 5077, Section 3.2.
	//		//
	//		// RFC 8446 makes no mention of dropping tickets on failure, but it
	//		// does require servers to abort on invalid binders, so we need to
	//		// delete tickets to recover from a corrupted PSK.
	//		if err != nil {
	//			c.config.ClientSessionCache.Put(cacheKey, nil)
	//		}
	//	}()
	//}

	if _, err := c.writeRecord(recordTypeHandshake, hello.marshal()); err != nil {
		return err
	}

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}

	serverHello, ok := msg.(*serverHelloMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(serverHello, msg)
	}

	if err := c.pickTLSVersion(serverHello); err != nil {
		return err
	}

	//// If we are negotiating a protocol version that's lower than what we
	//// support, check for the server downgrade canaries.
	//// See RFC 8446, Section 4.1.3.
	//maxVers := c.config.maxSupportedVersion(roleClient)
	//tls12Downgrade := string(serverHello.random[24:]) == downgradeCanaryTLS12
	//tls11Downgrade := string(serverHello.random[24:]) == downgradeCanaryTLS11
	//if maxVers == VersionTLS13 && c.vers <= VersionTLS12 && (tls12Downgrade || tls11Downgrade) ||
	//	maxVers == VersionTLS12 && c.vers <= VersionTLS11 && tls11Downgrade {
	//	c.sendAlert(alertIllegalParameter)
	//	return errors.New("tlcp: downgrade attempt detected, possibly due to a MitM attack or a broken middlebox")
	//}
	//
	//if c.vers == VersionTLS13 {
	//	hs := &clientHandshakeStateTLS13{
	//		c:           c,
	//		ctx:         ctx,
	//		serverHello: serverHello,
	//		hello:       hello,
	//		ecdheParams: ecdheParams,
	//		session:     session,
	//		earlySecret: earlySecret,
	//		binderKey:   binderKey,
	//	}
	//
	//	// In TLS 1.3, session tickets are delivered after the handshake.
	//	return hs.handshake()
	//}

	hs := &clientHandshakeState{
		c:           c,
		ctx:         ctx,
		serverHello: serverHello,
		hello:       hello,
		//session:     session,
	}

	if err := hs.handshake(); err != nil {
		return err
	}

	//// If we had a successful handshake and hs.session is different from
	//// the one already cached - cache a new one.
	//if cacheKey != "" && hs.session != nil && session != hs.session {
	//	c.config.ClientSessionCache.Put(cacheKey, hs.session)
	//}

	return nil
}

func (c *Conn) loadSession(hello *clientHelloMsg) (cacheKey string, session *SessionState, earlySecret, binderKey []byte) {
	//if c.config.SessionTicketsDisabled || c.config.ClientSessionCache == nil {
	//	return "", nil, nil, nil
	//}
	//
	//hello.ticketSupported = true
	//
	//if hello.supportedVersions[0] == VersionTLS13 {
	//	// Require DHE on resumption as it guarantees forward secrecy against
	//	// compromise of the session ticket key. See RFC 8446, Section 4.2.9.
	//	hello.pskModes = []uint8{pskModeDHE}
	//}
	//
	//// Session resumption is not allowed if renegotiating because
	//// renegotiation is primarily used to allow a client to send a client
	//// certificate, which would be skipped if session resumption occurred.
	//if c.handshakes != 0 {
	//	return "", nil, nil, nil
	//}
	//
	//// Try to resume a previously negotiated TLS session, if available.
	//cacheKey = clientSessionCacheKey(c.conn.RemoteAddr(), c.config)
	//session, ok := c.config.ClientSessionCache.Get(cacheKey)
	//if !ok || session == nil {
	//	return cacheKey, nil, nil, nil
	//}
	//
	//// Check that version used for the previous session is still valid.
	//versOk := false
	//for _, v := range hello.supportedVersions {
	//	if v == session.vers {
	//		versOk = true
	//		break
	//	}
	//}
	//if !versOk {
	//	return cacheKey, nil, nil, nil
	//}
	//
	//// Check that the cached server certificate is not expired, and that it's
	//// valid for the ServerName. This should be ensured by the cache key, but
	//// protect the application from a faulty ClientSessionCache implementation.
	//if !c.config.InsecureSkipVerify {
	//	if len(session.verifiedChains) == 0 {
	//		// The original connection had InsecureSkipVerify, while this doesn't.
	//		return cacheKey, nil, nil, nil
	//	}
	//	serverCert := session.serverCertificates[0]
	//	if c.config.time().After(serverCert.NotAfter) {
	//		// Expired certificate, delete the entry.
	//		c.config.ClientSessionCache.Put(cacheKey, nil)
	//		return cacheKey, nil, nil, nil
	//	}
	//	if err := serverCert.VerifyHostname(c.config.ServerName); err != nil {
	//		return cacheKey, nil, nil, nil
	//	}
	//}
	//
	//if session.vers != VersionTLS13 {
	//	// In TLS 1.2 the cipher suite must match the resumed session. Ensure we
	//	// are still offering it.
	//	if mutualCipherSuite(hello.cipherSuites, session.cipherSuite) == nil {
	//		return cacheKey, nil, nil, nil
	//	}
	//
	//	hello.sessionTicket = session.sessionTicket
	//	return
	//}
	//
	//// Check that the session ticket is not expired.
	//if c.config.time().After(session.useBy) {
	//	c.config.ClientSessionCache.Put(cacheKey, nil)
	//	return cacheKey, nil, nil, nil
	//}
	//
	//// In TLS 1.3 the KDF hash must match the resumed session. Ensure we
	//// offer at least one cipher suite with that hash.
	//cipherSuite := cipherSuiteTLS13ByID(session.cipherSuite)
	//if cipherSuite == nil {
	//	return cacheKey, nil, nil, nil
	//}
	//cipherSuiteOk := false
	//for _, offeredID := range hello.cipherSuites {
	//	offeredSuite := cipherSuiteTLS13ByID(offeredID)
	//	if offeredSuite != nil && offeredSuite.hash == cipherSuite.hash {
	//		cipherSuiteOk = true
	//		break
	//	}
	//}
	//if !cipherSuiteOk {
	//	return cacheKey, nil, nil, nil
	//}
	//
	//// Set the pre_shared_key extension. See RFC 8446, Section 4.2.11.1.
	//ticketAge := uint32(c.config.time().Sub(session.receivedAt) / time.Millisecond)
	//identity := pskIdentity{
	//	label:               session.sessionTicket,
	//	obfuscatedTicketAge: ticketAge + session.ageAdd,
	//}
	//hello.pskIdentities = []pskIdentity{identity}
	//hello.pskBinders = [][]byte{make([]byte, cipherSuite.hash.Size())}
	//
	//// Compute the PSK binders. See RFC 8446, Section 4.2.11.2.
	//psk := cipherSuite.expandLabel(session.masterSecret, "resumption",
	//	session.nonce, cipherSuite.hash.Size())
	//earlySecret = cipherSuite.extract(psk, nil)
	//binderKey = cipherSuite.deriveSecret(earlySecret, resumptionBinderLabel, nil)
	//transcript := cipherSuite.hash.New()
	//transcript.Write(hello.marshalWithoutBinders())
	//pskBinders := [][]byte{cipherSuite.finishedHash(binderKey, transcript)}
	//hello.updateBinders(pskBinders)

	return
}

// 根据服务端消息选择客户端协议版本
func (c *Conn) pickTLSVersion(serverHello *serverHelloMsg) error {
	peerVersion := serverHello.vers

	vers, ok := c.config.mutualVersion(roleClient, []uint16{peerVersion})
	if !ok {
		c.sendAlert(alertProtocolVersion)
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

	hs.finishedHash.Write(hs.hello.marshal())
	hs.finishedHash.Write(hs.serverHello.marshal())

	c.buffering = true
	c.didResume = isResume
	if isResume {
		if err := hs.establishKeys(); err != nil {
			return err
		}
		if err := hs.readSessionTicket(); err != nil {
			return err
		}
		if err := hs.readFinished(c.serverFinished[:]); err != nil {
			return err
		}
		c.clientFinishedIsFirst = false
		// Make sure the connection is still being verified whether or not this
		// is a resumption. Resumptions currently don't reverify certificates so
		// they don't call verifyServerCertificate. See Issue 31641.
		if c.config.VerifyConnection != nil {
			if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
				c.sendAlert(alertBadCertificate)
				return err
			}
		}
		if err := hs.sendFinished(c.clientFinished[:]); err != nil {
			return err
		}
		if _, err := c.flush(); err != nil {
			return err
		}
	} else {
		if err := hs.doFullHandshake(); err != nil {
			return err
		}
		if err := hs.establishKeys(); err != nil {
			return err
		}
		if err := hs.sendFinished(c.clientFinished[:]); err != nil {
			return err
		}
		if _, err := c.flush(); err != nil {
			return err
		}
		c.clientFinishedIsFirst = true
		if err := hs.readSessionTicket(); err != nil {
			return err
		}
		if err := hs.readFinished(c.serverFinished[:]); err != nil {
			return err
		}
	}

	//c.ekm = ekmFromMasterSecret(c.vers, hs.suite, hs.masterSecret, hs.hello.random, hs.serverHello.random)
	atomic.StoreUint32(&c.handshakeStatus, 1)

	return nil
}

func (hs *clientHandshakeState) pickCipherSuite() error {
	if hs.suite = mutualCipherSuite(hs.hello.cipherSuites, hs.serverHello.cipherSuite); hs.suite == nil {
		hs.c.sendAlert(alertHandshakeFailure)
		return errors.New("tlcp: server chose an unconfigured cipher suite")
	}

	hs.c.cipherSuite = hs.suite.id
	return nil
}

func (hs *clientHandshakeState) doFullHandshake() error {
	c := hs.c

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	certMsg, ok := msg.(*certificateMsg)
	if !ok || len(certMsg.certificates) == 0 {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(certMsg, msg)
	}
	hs.finishedHash.Write(certMsg.marshal())

	msg, err = c.readHandshake()
	if err != nil {
		return err
	}

	if c.handshakes == 0 {
		// If this is the first handshake on a connection, process and
		// (optionally) verify the server's certificates.
		if err := c.verifyServerCertificate(certMsg.certificates); err != nil {
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
			c.sendAlert(alertBadCertificate)
			return errors.New("tlcp: server's identity changed during renegotiation")
		}
	}

	keyAgreement := hs.suite.ka(c.vers)

	skx, ok := msg.(*serverKeyExchangeMsg)
	if ok {
		hs.finishedHash.Write(skx.marshal())
		err = keyAgreement.processServerKeyExchange(c.config, hs.hello, hs.serverHello, c.peerCertificates, skx)
		if err != nil {
			c.sendAlert(alertUnexpectedMessage)
			return err
		}

		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
	}

	var chainToSend *Certificate
	var certRequested bool
	certReq, ok := msg.(*certificateRequestMsg)
	if ok {
		certRequested = true
		hs.finishedHash.Write(certReq.marshal())

		cri := &CertificateRequestInfo{AcceptableCAs: certReq.certificateAuthorities, Version: c.vers, ctx: hs.ctx}
		if chainToSend, err = c.getClientCertificate(cri); err != nil {
			c.sendAlert(alertInternalError)
			return err
		}

		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
	}

	shd, ok := msg.(*serverHelloDoneMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(shd, msg)
	}
	hs.finishedHash.Write(shd.marshal())

	// 如果服务端发送了证书请求消息，那么我们必须发送证书消息（客户端）
	// 即便客户端没有证书，也需要发一条空证书的证书消息到服务端。
	if certRequested {
		certMsg = new(certificateMsg)
		certMsg.certificates = chainToSend.Certificate
		hs.finishedHash.Write(certMsg.marshal())
		if _, err := c.writeRecord(recordTypeHandshake, certMsg.marshal()); err != nil {
			return err
		}
	}

	preMasterSecret, ckx, err := keyAgreement.generateClientKeyExchange(c.config, hs.hello, c.peerCertificates)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	if ckx != nil {
		hs.finishedHash.Write(ckx.marshal())
		if _, err := c.writeRecord(recordTypeHandshake, ckx.marshal()); err != nil {
			return err
		}
	}

	// 准备 客户端证书验证消息
	if chainToSend != nil && len(chainToSend.Certificate) > 0 {
		certVerify := &certificateVerifyMsg{}

		// 根据算法套件获取签名算法类型
		sigType, newHash, err := typeAndHashFrom(hs.suite.id)
		if !ok {
			c.sendAlert(alertInternalError)
			return fmt.Errorf("tlcp: client certificate private key of type %T does not implement crypto.Signer", chainToSend.PrivateKey)
		}
		// 计算从Hello开始至今的握手消息Hash
		signed := hs.finishedHash.Sum()
		// 根据算法套件使用密钥签名
		certVerify.signature, err = signHandshake(c, sigType, chainToSend.PrivateKey, newHash, signed)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}

		hs.finishedHash.Write(certVerify.marshal())
		if _, err := c.writeRecord(recordTypeHandshake, certVerify.marshal()); err != nil {
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
	// If the server responded with the same sessionId then it means the
	// sessionTicket is being used to resume a TLS session.
	return hs.session != nil && hs.hello.sessionId != nil &&
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
		c.sendAlert(alertUnexpectedMessage)
		return false, errors.New("tlcp: server selected unsupported compression format")
	}

	//if c.handshakes == 0 && hs.serverHello.secureRenegotiationSupported {
	//	c.secureRenegotiation = true
	//	if len(hs.serverHello.secureRenegotiation) != 0 {
	//		c.sendAlert(alertHandshakeFailure)
	//		return false, errors.New("tlcp: initial handshake had non-empty renegotiation extension")
	//	}
	//}

	//if c.handshakes > 0 && c.secureRenegotiation {
	//	var expectedSecureRenegotiation [24]byte
	//	copy(expectedSecureRenegotiation[:], c.clientFinished[:])
	//	copy(expectedSecureRenegotiation[12:], c.serverFinished[:])
	//	if !bytes.Equal(hs.serverHello.secureRenegotiation, expectedSecureRenegotiation[:]) {
	//		c.sendAlert(alertHandshakeFailure)
	//		return false, errors.New("tlcp: incorrect renegotiation extension contents")
	//	}
	//}

	if !hs.serverResumedSession() {
		return false, nil
	}

	if hs.session.vers != c.vers {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tlcp: server resumed a session with a different version")
	}

	if hs.session.cipherSuite != hs.suite.id {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tlcp: server resumed a session with a different cipher suite")
	}

	// Restore masterSecret, peerCerts, and ocspResponse from previous state
	hs.masterSecret = hs.session.masterSecret
	c.peerCertificates = hs.session.peerCertificates
	//c.verifiedChains = hs.session.verifiedChains
	//c.ocspResponse = hs.session.ocspResponse
	//// Let the ServerHello SCTs override the session SCTs from the original
	//// connection, if any are provided
	//if len(c.scts) == 0 && len(hs.session.scts) != 0 {
	//	c.scts = hs.session.scts
	//}
	return true, nil
}

// checkALPN ensure that the server's choice of ALPN protocol is compatible with
// the protocols that we advertised in the Client Hello.
func checkALPN(clientProtos []string, serverProto string) error {
	if serverProto == "" {
		return nil
	}
	if len(clientProtos) == 0 {
		return errors.New("tlcp: server advertised unrequested ALPN extension")
	}
	for _, proto := range clientProtos {
		if proto == serverProto {
			return nil
		}
	}
	return errors.New("tlcp: server selected unadvertised ALPN protocol")
}

func (hs *clientHandshakeState) readFinished(out []byte) error {
	c := hs.c

	if err := c.readChangeCipherSpec(); err != nil {
		return err
	}

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	serverFinished, ok := msg.(*finishedMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(serverFinished, msg)
	}

	verify := hs.finishedHash.serverSum(hs.masterSecret)
	if len(verify) != len(serverFinished.verifyData) ||
		subtle.ConstantTimeCompare(verify, serverFinished.verifyData) != 1 {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("tlcp: server's Finished message was incorrect")
	}
	hs.finishedHash.Write(serverFinished.marshal())
	copy(out, verify)
	return nil
}

// 生成Session会话信息，用于握手重用
func (hs *clientHandshakeState) readSessionTicket() error {
	//if !hs.serverHello.ticketSupported {
	//	return nil
	//}
	//
	//c := hs.c
	//msg, err := c.readHandshake()
	//if err != nil {
	//	return err
	//}
	//sessionTicketMsg, ok := msg.(*newSessionTicketMsg)
	//if !ok {
	//	c.sendAlert(alertUnexpectedMessage)
	//	return unexpectedMessageError(sessionTicketMsg, msg)
	//}
	//hs.finishedHash.Write(sessionTicketMsg.marshal())
	//
	//hs.session = &ClientSessionState{
	//	sessionTicket:      sessionTicketMsg.ticket,
	//	vers:               c.vers,
	//	cipherSuite:        hs.suite.id,
	//	masterSecret:       hs.masterSecret,
	//	serverCertificates: c.peerCertificates,
	//	verifiedChains:     c.verifiedChains,
	//	receivedAt:         c.config.time(),
	//	ocspResponse:       c.ocspResponse,
	//	scts:               c.scts,
	//}

	return nil
}

func (hs *clientHandshakeState) sendFinished(out []byte) error {
	c := hs.c

	if _, err := c.writeRecord(recordTypeChangeCipherSpec, []byte{1}); err != nil {
		return err
	}

	finished := new(finishedMsg)
	finished.verifyData = hs.finishedHash.clientSum(hs.masterSecret)
	hs.finishedHash.Write(finished.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, finished.marshal()); err != nil {
		return err
	}
	copy(out, finished.verifyData)
	return nil
}

// verifyServerCertificate 解析并验证服务端证书（签名,加密）
// c.verifiedChains and c.peerCertificates or sending the appropriate alert.
func (c *Conn) verifyServerCertificate(certificates [][]byte) error {
	certs := make([]*x509.Certificate, len(certificates))
	for i, asn1Data := range certificates {
		cert, err := x509.ParseCertificate(asn1Data)
		if err != nil {
			c.sendAlert(alertBadCertificate)
			return errors.New("tlcp: failed to parse certificate from server: " + err.Error())
		}
		certs[i] = cert
	}

	if len(certs) < 2 {
		c.sendAlert(alertBadCertificate)
		return errors.New("tlcp: need two of certificate one for sign one for encrypt")
	}

	if !c.config.InsecureSkipVerify {
		opts := x509.VerifyOptions{
			Roots:       c.config.RootCAs,
			CurrentTime: c.config.time(),
			DNSName:     c.config.ServerName,
		}

		var err error

		// 验证签名证书
		c.verifiedChains, err = certs[0].Verify(opts)
		if err != nil {
			c.sendAlert(alertBadCertificate)
			return err
		}
		// 验证加密证书
		_, err = certs[1].Verify(opts)
		if err != nil {
			c.sendAlert(alertBadCertificate)
			return err
		}
	}

	switch certs[0].PublicKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
		break
	default:
		c.sendAlert(alertUnsupportedCertificate)
		return fmt.Errorf("tlcp: server's certificate contains an unsupported type of public key: %T", certs[0].PublicKey)
	}

	c.peerCertificates = certs

	if c.config.VerifyPeerCertificate != nil {
		if err := c.config.VerifyPeerCertificate(certificates, c.verifiedChains); err != nil {
			c.sendAlert(alertBadCertificate)
			return err
		}
	}

	if c.config.VerifyConnection != nil {
		if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
			c.sendAlert(alertBadCertificate)
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

	for _, chain := range c.config.Certificates {
		if err := cri.SupportsCertificate(&chain); err != nil {
			continue
		}
		return &chain, nil
	}

	// No acceptable certificate found. Don't send a certificate.
	return new(Certificate), nil
}

//// hostnameInSNI converts name into an appropriate hostname for SNI.
//// Literal IP addresses and absolute FQDNs are not permitted as SNI values.
//// See RFC 6066, Section 3.
//func hostnameInSNI(name string) string {
//	host := name
//	if len(host) > 0 && host[0] == '[' && host[len(host)-1] == ']' {
//		host = host[1 : len(host)-1]
//	}
//	if i := strings.LastIndex(host, "%"); i > 0 {
//		host = host[:i]
//	}
//	if net.ParseIP(host) != nil {
//		return ""
//	}
//	for len(name) > 0 && name[len(name)-1] == '.' {
//		name = name[:len(name)-1]
//	}
//	return name
//}
