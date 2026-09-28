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
	"errors"
	"fmt"
	"io"

	"github.com/emmansun/gmsm/sm9"
	"golang.org/x/crypto/cryptobyte"
	cryptobyteasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// ibcPreMasterSecretLen TLCP 要求预主密钥为 48 字节。
//
// SM9 密钥交换协议的 KDF 输出长度由双方约定（GM/T 0044 测试向量用 16 字节），
// 48 字节是 TLCP 的特有要求。
const ibcPreMasterSecretLen = 48

// ibcKeyAgreement 实现 IBC 套件的密钥交换（GM/T 0024-2023 6.4.5.4 case IBC）。
//
// 服务端在 ServerKeyExchange 中仅发送对 client_random ‖ server_random ‖ ibc_id
// 的签名（GM/T 0024-2023 已删除 GB/T 38636-2020 的 ServerIBCSysParams 与
// IBCEncryptionKey 字段）；客户端用服务端 ibc_parameter 中的加密主公钥
// 加密 48 字节预主密钥。
type ibcKeyAgreement struct {
	// 客户端侧状态
	peerIdentityRaw []byte        // 服务端 ibc_id 原始报文字节
	peerIdentity    []byte        // 服务端标识内容（identityData）
	peerParams      *IBCSysParams // 已命中信任池的服务端参数
}

// generateServerKeyExchange 服务端生成 IBC 的 ServerKeyExchange。
func (ka *ibcKeyAgreement) generateServerKeyExchange(hs *serverHandshakeState) (*serverKeyExchangeMsg, error) {
	ibcCfg := hs.ibcIdentity
	if ibcCfg == nil || ibcCfg.SignPrivateKey == nil {
		return nil, errors.New("tlcp: IBC key exchange requires an IBC sign private key")
	}
	if len(ibcCfg.Identity) == 0 {
		return nil, errors.New("tlcp: IBC key exchange requires a local identity")
	}

	tbs := ibcSignedParams(hs.clientHello.random, hs.hello.random, ibcCfg.Identity)
	sig, err := signIBSHandshake(hs.c, ibcCfg.SignPrivateKey, tbs)
	if err != nil {
		return nil, err
	}

	ske := new(serverKeyExchangeMsg)
	ske.key = make([]byte, 2+len(sig))
	ske.key[0] = byte(len(sig) >> 8)
	ske.key[1] = byte(len(sig))
	copy(ske.key[2:], sig)
	return ske, nil
}

// processClientKeyExchange 服务端解密 IBC 的 ClientKeyExchange。
func (ka *ibcKeyAgreement) processClientKeyExchange(hs *serverHandshakeState, ckx *clientKeyExchangeMsg) ([]byte, error) {
	ibcCfg := hs.ibcIdentity
	if ibcCfg == nil || ibcCfg.EncryptPrivateKey == nil {
		return nil, errors.New("tlcp: IBC key exchange requires an IBC encrypt private key")
	}
	if len(ckx.ciphertext) < 2 {
		return nil, errClientKeyExchange
	}
	size := int(ckx.ciphertext[0])<<8 | int(ckx.ciphertext[1])
	if size+2 != len(ckx.ciphertext) {
		return nil, errClientKeyExchange
	}
	cipher := ckx.ciphertext[2:]
	if len(cipher) == 0 {
		return nil, errClientKeyExchange
	}

	preMasterSecret, err := sm9.DecryptASN1(ibcCfg.EncryptPrivateKey, ibcCfg.Identity, cipher)
	if err != nil {
		return nil, fmt.Errorf("tlcp: failed to decrypt IBC pre-master secret: %w", err)
	}
	if len(preMasterSecret) != ibcPreMasterSecretLen {
		return nil, newIBCError(alertBadIbcparam, "unexpected IBC pre-master secret length: %d", len(preMasterSecret))
	}
	return preMasterSecret, nil
}

// processServerKeyExchange 客户端验证 IBC 的 ServerKeyExchange 签名。
func (ka *ibcKeyAgreement) processServerKeyExchange(hs *clientHandshakeState, skx *serverKeyExchangeMsg) error {
	params := hs.peerIBCSysParams
	if params == nil || params.SignMasterPublicKey == nil {
		return errors.New("tlcp: missing server IBC parameters")
	}
	if len(skx.key) < 2 {
		return errServerKeyExchange
	}
	sigLen := int(skx.key[0])<<8 | int(skx.key[1])
	if sigLen+2 != len(skx.key) || sigLen == 0 {
		return errServerKeyExchange
	}
	sig := skx.key[2:]

	tbs := ibcSignedParams(hs.hello.random, hs.serverHello.random, hs.peerIBCIdentityRaw)
	if err := verifyIBSHandshakeSignature(params.SignMasterPublicKey, hs.peerIBCIdentity, tbs, sig); err != nil {
		return err
	}

	ka.peerIdentityRaw = hs.peerIBCIdentityRaw
	ka.peerIdentity = hs.peerIBCIdentity
	ka.peerParams = params
	return nil
}

// generateClientKeyExchange 客户端加密并发送 IBC 的 ClientKeyExchange。
func (ka *ibcKeyAgreement) generateClientKeyExchange(hs *clientHandshakeState) ([]byte, *clientKeyExchangeMsg, error) {
	if ka.peerParams == nil || ka.peerParams.EncryptMasterPublicKey == nil {
		return nil, nil, errServerKeyExchange
	}

	preMasterSecret := make([]byte, ibcPreMasterSecretLen)
	preMasterSecret[0] = byte(hs.hello.vers >> 8)
	preMasterSecret[1] = byte(hs.hello.vers)
	if _, err := io.ReadFull(hs.c.config.rand(), preMasterSecret[2:]); err != nil {
		return nil, nil, err
	}

	// 固定使用默认模式（opts=nil ⇒ encType=0 XOR）；解密端会从密文自读 encType。
	cipher, err := sm9.EncryptASN1(hs.c.config.rand(), ka.peerParams.EncryptMasterPublicKey,
		ka.peerIdentity, hidSM9Encrypt, preMasterSecret, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("tlcp: failed to encrypt IBC pre-master secret: %w", err)
	}

	ckx := new(clientKeyExchangeMsg)
	ckx.ciphertext = make([]byte, 2+len(cipher))
	ckx.ciphertext[0] = byte(len(cipher) >> 8)
	ckx.ciphertext[1] = byte(len(cipher))
	copy(ckx.ciphertext[2:], cipher)
	return preMasterSecret, ckx, nil
}

// ibsdhKeyAgreement 实现 IBSDH 套件的密钥交换（GM/T 0024-2023 6.4.5.4 case IBSDH）。
//
// 角色映射：TLCP 中服务端先发 ServerKeyExchange，因此服务端 = SM9 密钥交换的
// 发起方 A，客户端 = 响应方 B。发起方生成 R_A 只需响应方的用户公钥（由客户端标识
// 派生），不需要对方的临时公钥。
//
// 这里使用 genSignature=false：不使用 SM9 密钥交换协议自带的 S_A/S_B 确认
// （GM/T 0024-2023 的报文中没有承载它们的位置），服务端身份由 TLS 层的
// signed_params 保证，客户端持有性由 CertificateVerify 补齐。
type ibsdhKeyAgreement struct {
	// 服务端侧状态
	ke      sm9.KeyExchange
	localID []byte
	peerID  []byte

	// 客户端侧状态
	peerKeyInfo *KeyAgreementInfo
	peerHid     byte // 服务端 ServerIBSDHParams 中携带的 hid
}

// generateServerKeyExchange 服务端（发起方 A）生成 ServerIBSDHParams 与签名。
func (ka *ibsdhKeyAgreement) generateServerKeyExchange(hs *serverHandshakeState) (*serverKeyExchangeMsg, error) {
	ibcCfg := hs.ibcIdentity
	if ibcCfg == nil || ibcCfg.keyExchangeKey() == nil || ibcCfg.SignPrivateKey == nil {
		return nil, errors.New("tlcp: IBSDH key exchange requires IBC sign and key exchange private keys")
	}
	if len(hs.ibcClientIDRaw) == 0 {
		return nil, newIBCError(alertIdentityNeed, "IBSDH requires the client identity from the client_id extension")
	}

	localID := identityDataOf(ibcCfg.Identity)
	clientID := identityDataOf(hs.ibcClientIDRaw)
	if len(localID) == 0 || len(clientID) == 0 {
		return nil, newIBCError(alertIdentityNeed, "IBSDH requires non-empty identities")
	}

	// 服务端是 SM9 密钥交换的发起方 A，没有上游消息可读，hid 取协议固定值
	// hidSM9KeyExch(0x02)；该值随 ServerIBSDHParams 下发给客户端，客户端（响应方 B）
	// 直接使用消息中的 hid。本库不校验本端私钥的派生 hid，由调用方保证一致。
	hid := hidSM9KeyExch
	ke := ibcCfg.keyExchangeKey().NewKeyExchange(localID, clientID, ibcPreMasterSecretLen, false)
	rA, err := ke.InitKeyExchange(hs.c.config.rand(), hid)
	if err != nil {
		ke.Destroy()
		return nil, fmt.Errorf("tlcp: IBSDH InitKeyExchange failed: %w", err)
	}
	ka.ke = ke
	ka.localID = localID
	ka.peerID = clientID

	params, err := marshalKeyAgreementInfo(&KeyAgreementInfo{
		Version:  keyAgreementInfoVersionV1,
		TempKey:  rA,
		UserID_A: localID,
		UserID_B: clientID,
		Hid:      hid,
	})
	if err != nil {
		return nil, err
	}

	tbs := ibsdhSignedParams(hs.clientHello.random, hs.hello.random, params)
	sig, err := signIBSHandshake(hs.c, ibcCfg.SignPrivateKey, tbs)
	if err != nil {
		return nil, err
	}

	ske := new(serverKeyExchangeMsg)
	ske.key = make([]byte, 0, len(params)+2+len(sig))
	ske.key = append(ske.key, params...)
	ske.key = append(ske.key, byte(len(sig)>>8), byte(len(sig)))
	ske.key = append(ske.key, sig...)
	return ske, nil
}

// processClientKeyExchange 服务端（发起方 A）处理 ClientIBSDHParams 并协商预主密钥。
func (ka *ibsdhKeyAgreement) processClientKeyExchange(hs *serverHandshakeState, ckx *clientKeyExchangeMsg) ([]byte, error) {
	if ka.ke == nil {
		return nil, errClientKeyExchange
	}
	if len(ckx.ciphertext) < 2 {
		return nil, errClientKeyExchange
	}
	size := int(ckx.ciphertext[0])<<8 | int(ckx.ciphertext[1])
	if size+2 != len(ckx.ciphertext) {
		return nil, errClientKeyExchange
	}
	info, err := parseKeyAgreementInfo(ckx.ciphertext[2:])
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(identityDataOf(info.UserID_A), ka.localID) {
		return nil, newIBCError(alertBadIbcparam, "IBSDH userID_A does not match the server identity")
	}
	if !bytes.Equal(identityDataOf(info.UserID_B), ka.peerID) {
		return nil, newIBCError(alertBadIbcparam, "IBSDH userID_B does not match the client identity")
	}
	// 有意不校验客户端回传的 info.Hid：发起方的 hid 已由本端决定（hidSM9KeyExch），
	// 若客户端使用了不一致的 hid，双方预主密钥不同，会在 Finished 阶段失败。

	key, _, err := ka.ke.ConfirmResponder(info.TempKey, nil)
	if err != nil {
		return nil, fmt.Errorf("tlcp: IBSDH ConfirmResponder failed: %w", err)
	}
	ka.ke.Destroy()
	ka.ke = nil
	if len(key) != ibcPreMasterSecretLen {
		return nil, newIBCError(alertBadIbcparam, "unexpected IBSDH pre-master secret length: %d", len(key))
	}
	return key, nil
}

// processServerKeyExchange 客户端（响应方 B）解析 ServerIBSDHParams 并验证签名。
func (ka *ibsdhKeyAgreement) processServerKeyExchange(hs *clientHandshakeState, skx *serverKeyExchangeMsg) error {
	info, consumed, err := parseKeyAgreementInfoPrefix(skx.key)
	if err != nil {
		return err
	}
	if len(skx.key) < consumed+2 {
		return errServerKeyExchange
	}
	sigLen := int(skx.key[consumed])<<8 | int(skx.key[consumed+1])
	if sigLen == 0 || consumed+2+sigLen != len(skx.key) {
		return errServerKeyExchange
	}
	sig := skx.key[consumed+2:]

	params := hs.peerIBCSysParams
	if params == nil || params.SignMasterPublicKey == nil {
		return errors.New("tlcp: missing server IBC parameters")
	}
	tbs := ibsdhSignedParams(hs.hello.random, hs.serverHello.random, skx.key[:consumed])
	if err := verifyIBSHandshakeSignature(params.SignMasterPublicKey, hs.peerIBCIdentity, tbs, sig); err != nil {
		return err
	}
	// 响应方 B 直接使用消息中的 hid：ServerIBSDHParams 整体被服务端签名覆盖
	// （signed_params = client_random ‖ server_random ‖ params），签名已在上方校验通过，
	// 因此该值不可被篡改。本库不做取值校验（不要求等于 0x02）。
	ka.peerKeyInfo = info
	ka.peerHid = info.Hid
	return nil
}

// generateClientKeyExchange 客户端（响应方 B）生成 ClientIBSDHParams 并协商预主密钥。
func (ka *ibsdhKeyAgreement) generateClientKeyExchange(hs *clientHandshakeState) ([]byte, *clientKeyExchangeMsg, error) {
	if ka.peerKeyInfo == nil {
		return nil, nil, errServerKeyExchange
	}
	ibcCfg := hs.ibcIdentity
	if ibcCfg == nil || ibcCfg.keyExchangeKey() == nil {
		return nil, nil, errors.New("tlcp: IBSDH key exchange requires an IBC key exchange private key")
	}

	localID := identityDataOf(ibcCfg.Identity)
	peerID := hs.peerIBCIdentity
	if len(localID) == 0 || len(peerID) == 0 {
		return nil, nil, newIBCError(alertIdentityNeed, "IBSDH requires non-empty identities")
	}

	// 响应方 B 的 hid 取自服务端下发的 ServerIBSDHParams（已在 processServerKeyExchange
	// 中随签名一并校验），本库不校验其取值，也不使用本端常量。
	hid := ka.peerHid
	ke := ibcCfg.keyExchangeKey().NewKeyExchange(localID, peerID, ibcPreMasterSecretLen, false)
	rB, _, err := ke.RespondKeyExchange(hs.c.config.rand(), hid, ka.peerKeyInfo.TempKey)
	if err != nil {
		ke.Destroy()
		return nil, nil, fmt.Errorf("tlcp: IBSDH RespondKeyExchange failed: %w", err)
	}
	preMasterSecret, err := ke.ConfirmInitiator(nil)
	if err != nil {
		ke.Destroy()
		return nil, nil, fmt.Errorf("tlcp: IBSDH ConfirmInitiator failed: %w", err)
	}
	ke.Destroy()
	if len(preMasterSecret) != ibcPreMasterSecretLen {
		return nil, nil, newIBCError(alertBadIbcparam, "unexpected IBSDH pre-master secret length: %d", len(preMasterSecret))
	}

	der, err := marshalKeyAgreementInfo(&KeyAgreementInfo{
		Version:  keyAgreementInfoVersionV1,
		TempKey:  rB,
		UserID_A: peerID,
		UserID_B: localID,
		Hid:      hid,
	})
	if err != nil {
		return nil, nil, err
	}

	ckx := new(clientKeyExchangeMsg)
	ckx.ciphertext = make([]byte, 2+len(der))
	ckx.ciphertext[0] = byte(len(der) >> 8)
	ckx.ciphertext[1] = byte(len(der))
	copy(ckx.ciphertext[2:], der)
	return preMasterSecret, ckx, nil
}

// parseKeyAgreementInfoPrefix 从字节流开头解析一个 DER 编码的 KeyAgreementInfo，
// 并返回其占用的字节数（用于在同一字节流中定位后续的 signed_params）。
func parseKeyAgreementInfoPrefix(data []byte) (*KeyAgreementInfo, int, error) {
	s := cryptobyte.String(data)
	var elem cryptobyte.String
	if !s.ReadASN1Element(&elem, cryptobyteasn1.SEQUENCE) {
		return nil, 0, errServerKeyExchange
	}
	consumed := len(data) - len(s)
	info, err := parseKeyAgreementInfo(elem)
	if err != nil {
		return nil, 0, err
	}
	return info, consumed, nil
}
