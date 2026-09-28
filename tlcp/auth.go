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
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/sm9"
)

// 根据算法套件获取 签名算法 和对应的Hash函数
func typeAndHashFrom(suite uint16) (SignatureAlgorithm, func() hash.Hash, error) {
	switch suite {
	case ECC_SM4_CBC_SM3, ECC_SM4_GCM_SM3, ECDHE_SM4_CBC_SM3, ECDHE_SM4_GCM_SM3:
		return ECC_SM3, sm3.New, nil
	case IBC_SM4_CBC_SM3, IBC_SM4_GCM_SM3,
		IBSDH_SM4_CBC_SM3, IBSDH_SM4_GCM_SM3:
		return IBS_SM3, sm3.New, nil
	case RSA_SM4_CBC_SM3, RSA_SM4_GCM_SM3:
		return RSA_SM3, sm3.New, nil
	case RSA_SM4_CBC_SHA256, RSA_SM4_GCM_SHA256:
		return RSA_SHA256, sha256.New, nil
	default:
		return NONE, nil, fmt.Errorf("tlcp: unsupported certificate verify alg: %s", CipherSuiteName(suite))
	}
}

// verifyHandshakeSignature 验证握手消息的签名值
func verifyHandshakeSignature(sigType SignatureAlgorithm, pubkey crypto.PublicKey, h func() hash.Hash, tbs, sig []byte) error {
	switch sigType {
	case ECC_SM3:
		pubKey, ok := pubkey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("expected an ECC(SM2) public key, got %T", pubkey)
		}
		if !sm2.VerifyASN1WithSM2(pubKey, nil, tbs, sig) {
			return errors.New("SM2 verification failure")
		}
	case RSA_SHA256:
		pubKey, ok := pubkey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("expected an RSA public key, got %T", pubkey)
		}
		if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, tbs, sig); err != nil {
			return err
		}
	case RSA_SM3:
		// TODO: RSA_SM3 签名值校验
		return errors.New("unsupported handshake signature: RSA_SM3")
	case IBS_SM3:
		// SM9(IBS) 验签需要用户标识，无法仅凭公钥完成，
		// 请使用 verifyIBSHandshakeSignature。
		return errors.New("tlcp: IBS_SM3 verification requires a user identity")
	default:
		return errors.New("internal error: unknown signature type")
	}
	return nil
}

// signHandshake 对握手消息进行签名，产生签名值
func signHandshake(c *Conn, sigType SignatureAlgorithm, prvKey crypto.PrivateKey, newHash func() hash.Hash, tbs []byte) (sig []byte, err error) {
	key, ok := prvKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("client certificate private key not implement crypto.Signer")
	}
	var signOpts crypto.SignerOpts = nil
	switch sigType {
	case ECC_SM3:
		if _, ok := prvKey.(*sm2.PrivateKey); ok {
			// SM2密钥需要额外进行 H的Hash计算
			signOpts = sm2.NewSM2SignerOption(true, nil)
		}
	case RSA_SHA256:
		// TODO: RSA_SHA256 签名参数
	case RSA_SM3:
		// TODO: RSA_SM3 签名参数
	case IBS_SM3:
		// SM9 签名私钥实现了 crypto.Signer，其 Sign 直接对摘要签名，
		// 不需要额外的签名参数。
		if _, ok := prvKey.(*sm9.SignPrivateKey); !ok {
			return nil, fmt.Errorf("tlcp: IBS_SM3 handshake signature requires an SM9 sign private key, got %T", prvKey)
		}
	default:
		signOpts = nil
	}
	return key.Sign(c.config.rand(), tbs, signOpts)
}

// signIBSHandshake 使用 SM9 标识密码签名私钥对摘要 tbs 签名，
// 产生 SM9Signature（SEQUENCE { OCTET STRING h, BIT STRING s }）。
func signIBSHandshake(c *Conn, priv *sm9.SignPrivateKey, tbs []byte) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("tlcp: missing SM9 sign private key")
	}
	return priv.Sign(c.config.rand(), tbs, nil)
}

// verifyIBSHandshakeSignature 使用 SM9 标识密码签名主公钥与用户标识验签。
//
// 注意：绝不能直接使用对端带来的公钥验签，调用方必须先用本地信任池
// （Config.RootIBCSysParams / Config.ClientIBCSysParams）确认主公钥可信。
func verifyIBSHandshakeSignature(masterPub *sm9.SignMasterPublicKey, uid []byte, tbs, sig []byte) error {
	if masterPub == nil {
		return errors.New("tlcp: missing SM9 sign master public key")
	}
	if len(uid) == 0 {
		return errors.New("tlcp: missing SM9 user identity")
	}
	if !masterPub.Verify(uid, hidSM9Sign, tbs, sig) {
		return errors.New("tlcp: SM9(IBS) verification failure")
	}
	return nil
}
