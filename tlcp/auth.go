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
)

// 根据算法套件获取 签名算法 和对应的Hash函数
func typeAndHashFrom(suite uint16) (SignatureAlgorithm, func() hash.Hash, error) {
	switch suite {
	case ECC_SM4_CBC_SM3, ECC_SM4_GCM_SM3, ECDHE_SM4_CBC_SM3, ECDHE_SM4_GCM_SM3:
		return ECC_SM3, sm3.New, nil
	case IBC_SM4_CBC_SM3, IBC_SM4_GCM_SM3:
		return IBS_SM3, sm3.New, nil
	case RSA_SM4_CBC_SM3, RSA_SM4_GCM_SM3:
		return RSA_SM3, sm3.New, nil
	case RSA_SM4_CBC_SHA256, RSA_SM4_GCM_SHA256:
		return RSA_SHA256, sha256.New, nil
	case IBSDH_SM4_CBC_SM3, IBSDH_SM4_GCM_SM3:
		fallthrough
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
		// TODO: IBS_SM3 签名值校验
		return errors.New("unsupported handshake signature: IBS_SM3")
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
		// TODO: IBS_SM3 签名参数
	default:
		signOpts = nil
	}
	return key.Sign(c.config.rand(), tbs, signOpts)
}
