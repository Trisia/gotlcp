// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tlcp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/emmansun/gmsm/sm3"
	"hash"
)

func typeAndHashFrom(suite uint16) (SignatureAlgorithm, func() hash.Hash, error) {
	switch suite {
	case TLCP_ECC_SM4_CBC_SM3, TLCP_ECC_SM4_GCM_SM3:
		return ECC_SM3, sm3.New, nil
	case TLCP_IBC_SM4_CBC_SM3, TLCP_IBC_SM4_GCM_SM3:
		return IBS_SM3, sm3.New, nil
	case TLCP_RSA_SM4_CBC_SM3, TLCP_RSA_SM4_GCM_SM3:
		return RSA_SM3, sm3.New, nil
	case TLCP_RSA_SM4_CBC_SHA256, TLCP_RSA_SM4_GCM_SHA256:
		return RSA_SHA256, sha256.New, nil
	case TLCP_ECDHE_SM4_CBC_SM3, TLCP_ECDHE_SM4_GCM_SM3:
		fallthrough
	case TLCP_IBSDH_SM4_CBC_SM3, TLCP_IBSDH_SM4_GCM_SM3:
		fallthrough
	default:
		return NONE, nil, fmt.Errorf("tlcp: unsupported certificate verify alg: %d", suite)
	}
}

// verifyHandshakeSignature 验证握手消息的签名值
func verifyHandshakeSignature(sigType SignatureAlgorithm, pubkey crypto.PublicKey, hashFunc func() hash.Hash, signed, sig []byte) error {
	switch sigType {
	case ECC_SM3:
		pubKey, ok := pubkey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("expected an ECC(SM2) public key, got %T", pubkey)
		}
		if !ecdsa.VerifyASN1(pubKey, signed, sig) {
			return errors.New("ECDSA verification failure")
		}
	case RSA_SHA256:
		pubKey, ok := pubkey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("expected an RSA public key, got %T", pubkey)
		}
		if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, signed, sig); err != nil {
			return err
		}
	case RSA_SM3:
		// TODO: RSA_SM3 签名值校验
		return errors.New("RSA_SM3 Handshake Signature no support!")
	case IBS_SM3:
		// TODO: IBS_SM3 签名值校验
		return errors.New("IBS_SM3 Handshake Signature no support!")
	default:
		return errors.New("internal error: unknown signature type")
	}
	return nil
}
