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
	"crypto"
	"crypto/ecdsa"
	"errors"
	"github.com/emmansun/gmsm/sm2"
	x509 "github.com/emmansun/gmsm/smx509"
	"io"
	"math/big"
)

// a keyAgreement implements the client and server side of a TLS key agreement
// protocol by generating and processing key exchange messages.
type keyAgreement interface {
	// 服务端侧

	// 生成服务端密钥加交换消息
	// config: 配置
	// certs: 证书列表 {签名证书,加密证书}
	// msg: 服务端Hello消息
	generateServerKeyExchange(*Config, []*Certificate, *clientHelloMsg, *serverHelloMsg) (*serverKeyExchangeMsg, error)
	// 处理客户端密钥交换消息
	// config: 配置
	// certs: 证书列表 {签名证书,加密证书}
	// msg: 客户端密钥交换消息
	// ver: 协议版本号
	processClientKeyExchange(*Config, []*Certificate, *clientKeyExchangeMsg, uint16) ([]byte, error)

	// 客户端侧

	// 处理服务端密钥交换消息
	// config: 配置
	// clientHello: 客户端Hello消息
	// serverHello: 服务端Hello消息
	// certs: 服务端证书列表 {签名证书,加密证书}
	// msg: 服务端密钥交换消息
	processServerKeyExchange(*Config, *clientHelloMsg, *serverHelloMsg, []*x509.Certificate, *serverKeyExchangeMsg) error
	// 生成客户端密钥交换消息
	// config: 配置
	// clientHello: 客户端Hello消息
	// certs: 服务端证书列表 {签名证书,加密证书}
	generateClientKeyExchange(*Config, *clientHelloMsg, []*x509.Certificate) ([]byte, *clientKeyExchangeMsg, error)
}

var errClientKeyExchange = errors.New("tlcp: invalid ClientKeyExchange message")
var errServerKeyExchange = errors.New("tlcp: invalid ServerKeyExchange message")

// eccKeyAgreement SM2密钥交换，公钥加密预主密钥，私钥解密。
type eccKeyAgreement struct {
	version    uint16
	privateKey []byte
	curveid    CurveID

	publicKey []byte
	x, y      *big.Int

	// 加密证书
	encipherCert *x509.Certificate
}

func (e *eccKeyAgreement) generateServerKeyExchange(config *Config, certs []*Certificate, clientHello *clientHelloMsg, serverHello *serverHelloMsg) (*serverKeyExchangeMsg, error) {

	if len(certs) < 2 {
		return nil, errors.New("tlcp: ecc key exchange need 2 certificates")
	}
	sigCert := certs[0]
	encCert := certs[1]

	/*
			digitally-signed struct {
				opaque client_random[32];
				opaque server_random[32];
				opaque ASN.1Cert<1..2^24-1>;
			}signed_params

			 GM/T 38636-2016 6.4.5.4 Server Key Exchange消息
		 		e) signed_params
		 		当密钥交换方式为ECC和RSA时，signed_params是服务端对双方
		 		随机数和服务端加密证书的签名。
	*/

	// 组装签名数据
	msg := e.hashForServerKeyExchange(clientHello.random, serverHello.random, encCert.Certificate[0])

	priv, ok := sigCert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("tlcp: certificate private key does not implement crypto.Signer")
	}
	sig, err := priv.Sign(config.rand(), msg, &sm2.SM2SignerOption{ForceGMSign: true})
	if err != nil {
		return nil, err
	}

	//fmt.Printf("server [src]>> %02X\n", msg)
	//fmt.Printf("server [sig]>> %02X\n", sig)

	ske := new(serverKeyExchangeMsg)
	size := len(sig)
	ske.key = make([]byte, size+2)
	ske.key[0] = byte(size >> 8)
	ske.key[1] = byte(size & 0xFF)
	copy(ske.key[2:], sig)

	return ske, nil
}

func (e *eccKeyAgreement) processClientKeyExchange(config *Config, certs []*Certificate, ckx *clientKeyExchangeMsg, version uint16) ([]byte, error) {
	if len(certs) < 2 {
		return nil, errors.New("tlcp: ecc key exchange need 2 certificates")
	}
	encCert := certs[1]

	if len(ckx.ciphertext) == 0 {
		return nil, errClientKeyExchange
	}

	size := int(ckx.ciphertext[0]) << 8
	size |= int(ckx.ciphertext[1])

	if 2+size != len(ckx.ciphertext) {
		return nil, errClientKeyExchange
	}

	cipher := ckx.ciphertext[2:]

	decrypter, ok := encCert.PrivateKey.(crypto.Decrypter)
	if !ok {
		return nil, errors.New("tlcp: certificate private key does not implement crypto.Decrypter")
	}
	plain, err := decrypter.Decrypt(config.rand(), cipher, &sm2.DecrypterOpts{CiphertextEncoding: sm2.ENCODING_ASN1})
	if err != nil {
		return nil, err
	}

	if len(plain) != 48 {
		return nil, errClientKeyExchange
	}

	return plain, nil
}

func (e *eccKeyAgreement) processServerKeyExchange(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, certs []*x509.Certificate, skx *serverKeyExchangeMsg) error {
	if len(certs) < 2 {
		return errors.New("tlcp: ecc key exchange need 2 certificates")
	}
	sigCert := certs[0]
	encCert := certs[1]

	if len(skx.key) <= 2 {
		return errServerKeyExchange
	}
	sigLen := int(skx.key[0]) << 8
	sigLen |= int(skx.key[1])
	if sigLen+2 != len(skx.key) {
		return errServerKeyExchange
	}

	sig := skx.key[2:]

	pub, ok := sigCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("tlcp: sm2 signing requires a sm2 public key")
	}

	// 组装签名数据
	tbs := e.hashForServerKeyExchange(clientHello.random, serverHello.random, encCert.Raw)

	//fmt.Printf("client [src]>> %02X\n", tbs)
	//fmt.Printf("client [sig]>> %02X\n", sig)

	if !sm2.VerifyASN1WithSM2(pub, nil, tbs, sig) {
		return errors.New("tlcp: processServerKeyExchange: sm2 verification failure")
	}
	return nil
}

func (e *eccKeyAgreement) generateClientKeyExchange(config *Config, clientHello *clientHelloMsg, certs []*x509.Certificate) ([]byte, *clientKeyExchangeMsg, error) {
	if len(certs) < 2 {
		return nil, nil, errors.New("tlcp: ecc key exchange need 2 certificates")
	}
	encCert := certs[1]

	preMasterSecret := make([]byte, 48)
	preMasterSecret[0] = byte(clientHello.vers >> 8)
	preMasterSecret[1] = byte(clientHello.vers)
	_, err := io.ReadFull(config.rand(), preMasterSecret[2:])
	if err != nil {
		return nil, nil, err
	}

	pub := encCert.PublicKey.(*ecdsa.PublicKey)
	encrypted, err := sm2.Encrypt(config.rand(), pub, preMasterSecret, sm2.ASN1EncrypterOpts)
	if err != nil {
		return nil, nil, err
	}

	ckx := new(clientKeyExchangeMsg)
	size := len(encrypted)
	ckx.ciphertext = make([]byte, len(encrypted)+2)
	ckx.ciphertext[0] = byte(size >> 8)
	ckx.ciphertext[1] = byte(size & 0xFF)
	copy(ckx.ciphertext[2:], encrypted)
	return preMasterSecret, ckx, nil
}

// GM/T 38636-2016 Server Key Exchange 组装待签名数据
func (e *eccKeyAgreement) hashForServerKeyExchange(clientRandom, serverRandom, cert []byte) []byte {
	/*
		struct {
			opaque client_random[32];
			opaque server_random[32];
			opaque ASN.1Cert<1..2^24-1>;
		}params
	*/
	buffer := new(bytes.Buffer)
	buffer.Write(clientRandom)
	buffer.Write(serverRandom)

	certLen := len(cert)
	buffer.Write([]byte{
		byte(certLen>>16) & 0xFF,
		byte(certLen>>8) & 0xFF,
		byte(certLen),
	})
	buffer.Write(cert)

	return buffer.Bytes()
}
