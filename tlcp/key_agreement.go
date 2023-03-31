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
	"fmt"
	"io"
	"math/big"

	"github.com/emmansun/gmsm/ecdh"
	"github.com/emmansun/gmsm/sm2"
	x509 "github.com/emmansun/gmsm/smx509"
)

// 密钥协商接口，实现了客户端 或 服务端的密钥协商协议
type keyAgreementProtocol interface {
	// 服务端侧

	// 生成服务端密钥加交换消息
	// config: 配置
	// certs: 证书列表 {签名证书,加密证书}
	// msg: 服务端Hello消息
	generateServerKeyExchange(*serverHandshakeState) (*serverKeyExchangeMsg, error)
	// 处理客户端密钥交换消息
	// config: 配置
	// certs: 证书列表 {签名证书,加密证书}
	// msg: 客户端密钥交换消息
	// ver: 协议版本号
	processClientKeyExchange(*serverHandshakeState, *clientKeyExchangeMsg) ([]byte, error)

	// 客户端侧

	// 处理服务端密钥交换消息
	// config: 配置
	// clientHello: 客户端Hello消息
	// serverHello: 服务端Hello消息
	// certs: 服务端证书列表 {签名证书,加密证书}
	// msg: 服务端密钥交换消息
	processServerKeyExchange(*clientHandshakeState, *serverKeyExchangeMsg) error
	// 生成客户端密钥交换消息
	// config: 配置
	// clientHello: 客户端Hello消息
	// certs: 服务端证书列表 {签名证书,加密证书}
	generateClientKeyExchange(*clientHandshakeState) ([]byte, *clientKeyExchangeMsg, error)
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

func (e *eccKeyAgreement) generateServerKeyExchange(hs *serverHandshakeState) (*serverKeyExchangeMsg, error) {
	sigCert := hs.sigCert
	encCert := hs.encCert
	if sigCert == nil && encCert == nil {
		return nil, errors.New("tlcp: ecc key exchange need 2 certificates")
	}
	config := hs.c.config
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
	msg := e.hashForServerKeyExchange(hs.clientHello.random, hs.hello.random, encCert.Certificate[0])

	priv, ok := sigCert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("tlcp: certificate private key does not implement crypto.Signer")
	}
	sig, err := priv.Sign(config.rand(), msg, sm2.NewSM2SignerOption(true, nil))
	if err != nil {
		return nil, err
	}

	ske := new(serverKeyExchangeMsg)
	size := len(sig)
	ske.key = make([]byte, size+2)
	ske.key[0] = byte(size >> 8)
	ske.key[1] = byte(size & 0xFF)
	copy(ske.key[2:], sig)

	return ske, nil
}

func (e *eccKeyAgreement) processClientKeyExchange(hs *serverHandshakeState, ckx *clientKeyExchangeMsg) ([]byte, error) {
	sigCert := hs.sigCert
	encCert := hs.encCert
	if sigCert == nil && encCert == nil {
		return nil, errors.New("tlcp: ecc key exchange need 2 certificates")
	}
	config := hs.c.config

	if len(ckx.ciphertext) == 0 {
		return nil, errClientKeyExchange
	}

	size := int(ckx.ciphertext[0]) << 8
	size |= int(ckx.ciphertext[1])

	if 2+size != len(ckx.ciphertext) {
		return nil, errClientKeyExchange
	}

	cipher := ckx.ciphertext[2:]
	if cipher[0] != 0x30 {
		return nil, errors.New("tlcp: bad client key exchange ciphertext format")
	}

	// 此处兼容C1C3C2 ASN1 报文中含有而外填充内容
	// 长形式也不会超过255， 3+32 + 3+32 + 3+32 + 3+48
	// ASN.1 Seq: tag(1B)+ length(1B+1B) = 3
	// ContentsLength fixed: 0x8001
	length := 3 + int(cipher[2])
	if len(cipher) >= length {
		cipher = cipher[:length]
	}

	decrypter, ok := encCert.PrivateKey.(crypto.Decrypter)
	if !ok {
		return nil, errors.New("tlcp: certificate private key does not implement crypto.Decrypter")
	}
	plain, err := decrypter.Decrypt(config.rand(), cipher, sm2.ASN1DecrypterOpts)
	if err != nil {
		return nil, err
	}

	if len(plain) != 48 {
		return nil, errClientKeyExchange
	}

	return plain, nil
}

func (e *eccKeyAgreement) processServerKeyExchange(hs *clientHandshakeState, skx *serverKeyExchangeMsg) error {
	if len(hs.peerCertificates) < 2 {
		return errors.New("tlcp: ecc key exchange need 2 certificates")
	}
	sigCert := hs.peerCertificates[0]
	encCert := hs.peerCertificates[1]

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

	tbs := e.hashForServerKeyExchange(hs.hello.random, hs.serverHello.random, encCert.Raw)

	if !sm2.VerifyASN1WithSM2(pub, nil, tbs, sig) {
		return errors.New("tlcp: processServerKeyExchange: sm2 verification failure")
	}
	return nil
}

func (e *eccKeyAgreement) generateClientKeyExchange(hs *clientHandshakeState) ([]byte, *clientKeyExchangeMsg, error) {
	if len(hs.peerCertificates) < 2 {
		return nil, nil, errors.New("tlcp: ecc key exchange need 2 certificates")
	}
	encCert := hs.peerCertificates[1]
	config := hs.c.config

	preMasterSecret := make([]byte, 48)
	preMasterSecret[0] = byte(hs.hello.vers >> 8)
	preMasterSecret[1] = byte(hs.hello.vers)
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

// sm2ECDHEKeyAgreement 实现了基于SM2密钥交换算法的ECHD密钥交换，SM2密钥交换算法详见 GT/T GBT 35276-2017 9.6
type sm2ECDHEKeyAgreement struct {
	ke         SM2KeyAgreement // SM2密钥交换
	peerTmpKey *ecdh.PublicKey // 对端的临时公钥
}

// generateServerKeyExchange 生成服务端ECDHE密钥交换消息
func (ka *sm2ECDHEKeyAgreement) generateServerKeyExchange(hs *serverHandshakeState) (*serverKeyExchangeMsg, error) {
	if hs.sigCert == nil || hs.encCert == nil {
		return nil, errors.New("tlcp: ECDHE key exchange needs 2 certificates")
	}
	config := hs.c.config
	sigkey := hs.sigCert

	// 使用加密密钥对进行SM2密钥交换
	encPrv := hs.encCert.PrivateKey
	switch key := encPrv.(type) {
	case SM2KeyAgreement:
		ka.ke = key
	case *sm2.PrivateKey:
		ecdhKey, err := key.ECDH()
		if err != nil {
			return nil, err
		}
		ka.ke = newSM2KeyKE(config.rand(), ecdhKey)
	default:
		return nil, fmt.Errorf("tlcp: private key not support sm2 key exchange")
	}

	// 由于TLCP标准并未明确提及密钥长度，因此与ECC密钥交换类型保持一致48字节。
	_, sponsorTmpPubKey, err := ka.ke.GenerateAgreementData(nil, 48)
	if err != nil {
		return nil, err
	}

	/*
				See RFC 4492, Section 5.4.
				struct {
				 	ECCurveType    curve_type;
				 	select (curve_type) {
				 	    case named_curve:
				 	        NamedCurve namedcurve;
				 	};
				} ECParameters;

				struct {
		            opaque point <1..2^8-1>;
		        } ECPoint;

				struct {
			    	ECParameters    curve_params;
			    	ECPoint         public;
			    } ServerECDHParams;
		其中服务端的公钥不需要交换，客户端直接从服务端的加密证书中获取。
	*/
	ecdhePublic := sponsorTmpPubKey.Bytes()
	serverECDHEParams := make([]byte, 1+2+1+len(ecdhePublic))
	serverECDHEParams[0] = 3 // named curve
	serverECDHEParams[1] = byte(CurveSM2 >> 8)
	serverECDHEParams[2] = byte(CurveSM2)
	serverECDHEParams[3] = byte(len(ecdhePublic))
	copy(serverECDHEParams[4:], ecdhePublic)

	/*
		  case ECDHE:
			ServerECDHParams params;
			digitally-signed struct {
				opaque client_random[32];
				opaque server_random[32];
				ServerECDHParams params;
			}signed_params

			GM/T 38636-2016 6.4.5.4 Server Key Exchange消息
		 	e) signed_params
		 		当密钥交换方式为ECDHE和IBSDH和IBC时，signed_params是服务端对双方
		 		随机数和服务端密钥交换参数的签名。
	*/
	buffer := new(bytes.Buffer)
	buffer.Write(hs.clientHello.random)
	buffer.Write(hs.hello.random)
	buffer.Write(serverECDHEParams)
	tbs := buffer.Bytes()
	// 使用签名密钥对对 双方随机数 和 密钥交换 参数签名
	sigPrv, ok := sigkey.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("tlcp: certificate private key does not implement crypto.Signer")
	}
	sig, err := sigPrv.Sign(config.rand(), tbs, sm2.NewSM2SignerOption(true, nil))
	if err != nil {
		return nil, err
	}

	/*
		struct{
			ServerECDHParams params;
			opaque           signed_params<1..2^16-1>;
		}
	*/
	skx := new(serverKeyExchangeMsg)
	skx.key = make([]byte, len(serverECDHEParams)+2+len(sig))
	copy(skx.key, serverECDHEParams)
	k := skx.key[len(serverECDHEParams):]
	k[0] = byte(len(sig) >> 8)
	k[1] = byte(len(sig) & 0xFF)
	copy(k[2:], sig)

	return skx, nil
}

func getECDHEPublicKey(ciphertext []byte) (*ecdh.PublicKey, error) {
	/*
		opaque ClientECDHParams<1..2^16-1>

		GM/T 38636-2016  6.4.5.8 如果密钥算法使用ECDHE算法或IBSDH算法，本消息包括计算预主秘钥的客户端密钥交换参数。
		使用ECDHE算法时，要求客户端发送证书。密钥交换参数，当使用SM2算法时，交换参数间 GB/T 35276
			struct {
		    	ECParameters    curve_params;  // 3 byte See RFC 4492, Section 5.4.
		    	ECPoint         public;        // 1 byte of vector len
		    } ClientECDHParams;
		如果使用SM2算法时，第一个参数不校验
		struct {
		    opaque point <1..2^8-1>;
		} ECPoint;
	*/

	var pubLenStart int
	switch len(ciphertext) {
	case 69: // fixed structure
		pubLenStart = 3
	case 71: // vector
		pubLenStart = 5
		size := int(ciphertext[0]) << 8
		size |= int(ciphertext[1])

		if 2+size != len(ciphertext) {
			return nil, errClientKeyExchange
		}
	default:
		return nil, errClientKeyExchange
	}
	// 第一个参数不校验 3 + 1
	publicLen := int(ciphertext[pubLenStart])
	if publicLen != len(ciphertext[pubLenStart+1:]) {
		return nil, errClientKeyExchange
	}
	return ecdh.P256().NewPublicKey(ciphertext[pubLenStart+1:])
}

// processClientKeyExchange 处理客户端密钥交换消息（服务端）
func (ka *sm2ECDHEKeyAgreement) processClientKeyExchange(hs *serverHandshakeState, ckx *clientKeyExchangeMsg) ([]byte, error) {
	if len(hs.peerCertificates) < 2 {
		return nil, errors.New("tlcp: sm2 key exchange need client enc cert")
	}
	responsePubKey, ok := hs.peerCertificates[1].PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("tlcp: client key not sm2 type")
	}
	responsePubKeyECDH, err := sm2.PublicKeyToECDH(responsePubKey)
	if err != nil {
		return nil, err
	}

	responseTmpPubKey, err := getECDHEPublicKey(ckx.ciphertext)
	if err != nil {
		return nil, err
	}

	// 服务端 生成预主密钥
	return ka.ke.GenerateKey(nil, responsePubKeyECDH, responseTmpPubKey)
}

// processServerKeyExchange 处理服务端密钥交换消息（客户端）
func (ka *sm2ECDHEKeyAgreement) processServerKeyExchange(hs *clientHandshakeState, skx *serverKeyExchangeMsg) error {
	if len(hs.peerCertificates) < 2 {
		return errors.New("tlcp: sm2 key exchange need server provide two certificate")
	}

	sigCert := hs.peerCertificates[0]

	if len(skx.key) < 4 {
		return errServerKeyExchange
	}

	/*
			struct{
				ServerECDHParams params; 	// 3 + 1 + n
				digitally-signed struct {
					opaque client_random[32];
					opaque server_random[32];
					ServerECDHParams params;
				}signed_params 				//  opaque signed_params<1..2^16-1>
			}
		 	特别的根据 GM/T 38636-2016 6.4.5.4
		 	a) 如果使用SM2算法时忽略第一个参数 ECParameters。
	*/

	publicLen := int(skx.key[3])
	if publicLen+4 > len(skx.key) {
		return errServerKeyExchange
	}
	// 服务端曲线参数 ServerECDHParams
	serverECDHEParams := skx.key[:4+publicLen]
	// 服务端临时公钥
	tmpPubKey, err := ecdh.P256().NewPublicKey(serverECDHEParams[4:])
	if err != nil {
		return err
	}
	ka.peerTmpKey = tmpPubKey

	// 验证签名值，认证对端身份
	signedParams := skx.key[4+publicLen:]
	sigLen := int(signedParams[0]) << 8
	sigLen |= int(signedParams[1])
	if sigLen+2 > len(signedParams) {
		return errServerKeyExchange
	}

	sig := signedParams[2:]
	pub, ok := sigCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("tlcp: sm2 signing requires a sm2 public key")
	}

	// 组装签名数据，见 GM/T 38636-2016 6.4.5.4
	buffer := new(bytes.Buffer)
	buffer.Write(hs.hello.random)
	buffer.Write(hs.serverHello.random)
	buffer.Write(serverECDHEParams)
	tbs := buffer.Bytes()
	if !sm2.VerifyASN1WithSM2(pub, nil, tbs, sig) {
		return errors.New("tlcp: processServerKeyExchange: sm2 verification failure")
	}
	return nil
}

// generateClientKeyExchange 生成客户端ECDHE SM2密钥交换消息（客户端）
func (ka *sm2ECDHEKeyAgreement) generateClientKeyExchange(hs *clientHandshakeState) ([]byte, *clientKeyExchangeMsg, error) {
	if ka.peerTmpKey == nil {
		return nil, nil, errServerKeyExchange
	}

	// 使用客户端加密密钥对进行SM2密钥交换
	encPriv := hs.encCert.PrivateKey
	switch prvKey := encPriv.(type) {
	case SM2KeyAgreement:
		ka.ke = prvKey
	case *sm2.PrivateKey:
		ecdhPriv, err := prvKey.ECDH()
		if err != nil {
			return nil, nil, err
		}
		ka.ke = newSM2KeyKE(hs.c.config.rand(), ecdhPriv)
	default:
		return nil, nil, fmt.Errorf("tlcp: private key not support sm2 key exchange")
	}

	// 获取服务端加密证书中的加密公钥
	encCert := hs.peerCertificates[1]

	sponsorPubKey, ok := encCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, errors.New("tlcp: server encrypt certificate key type not sm2")
	}

	sponsorECDHPubKey, err := sm2.PublicKeyToECDH(sponsorPubKey)
	if err != nil {
		return nil, nil, err
	}

	// 使用服务端的临时公钥以及客户端加密密钥对计算SM2密钥交换，生成预主密钥与客户端临时公钥
	responseTmpPubKey, preMasterSecret, err := ka.ke.GenerateAgreementDataAndKey(nil, nil, sponsorECDHPubKey, ka.peerTmpKey, 48)
	if err != nil {
		return nil, nil, err
	}

	/*
		GM/T 38636-2016 6.4.5.4
		case ECDHE:
			opaque ClientECDHEParams<1..2^16-1>;

		struct {
			ECParameters    curve_params;
			ECPoint         public;
		} ClientECDHParams;
	*/
	var params []byte
	ecdhePublic := responseTmpPubKey.Bytes()
	paramLen := 1 + 2 + 1 + len(ecdhePublic)
	ckx := new(clientKeyExchangeMsg)
	if hs.c.config.ClientECDHEParamsAsVector {
		ckx.ciphertext = make([]byte, 2+paramLen)
		ckx.ciphertext[0] = byte(paramLen >> 8)
		ckx.ciphertext[1] = byte(paramLen & 0xFF)
		params = ckx.ciphertext[2:]
	} else {
		ckx.ciphertext = make([]byte, paramLen)
		params = ckx.ciphertext
	}
	params[0] = 3 // named curve
	params[1] = byte(CurveSM2 >> 8)
	params[2] = byte(CurveSM2)
	params[3] = byte(len(ecdhePublic))
	copy(params[4:], ecdhePublic)

	return preMasterSecret, ckx, nil
}
