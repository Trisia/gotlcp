// Copyright (c) 2022 QuanGuanyu
// tlcp is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package tlcp

import (
	"crypto/cipher"
	"crypto/hmac"
	"fmt"
	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/sm4"
	"hash"
)

// CipherSuite is a TLS cipher suite. Note that most functions in this package
// accept and expose cipher suite IDs instead of this type.
type CipherSuite struct {
	ID   uint16
	Name string

	// Supported versions is the list of TLS protocol versions that can
	// negotiate this cipher suite.
	SupportedVersions []uint16

	// Insecure is true if the cipher suite has known security issues
	// due to its primitives, design, or implementation.
	Insecure bool
}

var (
	supportedOnlyTLCP = []uint16{VersionTLCP}
)

// CipherSuites 返回支持的密码算法套件列表
func CipherSuites() []*CipherSuite {
	return []*CipherSuite{
		{TLCP_ECC_SM4_CBC_SM3, "TLCP_ECC_SM4_CBC_SM3", supportedOnlyTLCP, false},
		{TLCP_ECC_SM4_GCM_SM3, "TLCP_ECC_SM4_GCM_SM3", supportedOnlyTLCP, false},
	}
}

// InsecureCipherSuites returns a list of cipher suites currently implemented by
// this package and which have security issues.
//
// Most applications should not use the cipher suites in this list, and should
// only use those returned by CipherSuites.
func InsecureCipherSuites() []*CipherSuite {
	return []*CipherSuite{}
}

// CipherSuiteName returns the standard name for the passed cipher suite ID
// (e.g. "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"), or a fallback representation
// of the ID value if the cipher suite is not implemented by this package.
func CipherSuiteName(id uint16) string {
	for _, c := range CipherSuites() {
		if c.ID == id {
			return c.Name
		}
	}
	for _, c := range InsecureCipherSuites() {
		if c.ID == id {
			return c.Name
		}
	}
	return fmt.Sprintf("0x%04X", id)
}

const (
	// suiteECDHE indicates that the cipher suite involves elliptic curve
	// Diffie-Hellman. This means that it should only be selected when the
	// client indicates that it supports ECC with a curve and point format
	// that we're happy with.
	suiteECDHE = 1 << iota
	// suiteECSign indicates that the cipher suite involves an ECDSA or
	// EdDSA signature and therefore may only be selected when the server's
	// certificate is ECDSA or EdDSA. If this is not set then the cipher suite
	// is RSA based.
	suiteECSign
)

// A cipherSuite is a TLS 1.0–1.2 cipher suite, and defines the key exchange
// mechanism, as well as the cipher+MAC pair or the AEAD.
type cipherSuite struct {
	id uint16
	// the lengths, in bytes, of the key material needed for each component.
	keyLen int
	macLen int
	ivLen  int
	ka     func(version uint16) keyAgreement
	// flags is a bitmask of the suite* values, above.
	flags  int
	cipher func(key, iv []byte, isRead bool) interface{}
	mac    func(key []byte) hash.Hash
	aead   func(key, fixedNonce []byte) aead
}

var cipherSuites = map[uint16]*cipherSuite{
	TLCP_ECC_SM4_CBC_SM3: {TLCP_ECC_SM4_CBC_SM3, 16, 32, 16, eccKA, suiteECSign, cipherSM4, macSM3, nil},
	TLCP_ECC_SM4_GCM_SM3: {TLCP_ECC_SM4_GCM_SM3, 16, 0, 4, eccKA, suiteECSign, nil, nil, aeadSM4GCM},
}

// selectCipherSuite 从推荐ID和候选ID中选择出符合条件的密钥套件
func selectCipherSuite(ids, supportedIDs []uint16, ok func(*cipherSuite) bool) *cipherSuite {
	for _, id := range ids {
		candidate := cipherSuites[id]
		if candidate == nil || !ok(candidate) {
			continue
		}

		for _, suppID := range supportedIDs {
			if id == suppID {
				return candidate
			}
		}
	}
	return nil
}

// 推荐的密码套件列表（顺序表示优先级）
var cipherSuitesPreferenceOrder = []uint16{
	TLCP_ECC_SM4_CBC_SM3,
	TLCP_ECC_SM4_GCM_SM3,
}

// disabledCipherSuites 禁用的密码套件
var disabledCipherSuites = []uint16{}

var (
	defaultCipherSuitesLen = len(cipherSuitesPreferenceOrder) - len(disabledCipherSuites)
	defaultCipherSuites    = cipherSuitesPreferenceOrder[:defaultCipherSuitesLen]
)

// tls10MAC implements the TLS 1.0 MAC function. RFC 2246, Section 6.2.3.
func tls10MAC(h hash.Hash, out, seq, header, data, extra []byte) []byte {
	h.Reset()
	h.Write(seq)
	h.Write(header)
	h.Write(data)
	res := h.Sum(out)
	if extra != nil {
		h.Write(extra)
	}
	return res
}

// mutualCipherSuite returns a cipherSuite given a list of supported
// ciphersuites and the id requested by the peer.
func mutualCipherSuite(have []uint16, want uint16) *cipherSuite {
	for _, id := range have {
		if id == want {
			//return cipherSuiteByID(id)
			return cipherSuites[id]
		}
	}
	return nil
}

//func cipherSuiteByID(id uint16) *cipherSuite {
//	if suite, ok := cipherSuites[id]; ok {
//		return suite
//	}
//	return nil
//}

// 密码套件ID，见 GB/T 38636-2016 6.4.5.2.1  表 2 密码套件列表
const (
	TLCP_ECDHE_SM4_CBC_SM3  uint16 = 0xe011
	TLCP_ECDHE_SM4_GCM_SM3  uint16 = 0xe051
	TLCP_ECC_SM4_CBC_SM3    uint16 = 0xe013
	TLCP_ECC_SM4_GCM_SM3    uint16 = 0xe053
	TLCP_IBSDH_SM4_CBC_SM3  uint16 = 0xe015
	TLCP_IBSDH_SM4_GCM_SM3  uint16 = 0xe055
	TLCP_IBC_SM4_CBC_SM3    uint16 = 0xe017
	TLCP_IBC_SM4_GCM_SM3    uint16 = 0xe057
	TLCP_RSA_SM4_CBC_SM3    uint16 = 0xe019
	TLCP_RSA_SM4_GCM_SM3    uint16 = 0xe059
	TLCP_RSA_SM4_CBC_SHA256 uint16 = 0xe01e
	TLCP_RSA_SM4_GCM_SHA256 uint16 = 0xe05a
)

// SignatureAlgorithm 签名算法 见 GB/T 38636-2016 6.4.5.9 Certificate Verify 消息
type SignatureAlgorithm uint16

const (
	NONE       SignatureAlgorithm = 0
	RSA_SHA256 SignatureAlgorithm = 1
	RSA_SM3    SignatureAlgorithm = 2
	ECC_SM3    SignatureAlgorithm = 3
	IBS_SM3    SignatureAlgorithm = 4
)

const (
	aeadNonceLength   = 12
	noncePrefixLength = 4
)

type aead interface {
	cipher.AEAD

	// explicitNonceLen returns the number of bytes of explicit nonce
	// included in each record. This is eight for older AEADs and
	// zero for modern ones.
	explicitNonceLen() int
}

// prefixNonceAEAD wraps an AEAD and prefixes a fixed portion of the nonce to
// each call.
type prefixNonceAEAD struct {
	// nonce contains the fixed part of the nonce in the first four bytes.
	nonce [aeadNonceLength]byte
	aead  cipher.AEAD
}

func (f *prefixNonceAEAD) NonceSize() int        { return aeadNonceLength - noncePrefixLength }
func (f *prefixNonceAEAD) Overhead() int         { return f.aead.Overhead() }
func (f *prefixNonceAEAD) explicitNonceLen() int { return f.NonceSize() }

func (f *prefixNonceAEAD) Seal(out, nonce, plaintext, additionalData []byte) []byte {
	copy(f.nonce[4:], nonce)
	return f.aead.Seal(out, f.nonce[:], plaintext, additionalData)
}

func (f *prefixNonceAEAD) Open(out, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	copy(f.nonce[4:], nonce)
	return f.aead.Open(out, f.nonce[:], ciphertext, additionalData)
}

func eccKA(version uint16) keyAgreement {
	return &eccKeyAgreement{
		version: version,
	}
}

func cipherSM4(key, iv []byte, isRead bool) interface{} {
	block, _ := sm4.NewCipher(key)
	if isRead {
		return cipher.NewCBCDecrypter(block, iv)
	}
	return cipher.NewCBCEncrypter(block, iv)
}

func macSM3(key []byte) hash.Hash {
	return hmac.New(sm3.New, key)
}

// aeadSM4GCM SM4 GCM向前加解密函数
// key: 对称密钥
// nonce: 隐式随机数 (implicit nonce 4 Byte)
func aeadSM4GCM(key []byte, nonce []byte) aead {
	if len(nonce) != noncePrefixLength {
		panic("tls: internal error: wrong implicit nonce length")
	}
	block, err := sm4.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCMWithNonceSize(block, 12)
	if err != nil {
		panic(err)
	}
	// AEAD 使用的随机数应由显式和隐式两部分构成，
	// 显式部分即 nonce explicit，客户端和服务端使用隐式部分
	// 分别来自 client_write_iv 和 server_write_iv。
	// AEAD使用的随机数和计数器的构造参见 RFC 5116
	ret := &prefixNonceAEAD{aead: aead}
	copy(ret.nonce[:], nonce)
	return ret
}
