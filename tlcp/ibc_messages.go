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
	"fmt"

	"golang.org/x/crypto/cryptobyte"
)

// ibcCertificateMsg 是 GM/T 0024-2023 6.4.5.3 / 6.4.5.7 定义的 IBC 变体 Certificate 消息。
//
//	opaque ASN.1IBCParam<1..2^24-1>;
//	struct {
//	    opaque ibc_id<1..2^16-1>;      // 服务端/客户端标识
//	    ASN.1IBCParam ibc_parameter;   // = IBCSysParams 的 DER
//	} Certificate;
//
// 该消息与 X.509 的 Certificate 消息共用握手消息类型 typeCertificate，
// 由所协商的密码套件（suiteIBC）区分。
type ibcCertificateMsg struct {
	raw          []byte
	ibcID        []byte // 标识原始字节（Identifier DER 或裸标识），原样透传
	ibcParameter []byte // IBCSysParams 的 DER
}

func (m *ibcCertificateMsg) marshal() ([]byte, error) {
	if m.raw != nil {
		return m.raw, nil
	}
	var b cryptobyte.Builder
	b.AddUint8(typeCertificate)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(m.ibcID)
		})
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(m.ibcParameter)
		})
	})
	var err error
	m.raw, err = b.Bytes()
	return m.raw, err
}

func (m *ibcCertificateMsg) unmarshal(data []byte) bool {
	m.raw = data
	s := cryptobyte.String(data)
	if !s.Skip(4) { // message type and uint24 length field
		return false
	}
	if !readUint16LengthPrefixed(&s, &m.ibcID) || len(m.ibcID) == 0 {
		return false
	}
	if !readUint24LengthPrefixed(&s, &m.ibcParameter) || len(m.ibcParameter) == 0 {
		return false
	}
	return s.Empty()
}

func (m *ibcCertificateMsg) messageType() uint8 {
	return typeCertificate
}

func (m *ibcCertificateMsg) debug() {
	fmt.Printf(">>> Certificate (IBC)\n")
	fmt.Printf("IBC ID(%d): %x\n", len(m.ibcID), m.ibcID)
	fmt.Printf("IBC Parameter(%d bytes)\n", len(m.ibcParameter))
	fmt.Printf("<<<\n")
}

// identityContent 返回标识的原始标识内容（若为 Identifier 则抽取 identityData）。
func (m *ibcCertificateMsg) identityContent() []byte {
	return identityDataOf(m.ibcID)
}

// ibcSignedParams 组装 IBC 套件的 signed_params 覆盖数据（GM/T 0024-2023 6.4.5.4）：
//
//	opaque client_random[32];
//	opaque server_random[32];
//	opaque ibc_id<1..2^16-1>;
func ibcSignedParams(clientRandom, serverRandom, ibcID []byte) []byte {
	var b cryptobyte.Builder
	b.AddBytes(clientRandom)
	b.AddBytes(serverRandom)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(ibcID)
	})
	return b.BytesOrPanic()
}

// ibsdhSignedParams 组装 IBSDH 套件的 signed_params 覆盖数据（GM/T 0024-2023 6.4.5.4）：
//
//	opaque client_random[32];
//	opaque server_random[32];
//	ServerIBSDHParams params;   // KeyAgreementInfo 的 DER
func ibsdhSignedParams(clientRandom, serverRandom, params []byte) []byte {
	b := make([]byte, 0, len(clientRandom)+len(serverRandom)+len(params))
	b = append(b, clientRandom...)
	b = append(b, serverRandom...)
	b = append(b, params...)
	return b
}

// setClientIDExtension 在 ClientHello 中携带 client_id(66) 扩展。
//
// GM/T 0024-2023 附录 A.7：客户端的 Client Hello 消息的 CipherSuite 包括 IBSDH
// 密钥交换算法时，需要发送 Client ID 扩展，指定客户端的标识信息。
// 本库在客户端配置了 IBCIdentity 时即发送（发 ClientHello 时尚未协商出套件）。
func setClientIDExtension(hello *clientHelloMsg, identity []byte) {
	if hello == nil || len(identity) == 0 {
		return
	}
	hello.ibsdhClientID = append([]byte(nil), identity...)
}
