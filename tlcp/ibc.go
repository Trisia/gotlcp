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
	"encoding/asn1"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/emmansun/gmsm/sm9"
	"github.com/emmansun/gmsm/smx509"
)

// IBCIdentity 一套 SM9 标识密码（IBC）身份凭据：本端标识 + 本端公共参数 +
// 由 KGC 下发的用户私钥。
//
// 仅当 CipherSuites 中包含 IBC/IBSDH 套件时生效。
//
// 三把用户私钥均由 KGC 使用主私钥按 (Identity, hid) 派生后下发，本库只负责装载，
// 不提供派生能力。必需性随角色与套件不同：
//
//	SignPrivateKey        hid=0x01  服务端签 signed_params；客户端双向认证签 CertificateVerify
//	EncryptPrivateKey     hid=0x03  IBC 套件解密预主密钥（仅服务端需要）
//	KeyExchangePrivateKey hid=0x02  IBSDH 套件的 SM9 密钥交换（双方都需要）
//
// 未配置 KeyExchangePrivateKey 时本端不具备 IBSDH 能力，IBSDH 套件不参与协商
// （服务端不会选中，客户端不会在 ClientHello 中携带）。
type IBCIdentity struct {
	// Identity 本端 IBC 标识。
	//
	// 支持两种形式：GM/T 0090 Identifier 的 DER 编码，或用户自定义的裸标识字节串。
	// 推荐使用裸字节串，以避免 Identifier.validStart 必填带来的额外配置。
	Identity []byte

	// Parameters 本端 IBC 公共参数。服务端随 Certificate（IBC 变体）消息下发；
	// 客户端仅在双向认证（需下发自身 Certificate）时必需。
	Parameters *IBCSysParams

	// SignPrivateKey 本端签名用户私钥（hid=0x01），由 KGC 基于 Identity 派生。
	// 服务端：对 signed_params 签名（必需）。
	// 客户端：对 CertificateVerify 签名（双向认证时必需）。
	SignPrivateKey *sm9.SignPrivateKey

	// EncryptPrivateKey 本端加密用户私钥（hid=0x03），由 KGC 基于 Identity 派生。
	// IBC：服务端解密预主密钥（必需）。
	EncryptPrivateKey *sm9.EncryptPrivateKey

	// KeyExchangePrivateKey 本端密钥交换用户私钥（hid=0x02），由 KGC 基于 Identity 派生。
	// IBSDH：双方参与密钥交换时均必需。
	//
	// SM9 密钥交换协议中的用户公钥由 H1(uid ‖ 0x02) · P 推导，因此参与密钥交换的
	// 私钥必须按 hid=0x02 派生，与 IBC 加密用的 hid=0x03 私钥不同（二者都由加密
	// 主私钥派生，但 hid 不同即得到不同的密钥对）。
	//
	// 本库不校验该私钥的派生 hid，也不回退到 EncryptPrivateKey：装载与配置期均不做
	// 拦截，正确性由调用方（KGC 派发与本地装载环节）自行保证。若装入按其它 hid 派生的
	// 私钥，密钥交换阶段不会报错，而是双方预主密钥不同，直到 Finished 校验失败才以
	// bad record MAC 告终。
	//
	// 为空表示本端不具备 IBSDH 能力，此时 IBSDH 套件不可用。
	KeyExchangePrivateKey *sm9.EncryptPrivateKey
}

// keyExchangeKey 返回 IBSDH 使用的密钥交换私钥（hid=0x02），未配置时为 nil。
//
// 不再回退到 EncryptPrivateKey：hid=0x03 的加密私钥参与 hid=0x02 的密钥交换
// 时双方预主密钥不同，只会推迟到 Finished 才以 bad record MAC 失败。
func (c *IBCIdentity) keyExchangeKey() *sm9.EncryptPrivateKey {
	if c == nil {
		return nil
	}
	return c.KeyExchangePrivateKey
}

// sysParams 返回本端公共参数，未配置时为 nil。
//
// 握手时若未配置信任池（Config.RootIBCSysParams / Config.ClientIBCSysParams）与
// Config.VerifyIBCSysParams 回调，本端公共参数会作为默认信任池：对端下发的公共参数
// 必须与它属于同一 KGC（districtName + districtSerial + 两个主公钥相等）才能通过校验。
func (c *IBCIdentity) sysParams() *IBCSysParams {
	if c == nil {
		return nil
	}
	return c.Parameters
}

// canKeyExchange 判断本端是否具备 IBSDH 密钥交换能力。
func (c *IBCIdentity) canKeyExchange() bool {
	return c != nil && c.KeyExchangePrivateKey != nil
}

// Clone 返回 IBCIdentity 的浅复制。
//
// 返回值：
//   - *IBCIdentity：接收者为 nil 时返回 nil；否则返回顶层字段逐一复制的新对象。
//
// 复制为浅复制：Identity 切片与各私钥指针均与原对象共享底层数据。
func (c *IBCIdentity) Clone() *IBCIdentity {
	if c == nil {
		return nil
	}
	cp := *c
	return &cp
}

// IBCSysParams IBC 公共参数，即 GM/T 0081-2020《SM9 密码算法加密签名消息语法规范》
// 附录 A.2 定义的 IBCSysParams。
//
// 出处：
//   - 标准来源：GM/T 0081-2020 附录 A.2 定义的 IBCSysParams；
//   - 协议位置：GM/T 0024-2023 中 Certificate（IBC 变体）消息的 ibc_parameter 字段，
//     其内容就是本结构的 DER 编码；
//
// 用途：
//   - 提供 SM9 签名/加密主公钥（SignMasterPublicKey、EncryptMasterPublicKey）与 KGC 域标识
//     （DistrictName、DistrictSerial），供 IBC/IBSDH 套件完成密钥协商、加密与签名校验；
//   - 作为信任锚参与校验：IBCIdentity.Parameters 为本端参数，Config.RootIBCSysParams /
//     ClientIBCSysParams（IBCPool）配置受信参数池，握手时 verifyPeerIBCSysParams 解析对端下发的
//     DER 并比对是否命中信任池；未配置信任池时先由 Config.VerifyIBCSysParams 回调判定，
//     回调也为 nil 时以本端 IBCIdentity.Parameters 作为默认信任池（见该函数注释）；
//   - VerifyValidity 按 GM/T 0081-2020 要求校验参数及 issuerID 的有效期；
//   - 握手结果经 ConnectionState.PeerIBCSysParams 暴露，并随会话状态持久化以支持会话重用。
//
// 解析约定：忠于标准，不发明标准之外的宽容规则；标准本身允许多种形式之处（如 ibc_id 的
// 两种编码形式）兼容处理，未知字段经 Raw 透传保留。
//
// 字段命名与 GM/T 0081-2020 附录 A.2 的 IBCSysParams 逐字段对应，不得随意改名；
// 每个字段的标准名见其注释，Raw 与两个主公钥字段是实现附加字段，不属于标准字段。
type IBCSysParams struct {
	// Raw 原始 DER 编码，解析时原样保存、编码时原样返回，以便透传保留未知字段【实现附加，非标准字段】。
	Raw []byte

	// Version 版本项，确定 IBCSysParams 格式的版本；本文件提及的格式应设置为 2。
	// ASN.1：version INTEGER { v2(2) }。
	Version int

	// DistrictName 名称项，是一个应以 URI 或者 IRI 编码的 IA5 字符串，
	// 用以标明公布本组公共参数的 KGC 域（district）。
	// ASN.1：districtName IA5String。
	DistrictName string

	// DistrictSerial 域序列号，代表在 districtName 所定义的 URI 或 IRI 下、
	// 可用的唯一一组 IBC 公共参数的整数编号；若为同一 districtName 公布新的参数，
	// 其数值应大于此前使用的 districtSerial。
	// ASN.1：districtSerial INTEGER。
	DistrictSerial int

	// Validity 有效期项，确定一个具体 IBCSysParams 范例的寿命。
	// 客户必须确认所使用的 IBC 公共参数的日期处于 notBefore 与 notAfter 之间；
	// 若日期不处于该区间，则不能将参数用于 IBC 加密操作。
	// ASN.1：validity ValidityPeriod。
	Validity ValidityPeriod

	// IBCPublicParameters 公共参数项，是一个包含公共参数（对应于 PKG 支持的
	// 各 IBC 算法式）的结构；SM9 算法式对应项的内容为 SM9PublicParameterData 的 DER 编码。
	// ASN.1：ibcPublicParameters IBCPublicParameters（SEQUENCE (1..MAX) OF IBCPublicParameter）。
	IBCPublicParameters []IBCPublicParameter

	// IBCIdentityType 标识类型项，是一个确定在这一区域使用的身份类型的 OID；
	// 对于每一个 OID，所需要以及可选择的域都依赖于应用程序而存在。
	// ASN.1：ibcIdentityType OBJECT IDENTIFIER。
	IBCIdentityType asn1.ObjectIdentifier

	// IssuerID 公开参数颁发者标识，即签发本组 IBC 公共参数的 KGC 标识，
	// 其 validStart/validEnd 为该信任锚的时间有效期。
	// ASN.1：issuerID Identifier。
	IssuerID *Identifier

	// IBCParamExtensions 扩散（扩展）参数项，是一组用于确定特定操作所需额外参数的扩展，
	// 可能包含任意数量的扩展（包括零个在内）。
	// ASN.1：ibcParamExtensions IBCParamExtensions OPTIONAL。
	IBCParamExtensions []IBCParamExtension

	// 以下两个字段从 IBCPublicParameters 中挑选 SM9 项后解析得到，非标准字段【实现附加】。

	// SignMasterPublicKey SM9 签名主公钥，用于校验 signed_params 与 CertificateVerify 的签名。
	SignMasterPublicKey *sm9.SignMasterPublicKey

	// EncryptMasterPublicKey SM9 加密主公钥，用于加密预主密钥以及 IBSDH 密钥协商。
	EncryptMasterPublicKey *sm9.EncryptMasterPublicKey
}

// Marshal 返回 IBCSysParams 的 DER 编码。
//
// 返回值：
//   - []byte：IBCSysParams 的完整 DER 编码。
//   - error：IssuerID 编码失败或整体编码失败时返回非 nil。
//
// 若 p.Raw 非空则直接原样返回 p.Raw，不按当前字段重新编码；否则依据各字段编码，
// 其中 IssuerID 为 nil 时自动以 DistrictName、Validity.NotBefore 与 SM9 算法 OID 构造。
func (p *IBCSysParams) Marshal() ([]byte, error) {
	if len(p.Raw) > 0 {
		return p.Raw, nil
	}
	w := &ibcSysParamsWire{
		Version:             p.Version,
		DistrictName:        p.DistrictName,
		DistrictSerial:      p.DistrictSerial,
		Validity:            p.Validity,
		IBCIdentityType:     p.IBCIdentityType,
		IBCPublicParameters: p.IBCPublicParameters,
		IBCParamExtensions:  p.IBCParamExtensions,
	}
	issuerID := p.IssuerID
	if issuerID == nil {
		issuerID = &Identifier{
			Version:      identifierVersionV1,
			IBCType:      oidSM9,
			IdentityData: []byte(p.DistrictName),
			ValidStart:   p.Validity.NotBefore,
		}
	}
	issuerDER, err := issuerID.Marshal()
	if err != nil {
		return nil, err
	}
	w.IssuerID = asn1.RawValue{FullBytes: issuerDER}
	return marshalIBCSysParams(w)
}

// ParseIBCSysParams 解析 DER 编码的 IBCSysParams。
//
// 参数：
//   - der：IBCSysParams 的 DER 编码字节，不能为空。
//
// 返回值：
//   - *IBCSysParams：解析结果，其 Raw 字段原样保存传入的 der。
//   - error：DER 非法、version 不为 2、必需字段缺失、issuerID 解析失败或缺少受支持的 SM9 项时返回非 nil。
//
// 解析约定：忠于标准，不发明标准之外的宽容规则；当 ibcPublicParameters 中没有 SM9 项，
// 或主公钥形式不受支持时返回 unsupported_ibcparam(204)。
func ParseIBCSysParams(der []byte) (*IBCSysParams, error) {
	w, err := parseIBCSysParams(der)
	if err != nil {
		return nil, err
	}
	p := &IBCSysParams{
		Raw:                 der,
		Version:             w.Version,
		DistrictName:        w.DistrictName,
		DistrictSerial:      w.DistrictSerial,
		Validity:            w.Validity,
		IBCIdentityType:     w.IBCIdentityType,
		IBCPublicParameters: w.IBCPublicParameters,
		IBCParamExtensions:  w.IBCParamExtensions,
	}

	if len(w.IssuerID.FullBytes) > 0 {
		issuer, err := ParseIdentifier(w.IssuerID.FullBytes)
		if err != nil {
			return nil, ibcParamError("failed to parse IBCSysParams.issuerID: %v", err)
		}
		p.IssuerID = issuer
	}

	// 多算法式：按 ibcAlgorithm OID 遍历挑选 SM9 项。
	for _, item := range p.IBCPublicParameters {
		if !item.IBCAlgorithm.Equal(oidSM9) {
			continue
		}
		var data sm9PublicParameterData
		if _, err := asn1.Unmarshal(item.PublicParameterData, &data); err != nil {
			return nil, ibcParamError("failed to parse SM9PublicParameterData: %v", err)
		}
		encDER := rawValueBytes(&data.EncMastPublicKey)
		signDER := rawValueBytes(&data.SignMastPublicKey)
		if len(encDER) == 0 || len(signDER) == 0 {
			return nil, ibcParamError("SM9PublicParameterData is missing a master public key")
		}
		encPub, err := sm9.UnmarshalEncryptMasterPublicKeyASN1(encDER)
		if err != nil {
			return nil, ibcUnsupportedError("unsupported SM9 encrypt master public key: %v", err)
		}
		signPub, err := sm9.UnmarshalSignMasterPublicKeyASN1(signDER)
		if err != nil {
			return nil, ibcUnsupportedError("unsupported SM9 sign master public key: %v", err)
		}
		p.EncryptMasterPublicKey = encPub
		p.SignMasterPublicKey = signPub
		break
	}
	if p.SignMasterPublicKey == nil || p.EncryptMasterPublicKey == nil {
		return nil, ibcUnsupportedError("no SM9 public parameters found")
	}
	return p, nil
}

// VerifyValidity 校验当前时间是否落在参数有效期内。
//
// 参数：
//   - now：用于校验的时间点，通常取 time.Now()。
//
// 返回值：
//   - error：接收者为 nil、参数有效期不包含 now 或 issuerID 有效期不包含 now 时返回非 nil。
//
// GM/T 0081-2020 要求客户必须确认其使用的 IBC 公共参数的日期处于
// notBefore 与 notAfter 之间；issuerID 的时间有效性同样强制校验。
// Validity 为零值时不校验参数有效期，IssuerID 为 nil 或其 ValidEnd 为零值时跳过 issuerID 校验。
func (p *IBCSysParams) VerifyValidity(now time.Time) error {
	if p == nil {
		return ibcParamError("nil IBC parameters")
	}
	if !p.Validity.IsZero() && !p.Validity.Contains(now) {
		return ibcUnsupportedError("IBC parameters are not valid at %s", now.Format(time.RFC3339))
	}
	if p.IssuerID != nil && !p.IssuerID.ValidEnd.IsZero() {
		if now.Before(p.IssuerID.ValidStart) || now.After(p.IssuerID.ValidEnd) {
			return ibcUnsupportedError("IBC issuer identity is not valid at %s", now.Format(time.RFC3339))
		}
	}
	return nil
}

// sameKGC 判断两组参数是否来自同一 KGC 参数实例。
func (p *IBCSysParams) sameKGC(other *IBCSysParams) bool {
	if p == nil || other == nil {
		return false
	}
	if p.DistrictName != other.DistrictName || p.DistrictSerial != other.DistrictSerial {
		return false
	}
	if p.SignMasterPublicKey == nil || other.SignMasterPublicKey == nil ||
		p.EncryptMasterPublicKey == nil || other.EncryptMasterPublicKey == nil {
		return false
	}
	return bytes.Equal(p.SignMasterPublicKey.Bytes(), other.SignMasterPublicKey.Bytes()) &&
		bytes.Equal(p.EncryptMasterPublicKey.Bytes(), other.EncryptMasterPublicKey.Bytes())
}

// ibcPoolKey 返回 KGC 的唯一标识键：同一 KGC 由 (districtName, districtSerial) 唯一标识。
func ibcPoolKey(districtName string, districtSerial int) string {
	return districtName + "\x00" + strconv.Itoa(districtSerial)
}

// IBCPool 一组受信任的 IBC 公共参数（KGC），语义对称于 smx509.CertPool。
//
// IBCPool 可以被多个 goroutine 并发访问。
type IBCPool struct {
	mu     sync.RWMutex
	params map[string]*IBCSysParams
}

// NewIBCPool 返回一个空的 IBC 信任池。
//
// 返回值：
//   - *IBCPool：内部参数表已初始化的空信任池，可被多个 goroutine 并发访问。
func NewIBCPool() *IBCPool {
	return &IBCPool{params: make(map[string]*IBCSysParams)}
}

// AddParams 将一组公共参数加入信任池。
//
// 参数：
//   - params：待加入的公共参数，不能为 nil；其 Raw 为空时会被补齐为 Marshal 的结果。
//
// 返回值：
//   - error：params 为 nil 或补齐 Raw 时编码失败返回非 nil，成功返回 nil。
//
// 同一 KGC 由 (districtName, districtSerial) 唯一标识，重复加入同一 KGC 的参数会覆盖先前的值。
//
// 注意：Raw 为空时会就地修改传入的 params（写入其 DER 编码）；本方法不校验主公钥，
// 若参数缺少签名/加密主公钥，之后将无法被 Lookup/Contains 命中。
func (p *IBCPool) AddParams(params *IBCSysParams) error {
	if params == nil {
		return errors.New("tlcp: cannot add nil IBC parameters to pool")
	}
	if len(params.Raw) == 0 {
		der, err := params.Marshal()
		if err != nil {
			return err
		}
		params.Raw = der
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.params == nil {
		p.params = make(map[string]*IBCSysParams)
	}
	p.params[ibcPoolKey(params.DistrictName, params.DistrictSerial)] = params
	return nil
}

// AddParamsDER 从 DER 编码的 IBCSysParams 加入信任池。
//
// 参数：
//   - der：IBCSysParams 的 DER 编码字节，不能为空。
//
// 返回值：
//   - error：DER 解析失败或加入信任池失败时返回非 nil，成功返回 nil。
//
// 内部先经 ParseIBCSysParams 解析，再以 AddParams 加入，因此同一 KGC 的参数会被覆盖。
func (p *IBCPool) AddParamsDER(der []byte) error {
	params, err := ParseIBCSysParams(der)
	if err != nil {
		return err
	}
	return p.AddParams(params)
}

// Lookup 返回信任池中与给定参数匹配的公共参数。
//
// 参数：
//   - params：待检索的公共参数，可为 nil（此时直接未命中）。
//
// 返回值：
//   - *IBCSysParams：命中的受信公共参数，未命中时为 nil。
//   - bool：是否命中。
//
// 命中判定见 Contains：除 KGC 身份（districtName + districtSerial）外，还要求双方的签名主公钥与
// 加密主公钥逐字节相等；若池中参数的主公钥为 nil，则永远不会命中。
func (p *IBCPool) Lookup(params *IBCSysParams) (*IBCSysParams, bool) {
	if p == nil || params == nil {
		return nil, false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	trusted, ok := p.params[ibcPoolKey(params.DistrictName, params.DistrictSerial)]
	if !ok {
		return nil, false
	}
	if !trusted.sameKGC(params) {
		return nil, false
	}
	return trusted, true
}

// Contains 判断给定参数是否命中信任池。
//
// 参数：
//   - params：待比对的公共参数，可为 nil（此时返回 false）。
//
// 返回值：
//   - bool：命中返回 true，否则返回 false。
//
// 比对项：KGC 身份（districtName + districtSerial）+ 签名主公钥 + 加密主公钥。
func (p *IBCPool) Contains(params *IBCSysParams) bool {
	_, ok := p.Lookup(params)
	return ok
}

// LoadIBCIdentity 从 DER / PKCS#8 字节装载一个 IBC 身份凭据。
//
// 参数：
//   - identity：本端 IBC 标识，GM/T 0090 Identifier 的 DER 或用户自定义的裸标识字节串，会被复制保存。
//   - paramsDER：本端 IBC 公共参数（IBCSysParams）的 DER 编码，解析后作为 IBCIdentity.Parameters。
//     可为空，仅"客户端单向认证"可省（客户端使用对端下发并经信任池校验的参数）；服务端与
//     双向认证的客户端必需，缺失会在下发 Certificate 时报 bad_ibcparam(203)。
//     若手上已有解析好的 *IBCSysParams，可直接赋值 ident.Parameters 或改用 paramsDER = params.Raw。
//   - signKeyDER：SM9 签名私钥（hid=0x01）的 PKCS#8 DER，可为空表示不提供该用途的私钥。
//   - encKeyDER：SM9 加密私钥（hid=0x03）的 PKCS#8 DER，可为空表示不提供该用途的私钥。
//   - keyExchangeKeyDER：SM9 密钥交换私钥（hid=0x02）的 PKCS#8 DER，可为空表示本端不具备
//     IBSDH 能力（此时 IBSDH 套件不参与协商）。
//
// 返回值：
//   - *IBCIdentity：装载完成的身份凭据，其 Identity 为 identity 的副本。
//   - error：公共参数 DER 解析失败、任一非空私钥 DER 解析失败或私钥类型不符时返回非 nil，
//     此时返回的凭据为 nil。
//
// 公共参数由 ParseIBCSysParams 解析，私钥由 smx509.ParsePKCS8PrivateKey 解析，
// 支持 *sm9.SignPrivateKey / *sm9.EncryptPrivateKey。
// 装载只做结构解析：不校验密钥交换私钥的派生 hid，也不要求配置密钥交换私钥时标识非空。
func LoadIBCIdentity(identity []byte, paramsDER, signKeyDER, encKeyDER, keyExchangeKeyDER []byte) (*IBCIdentity, error) {
	ident := &IBCIdentity{Identity: append([]byte(nil), identity...)}
	if len(paramsDER) > 0 {
		params, err := ParseIBCSysParams(paramsDER)
		if err != nil {
			return nil, fmt.Errorf("tlcp: failed to parse local IBC parameters: %w", err)
		}
		ident.Parameters = params
	}
	if len(signKeyDER) > 0 {
		key, err := smx509.ParsePKCS8PrivateKey(signKeyDER)
		if err != nil {
			return nil, fmt.Errorf("tlcp: failed to parse IBC sign private key: %w", err)
		}
		signPriv, ok := key.(*sm9.SignPrivateKey)
		if !ok {
			return nil, fmt.Errorf("tlcp: IBC sign private key has unexpected type %T", key)
		}
		ident.SignPrivateKey = signPriv
	}
	if len(encKeyDER) > 0 {
		key, err := smx509.ParsePKCS8PrivateKey(encKeyDER)
		if err != nil {
			return nil, fmt.Errorf("tlcp: failed to parse IBC encrypt private key: %w", err)
		}
		encPriv, ok := key.(*sm9.EncryptPrivateKey)
		if !ok {
			return nil, fmt.Errorf("tlcp: IBC encrypt private key has unexpected type %T", key)
		}
		ident.EncryptPrivateKey = encPriv
	}
	if len(keyExchangeKeyDER) > 0 {
		key, err := smx509.ParsePKCS8PrivateKey(keyExchangeKeyDER)
		if err != nil {
			return nil, fmt.Errorf("tlcp: failed to parse IBC key exchange private key: %w", err)
		}
		kePriv, ok := key.(*sm9.EncryptPrivateKey)
		if !ok {
			return nil, fmt.Errorf("tlcp: IBC key exchange private key has unexpected type %T", key)
		}
		ident.KeyExchangePrivateKey = kePriv
	}
	return ident, nil
}

// NewIBCSysParamsFromMaster 由 KGC 主密钥对生成公共参数（供 KGC 侧使用）。
//
// 参数：
//   - districtName：KGC 域名称，同时用作参数中的 pkgID 与 issuerID 的 identityData。
//   - districtSerial：KGC 域序列号，与 districtName 共同唯一标识一个 KGC。
//   - validity：参数有效期，写入 IBCSysParams.Validity 及 issuerID 的有效起止时间。
//   - signMaster：SM9 签名主私钥，不能为 nil。
//   - encMaster：SM9 加密主私钥，不能为 nil。
//
// 返回值：
//   - *IBCSysParams：生成完成的公共参数，Version 固定为 2，Raw 已填充其 DER 编码；内容包含一项 SM9 算法项（pkgID 为 districtName）、SM9 的 IBCIdentityType、由 v1/SM9 OID/districtName/validity 构造的 IssuerID，以及签名与加密主公钥（validity.NotAfter 为零值时 IssuerID 不写出 validEnd）。
//   - error：主密钥为 nil、主密钥公钥 ASN.1 编码失败或整体编码失败时返回非 nil。
//
// 生成的参数可直接用于 Config.IBCIdentity.Parameters，或加入 IBCPool 作为信任锚。
func NewIBCSysParamsFromMaster(
	districtName string,
	districtSerial int,
	validity ValidityPeriod,
	signMaster *sm9.SignMasterPrivateKey,
	encMaster *sm9.EncryptMasterPrivateKey,
) (*IBCSysParams, error) {
	if signMaster == nil || encMaster == nil {
		return nil, errors.New("tlcp: both SM9 master keys are required")
	}
	signDER, err := signMaster.PublicKey().MarshalASN1()
	if err != nil {
		return nil, fmt.Errorf("tlcp: failed to marshal SM9 sign master public key: %w", err)
	}
	encDER, err := encMaster.PublicKey().MarshalASN1()
	if err != nil {
		return nil, fmt.Errorf("tlcp: failed to marshal SM9 encrypt master public key: %w", err)
	}

	// SM9PublicParameterData 的内层 DER。
	inner := sm9PublicParameterData{
		PkgID:             []byte(districtName),
		EncMastPublicKey:  asn1.RawValue{FullBytes: encDER},
		SignMastPublicKey: asn1.RawValue{FullBytes: signDER},
	}
	innerDER, err := asn1.Marshal(inner)
	if err != nil {
		return nil, err
	}

	params := &IBCSysParams{
		Version:        ibcSysParamsVersionV2,
		DistrictName:   districtName,
		DistrictSerial: districtSerial,
		Validity:       validity,
		IBCPublicParameters: []IBCPublicParameter{{
			IBCAlgorithm:        oidSM9,
			PublicParameterData: innerDER,
		}},
		IBCIdentityType: oidSM9,
		IssuerID: &Identifier{
			Version:      identifierVersionV1,
			IBCType:      oidSM9,
			IdentityData: []byte(districtName),
			ValidStart:   validity.NotBefore,
			ValidEnd:     validity.NotAfter,
		},
		SignMasterPublicKey:    signMaster.PublicKey(),
		EncryptMasterPublicKey: encMaster.PublicKey(),
	}
	params.Raw, err = params.Marshal()
	if err != nil {
		return nil, err
	}
	return params, nil
}
