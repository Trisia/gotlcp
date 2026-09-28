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
	"encoding/asn1"
	"time"

	"github.com/emmansun/gmsm/sm9"
	"golang.org/x/crypto/cryptobyte"
	cryptobyteasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// 本文件实现 GM/T 0081-2020 定义的 IBC 相关 ASN.1 结构编解码：
//
//   - Identifier（§6.8）
//   - IBCSysParams（附录 A.2）
//   - KeyAgreementInfo（§12）
//
// 解析约定：不发明标准之外的宽容规则，但标准本身允许多种形式的地方（ibc_id 的两种形式、
// tempKey 的两种封装、SEQUENCE 尾部的剩余字节）必须兼容。

var (
	// oidSM9 SM9 标识密码算法（GB/T 33560）。
	oidSM9 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 302}

	// oidIBCKeyAgreementInfo GM/T 0081-2020 §12 KeyAgreementInfo 的数据类型 OID。
	oidIBCKeyAgreementInfo = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 4, 6}
)

// IBC 相关结构的版本号取值。
const (
	// identifierVersionV1 Identifier::Version 的取值（DEFAULT v1）。
	identifierVersionV1 = 1
	// ibcSysParamsVersionV2 IBCSysParams::version 的取值。
	ibcSysParamsVersionV2 = 2
	// keyAgreementInfoVersionV1 KeyAgreementInfo::version 的取值。
	keyAgreementInfoVersionV1 = 1
)

// SM9 hid 取值，见 GM/T 0044。
const (
	// hidSM9Sign 数字签名（signed_params、CertificateVerify）。
	hidSM9Sign byte = 0x01
	// hidSM9KeyExch 密钥交换（KeyAgreementInfo.hid）。
	hidSM9KeyExch byte = 0x02
	// hidSM9Encrypt 密钥封装 / 公钥加密（IBC 套件加密预主密钥）。
	hidSM9Encrypt byte = 0x03
)

// newIBCError 构造一个携带告警码的 IBC 错误。
func newIBCError(a alert, format string, args ...interface{}) error {
	return newAlertError(a, "tlcp: "+format, args...)
}

// ibcParamError 构造 bad_ibcparam(203) 错误。
func ibcParamError(format string, args ...interface{}) error {
	return newIBCError(alertBadIbcparam, format, args...)
}

// ibcUnsupportedError 构造 unsupported_ibcparam(204) 错误。
func ibcUnsupportedError(format string, args ...interface{}) error {
	return newIBCError(alertUnsupportedIbcparam, format, args...)
}

// Extension 是 Identifier 中的扩展项（GM/T 0081-2020 §6.8）。
//
//	Extension ::= SEQUENCE {
//	    extnID    OBJECT IDENTIFIER,
//	    critical  BOOLEAN DEFAULT FALSE,
//	    extnValue OCTET STRING
//	}
type Extension struct {
	// ExtnID 表示一个扩展元素的 OID。
	ExtnID asn1.ObjectIdentifier

	// Critical 表示这个扩展元素的重要性；缺省为 FALSE。
	Critical bool

	// ExtnValue 表示这个扩展元素的值，字符串类型（OCTET STRING）。
	ExtnValue []byte
}

// DistrictInfo 当 ibcType 为 SM9 OID 时，扩展中的发布服务信息（GM/T 0081-2020 §6.8），
// 即扩展项 extnValue 的 ASN.1 编码内容。
//
//	DistrictInfo ::= SEQUENCE {
//	    district   IA5String,
//	    districtNo INTEGER
//	}
type DistrictInfo struct {
	// District 描述生成该标识密钥的基础设施的公共参数发布服务的地址信息。
	District string

	// DistrictNo 描述在公共参数发布服务中存在多套公开参数信息时，
	// 生成该标识密钥的那套公共参数信息的唯一编号。
	DistrictNo int
}

// Identifier 对应 GM/T 0081-2020 §6.8 的 Identifier 结构，
// 用于 ibc_id / client_id 以及 IBCSysParams.issuerID。
//
//	Identifier ::= SEQUENCE {
//	    version      Version DEFAULT v1,
//	    ibcType      OBJECT IDENTIFIER,
//	    ibcTypeAlias [0] OCTET STRING OPTIONAL,
//	    identityData OCTET STRING,
//	    validStart   UTCTime,
//	    validEnd     [1] UTCTime OPTIONAL,
//	    extensions   [2] Extensions OPTIONAL
//	}
type Identifier struct {
	// Version 标识信息的版本号，默认为 1（v1）；编码时若出现则必须为 v1。
	Version int

	// IBCType 是一个对象标识符 OID，用于定义该标识应用的算法（如 SM9）。
	IBCType asn1.ObjectIdentifier

	// IBCTypeAlias 是一个标识的别名，可选项。
	IBCTypeAlias []byte

	// IdentityData 描述标识的内容（标识主体）。
	IdentityData []byte

	// ValidStart 用于描述标识有效期的起始时间。
	ValidStart time.Time

	// ValidEnd 可选项，用于描述标识有效期的终止时间；
	// 如果该项不存在，则该标识的结束有效期和公开参数的结束有效期一致。
	// 零值表示不写出 validEnd。
	ValidEnd time.Time

	// Extensions 可选项，是一个扩展序列（SEQUENCE）；
	// 如果出现，此项由一个或多个标识扩展的序列组成。
	// 当 ibcType 为 SM9 的 OID 时，扩展中需包括颁发该标识密钥的
	// 密钥基础设施的公开参数服务器信息（DistricInfo）。
	Extensions []Extension
}

// Marshal 返回 Identifier 的 DER 编码。
//
// 返回值：
//   - []byte：Identifier 的完整 DER 编码。
//   - error：字段编码失败（如 IBCType 不是合法 OID、时间取值无法编码）时返回非 nil。
//
// 编码固定使用隐式标签（IMPLICIT TAGS），这是国标 ASN.1 模块的常见形式；
// 解析时对 extensions 兼容显式与隐式两种形式（见 readIdentifierExtensions），
// 而 ibcTypeAlias 只按隐式形式读取。
// Version 恒按 INTEGER 写入；IBCTypeAlias 为空、ValidEnd 为零值、Extensions 为空时省略对应可选字段。
func (id *Identifier) Marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(cryptobyteasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(int64(id.Version))
		b.AddASN1ObjectIdentifier(id.IBCType)
		if len(id.IBCTypeAlias) > 0 {
			b.AddASN1(cryptobyteasn1.Tag(0).ContextSpecific(), func(b *cryptobyte.Builder) {
				b.AddBytes(id.IBCTypeAlias)
			})
		}
		b.AddASN1OctetString(id.IdentityData)
		addASN1Time(b, id.ValidStart)
		if !id.ValidEnd.IsZero() {
			b.AddASN1(cryptobyteasn1.Tag(1).ContextSpecific(), func(b *cryptobyte.Builder) {
				addASN1Time(b, id.ValidEnd)
			})
		}
		if len(id.Extensions) > 0 {
			b.AddASN1(cryptobyteasn1.Tag(2).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				for _, ext := range id.Extensions {
					b.AddASN1(cryptobyteasn1.SEQUENCE, func(b *cryptobyte.Builder) {
						b.AddASN1ObjectIdentifier(ext.ExtnID)
						if ext.Critical {
							b.AddASN1Boolean(true)
						}
						b.AddASN1OctetString(ext.ExtnValue)
					})
				}
			})
		}
	})
	return b.Bytes()
}

// ParseIdentifier 解析 DER 编码的 Identifier。
//
// 参数：
//   - der：Identifier 的 DER 编码字节。
//
// 返回值：
//   - *Identifier：解析结果，version 字段缺省时取 v1。
//   - error：不是合法 Identifier（非 SEQUENCE、必需字段缺失或非法、version 不为 v1、validEnd 含尾部数据、extensions 解析失败）时返回非 nil。
//
// SEQUENCE 内的多余尾部字节会被忽略（向前兼容），不视为错误。
//
// 当 der 不是合法的 Identifier 结构时返回错误；调用方（如标识比对逻辑）
// 可据此回退到"用户自定义的裸标识字节串"形式。
func ParseIdentifier(der []byte) (*Identifier, error) {
	input := cryptobyte.String(der)
	var seq cryptobyte.String
	if !input.ReadASN1(&seq, cryptobyteasn1.SEQUENCE) {
		return nil, ibcParamError("failed to parse Identifier: not a SEQUENCE")
	}

	id := &Identifier{Version: identifierVersionV1}

	// version Version DEFAULT v1：标准给出了 DEFAULT，故允许缺省；
	// 但若出现则必须为 v1。
	if seq.PeekASN1Tag(cryptobyteasn1.INTEGER) {
		var vers int64
		if !seq.ReadASN1Integer(&vers) {
			return nil, ibcParamError("failed to parse Identifier.version")
		}
		if vers != identifierVersionV1 {
			return nil, ibcParamError("unsupported Identifier.version: %d", vers)
		}
		id.Version = int(vers)
	}

	// ibcType OBJECT IDENTIFIER 必填
	if !seq.ReadASN1ObjectIdentifier(&id.IBCType) {
		return nil, ibcParamError("Identifier.ibcType is missing or malformed")
	}

	// ibcTypeAlias [0] OCTET STRING OPTIONAL
	if seq.PeekASN1Tag(cryptobyteasn1.Tag(0).ContextSpecific()) {
		var alias cryptobyte.String
		if !seq.ReadASN1(&alias, cryptobyteasn1.Tag(0).ContextSpecific()) {
			return nil, ibcParamError("failed to parse Identifier.ibcTypeAlias")
		}
		id.IBCTypeAlias = []byte(alias)
	}

	// identityData OCTET STRING 必填
	if !seq.ReadASN1Bytes(&id.IdentityData, cryptobyteasn1.OCTET_STRING) {
		return nil, ibcParamError("Identifier.identityData is missing or malformed")
	}

	// validStart UTCTime 必填
	if !readASN1Time(&seq, &id.ValidStart) {
		return nil, ibcParamError("Identifier.validStart is missing or malformed")
	}

	// validEnd [1] UTCTime OPTIONAL
	if seq.PeekASN1Tag(cryptobyteasn1.Tag(1).ContextSpecific()) {
		var validEnd cryptobyte.String
		if !seq.ReadASN1(&validEnd, cryptobyteasn1.Tag(1).ContextSpecific()) ||
			!readASN1Time(&validEnd, &id.ValidEnd) {
			return nil, ibcParamError("failed to parse Identifier.validEnd")
		}
		if !validEnd.Empty() {
			return nil, ibcParamError("trailing data in Identifier.validEnd")
		}
	}

	// extensions [2] Extensions OPTIONAL
	if seq.PeekASN1Tag(cryptobyteasn1.Tag(2).ContextSpecific().Constructed()) {
		if !readIdentifierExtensions(&seq, &id.Extensions) {
			return nil, ibcParamError("failed to parse Identifier.extensions")
		}
	}

	// SEQUENCE 内剩余字节：忽略（向前兼容），不做校验。
	return id, nil
}

// addASN1Time 按编码/asn1 包的惯例编码时间：1950..2049 使用 UTCTime，否则 GeneralizedTime。
func addASN1Time(b *cryptobyte.Builder, t time.Time) {
	if t.Year() >= 1950 && t.Year() <= 2049 {
		b.AddASN1UTCTime(t)
		return
	}
	b.AddASN1GeneralizedTime(t)
}

// readASN1Time 读取 UTCTime 或 GeneralizedTime。
func readASN1Time(s *cryptobyte.String, out *time.Time) bool {
	switch {
	case s.PeekASN1Tag(cryptobyteasn1.UTCTime):
		return s.ReadASN1UTCTime(out)
	case s.PeekASN1Tag(cryptobyteasn1.GeneralizedTime):
		return s.ReadASN1GeneralizedTime(out)
	default:
		return false
	}
}

// readIdentifierExtensions 读取 [2] Extensions。
//
// 标准未在方案中明确 tagging 模式，故同时兼容：
//   - IMPLICIT：a2 <len> { Extension... }
//   - EXPLICIT：a2 <len> SEQUENCE { Extension... }
//
// 两者无法直接从长度上区分（单个 Extension 的 IMPLICIT 内容恰好也是一个 SEQUENCE），
// 因此先按 IMPLICIT 尝试，失败后再剥离一层 EXPLICIT 包装重试。
//
// extensions 的内容本身不解析（发布服务扩展的 extnID 是占位符），仅整体保留。
func readIdentifierExtensions(s *cryptobyte.String, out *[]Extension) bool {
	var content cryptobyte.String
	if !s.ReadASN1(&content, cryptobyteasn1.Tag(2).ContextSpecific().Constructed()) {
		return false
	}
	if parseExtensionList(content, out) {
		return true
	}
	// 退化为 EXPLICIT 形式。
	var inner cryptobyte.String
	rest := content
	if !rest.ReadASN1(&inner, cryptobyteasn1.SEQUENCE) || !rest.Empty() {
		return false
	}
	*out = nil
	return parseExtensionList(inner, out)
}

// parseExtensionList 解析 Extensions ::= SEQUENCE OF Extension 的内容部分。
func parseExtensionList(content cryptobyte.String, out *[]Extension) bool {
	var list []Extension
	for !content.Empty() {
		var item cryptobyte.String
		if !content.ReadASN1(&item, cryptobyteasn1.SEQUENCE) {
			return false
		}
		var ext Extension
		if !item.ReadASN1ObjectIdentifier(&ext.ExtnID) {
			return false
		}
		if item.PeekASN1Tag(cryptobyteasn1.BOOLEAN) {
			if !item.ReadASN1Boolean(&ext.Critical) {
				return false
			}
		}
		if !item.ReadASN1Bytes(&ext.ExtnValue, cryptobyteasn1.OCTET_STRING) {
			return false
		}
		list = append(list, ext)
	}
	*out = append(*out, list...)
	return true
}

// identityDataOf 从 ibc_id / client_id 的原始字节中抽取标识内容。
//
// 标识有两个允许的载体（GM/T 0024-2023 6.4.5.3）：GM/T 0090 的 Identifier DER，
// 或用户自定义的裸标识字节串。若可解析为 Identifier 则返回 identityData，
// 否则原样返回。
func identityDataOf(raw []byte) []byte {
	if len(raw) == 0 {
		return raw
	}
	if id, err := ParseIdentifier(raw); err == nil {
		return id.IdentityData
	}
	return raw
}

// ValidityPeriod 对应 GM/T 0081-2020 中的 ValidityPeriod 结构。
//
//	ValidityPeriod ::= SEQUENCE {
//	    notBefore Time,
//	    notAfter  Time
//	}
//
// 标准未在本文件给出形式定义，按 §6.9 的 Validity 处理。
type ValidityPeriod struct {
	// NotBefore 有效期起点，起始时间。
	// 按 §6.9 要求必须以格林威治时间表示并包含秒（形如 YYYYMMDDHHMMSSZ），
	// 即使秒数为零也要表示到最近的秒数。零值表示不限制下界。
	NotBefore time.Time

	// NotAfter 有效期终点，终止时间；时间表示要求同 NotBefore。
	// 零值表示不限制上界。
	NotAfter time.Time
}

// IsZero 判断有效期是否为空。
//
// 返回值：
//   - bool：NotBefore 与 NotAfter 均为零值时返回 true，否则返回 false。
func (v ValidityPeriod) IsZero() bool {
	return v.NotBefore.IsZero() && v.NotAfter.IsZero()
}

// Contains 判断 t 是否落在有效期内（闭区间）。
//
// 参数：
//   - t：待判断的时间点。
//
// 返回值：
//   - bool：t 位于有效期内返回 true，否则返回 false。
//
// 零值边界视为无限制：NotBefore 为零值时不校验下界，NotAfter 为零值时不校验上界；
// 边界值本身包含在有效期内（闭区间）。
func (v ValidityPeriod) Contains(t time.Time) bool {
	if !v.NotBefore.IsZero() && t.Before(v.NotBefore) {
		return false
	}
	if !v.NotAfter.IsZero() && t.After(v.NotAfter) {
		return false
	}
	return true
}

// IBCPublicParameter 对应 IBCSysParams.ibcPublicParameters 中的一项（GM/T 0081-2020 附录 A.2）。
//
//	IBCPublicParameter ::= SEQUENCE {
//	    ibcAlgorithm        OBJECT IDENTIFIER,
//	    publicParameterData OCTET STRING
//	}
type IBCPublicParameter struct {
	// IBCAlgorithm OID 确定了 IBC 算法式，用于挑选 SM9 那一项。
	IBCAlgorithm asn1.ObjectIdentifier

	// PublicParameterData 的**内容**是 SM9PublicParameterData 的 DER 编码结构（两层编码），
	// 其中包含了真实的加密参数。
	PublicParameterData []byte
}

// IBCParamExtension 是 IBCSysParams 的参数扩展项（GM/T 0081-2020 附录 A.2）。
//
//	IBCParamExtension ::= SEQUENCE {
//	    ibcParamExtensionOID   OBJECT IDENTIFIER,
//	    ibcParamExtensionValue OCTET STRING
//	}
type IBCParamExtension struct {
	// IBCParamExtensionOID 扩展的 OID，确定该扩展的语义。
	IBCParamExtensionOID asn1.ObjectIdentifier

	// IBCParamExtensionValue 八位字符串内容由具体的 ibcParamExtensionOID 确定；
	// 一个域的 IBCParamExtensions 可能包含任何数量的扩展（包括零在内）。
	IBCParamExtensionValue []byte
}

// ===== IBCSysParams 的低层 DER 映射 =====

// ibcSysParamsWire 对应 GM/T 0081-2020 附录 A.2 的 IBCSysParams。
//
//	IBCSysParams ::= SEQUENCE {
//	    version             INTEGER { v2(2) },
//	    districtName        IA5String,
//	    districtSerial      INTEGER,
//	    validity            ValidityPeriod,
//	    ibcPublicParameters IBCPublicParameters,
//	    ibcIdentityType     OBJECT IDENTIFIER,
//	    issuerID            Identifier,
//	    ibcParamExtensions  IBCParamExtensions OPTIONAL
//	}
type ibcSysParamsWire struct {
	// Version version INTEGER { v2(2) }，格式版本，应为 2。
	Version int
	// DistrictName districtName IA5String，以 URI 或 IRI 编码的 KGC 域名称。
	DistrictName string `asn1:"ia5"`
	// DistrictSerial districtSerial INTEGER，域名称下该组公共参数的唯一编号。
	DistrictSerial int
	// Validity validity ValidityPeriod，本组公共参数的有效期。
	Validity ValidityPeriod
	// IBCPublicParameters ibcPublicParameters IBCPublicParameters，
	// PKG 支持的各 IBC 算法式对应的公共参数集合，至少一项。
	IBCPublicParameters []IBCPublicParameter
	// IBCIdentityType ibcIdentityType OBJECT IDENTIFIER，本区域使用的身份类型。
	IBCIdentityType asn1.ObjectIdentifier
	// IssuerID issuerID Identifier，公开参数颁发者标识（整体以 DER 透传）。
	IssuerID asn1.RawValue
	// IBCParamExtensions ibcParamExtensions IBCParamExtensions OPTIONAL，扩散参数项。
	IBCParamExtensions []IBCParamExtension `asn1:"optional"`
}

// sm9PublicParameterData 是 IBCPublicParameter.publicParameterData 的内层结构。
//
//	SM9PublicParameterData ::= SEQUENCE {
//	    pkgID             OCTET STRING,
//	    encMastPublicKey  SM9EncryptMasterPublicKey,
//	    signMastPublicKey SM9SignMasterPublicKey
//	}
type sm9PublicParameterData struct {
	// PkgID 私钥生成中心标识（pkgID OCTET STRING）。
	PkgID []byte
	// EncMastPublicKey 加密主公钥（encMastPublicKey SM9EncryptMasterPublicKey）。
	EncMastPublicKey asn1.RawValue
	// SignMastPublicKey 签名主公钥（signMastPublicKey SM9SignMasterPublicKey）。
	SignMastPublicKey asn1.RawValue
}

// marshalIBCSysParams 将低层映射编码为 DER。
func marshalIBCSysParams(w *ibcSysParamsWire) ([]byte, error) {
	return asn1.Marshal(*w)
}

// parseIBCSysParams 解析 DER 编码的 IBCSysParams。
//
// 解析规则（§3.4）：
//   - version 缺失或不为 2 → bad_ibcparam
//   - tag 类型不符 / 标准要求的字段缺失 → bad_ibcparam
//   - SEQUENCE 内剩余字节 → 忽略
func parseIBCSysParams(der []byte) (*ibcSysParamsWire, error) {
	var w ibcSysParamsWire
	rest, err := asn1.Unmarshal(der, &w)
	if err != nil {
		return nil, ibcParamError("failed to parse IBCSysParams: %v", err)
	}
	_ = rest // 结构尾部剩余字节忽略，向前兼容
	if w.Version != ibcSysParamsVersionV2 {
		return nil, ibcParamError("unsupported IBCSysParams.version: %d", w.Version)
	}
	if len(w.IBCPublicParameters) == 0 {
		return nil, ibcParamError("IBCSysParams.ibcPublicParameters is empty")
	}
	if len(w.IssuerID.FullBytes) == 0 {
		return nil, ibcParamError("IBCSysParams.issuerID is missing")
	}
	return &w, nil
}

// ===== KeyAgreementInfo（GM/T 0081-2020 §12） =====

// KeyAgreementInfo 对应 GM/T 0081-2020 §12 的 KeyAgreementInfo，
// 即 TLCP 的 ServerIBSDHParams / ClientIBSDHParams 载荷。
//
//	KeyAgreementInfo ::= SEQUENCE {
//	    version  Version,                    -- INTEGER(1)，必填
//	    tempKey  SM9MastEncryptPublicKey,    -- 临时公钥
//	    userID_A OCTET STRING,               -- 发起方（服务端）标识
//	    userID_B OCTET STRING,               -- 响应方（客户端）标识
//	    hid      OCTET STRING                -- 算法类型，固定 0x02
//	}
type KeyAgreementInfo struct {
	// Version Version(1)，语法版本号，本结构固定取 1。
	Version int

	// TempKey 临时密钥（tempKey SM9MastEncryptPublicKey），
	// 见附录 A 或 GM/T 0080；此处为 65 字节未压缩 G1 点。
	TempKey []byte

	// UserID_A 发起方用户标识（本实现中为服务端）。
	UserID_A []byte

	// UserID_B 响应方用户标识（本实现中为客户端）。
	UserID_B []byte

	// Hid 算法类型（OCTET STRING），密钥交换固定取 0x02（hidSM9KeyExch）。
	// 本库不做取值校验：编码时原样写出，解析时原样保留，由握手层直接使用。
	Hid byte
}

// keyAgreementInfoWire 是 KeyAgreementInfo 的 DER 映射类型。
type keyAgreementInfoWire struct {
	// Version version Version，语法版本号，固定为 1。
	Version int
	// TempKey tempKey SM9MastEncryptPublicKey，临时公钥（整体以 DER 透传）。
	TempKey asn1.RawValue
	// UserID_A userID_A OCTET STRING，发起方用户标识。
	UserID_A []byte
	// UserID_B userID_B OCTET STRING，响应方用户标识。
	UserID_B []byte
	// Hid hid OCTET STRING，算法类型，密钥协商固定为 0x02；解析时不校验取值。
	Hid []byte
}

// marshalSM9MastEncryptPublicKey 按 SM9MastEncryptPublicKey ::= SEQUENCE { BIT STRING }
// 编码临时公钥。
func marshalSM9MastEncryptPublicKey(point []byte) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(cryptobyteasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BitString(point)
	})
	return b.Bytes()
}

// parseSM9MastEncryptPublicKey 解析临时公钥，兼容两种封装：
//   - SEQUENCE { BIT STRING }
//   - 裸 BIT STRING
func parseSM9MastEncryptPublicKey(der []byte) ([]byte, error) {
	input := cryptobyte.String(der)
	var point []byte
	if input.PeekASN1Tag(cryptobyteasn1.SEQUENCE) {
		var inner cryptobyte.String
		if !input.ReadASN1(&inner, cryptobyteasn1.SEQUENCE) ||
			!inner.ReadASN1BitStringAsBytes(&point) ||
			!inner.Empty() {
			return nil, ibcParamError("invalid tempKey encoding")
		}
	} else if !input.ReadASN1BitStringAsBytes(&point) {
		return nil, ibcParamError("invalid tempKey encoding")
	}
	if !input.Empty() {
		return nil, ibcParamError("trailing data in tempKey")
	}
	if err := verifySM9G1Point(point); err != nil {
		return nil, err
	}
	return point, nil
}

// marshalKeyAgreementInfo 编码 KeyAgreementInfo。
func marshalKeyAgreementInfo(info *KeyAgreementInfo) ([]byte, error) {
	tempKey, err := marshalSM9MastEncryptPublicKey(info.TempKey)
	if err != nil {
		return nil, err
	}
	w := keyAgreementInfoWire{
		Version:  info.Version,
		TempKey:  asn1.RawValue{FullBytes: tempKey},
		UserID_A: info.UserID_A,
		UserID_B: info.UserID_B,
		Hid:      []byte{info.Hid},
	}
	return asn1.Marshal(w)
}

// parseKeyAgreementInfo 解析 DER 编码的 KeyAgreementInfo。
//
// 解析规则（§3.4）：
//   - version 缺失或不为 1 → bad_ibcparam
//   - hid 不是 1 字节 OCTET STRING → bad_ibcparam（只校验编码长度，不校验取值）
//   - tempKey 不是合法 G1 点 → bad_ibcparam
//   - SEQUENCE 内剩余字节 → 忽略
func parseKeyAgreementInfo(der []byte) (*KeyAgreementInfo, error) {
	var w keyAgreementInfoWire
	rest, err := asn1.Unmarshal(der, &w)
	if err != nil {
		return nil, ibcParamError("failed to parse KeyAgreementInfo: %v", err)
	}
	_ = rest // 结构尾部剩余字节忽略，向前兼容
	if w.Version != keyAgreementInfoVersionV1 {
		return nil, ibcParamError("unsupported KeyAgreementInfo.version: %d", w.Version)
	}
	// 只校验 hid 的编码长度，不校验其取值：hid 由发送方填写，接收方按消息中的值
	// 参与密钥交换。该字段受 signed_params 签名覆盖，篡改会被签名校验拦下。
	if len(w.Hid) != 1 {
		return nil, ibcParamError("KeyAgreementInfo.hid must be a 1 byte OCTET STRING")
	}
	point, err := parseSM9MastEncryptPublicKey(rawValueBytes(&w.TempKey))
	if err != nil {
		return nil, err
	}
	return &KeyAgreementInfo{
		Version:  w.Version,
		TempKey:  point,
		UserID_A: w.UserID_A,
		UserID_B: w.UserID_B,
		Hid:      w.Hid[0],
	}, nil
}

// rawValueBytes 返回 asn1.RawValue 的完整 DER。
func rawValueBytes(v *asn1.RawValue) []byte {
	if len(v.FullBytes) > 0 {
		return v.FullBytes
	}
	return v.Bytes
}

// verifySM9G1Point 校验 65 字节未压缩 G1 点的合法性。
//
// 通过 gmsm 的 SM9 加密主公钥解析入口复用其曲线校验逻辑：
// 非法点（不在曲线上 / 无穷远）会被拒绝。
func verifySM9G1Point(point []byte) error {
	if len(point) != 65 || point[0] != 0x04 {
		return ibcParamError("tempKey is not an uncompressed G1 point")
	}
	// 拒绝无穷远点（未压缩编码下表现为坐标全零）。
	infinity := true
	for _, b := range point[1:] {
		if b != 0 {
			infinity = false
			break
		}
	}
	if infinity {
		return ibcParamError("tempKey is the point at infinity")
	}
	if _, err := sm9.UnmarshalEncryptMasterPublicKeyRaw(point); err != nil {
		return ibcParamError("tempKey is not a valid G1 point: %v", err)
	}
	return nil
}
