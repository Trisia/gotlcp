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
	"crypto/rand"
	"encoding/asn1"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm9"
	"github.com/emmansun/gmsm/smx509"
	"golang.org/x/crypto/cryptobyte"
	cryptobyteasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	testOIDOther = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 999}
)

// testIBCMaster 生成一对 SM9 主密钥。
func testIBCMaster(t *testing.T) (*sm9.SignMasterPrivateKey, *sm9.EncryptMasterPrivateKey) {
	t.Helper()
	sign, err := sm9.GenerateSignMasterKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateSignMasterKey: %v", err)
	}
	enc, err := sm9.GenerateEncryptMasterKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateEncryptMasterKey: %v", err)
	}
	return sign, enc
}

// testIBCSysParams 生成一组有效期覆盖当前时间的公共参数。
func testIBCSysParams(t *testing.T) *IBCSysParams {
	t.Helper()
	sign, enc := testIBCMaster(t)
	now := time.Now().Truncate(time.Second)
	params, err := NewIBCSysParamsFromMaster("test.kgc.example", 1,
		ValidityPeriod{NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}, sign, enc)
	if err != nil {
		t.Fatalf("NewIBCSysParamsFromMaster: %v", err)
	}
	return params
}

// appendToSequence 在 DER SEQUENCE 的末尾追加原始字节，并修正长度域。
func appendToSequence(t *testing.T, der, extra []byte) []byte {
	t.Helper()
	if len(der) < 2 || der[0] != 0x30 {
		t.Fatalf("not a DER SEQUENCE")
	}
	var headerLen int
	var contentLen int
	if der[1] < 0x80 {
		headerLen = 2
		contentLen = int(der[1])
	} else {
		n := int(der[1] & 0x7F)
		headerLen = 2 + n
		for i := 0; i < n; i++ {
			contentLen = contentLen<<8 | int(der[2+i])
		}
	}
	if contentLen != len(der)-headerLen {
		t.Fatalf("length mismatch: %d vs %d", contentLen, len(der)-headerLen)
	}
	content := append(append([]byte(nil), der[headerLen:]...), extra...)
	var b cryptobyte.Builder
	b.AddASN1(cryptobyteasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(content)
	})
	out, err := b.Bytes()
	if err != nil {
		t.Fatalf("rebuild sequence: %v", err)
	}
	return out
}

func TestIdentifierRoundTrip(t *testing.T) {
	start := time.Date(2024, 3, 4, 5, 6, 7, 0, time.UTC)
	id := &Identifier{
		Version:      identifierVersionV1,
		IBCType:      oidSM9,
		IBCTypeAlias: []byte("alias"),
		IdentityData: []byte("alice@example.com"),
		ValidStart:   start,
		ValidEnd:     start.Add(24 * time.Hour),
		Extensions: []Extension{{
			ExtnID:    asn1.ObjectIdentifier{1, 2, 3},
			Critical:  true,
			ExtnValue: []byte{0xAA, 0xBB},
		}},
	}
	der, err := id.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := ParseIdentifier(der)
	if err != nil {
		t.Fatalf("ParseIdentifier: %v", err)
	}
	if got.Version != id.Version ||
		!got.IBCType.Equal(id.IBCType) ||
		!bytes.Equal(got.IBCTypeAlias, id.IBCTypeAlias) ||
		!bytes.Equal(got.IdentityData, id.IdentityData) ||
		!got.ValidStart.Equal(id.ValidStart) ||
		!got.ValidEnd.Equal(id.ValidEnd) ||
		len(got.Extensions) != 1 ||
		!got.Extensions[0].ExtnID.Equal(id.Extensions[0].ExtnID) ||
		got.Extensions[0].Critical != id.Extensions[0].Critical ||
		!bytes.Equal(got.Extensions[0].ExtnValue, id.Extensions[0].ExtnValue) {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}

// TestIdentifierVersionDefault Identifier 的 version 有 DEFAULT v1，缺失时应取 v1。
func TestIdentifierVersionDefault(t *testing.T) {
	var b cryptobyte.Builder
	b.AddASN1(cryptobyteasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oidSM9)
		b.AddASN1OctetString([]byte("bob"))
		b.AddASN1UTCTime(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))
	})
	der, _ := b.Bytes()
	id, err := ParseIdentifier(der)
	if err != nil {
		t.Fatalf("ParseIdentifier: %v", err)
	}
	if id.Version != identifierVersionV1 || string(id.IdentityData) != "bob" {
		t.Fatalf("unexpected identifier: %+v", id)
	}
}

func TestIdentifierParseRules(t *testing.T) {
	validStart := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	build := func(f func(b *cryptobyte.Builder)) []byte {
		var b cryptobyte.Builder
		b.AddASN1(cryptobyteasn1.SEQUENCE, f)
		der, err := b.Bytes()
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		return der
	}

	tests := []struct {
		name string
		der  []byte
		ok   bool
	}{
		{
			name: "version 值不符",
			der: build(func(b *cryptobyte.Builder) {
				b.AddASN1Int64(2)
				b.AddASN1ObjectIdentifier(oidSM9)
				b.AddASN1OctetString([]byte("a"))
				b.AddASN1UTCTime(validStart)
			}),
		},
		{
			name: "ibcType 缺失",
			der: build(func(b *cryptobyte.Builder) {
				b.AddASN1Int64(1)
				b.AddASN1OctetString([]byte("a"))
				b.AddASN1UTCTime(validStart)
			}),
		},
		{
			name: "identityData tag 不符",
			der: build(func(b *cryptobyte.Builder) {
				b.AddASN1Int64(1)
				b.AddASN1ObjectIdentifier(oidSM9)
				b.AddASN1Int64(5)
				b.AddASN1UTCTime(validStart)
			}),
		},
		{
			name: "validStart 缺失",
			der: build(func(b *cryptobyte.Builder) {
				b.AddASN1Int64(1)
				b.AddASN1ObjectIdentifier(oidSM9)
				b.AddASN1OctetString([]byte("a"))
			}),
		},
		{
			name: "SEQUENCE 尾部剩余字节被忽略",
			der: build(func(b *cryptobyte.Builder) {
				b.AddASN1Int64(1)
				b.AddASN1ObjectIdentifier(oidSM9)
				b.AddASN1OctetString([]byte("a"))
				b.AddASN1UTCTime(validStart)
				b.AddASN1Int64(42)
			}),
			ok: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseIdentifier(tt.der)
			if tt.ok && err != nil {
				t.Fatalf("expected success, got %v", err)
			}
			if !tt.ok {
				if err == nil {
					t.Fatal("expected failure, got nil")
				}
				if a := alertForError(err, 0); a != alertBadIbcparam {
					t.Fatalf("expected bad_ibcparam, got %v", a)
				}
			}
		})
	}
}

// TestIdentifierExplicitExtensions 兼容 extensions 的显式标签编码。
func TestIdentifierExplicitExtensions(t *testing.T) {
	var b cryptobyte.Builder
	b.AddASN1(cryptobyteasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(1)
		b.AddASN1ObjectIdentifier(oidSM9)
		b.AddASN1OctetString([]byte("a"))
		b.AddASN1UTCTime(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))
		// EXPLICIT：[2] 内含完整 SEQUENCE OF Extension
		b.AddASN1(cryptobyteasn1.Tag(2).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			b.AddASN1(cryptobyteasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1(cryptobyteasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1ObjectIdentifier(asn1.ObjectIdentifier{1, 2, 3})
					b.AddASN1OctetString([]byte{0x01})
				})
			})
		})
	})
	der, _ := b.Bytes()
	id, err := ParseIdentifier(der)
	if err != nil {
		t.Fatalf("ParseIdentifier: %v", err)
	}
	if len(id.Extensions) != 1 || !id.Extensions[0].ExtnID.Equal(asn1.ObjectIdentifier{1, 2, 3}) {
		t.Fatalf("unexpected extensions: %+v", id.Extensions)
	}
}

func TestIdentityDataOf(t *testing.T) {
	id := &Identifier{
		Version:      1,
		IBCType:      oidSM9,
		IdentityData: []byte("carol"),
		ValidStart:   time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	der, _ := id.Marshal()
	if got := identityDataOf(der); string(got) != "carol" {
		t.Fatalf("identifier form: got %q", got)
	}
	if got := identityDataOf([]byte("dave")); string(got) != "dave" {
		t.Fatalf("raw form: got %q", got)
	}
}

func TestIBCSysParamsRoundTrip(t *testing.T) {
	params := testIBCSysParams(t)
	der, err := params.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := ParseIBCSysParams(der)
	if err != nil {
		t.Fatalf("ParseIBCSysParams: %v", err)
	}
	if got.Version != ibcSysParamsVersionV2 ||
		got.DistrictName != params.DistrictName ||
		got.DistrictSerial != params.DistrictSerial ||
		!got.Validity.NotBefore.Equal(params.Validity.NotBefore) ||
		!got.Validity.NotAfter.Equal(params.Validity.NotAfter) {
		t.Fatalf("metadata mismatch: %+v", got)
	}
	if !bytes.Equal(got.SignMasterPublicKey.Bytes(), params.SignMasterPublicKey.Bytes()) ||
		!bytes.Equal(got.EncryptMasterPublicKey.Bytes(), params.EncryptMasterPublicKey.Bytes()) {
		t.Fatal("master public key mismatch")
	}
	if got.IssuerID == nil || string(got.IssuerID.IdentityData) != params.DistrictName {
		t.Fatalf("issuer id mismatch: %+v", got.IssuerID)
	}

	// 两层编码：publicParameterData 的内容可二次解码为 SM9PublicParameterData。
	var inner sm9PublicParameterData
	if _, err := asn1.Unmarshal(got.IBCPublicParameters[0].PublicParameterData, &inner); err != nil {
		t.Fatalf("second layer decode: %v", err)
	}
	if len(inner.EncMastPublicKey.FullBytes) == 0 || len(inner.SignMastPublicKey.FullBytes) == 0 {
		t.Fatal("missing master public key in inner encoding")
	}
}

// TestIBCSysParamsExtensionsRoundTrip 验证 ibcParamExtensions 的编解码往返。
//
// 该字段为 OPTIONAL，解析时仅在 SEQUENCE 尚有余量时读取；编码类型已由公开的
// IBCParamExtension 直接承担，此处覆盖此前缺失的往返验证。
func TestIBCSysParamsExtensionsRoundTrip(t *testing.T) {
	params := testIBCSysParams(t)
	params.Raw = nil // 清空 Raw，强制走逐字段编码路径。
	params.IBCParamExtensions = []IBCParamExtension{
		{IBCParamExtensionOID: testOIDOther, IBCParamExtensionValue: []byte{0x01, 0x02}},
		{IBCParamExtensionOID: oidSM9, IBCParamExtensionValue: nil},
	}
	der, err := params.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := ParseIBCSysParams(der)
	if err != nil {
		t.Fatalf("ParseIBCSysParams: %v", err)
	}
	if len(got.IBCParamExtensions) != len(params.IBCParamExtensions) {
		t.Fatalf("extensions count = %d, want %d", len(got.IBCParamExtensions), len(params.IBCParamExtensions))
	}
	for i, want := range params.IBCParamExtensions {
		g := got.IBCParamExtensions[i]
		if !g.IBCParamExtensionOID.Equal(want.IBCParamExtensionOID) ||
			!bytes.Equal(g.IBCParamExtensionValue, want.IBCParamExtensionValue) {
			t.Fatalf("extensions[%d] = %+v, want %+v", i, g, want)
		}
	}
}

// TestIBCSysParamsMultiAlgorithm 验证多算法式：按 OID 挑选 SM9 项。
func TestIBCSysParamsMultiAlgorithm(t *testing.T) {
	params := testIBCSysParams(t)
	var w ibcSysParamsWire
	if _, err := asn1.Unmarshal(params.Raw, &w); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// 在 SM9 项之前插入一个其它算法的项，其数据无法解析。
	w.IBCPublicParameters = append([]IBCPublicParameter{{
		IBCAlgorithm:        testOIDOther,
		PublicParameterData: []byte{0xDE, 0xAD, 0xBE, 0xEF},
	}}, w.IBCPublicParameters...)
	der, err := asn1.Marshal(w)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := ParseIBCSysParams(der)
	if err != nil {
		t.Fatalf("ParseIBCSysParams: %v", err)
	}
	if got.SignMasterPublicKey == nil {
		t.Fatal("SM9 entry not selected")
	}
}

// TestIBCSysParamsNoSM9 没有 SM9 项时返回 unsupported_ibcparam。
func TestIBCSysParamsNoSM9(t *testing.T) {
	params := testIBCSysParams(t)
	var w ibcSysParamsWire
	if _, err := asn1.Unmarshal(params.Raw, &w); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for i := range w.IBCPublicParameters {
		w.IBCPublicParameters[i].IBCAlgorithm = testOIDOther
	}
	der, _ := asn1.Marshal(w)
	_, err := ParseIBCSysParams(der)
	if err == nil {
		t.Fatal("expected failure")
	}
	if a := alertForError(err, 0); a != alertUnsupportedIbcparam {
		t.Fatalf("expected unsupported_ibcparam, got %v", a)
	}
}

// TestIBCSysParamsTrailingBytes SEQUENCE 内有剩余字节时忽略。
func TestIBCSysParamsTrailingBytes(t *testing.T) {
	params := testIBCSysParams(t)
	der := appendToSequence(t, params.Raw, []byte{0x02, 0x01, 0x2A})
	got, err := ParseIBCSysParams(der)
	if err != nil {
		t.Fatalf("ParseIBCSysParams: %v", err)
	}
	if got.DistrictSerial != params.DistrictSerial {
		t.Fatalf("unexpected params: %+v", got)
	}
}

func TestIBCSysParamsParseRules(t *testing.T) {
	params := testIBCSysParams(t)
	var w ibcSysParamsWire
	if _, err := asn1.Unmarshal(params.Raw, &w); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	t.Run("version 值不符", func(t *testing.T) {
		bad := w
		bad.Version = 1
		der, _ := asn1.Marshal(bad)
		_, err := ParseIBCSysParams(der)
		if err == nil {
			t.Fatal("expected failure")
		}
		if a := alertForError(err, 0); a != alertBadIbcparam {
			t.Fatalf("expected bad_ibcparam, got %v", a)
		}
	})

	t.Run("version 缺失", func(t *testing.T) {
		// 去掉 version 字段：直接手工构造一个缺少首个字段的 SEQUENCE。
		der := removeFirstSequenceField(t, params.Raw)
		if _, err := ParseIBCSysParams(der); err == nil {
			t.Fatal("expected failure")
		}
	})

	t.Run("tag 类型不符", func(t *testing.T) {
		// districtName 被编码为 INTEGER 而非 IA5String。
		var b cryptobyte.Builder
		b.AddASN1(cryptobyteasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1Int64(ibcSysParamsVersionV2)
			b.AddASN1Int64(1) // 应为 IA5String
			b.AddASN1Int64(1)
			b.AddASN1(cryptobyteasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1UTCTime(params.Validity.NotBefore)
				b.AddASN1UTCTime(params.Validity.NotAfter)
			})
			b.AddASN1(cryptobyteasn1.SEQUENCE, func(b *cryptobyte.Builder) {})
			b.AddASN1ObjectIdentifier(oidSM9)
			b.AddBytes(params.IssuerID.must(t))
		})
		der, _ := b.Bytes()
		if _, err := ParseIBCSysParams(der); err == nil {
			t.Fatal("expected failure")
		}
	})
}

// removeFirstSequenceField 去掉 DER SEQUENCE 的第一个元素。
func removeFirstSequenceField(t *testing.T, der []byte) []byte {
	t.Helper()
	content := sequenceContent(t, der)
	rest, err := asn1.Unmarshal(content, new(asn1.RawValue))
	if err != nil {
		t.Fatalf("unmarshal first field: %v", err)
	}
	var b cryptobyte.Builder
	b.AddASN1(cryptobyteasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(rest)
	})
	out, err := b.Bytes()
	if err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	return out
}

// sequenceContent 返回 DER SEQUENCE 的内容部分。
func sequenceContent(t *testing.T, der []byte) []byte {
	t.Helper()
	s := cryptobyte.String(der)
	var content cryptobyte.String
	if !s.ReadASN1(&content, cryptobyteasn1.SEQUENCE) {
		t.Fatalf("not a SEQUENCE")
	}
	return content
}

func TestKeyAgreementInfoRoundTrip(t *testing.T) {
	_, enc := testIBCMaster(t)
	point := enc.PublicKey().Bytes()

	info := &KeyAgreementInfo{
		Version:  keyAgreementInfoVersionV1,
		TempKey:  point,
		UserID_A: []byte("server"),
		UserID_B: []byte("client"),
		Hid:      hidSM9KeyExch,
	}
	der, err := marshalKeyAgreementInfo(info)
	if err != nil {
		t.Fatalf("marshalKeyAgreementInfo: %v", err)
	}
	got, err := parseKeyAgreementInfo(der)
	if err != nil {
		t.Fatalf("parseKeyAgreementInfo: %v", err)
	}
	if got.Version != info.Version ||
		!bytes.Equal(got.TempKey, info.TempKey) ||
		!bytes.Equal(got.UserID_A, info.UserID_A) ||
		!bytes.Equal(got.UserID_B, info.UserID_B) ||
		got.Hid != info.Hid {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}

// TestKeyAgreementInfoBareBitString tempKey 也接受裸 BIT STRING 形式。
func TestKeyAgreementInfoBareBitString(t *testing.T) {
	_, enc := testIBCMaster(t)
	point := enc.PublicKey().Bytes()

	var b cryptobyte.Builder
	b.AddASN1(cryptobyteasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(keyAgreementInfoVersionV1)
		b.AddASN1BitString(point)
		b.AddASN1OctetString([]byte("server"))
		b.AddASN1OctetString([]byte("client"))
		b.AddASN1OctetString([]byte{hidSM9KeyExch})
	})
	der, _ := b.Bytes()

	got, err := parseKeyAgreementInfo(der)
	if err != nil {
		t.Fatalf("parseKeyAgreementInfo: %v", err)
	}
	if !bytes.Equal(got.TempKey, point) {
		t.Fatal("temp key mismatch")
	}
}

func TestKeyAgreementInfoRejects(t *testing.T) {
	_, enc := testIBCMaster(t)
	point := enc.PublicKey().Bytes()
	base := &KeyAgreementInfo{
		Version:  keyAgreementInfoVersionV1,
		TempKey:  point,
		UserID_A: []byte("server"),
		UserID_B: []byte("client"),
		Hid:      hidSM9KeyExch,
	}

	tests := []struct {
		name   string
		mutate func(*KeyAgreementInfo)
	}{
		{"version 值不符", func(i *KeyAgreementInfo) { i.Version = 2 }},
		{"tempKey 非 G1 点", func(i *KeyAgreementInfo) { i.TempKey = make([]byte, 65); i.TempKey[0] = 0x04 }},
		{"tempKey 长度错误", func(i *KeyAgreementInfo) { i.TempKey = point[:64] }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := *base
			tt.mutate(&info)
			der, err := marshalKeyAgreementInfo(&info)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			_, err = parseKeyAgreementInfo(der)
			if err == nil {
				t.Fatal("expected failure")
			}
			if a := alertForError(err, 0); a != alertBadIbcparam {
				t.Fatalf("expected bad_ibcparam, got %v", a)
			}
		})
	}

	t.Run("version 缺失", func(t *testing.T) {
		var b cryptobyte.Builder
		b.AddASN1(cryptobyteasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1BitString(point)
			b.AddASN1OctetString([]byte("a"))
			b.AddASN1OctetString([]byte("b"))
			b.AddASN1OctetString([]byte{hidSM9KeyExch})
		})
		der, _ := b.Bytes()
		if _, err := parseKeyAgreementInfo(der); err == nil {
			t.Fatal("expected failure")
		}
	})

	t.Run("SEQUENCE 尾部剩余字节被忽略", func(t *testing.T) {
		der, _ := marshalKeyAgreementInfo(base)
		der = appendToSequence(t, der, []byte{0x02, 0x01, 0x2A})
		if _, err := parseKeyAgreementInfo(der); err != nil {
			t.Fatalf("expected success, got %v", err)
		}
	})
}

// TestKeyAgreementInfoAcceptsAnyHid 解析不再校验 hid 取值（只校验编码长度）：
// 任意 1 字节 hid 都被原样接受，由握手层按消息中的值参与密钥交换。
func TestKeyAgreementInfoAcceptsAnyHid(t *testing.T) {
	_, enc := testIBCMaster(t)
	point := enc.PublicKey().Bytes()

	build := func(hid []byte) []byte {
		var b cryptobyte.Builder
		b.AddASN1(cryptobyteasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1Int64(keyAgreementInfoVersionV1)
			b.AddASN1(cryptobyteasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1BitString(point)
			})
			b.AddASN1OctetString([]byte("server"))
			b.AddASN1OctetString([]byte("client"))
			b.AddASN1OctetString(hid)
		})
		der, err := b.Bytes()
		if err != nil {
			t.Fatalf("build KeyAgreementInfo: %v", err)
		}
		return der
	}

	for _, hid := range []byte{0x00, hidSM9Sign, hidSM9KeyExch, hidSM9Encrypt, 0xFF} {
		info, err := parseKeyAgreementInfo(build([]byte{hid}))
		if err != nil {
			t.Fatalf("parseKeyAgreementInfo(hid=0x%02X): %v", hid, err)
		}
		if info.Hid != hid {
			t.Fatalf("Hid = 0x%02X, want 0x%02X", info.Hid, hid)
		}
	}

	// 编码长度仍必须是 1 字节 OCTET STRING。
	if _, err := parseKeyAgreementInfo(build([]byte{hidSM9KeyExch, 0x00})); err == nil {
		t.Fatal("expected failure for a 2-byte hid")
	} else if a := alertForError(err, 0); a != alertBadIbcparam {
		t.Fatalf("expected bad_ibcparam, got %v", a)
	}
}

func TestIBCPoolContains(t *testing.T) {
	pool := NewIBCPool()
	if pool.Contains(nil) {
		t.Fatal("empty pool must not contain nil")
	}

	params := testIBCSysParams(t)
	if pool.Contains(params) {
		t.Fatal("params must not be contained before AddParams")
	}
	if err := pool.AddParams(params); err != nil {
		t.Fatalf("AddParams: %v", err)
	}
	if !pool.Contains(params) {
		t.Fatal("params must be contained after AddParams")
	}

	// 从 DER 重新解析后应仍命中（比对的是内容而非指针）。
	reparsed, err := ParseIBCSysParams(params.Raw)
	if err != nil {
		t.Fatalf("ParseIBCSysParams: %v", err)
	}
	if !pool.Contains(reparsed) {
		t.Fatal("reparsed params must be contained")
	}
	trusted, ok := pool.Lookup(reparsed)
	if !ok || !bytes.Equal(trusted.SignMasterPublicKey.Bytes(), params.SignMasterPublicKey.Bytes()) {
		t.Fatal("Lookup must return trusted params")
	}

	// 同一 districtName 但 serial 不同 → 未命中。
	other := *params
	other.DistrictSerial = params.DistrictSerial + 1
	if pool.Contains(&other) {
		t.Fatal("different serial must not be contained")
	}

	// 同一 (districtName, serial) 但主公钥不同 → 未命中。
	fake := testIBCSysParams(t)
	fake.DistrictName = params.DistrictName
	fake.DistrictSerial = params.DistrictSerial
	if pool.Contains(fake) {
		t.Fatal("different master public key must not be contained")
	}
}

func TestIBCPoolAddParamsDER(t *testing.T) {
	params := testIBCSysParams(t)
	pool := NewIBCPool()
	if err := pool.AddParamsDER(params.Raw); err != nil {
		t.Fatalf("AddParamsDER: %v", err)
	}
	if !pool.Contains(params) {
		t.Fatal("params must be contained")
	}
	if err := pool.AddParamsDER([]byte{0x01, 0x02}); err == nil {
		t.Fatal("expected failure for invalid DER")
	}
}

func TestIBCSysParamsVerifyValidity(t *testing.T) {
	params := testIBCSysParams(t)
	if err := params.VerifyValidity(time.Now()); err != nil {
		t.Fatalf("VerifyValidity: %v", err)
	}
	if err := params.VerifyValidity(params.Validity.NotAfter.Add(time.Second)); err == nil {
		t.Fatal("expected failure for expired params")
	} else if a := alertForError(err, 0); a != alertUnsupportedIbcparam {
		t.Fatalf("expected unsupported_ibcparam, got %v", a)
	}
	if err := params.VerifyValidity(params.Validity.NotBefore.Add(-time.Second)); err == nil {
		t.Fatal("expected failure for not yet valid params")
	}
}

func TestLoadIBCIdentity(t *testing.T) {
	signMaster, encMaster := testIBCMaster(t)
	uid := []byte("server@example.com")

	signPriv, err := signMaster.GenerateUserKey(uid, hidSM9Sign)
	if err != nil {
		t.Fatalf("GenerateUserKey(sign): %v", err)
	}
	encPriv, err := encMaster.GenerateUserKey(uid, hidSM9Encrypt)
	if err != nil {
		t.Fatalf("GenerateUserKey(enc): %v", err)
	}

	signDER, err := smx509.MarshalPKCS8PrivateKey(signPriv)
	if err != nil {
		t.Fatalf("marshal sign: %v", err)
	}
	encDER, err := smx509.MarshalPKCS8PrivateKey(encPriv)
	if err != nil {
		t.Fatalf("marshal enc: %v", err)
	}

	cfg, err := LoadIBCIdentity(uid, nil, signDER, encDER, nil)
	if err != nil {
		t.Fatalf("LoadIBCIdentity: %v", err)
	}
	if !bytes.Equal(cfg.Identity, uid) || cfg.SignPrivateKey == nil || cfg.EncryptPrivateKey == nil {
		t.Fatalf("unexpected config: %+v", cfg)
	}

	// 三个私钥均可为空。
	cfg, err = LoadIBCIdentity(uid, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("LoadIBCIdentity(nil keys): %v", err)
	}
	if cfg.SignPrivateKey != nil || cfg.EncryptPrivateKey != nil || cfg.KeyExchangePrivateKey != nil {
		t.Fatal("expected nil private keys")
	}
	if cfg.canKeyExchange() {
		t.Fatal("expected no IBSDH capability without a key exchange private key")
	}

	// 本端公共参数可以是 DER，装载时解析为 *IBCSysParams。
	params, err := NewIBCSysParamsFromMaster("kgc.example", 1, ValidityPeriod{}, signMaster, encMaster)
	if err != nil {
		t.Fatalf("NewIBCSysParamsFromMaster: %v", err)
	}
	paramsDER, err := params.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	cfg, err = LoadIBCIdentity(uid, paramsDER, signDER, encDER, nil)
	if err != nil {
		t.Fatalf("LoadIBCIdentity(paramsDER): %v", err)
	}
	if cfg.Parameters == nil || cfg.Parameters.DistrictName != "kgc.example" {
		t.Fatalf("unexpected parameters: %+v", cfg.Parameters)
	}
	if !bytes.Equal(cfg.Parameters.Raw, paramsDER) {
		t.Fatal("parameters should keep the original DER")
	}

	// 非法的公共参数 DER 会被拒绝。
	if _, err := LoadIBCIdentity(uid, []byte{0x30, 0x00}, signDER, encDER, nil); err == nil {
		t.Fatal("expected failure for invalid IBC parameters")
	}

	if _, err := LoadIBCIdentity(uid, nil, []byte{0x30, 0x00}, nil, nil); err == nil {
		t.Fatal("expected failure for invalid sign key")
	}
}

// TestLoadIBCIdentitySkipsKeyExchangeHidCheck 装载不再探测密钥交换私钥的派生 hid：
// 任意 hid 派生的私钥都被接受，标识也可为空——正确性由调用方保证，
// 配错的后果要到握手阶段（Finished 校验失败）才暴露。
func TestLoadIBCIdentitySkipsKeyExchangeHidCheck(t *testing.T) {
	_, encMaster := testIBCMaster(t)
	uid := []byte("server@example.com")

	kePriv, err := encMaster.GenerateUserKey(uid, hidSM9KeyExch)
	if err != nil {
		t.Fatalf("GenerateUserKey(ke): %v", err)
	}
	keDER, err := smx509.MarshalPKCS8PrivateKey(kePriv)
	if err != nil {
		t.Fatalf("marshal ke: %v", err)
	}

	ident, err := LoadIBCIdentity(uid, nil, nil, nil, keDER)
	if err != nil {
		t.Fatalf("LoadIBCIdentity(hid=0x02): %v", err)
	}
	if !ident.canKeyExchange() {
		t.Fatal("expected IBSDH capability")
	}

	// hid=0x03 的加密私钥同样被装载：库只做结构解析，不判断派生 hid。
	encPriv, err := encMaster.GenerateUserKey(uid, hidSM9Encrypt)
	if err != nil {
		t.Fatalf("GenerateUserKey(enc): %v", err)
	}
	encDER, err := smx509.MarshalPKCS8PrivateKey(encPriv)
	if err != nil {
		t.Fatalf("marshal enc: %v", err)
	}
	ident, err = LoadIBCIdentity(uid, nil, nil, nil, encDER)
	if err != nil {
		t.Fatalf("LoadIBCIdentity(hid=0x03) must be accepted, got: %v", err)
	}
	if !ident.canKeyExchange() {
		t.Fatal("expected IBSDH capability even for a hid=0x03 key (the library does not judge it)")
	}

	// 配置密钥交换私钥时不再要求标识非空；缺失标识会在握手阶段以 identity_need 失败。
	ident, err = LoadIBCIdentity(nil, nil, nil, nil, keDER)
	if err != nil {
		t.Fatalf("LoadIBCIdentity(empty identity) must be accepted, got: %v", err)
	}
	if len(ident.Identity) != 0 {
		t.Fatalf("expected an empty identity, got %x", ident.Identity)
	}
}

// must 返回 Identifier 的 DER，仅供测试使用。
func (id *Identifier) must(t *testing.T) []byte {
	t.Helper()
	der, err := id.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return der
}

// TestListenIBCOnlyConfig 验证 Listen 允许仅配置 IBC 能力、不携带任何 X.509
// 证书的服务端（见 IBC 配置指南 §6.1），同时仍拒绝什么身份都没有的配置。
func TestListenIBCOnlyConfig(t *testing.T) {
	t.Run("IBCIdentity", func(t *testing.T) {
		ln, err := Listen("tcp", "127.0.0.1:0", &Config{
			CipherSuites: []uint16{IBC_SM4_GCM_SM3},
			IBCIdentity:  &IBCIdentity{Identity: []byte("server@kgc.example")},
		})
		if err != nil {
			t.Fatalf("Listen with only IBCIdentity failed: %v", err)
		}
		ln.Close()
	})

	t.Run("GetIBCIdentity", func(t *testing.T) {
		ln, err := Listen("tcp", "127.0.0.1:0", &Config{
			CipherSuites: []uint16{IBC_SM4_GCM_SM3},
			GetIBCIdentity: func(*ClientHelloInfo) (*IBCIdentity, error) {
				return &IBCIdentity{Identity: []byte("server@kgc.example")}, nil
			},
		})
		if err != nil {
			t.Fatalf("Listen with only GetIBCIdentity failed: %v", err)
		}
		ln.Close()
	})

	t.Run("NoIdentity", func(t *testing.T) {
		if _, err := Listen("tcp", "127.0.0.1:0", &Config{
			CipherSuites: []uint16{IBC_SM4_GCM_SM3},
		}); err == nil {
			t.Fatal("expected failure when no certificate and no IBC identity are configured")
		}
	})
}
