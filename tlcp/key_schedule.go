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
	"crypto/elliptic"
	"errors"
	"github.com/emmansun/gmsm/sm2"
	"io"
	"math/big"
)

// ecdheParameters implements Diffie-Hellman with either NIST curves or X25519,
// according to RFC 8446, Section 4.2.8.2.
type ecdheParameters interface {
	CurveID() CurveID
	PublicKey() []byte
	SharedKey(peerPublicKey []byte) []byte
}

// generateECDHEParameters 生成 ECDHE 参数
func generateECDHEParameters(rand io.Reader, curveID CurveID) (ecdheParameters, error) {
	if curveID != CurveSM2 {
		return nil, errors.New("tlcp: internal error unsupported curve")
	}

	// SM2曲线
	curve := sm2.P256()

	p := &eccParameters{curveID: curveID}
	var err error
	// 生成DHE的私钥 d1 并使用 d1*G 客户端公钥点 p1
	p.privateKey, p.x, p.y, err = elliptic.GenerateKey(curve, rand)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// curveForCurveID 通过曲线ID获取曲线
func curveForCurveID(id CurveID) (elliptic.Curve, bool) {
	switch id {
	case CurveSM2:
		return sm2.P256(), true
	default:
		return nil, false
	}
}

// eccParameters SM2密钥交换传输
type eccParameters struct {
	privateKey []byte
	x, y       *big.Int // public key
	curveID    CurveID
}

// CurveID 获取椭圆曲线ID
func (p *eccParameters) CurveID() CurveID {
	return p.curveID
}

// PublicKey 计算临时公钥 d*G
func (p *eccParameters) PublicKey() []byte {
	curve, _ := curveForCurveID(p.curveID)
	return elliptic.Marshal(curve, p.x, p.y)
}

// SharedKey 计算DH的共享密钥 (d1*d2*G)
//
// peerPublicKey: 对端临时公钥
//
// return: 共享密钥
func (p *eccParameters) SharedKey(peerPublicKey []byte) []byte {
	curve, _ := curveForCurveID(p.curveID)
	// Unmarshal also checks whether the given point is on the curve.
	x, y := elliptic.Unmarshal(curve, peerPublicKey)
	if x == nil {
		return nil
	}

	xShared, _ := curve.ScalarMult(x, y, p.privateKey)
	sharedKey := make([]byte, (curve.Params().BitSize+7)/8)
	return xShared.FillBytes(sharedKey)
}
