// Copyright (c) 2022 QuanGuanyu
// gotlcp is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package dtlcp

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/emmansun/gmsm/ecdh"
)

// SM2KeyAgreement SM2 密钥交换接口，接口设计参考 GB/T 36322-2018
type SM2KeyAgreement interface {
	// GenerateAgreementData 发起方生成临时公钥，接口设计参考 GB/T 36322-2018 6.3.15
	//
	// 参数：
	//   - sponsorId：发起方标识（用户 ID），参与后续会话密钥派生。
	//   - keyLen：期望的会话密钥长度，单位为字节，必须大于 0。
	//
	// 返回值：
	//   - sponsorPubKey：发起方长期公钥。
	//   - sponsorTmpPubKey：发起方本次生成的临时公钥。
	//   - err：keyLen 非法或临时密钥生成失败时返回非 nil。
	GenerateAgreementData(sponsorId []byte, keyLen int) (sponsorPubKey, sponsorTmpPubKey *ecdh.PublicKey, err error)
	// GenerateKey 发起方计算会话密钥，接口设计参考 GB/T 36322-2018 6.3.16
	//
	// 调用前必须先成功调用 GenerateAgreementData，由该方法保存发起方标识与密钥长度。
	//
	// 参数：
	//   - responseId：响应方标识（用户 ID），参与会话密钥派生。
	//   - responsePubKey：响应方长期公钥。
	//   - responseTmpPubKey：响应方临时公钥。
	//
	// 返回值：
	//   - []byte：长度为 GenerateAgreementData 所指定 keyLen 的会话密钥。
	//   - error：未先调用 GenerateAgreementData 或密钥协商失败时返回非 nil。
	GenerateKey(responseId []byte, responsePubKey, responseTmpPubKey *ecdh.PublicKey) ([]byte, error)
	// GenerateAgreementDataAndKey 响应方计算会话密钥并返回临时公钥，接口设计参考 GB/T 36322-2018 6.3.17
	//
	// 参数：
	//   - responseId：响应方标识（用户 ID），参与会话密钥派生。
	//   - sponsorId：发起方标识（用户 ID），参与会话密钥派生。
	//   - sponsorPubKey：发起方长期公钥。
	//   - sponsorTmpPubKey：发起方临时公钥。
	//   - keyLen：期望的会话密钥长度，单位为字节。
	//
	// 返回值：
	//   - *ecdh.PublicKey：响应方本次生成的临时公钥。
	//   - []byte：长度为 keyLen 的会话密钥。
	//   - error：临时密钥生成或密钥协商失败时返回非 nil。
	GenerateAgreementDataAndKey(responseId, sponsorId []byte, sponsorPubKey, sponsorTmpPubKey *ecdh.PublicKey, keyLen int) (*ecdh.PublicKey, []byte, error)
}

type sm2ke struct {
	rd     io.Reader
	prv    *ecdh.PrivateKey
	keyLen int              // only used by sponsor/server side
	uid    []byte           // only used by sponsor/server side
	ePrv   *ecdh.PrivateKey // only used by sponsor/server side
}

func newSM2KeyKE(rd io.Reader, prv *ecdh.PrivateKey) *sm2ke {
	if rd == nil {
		rd = rand.Reader
	}
	return &sm2ke{rd: rd, prv: prv}
}

func (s *sm2ke) GenerateAgreementData(sponsorId []byte, keyLen int) (sponsorPubKey, sponsorTmpPubKey *ecdh.PublicKey, err error) {
	if keyLen <= 0 {
		return nil, nil, errors.New("sm2ke: invalid key length")
	}
	// below values will be used by GenerateKey() method.
	s.keyLen = keyLen
	s.uid = sponsorId

	sponsorPubKey = s.prv.PublicKey()

	// 计算发起方临时公钥
	s.ePrv, err = ecdh.P256().GenerateKey(s.rd)
	if err != nil {
		return nil, nil, err
	}
	sponsorTmpPubKey = s.ePrv.PublicKey()
	return
}

func (s *sm2ke) GenerateKey(responseId []byte, responsePubKey, responseTmpPubKey *ecdh.PublicKey) ([]byte, error) {
	if s.ePrv == nil {
		return nil, fmt.Errorf("sm2ke: should call GenerateAgreementData frist")
	}
	secret, err := s.prv.SM2MQV(s.ePrv, responsePubKey, responseTmpPubKey)
	if err != nil {
		return nil, err
	}

	sharedKey, err := secret.SM2SharedKey(false, s.keyLen, s.prv.PublicKey(), responsePubKey, s.uid, responseId)
	if err != nil {
		return nil, err
	}

	return sharedKey, nil
}

func (s *sm2ke) GenerateAgreementDataAndKey(responseId, sponsorId []byte, sponsorPubKey, sponsorTmpPubKey *ecdh.PublicKey, keyLen int) (*ecdh.PublicKey, []byte, error) {
	ePrv, err := ecdh.P256().GenerateKey(s.rd)
	if err != nil {
		return nil, nil, err
	}
	secret, err := s.prv.SM2MQV(ePrv, sponsorPubKey, sponsorTmpPubKey)
	if err != nil {
		return nil, nil, err
	}

	sharedKey, err := secret.SM2SharedKey(true, keyLen, s.prv.PublicKey(), sponsorPubKey, responseId, sponsorId)
	if err != nil {
		return nil, nil, err
	}

	return ePrv.PublicKey(), sharedKey, nil
}
