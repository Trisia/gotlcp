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
	"crypto/ecdsa"
	"fmt"
	"github.com/emmansun/gmsm/sm2"
	"io"
)

// SM2KeyAgreement SM2密钥交换接口，接口设计参考 GB/T 3622-2018
type SM2KeyAgreement interface {
	// GenerateAgreementData 发起方生成临时公钥，接口设计参考 GB/T 3622-2018 6.3.15
	GenerateAgreementData(sponsorId []byte, keyLen int) (sponsorPubKey, sponsorTmpPubKey *ecdsa.PublicKey, err error)
	// GenerateKey 发起方计算会话密钥，接口设计参考 GB/T 3622-2018 6.3.16
	GenerateKey(responseId []byte, responsePubKey, responseTmpPubKey *ecdsa.PublicKey) ([]byte, error)
	// GenerateAgreementDataAndKey 响应方计算会话密钥并返回临时公钥，接口设计参考 GB/T 3622-2018 6.3.17
	GenerateAgreementDataAndKey(responseId, sponsorId []byte, sponsorPubKey, sponsorTmpPubKey *ecdsa.PublicKey, kenLen int) (*ecdsa.PublicKey, []byte, error)
}

type sm2ke struct {
	rd     io.Reader
	prv    *sm2.PrivateKey
	ke     *sm2.KeyExchange
	keyLen int
}

func newSM2Key(rd io.Reader, prv *sm2.PrivateKey) *sm2ke {
	return &sm2ke{rd: rd, prv: prv}
}

func (s *sm2ke) GenerateAgreementData(sponsorId []byte, keyLen int) (sponsorPubKey, sponsorTmpPubKey *ecdsa.PublicKey, err error) {
	s.ke, err = sm2.NewKeyExchange(s.prv, nil, sponsorId, nil, keyLen, false)
	if err != nil {
		return
	}
	sponsorPubKey = &s.prv.PublicKey
	// 计算发起方临时公钥
	sponsorTmpPubKey, err = s.ke.InitKeyExchange(s.rd)
	return
}

func (s *sm2ke) GenerateKey(responseId []byte, responsePubKey, responseTmpPubKey *ecdsa.PublicKey) ([]byte, error) {
	if s.ke == nil {
		return nil, fmt.Errorf("sm2ke: should call GenerateAgreementData frist")
	}
	err := s.ke.SetPeerParameters(responsePubKey, responseId)
	if err != nil {
		return nil, err
	}
	_, err = s.ke.ConfirmResponder(responseTmpPubKey, nil)
	if err != nil {
		return nil, err
	}
	return s.ke.GetSharedKey(), nil
}

func (s *sm2ke) GenerateAgreementDataAndKey(responseId, sponsorId []byte, sponsorPubKey, sponsorTmpPubKey *ecdsa.PublicKey, kenLen int) (*ecdsa.PublicKey, []byte, error) {
	var err error
	s.ke, err = sm2.NewKeyExchange(s.prv, sponsorPubKey, responseId, sponsorId, kenLen, false)
	if err != nil {
		return nil, nil, err
	}
	tmpPub, _, err := s.ke.RepondKeyExchange(s.rd, sponsorTmpPubKey)
	if err != nil {
		return nil, nil, err
	}
	return tmpPub, s.ke.GetSharedKey(), nil
}
