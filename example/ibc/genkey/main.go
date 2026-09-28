// Copyright (c) 2022 QuanGuanyu
// gotlcp is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

// 本示例在进程内模拟 KGC：生成 SM9 主密钥、发布公共参数、为两个标识派生用户私钥，
// 并把公共参数与三把用户私钥编码为 PEM 字符串输出，供粘贴到
// example/ibc/quickstart 中作为内嵌常量使用。
//
// 运行：go run ./example/ibc/genkey
//
// 密钥材料的说明见 doc/CertAndKey.md 第 3 章。生产环境的主密钥必须由国家密码管理
// 机构认可的 KGC 离线生成与保管，本示例仅用于测试与调试。
package main

import (
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"log"
	"time"

	"gitee.com/Trisia/gotlcp/tlcp"
	"github.com/emmansun/gmsm/sm9"
	"github.com/emmansun/gmsm/smx509"
)

const (
	serverID = "server@kgc.example"
	clientID = "client@kgc.example"

	districtName   = "kgc.example"
	districtSerial = 1
)

func main() {
	// 1. KGC 生成签名主密钥与加密主密钥（生产环境由 KGC 离线保管，绝不外发）。
	signMaster, err := sm9.GenerateSignMasterKey(rand.Reader)
	if err != nil {
		log.Fatalf("生成签名主密钥失败: %v", err)
	}
	encMaster, err := sm9.GenerateEncryptMasterKey(rand.Reader)
	if err != nil {
		log.Fatalf("生成加密主密钥失败: %v", err)
	}

	// 2. 生成公共参数（IBCSysParams）。有效期取足够长，避免内嵌常量随示例过期。
	params, err := tlcp.NewIBCSysParamsFromMaster(
		districtName, districtSerial,
		tlcp.ValidityPeriod{
			NotBefore: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:  time.Date(2124, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		signMaster, encMaster,
	)
	if err != nil {
		log.Fatalf("生成公共参数失败: %v", err)
	}
	paramsPEM := string(pem.EncodeToMemory(&pem.Block{Type: "IBC PARAMETERS", Bytes: params.Raw}))

	// 3. 逐项派生用户私钥并编码为 PEM：签名 hid=0x01、加密 hid=0x03、密钥交换 hid=0x02。
	serverSignPEM := signKeyPEM(signMaster, serverID)
	serverEncPEM := encKeyPEM(encMaster, serverID, 0x03)
	serverKEPEM := encKeyPEM(encMaster, serverID, 0x02)
	clientSignPEM := signKeyPEM(signMaster, clientID)
	clientEncPEM := encKeyPEM(encMaster, clientID, 0x03)
	clientKEPEM := encKeyPEM(encMaster, clientID, 0x02)

	// 4. 如需落盘为文件，把下面的 fmt.Printf 换成 os.WriteFile 即可，例如：
	//
	//	os.WriteFile("server-sign.pem", []byte(serverSignPEM), 0o600)
	fmt.Printf("\tkgcParamsPEM     = `%s`\n", paramsPEM)
	fmt.Printf("\tserverID         = %q\n", serverID)
	fmt.Printf("\tserverSignKeyPEM = `%s`\n", serverSignPEM)
	fmt.Printf("\tserverEncKeyPEM  = `%s`\n", serverEncPEM)
	fmt.Printf("\tserverKEKeyPEM   = `%s`\n", serverKEPEM)
	fmt.Printf("\tclientID         = %q\n", clientID)
	fmt.Printf("\tclientSignKeyPEM = `%s`\n", clientSignPEM)
	fmt.Printf("\tclientEncKeyPEM  = `%s`\n", clientEncPEM)
	fmt.Printf("\tclientKEKeyPEM   = `%s`\n", clientKEPEM)
}

// signKeyPEM 派生签名用户私钥（hid=0x01）并编码为 PKCS#8 PEM。
func signKeyPEM(master *sm9.SignMasterPrivateKey, uid string) string {
	key, err := master.GenerateUserKey([]byte(uid), 0x01)
	if err != nil {
		log.Fatalf("派生 %s 签名私钥失败: %v", uid, err)
	}
	der, err := smx509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		log.Fatalf("编码 %s 签名私钥失败: %v", uid, err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// encKeyPEM 派生加密用户私钥（hid=0x03）或密钥交换用户私钥（hid=0x02），编码为 PKCS#8 PEM。
func encKeyPEM(master *sm9.EncryptMasterPrivateKey, uid string, hid byte) string {
	key, err := master.GenerateUserKey([]byte(uid), hid)
	if err != nil {
		log.Fatalf("派生 %s hid=0x%02X 私钥失败: %v", uid, hid, err)
	}
	der, err := smx509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		log.Fatalf("编码 %s hid=0x%02X 私钥失败: %v", uid, hid, err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}
