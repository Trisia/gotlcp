// Copyright (c) 2022 QuanGuanyu
// gotlcp is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

// 基于 SM9 标识密码（IBC/IBSDH）的 DTLCP 服务端示例：不使用任何 X.509 证书，
// 仅凭 KGC 公共参数（信任锚）与用户标识完成握手。
//
// 生产环境请从 KGC 下发的密钥文件或密钥管理服务加载，不要硬编码私钥。
// 下方内嵌的测试密钥材料由 go run ./example/dtlcp/ibc/genkey 生成。
package main

import (
	"encoding/pem"
	"fmt"
	"io"

	"gitee.com/Trisia/gotlcp/dtlcp"
)

// 服务端内嵌的测试密钥材料（由 example/dtlcp/ibc/genkey 生成）。
const (
	kgcParamsPEM = `-----BEGIN IBC PARAMETERS-----
MIIBaQIBAhYLa2djLmV4YW1wbGUCAQEwIBcNMjQwMTAxMDAwMDAwWhgPMjEyNDAx
MDEwMDAwMDBaMIHpMIHmBggqgRzPVQGCLgSB2TCB1gQLa2djLmV4YW1wbGUDQgAE
kPAQT9OC3a4Ra+bq9aVqoitSxr4i2EdhZu1LhsAalnICAg15OPijUnPS1VJ9FOOL
xAKa10KBVGo4A7aYo3R5rAOBggAEPo8YMYuVpe1RXwzGH3z2OmmPMotodaE4LC/d
zXAsq0pvJVNY+sAA8xAalTi1K3dox96XEv0JqQgbUX1CBu6h2UjCf8fTKLgwH559
WnLxHfVlUH0ImUfcaaDHwFXd9gtjejVNbD94hmVNb2T7gLdhQRHO3K/3WiqDspG3
mCs6tmcGCCqBHM9VAYIuMDwCAQEGCCqBHM9VAYIuBAtrZ2MuZXhhbXBsZRcNMjQw
MTAxMDAwMDAwWoERGA8yMTI0MDEwMTAwMDAwMFo=
-----END IBC PARAMETERS-----
`
	serverID         = "server@kgc.example"
	serverSignKeyPEM = `-----BEGIN PRIVATE KEY-----
MIHhAgEAMA0GCSqBHM9VAYIuAQUABIHMMIHJA0IABHrjec++2YCJ1rv4S/tCF5RT
zvxCi6AqeEKJWRiYDIsCFH+/Q0OEtqj8QeqE4oqTrblttqvB04i24YONlTuvWVkD
gYIABD6PGDGLlaXtUV8Mxh989jppjzKLaHWhOCwv3c1wLKtKbyVTWPrAAPMQGpU4
tSt3aMfelxL9CakIG1F9QgbuodlIwn/H0yi4MB+efVpy8R31ZVB9CJlH3Gmgx8BV
3fYLY3o1TWw/eIZlTW9k+4C3YUERztyv91oqg7KRt5grOrZn
-----END PRIVATE KEY-----
`
	serverEncKeyPEM = `-----BEGIN PRIVATE KEY-----
MIHhAgEAMA0GCSqBHM9VAYIuAwUABIHMMIHJA4GCAASVunPyTWui/cecCI59rHoT
h0zWtIv9WpOyshf5vCEOoRddFTHjVBHuDYU0uvcyoBL4s6xyZOMNSRrwoZFR8vv7
EsF/01ZaJC/WbU++mUK8sKb2/zGw57iHxaXPmAbBSThiE6rBDmskPWMHD6eRuDQY
2CZp51cULGhYPyTuxHyeJANCAASQ8BBP04LdrhFr5ur1pWqiK1LGviLYR2Fm7UuG
wBqWcgICDXk4+KNSc9LVUn0U44vEAprXQoFUajgDtpijdHms
-----END PRIVATE KEY-----
`
	serverKEKeyPEM = `-----BEGIN PRIVATE KEY-----
MIHhAgEAMA0GCSqBHM9VAYIuAwUABIHMMIHJA4GCAAQ7bhUtaWpMvhKL+OXJDQDn
ONflJgzgJuLwD89EyepIuDPpGmMakhgrzbK50zTqKHMT+vxumrYYpX3+UDWfaGkJ
D2hKE0r6FUYIMA4XBW3xtNGdGFpyDt9N9l0JRG0LyClQwR0ZNbumC6Mq70xBODgd
uLwDMkLXS0CNfcrm21ud2ANCAASQ8BBP04LdrhFr5ur1pWqiK1LGviLYR2Fm7UuG
wBqWcgICDXk4+KNSc9LVUn0U44vEAprXQoFUajgDtpijdHms
-----END PRIVATE KEY-----
`
)

func main() {
	// ---- 解析内嵌 PEM，得到 DER ----
	paramsBlock, _ := pem.Decode([]byte(kgcParamsPEM))
	signBlock, _ := pem.Decode([]byte(serverSignKeyPEM))
	encBlock, _ := pem.Decode([]byte(serverEncKeyPEM))
	keBlock, _ := pem.Decode([]byte(serverKEKeyPEM))
	if paramsBlock == nil || signBlock == nil || encBlock == nil || keBlock == nil {
		panic("无效的 PEM 常量")
	}

	// ---- 解析公共参数并装载服务端身份 ----
	params, err := dtlcp.ParseIBCSysParams(paramsBlock.Bytes)
	if err != nil {
		panic(err)
	}
	pool := dtlcp.NewIBCPool()
	if err := pool.AddParams(params); err != nil {
		panic(err)
	}
	// 标识、公共参数 DER 与三把 PKCS#8 私钥一次装载；
	// 本库不校验密钥交换私钥的派生 hid，请自行确保它按 hid=0x02 派生，
	// 否则握手会一直走到 Finished 才以 bad record MAC 失败。
	server, err := dtlcp.LoadIBCIdentity([]byte(serverID), paramsBlock.Bytes,
		signBlock.Bytes, encBlock.Bytes, keBlock.Bytes)
	if err != nil {
		panic(err)
	}

	// ---- 以上材料就绪，以下为服务端核心代码 ----
	config := &dtlcp.Config{
		// IBC 套件必须显式配置，越靠前优先级越高。
		CipherSuites: []uint16{dtlcp.IBC_SM4_GCM_SM3, dtlcp.IBSDH_SM4_GCM_SM3},
		IBCIdentity:  server,
		// ClientIBCSysParams：本端信任的客户端 KGC 公共参数。
		// 要求客户端认证时必需，用于校验客户端下发的 ibc_parameter。
		ClientIBCSysParams: pool,
		// 要求客户端认证：客户端将下发自身 IBC 标识与 CertificateVerify，
		// 服务端据此填充 ConnectionState.PeerIBCIdentity。
		ClientAuth: dtlcp.RequireAndVerifyClientCert,
	}
	// DTLCP 基于 UDP：使用 Listen + Accept，或直接对 net.PacketConn 调用 dtlcp.Server。
	ln, err := dtlcp.Listen("udp", ":8443", config)
	if err != nil {
		panic(err)
	}
	defer ln.Close()
	fmt.Println("[服务端] 监听 :8443 ...")

	conn, err := ln.Accept()
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// Accept 返回的连接尚未完成握手，首次 Read 触发握手并读取应用数据。
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if n > 0 {
		fmt.Printf("[服务端] 收到：%s\n", buf[:n])
	}
	if err != nil {
		if err == io.EOF {
			return
		}
		panic(err)
	}
	if _, err := conn.Write([]byte("Hello IBC Client!")); err != nil {
		panic(err)
	}

	// 握手完成后可读取对端 IBC 标识与公共参数。
	// 注意：Accept 返回 net.Conn，需断言为 *dtlcp.Conn 才能读取连接状态。
	state := conn.(*dtlcp.Conn).ConnectionState()
	fmt.Printf("[服务端] 套件：%s，客户端标识：%s\n",
		dtlcp.CipherSuiteName(state.CipherSuite), state.PeerIBCIdentity)
}
