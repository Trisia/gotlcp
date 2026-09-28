// Copyright (c) 2022 QuanGuanyu
// gotlcp is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

// 生产环境请从 KGC 下发的密钥文件或密钥管理服务加载，不要硬编码私钥。
package main

import (
	"encoding/pem"
	"fmt"
	"io"

	"gitee.com/Trisia/gotlcp/tlcp"
)

// 服务端内嵌的测试密钥材料（由 example/ibc/genkey 生成）。
const (
	kgcParamsPEM = `-----BEGIN IBC PARAMETERS-----
MIIBawIBAhYLa2djLmV4YW1wbGUCAQEwIBcNMjQwMTAxMDAwMDAwWhgPMjEyNDAx
MDEwMDAwMDBaMIHpMIHmBggqgRzPVQGCLgSB2TCB1gQLa2djLmV4YW1wbGUDQgAE
mjTOnA5wkEmfpx4TgLC2qgOqn9LP9aP7EFOg66eBv98ROV3laC/DEJDVwRlHjE55
jy/v8b/iCr1PLCXcYmNDBgOBggAEQ3auBFURx0Krlbk92oKdZlsLwfoU8uXcveAu
pLK284RWpU0vbwZqeCKzU+W7/6jm7uAtd4sAo653OS7tYp2PboK2uFa620+V/vX7
ls4BGNkPNMrH1vc1VWJ5X7sZ6KHABEvKPHbIRPKYxhIz+5ujRby0MrTOs+A4jkYV
77Q+Gd0GCCqBHM9VAYIuMDwCAQEGCCqBHM9VAYIuBAtrZ2MuZXhhbXBsZRcNMjQw
MTAxMDAwMDAwWoERGA8yMTI0MDEwMTAwMDAwMFowAA==
-----END IBC PARAMETERS-----
`
	serverID         = "server@kgc.example"
	serverSignKeyPEM = `-----BEGIN PRIVATE KEY-----
MIHhAgEAMA0GCSqBHM9VAYIuAQUABIHMMIHJA0IABKu+wwazT4TcjsfRdfJSTKUm
Fe0xirnPQiYtUWgU0FaBilnjgmkgA5PLFTYrXzXvn1Qu8uHqqM0S5Z9HdSjv/lUD
gYIABEN2rgRVEcdCq5W5PdqCnWZbC8H6FPLl3L3gLqSytvOEVqVNL28Gangis1Pl
u/+o5u7gLXeLAKOudzku7WKdj26CtrhWuttPlf71+5bOARjZDzTKx9b3NVVieV+7
GeihwARLyjx2yETymMYSM/ubo0W8tDK0zrPgOI5GFe+0Phnd
-----END PRIVATE KEY-----
`
	serverEncKeyPEM = `-----BEGIN PRIVATE KEY-----
MIHhAgEAMA0GCSqBHM9VAYIuAwUABIHMMIHJA4GCAAQonmVut6eh8Hw8hKC1dHgR
1dysdNaEYH/g82Ri3C0K3leVEiexYygNirZxwLYeC39lqcyLylyOHSZr/mlCCdri
ZEX5R5BjyUR2w71IoWq/X2pmrYBbI4Qxrf/wdzIEg8B1E+6+/eo/5B21wlvCAOOf
MoNha7cRJNIyo760nVgZMwNCAASaNM6cDnCQSZ+nHhOAsLaqA6qf0s/1o/sQU6Dr
p4G/3xE5XeVoL8MQkNXBGUeMTnmPL+/xv+IKvU8sJdxiY0MG
-----END PRIVATE KEY-----
`
	serverKEKeyPEM = `-----BEGIN PRIVATE KEY-----
MIHhAgEAMA0GCSqBHM9VAYIuAwUABIHMMIHJA4GCAARUDmGj/laZzma+wGAoTTTs
Fx0NRcVePi0oyAoM9XgO3G8omyHhWmfHQMCkrRVgLx4sEoU8MJyexp29z1ZVEeHb
BcfBk3b6SIO27yXqGn033McvgmuUH9lVmwUhrySCPoK1NFlY0u04lwb56Dm0M6tu
03f3quGxTEnHPToe/kJDogNCAASaNM6cDnCQSZ+nHhOAsLaqA6qf0s/1o/sQU6Dr
p4G/3xE5XeVoL8MQkNXBGUeMTnmPL+/xv+IKvU8sJdxiY0MG
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
	params, err := tlcp.ParseIBCSysParams(paramsBlock.Bytes)
	if err != nil {
		panic(err)
	}
	pool := tlcp.NewIBCPool()
	if err := pool.AddParams(params); err != nil {
		panic(err)
	}
	// 标识、公共参数 DER 与三把 PKCS#8 私钥一次装载；
	// 本库不校验密钥交换私钥的派生 hid，请自行确保它按 hid=0x02 派生，
	// 否则握手会一直走到 Finished 才以 bad record MAC 失败。
	server, err := tlcp.LoadIBCIdentity([]byte(serverID), paramsBlock.Bytes,
		signBlock.Bytes, encBlock.Bytes, keBlock.Bytes)
	if err != nil {
		panic(err)
	}

	// ---- 以上材料就绪，以下为服务端核心代码 ----
	config := &tlcp.Config{
		// IBC 套件必须显式配置，越靠前优先级越高。
		CipherSuites: []uint16{tlcp.IBC_SM4_GCM_SM3, tlcp.IBSDH_SM4_GCM_SM3},
		IBCIdentity:  server,
		// ClientIBCSysParams：本端信任的客户端 KGC 公共参数。
		// 要求客户端认证时必需，用于校验客户端下发的 ibc_parameter。
		ClientIBCSysParams: pool,
		// 要求客户端认证：客户端将下发自身 IBC 标识与 CertificateVerify，
		// 服务端据此填充 ConnectionState.PeerIBCIdentity。
		ClientAuth: tlcp.RequireAnyClientCert,
	}
	ln, err := tlcp.Listen("tcp", ":8443", config)
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

	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	// close_notify 可能与明文同批到达：Read 会返回 (n>0, io.EOF)，
	// 必须先处理 n 个字节，再判定连接是否结束。
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
	// 注意：Accept 返回 net.Conn，需断言为 *tlcp.Conn 才能读取连接状态。
	state := conn.(*tlcp.Conn).ConnectionState()
	fmt.Printf("[服务端] 套件：%s，客户端标识：%s\n",
		tlcp.CipherSuiteName(state.CipherSuite), state.PeerIBCIdentity)
}
