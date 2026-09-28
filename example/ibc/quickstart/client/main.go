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

// 客户端内嵌的测试密钥材料（由 example/ibc/genkey 生成）。
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
	clientID         = "client@kgc.example"
	clientSignKeyPEM = `-----BEGIN PRIVATE KEY-----
MIHhAgEAMA0GCSqBHM9VAYIuAQUABIHMMIHJA0IABAyqTZoBN80Kw8YL4tok+OYP
5gfAVKfpKDZ2KSW/RQMuUsgtu0sUMF0TydHEAwtjmgvlpB3vdnGFKHgJ1vq5IKgD
gYIABEN2rgRVEcdCq5W5PdqCnWZbC8H6FPLl3L3gLqSytvOEVqVNL28Gangis1Pl
u/+o5u7gLXeLAKOudzku7WKdj26CtrhWuttPlf71+5bOARjZDzTKx9b3NVVieV+7
GeihwARLyjx2yETymMYSM/ubo0W8tDK0zrPgOI5GFe+0Phnd
-----END PRIVATE KEY-----
`
	clientEncKeyPEM = `-----BEGIN PRIVATE KEY-----
MIHhAgEAMA0GCSqBHM9VAYIuAwUABIHMMIHJA4GCAAQqoDlSTKdoDnKVd8tZlBW1
I69HgD9QTi1r5nP/xTgD15EmFZOn8M1KGiCu/RLk6JCuJfF0EYrSQATNCogK/TAS
I2ftrCtVN5x1Pz/KXSRAvweZ2oMi/16xx+FOcGAf1OFdakVYip/hhy4uovXV2O4Y
VJ1JIaum5nHo+W8JskmA7wNCAASaNM6cDnCQSZ+nHhOAsLaqA6qf0s/1o/sQU6Dr
p4G/3xE5XeVoL8MQkNXBGUeMTnmPL+/xv+IKvU8sJdxiY0MG
-----END PRIVATE KEY-----
`
	clientKEKeyPEM = `-----BEGIN PRIVATE KEY-----
MIHhAgEAMA0GCSqBHM9VAYIuAwUABIHMMIHJA4GCAARgd7AwjNgZAkQ79W772LIm
bqEY1JYl7eZbmClA9QJbRA5BFA5WoWh4M5p5hQlxpeN630NwglnBAJrW/Vb/riBe
T+cvsAhUGGb9PgcpZAeS07+Iy6EtPFK1fcxYDpqwlaSL57xybk1LnnGFnLASW1s/
hmkjUkVlzyPOQfXKou6UHgNCAASaNM6cDnCQSZ+nHhOAsLaqA6qf0s/1o/sQU6Dr
p4G/3xE5XeVoL8MQkNXBGUeMTnmPL+/xv+IKvU8sJdxiY0MG
-----END PRIVATE KEY-----
`
)

func main() {
	// ---- 解析内嵌 PEM，得到 DER ----
	paramsBlock, _ := pem.Decode([]byte(kgcParamsPEM))
	signBlock, _ := pem.Decode([]byte(clientSignKeyPEM))
	encBlock, _ := pem.Decode([]byte(clientEncKeyPEM))
	keBlock, _ := pem.Decode([]byte(clientKEKeyPEM))
	if paramsBlock == nil || signBlock == nil || encBlock == nil || keBlock == nil {
		panic("无效的 PEM 常量")
	}

	// ---- 解析公共参数并装载客户端身份 ----
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
	client, err := tlcp.LoadIBCIdentity([]byte(clientID), paramsBlock.Bytes,
		signBlock.Bytes, encBlock.Bytes, keBlock.Bytes)
	if err != nil {
		panic(err)
	}

	// ---- 以上材料就绪，以下为客户端核心代码 ----
	conn, err := tlcp.Dial("tcp", "127.0.0.1:8443", &tlcp.Config{
		// IBC 套件必须显式配置，越靠前优先级越高。
		CipherSuites: []uint16{tlcp.IBC_SM4_GCM_SM3, tlcp.IBSDH_SM4_GCM_SM3},
		IBCIdentity:  client,
		// RootIBCSysParams：本端信任的服务端 KGC 公共参数。
		// 服务端下发的 ibc_parameter 必须命中该池，否则握手失败。
		RootIBCSysParams: pool,
	})
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("Hello IBC Server!")); err != nil {
		panic(err)
	}
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	// 对端发送 close_notify 时 Read 会返回 (n>0, io.EOF)，
	// 必须先处理 n 个字节，再判定连接是否结束。
	if n > 0 {
		fmt.Printf("[客户端] 收到：%s\n", buf[:n])
	}
	if err != nil && err != io.EOF {
		panic(err)
	}

	state := conn.ConnectionState()
	fmt.Printf("[客户端] 套件：%s，服务端标识：%s\n",
		tlcp.CipherSuiteName(state.CipherSuite), state.PeerIBCIdentity)
}
