package main

import (
	"fmt"
	"gitee.com/Trisia/gotlcp/dtlcp"
	"github.com/emmansun/gmsm/smx509"
)

const ROOT_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIIB3jCCAYOgAwIBAgIIAs4MAPwpIBcwCgYIKoEcz1UBg3UwQjELMAkGA1UEBhMC
Q04xDzANBgNVBAgMBua1meaxnzEPMA0GA1UEBwwG5p2t5beeMREwDwYDVQQKDAjm
tYvor5VDQTAeFw0yMTEyMjMwODQ4MzNaFw0zMTEyMjMwODQ4MzNaMEIxCzAJBgNV
BAYTAkNOMQ8wDQYDVQQIDAbmtZnmsZ8xDzANBgNVBAcMBuadreW3njERMA8GA1UE
CgwI5rWL6K+VQ0EwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAARKs6B5ZBy753Os
ZSeIfv8zScbiiXkLjB+Plw+YWvoesRkqYGe/Mqjr8rrmThq6iEWubYK6ZiQQV54k
Klcva3Hto2MwYTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNV
HQ4EFgQUNpPjFOdFCfrV7+ovEi3ToZY8wqQwHwYDVR0jBBgwFoAUNpPjFOdFCfrV
7+ovEi3ToZY8wqQwCgYIKoEcz1UBg3UDSQAwRgIhALDhtLKVziUhXbTedDovRANS
Cdu6CJ0MAw7Wbl3vAWGOAiEAzCXLcF32DM5Aze9MqpUfQfYPaRTLYkNwSXlw/LUY
E6E=
-----END CERTIFICATE-----
`

var rootCert *smx509.Certificate

func init() {
	var err error
	rootCert, err = smx509.ParseCertificatePEM([]byte(ROOT_CERT_PEM))
	if err != nil {
		panic(err)
	}
}

// 客户端会话重用示例
// 第一次连接进行完整握手并缓存会话，第二次连接重用会话
func main() {
	pool := smx509.NewCertPool()
	pool.AddCert(rootCert)

	config := &dtlcp.Config{
		RootCAs:      pool,
		SessionCache: dtlcp.NewLRUSessionCache(32),
	}

	// 第一次连接：完整握手
	conn, err := dtlcp.Dial("udp", "127.0.0.1:8451", config)
	if err != nil {
		panic(err)
	}
	_ = conn.Close()
	fmt.Printf("第一次连接 - DidResume: %t\n", conn.ConnectionState().DidResume)

	// 第二次连接：重用会话
	conn, err = dtlcp.Dial("udp", "127.0.0.1:8451", config)
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	fmt.Printf("第二次连接 - DidResume: %t\n", conn.ConnectionState().DidResume)

	_, err = conn.Write([]byte("Hello DTLCP Resume!"))
	if err != nil {
		panic(err)
	}
	buff := make([]byte, 512)
	n, err := conn.Read(buff)
	if err != nil {
		panic(err)
	}
	fmt.Printf("<< %s\n", buff[:n])
}
