package main

import (
	"fmt"
	"gitee.com/Trisia/gotlcp/dtlcp"
	"github.com/emmansun/gmsm/smx509"
	"net"
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

var pool *smx509.CertPool

func init() {
	var err error
	rootCert, err := smx509.ParseCertificatePEM([]byte(ROOT_CERT_PEM))
	if err != nil {
		panic(err)
	}
	pool = smx509.NewCertPool()
	pool.AddCert(rootCert)
}

// 客户端使用现有 PacketConn 创建 DTLCP 连接
// 先通过 net.Dial 创建 UDP 连接，再通过 dtlcp.Client 将其包装为 DTLCP 连接
func main() {
	config := &dtlcp.Config{RootCAs: pool}

	// 创建 UDP 连接
	raw, err := net.Dial("udp", "127.0.0.1:8452")
	if err != nil {
		panic(err)
	}

	// 使用现有 PacketConn 构造 DTLCP 连接
	conn := dtlcp.Client(raw.(net.PacketConn), raw.RemoteAddr(), config)
	defer conn.Close()

	_, err = conn.Write([]byte("Hello DTLCP Raw!"))
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
