package main

import (
	"gitee.com/Trisia/gotlcp/https"
	"gitee.com/Trisia/gotlcp/tlcp"
	"github.com/emmansun/gmsm/smx509"
	"io"
	"os"
)

func main() {
	config := &tlcp.Config{RootCAs: load()}

	client := https.NewHTTPSClient(config)
	resp, err := client.Get("https://127.0.0.1")
	if err != nil {
		panic(err)
	}
	_, err = io.Copy(os.Stdout, resp.Body)
	if err != nil && err != io.EOF {
		panic(err)
	}
}

func load() *smx509.CertPool {

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

	rootCert, err := smx509.ParseCertificatePEM([]byte(ROOT_CERT_PEM))
	if err != nil {
		panic(err)
	}
	// 构造根证书列表
	pool := smx509.NewCertPool()
	pool.AddCert(rootCert)
	return pool

}
