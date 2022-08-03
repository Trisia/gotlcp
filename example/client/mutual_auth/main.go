package main

import (
	"fmt"
	"gitee.com/Trisia/gotlcp/tlcp"
	"github.com/emmansun/gmsm/smx509"
)

func main() {
	loadCert()
	// 构造根证书列表
	pool := smx509.NewCertPool()
	pool.AddCert(rootCert)

	config := &tlcp.Config{
		RootCAs:      pool,
		Certificates: []tlcp.Certificate{authCertKeypair},
	}
	conn, err := tlcp.Dial("tcp", "127.0.0.1:8445", config)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	_, err = conn.Write([]byte("Hello Go TLCP!"))
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

const (
	ROOT_CERT_PEM = `-----BEGIN CERTIFICATE-----
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
	AUTH_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIICMDCCAdWgAwIBAgIIAs5iXGP9FtEwCgYIKoEcz1UBg3UwQjELMAkGA1UEBhMC
Q04xDzANBgNVBAgMBua1meaxnzEPMA0GA1UEBwwG5p2t5beeMREwDwYDVQQKDAjm
tYvor5VDQTAeFw0yMjA3MTgxNDMyMjlaFw0yMzA3MTgxNDMyMjlaMG8xCzAJBgNV
BAYTAmNuMQ8wDQYDVQQIDAbmtZnmsZ8xDzANBgNVBAcMBuadreW3njEYMBYGA1UE
CgwP5rWL6K+V5a6i5oi356uvMRYwFAYDVQQLDA1UTENQ5a6i5oi356uvMQwwCgYD
VQQDEwMwMDIwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAATOyJ0LJKSf9lHwJ9Bq
7pe38CkohX2biKwJScLBTfNO/+bA4VvBndoY3FEgY76kHL0YhEuoPwIQqkU4OA/n
CdeUo4GHMIGEMA4GA1UdDwEB/wQEAwIGwDATBgNVHSUEDDAKBggrBgEFBQcDATAM
BgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQghMpEvPxKG4GG6UjMELjavzTr8DAfBgNV
HSMEGDAWgBQ2k+MU50UJ+tXv6i8SLdOhljzCpDAPBgNVHREECDAGhwR/AAABMAoG
CCqBHM9VAYN1A0kAMEYCIQD9xYsa7uylJhoo/9mI1syRn6yhIBu+ngN8UuIi8XMk
fAIhANlVBUGtC/yrMoYG9I2O6VchvouMGJ1doF+BYIfm0A2k
-----END CERTIFICATE-----
`
	AUTH_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQg84KPC3TBK6YaNI9w
WUXKWtumd+Ntd1Aid1Wk0CLbRaegCgYIKoEcz1UBgi2hRANCAATOyJ0LJKSf9lHw
J9Bq7pe38CkohX2biKwJScLBTfNO/+bA4VvBndoY3FEgY76kHL0YhEuoPwIQqkU4
OA/nCdeU
-----END PRIVATE KEY-----
`
)

var (
	rootCert        *smx509.Certificate
	authCertKeypair tlcp.Certificate
)

func loadCert() {
	var err error
	rootCert, err = smx509.ParseCertificatePEM([]byte(ROOT_CERT_PEM))
	if err != nil {
		panic(err)
	}
	authCertKeypair, err = tlcp.X509KeyPair([]byte(AUTH_CERT_PEM), []byte(AUTH_KEY_PEM))
	if err != nil {
		panic(err)
	}
}
