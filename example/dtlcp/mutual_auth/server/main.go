package main

import (
	"fmt"
	"gitee.com/Trisia/gotlcp/dtlcp"
	"github.com/emmansun/gmsm/smx509"
)

const (
	SIG_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIICHTCCAcSgAwIBAgIIAs5iVWOA17swCgYIKoEcz1UBg3UwQjELMAkGA1UEBhMC
Q04xDzANBgNVBAgMBua1meaxnzEPMA0GA1UEBwwG5p2t5beeMREwDwYDVQQKDAjm
tYvor5VDQTAeFw0yMjA3MTUxMzU5MzhaFw0yMzA3MTUxMzU5MzhaMF4xCzAJBgNV
BAYTAmNuMQ8wDQYDVQQIDAbmtZnmsZ8xDzANBgNVBAcMBuadreW3njEQMA4GA1UE
ChMHR08gVExDUDENMAsGA1UECxMEVGVzdDEMMAoGA1UEAxMDMDAxMFkwEwYHKoZI
zj0CAQYIKoEcz1UBgi0DQgAElcuhLnzaqjMbCGBAg6QZTA6iMCsck90kwh4NK0ro
+XY0XwzYaD5PQq7VehcucHGvrUL2VK2d+v16i1J2aD+N5aOBhzCBhDAOBgNVHQ8B
Af8EBAMCBsAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAdBgNV
HQ4EFgQU77hb1KL698m25EqrGuBHdEN8WEswHwYDVR0jBBgwFoAUNpPjFOdFCfrV
7+ovEi3ToZY8wqQwDwYDVR0RBAgwBocEfwAAATAKBggqgRzPVQGDdQNHADBEAiB/
VgNXutPGOqHaaywG6yApn4I5ipd4lQmDzDArHGgPtgIgRtoKKhJzAVknoubSZqKL
6YtPS7P6mYhCzW3974poADA=
-----END CERTIFICATE-----
`
	ENC_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIICHjCCAcSgAwIBAgIIAs5iVWOA9lcwCgYIKoEcz1UBg3UwQjELMAkGA1UEBhMC
Q04xDzANBgNVBAgMBua1meaxnzEPMA0GA1UEBwwG5p2t5beeMREwDwYDVQQKDAjm
tYvor5VDQTAeFw0yMjA3MTUxMzU5MzhaFw0yMzA3MTUxMzU5MzhaMF4xCzAJBgNV
BAYTAmNuMQ8wDQYDVQQIDAbmtZnmsZ8xDzANBgNVBAcMBuadreW3njEQMA4GA1UE
ChMHR08gVExDUDENMAsGA1UECxMEVGVzdDEMMAoGA1UEAxMDMDAxMFkwEwYHKoZI
zj0CAQYIKoEcz1UBgi0DQgAEeiDKvy4amGMSU6lSmohUwcI4oRAVGSW6ktL2v3mq
ps8J9JDEfMskknEVWjfrL7OT+EaYm0rO7tvx6oJqrmUd5qOBhzCBhDAOBgNVHQ8B
Af8EBAMCAzgwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAdBgNV
HQ4EFgQU9SD+JHfBKpsN/+zbSSkZnw1qVdAwHwYDVR0jBBgwFoAUNpPjFOdFCfrV
7+ovEi3ToZY8wqQwDwYDVR0RBAgwBocEfwAAATAKBggqgRzPVQGDdQNIADBFAiAD
29ovbTAIhZgfvAYKXphZSvcMnQ3QdCDyCqb4j8KMQwIhAINoMaInvyMB86C/aa7P
gqBZDVjZd/X+yWxzRGtLG/AT
-----END CERTIFICATE-----
`
	SIG_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgC1Sw2Ptopr75mxS/
R+lT45og/55WuueomJKSXqTmAfKgCgYIKoEcz1UBgi2hRANCAASVy6EufNqqMxsI
YECDpBlMDqIwKxyT3STCHg0rSuj5djRfDNhoPk9CrtV6Fy5wca+tQvZUrZ36/XqL
UnZoP43l
-----END PRIVATE KEY-----
`
	ENC_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgpcgOKHIjr+jDTNjc
mfeSZuYZlwi344P7s7bz1ofThjigCgYIKoEcz1UBgi2hRANCAAR6IMq/LhqYYxJT
qVKaiFTBwjihEBUZJbqS0va/eaqmzwn0kMR8yySScRVaN+svs5P4RpibSs7u2/Hq
gmquZR3m
-----END PRIVATE KEY-----
`
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
)

var (
	sigCert, encCert dtlcp.Certificate
	rootCert         *smx509.Certificate
)

func init() {
	var err error
	sigCert, err = dtlcp.X509KeyPair([]byte(SIG_CERT_PEM), []byte(SIG_KEY_PEM))
	if err != nil {
		panic(err)
	}
	encCert, err = dtlcp.X509KeyPair([]byte(ENC_CERT_PEM), []byte(ENC_KEY_PEM))
	if err != nil {
		panic(err)
	}
	rootCert, err = smx509.ParseCertificatePEM([]byte(ROOT_CERT_PEM))
	if err != nil {
		panic(err)
	}
}

func main() {
	// 创建客户端根证书池，用于验证客户端证书
	pool := smx509.NewCertPool()
	pool.AddCert(rootCert)

	config := &dtlcp.Config{
		Certificates: []dtlcp.Certificate{sigCert, encCert},
		ClientAuth:   dtlcp.RequireAndVerifyClientCert, // 要求客户端发送证书并验证
		ClientCAs:    pool,                              // 用于验证客户端证书的根证书
	}
	ln, err := dtlcp.Listen("udp", ":8447", config)
	if err != nil {
		panic(err)
	}
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			panic(err)
		}
		go func() {
			defer conn.Close()
			buf := make([]byte, 1024)
			_, _ = conn.Read(buf)
			_, _ = conn.Write([]byte("Hello DTLCP Mutual Auth Client!"))

			// 读取并打印客户端证书信息
			state := conn.(*dtlcp.Conn).ConnectionState()
			for i, cert := range state.PeerCertificates {
				fmt.Printf(">>> 客户端证书[%d]: Subject=%q, Issuer=%q\n", i, cert.Subject.CommonName, cert.Issuer.CommonName)
			}
		}()
	}
}
