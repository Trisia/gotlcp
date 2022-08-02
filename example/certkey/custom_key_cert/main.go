package main

import (
	"crypto"
	"gitee.com/Trisia/gotlcp/tlcp"
	"github.com/emmansun/gmsm/smx509"
	"io"
)

func main() {
	/*
		构造签名密钥对
	*/
	sigCert, err := smx509.ParseCertificatePEM([]byte(SIG_CERT_PEM))
	if err != nil {
		panic(err)
	}
	sigCertKeypair := tlcp.Certificate{
		Certificate: [][]byte{sigCert.Raw},
		PrivateKey:  &CustomSigKeypair{},
	}

	/*
		构造加密密钥对
	*/
	encCert, err := smx509.ParseCertificatePEM([]byte(ENC_CERT_PEM))
	if err != nil {
		panic(err)
	}
	encCertKeypair := tlcp.Certificate{
		Certificate: [][]byte{encCert.Raw},
		PrivateKey:  &CustomEncKeypair{},
	}

	_ = sigCertKeypair
	_ = encCertKeypair
}

// CustomSigKeypair 自定义签名密钥对
type CustomSigKeypair struct{}

func (m *CustomSigKeypair) Public() crypto.PublicKey {
	panic("请实现返回公钥")
}

func (m *CustomSigKeypair) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	panic("请实现完成数字签名")
}

// CustomEncKeypair 自定义加密密钥对
type CustomEncKeypair struct{}

func (c *CustomEncKeypair) Public() crypto.PublicKey {
	panic("请实现返回公钥")
}

func (c *CustomEncKeypair) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error) {
	panic("请实现完成数据解密")
}

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
)
