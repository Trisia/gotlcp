package main

import (
	"fmt"
	"gitee.com/Trisia/gotlcp/tlcp"
	"github.com/emmansun/gmsm/smx509"
)

// 客户端双向身份认证
func main() {
	loadCert()
	// 构造根证书列表
	pool := smx509.NewCertPool()
	pool.AddCert(rootCert)

	// ECDHE系列套件 同时需要 认证密钥对 与 加密密钥对
	config := &tlcp.Config{
		RootCAs:      pool,
		Certificates: []tlcp.Certificate{authCertKeypair, encCertKeypair},
		CipherSuites: []uint16{
			tlcp.ECDHE_SM4_GCM_SM3,
			tlcp.ECDHE_SM4_CBC_SM3,
			// 注意：不能出现 ECC 系列套件，否则服务端可能选择ECC系列套件。
		},
	}
	//// 兼容向量模式的密钥交换参数
	//config.ClientECDHEParamsAsVector = true

	conn, err := tlcp.Dial("tcp", "127.0.0.1:8450", config)
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
MIICGDCCAb6gAwIBAgIIAs64yjcYUlswCgYIKoEcz1UBg3UwQjELMAkGA1UEBhMC
Q04xDzANBgNVBAgMBua1meaxnzEPMA0GA1UEBwwG5p2t5beeMREwDwYDVQQKDAjm
tYvor5VDQTAeFw0yMzAyMjExMTI1NDlaFw0yNDAyMjExMTI1NDlaMGsxCzAJBgNV
BAYTAkNOMQ8wDQYDVQQIDAbmtZnmsZ8xDzANBgNVBAcMBuadreW3njEPMA0GA1UE
CgwG5rWL6K+VMQ8wDQYDVQQLDAbmtYvor5UxGDAWBgNVBAMMD+a1i+ivleWuouaI
t+errzBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABLy4fl7DvcLEUw36WSdVZbT/
8Hm1d8sj7LLRosgTJLD0lwFreRmUPQsS7ovB7WMZ5y6TcWUd3OES9aC3gSnZwzej
dTBzMA4GA1UdDwEB/wQEAwIGwDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMB
Af8EAjAAMB0GA1UdDgQWBBRjLpNC4oQ8ib5uKVzE9ON3m2c/hjAfBgNVHSMEGDAW
gBQ2k+MU50UJ+tXv6i8SLdOhljzCpDAKBggqgRzPVQGDdQNIADBFAiEA9PFnYoST
+r5fhvtcH1P5HhKS7DEkjKo/37jZjZRxsRkCIFNpBpSuZkn2VirZMlcZCERQpAMx
8/91/Op17FjF7Dp7
-----END CERTIFICATE-----
`
	AUTH_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgZF5oB3V13GrOsZoE
RPi+m3tksNaWiEGK80lD2UqHaYCgCgYIKoEcz1UBgi2hRANCAAS8uH5ew73CxFMN
+lknVWW0//B5tXfLI+yy0aLIEySw9JcBa3kZlD0LEu6Lwe1jGecuk3FlHdzhEvWg
t4Ep2cM3
-----END PRIVATE KEY-----
`

	ENC_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIICGTCCAb6gAwIBAgIIAs64yjcYSQgwCgYIKoEcz1UBg3UwQjELMAkGA1UEBhMC
Q04xDzANBgNVBAgMBua1meaxnzEPMA0GA1UEBwwG5p2t5beeMREwDwYDVQQKDAjm
tYvor5VDQTAeFw0yMzAyMjExMTI1NDlaFw0yNDAyMjExMTI1NDlaMGsxCzAJBgNV
BAYTAkNOMQ8wDQYDVQQIDAbmtZnmsZ8xDzANBgNVBAcMBuadreW3njEPMA0GA1UE
CgwG5rWL6K+VMQ8wDQYDVQQLDAbmtYvor5UxGDAWBgNVBAMMD+a1i+ivleWuouaI
t+errzBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABCCV8MWmwYY1MC7L23+bplrC
2nxH5RJMR4hh55TItZ5XMfCJceSVtjKPpd6zr2xvA1kb4G5ydHwmGSfRk6OmjDmj
dTBzMA4GA1UdDwEB/wQEAwIDODATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMB
Af8EAjAAMB0GA1UdDgQWBBTqqUJAy1bB0KiYgh8CUh4x3TW/YTAfBgNVHSMEGDAW
gBQ2k+MU50UJ+tXv6i8SLdOhljzCpDAKBggqgRzPVQGDdQNJADBGAiEA57snhYf5
8y/lCX6OOXr1/3H71aY9c54Wpf38WWDRaskCIQCmslF8tguQIhQqS831kmJ9nFf9
TN4y0RkQBH74aBqeQQ==
-----END CERTIFICATE-----
`
	ENC_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgkwiV92G2uKq40+gI
b8cMuaSxv2VdCWRAZJ3MOXSO2JSgCgYIKoEcz1UBgi2hRANCAAQglfDFpsGGNTAu
y9t/m6Zawtp8R+USTEeIYeeUyLWeVzHwiXHklbYyj6Xes69sbwNZG+BucnR8Jhkn
0ZOjpow5
-----END PRIVATE KEY-----
`
)

var (
	rootCert        *smx509.Certificate
	authCertKeypair tlcp.Certificate
	encCertKeypair  tlcp.Certificate
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

	encCertKeypair, err = tlcp.X509KeyPair([]byte(ENC_CERT_PEM), []byte(ENC_KEY_PEM))
	if err != nil {
		panic(err)
	}
}
