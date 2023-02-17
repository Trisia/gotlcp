package main

import (
	"io"
	"os"

	"gitee.com/Trisia/gotlcp/https"
	"gitee.com/Trisia/gotlcp/tlcp"
	"github.com/emmansun/gmsm/smx509"
)

// 测试ECDHE 客户端
func main() {
	config := &tlcp.Config{
		RootCAs:      load(),
		Certificates: []tlcp.Certificate{loadAuthCert(), loadEncCert()},
		CipherSuites: []uint16{
			tlcp.ECDHE_SM4_CBC_SM3,
			tlcp.ECDHE_SM4_GCM_SM3,
		},
		EnableDebug: true,
	}

	client := https.NewHTTPSClient(config)
	resp, err := client.Get("https://demo.gmssl.cn:1443")
	if err != nil {
		panic(err)
	}
	_, err = io.Copy(os.Stdout, resp.Body)
	if err != nil && err != io.EOF {
		panic(err)
	}
}

// 证书将于2023-9-14日过期
func load() *smx509.CertPool {

	const ROOT_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIIB6zCCAY+gAwIBAgIGAXKnMMauMAwGCCqBHM9VAYN1BQAwSTELMAkGA1UEBhMC
Q04xDjAMBgNVBAoTBUdNU1NMMRAwDgYDVQQLEwdQS0kvU00yMRgwFgYDVQQDEw9S
b290Q0EgZm9yIFRlc3QwIhgPMjAxNTEyMzExNjAwMDBaGA8yMDM1MTIzMDE2MDAw
MFowSzELMAkGA1UEBhMCQ04xDjAMBgNVBAoTBUdNU1NMMRAwDgYDVQQLEwdQS0kv
U00yMRowGAYDVQQDExFNaWRkbGVDQSBmb3IgVGVzdDBZMBMGByqGSM49AgEGCCqB
HM9VAYItA0IABA4uB1fiqJjs1uR6bFIrtxvLFuoU0x+uPPxrslzodyTG1Mj9dJpm
4AUjT9q2bL4cj7H73qWJNpwArnZr7fCc3A2jWzBZMBsGA1UdIwQUMBKAEJxp7A+6
GjnFr+gk67KcEgQwGQYDVR0OBBIEEPl/VbQnlDNiplbKb8xdGv8wDwYDVR0TAQH/
BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAMYwDAYIKoEcz1UBg3UFAANIADBFAiA31tn0
qKz6G0YgGjWd6/ULMyqfTzoL82Y7EkvxbOpX/AIhAKCJYkDp62cvbKvj/Njc2dIe
5BN+DGhO5JOhIyo4oWE3
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

const (
	AUTH_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIIB3TCCAYGgAwIBAgIGAYM50cbFMAwGCCqBHM9VAYN1BQAwSzELMAkGA1UEBhMC
Q04xDjAMBgNVBAoTBUdNU1NMMRAwDgYDVQQLEwdQS0kvU00yMRowGAYDVQQDExFN
aWRkbGVDQSBmb3IgVGVzdDAiGA8yMDIyMDkxMzE2MDAwMFoYDzIwMjMwOTEzMTYw
MDAwWjAmMQswCQYDVQQGEwJDTjEXMBUGA1UEAxMOZ20gdGVzdCBjbGllbnQwWTAT
BgcqhkjOPQIBBggqgRzPVQGCLQNCAASQO0zDql3Y/0KnzTA2tMMy+/ZbYrB7rMTe
n4gvDu5IXckBoZiuNPfSN7mSEHe88suzkirZe5H1MQuGmatZXJTuo3AwbjAbBgNV
HSMEFDASgBD5f1W0J5QzYqZWym/MXRr/MBkGA1UdDgQSBBDyWxjI1TzsQOudZXcE
slWiMBkGA1UdEQQSMBCCDmdtIHRlc3QgY2xpZW50MAkGA1UdEwQCMAAwDgYDVR0P
AQH/BAQDAgDAMAwGCCqBHM9VAYN1BQADSAAwRQIhAPfJozULRYURIFHcrbzw3C1E
Fe00PkKfOnrWI3PRVWlkAiAhfFtr5ydu7i7m+LF8jk4vhxCy3g9rEo8+Q2GnKKsA
Fw==
-----END CERTIFICATE-----
`
	AUTH_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgwWUmv7RlOnXHeURD
KCUGPR08E+cs/2wX1N1DeZkf7NCgCgYIKoEcz1UBgi2hRANCAASQO0zDql3Y/0Kn
zTA2tMMy+/ZbYrB7rMTen4gvDu5IXckBoZiuNPfSN7mSEHe88suzkirZe5H1MQuG
matZXJTu
-----END PRIVATE KEY-----
`

	ENC_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIIB3DCCAYGgAwIBAgIGAYM50cb7MAwGCCqBHM9VAYN1BQAwSzELMAkGA1UEBhMC
Q04xDjAMBgNVBAoTBUdNU1NMMRAwDgYDVQQLEwdQS0kvU00yMRowGAYDVQQDExFN
aWRkbGVDQSBmb3IgVGVzdDAiGA8yMDIyMDkxMzE2MDAwMFoYDzIwMjMwOTEzMTYw
MDAwWjAmMQswCQYDVQQGEwJDTjEXMBUGA1UEAxMOZ20gdGVzdCBjbGllbnQwWTAT
BgcqhkjOPQIBBggqgRzPVQGCLQNCAATnDRcSm2RnIgX/m9TUtEgxXYkJn9hkEkIh
xO08WPAISaCf/r05v7magIjv1cuOR/qZUh57Ch36GGWfWX3zY6YCo3AwbjAbBgNV
HSMEFDASgBD5f1W0J5QzYqZWym/MXRr/MBkGA1UdDgQSBBDnAAt+PPUCVYy/MSfA
XFz2MBkGA1UdEQQSMBCCDmdtIHRlc3QgY2xpZW50MAkGA1UdEwQCMAAwDgYDVR0P
AQH/BAQDAgA4MAwGCCqBHM9VAYN1BQADRwAwRAIgJnQhiKYrnCTh33UlX0LZ3btl
sJyOUwJYGt+fUIo+RiYCIFwUjptplIdhqCMfgsDbMERGq5WUyKgOsIXOy5WOZUya
-----END CERTIFICATE-----
`
	ENC_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgnA20piS3TJfmHq1L
Vwz2EOMEwyN47irhSQ1kIul3hWCgCgYIKoEcz1UBgi2hRANCAATnDRcSm2RnIgX/
m9TUtEgxXYkJn9hkEkIhxO08WPAISaCf/r05v7magIjv1cuOR/qZUh57Ch36GGWf
WX3zY6YC
-----END PRIVATE KEY-----
`
)

func loadAuthCert() tlcp.Certificate {
	authCertKeypair, err := tlcp.X509KeyPair([]byte(AUTH_CERT_PEM), []byte(AUTH_KEY_PEM))
	if err != nil {
		panic(err)
	}
	return authCertKeypair
}

func loadEncCert() tlcp.Certificate {
	authCertKeypair, err := tlcp.X509KeyPair([]byte(ENC_CERT_PEM), []byte(ENC_KEY_PEM))
	if err != nil {
		panic(err)
	}
	return authCertKeypair
}
