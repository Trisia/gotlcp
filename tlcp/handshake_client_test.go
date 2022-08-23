package tlcp

import (
	"fmt"
	"github.com/emmansun/gmsm/smx509"
	"io"
	"testing"
	"time"
)

const (
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

	ZJCA_ROOT_PEM = `-----BEGIN CERTIFICATE-----
MIICpjCCAkqgAwIBAgIQHzXZGQVs5o0CLlHzinoINzAMBggqgRzPVQGDdQUAMC4x
CzAJBgNVBAYTAkNOMQ4wDAYDVQQKDAVOUkNBQzEPMA0GA1UEAwwGUk9PVENBMB4X
DTEzMTIyMTAyNDY0MVoXDTMzMTIxNjAyNDY0MVowUjELMAkGA1UEBhMCQ04xLzAt
BgNVBAoMJlpoZWppYW5nIERpZ2l0YWwgQ2VydGlmaWNhdGUgQXV0aG9yaXR5MRIw
EAYDVQQDDAlaSkNBIE9DQTEwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAATp48tm
okIXIRCe6x9O5iaVViNlv1Yjwt1YbF9DpX63uSuuq2BioZhy+SWwNdXIYroR4zAV
DQoPMSzrFJ1SmEyfo4IBIjCCAR4wHwYDVR0jBBgwFoAUTDKxl9kzG8SmBcHG5Yti
W/CXdlgwDwYDVR0TAQH/BAUwAwEB/zCBugYDVR0fBIGyMIGvMEGgP6A9pDswOTEL
MAkGA1UEBhMCQ04xDjAMBgNVBAoMBU5SQ0FDMQwwCgYDVQQLDANBUkwxDDAKBgNV
BAMMA2FybDAqoCigJoYkaHR0cDovL3d3dy5yb290Y2EuZ292LmNuL2FybC9hcmwu
Y3JsMD6gPKA6hjhsZGFwOi8vbGRhcC5yb290Y2EuZ292LmNuOjM4OS9DTj1hcmws
T1U9QVJMLE89TlJDQUMsQz1DTjAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFKfT
sSSQIB09tFTuSzcoUpGuLGoiMAwGCCqBHM9VAYN1BQADSAAwRQIhAJLutfL7dLEb
M7EP0QCwN5g0WMLBI/MG5He9N6oREaYZAiAbWypQB34bhGNSqUQs+RQIYpct4yN5
UIufisb9BHWQIQ==
-----END CERTIFICATE-----
`
)

var (
	authCert Certificate
	zjcaRoot *smx509.Certificate
)

func init() {
	var err error

	zjcaRoot, err = smx509.ParseCertificatePEM([]byte(ZJCA_ROOT_PEM))
	if err != nil {
		panic(err)
	}

	authCert, err = X509KeyPair([]byte(AUTH_CERT_PEM), []byte(AUTH_KEY_PEM))
	if err != nil {
		panic(err)
	}
}

// 测试忽略安全验证的客户端握手
func Test_clientHandshake_no_auth(t *testing.T) {
	go func() {
		if err := server(8444); err != nil {
			panic(err)
		}
	}()
	time.Sleep(time.Millisecond * 300)

	config := &Config{InsecureSkipVerify: true}
	conn, err := Dial("tcp", "127.0.0.1:8444", config)
	if err != nil {
		t.Fatal(err)
	}
	err = conn.Handshake()
	if err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	_ = conn.Close()
}

// 测试服务端身份认证
func Test_clientHandshake_auth_server(t *testing.T) {
	go func() {
		if err := server(8445); err != nil {
			panic(err)
		}
	}()
	pool := smx509.NewCertPool()
	pool.AddCert(root1)
	// 不匹配的证书
	pool.AddCert(zjcaRoot)

	time.Sleep(time.Millisecond * 300)
	config := &Config{RootCAs: pool}
	conn, err := Dial("tcp", "127.0.0.1:8445", config)
	if err != nil {
		t.Fatal(err)
	}
	err = conn.Handshake()
	if err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	_ = conn.Close()
}

// 测试双向身份认证
func Test_clientHandshake_client_auth(t *testing.T) {
	go func() {
		if err := serverNeedAuth(8446); err != nil {
			panic(err)
		}
	}()
	pool := smx509.NewCertPool()
	pool.AddCert(root1)

	time.Sleep(time.Millisecond * 300)

	config := &Config{RootCAs: pool, Certificates: []Certificate{authCert}}
	conn, err := Dial("tcp", "127.0.0.1:8446", config)
	if err != nil {
		t.Fatal(err)
	}
	err = conn.Handshake()
	if err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	_ = conn.Close()
}

// 测试握手重用
func Test_resumedSession(t *testing.T) {
	go func() {
		if err := serverResumeSession(8448); err != nil {
			panic(err)
		}
	}()
	pool := smx509.NewCertPool()
	pool.AddCert(root1)
	time.Sleep(time.Millisecond * 300)
	config := &Config{RootCAs: pool, SessionCache: NewLRUSessionCache(2)}

	buff := make([]byte, 1024)
	for i := 0; i < 2; i++ {
		conn, err := Dial("tcp", "127.0.0.1:8448", config)
		if err != nil {
			t.Fatal(err)
		}
		err = conn.Handshake()
		if err != nil {
			_ = conn.Close()
			t.Fatal(err)
		}
		n, err := conn.Read(buff)
		if err != nil && err != io.EOF {
			t.Fatal(err)
		}
		fmt.Printf(">> %02X\n", buff[:n])
		_ = conn.Close()
	}
}

func Test_clientHandshake_ECDHE(t *testing.T) {
	go func() {
		if err := server(8451); err != nil {
			panic(err)
		}
	}()
	time.Sleep(time.Millisecond * 300)
	pool := smx509.NewCertPool()
	pool.AddCert(root1)
	config := &Config{
		RootCAs:      pool,
		Certificates: []Certificate{authCert},
		CipherSuites: []uint16{ECDHE_SM4_GCM_SM3, ECDHE_SM4_CBC_SM3},
	}
	conn, err := Dial("tcp", "127.0.0.1:8451", config)
	if err != nil {
		t.Fatal(err)
	}
	err = conn.Handshake()
	if err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	_ = conn.Close()

}
