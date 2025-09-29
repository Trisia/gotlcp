package tlcp

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/emmansun/gmsm/smx509"
)

const (
	AUTH_KEY_PEM = `-----BEGIN SM2 PRIVATE KEY-----
MHcCAQEEIE/fa/dA39u8xgGt8cRmex9sxdS/xHVRWhvXOKQePSs2oAoGCCqBHM9V
AYItoUQDQgAEYrYenPGV0iBRy5HcJ8RmPdDn+WU00IVBaBUEoBsBMdVTVsELqpbN
VVu5Hb+Mbfulh1RMweERSqqvKhrbw5p2xA==
-----END SM2 PRIVATE KEY-----
`

	AUTH_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIIBzzCCAXagAwIBAgIEZ5I/7jAKBggqgRzPVQGDdTAfMQswCQYDVQQGEwJDTjEQ
MA4GA1UEAwwHVEVTVF9DQTAgFw0yNTAxMjIxMzExMTBaGA8yMDU1MDEyMzEzMTEx
MFowRTELMAkGA1UEBhMCQ04xDzANBgNVBAgMBua1meaxnzEPMA0GA1UEBwwG5p2t
5beeMRQwEgYDVQQDDAtFbnRpdHlfQ0VSVDBZMBMGByqGSM49AgEGCCqBHM9VAYIt
A0IABGK2HpzxldIgUcuR3CfEZj3Q5/llNNCFQWgVBKAbATHVU1bBC6qWzVVbuR2/
jG37pYdUTMHhEUqqryoa28OadsSjeDB2MA4GA1UdDwEB/wQEAwIDuDAdBgNVHSUE
FjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwHwYDVR0jBBgwFoAUp00Errs8sKqKv2EA
/TnE1vJC7RswJAYDVR0RBB0wG4IJbG9jYWxob3N0ggh0ZXN0LmNvbYcEfwAAATAK
BggqgRzPVQGDdQNHADBEAiBL/8aRlrhltUk2PAwTEuAgBwt7VPjt5DGJrHclsQJ0
DwIgJiWgta8Tx6UVY3SZwQxQqcMM5YlZ0NHyV5DC8AGyNmg=
-----END CERTIFICATE-----
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
	testClientHandshake(t, config, "127.0.0.1:8444")
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
	config := &Config{RootCAs: pool, Time: runtimeTime}
	testClientHandshake(t, config, "127.0.0.1:8445")
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

	config := &Config{RootCAs: pool, Certificates: []Certificate{authCert}, Time: runtimeTime}
	testClientHandshake(t, config, "127.0.0.1:8446")
}

// 测试客户端无证书，服务端要求证书
func Test_clientHandshake_client_noauth_nocert(t *testing.T) {
	go func() {
		if err := serverNeedAuth(8447); err != nil {
			if err.Error() != "tlcp: client didn't provide a certificate" {
				t.Errorf("%v\n", err)
			}
		}
	}()
	time.Sleep(time.Millisecond * 300)

	config := &Config{InsecureSkipVerify: true}
	conn, err := Dial("tcp", "127.0.0.1:8447", config)
	if err != nil && err.Error() != "remote error: tlcp: bad certificate" {
		t.Fatal(err)
	}

	if err == nil {
		conn.Close()
	}
}

// 测试客户端无证书，服务端要求证书
func Test_clientHandshake_client_nocert(t *testing.T) {
	go func() {
		if err := serverNeedAuth(8449); err != nil {
			if err.Error() != "tlcp: client didn't provide a certificate" {
				t.Errorf("%v\n", err)
			}
		}
	}()
	pool := smx509.NewCertPool()
	pool.AddCert(root1)

	time.Sleep(time.Millisecond * 300)

	config := &Config{RootCAs: pool, Time: runtimeTime}
	conn, err := Dial("tcp", "127.0.0.1:8449", config)
	if err != nil && err.Error() != "remote error: tlcp: bad certificate" {
		t.Fatal(err)
	}

	if err == nil {
		conn.Close()
	}
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
	config := &Config{RootCAs: pool, SessionCache: NewLRUSessionCache(2), Time: runtimeTime}

	buff := make([]byte, 1024)
	for i := 0; i < 5; i++ {
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
			_ = conn.Close()
			t.Fatal(err)
		}
		peerCertificates := conn.PeerCertificates()
		if len(peerCertificates) < 2 {
			_ = conn.Close()
			t.Fatal("peerCertificates no found, it should be 2 (sig cert,enc cert)")
		}
		_ = n
		_ = conn.Close()
		//fmt.Printf(">> %02X\n", buff[:n])
	}
}

func Test_clientHandshake_ECDHE(t *testing.T) {
	go func() {
		if err := server(8451, ECDHE_SM4_GCM_SM3, ECDHE_SM4_CBC_SM3); err != nil {
			panic(err)
		}
	}()
	time.Sleep(time.Millisecond * 300)
	pool := smx509.NewCertPool()
	pool.AddCert(root1)

	config := &Config{
		RootCAs:      pool,
		Certificates: []Certificate{authCert, authCert},
		CipherSuites: []uint16{ECDHE_SM4_GCM_SM3, ECDHE_SM4_CBC_SM3},
		Time:         runtimeTime,
	}
	testClientHandshake(t, config, "127.0.0.1:8451")

	config.ClientECDHEParamsAsVector = true
	testClientHandshake(t, config, "127.0.0.1:8451")
}

func testClientHandshake(t *testing.T, config *Config, addr string) {
	conn, err := Dial("tcp", addr, config)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err = conn.Handshake(); err != nil {
		t.Fatal(err)
	}
}

// 测试握手重用
func Test_NotResumedSession(t *testing.T) {
	pool := smx509.NewCertPool()
	pool.AddCert(root1)
	go func() {
		var err error
		tcpLn, err := net.Listen("tcp", fmt.Sprintf(":%d", 20099))
		if err != nil {
			t.Fatal(err)
		}
		defer tcpLn.Close()
		config := &Config{
			ClientCAs:    pool,
			ClientAuth:   RequireAndVerifyClientCert,
			Certificates: []Certificate{sigCert, encCert},
			Time:         runtimeTime,
		}
		for {
			conn, err := tcpLn.Accept()
			if err != nil {
				return
			}

			tlcpConn := Server(conn, config)
			err = tlcpConn.Handshake()
			if err != nil {
				_ = conn.Close()
				return
			}
			_ = tlcpConn.Close()
		}
	}()

	time.Sleep(time.Millisecond * 300)
	config := &Config{
		RootCAs:      pool,
		Certificates: []Certificate{authCert},
		SessionCache: NewLRUSessionCache(2),
		Time:         runtimeTime,
	}

	for i := 0; i < 2; i++ {
		conn, err := Dial("tcp", "127.0.0.1:20099", config)
		if err != nil {
			t.Fatal(err)
		}
		err = conn.Handshake()
		if err != nil {
			t.Fatal(err)
		}

		if !conn.IsClient() {
			t.Fatalf("Expect client connection type, but not")
		}
		if len(conn.PeerCertificates()) == 0 {
			t.Fatalf("Expect get peer cert, but not")
		}
		if conn.didResume {
			t.Fatalf("Expect disable resume, but not")
		}
		_ = conn.Close()
	}
}

// ECC 套件下客户端传输双证书
func Test_clientHandshake_ECCWithEncCert(t *testing.T) {
	go func() {
		if err := serverNeedAuth(8452); err != nil {
			panic(err)
		}
	}()
	time.Sleep(time.Millisecond * 300)
	pool := smx509.NewCertPool()
	pool.AddCert(root1)

	config := &Config{
		RootCAs:      pool,
		Certificates: []Certificate{authCert, authCert},
		CipherSuites: []uint16{ECC_SM4_GCM_SM3, ECC_SM4_CBC_SM3},
		Time:         runtimeTime,
	}
	testClientHandshake(t, config, "127.0.0.1:8452")
}

// 测试 ALPN 协议选择
func Test_ClientHelloExtALPN(t *testing.T) {
	cli, svr := tcpPipe(8455)

	conn := Client(cli, &Config{
		Time:       runtimeTime,
		RootCAs:    simplePool,
		NextProtos: []string{"h2"},
	})

	svc := Server(svr, &Config{
		Certificates: []Certificate{sigCert, encCert},
		Time:         runtimeTime,
		NextProtos:   []string{"h2", "http/1.1"},
	})
	go func() {
		defer svc.Close()
		// 忽略服务端收到的错误
		_ = svc.Handshake()
	}()
	if err := conn.Handshake(); err != nil {
		t.Fatalf("Expect handshake finish without error but not %v", err)
	}
	if conn.ConnectionState().NegotiatedProtocol != "h2" {
		t.Fatalf("Expect negotiated protocol is h2 but %v", conn.ConnectionState().NegotiatedProtocol)
	}
}
