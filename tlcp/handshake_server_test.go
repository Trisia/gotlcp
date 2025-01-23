package tlcp

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/emmansun/gmsm/smx509"
)

const (
	ROOT_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIIBcTCCARegAwIBAgIBATAKBggqgRzPVQGDdTAfMQswCQYDVQQGEwJDTjEQMA4G
A1UEAwwHVEVTVF9DQTAgFw0yNTAxMjIxMzAwNTlaGA8yMDU1MDEyMzEzMDA1OVow
HzELMAkGA1UEBhMCQ04xEDAOBgNVBAMMB1RFU1RfQ0EwWTATBgcqhkjOPQIBBggq
gRzPVQGCLQNCAATLGG85F2R/VGb21NoJvMA76bdXo7jAItc12MrssTpi9eqVuEQr
eJFWk3mO8FltQ72iQmPGNHQNKj6hcIGqvGqio0IwQDAOBgNVHQ8BAf8EBAMCAQYw
DwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUp00Errs8sKqKv2EA/TnE1vJC7Rsw
CgYIKoEcz1UBg3UDSAAwRQIhAKdlU8wecffSoH/alVUUogSOMoFxSV+QqHvTcRjX
jKbiAiB+126kkQVjXlc5LMUhLCWB28JvRyrtg7flbEJr1FYMeQ==
-----END CERTIFICATE-----
`

	SIG_KEY_PEM = `-----BEGIN SM2 PRIVATE KEY-----
MHcCAQEEIBbYDi3GR7DIrhwEsgMwmxLeliFOFhYpJHdX5GOSPQzCoAoGCCqBHM9V
AYItoUQDQgAEWcnwQdvRCF5K+hu6tuFiQoph3cl79pvy+NfBQbRZnkvDsnuvVzWW
5a1BFIsmSjQAQxWMUtuwCnHmmW8dqVeglQ==
-----END SM2 PRIVATE KEY-----
`
	SIG_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIIBzjCCAXagAwIBAgIEZ5I/yjAKBggqgRzPVQGDdTAfMQswCQYDVQQGEwJDTjEQ
MA4GA1UEAwwHVEVTVF9DQTAgFw0yNTAxMjIxMzEwMzRaGA8yMDU1MDEyMzEzMTAz
NFowRTELMAkGA1UEBhMCQ04xDzANBgNVBAgMBua1meaxnzEPMA0GA1UEBwwG5p2t
5beeMRQwEgYDVQQDDAtFbnRpdHlfQ0VSVDBZMBMGByqGSM49AgEGCCqBHM9VAYIt
A0IABFnJ8EHb0QheSvoburbhYkKKYd3Je/ab8vjXwUG0WZ5Lw7J7r1c1luWtQRSL
Jko0AEMVjFLbsApx5plvHalXoJWjeDB2MA4GA1UdDwEB/wQEAwIDuDAdBgNVHSUE
FjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwHwYDVR0jBBgwFoAUp00Errs8sKqKv2EA
/TnE1vJC7RswJAYDVR0RBB0wG4IJbG9jYWxob3N0ggh0ZXN0LmNvbYcEfwAAATAK
BggqgRzPVQGDdQNGADBDAh9uv08YiNEYRUQJXtY9CWOJzty+mIqspsz/NTHLzTVi
AiAtmAwO28Tc/r4KhEa59hihvFt/gCtrqqW+e1WggfNVpw==
-----END CERTIFICATE-----
`
	ENC_KEY_PEM = `-----BEGIN SM2 PRIVATE KEY-----
MHcCAQEEIAqa7hSnNnbRu3wglY6G+9aHTsOpQPmjjpG19X8uQZsroAoGCCqBHM9V
AYItoUQDQgAE2X/XKR3nZm03XEZQZw91/YSBXT2VmpdxlWyDPIKtFxB/nRaKbERL
BC4HjiCdDyBuebAaB1xieQ3puuE5vn8nwg==
-----END SM2 PRIVATE KEY-----
`

	ENC_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIIB0DCCAXagAwIBAgIEZ5I/3DAKBggqgRzPVQGDdTAfMQswCQYDVQQGEwJDTjEQ
MA4GA1UEAwwHVEVTVF9DQTAgFw0yNTAxMjIxMzEwNTJaGA8yMDU1MDEyMzEzMTA1
MlowRTELMAkGA1UEBhMCQ04xDzANBgNVBAgMBua1meaxnzEPMA0GA1UEBwwG5p2t
5beeMRQwEgYDVQQDDAtFbnRpdHlfQ0VSVDBZMBMGByqGSM49AgEGCCqBHM9VAYIt
A0IABNl/1ykd52ZtN1xGUGcPdf2EgV09lZqXcZVsgzyCrRcQf50WimxESwQuB44g
nQ8gbnmwGgdcYnkN6brhOb5/J8KjeDB2MA4GA1UdDwEB/wQEAwIDuDAdBgNVHSUE
FjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwHwYDVR0jBBgwFoAUp00Errs8sKqKv2EA
/TnE1vJC7RswJAYDVR0RBB0wG4IJbG9jYWxob3N0ggh0ZXN0LmNvbYcEfwAAATAK
BggqgRzPVQGDdQNIADBFAiEAxRW36Sb8rwer4/VmKz/UFbuNVj+IbTRInLQ4a7Cf
VOYCID1xEk1g/8nprur+bX7jv9t3jTAN7+BeDd6N0x2pRLqp
-----END CERTIFICATE-----
`
)

var (
	sigCert    Certificate
	encCert    Certificate
	root1      *smx509.Certificate
	simplePool *smx509.CertPool
)

func init() {
	var err error
	root1, err = smx509.ParseCertificatePEM([]byte(ROOT_CERT_PEM))
	if err != nil {
		panic(err)
	}
	sigCert, err = X509KeyPair([]byte(SIG_CERT_PEM), []byte(SIG_KEY_PEM))
	if err != nil {
		panic(err)
	}
	encCert, err = X509KeyPair([]byte(ENC_CERT_PEM), []byte(ENC_KEY_PEM))
	if err != nil {
		panic(err)
	}

	simplePool = smx509.NewCertPool()
	simplePool.AddCert(root1)
}

// 测试时服务器时间，防止证书过期
func runtimeTime() time.Time {
	res, _ := time.Parse("2006-01-02 15:04:05", "2025-01-23 21:30:00")
	return res
}

/*
func Test_serverHandshake(t *testing.T) {
	err := server(8443)
	if err != nil {
		t.Fatal(err)
	}
}

func Test_serverHandshake_auth(t *testing.T) {
	err := serverNeedAuth(8442)
	if err != nil {
		t.Fatal(err)
	}
}

// 重用握手测试
func Test_doResumeHandshake(t *testing.T) {
	var err error

	config := &Config{
		Certificates: []Certificate{sigCert, encCert},
		SessionCache: NewLRUSessionCache(2),
	}

	ln, err := Listen("tcp", fmt.Sprintf(":%d", 8447), config)
	if err != nil {
		t.Fatal(err)
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello tlcp!")
	})
	svr := http.Server{}
	err = svr.Serve(ln)
	if err != nil {
		t.Fatal(err)
	}

}
*/
// 启动TLCP服务端
func server(port int, suites ...uint16) error {
	var err error
	tcpLn, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}
	defer tcpLn.Close()
	config := &Config{
		Certificates: []Certificate{sigCert, encCert},
		Time:         runtimeTime,
	}
	if len(suites) > 0 {
		config.CipherSuites = suites
	}
	var conn net.Conn
	for {
		conn, err = tcpLn.Accept()
		if err != nil {
			return err
		}

		tlcpConn := Server(conn, config)
		err = tlcpConn.Handshake()
		if err != nil {
			_ = conn.Close()
			return err
		}
		_ = tlcpConn.Close()
	}
}

// 启动TLCP服务端 要求客户端进行身份认证
func serverNeedAuth(port int) error {
	var err error
	tcpLn, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}
	defer tcpLn.Close()
	config := &Config{
		Certificates: []Certificate{sigCert, encCert},
		ClientAuth:   RequireAndVerifyClientCert,
		ClientCAs:    simplePool,
		Time:         runtimeTime,
	}
	var conn net.Conn
	for {
		conn, err = tcpLn.Accept()
		if err != nil {
			return err
		}

		tlcpConn := Server(conn, config)
		err = tlcpConn.Handshake()
		if err != nil {
			_ = conn.Close()
			return err
		}
		_ = tlcpConn.Close()
	}
}

// 启用支持握手重用的服务端
func serverResumeSession(port int) error {
	var err error
	tcpLn, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}
	defer tcpLn.Close()
	config := &Config{
		Certificates: []Certificate{sigCert, encCert},
		SessionCache: NewLRUSessionCache(10),
	}
	data := []byte{
		0, 1, 2, 3,
		0, 1, 2, 3,
		0, 1, 2, 3,
		0, 1, 2, 3,
	}
	var conn net.Conn
	for {
		conn, err = tcpLn.Accept()
		if err != nil {
			return err
		}

		tlcpConn := Server(conn, config)
		err = tlcpConn.Handshake()
		if err != nil {
			_ = conn.Close()
			return err
		}
		_, _ = tlcpConn.Write(data)

		_ = tlcpConn.Close()
	}
}

// 测试握手重用
func Test_ResumedSession(t *testing.T) {
	pool := smx509.NewCertPool()
	pool.AddCert(root1)
	go func() {
		var err error
		tcpLn, err := net.Listen("tcp", fmt.Sprintf(":%d", 20100))
		if err != nil {
			t.Fatal(err)
		}
		defer tcpLn.Close()
		config := &Config{
			ClientCAs:    pool,
			ClientAuth:   RequireAndVerifyClientCert,
			Certificates: []Certificate{sigCert, encCert},
			SessionCache: NewLRUSessionCache(10),
			Time:         runtimeTime,
		}
		first := true
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

			if tlcpConn.IsClient() {
				t.Fatalf("Expect server connection type, but not")
			}
			if len(tlcpConn.PeerCertificates()) == 0 {
				t.Fatalf("Expect get peer cert, but not")
			}
			if first {
				first = false
			} else {
				if !tlcpConn.didResume {
					t.Fatalf("Expect second connection session resume, but not")
				}
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
		conn, err := Dial("tcp", "127.0.0.1:20100", config)
		if err != nil {
			t.Fatal(err)
		}
		err = conn.Handshake()
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
	}
}

func Test_processClientHello(t *testing.T) {
	c, s := mockPipe()
	cli := Client(c, &Config{
		InsecureSkipVerify: true,
		Time:               runtimeTime,
	})
	svr := Server(s, &Config{
		Certificates: []Certificate{sigCert, encCert},
		Time:         runtimeTime,
	})

	done := make(chan bool)

	go func() {
		defer close(done)

		if err := svr.Handshake(); err != nil {
			t.Errorf("server: %s", err)
			return
		}
		s.Close()
	}()
	if err := cli.Handshake(); err != nil {
		t.Fatalf("client: %s", err)
	}

	c.Close()
	<-done

}
