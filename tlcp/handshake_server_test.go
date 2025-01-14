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
	res, _ := time.Parse("2006-01-02 15:04:05", "2022-12-15 00:00:00")
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
	//c, s := mockPipe()
	//cli := Client(c, &Config{
	//	InsecureSkipVerify: true,
	//	Time:               runtimeTime,
	//})
	//svr := Server(s, &Config{
	//	Certificates: []Certificate{sigCert, encCert},
	//	Time:         runtimeTime,
	//})
	//
	//done := make(chan bool)
	//
	//go func() {
	//	defer close(done)
	//
	//	if err := svr.Handshake(); err != nil {
	//		t.Errorf("server: %s", err)
	//		return
	//	}
	//	s.Close()
	//}()
	//if err := cli.Handshake(); err != nil {
	//	t.Fatalf("client: %s", err)
	//}
	//
	//c.Close()
	//<-done

}
