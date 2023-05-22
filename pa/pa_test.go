package pa

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"gitee.com/Trisia/gotlcp/tlcp"
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

	RSA_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIIDmzCCAoOgAwIBAgIIAs5k+q7pWb8wDQYJKoZIhvcNAQELBQAwQjELMAkGA1UE
BhMCQ04xDzANBgNVBAgMBua1meaxnzEPMA0GA1UEBwwG5p2t5beeMREwDwYDVQQK
DAjmtYvor5VDQTAeFw0yMjEwMDYwMzE3MzhaFw0yMzEwMDYwMzE3MzhaMGIxCzAJ
BgNVBAYTAmNuMQ8wDQYDVQQIDAbmtZnmsZ8xDzANBgNVBAcMBuadreW3njEPMA0G
A1UEChMGR29UTENQMQ8wDQYDVQQLEwZHb1RMQ1AxDzANBgNVBAMTBkdvVExDUDCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANKp8SDLQIM5OYPgQtrqbuK+
7EuXv2T3p+XWbC0fCWlozF+MdQJOttcYcjiKUANfyHQ2FKmnqVDpRphaUk+ofcDr
TIlXDtabvInFhu7O9mnDK0vsLMK6JR9CppR9u1n/zIs5cAZMjcL3KAhtfzaHA0vu
lQWFU9X1OyXrWNJ9I8jiCwOsRvkKvlRdj6LjW63Jwe92SIAo4epCVthapI92GJqu
9JXYkLPIgNb5YWSwuyOxu4htq6F4WxCIjpyoDWvlCS2LkwSdNhZqqhAbPAooiS4O
ZpvIYMrk1Bv7Wc3VWKUNadbl1YMJS62Ddtz+gbTM6NmC6AhYvFKbeZ0Odci6tQkC
AwEAAaN1MHMwDgYDVR0PAQH/BAQDAgbAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwG
A1UdEwEB/wQCMAAwHQYDVR0OBBYEFNqgN+WK+ic6g1vm2XlHa99bDOH8MB8GA1Ud
IwQYMBaAFLPVquOPy0NHJs9Ymw09DimIBmkIMA0GCSqGSIb3DQEBCwUAA4IBAQCS
Jl3I1fBdeik+gG2MS52daZezeb/p25gsnipTALd4DWfW/xc1K3kX9OhUtCLSoxAU
MGwazQCwxnbyaTtX55ZPmULr+fr9WNPsMzRLKwPcdo8c673N8az7E7mgq4ZRAAvI
Hi9XJQgEgmWSm1bzwkC0FSWof+u2g0IBGrwzdbdFwiRjMfsHXzGulOQ/zc0rF+u6
nJpSP3NrzG/eu8/kSTCx/FHV9rv9eYdrGRwrEPa9Oqxvfisao68Et1qRIVN6taoi
oJQwxYtnmmpP81tFpPgTzqaQVMPU1OWveHyh7Q2rQEYwn64Tx0MyAM+FMWrp3tij
hkBabSSdkcdYL/PHNI/5
-----END CERTIFICATE-----
`
	RSA_ROOT_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIIDaTCCAlGgAwIBAgIIAs4MAPwpJ6cwDQYJKoZIhvcNAQELBQAwQjELMAkGA1UE
BhMCQ04xDzANBgNVBAgMBua1meaxnzEPMA0GA1UEBwwG5p2t5beeMREwDwYDVQQK
DAjmtYvor5VDQTAeFw0yMTEyMjMwODQ4MzNaFw0zMTEyMjMwODQ4MzNaMEIxCzAJ
BgNVBAYTAkNOMQ8wDQYDVQQIDAbmtZnmsZ8xDzANBgNVBAcMBuadreW3njERMA8G
A1UECgwI5rWL6K+VQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDZ
5Iv89jyy22xd7Y5iADGx4MyBBpquqneEElD41UEFry3TpmFXCNi52jLV4xHOSeQm
v90wkGcoKa2S1sdMTpq6xOEWaFDAeu6zO6y9TssR2h31ELgfPjQ/U+pUy+Lv9tFD
yNy0A9Yu9o0V4g+IoV0zDixR9OfKUnyzf9mOOQaeW1TDnHIlf7ghB+/aEJAACgbQ
wOH2ko4gHNxC0OWBX4/q7Go0ltDl2/N+hzCPv4kPtEHhFsmnuHkyELxedVCPdNxF
nIftorbEzY7VbUxKpafl1x46tcOXY4uinTEA/5KmMr/w+0DD2vFJbN+Ocr0PXCQF
1OTQH/OEK5e1z3WT4LJxAgMBAAGjYzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMB
Af8EBTADAQH/MB0GA1UdDgQWBBSz1arjj8tDRybPWJsNPQ4piAZpCDAfBgNVHSME
GDAWgBSz1arjj8tDRybPWJsNPQ4piAZpCDANBgkqhkiG9w0BAQsFAAOCAQEACDAM
F+N+tJC+uqse9vUPwOWtWkyMnB4P+3hhUO7DheSwKhsxXQZ68hanpdbik7Augdf3
CwyeVAn4mvc4s0TfplD59cmykJUrBd04E8/gXnXY765HHj+kvmEDn6a4zX5EfYvI
M2ZN14XUGupQaNTYZA3rg84c5YtOiISEqvb+UnFLOHFVK92ste0Y8DEigAG9Of8T
tFUr2ekrfFEZZkc4VJo93uvAN0XDIRduEIhy+bkGpDZJVEhs78PEMF7UdAXM/Baw
B0B94M1vvbGqgL76Z2+pVlAO9bf+pYVe8zCqOq73etCUplGznsoYIWvkguec6NeY
xpRON8bERA9uuM+q/g==
-----END CERTIFICATE-----
`
	RSA_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIIEpAIBAAKCAQEA0qnxIMtAgzk5g+BC2upu4r7sS5e/ZPen5dZsLR8JaWjMX4x1
Ak621xhyOIpQA1/IdDYUqaepUOlGmFpST6h9wOtMiVcO1pu8icWG7s72acMrS+ws
wrolH0KmlH27Wf/MizlwBkyNwvcoCG1/NocDS+6VBYVT1fU7JetY0n0jyOILA6xG
+Qq+VF2PouNbrcnB73ZIgCjh6kJW2Fqkj3YYmq70ldiQs8iA1vlhZLC7I7G7iG2r
oXhbEIiOnKgNa+UJLYuTBJ02FmqqEBs8CiiJLg5mm8hgyuTUG/tZzdVYpQ1p1uXV
gwlLrYN23P6BtMzo2YLoCFi8Upt5nQ51yLq1CQIDAQABAoIBAQDMXrehw+z7IRnu
GTNio4odiXE9yKKSNjx5GfLqNzDvRQ74JxAgw/JXa8zrkysaiuKx8wFKsW/uIdEt
3nn585DEBsHCf2XSx1U6JxnHNZsScZfgWOf3pZR75jIq3mtSXXm3G2rVgZEJsrLw
siF26bZGBNgnefgiGn1eRRpvYZ3Es9oN5YSwjydxc0Ovf/hNtlzYX10Nz0mWYxLh
NmGJwxZ7CjIPvi/BueU37/f844rdD8IPwnRxHp5FTCgGPC2OMdH6PAc21uBXDUce
8pasfcHos/SRLE4c5mLpZBTriOIk+lY02WYwWER4ntNPv7DR9OfyqVL/wBQfG/MO
r3/W8hdtAoGBAP0maUzS90+6bWiPuJKS9AORHhH3k6B9HpK78R4z18t4Ee7et0HL
IAOhAQte0BYVDFx8u14jJRm6dICrHkJem3O+ymzaNYuY8vgkTMT3YxTEEdNtLJRA
M8nNbbGEAEWuh3BrlW+CNwXMKm5nUa76XTj65t/JN/NYPnljTVIt5s0jAoGBANUJ
FWcraWCcYiNNkZUi4I54c5RPSOVLJ0vUo5eAiOIpu8a2kcYoWLRZpuu3Wth5F3o1
1vNzas8AHoKMioPHDlI58GTh+uwDbzC8Al45ve+IuKnCECWu7pTzpsLiiJmtfjXi
Ws2ARRnfCAdJIEOnCrL1qgBf4AswU3MK1vC9jGXjAoGAdiUJG9uRpFoDWbtJjs6a
p1eAyy3abho2vJCOFWRooAMni23R5Rjhlg/8JsxXHRcxr7Be2a5ZUEqeuLYj5yG0
Ny6h1m94cfAt5PU8BujWCwj+sMfQ+FeGU/ZV7XUHk33CpArxsRr6hvAkFWaOzrT1
8PPX8DU+sYlLjudzXJkjkDUCgYAsT/djvmPs9Jp1PW1K2DZdbDCeaN+A0mEaJODi
YpoWcRfd/ZvU3A+XdA6EeV8sKAP6J7jOavOMmzm9bf5h6sXP1L1sPpUzAoPeXz0e
3GPlr0q6BOPW8swtr4DAiN5hGPVnv+2jUUsOVpYU7eEIMXbIQtFZwpeXvDWfeGG9
MbBCgQKBgQCuuESWq6M4W6+0KnmRyaSMy2xkUcnS1Erzoi/UT1Z7RDaGeCfU35td
/OOXGKsXlMsYXo3JNAeYi74qpIyDuN+QCBStAxE+49OEL5XocLLzNmtaG8XamTfI
ZGYOtdOjNGchxzykr2HErzP+PAGkB9N0QzrA+Gid32/PJB4iJsD8yA==
-----END PRIVATE KEY-----
`
)

var (
	sigCert tlcp.Certificate
	encCert tlcp.Certificate
	sm2Root *smx509.Certificate

	rsaCert tls.Certificate
	rsaRoot *x509.Certificate
)

func init() {
	var err error
	sm2Root, err = smx509.ParseCertificatePEM([]byte(ROOT_CERT_PEM))
	if err != nil {
		panic(err)
	}
	sigCert, err = tlcp.X509KeyPair([]byte(SIG_CERT_PEM), []byte(SIG_KEY_PEM))
	if err != nil {
		panic(err)
	}
	encCert, err = tlcp.X509KeyPair([]byte(ENC_CERT_PEM), []byte(ENC_KEY_PEM))
	if err != nil {
		panic(err)
	}

	block, _ := pem.Decode([]byte(RSA_ROOT_CERT_PEM))
	rsaRoot, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(err)
	}

	rsaCert, err = tls.X509KeyPair([]byte(RSA_CERT_PEM), []byte(RSA_KEY_PEM))
	if err != nil {
		panic(err)
	}
}

func TestListen(t *testing.T) {
	go func() {
		err := mockHelloServer(9000)
		if err != nil {
			panic(err)
		}
	}()
	buf := make([]byte, 1480)
	time.Sleep(time.Millisecond * 300)
	// TLS Case
	conn, err := tls.Dial("tcp", "127.0.0.1:9000", &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	_, err = conn.Write([]byte("Hello from tls client!"))
	if err != nil {
		t.Fatal(err)
	}
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("[TLS  Client] << %s\n", buf[:n])

	// TLCP CASE
	conn2, err := tlcp.Dial("tcp", "127.0.0.1:9000", &tlcp.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	_, err = conn2.Write([]byte("Hello from tlcp client!"))
	if err != nil {
		t.Fatal(err)
	}
	n, err = conn2.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("[TLCP Client] << %s\n", buf[:n])

}

// 测试非标准TLS/TLCP 协议造成的Accept错误
func TestProtocolNotSupportError_Error(t *testing.T) {
	var port = 9001
	var err error
	var conn net.Conn
	send := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	buf := make([]byte, 256)
	tlcpCfg := &tlcp.Config{
		Certificates: []tlcp.Certificate{sigCert, encCert},
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{rsaCert},
	}

	listen, err := Listen("tcp", fmt.Sprintf(":%d", port), tlcpCfg, tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()

	go func() {
		var cli net.Conn
		time.Sleep(time.Millisecond * 100)
		cli, _ = net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		time.Sleep(time.Millisecond * 100)
		_, _ = cli.Write(send)
		if cli != nil {
			_ = cli.Close()
		}
		// 第二次发起正确的连接
		time.Sleep(time.Millisecond * 100)
		cli, _ = tlcp.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), &tlcp.Config{InsecureSkipVerify: true})
		time.Sleep(time.Millisecond * 100)
		_, err = cli.Write(send)
		if err != nil {
			t.Fatal(err)
		}
		if cli != nil {
			_ = cli.Close()
		}
		// 第二次发起正确的连接
		time.Sleep(time.Millisecond * 100)
		// 第三次发起TLS连接
		cli, err = tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), &tls.Config{InsecureSkipVerify: true})
		time.Sleep(time.Millisecond * 100)
		if err != nil {
			t.Fatal(err)
		}
		_, err = cli.Write(send)
		if err != nil {
			t.Fatal(err)
		}
		if cli != nil {
			_ = cli.Close()
		}
	}()

	conn, err = listen.Accept()
	// 不应该出现错误
	if err != nil {
		t.Fatal(err)
	}
	// 尝试读取数据
	_, err = conn.Read(buf)
	if err != notSupportError {
		t.Fatalf("err: %v, want: %v", err, notSupportError)
	}
	_ = conn.Close()

	// 第二次发送正常数据
	conn, err = listen.Accept()
	// 不应该出现错误
	if err != nil {
		t.Fatal(err)
	}
	// 可以正常读取数据
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := conn.(*ProtocolSwitchServerConn).ProtectedConn().(*tlcp.Conn); !ok {
		t.Fatalf("expect tlcp.Conn type but not")
	}
	if !bytes.Equal(buf[:n], send) {
		t.Fatalf("recv: %x, want: %x", buf[:n], send)
	}
	if conn != nil {
		_ = conn.Close()
	}

	// 第三次发送TLS数据
	conn, err = listen.Accept()
	// 不应该出现错误
	if err != nil {
		t.Fatal(err)
	}
	// 可以正常读取数据
	n, err = conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := conn.(*ProtocolSwitchServerConn).ProtectedConn().(*tls.Conn); !ok {
		t.Fatalf("expect tls.Conn type but not")
	}
	if !bytes.Equal(buf[:n], send) {
		t.Fatalf("recv: %x, want: %x", buf[:n], send)
	}
	if conn != nil {
		_ = conn.Close()
	}
}

// 提早关闭连接测试
func TestAccept_early_close(t *testing.T) {
	var port = 9002
	var err error
	var conn net.Conn
	send := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	buf := make([]byte, 256)
	tlcpCfg := &tlcp.Config{
		Certificates: []tlcp.Certificate{sigCert, encCert},
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{rsaCert},
	}

	listen, err := Listen("tcp", fmt.Sprintf(":%d", port), tlcpCfg, tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()

	go func() {
		var cli net.Conn
		time.Sleep(time.Millisecond * 100)
		cli, _ = net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		time.Sleep(time.Millisecond * 800)
		// 打开连接后立即关闭，不发送数据
		_ = cli.Close()

		// 第二次发起正确的连接
		time.Sleep(time.Millisecond * 100)
		cli, _ = tlcp.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), &tlcp.Config{InsecureSkipVerify: true})
		time.Sleep(time.Millisecond * 800)
		_, err = cli.Write(send)
		if err != nil {
			t.Fatal(err)
		}
		if cli != nil {
			_ = cli.Close()
		}
	}()

	conn, err = listen.Accept()
	// 不应该出现错误
	if err != nil {
		t.Fatal(err)
	}
	// 尝试读取数据
	_, err = conn.Read(buf)
	if err != io.EOF {
		t.Fatalf("err: %v, want: %v", err, io.EOF)
	}
	_ = conn.Close()

	// 第二次发送正常数据
	conn, err = listen.Accept()
	// 不应该出现错误
	if err != nil {
		t.Fatal(err)
	}
	// 可以正常读取数据
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], send) {
		t.Fatalf("recv: %x, want: %x", buf[:n], send)
	}
	if conn != nil {
		_ = conn.Close()
	}
}

func TestWeb(t *testing.T) {
	var port = 9004

	tlcpCfg := &tlcp.Config{
		Certificates: []tlcp.Certificate{sigCert, encCert},
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{rsaCert},
	}

	listen, err := Listen("tcp", fmt.Sprintf(":%d", port), tlcpCfg, tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()
	serveMux := http.NewServeMux()
	serveMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("Hello"))
	})
	srv := &http.Server{Handler: serveMux}

	go func() {
		defer srv.Close()
		time.Sleep(time.Millisecond * 500)
		// 提前关闭连接
		cli, _ := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		_ = cli.Close()

		// 测试Web正常调用
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}

		client := &http.Client{Transport: tr}
		response, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/", port))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		bin, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		if string(bin) != "Hello" {
			t.Fatalf("recv: %s, want: %s", string(bin), "Hello")
		}
	}()

	err = srv.Serve(listen)
	if err != nil && err != http.ErrServerClosed {
		t.Fatal(err)
	}

}

// 启动TLCP服务端
func mockHelloServer(port int) error {
	var err error
	tlcpCfg := &tlcp.Config{
		Certificates: []tlcp.Certificate{sigCert, encCert},
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{rsaCert},
	}

	listen, err := Listen("tcp", fmt.Sprintf(":%d", port), tlcpCfg, tlsCfg)
	if err != nil {
		return err
	}
	defer listen.Close()
	buf := make([]byte, 1480)
	for {
		conn, err := listen.Accept()
		if err != nil {
			return err
		}
		n, err := conn.Read(buf)
		if err != nil {
			_ = conn.Close()
			return err
		}
		fmt.Printf("[PA   Server] >> %s\n", buf[:n])
		_, err = conn.Write([]byte("Hello from Protocol Adapter!"))
		if err != nil {
			_ = conn.Close()
			return err
		}
		time.Sleep(time.Millisecond * 300)
		_ = conn.Close()
	}
}
