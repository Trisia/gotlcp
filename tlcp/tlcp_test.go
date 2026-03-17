package tlcp

import (
	"strings"
	"testing"
)

var ecdsaCertPEM = `-----BEGIN CERTIFICATE-----
MIIB/jCCAWICCQDscdUxw16XFDAJBgcqhkjOPQQBMEUxCzAJBgNVBAYTAkFVMRMw
EQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0
eSBMdGQwHhcNMTIxMTE0MTI0MDQ4WhcNMTUxMTE0MTI0MDQ4WjBFMQswCQYDVQQG
EwJBVTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lk
Z2l0cyBQdHkgTHRkMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBY9+my9OoeSUR
lDQdV/x8LsOuLilthhiS1Tz4aGDHIPwC1mlvnf7fg5lecYpMCrLLhauAc1UJXcgl
01xoLuzgtAEAgv2P/jgytzRSpUYvgLBt1UA0leLYBy6mQQbrNEuqT3INapKIcUv8
XxYP0xMEUksLPq6Ca+CRSqTtrd/23uTnapkwCQYHKoZIzj0EAQOBigAwgYYCQXJo
A7Sl2nLVf+4Iu/tAX/IF4MavARKC4PPHK3zfuGfPR3oCCcsAoz3kAzOeijvd0iXb
H5jBImIxPL4WxQNiBTexAkF8D1EtpYuWdlVQ80/h/f4pBcGiXPqX5h2PQSQY7hP1
+jwM1FGS4fREIOvlBYr/SzzQRtwrvrzGYxDEDbsC0ZGRnA==
-----END CERTIFICATE-----
`

var ecdsaKeyPEM = testingKey(`-----BEGIN EC PARAMETERS-----
BgUrgQQAIw==
-----END EC PARAMETERS-----
-----BEGIN EC TESTING KEY-----
MIHcAgEBBEIBrsoKp0oqcv6/JovJJDoDVSGWdirrkgCWxrprGlzB9o0X8fV675X0
NwuBenXFfeZvVcwluO7/Q9wkYoPd/t3jGImgBwYFK4EEACOhgYkDgYYABAFj36bL
06h5JRGUNB1X/Hwuw64uKW2GGJLVPPhoYMcg/ALWaW+d/t+DmV5xikwKssuFq4Bz
VQldyCXTXGgu7OC0AQCC/Y/+ODK3NFKlRi+AsG3VQDSV4tgHLqZBBus0S6pPcg1q
kohxS/xfFg/TEwRSSws+roJr4JFKpO2t3/be5OdqmQ==
-----END EC TESTING KEY-----
`)

var sm2CertPEM = `-----BEGIN CERTIFICATE-----
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
var sm2KeyPEM = testingKey(`-----BEGIN TESTING KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgwWUmv7RlOnXHeURD
KCUGPR08E+cs/2wX1N1DeZkf7NCgCgYIKoEcz1UBgi2hRANCAASQO0zDql3Y/0Kn
zTA2tMMy+/ZbYrB7rMTen4gvDu5IXckBoZiuNPfSN7mSEHe88suzkirZe5H1MQuG
matZXJTu
-----END TESTING KEY-----
`)

var sm2KeyPEM2 = testingKey(`-----BEGIN ECC TESTING KEY-----
MHcCAQEEIMFlJr+0ZTp1x3lEQyglBj0dPBPnLP9sF9TdQ3mZH+zQoAoGCCqBHM9V
AYItoUQDQgAEkDtMw6pd2P9Cp80wNrTDMvv2W2Kwe6zE3p+ILw7uSF3JAaGYrjT3
0je5khB3vPLLs5Iq2XuR9TELhpmrWVyU7g==
-----END ECC TESTING KEY-----
`)

var keyPairTests = []struct {
	algo string
	cert string
	key  string
}{
	{"PKCS8", sm2CertPEM, sm2KeyPEM},
	{"ECC", sm2CertPEM, sm2KeyPEM2},
}

func TestX509KeyPair(t *testing.T) {
	t.Parallel()
	var pem []byte
	for _, test := range keyPairTests {
		pem = []byte(test.cert + test.key)
		if _, err := X509KeyPair(pem, pem); err != nil {
			t.Errorf("Failed to load %s cert followed by %s key: %s", test.algo, test.algo, err)
		}
		pem = []byte(test.key + test.cert)
		if _, err := X509KeyPair(pem, pem); err != nil {
			t.Errorf("Failed to load %s key followed by %s cert: %s", test.algo, test.algo, err)
		}
	}
}

func TestX509KeyPairErrors(t *testing.T) {
	_, err := X509KeyPair([]byte(sm2KeyPEM), []byte(sm2CertPEM))
	if err == nil {
		t.Fatalf("X509KeyPair didn't return an error when arguments were switched")
	}
	if subStr := "been switched"; !strings.Contains(err.Error(), subStr) {
		t.Fatalf("Expected %q in the error when switching arguments to X509KeyPair, but the error was %q", subStr, err)
	}

	_, err = X509KeyPair([]byte(sm2CertPEM), []byte(sm2CertPEM))
	if err == nil {
		t.Fatalf("X509KeyPair didn't return an error when both arguments were certificates")
	}
	if subStr := "certificate"; !strings.Contains(err.Error(), subStr) {
		t.Fatalf("Expected %q in the error when both arguments to X509KeyPair were certificates, but the error was %q", subStr, err)
	}

	_, err = X509KeyPair([]byte(ecdsaCertPEM), []byte(ecdsaKeyPEM))
	if err == nil {
		t.Fatalf("X509KeyPair didn't return an error when arguments were switched")
	}
	if err.Error() != "tlcp: non-SM2 curve in EC private key" {
		t.Fatalf("Expected \"tlcp: non-SM2 curve in EC private key\" in the error when the key is non-SM2, but the error was %q", err)
	}

	const nonsensePEM = `
-----BEGIN NONSENSE-----
Zm9vZm9vZm9v
-----END NONSENSE-----
`

	_, err = X509KeyPair([]byte(nonsensePEM), []byte(nonsensePEM))
	if err == nil {
		t.Fatalf("X509KeyPair didn't return an error when both arguments were nonsense")
	}
	if subStr := "NONSENSE"; !strings.Contains(err.Error(), subStr) {
		t.Fatalf("Expected %q in the error when both arguments to X509KeyPair were nonsense, but the error was %q", subStr, err)
	}
}

func testingKey(s string) string { return strings.ReplaceAll(s, "TESTING KEY", "PRIVATE KEY") }
