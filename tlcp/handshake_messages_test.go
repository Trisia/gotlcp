package tlcp

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
)

var mockFF32 = []byte{
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
}
var mockOne32 = []byte{
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
}

func Test_clientHelloMsg_marshal_SNI(t *testing.T) {
	hello := &clientHelloMsg{
		vers:               VersionTLCP,
		compressionMethods: []uint8{compressionNone},
		sessionId:          []byte{},
		random:             mockFF32,
		cipherSuites:       []uint16{TLCP_ECC_SM4_CBC_SM3},
		serverName:         "example.com",
	}
	data, err := hello.marshal()
	if err != nil {
		t.Fatalf("marshal failed: %s", err)
	}

	hello2 := new(clientHelloMsg)
	if ok := hello2.unmarshal(data); !ok {
		t.Fatalf("unmarshal failed")
	}
	if hello2.serverName != hello.serverName {
		t.Fatalf("serverName not match")
	}
}

func Test_clientHelloMsg_marshal_TrustedAuthority(t *testing.T) {
	x509Name, _ := asn1.Marshal(&pkix.Name{
		Country:      []string{"CN"},
		Organization: []string{"example"},
		CommonName:   "TEST",
	})

	hello := &clientHelloMsg{
		vers:               VersionTLCP,
		compressionMethods: []uint8{compressionNone},
		sessionId:          []byte{},
		random:             mockFF32,
		cipherSuites:       []uint16{TLCP_ECC_SM4_CBC_SM3},
		trustedAuthorities: []TrustedAuthority{
			{IdentifierType: IdentifierTypePreAgreed},
			{IdentifierType: IdentifierTypeCertSM3Hash, Identifier: mockFF32},
			{IdentifierType: IdentifierTypeKeySM3Hash, Identifier: mockOne32},
			{IdentifierType: IdentifierTypeX509Name, Identifier: x509Name},
		},
	}
	data, err := hello.marshal()
	if err != nil {
		t.Fatalf("marshal failed: %s", err)
	}

	hello2 := new(clientHelloMsg)
	if ok := hello2.unmarshal(data); !ok {
		t.Fatalf("unmarshal failed")
	}
	if len(hello2.trustedAuthorities) != len(hello.trustedAuthorities) {
		t.Fatalf("trustedAuthorities length not match")
	}
	for i := range hello.trustedAuthorities {
		if hello2.trustedAuthorities[i].IdentifierType != hello.trustedAuthorities[i].IdentifierType {
			t.Fatalf("trustedAuthorities[%d].IdentifierType not match", i)
		}
		if len(hello2.trustedAuthorities[i].Identifier) != len(hello.trustedAuthorities[i].Identifier) {
			t.Fatalf("trustedAuthorities[%d].Identifier length not match", i)
		}
		if len(hello2.trustedAuthorities[i].Identifier) > 0 {
			if bytes.Compare(hello2.trustedAuthorities[i].Identifier, hello.trustedAuthorities[i].Identifier) != 0 {
				t.Fatalf("trustedAuthorities[%d].Identifier not match", i)
			}
		}
	}
}

func Test_clientHelloMsg_marshal_OCSPStapling(t *testing.T) {
	hello := &clientHelloMsg{
		vers:               VersionTLCP,
		compressionMethods: []uint8{compressionNone},
		sessionId:          []byte{},
		random:             mockFF32,
		cipherSuites:       []uint16{TLCP_ECC_SM4_CBC_SM3},
		ocspStapling:       true,
	}

	data, err := hello.marshal()
	if err != nil {
		t.Fatalf("marshal failed: %s", err)
	}

	hello2 := new(clientHelloMsg)
	if ok := hello2.unmarshal(data); !ok {
		t.Fatalf("unmarshal failed")
	}
	if hello2.ocspStapling != hello.ocspStapling {
		t.Fatalf("ocspStapling not match")
	}
}

func Test_clientHelloMsg_marshal_SupportedCurves(t *testing.T) {
	hello := &clientHelloMsg{
		vers:               VersionTLCP,
		compressionMethods: []uint8{compressionNone},
		sessionId:          []byte{},
		random:             mockFF32,
		cipherSuites:       []uint16{TLCP_ECC_SM4_CBC_SM3},
		supportedCurves:    []CurveID{CurveSM2},
	}

	data, err := hello.marshal()
	if err != nil {
		t.Fatalf("marshal failed: %s", err)
	}

	hello2 := new(clientHelloMsg)
	if ok := hello2.unmarshal(data); !ok {
		t.Fatalf("unmarshal failed")
	}
	if len(hello2.supportedCurves) != len(hello.supportedCurves) {
		t.Fatalf("supportedCurves length not match")
	}
	for i := range hello.supportedCurves {
		if hello2.supportedCurves[i] != hello.supportedCurves[i] {
			t.Fatalf("supportedCurves[%d] not match", i)
		}
	}
}

func Test_clientHelloMsg_marshal_SupportedSignatureAlgorithms(t *testing.T) {
	hello := &clientHelloMsg{
		vers:                         VersionTLCP,
		compressionMethods:           []uint8{compressionNone},
		sessionId:                    []byte{},
		random:                       mockFF32,
		cipherSuites:                 []uint16{TLCP_ECC_SM4_CBC_SM3},
		supportedSignatureAlgorithms: []SignatureScheme{SM2WithSM3},
	}

	data, err := hello.marshal()
	if err != nil {
		t.Fatalf("marshal failed: %s", err)
	}

	hello2 := new(clientHelloMsg)
	if ok := hello2.unmarshal(data); !ok {
		t.Fatalf("unmarshal failed")
	}

	if len(hello2.supportedSignatureAlgorithms) != len(hello.supportedSignatureAlgorithms) {
		t.Fatalf("supportedSignatureAlgorithms length not match")
	}
	for i := range hello.supportedSignatureAlgorithms {
		if hello2.supportedSignatureAlgorithms[i] != hello.supportedSignatureAlgorithms[i] {
			t.Fatalf("supportedSignatureAlgorithms[%d] not match", i)
		}
	}
}

func Test_clientHelloMsg_marshal_ALPNProtocols(t *testing.T) {
	hello := &clientHelloMsg{
		vers:               VersionTLCP,
		compressionMethods: []uint8{compressionNone},
		sessionId:          []byte{},
		random:             mockFF32,
		cipherSuites:       []uint16{TLCP_ECC_SM4_CBC_SM3},
		alpnProtocols:      []string{"h2", "http/1.1"},
	}

	data, err := hello.marshal()
	if err != nil {
		t.Fatalf("marshal failed: %s", err)
	}

	hello2 := new(clientHelloMsg)
	if ok := hello2.unmarshal(data); !ok {
		t.Fatalf("unmarshal failed")
	}

	if len(hello2.alpnProtocols) != len(hello.alpnProtocols) {
		t.Fatalf("alpnProtocols length not match")
	}
	for i := range hello.alpnProtocols {
		if hello2.alpnProtocols[i] != hello.alpnProtocols[i] {
			t.Fatalf("alpnProtocols[%d] not match", i)
		}
	}
}

func Test_serverHelloMsg_marshal_ClientID(t *testing.T) {
	hello := &clientHelloMsg{
		vers:               VersionTLCP,
		compressionMethods: []uint8{compressionNone},
		sessionId:          []byte{},
		random:             mockFF32,
		cipherSuites:       []uint16{TLCP_ECC_SM4_CBC_SM3},
		ibsdhClientID:      []byte{0x01, 0x02, 0x03, 0x04},
	}

	data, err := hello.marshal()
	if err != nil {
		t.Fatalf("marshal failed: %s", err)
	}

	hello2 := new(clientHelloMsg)
	if ok := hello2.unmarshal(data); !ok {
		t.Fatalf("unmarshal failed")
	}
	if bytes.Compare(hello2.ibsdhClientID, hello.ibsdhClientID) != 0 {
		t.Fatalf("ibsdhClientID not match")
	}
}

func TestServerHelloMsg_OCSPStapling(t *testing.T) {
	hello := &serverHelloMsg{
		vers:              VersionTLCP,
		compressionMethod: 0,
		sessionId:         []byte{},
		random:            mockFF32,
		cipherSuite:       TLCP_ECC_SM4_CBC_SM3,
		ocspStapling:      true,
		ocspResponse:      mockOne32,
	}

	data, err := hello.marshal()
	if err != nil {
		t.Fatalf("marshal failed: %s", err)
	}

	hello2 := new(serverHelloMsg)
	if ok := hello2.unmarshal(data); !ok {
		t.Fatalf("unmarshal failed")
	}
	if hello2.ocspStapling != hello.ocspStapling {
		t.Fatalf("ocspStapling not match")
	}
	if bytes.Compare(hello2.ocspResponse, hello.ocspResponse) != 0 {
		t.Fatalf("ocspResponse not match")
	}
}

func TestServerHelloMsg_ALPN(t *testing.T) {
	hello := &serverHelloMsg{
		vers:              VersionTLCP,
		compressionMethod: 0,
		sessionId:         []byte{},
		random:            mockFF32,
		cipherSuite:       TLCP_ECC_SM4_CBC_SM3,
		alpnProtocol:      "h2",
	}

	data, err := hello.marshal()
	if err != nil {
		t.Fatalf("marshal failed: %s", err)
	}

	hello2 := new(serverHelloMsg)
	if ok := hello2.unmarshal(data); !ok {
		t.Fatalf("unmarshal failed")
	}
	if hello2.alpnProtocol != hello.alpnProtocol {
		t.Fatalf("alpnProtocol not match")
	}

}

func TestServerHelloMsg_ServerNameAck(t *testing.T) {
	hello := &serverHelloMsg{
		vers:              VersionTLCP,
		compressionMethod: 0,
		sessionId:         []byte{},
		random:            mockFF32,
		cipherSuite:       TLCP_ECC_SM4_CBC_SM3,
		serverNameAck:     true,
	}

	data, err := hello.marshal()
	if err != nil {
		t.Fatalf("marshal failed: %s", err)
	}

	hello2 := new(serverHelloMsg)
	if ok := hello2.unmarshal(data); !ok {
		t.Fatalf("unmarshal failed")
	}
	if hello2.serverNameAck != hello.serverNameAck {
		t.Fatalf("serverNameAck not match")
	}
}
