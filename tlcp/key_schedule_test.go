package tlcp

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/emmansun/gmsm/ecdh"
)

func Test_sm2ke_GenerateAgreementData(t *testing.T) {
	sponsorPri, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	responsePri, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	sponsorKE := newSM2KeyKE(rand.Reader, sponsorPri)
	responseKE := newSM2KeyKE(rand.Reader, responsePri)

	sponsorPubKey, sponsorTmpPubKey, err := sponsorKE.GenerateAgreementData(nil, 48)
	if err != nil {
		t.Fatal(err)
	}

	responseTmpPubKey, preMasterSecretClient, err := responseKE.GenerateAgreementDataAndKey(nil, nil, sponsorPubKey, sponsorTmpPubKey, 48)
	if err != nil {
		t.Fatal(err)
	}

	preMasterSecretServer, err := sponsorKE.GenerateKey(nil, responsePri.PublicKey(), responseTmpPubKey)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(preMasterSecretClient, preMasterSecretServer) {
		t.Fatalf("Session key should same but not,\n"+
			"Client key: %02X\n"+
			"Server key: %02X\n", preMasterSecretClient, preMasterSecretServer)
	}
	fmt.Printf("Session Key: %02X\n", preMasterSecretClient)
}
