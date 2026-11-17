package hcore

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/hiddify/hiddify-core/v2/hutils"
)

func TestServerCertificateIsNeutral(t *testing.T) {
	pair, err := hutils.GenerateCertificatePair()
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pair.Certificate)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(pair.Certificate)+cert.Subject.String()), "hiddify") || len(cert.Subject.Organization) != 0 {
		t.Fatalf("subject %q", cert.Subject)
	}
	if cert.PublicKeyAlgorithm != x509.ECDSA {
		t.Fatalf("key %v", cert.PublicKeyAlgorithm)
	}
	if !hutils.CertificateHasLoopbackSAN(pair.Certificate) || !hutils.CertificateIsNeutral(pair.Certificate) {
		t.Fatal("the new certificate is not taken")
	}
	if err := cert.VerifyHostname("127.0.0.1"); err != nil {
		t.Fatal(err)
	}
}
