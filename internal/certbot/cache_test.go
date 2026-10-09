package certbot

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
)

func TestCertificatePEMFiles(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := CertificateKeyPEM(key)
	keyBlock, rest := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "RSA PRIVATE KEY" || len(rest) != 0 {
		t.Fatalf("key is not a single RSA PRIVATE KEY PEM block: %q", keyPEM)
	}
	parsedKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil || parsedKey.N.Cmp(key.N) != 0 {
		t.Fatalf("PEM key does not match original: %v", err)
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "example.org"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := CertificateRequestPEM(csrDER)
	csrBlock, rest := pem.Decode(csrPEM)
	if csrBlock == nil || csrBlock.Type != "CERTIFICATE REQUEST" || len(rest) != 0 {
		t.Fatalf("CSR is not a single CERTIFICATE REQUEST PEM block: %q", csrPEM)
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != "example.org" || csr.CheckSignature() != nil {
		t.Fatalf("invalid PEM CSR: %v", csr)
	}
}
