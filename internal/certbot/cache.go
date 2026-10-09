package certbot

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func DERChainToSingleBuffer(derChain [][]byte) ([]byte, error) {
	var buf bytes.Buffer
	for _, der := range derChain {
		if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
			// pem.Encode never returns a non-nil error, but keep this for completeness.
			return buf.Bytes(), fmt.Errorf("pem encode: %w", err)
		}
	}
	return buf.Bytes(), nil
}

// CertificateKeyPEM encodes a certificate's RSA private key for a .key.pem file.
// The ACME account.key cache entry intentionally remains DER for compatibility.
func CertificateKeyPEM(key *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

// CertificateRequestPEM encodes a DER CSR for a .csr.pem file.
func CertificateRequestPEM(csr []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})
}

func SingleBufferToDERChain(buf []byte) ([][]byte, error) {
	var out [][]byte
	for {
		var block *pem.Block
		block, buf = pem.Decode(buf)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			// ignore other blocks or return an error if you prefer
			continue
		}
		out = append(out, block.Bytes)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}
	return out, nil
}
