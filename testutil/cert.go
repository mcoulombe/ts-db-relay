package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func CreateClientCertificate(t *testing.T, certDir string, caKey *ecdsa.PrivateKey, caCert *x509.Certificate, username string) {
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3 + int64(len(username))),
		Subject: pkix.Name{
			CommonName: username,
		},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	key, DER := createCertificate(t, clientTemplate, caCert, caKey)
	WriteCertificate(t, certDir, fmt.Sprintf("client.%s", username), key, DER)
}

func CreateServerCertificate(t *testing.T, dir string, filename string, caKey *ecdsa.PrivateKey, caCert *x509.Certificate, commonName string, dnsNames ...string) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "node",
		},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              append(dnsNames, "localhost", "cockroachdb"),
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	key, certDER := createCertificate(t, template, caCert, caKey)

	WriteCertificate(t, dir, filename, key, certDER)
}

func createCertificate(t *testing.T, template *x509.Certificate, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) (*ecdsa.PrivateKey, []byte) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	return key, certDER
}

func CreateCACertificate(t *testing.T, certDir string, filename string, commonName string, organisations ...string) (*ecdsa.PrivateKey, *x509.Certificate, string) {
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: organisations,
		},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	certFile := WriteCertificate(t, certDir, filename, key, certDER)

	return key, cert, certFile
}

func WriteCertificate(t *testing.T, certDir string, filename string, key *ecdsa.PrivateKey, certDER []byte) string {
	certFile := filepath.Join(certDir, fmt.Sprintf("%s.crt", filename))
	keyFile := filepath.Join(certDir, fmt.Sprintf("%s.key", filename))

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		t.Fatalf("failed to write certificate: %v", err)
	}

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}

	return certFile
}
