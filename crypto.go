package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"time"
)

func mkSelfSigned(hostname string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	pub := priv.Public()
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"pgproxy"},
		},
		DNSNames:              []string{hostname},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
		Leaf:        cert,
	}, nil
}

// md5Response computes the md5 response string for Postgres md5 auth:
// result = "md5" + hex(md5( hex(md5(password+role)) + salt ))
func md5Response(password, role string, salt [4]byte) string {
	h1 := md5.Sum([]byte(password + role))
	h1hex := hex.EncodeToString(h1[:])
	h2inp := append([]byte(h1hex), salt[:]...)
	h2 := md5.Sum(h2inp)
	return "md5" + hex.EncodeToString(h2[:])
}
