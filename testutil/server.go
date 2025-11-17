package testutil

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tsnet"
	"tailscale.com/types/key"
	"testing"
	"time"
	"unsafe"
)

func StartTsnetServer(t *testing.T, ctx context.Context, controlURL, hostname string) (*tsnet.Server, netip.Addr, key.NodePublic) {
	t.Helper()

	tmp := filepath.Join(t.TempDir(), hostname)
	os.MkdirAll(tmp, 0755)
	s := &tsnet.Server{
		Dir:        tmp,
		ControlURL: controlURL,
		Hostname:   hostname,
		Store:      new(mem.Store),
		Ephemeral:  true,
	}
	setTsNetServerGetCertForTesting(s, testCertRoot.getCert)
	t.Cleanup(func() { s.Close() })

	status, err := s.Up(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return s, status.TailscaleIPs[0], status.Self.PublicKey
}

func setTsNetServerGetCertForTesting(s *tsnet.Server, f func(*tls.ClientHelloInfo) (*tls.Certificate, error)) {
	v := reflect.ValueOf(s).Elem()
	field := v.FieldByName("getCertForTesting")
	field = reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem()
	field.Set(reflect.ValueOf(f))
}

type testCertIssuer struct {
	mu    sync.Mutex
	certs map[string]*tls.Certificate

	root    *x509.Certificate
	rootKey *ecdsa.PrivateKey
}

func newCertIssuer() *testCertIssuer {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	t := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "root",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, t, t, &rootKey.PublicKey, rootKey)
	if err != nil {
		panic(err)
	}
	rootCA, err := x509.ParseCertificate(rootDER)
	if err != nil {
		panic(err)
	}
	return &testCertIssuer{
		certs:   make(map[string]*tls.Certificate),
		root:    rootCA,
		rootKey: rootKey,
	}
}

func (tci *testCertIssuer) getCert(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	tci.mu.Lock()
	defer tci.mu.Unlock()
	cert, ok := tci.certs[chi.ServerName]
	if ok {
		return cert, nil
	}

	certPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	certTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{chi.ServerName},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, certTmpl, tci.root, &certPrivKey.PublicKey, tci.rootKey)
	if err != nil {
		return nil, err
	}
	cert = &tls.Certificate{
		Certificate: [][]byte{certDER, tci.root.Raw},
		PrivateKey:  certPrivKey,
	}
	tci.certs[chi.ServerName] = cert
	return cert, nil
}

var testCertRoot = newCertIssuer()
