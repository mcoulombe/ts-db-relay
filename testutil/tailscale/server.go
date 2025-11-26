package tailscale

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"tailscale.com/ipn/store/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/types/key"
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
	t.Cleanup(func() { s.Close() })

	status, err := s.Up(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return s, status.TailscaleIPs[0], status.Self.PublicKey
}

func AssertCanPingNode(t *testing.T, ctx context.Context, clientTsnet *tsnet.Server, peerIP netip.Addr) {
	t.Helper()

	lc, err := clientTsnet.LocalClient()
	if err != nil {
		t.Fatalf("failed to get local client: %v", err)
	}

	// client can see the peer (tailscale status)
	status, err := lc.Status(ctx)
	if err != nil {
		t.Fatalf("failed to get client status: %v", err)
	}
	t.Logf("client status: %d peers", len(status.Peer))
	for ip, peer := range status.Peer {
		t.Logf("  Peer: %s -> %s", ip, peer.HostName)
	}

	// client can ping the peer (tailscale ping)
	if _, err := lc.Ping(ctx, peerIP, tailcfg.PingTSMP); err != nil {
		t.Fatalf("failed to ping peer: %v", err)
	}

	t.Log("Ping check successful: client able to ping connector via tailnet")
}

func AssertCanDialNode(t *testing.T, ctx context.Context, clientTsnet *tsnet.Server, connectorIP netip.Addr, pgPort int) {
	t.Helper()

	testConn, err := clientTsnet.Dial(ctx, "tcp", fmt.Sprintf("%s:%d", connectorIP.String(), pgPort))
	if err != nil {
		t.Fatalf("Failed to dial via tsnet: %v", err)
	}
	testConn.Close()

	t.Logf("Direct dial check successful: client able to directly connect to connector's relay port via tailnet")
}
