package tailscale

import (
	"net/http/httptest"
	"testing"

	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

func StartControl(t *testing.T) (controlURL string, control *testcontrol.Server) {
	t.Helper()

	// Corp#4520: don't use netns for tests.
	netns.SetEnabled(false)
	t.Cleanup(func() {
		netns.SetEnabled(true)
	})

	derpLogf := logger.Discard
	derpMap := integration.RunDERPAndSTUN(t, derpLogf, "127.0.0.1")
	control = &testcontrol.Server{
		DERPMap: derpMap,
		DNSConfig: &tailcfg.DNSConfig{
			Proxied: true,
		},
		MagicDNSDomain: "tail-scale.ts.net",
		Logf:           t.Logf,
	}
	control.HTTPTestServer = httptest.NewUnstartedServer(control)
	control.HTTPTestServer.Start()
	t.Cleanup(control.HTTPTestServer.Close)
	controlURL = control.HTTPTestServer.URL
	t.Logf("testcontrol listening on %s", controlURL)
	return controlURL, control
}

func MustInjectFilterRules(t *testing.T, control *testcontrol.Server, nodeKey key.NodePublic, peerNodeKey key.NodePublic, filterRules ...tailcfg.FilterRule) {
	t.Helper()

	node := control.Node(nodeKey)
	if node == nil {
		t.Fatalf("no node found for %s", nodeKey)
	}

	peer := control.Node(peerNodeKey)
	if peer == nil {
		t.Fatalf("no node found for %s", peerNodeKey)
	}

	mapResponse := &tailcfg.MapResponse{
		Node:         node,
		Peers:        []*tailcfg.Node{peer},
		KeepAlive:    false,
		PacketFilter: filterRules,
	}

	if !control.AddRawMapResponse(nodeKey, mapResponse) {
		t.Fatalf("failed to inject raw MapResponse for node with key %s", nodeKey)
	}
}
