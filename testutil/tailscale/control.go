package tailscale

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"

	"github.com/tailscale/ts-db-connector/pkg"
	"tailscale.com/client/tailscale/v2"
	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

func FakeControlStart(t *testing.T) (controlURL string, control *testcontrol.Server) {
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

func FakeControlGrantAppCap(t *testing.T, appCaps map[string]any, clientIP netip.Addr, clientNodeKey key.NodePublic, connectorIP netip.Addr, connectorNodeKey key.NodePublic, control *testcontrol.Server) {
	t.Helper()

	rawAppCaps, err := json.Marshal(appCaps)
	if err != nil {
		t.Fatal(err)
	}
	filterRules := FormatFilterRules(t, clientIP, connectorIP, rawAppCaps)
	MustInjectFilterRules(t, control, connectorNodeKey, clientNodeKey, filterRules...)
	MustInjectFilterRules(t, control, clientNodeKey, connectorNodeKey)
}

func FormatFilterRules(t *testing.T, clientIP netip.Addr, connectorIP netip.Addr, connectorAppCap []byte) []tailcfg.FilterRule {
	t.Helper()

	return []tailcfg.FilterRule{
		{
			SrcIPs: []string{clientIP.String()},
			DstPorts: []tailcfg.NetPortRange{
				{
					IP:    fmt.Sprintf("%s/32", connectorIP),
					Ports: tailcfg.PortRange{First: 0, Last: 65535},
				},
			},
		},
		{
			SrcIPs: []string{clientIP.String()},
			CapGrant: []tailcfg.CapGrant{{
				Dsts: []netip.Prefix{
					netip.MustParsePrefix(fmt.Sprintf("%s/32", connectorIP)),
				},
				CapMap: tailcfg.PeerCapMap{
					pkg.TSDBCap: []tailcfg.RawMessage{
						tailcfg.RawMessage(connectorAppCap),
					},
				},
			}},
		},
	}
}

func ControlGrantAppCap(t *testing.T, appCaps map[string]any, controlURL string, apiKey string) {
	t.Helper()

	url, err := url.Parse(controlURL)
	if err != nil {
		t.Fatal(err)
	}
	client := &tailscale.Client{
		BaseURL: url,
		APIKey:  apiKey,
	}

	acl := tailscale.ACL{
		Grants: []tailscale.Grant{
			{
				Source:      []string{"*"},
				Destination: []string{"*"},
				IP:          []string{"tcp:*"},
				App: map[string][]map[string]any{
					pkg.TSDBCap: {appCaps},
				},
			},
		},
	}
	t.Logf("Overwriting ACL with: %s", acl)
	res, err := client.PolicyFile().SetAndGet(context.Background(), acl, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("API response: %s", res)
}
