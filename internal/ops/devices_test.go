package ops

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestVerifierCombinesMechanismsWithOR(t *testing.T) {
	nodeKey := key.NewNode().Public()
	verifier := &verifier{
		cfg: VerifyConfig{Enabled: true, TailscaledEnabled: false, APIEnabled: true},
		store: &deviceStore{
			cache: map[string]deviceCache{
				"primary": {
					devices:     map[string]Device{nodeKey.String(): {NodeKey: nodeKey.String(), Authorized: true}},
					lastSuccess: time.Now(),
				},
			},
			ttl: time.Minute,
		},
	}
	if !verifier.verify(context.Background(), tailcfg.DERPAdmitClientRequest{NodePublic: nodeKey}, "") {
		t.Fatal("expected Official API mechanism to allow the client")
	}
}

func TestNewVerifierUsesConfiguredTailscaledSocketOnlyWhenEnabled(t *testing.T) {
	const socket = "/tmp/custom-tailscaled.sock"

	defaultVerifier := newVerifier(VerifyConfig{TailscaledSocket: socket}, nil)
	if defaultVerifier.local.Socket != "" {
		t.Fatalf("expected default socket when custom socket is disabled, got %q", defaultVerifier.local.Socket)
	}

	customVerifier := newVerifier(VerifyConfig{
		TailscaledSocketEnabled: true,
		TailscaledSocket:        socket,
	}, nil)
	if customVerifier.local.Socket != socket {
		t.Fatalf("expected custom socket %q, got %q", socket, customVerifier.local.Socket)
	}
}

func TestDeviceStoreRefreshFiltersAndAuthorizesDevices(t *testing.T) {
	secret := "tskey-api-secret"
	nodeKey := key.NewNode().Public()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != secret || password != "" {
			t.Fatalf("unexpected basic authentication: username=%q password=%q present=%v", username, password, ok)
		}
		if r.URL.Query().Get("fields") != "default" {
			t.Fatalf("expected fields=default, got %q", r.URL.Query().Get("fields"))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"devices": []map[string]any{
			{"nodeId": "node-1", "nodeKey": nodeKey.String(), "name": "allowed", "authorized": true},
			{"nodeId": "node-2", "nodeKey": key.NewNode().Public().String(), "name": "unauthorized", "authorized": false},
		}})
	}))
	defer api.Close()

	store := newDeviceStore(VerifyConfig{APIs: []APIConfig{{Name: "primary", Label: "Primary", Tailnet: "-", APIKey: secret}}})
	store.setHTTPClientForTest(api.Client(), api.URL)
	if err := store.refresh(context.Background()); err != nil {
		t.Fatalf("refresh failed: %v", err)
	}
	if !store.allowed(nodeKey, time.Now()) {
		t.Fatal("expected authorized device to be allowed")
	}
	response := store.snapshot()
	if len(response.Devices) != 2 {
		t.Fatalf("expected both devices in display response, got %d", len(response.Devices))
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("marshal device response: %v", err)
	}
	if strings.Contains(string(encoded), secret) {
		t.Fatal("API key leaked in device response")
	}
}

func TestDeviceStoreRefreshUsesOAuthClientCredentials(t *testing.T) {
	const clientID = "client-id"
	const clientSecret = "client-secret"
	const accessToken = "access-token"
	nodeKey := key.NewNode().Public()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/oauth/token":
			username, password, ok := r.BasicAuth()
			if !ok {
				username = r.FormValue("client_id")
				password = r.FormValue("client_secret")
			}
			if username != clientID || password != clientSecret {
				t.Fatalf("unexpected OAuth client authentication: username=%q password=%q present=%v", username, password, ok)
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(map[string]any{"access_token": accessToken, "token_type": "Bearer", "expires_in": 3600}); err != nil {
				t.Fatalf("write OAuth response: %v", err)
			}
		case "/api/v2/tailnet/-/devices":
			if authorization := r.Header.Get("Authorization"); authorization != "Bearer "+accessToken {
				t.Fatalf("unexpected OAuth access authentication: %q", authorization)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"devices": []map[string]any{
				{"nodeId": "node-1", "nodeKey": nodeKey.String(), "name": "allowed", "authorized": true},
			}})
		default:
			t.Fatalf("unexpected API path: %s", r.URL.Path)
		}
	}))
	defer api.Close()

	store := newDeviceStore(VerifyConfig{APIs: []APIConfig{{
		Name:              "primary",
		Tailnet:           "-",
		AuthType:          APIAuthTypeOAuth,
		OAuthClientID:     clientID,
		OAuthClientSecret: clientSecret,
	}}})
	store.setHTTPClientForTest(api.Client(), api.URL)
	if err := store.refresh(context.Background()); err != nil {
		t.Fatalf("refresh failed: %v", err)
	}
	if !store.allowed(nodeKey, time.Now()) {
		t.Fatal("expected OAuth-authorized device to be allowed")
	}
	encoded, err := json.Marshal(store.snapshot())
	if err != nil {
		t.Fatalf("marshal device response: %v", err)
	}
	for _, credential := range []string{clientID, clientSecret, accessToken} {
		if strings.Contains(string(encoded), credential) {
			t.Fatalf("credential leaked in device response: %q", credential)
		}
	}
}

func TestDeviceStoreExpiredCacheDoesNotAuthorize(t *testing.T) {
	nodeKey := key.NewNode().Public()
	store := &deviceStore{
		cache: map[string]deviceCache{
			"primary": {
				devices:     map[string]Device{nodeKey.String(): {NodeKey: nodeKey.String(), Authorized: true}},
				lastSuccess: time.Now().Add(-time.Hour),
			},
		},
		ttl: time.Minute,
	}
	if store.allowed(nodeKey, time.Now()) {
		t.Fatal("expired cache must not authorize a client")
	}
}

func TestDeviceStoreUnionAndSources(t *testing.T) {
	nodeKey := key.NewNode().Public().String()
	now := time.Now()
	store := &deviceStore{
		configs: []APIConfig{
			{Name: "one", Label: "One", Tailnet: "-"},
			{Name: "two", Label: "Two", Tailnet: "T123"},
		},
		cache: map[string]deviceCache{
			"one": {devices: map[string]Device{nodeKey: {NodeID: "node-one", NodeKey: nodeKey, Name: "device", Sources: []string{"One"}, Origins: []DeviceOrigin{{Instance: "one", NodeID: "node-one"}}}}, lastSuccess: now},
			"two": {devices: map[string]Device{nodeKey: {NodeID: "node-two", NodeKey: nodeKey, Name: "device", Sources: []string{"Two"}, Origins: []DeviceOrigin{{Instance: "two", NodeID: "node-two"}}}}, lastSuccess: now},
		},
		ttl: time.Minute,
	}
	response := store.snapshot()
	if len(response.Devices) != 1 {
		t.Fatalf("expected one merged device, got %d", len(response.Devices))
	}
	if len(response.Devices[0].Sources) != 2 {
		t.Fatalf("expected two sources, got %v", response.Devices[0].Sources)
	}
	if len(response.Devices[0].Origins) != 2 {
		t.Fatalf("expected two origins, got %v", response.Devices[0].Origins)
	}
}
