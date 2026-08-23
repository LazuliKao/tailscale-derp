package ops

import (
	"bytes"
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

func TestHandleVerifyUsesStandardDERPJSONAndURL(t *testing.T) {
	var receivedKey string
	admission := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedKey = r.URL.Query().Get("key")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer admission.Close()

	nodeKey := key.NewNode().Public()
	verifier := newVerifier(VerifyConfig{
		Enabled:     true,
		URLsEnabled: true,
		URLs:        []string{admission.URL + "/verify"},
	}, nil)
	requestBody, err := json.Marshal(tailcfg.DERPAdmitClientRequest{NodePublic: nodeKey})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/verify", bytes.NewReader(requestBody))
	resp := httptest.NewRecorder()
	handleVerify(verifier)(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}
	var result tailcfg.DERPAdmitClientResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !result.Allow {
		t.Fatal("expected URL admission to allow the client")
	}
	if receivedKey != nodeKey.String() {
		t.Fatalf("expected query key %q, got %q", nodeKey, receivedKey)
	}
}

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

func TestDeviceStoreRefreshFiltersAndAuthorizesDevices(t *testing.T) {
	secret := "tskey-api-secret"
	nodeKey := key.NewNode().Public()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+secret {
			t.Fatalf("unexpected authorization header: %q", r.Header.Get("Authorization"))
		}
		if r.URL.Query().Get("fields") != "default" {
			t.Fatalf("expected fields=default, got %q", r.URL.Query().Get("fields"))
		}
		_ = json.NewEncoder(w).Encode(apiDevicesResponse{Devices: []apiDevice{
			{NodeID: "node-1", NodeKey: nodeKey.String(), Name: "allowed", Authorized: true},
			{NodeID: "node-2", NodeKey: key.NewNode().Public().String(), Name: "unauthorized", Authorized: false},
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
			"one": {devices: map[string]Device{nodeKey: {NodeKey: nodeKey, Name: "device", Sources: []string{"One"}}}, lastSuccess: now},
			"two": {devices: map[string]Device{nodeKey: {NodeKey: nodeKey, Name: "device", Sources: []string{"Two"}}}, lastSuccess: now},
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
}
