package ops

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"tailscale.com/types/key"
)

func TestDeviceManagementMutationsUpdateAPIAndCache(t *testing.T) {
	secret := "tskey-api-secret"
	nodeKey := key.NewNode().Public().String()
	requests := map[string]any{
		"/api/v2/device/node-1/authorized": map[string]any{"authorized": true},
		"/api/v2/device/node-1/name":       map[string]any{"name": "Office router"},
		"/api/v2/device/node-1/tags":       map[string]any{"tags": []any{"tag:router"}},
		"/api/v2/device/node-1/key":        map[string]any{"keyExpiryDisabled": true},
	}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != secret || password != "" {
			t.Fatalf("unexpected basic authentication: username=%q password=%q present=%v", username, password, ok)
		}
		if expected, ok := requests[r.URL.Path]; ok {
			if r.Method != http.MethodPost {
				t.Fatalf("expected POST for %s, got %s", r.URL.Path, r.Method)
			}
			var body any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode %s request: %v", r.URL.Path, err)
			}
			if !reflect.DeepEqual(body, expected) {
				t.Fatalf("unexpected %s request: %#v", r.URL.Path, body)
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/api/v2/device/node-1/expire" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method == http.MethodDelete && r.URL.Path == "/api/v2/device/node-1" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL)
	}))
	defer api.Close()

	store := newManagementTestStore(api, secret, nodeKey)
	callDeviceAction(t, handleSetDeviceAuthorized(store), http.MethodPut, `{"authorized":true}`)
	callDeviceAction(t, handleSetDeviceName(store), http.MethodPut, `{"name":"Office router"}`)
	callDeviceAction(t, handleSetDeviceTags(store), http.MethodPut, `{"tags":["tag:router"]}`)
	callDeviceAction(t, handleSetDeviceKey(store), http.MethodPut, `{"keyExpiryDisabled":true}`)
	callDeviceAction(t, handleExpireDevice(store), http.MethodPost, "")

	device := store.cache["primary"].devices[nodeKey]
	if !device.Authorized || device.Name != "Office router" || !device.KeyExpiryDisabled || !reflect.DeepEqual(device.Tags, []string{"tag:router"}) {
		t.Fatalf("unexpected cached device: %#v", device)
	}
	if device.Expires == "" || !deviceExpired(device.Expires, time.Now().Add(time.Second)) {
		t.Fatalf("expected cached expired device, got %q", device.Expires)
	}

	callDeviceAction(t, handleDeleteDevice(store), http.MethodDelete, "")
	if _, ok := store.cache["primary"].devices[nodeKey]; ok {
		t.Fatal("deleted device remained in cache")
	}
}

func TestDeviceRoutesAndAttributesHandlers(t *testing.T) {
	secret := "tskey-api-secret"
	nodeKey := key.NewNode().Public().String()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, _, ok := r.BasicAuth()
		if !ok || username != secret {
			t.Fatalf("unexpected authentication")
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /api/v2/device/node-1/routes":
			_, _ = w.Write([]byte(`{"advertisedRoutes":["10.0.0.0/24"],"enabledRoutes":["10.0.0.0/24"]}`))
		case "POST /api/v2/device/node-1/routes":
			assertJSONBody(t, r, map[string]any{"routes": []any{"10.0.0.0/24"}})
			w.WriteHeader(http.StatusNoContent)
		case "GET /api/v2/device/node-1/attributes":
			_, _ = w.Write([]byte(`{"attributes":{"com.example.checked":true},"expiries":{"com.example.checked":"2026-01-02T03:04:05Z"}}`))
		case "POST /api/v2/device/node-1/attributes/com.example.checked":
			assertJSONBody(t, r, map[string]any{"value": map[string]any{"build": "123"}, "expiry": "2026-01-02T03:04:05Z", "comment": "managed"})
			w.WriteHeader(http.StatusNoContent)
		case "DELETE /api/v2/device/node-1/attributes/com.example.checked":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL)
		}
	}))
	defer api.Close()

	store := newManagementTestStore(api, secret, nodeKey)
	routesHandler := handleDeviceRoutes(store)
	routesResponse := callDeviceHandler(routesHandler, http.MethodGet, "")
	if routesResponse.Code != http.StatusOK || !bytes.Contains(routesResponse.Body.Bytes(), []byte("10.0.0.0/24")) {
		t.Fatalf("unexpected routes response: %d %s", routesResponse.Code, routesResponse.Body.String())
	}
	if response := callDeviceHandler(routesHandler, http.MethodPut, `{"routes":["10.0.0.0/24"]}`); response.Code != http.StatusOK {
		t.Fatalf("expected route update success, got %d: %s", response.Code, response.Body.String())
	}
	if response := callDeviceHandler(routesHandler, http.MethodPut, `{"routes":["not-a-route"]}`); response.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid route rejection, got %d", response.Code)
	}

	attributesHandler := handleDeviceAttributes(store)
	attributesResponse := callDeviceHandler(attributesHandler, http.MethodGet, "")
	if attributesResponse.Code != http.StatusOK || !bytes.Contains(attributesResponse.Body.Bytes(), []byte("com.example.checked")) {
		t.Fatalf("unexpected attributes response: %d %s", attributesResponse.Code, attributesResponse.Body.String())
	}
	attributeRequest := `{"key":"com.example.checked","value":{"build":"123"},"expiry":"2026-01-02T03:04:05Z","comment":"managed"}`
	if response := callDeviceHandler(attributesHandler, http.MethodPost, attributeRequest); response.Code != http.StatusOK {
		t.Fatalf("expected attribute update success, got %d: %s", response.Code, response.Body.String())
	}
	if response := callDeviceHandler(attributesHandler, http.MethodPost, `{"key":"com.example.checked","value":true,"expiry":"invalid"}`); response.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid attribute rejection, got %d", response.Code)
	}
	if response := callDeviceHandler(attributesHandler, http.MethodDelete, `{"key":"com.example.checked"}`); response.Code != http.StatusOK {
		t.Fatalf("expected attribute deletion success, got %d: %s", response.Code, response.Body.String())
	}
}

func TestDeviceMutationHandlersRejectInvalidRequests(t *testing.T) {
	store := newDeviceStore(VerifyConfig{})
	if response := callDeviceHandler(handleSetDeviceName(store), http.MethodPut, `{"name":""}`); response.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid name rejection, got %d", response.Code)
	}
	if response := callDeviceHandler(handleSetDeviceTags(store), http.MethodPut, `{"tags":["untagged"]}`); response.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid tag rejection, got %d", response.Code)
	}
}

func newManagementTestStore(api *httptest.Server, secret, nodeKey string) *deviceStore {
	store := newDeviceStore(VerifyConfig{APIs: []APIConfig{{Name: "primary", Tailnet: "-", APIKey: secret}}})
	store.cache["primary"] = deviceCache{devices: map[string]Device{
		nodeKey: {NodeID: "node-1", NodeKey: nodeKey, Expires: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)},
	}}
	store.setHTTPClientForTest(api.Client(), api.URL)
	return store
}

func callDeviceAction(t *testing.T, handler http.HandlerFunc, method, body string) {
	t.Helper()
	response := callDeviceHandler(handler, method, body)
	if response.Code != http.StatusOK {
		t.Fatalf("expected success, got %d: %s", response.Code, response.Body.String())
	}
}

func callDeviceHandler(handler http.HandlerFunc, method, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "/tailnets/primary/devices/node-1", bytes.NewBufferString(body))
	request.SetPathValue("instance", "primary")
	request.SetPathValue("deviceID", "node-1")
	response := httptest.NewRecorder()
	handler(response, request)
	return response
}

func assertJSONBody(t *testing.T, r *http.Request, expected any) {
	t.Helper()
	var body any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		t.Fatalf("decode request: %v", err)
	}
	if !reflect.DeepEqual(body, expected) {
		t.Fatalf("unexpected request body: %#v", body)
	}
}
