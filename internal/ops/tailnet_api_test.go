package ops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"tailscale.com/types/key"
)

func TestHandleSetDeviceIPv4UsesSDKAndUpdatesCache(t *testing.T) {
	secret := "tskey-api-secret"
	nodeKey := key.NewNode().Public().String()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v2/device/node-1/ip" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL)
		}
		username, password, ok := r.BasicAuth()
		if !ok || username != secret || password != "" {
			t.Fatalf("unexpected basic authentication: username=%q password=%q present=%v", username, password, ok)
		}
		var request setDeviceIPv4Request
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if request.IPv4 != "100.64.0.10" {
			t.Fatalf("unexpected IPv4 address: %q", request.IPv4)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer api.Close()

	store := newDeviceStore(VerifyConfig{APIs: []APIConfig{{Name: "primary", Tailnet: "-", APIKey: secret}}})
	store.cache["primary"] = deviceCache{devices: map[string]Device{
		nodeKey: {NodeID: "node-1", NodeKey: nodeKey, Addresses: []string{"100.64.0.1", "fd7a:115c:a1e0::1"}},
	}}
	store.setHTTPClientForTest(api.Client(), api.URL)

	request := httptest.NewRequest(http.MethodPut, "/tailnets/primary/devices/node-1/ip", bytes.NewBufferString(`{"ipv4":"100.64.0.10"}`))
	request.SetPathValue("instance", "primary")
	request.SetPathValue("deviceID", "node-1")
	response := httptest.NewRecorder()
	handleSetDeviceIPv4(store)(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	addresses := store.cache["primary"].devices[nodeKey].Addresses
	if len(addresses) != 2 || addresses[0] != "100.64.0.10" || addresses[1] != "fd7a:115c:a1e0::1" {
		t.Fatalf("unexpected cached addresses: %v", addresses)
	}
}

func TestHandleSetDeviceIPv4RejectsInvalidAddress(t *testing.T) {
	store := newDeviceStore(VerifyConfig{})
	request := httptest.NewRequest(http.MethodPut, "/tailnets/primary/devices/node-1/ip", bytes.NewBufferString(`{"ipv4":"not-an-ip"}`))
	request.SetPathValue("instance", "primary")
	request.SetPathValue("deviceID", "node-1")
	response := httptest.NewRecorder()

	handleSetDeviceIPv4(store)(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", response.Code)
	}
}

func TestPolicyHandlersPreserveHuJSONAndETag(t *testing.T) {
	secret := "tskey-api-secret"
	const hujson = "// keep this comment\n{\n  \"acls\": [],\n}\n"
	requests := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != secret || password != "" {
			t.Fatalf("unexpected basic authentication: username=%q password=%q present=%v", username, password, ok)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		switch requests {
		case 0:
			if r.Method != http.MethodGet || r.URL.Path != "/api/v2/tailnet/-/acl" || r.Header.Get("Accept") != "application/hujson" {
				t.Fatalf("unexpected raw ACL request: %s %s accept=%q", r.Method, r.URL, r.Header.Get("Accept"))
			}
			w.Header().Set("Etag", "v1")
			_, _ = w.Write([]byte(hujson))
		case 1:
			if r.Method != http.MethodPost || r.URL.Path != "/api/v2/tailnet/-/acl/validate" || r.Header.Get("Content-Type") != "application/hujson" || string(body) != hujson {
				t.Fatalf("unexpected validate request: %s %s content-type=%q body=%q", r.Method, r.URL, r.Header.Get("Content-Type"), body)
			}
		case 2:
			if r.Method != http.MethodPost || r.URL.Path != "/api/v2/tailnet/-/acl/validate" || r.Header.Get("Content-Type") != "application/hujson" || string(body) != hujson {
				t.Fatalf("unexpected write validation request: %s %s content-type=%q body=%q", r.Method, r.URL, r.Header.Get("Content-Type"), body)
			}
		case 3:
			if r.Method != http.MethodPost || r.URL.Path != "/api/v2/tailnet/-/acl" || r.Header.Get("Content-Type") != "application/hujson" || r.Header.Get("If-Match") != `"v1"` || string(body) != hujson {
				t.Fatalf("unexpected set request: %s %s content-type=%q if-match=%q body=%q", r.Method, r.URL, r.Header.Get("Content-Type"), r.Header.Get("If-Match"), body)
			}
		default:
			t.Fatalf("unexpected extra request: %s %s", r.Method, r.URL)
		}
		requests++
	}))
	defer api.Close()

	store := newDeviceStore(VerifyConfig{APIs: []APIConfig{{Name: "primary", Tailnet: "-", APIKey: secret}}})
	store.setHTTPClientForTest(api.Client(), api.URL)

	getRequest := httptest.NewRequest(http.MethodGet, "/tailnets/primary/acl", nil)
	getRequest.SetPathValue("instance", "primary")
	getResponse := httptest.NewRecorder()
	handlePolicyGet(store)(getResponse, getRequest)
	if getResponse.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", getResponse.Code, getResponse.Body.String())
	}
	var document policyDocument
	if err := json.NewDecoder(getResponse.Body).Decode(&document); err != nil {
		t.Fatalf("decode policy document: %v", err)
	}
	if document.HuJSON != hujson || document.ETag != "v1" {
		t.Fatalf("unexpected policy document: %#v", document)
	}

	validateRequest := httptest.NewRequest(http.MethodPost, "/tailnets/primary/acl/validate", bytes.NewBufferString(`{"hujson":"// keep this comment\n{\n  \"acls\": [],\n}\n"}`))
	validateRequest.SetPathValue("instance", "primary")
	validateResponse := httptest.NewRecorder()
	handlePolicyValidate(store)(validateResponse, validateRequest)
	if validateResponse.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", validateResponse.Code, validateResponse.Body.String())
	}

	setRequest := httptest.NewRequest(http.MethodPut, "/tailnets/primary/acl", bytes.NewBufferString(`{"hujson":"// keep this comment\n{\n  \"acls\": [],\n}\n","etag":"v1"}`))
	setRequest.SetPathValue("instance", "primary")
	setResponse := httptest.NewRecorder()
	handlePolicySet(store)(setResponse, setRequest)
	if setResponse.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", setResponse.Code, setResponse.Body.String())
	}
	if requests != 4 {
		t.Fatalf("expected four API requests, got %d", requests)
	}
}

func TestHandlePolicySetMapsETagConflict(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/tailnet/-/acl/validate":
			w.WriteHeader(http.StatusOK)
		case "/api/v2/tailnet/-/acl":
			w.WriteHeader(http.StatusPreconditionFailed)
			_, _ = w.Write([]byte(`{"message":"policy changed"}`))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer api.Close()

	store := newDeviceStore(VerifyConfig{APIs: []APIConfig{{Name: "primary", Tailnet: "-", APIKey: "tskey-api-secret"}}})
	store.setHTTPClientForTest(api.Client(), api.URL)
	request := httptest.NewRequest(http.MethodPut, "/tailnets/primary/acl", bytes.NewBufferString(`{"hujson":"{}","etag":"v1"}`))
	request.SetPathValue("instance", "primary")
	response := httptest.NewRecorder()

	handlePolicySet(store)(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", response.Code, response.Body.String())
	}
}

func TestAPIInstancesExcludeAPIKeys(t *testing.T) {
	store := newDeviceStore(VerifyConfig{APIs: []APIConfig{{Name: "primary", Label: "Primary", Tailnet: "-", APIKey: "tskey-api-secret"}}})
	request := httptest.NewRequest(http.MethodGet, "/tailnets", nil)
	response := httptest.NewRecorder()

	handleAPIInstances(store)(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.Code)
	}
	if bytes.Contains(response.Body.Bytes(), []byte("tskey-api-secret")) {
		t.Fatal("API key leaked in instance response")
	}
}

func TestNewMuxRegistersTailnetRoutes(t *testing.T) {
	handler := NewMux(Config{}, nil, nil, nil, nil, nil)
	request := httptest.NewRequest(http.MethodGet, "/tailnets", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
}

func TestStorePolicyRawUnknownInstance(t *testing.T) {
	store := newDeviceStore(VerifyConfig{})
	if _, err := store.policyRaw(context.Background(), "missing"); !errors.Is(err, errUnknownAPIInstance) {
		t.Fatalf("expected unknown instance error, got %v", err)
	}
}
