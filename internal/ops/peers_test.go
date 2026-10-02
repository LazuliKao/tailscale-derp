package ops

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LazuliKao/tailscale-derp/internal/tracker"
	"tailscale.com/client/local"
)

func TestPeersPreferAPICacheAndDoNotExposeCredentials(t *testing.T) {
	const key = "nodekey:test"
	const secret = "tskey-api-private"
	store := &deviceStore{configs: []APIConfig{{Name: "primary", Tailnet: "-", APIKey: secret}}, cache: map[string]deviceCache{"primary": {
		devices:     map[string]Device{key: {NodeKey: key, Name: "my laptop", User: "alice@example.com"}},
		lastSuccess: time.Now(),
	}}, ttl: time.Minute}
	track := tracker.NewPeerTracker()
	track.Register(1, key, "192.0.2.1:1234", time.Now())
	v := &verifier{store: store, local: &local.Client{}, cfg: VerifyConfig{APIs: []APIConfig{{APIKey: secret}}}}
	handler := handlePeerDetails(track, v)
	request := httptest.NewRequest(http.MethodGet, "/peers", nil)
	response := httptest.NewRecorder()
	handler(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", response.Code)
	}
	var data peerDetailsResponse
	if err := json.Unmarshal(response.Body.Bytes(), &data); err != nil {
		t.Fatal(err)
	}
	if data.Count != 1 || data.Peers[0].Identity.Source != "official_api" || data.Peers[0].Identity.Name != "my laptop" {
		t.Fatalf("unexpected enriched peer: %+v", data)
	}
	if body := response.Body.String(); strings.Contains(body, secret) {
		t.Fatalf("sensitive response: %s", body)
	}
}

func TestIdentityResolverCachesMissAndBoundsConcurrentLookups(t *testing.T) {
	r := &identityResolver{cache: make(map[string]identityEntry), slots: make(chan struct{}, 2)}
	started := make(chan struct{}, 3)
	release := make(chan struct{})
	var calls atomic.Int32
	r.lookup = func(ctx context.Context, key string) (*peerIdentity, error) {
		calls.Add(1)
		started <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil, errors.New("unavailable")
	}
	for _, key := range []string{"one", "one", "two", "three"} {
		if got := r.resolve(key); got != nil {
			t.Fatalf("unexpected immediate identity: %+v", got)
		}
	}
	<-started
	<-started
	if got := calls.Load(); got != 2 {
		t.Fatalf("expected two bounded lookups, got %d", got)
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		one, two := r.cache["one"], r.cache["two"]
		r.mu.Unlock()
		if !one.pending && !two.pending {
			break
		}
		time.Sleep(time.Millisecond)
	}
	r.resolve("one")
	if got := calls.Load(); got != 2 {
		t.Fatalf("negative cache did not prevent repeat lookup: %d", got)
	}
	r.prune(map[string]bool{"two": true})
	r.mu.Lock()
	_, retained := r.cache["two"]
	_, removed := r.cache["one"]
	r.mu.Unlock()
	if !retained || removed {
		t.Fatal("prune must only retain active identities")
	}
}

func TestIdentityResolverCachesSuccessfulLookup(t *testing.T) {
	r := &identityResolver{cache: make(map[string]identityEntry), slots: make(chan struct{}, 2)}
	var calls atomic.Int32
	r.lookup = func(context.Context, string) (*peerIdentity, error) {
		calls.Add(1)
		return &peerIdentity{Source: "local_tailscaled", Name: "laptop"}, nil
	}
	if got := r.resolve("nodekey:example"); got != nil {
		t.Fatalf("lookup should be asynchronous: %+v", got)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if identity := r.resolve("nodekey:example"); identity != nil {
			if identity.Name != "laptop" || calls.Load() != 1 {
				t.Fatalf("unexpected cached identity or duplicate lookup: %+v, calls %d", identity, calls.Load())
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("identity was not cached")
}
