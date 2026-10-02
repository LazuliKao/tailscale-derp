package ops

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/LazuliKao/tailscale-derp/internal/httpjson"
	"github.com/LazuliKao/tailscale-derp/internal/tracker"
	"go4.org/mem"
	"tailscale.com/types/key"
)

type peerIdentity struct {
	Source        string   `json:"source"`
	Name          string   `json:"name,omitempty"`
	Hostname      string   `json:"hostname,omitempty"`
	User          string   `json:"user,omitempty"`
	NodeID        string   `json:"nodeId,omitempty"`
	Addresses     []string `json:"addresses,omitempty"`
	OS            string   `json:"os,omitempty"`
	ClientVersion string   `json:"clientVersion,omitempty"`
	Tags          []string `json:"tags,omitempty"`
	Sources       []string `json:"sources,omitempty"`
}

type peerDetails struct {
	tracker.PeerInfo
	Identity *peerIdentity `json:"identity"`
}

type peerDetailsResponse struct {
	Peers     []peerDetails `json:"peers"`
	Count     int           `json:"count"`
	SampledAt string        `json:"sampledAt"`
}

type identityEntry struct {
	identity *peerIdentity
	expires  time.Time
	pending  bool
}

type identityResolver struct {
	mu     sync.Mutex
	cache  map[string]identityEntry
	slots  chan struct{}
	lookup func(context.Context, string) (*peerIdentity, error)
}

func newIdentityResolver(v *verifier) *identityResolver {
	r := &identityResolver{cache: make(map[string]identityEntry), slots: make(chan struct{}, 2)}
	r.lookup = func(ctx context.Context, nodeKey string) (*peerIdentity, error) {
		parsed, err := key.ParseNodePublicUntyped(mem.S(nodeKey))
		if err != nil {
			return nil, err
		}
		who, err := v.local.WhoIsNodeKey(ctx, parsed)
		if err != nil || who == nil || who.Node == nil {
			return nil, err
		}
		node := who.Node
		result := &peerIdentity{
			Source: "local_tailscaled", Name: strings.TrimSuffix(node.Name, "."),
			NodeID: string(node.StableID), Tags: append([]string(nil), node.Tags...),
		}
		if node.Hostinfo.Valid() {
			result.Hostname = node.Hostinfo.Hostname()
			result.OS = node.Hostinfo.OS()
			result.ClientVersion = node.Hostinfo.IPNVersion()
		}
		if who.UserProfile != nil {
			result.User = who.UserProfile.LoginName
			if result.User == "" {
				result.User = who.UserProfile.DisplayName
			}
		}
		for _, address := range node.Addresses {
			if address.IsSingleIP() {
				result.Addresses = append(result.Addresses, address.Addr().String())
			}
		}
		return result, nil
	}
	return r
}

// resolve never waits for tailscaled: unknown identities are populated on a later poll.
func (r *identityResolver) resolve(nodeKey string) *peerIdentity {
	r.mu.Lock()
	entry, ok := r.cache[nodeKey]
	if ok && (entry.pending || time.Now().Before(entry.expires)) {
		r.mu.Unlock()
		return entry.identity
	}
	select {
	case r.slots <- struct{}{}:
		r.cache[nodeKey] = identityEntry{pending: true}
	default:
		r.mu.Unlock()
		return nil
	}
	r.mu.Unlock()
	go func() {
		defer func() { <-r.slots }()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		identity, err := r.lookup(ctx, nodeKey)
		ttl := 5 * time.Minute
		if err != nil || identity == nil {
			identity = nil
			ttl = time.Minute
		}
		r.mu.Lock()
		if current, ok := r.cache[nodeKey]; ok && current.pending {
			r.cache[nodeKey] = identityEntry{identity: identity, expires: time.Now().Add(ttl)}
		}
		r.mu.Unlock()
	}()
	return nil
}

func (r *identityResolver) prune(active map[string]bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for nodeKey := range r.cache {
		if !active[nodeKey] {
			delete(r.cache, nodeKey)
		}
	}
}

func deviceIdentity(device Device) *peerIdentity {
	return &peerIdentity{
		Source: "official_api", Name: device.Name, Hostname: device.Hostname,
		User: device.User, NodeID: device.NodeID,
		Addresses: append([]string(nil), device.Addresses...), OS: device.OS,
		ClientVersion: device.ClientVersion, Tags: append([]string(nil), device.Tags...),
		Sources: append([]string(nil), device.Sources...),
	}
}

func handlePeerDetails(t *tracker.PeerTracker, v *verifier) http.HandlerFunc {
	resolver := newIdentityResolver(v)
	return func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			httpjson.Write(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET required"})
			return
		}
		snapshot := t.GetAll()
		devices := make(map[string]Device)
		if v != nil && v.store != nil {
			for _, device := range v.store.snapshot().Devices {
				devices[device.NodeKey] = device
			}
		}
		result := peerDetailsResponse{Peers: make([]peerDetails, 0, len(snapshot.Peers)), Count: snapshot.Count, SampledAt: snapshot.SampledAt}
		active := make(map[string]bool, len(snapshot.Peers))
		for _, peer := range snapshot.Peers {
			active[peer.PublicKey] = true
			var identity *peerIdentity
			if device, ok := devices[peer.PublicKey]; ok {
				identity = deviceIdentity(device)
			} else if v != nil && v.local != nil {
				identity = resolver.resolve(peer.PublicKey)
			}
			result.Peers = append(result.Peers, peerDetails{PeerInfo: peer, Identity: identity})
		}
		resolver.prune(active)
		httpjson.Write(w, http.StatusOK, result)
	}
}
