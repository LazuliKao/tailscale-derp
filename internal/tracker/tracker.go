package tracker

import (
	"sync"
	"time"
)

type PeerInfo struct {
	PublicKey   string `json:"publicKey"`
	RemoteAddr  string `json:"remoteAddr"`
	ConnectedAt string `json:"connectedAt"`
}

type PeerTracker struct {
	mu    sync.RWMutex
	peers map[string]PeerInfo // keyed by public key
}

func NewPeerTracker() *PeerTracker {
	return &PeerTracker{peers: make(map[string]PeerInfo)}
}

func (t *PeerTracker) Add(publicKey, remoteAddr string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.peers[publicKey] = PeerInfo{
		PublicKey:   publicKey,
		RemoteAddr:  remoteAddr,
		ConnectedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

func (t *PeerTracker) Remove(publicKey string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.peers, publicKey)
}

type PeersResponse struct {
	Peers []PeerInfo `json:"peers"`
	Count int        `json:"count"`
}

func (t *PeerTracker) GetAll() PeersResponse {
	t.mu.RLock()
	defer t.mu.RUnlock()
	list := make([]PeerInfo, 0, len(t.peers))
	for _, p := range t.peers {
		list = append(list, p)
	}
	return PeersResponse{Peers: list, Count: len(list)}
}
