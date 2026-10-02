package tracker

import (
	"sort"
	"sync"
	"time"
)

const sampleInterval = 5 * time.Second

// PeerInfo describes a node with at least one local DERP connection.
// Traffic counts packet payloads, not protocol framing or direct Tailscale traffic.
type PeerInfo struct {
	PublicKey       string       `json:"publicKey"`
	RemoteAddr      string       `json:"remoteAddr"`
	ConnectedAt     string       `json:"connectedAt"`
	Connections     []Connection `json:"connections"`
	BytesRecv       int64        `json:"bytesRecv"`
	BytesSent       int64        `json:"bytesSent"`
	RecvBytesPerSec *float64     `json:"recvBytesPerSecond"`
	SentBytesPerSec *float64     `json:"sentBytesPerSecond"`
}

type Connection struct {
	RemoteAddr  string `json:"remoteAddr"`
	ConnectedAt string `json:"connectedAt"`
}

type peerState struct {
	connections map[int64]Connection
	recv, sent  int64
	lastRecv    int64
	lastSent    int64
	lastSample  time.Time
	recvRate    *float64
	sentRate    *float64
}

type PeerTracker struct {
	mu          sync.Mutex
	peers       map[string]*peerState
	connections map[int64]string
}

func NewPeerTracker() *PeerTracker {
	return &PeerTracker{peers: make(map[string]*peerState), connections: make(map[int64]string)}
}

func (t *PeerTracker) Register(id int64, publicKey, remoteAddr string, connectedAt time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	p := t.peers[publicKey]
	if p == nil {
		p = &peerState{connections: make(map[int64]Connection), lastSample: connectedAt}
		t.peers[publicKey] = p
	}
	p.connections[id] = Connection{RemoteAddr: remoteAddr, ConnectedAt: connectedAt.UTC().Format(time.RFC3339Nano)}
	t.connections[id] = publicKey
}

func (t *PeerTracker) Unregister(id int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	key, ok := t.connections[id]
	if !ok {
		return
	}
	delete(t.connections, id)
	p := t.peers[key]
	delete(p.connections, id)
	if len(p.connections) == 0 {
		delete(t.peers, key)
	}
}

func (t *PeerTracker) Receive(id int64, bytes int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if key, ok := t.connections[id]; ok {
		t.peers[key].recv += int64(bytes)
	}
}

func (t *PeerTracker) Send(id int64, bytes int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if key, ok := t.connections[id]; ok {
		t.peers[key].sent += int64(bytes)
	}
}

type PeersResponse struct {
	Peers     []PeerInfo `json:"peers"`
	Count     int        `json:"count"`
	SampledAt string     `json:"sampledAt"`
}

func (t *PeerTracker) GetAll() PeersResponse {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	list := make([]PeerInfo, 0, len(t.peers))
	for key, p := range t.peers {
		if elapsed := now.Sub(p.lastSample); elapsed >= sampleInterval {
			recv := float64(p.recv-p.lastRecv) / elapsed.Seconds()
			sent := float64(p.sent-p.lastSent) / elapsed.Seconds()
			p.recvRate, p.sentRate = &recv, &sent
			p.lastRecv, p.lastSent, p.lastSample = p.recv, p.sent, now
		}
		ids := make([]int64, 0, len(p.connections))
		for id := range p.connections {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		connections := make([]Connection, 0, len(ids))
		for _, id := range ids {
			connections = append(connections, p.connections[id])
		}
		list = append(list, PeerInfo{
			PublicKey: key, RemoteAddr: connections[len(connections)-1].RemoteAddr,
			ConnectedAt: connections[0].ConnectedAt, Connections: connections,
			BytesRecv: p.recv, BytesSent: p.sent,
			RecvBytesPerSec: p.recvRate, SentBytesPerSec: p.sentRate,
		})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].PublicKey < list[j].PublicKey })
	return PeersResponse{Peers: list, Count: len(list), SampledAt: now.UTC().Format(time.RFC3339Nano)}
}
