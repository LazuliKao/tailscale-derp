package tracker

import (
	"testing"
	"time"
)

func TestConnectionLifetimeAndDuplicateAccounting(t *testing.T) {
	tracker := NewPeerTracker()
	now := time.Now()
	tracker.Register(1, "nodekey:one", "192.0.2.1:123", now)
	tracker.Register(2, "nodekey:one", "192.0.2.2:456", now.Add(time.Second))
	tracker.Receive(1, 100)
	tracker.Receive(2, 50)
	tracker.Send(2, 30)
	first := tracker.GetAll()
	if first.Count != 1 || len(first.Peers[0].Connections) != 2 || first.Peers[0].BytesRecv != 150 || first.Peers[0].BytesSent != 30 {
		t.Fatalf("unexpected duplicate snapshot: %+v", first)
	}
	if first.Peers[0].RecvBytesPerSec != nil {
		t.Fatal("rate should be unknown before first sample")
	}
	tracker.mu.Lock()
	tracker.peers["nodekey:one"].lastSample = time.Now().Add(-sampleInterval)
	tracker.mu.Unlock()
	sampled := tracker.GetAll().Peers[0]
	if sampled.RecvBytesPerSec == nil || *sampled.RecvBytesPerSec <= 0 || sampled.SentBytesPerSec == nil || *sampled.SentBytesPerSec <= 0 {
		t.Fatalf("missing sampled rates: %+v", sampled)
	}
	tracker.mu.Lock()
	tracker.peers["nodekey:one"].lastSample = time.Now().Add(-sampleInterval)
	tracker.mu.Unlock()
	idle := tracker.GetAll().Peers[0]
	if *idle.RecvBytesPerSec != 0 || *idle.SentBytesPerSec != 0 {
		t.Fatalf("idle rates must return to zero: %+v", idle)
	}
	tracker.Unregister(1)
	tracker.Receive(1, 999)
	tracker.Send(2, 70)
	remaining := tracker.GetAll().Peers[0]
	if len(remaining.Connections) != 1 || remaining.BytesRecv != 150 || remaining.BytesSent != 100 {
		t.Fatalf("traffic should survive until final disconnect: %+v", remaining)
	}
	tracker.Unregister(2)
	if got := tracker.GetAll(); got.Count != 0 || got.Peers == nil {
		t.Fatalf("expected empty, non-null peers after disconnect: %+v", got)
	}
	tracker.Register(3, "nodekey:one", "192.0.2.3:789", time.Now())
	if got := tracker.GetAll().Peers[0]; got.BytesRecv != 0 || got.BytesSent != 0 || got.RecvBytesPerSec != nil {
		t.Fatalf("reconnected node should start a new lifetime: %+v", got)
	}
}
