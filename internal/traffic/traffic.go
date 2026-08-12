package traffic

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Stats struct {
	BytesRecv int64     `json:"bytesRecv"`
	BytesSent int64     `json:"bytesSent"`
	Accepts   int64     `json:"accepts"`
	SavedAt   time.Time `json:"savedAt"`
}

type SessionMetricsFunc func() (bytesRecv, bytesSent, accepts int64)

type Persister struct {
	mu         sync.Mutex
	path       string
	persisted  Stats
	sessionRef SessionMetricsFunc
	offset     Stats
	interval   time.Duration
	enabled    bool
}

func New(enabled bool, path string, interval time.Duration, sessionRef SessionMetricsFunc) *Persister {
	return &Persister{
		enabled:    enabled,
		path:       path,
		interval:   interval,
		sessionRef: sessionRef,
	}
}

func (p *Persister) Load() error {
	if p == nil || !p.enabled {
		return nil
	}
	if p.path == "" {
		return fmt.Errorf("traffic persistence path is required")
	}

	var persisted Stats
	raw, err := os.ReadFile(p.path)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
	} else if err := json.Unmarshal(raw, &persisted); err != nil {
		return err
	}

	current := p.currentSession()

	p.mu.Lock()
	defer p.mu.Unlock()
	p.persisted = persisted
	p.offset = current
	return nil
	}

func (p *Persister) Save() error {
	if p == nil || !p.enabled {
		return nil
	}
	if p.path == "" {
		return fmt.Errorf("traffic persistence path is required")
	}

	current := p.currentSession()

	p.mu.Lock()
	defer p.mu.Unlock()

	nextPersisted := p.persisted
	nextPersisted.BytesRecv += current.BytesRecv - p.offset.BytesRecv
	nextPersisted.BytesSent += current.BytesSent - p.offset.BytesSent
	nextPersisted.Accepts += current.Accepts - p.offset.Accepts
	nextPersisted.SavedAt = time.Now().UTC()

	nextOffset := Stats{
		BytesRecv: current.BytesRecv,
		BytesSent: current.BytesSent,
		Accepts:   current.Accepts,
	}

	data, err := json.Marshal(nextPersisted)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(p.path), 0o755); err != nil {
		return err
	}

	tmpPath := p.path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, p.path); err != nil {
		return err
	}

	p.persisted = nextPersisted
	p.offset = nextOffset
	return nil
}

func (p *Persister) Start(ctx context.Context) {
	if p == nil || !p.enabled || p.interval <= 0 {
		return
	}

	go func() {
		ticker := time.NewTicker(p.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := p.Save(); err != nil {
					log.Printf("Traffic stats save failed: %v", err)
				}
			case <-ctx.Done():
				if err := p.Save(); err != nil {
					log.Printf("Traffic stats final save failed: %v", err)
				}
				return
			}
		}
	}()
}

func (p *Persister) Total() Stats {
	if p == nil || !p.enabled {
		return Stats{}
	}

	current := p.currentSession()

	p.mu.Lock()
	defer p.mu.Unlock()

	total := p.persisted
	total.BytesRecv += current.BytesRecv - p.offset.BytesRecv
	total.BytesSent += current.BytesSent - p.offset.BytesSent
	total.Accepts += current.Accepts - p.offset.Accepts
	return total
}

func (p *Persister) currentSession() Stats {
	if p == nil || p.sessionRef == nil {
		return Stats{}
	}

	bytesRecv, bytesSent, accepts := p.sessionRef()
	return Stats{
		BytesRecv: bytesRecv,
		BytesSent: bytesSent,
		Accepts:   accepts,
	}
}
