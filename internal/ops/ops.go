package ops

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"time"

	"github.com/LazuliKao/tailscale-derp/internal/httpjson"
	"github.com/LazuliKao/tailscale-derp/internal/service"
	"github.com/LazuliKao/tailscale-derp/internal/tracker"
	"github.com/LazuliKao/tailscale-derp/internal/traffic"
)

const verifyTimeout = 5 * time.Second

type Config struct {
	Verify          VerifyConfig
	Version         string
	Listen          string
	STUN            bool
	Mesh            bool
	OpsAddr         string
	Health          string
	TrafficPersist  bool
	TrafficPath     string
	TrafficInterval int
}

type Status struct {
	VerifyClients      []string `json:"verifyClients,omitempty"`
	VerifyEnabled      bool     `json:"verifyEnabled"`
	VerifyURLsEnabled  bool     `json:"verifyURLsEnabled"`
	VerifyTailscaled   bool     `json:"verifyTailscaled"`
	VerifyAPIEnabled   bool     `json:"verifyAPIEnabled"`
	VerifyAPIInstances int      `json:"verifyAPIInstances"`
	Running            bool     `json:"running"`
	Version            string   `json:"version"`
	Listen             string   `json:"listen"`
	STUN               bool     `json:"stun"`
	Mesh               bool     `json:"mesh"`
	Metrics            string   `json:"metrics"`
	Health             string   `json:"health"`
	TrafficPersist     bool     `json:"trafficPersist"`
	TrafficPath        string   `json:"trafficPath,omitempty"`
	TrafficInterval    int      `json:"trafficInterval,omitempty"`
	Error              string   `json:"error,omitempty"`
	Clients            int      `json:"clients"`
	Accepts            int64    `json:"accepts"`
	BytesRecv          int64    `json:"bytesRecv"`
	BytesSent          int64    `json:"bytesSent"`
	AcceptsTotal       int64    `json:"acceptsTotal,omitempty"`
	BytesRecvTotal     int64    `json:"bytesRecvTotal,omitempty"`
	BytesSentTotal     int64    `json:"bytesSentTotal,omitempty"`
}

type ActionResult struct {
	Action string `json:"action"`
	Result string `json:"result"`
	Error  string `json:"error,omitempty"`
}

type Executor func(action string) error
type Snapshot func() (bool, string)

// MetricsFunc returns DERP server expvar metrics as raw JSON.
type MetricsFunc func() json.RawMessage

type TrafficFunc func() *traffic.Stats

func StatusFromConfig(cfg Config, snapshot Snapshot, mf MetricsFunc, tf TrafficFunc) Status {
	running := true
	errMsg := ""
	if snapshot != nil {
		running, errMsg = snapshot()
	}
	metricsAddr := cfg.OpsAddr
	if metricsAddr == "" {
		metricsAddr = "127.0.0.1:9911"
	}
	healthAddr := cfg.Health
	if healthAddr == "" {
		healthAddr = ":9912"
	}

	s := Status{
		VerifyClients:      cfg.Verify.URLs,
		VerifyEnabled:      cfg.Verify.Enabled,
		VerifyURLsEnabled:  cfg.Verify.URLsEnabled,
		VerifyTailscaled:   cfg.Verify.TailscaledEnabled,
		VerifyAPIEnabled:   cfg.Verify.APIEnabled,
		VerifyAPIInstances: len(cfg.Verify.APIs),
		Running:            running,
		Version:            cfg.Version,
		Listen:             cfg.Listen,
		STUN:               cfg.STUN,
		Mesh:               cfg.Mesh,
		Metrics:            metricsAddr,
		Health:             healthAddr,
		TrafficPersist:     cfg.TrafficPersist,
		TrafficPath:        cfg.TrafficPath,
		TrafficInterval:    cfg.TrafficInterval,
		Error:              errMsg,
	}

	if mf != nil {
		if raw := mf(); len(raw) > 0 {
			var m map[string]json.RawMessage
			if json.Unmarshal(raw, &m) == nil {
				s.Clients = extractInt(m, "gauge_clients_local")
				s.Accepts = extractInt64(m, "accepts")
				s.BytesRecv = extractInt64(m, "bytes_received")
				s.BytesSent = extractInt64(m, "bytes_sent")
			}
		}
	}

	if tf != nil {
		if total := tf(); total != nil {
			s.AcceptsTotal = total.Accepts
			s.BytesRecvTotal = total.BytesRecv
			s.BytesSentTotal = total.BytesSent
		}
	}

	return s
}

func extractInt(m map[string]json.RawMessage, key string) int {
	raw, ok := m[key]
	if !ok {
		return 0
	}
	var v int
	json.Unmarshal(raw, &v)
	return v
}

func extractInt64(m map[string]json.RawMessage, key string) int64 {
	raw, ok := m[key]
	if !ok {
		return 0
	}
	var v int64
	json.Unmarshal(raw, &v)
	return v
}

func HandleOpsWithExecutor(executor Executor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			httpjson.Write(w, http.StatusMethodNotAllowed, ActionResult{Error: "POST required", Result: "error"})
			return
		}
		action := r.URL.Query().Get("action")
		if !service.AllowedAction(action) {
			httpjson.Write(w, http.StatusBadRequest, ActionResult{Action: action, Result: "error", Error: "unknown action"})
			return
		}
		if err := executor(action); err != nil {
			status := http.StatusBadGateway
			if errors.Is(err, exec.ErrNotFound) {
				status = http.StatusServiceUnavailable
			}
			httpjson.Write(w, status, ActionResult{Action: action, Result: "error", Error: err.Error()})
			return
		}

		httpjson.Write(w, http.StatusOK, ActionResult{Action: action, Result: "ok"})
	}
}

func HandleStatus(cfg Config, snapshot Snapshot, mf MetricsFunc, tf TrafficFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			httpjson.Write(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET required"})
			return
		}

		httpjson.Write(w, http.StatusOK, StatusFromConfig(cfg, snapshot, mf, tf))
	}
}

func HandleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httpjson.Write(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET required"})
		return
	}

	httpjson.Write(w, http.StatusOK, map[string]string{"status": "ok"})
}

func HandleVersion(version string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			httpjson.Write(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET required"})
			return
		}

		httpjson.Write(w, http.StatusOK, map[string]string{"version": version})
	}
}

// HandleVerify is retained as a compatibility wrapper for callers that only
// configure Verify URLs. The failOpen argument is intentionally ignored.
func HandleVerify(urls []string, failOpen bool, t *tracker.PeerTracker) http.HandlerFunc {
	_ = failOpen
	return handleVerify(newVerifier(VerifyConfig{
		Enabled:     true,
		URLsEnabled: true,
		URLs:        urls,
	}, t))
}

var errVerifyNetwork = fmt.Errorf("network error")

func checkVerifyURL(baseURL, clientKey string) error {
	u, err := url.Parse(baseURL)
	if err != nil {
		return errVerifyNetwork
	}
	q := u.Query()
	q.Set("key", clientKey)
	u.RawQuery = q.Encode()

	client := &http.Client{Timeout: verifyTimeout}
	resp, err := client.Get(u.String())
	if err != nil {
		return errVerifyNetwork
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	if resp.StatusCode >= 500 {
		return errVerifyNetwork
	}
	return fmt.Errorf("rejected with status %d", resp.StatusCode)
}

// HandleClients returns raw DERP server metrics.
func HandleClients(mf MetricsFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			httpjson.Write(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET required"})
			return
		}

		if mf == nil {
			httpjson.Write(w, http.StatusServiceUnavailable, map[string]string{"error": "DERP server not ready"})
			return
		}

		raw := mf()
		if len(raw) == 0 {
			httpjson.Write(w, http.StatusOK, map[string]any{})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(raw)
	}
}

// HandlePeers returns the list of tracked connected peers.
func HandlePeers(t *tracker.PeerTracker) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			httpjson.Write(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET required"})
			return
		}
		httpjson.Write(w, http.StatusOK, t.GetAll())
	}
}

func NewMux(cfg Config, snapshot Snapshot, executor Executor, mf MetricsFunc, t *tracker.PeerTracker, tf TrafficFunc) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/status", HandleStatus(cfg, snapshot, mf, tf))
	mux.HandleFunc("/health", HandleHealth)
	mux.HandleFunc("/version", HandleVersion(cfg.Version))
	mux.HandleFunc("/ops", HandleOpsWithExecutor(executor))

	verifier := newVerifier(cfg.Verify, t)
	mux.HandleFunc("/verify", handleVerify(verifier))
	mux.HandleFunc("/devices", handleDevices(verifier))
	mux.HandleFunc("/devices/refresh", handleDevicesRefresh(verifier))
	mux.HandleFunc("GET /tailnets", handleAPIInstances(verifier.store))
	mux.HandleFunc("PUT /tailnets/{instance}/devices/{deviceID}/ip", handleSetDeviceIPv4(verifier.store))
	mux.HandleFunc("PUT /tailnets/{instance}/devices/{deviceID}/authorized", handleSetDeviceAuthorized(verifier.store))
	mux.HandleFunc("PUT /tailnets/{instance}/devices/{deviceID}/name", handleSetDeviceName(verifier.store))
	mux.HandleFunc("PUT /tailnets/{instance}/devices/{deviceID}/tags", handleSetDeviceTags(verifier.store))
	mux.HandleFunc("PUT /tailnets/{instance}/devices/{deviceID}/key", handleSetDeviceKey(verifier.store))
	mux.HandleFunc("DELETE /tailnets/{instance}/devices/{deviceID}", handleDeleteDevice(verifier.store))
	mux.HandleFunc("GET /tailnets/{instance}/devices/{deviceID}/routes", handleDeviceRoutes(verifier.store))
	mux.HandleFunc("PUT /tailnets/{instance}/devices/{deviceID}/routes", handleDeviceRoutes(verifier.store))
	mux.HandleFunc("GET /tailnets/{instance}/devices/{deviceID}/attributes", handleDeviceAttributes(verifier.store))
	mux.HandleFunc("POST /tailnets/{instance}/devices/{deviceID}/attributes", handleDeviceAttributes(verifier.store))
	mux.HandleFunc("DELETE /tailnets/{instance}/devices/{deviceID}/attributes", handleDeviceAttributes(verifier.store))
	mux.HandleFunc("POST /tailnets/{instance}/devices/{deviceID}/expire", handleExpireDevice(verifier.store))
	mux.HandleFunc("GET /tailnets/{instance}/acl", handlePolicyGet(verifier.store))
	mux.HandleFunc("POST /tailnets/{instance}/acl/validate", handlePolicyValidate(verifier.store))
	mux.HandleFunc("PUT /tailnets/{instance}/acl", handlePolicySet(verifier.store))

	if t != nil {
		mux.HandleFunc("/peers", HandlePeers(t))
	}

	mux.HandleFunc("/clients", HandleClients(mf))
	return mux
}
