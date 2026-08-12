package main

import (
	"encoding/json"
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"expvar"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/LazuliKao/tailscale-derp/internal/httpjson"
	opsapi "github.com/LazuliKao/tailscale-derp/internal/ops"
	"github.com/LazuliKao/tailscale-derp/internal/service"
	"github.com/LazuliKao/tailscale-derp/internal/traffic"
	"github.com/LazuliKao/tailscale-derp/internal/tracker"

	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/net/stunserver"
	"tailscale.com/types/key"
)
var version = "dev"
var getServerMetrics opsapi.MetricsFunc
const (
	defaultNodeKeyPath   = "/var/lib/tailscale-derp/node.key"
	defaultListenAddr    = ":3478"
	defaultOpsAddr       = "127.0.0.1:9911"
	defaultHealthAddr    = ":9912"
	defaultTrafficPath   = "/tmp/tailscale-derp-traffic.json"
	defaultTrafficInterval = 60
	serviceActionTimeout = 15 * time.Second
	opsReadHeaderTimeout = 5 * time.Second
	opsReadTimeout       = 15 * time.Second
	opsWriteTimeout      = 15 * time.Second
	opsIdleTimeout       = 30 * time.Second
)

type Config struct {
	VerifyClientURLs     []string
	VerifyClientFailOpen bool
	Enabled              bool
	Listen               string
	STUN                 bool
	CertFile             string
	KeyFile              string
	Mesh                 bool
	MeshKey              string
	OpsAddr              string
	Health               string
	TrafficPersist       bool
	TrafficPath          string
	TrafficInterval      int
}

type Status = opsapi.Status

type ActionResult = opsapi.ActionResult

type runtimeState struct {
	mu      sync.RWMutex
	running bool
	err     string
}

func (s *runtimeState) setRunning(running bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.running = running
	if running {
		s.err = ""
	}
}

func (s *runtimeState) setError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.running = false
	if err == nil {
		s.err = ""
		return
	}
	s.err = err.Error()
}

func (s *runtimeState) snapshot() (bool, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running, s.err
}

type configFlags struct {
	VerifyClientURLs     *string
	VerifyClientFailOpen *bool
	Enabled    *bool
	Listen     *string
	STUN       *bool
	CertFile   *string
	KeyFile    *string
	Mesh       *bool
	MeshKey    *string
	OpsAddr    *string
	HealthAddr *string
	TrafficPersist  *bool
	TrafficPath     *string
	TrafficInterval *int
	ConfigPath *string
}

type uciConfig struct {
	values map[string]map[string][]string
}

type actionExecutor = opsapi.Executor

var execServiceAction actionExecutor = runServiceAction

const serviceScriptPath = service.DefaultScriptPath

func isLoopbackOpsAddress(value string) bool {
	trimmed := strings.TrimSpace(value)

	if trimmed == "" {
		return false
	}

	if strings.HasPrefix(trimmed, ":") {
		return false
	}

	for _, prefix := range []string{"127.0.0.1:", "localhost:", "[::1]:"} {
		if port, ok := strings.CutPrefix(trimmed, prefix); ok {
			_, err := strconv.Atoi(port)
			return err == nil
		}
	}

	return false
}

func newFlagSet(args []string) (*flag.FlagSet, *configFlags, error) {
	fs := flag.NewFlagSet("tailscale-derp", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	flags := &configFlags{
		VerifyClientURLs:     fs.String("verify-client-urls", "", "comma-separated admission controller URLs for verifying clients"),
		VerifyClientFailOpen: fs.Bool("verify-client-fail-open", false, "allow clients if admission controller is unreachable"),
		Enabled:    fs.Bool("enabled", false, "enable DERP service"),
		Listen:     fs.String("listen", "", "listen address"),
		STUN:       fs.Bool("stun", false, "enable STUN"),
		CertFile:   fs.String("certfile", "", "TLS certificate file"),
		KeyFile:    fs.String("keyfile", "", "TLS key file"),
		Mesh:       fs.Bool("mesh", false, "enable mesh mode"),
		MeshKey:    fs.String("mesh-key", "", "shared mesh key"),
		OpsAddr:    fs.String("ops", "", "ops server address"),
		HealthAddr: fs.String("health", "", "health server address"),
		TrafficPersist:  fs.Bool("traffic-persist", false, "enable traffic statistics persistence"),
		TrafficPath:     fs.String("traffic-path", "", "path to traffic statistics file"),
		TrafficInterval: fs.Int("traffic-interval", 0, "traffic save interval in seconds"),
		ConfigPath: fs.String("config", defaultConfigPath(), "UCI config path"),
	}

	if err := fs.Parse(args); err != nil {
		return nil, nil, err
	}

	return fs, flags, nil
}

func defaultConfigPath() string {
	if path := os.Getenv("GO_TAILSCALE_DERP_CONFIG"); path != "" {
		return path
	}

	return "/etc/config/tailscale-derp"
}

func validateOptionalPortBinding(name, value string) error {
	if !strings.HasPrefix(value, ":") {
		return nil
	}

	port, _ := strings.CutPrefix(value, ":")
	if _, err := strconv.Atoi(port); err != nil {
		return fmt.Errorf("%s must use a valid port", name)
	}

	return nil
}

func parseBoolValue(value string) (bool, error) {
	switch strings.TrimSpace(strings.ToLower(value)) {
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off", "":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean value %q", value)
	}
}

func parseUCIConfig(path string) (*uciConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	parsed := &uciConfig{values: make(map[string]map[string][]string)}
	scanner := bufio.NewScanner(file)
	currentSection := ""

	for lineNum := 1; scanner.Scan(); lineNum++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		switch fields[0] {
		case "config":
			if len(fields) < 3 {
				return nil, fmt.Errorf("invalid config declaration on line %d", lineNum)
			}
			currentSection = trimQuotes(fields[2])
			parsed.values[currentSection] = make(map[string][]string)
		case "option":
			if currentSection == "" || len(fields) < 3 {
				return nil, fmt.Errorf("invalid option declaration on line %d", lineNum)
			}
			key := trimQuotes(fields[1])
			value := trimQuotes(strings.Join(fields[2:], " "))
			parsed.values[currentSection][key] = []string{value}
		case "list":
			if currentSection == "" || len(fields) < 3 {
				return nil, fmt.Errorf("invalid list declaration on line %d", lineNum)
			}
			key := trimQuotes(fields[1])
			value := trimQuotes(strings.Join(fields[2:], " "))
			parsed.values[currentSection][key] = append(parsed.values[currentSection][key], value)
		default:
			return nil, fmt.Errorf("unsupported directive %q on line %d", fields[0], lineNum)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return parsed, nil
}

func trimQuotes(value string) string {
	return strings.Trim(value, "'\"")
}

func boolFlagProvided(fs *flag.FlagSet, name string) bool {
	provided := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			provided = true
		}
	})
	return provided
}

func stringFlagProvided(fs *flag.FlagSet, name string) bool {
	return boolFlagProvided(fs, name)
}

func buildConfig(args []string, openFile func(string) (*uciConfig, error)) (*Config, error) {
	fs, flags, err := newFlagSet(args)
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		Enabled: false,
		Listen:  defaultListenAddr,
		STUN:    true,
		OpsAddr: defaultOpsAddr,
		Health:  defaultHealthAddr,
		TrafficPath: defaultTrafficPath,
		TrafficInterval: defaultTrafficInterval,
	}

	if flags.ConfigPath != nil && *flags.ConfigPath != "" {
		uci, err := openFile(*flags.ConfigPath)
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, err
			}
		} else {
			if err := applyUCIConfig(cfg, uci); err != nil {
				return nil, err
			}
		}
	}

	applyFlagOverrides(cfg, fs, flags)
	if strings.TrimSpace(cfg.TrafficPath) == "" {
		cfg.TrafficPath = defaultTrafficPath
	}
	if cfg.TrafficInterval <= 0 {
		cfg.TrafficInterval = defaultTrafficInterval
	}
	return cfg, nil
}

func applyUCIConfig(cfg *Config, parsed *uciConfig) error {
	if parsed == nil {
		return nil
	}

	if value, ok := parsed.first("global", "enabled"); ok {
		parsedBool, err := parseBoolValue(value)
		if err != nil {
			return fmt.Errorf("global.enabled: %w", err)
		}
		cfg.Enabled = parsedBool
	}

	if value, ok := parsed.first("global", "listen"); ok && value != "" {
		cfg.Listen = value
	}

	if value, ok := parsed.first("global", "stun"); ok {
		parsedBool, err := parseBoolValue(value)
		if err != nil {
			return fmt.Errorf("global.stun: %w", err)
		}
		cfg.STUN = parsedBool
	}

	if value, ok := parsed.first("tls", "certfile"); ok {
		cfg.CertFile = value
	}

	if value, ok := parsed.first("tls", "keyfile"); ok {
		cfg.KeyFile = value
	}

	if value, ok := parsed.first("mesh", "enabled"); ok {
		parsedBool, err := parseBoolValue(value)
		if err != nil {
			return fmt.Errorf("mesh.enabled: %w", err)
		}
		cfg.Mesh = parsedBool
	}

	if value, ok := parsed.first("mesh", "key"); ok {
		cfg.MeshKey = strings.TrimSpace(value)
	}

	if value, ok := parsed.first("ops", "metrics"); ok && value != "" {
		cfg.OpsAddr = value
	}

	if value, ok := parsed.first("ops", "health"); ok && value != "" {
		cfg.Health = value
	}

	if value, ok := parsed.first("traffic", "persist"); ok {
		parsedBool, err := parseBoolValue(value)
		if err != nil {
			return fmt.Errorf("traffic.persist: %w", err)
		}
		cfg.TrafficPersist = parsedBool
	}

	if value, ok := parsed.first("traffic", "path"); ok && value != "" {
		cfg.TrafficPath = value
	}

	if value, ok := parsed.first("traffic", "interval"); ok && value != "" {
		parsedInt, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("traffic.interval: %w", err)
		}
		cfg.TrafficInterval = parsedInt
	}

	var verifyURLs []string
	for _, u := range parsed.get("verify", "url") {
		for _, part := range strings.Split(u, ",") {
			trimmed := strings.TrimSpace(part)
			if trimmed != "" {
				verifyURLs = append(verifyURLs, trimmed)
			}
		}
	}
	cfg.VerifyClientURLs = verifyURLs

	if value, ok := parsed.first("verify", "fail_open"); ok {
		parsedBool, err := parseBoolValue(value)
		if err != nil {
			return fmt.Errorf("verify.fail_open: %w", err)
		}
		cfg.VerifyClientFailOpen = parsedBool
	}

	return nil
}

func (u *uciConfig) first(section, key string) (string, bool) {
	if u == nil {
		return "", false
	}
	sectionValues, ok := u.values[section]
	if !ok {
		return "", false
	}
	values, ok := sectionValues[key]
	if !ok || len(values) == 0 {
		return "", false
	}
	return values[0], true
}

func (u *uciConfig) get(section, key string) []string {
	if u == nil {
		return nil
	}
	sectionValues, ok := u.values[section]
	if !ok {
		return nil
	}
	return sectionValues[key]
}

func applyFlagOverrides(cfg *Config, fs *flag.FlagSet, flags *configFlags) {
	if boolFlagProvided(fs, "enabled") {
		cfg.Enabled = *flags.Enabled
	}
	if stringFlagProvided(fs, "listen") {
		cfg.Listen = strings.TrimSpace(*flags.Listen)
	}
	if boolFlagProvided(fs, "stun") {
		cfg.STUN = *flags.STUN
	}
	if stringFlagProvided(fs, "certfile") {
		cfg.CertFile = strings.TrimSpace(*flags.CertFile)
	}
	if stringFlagProvided(fs, "keyfile") {
		cfg.KeyFile = strings.TrimSpace(*flags.KeyFile)
	}
	if boolFlagProvided(fs, "mesh") {
		cfg.Mesh = *flags.Mesh
	}
	if stringFlagProvided(fs, "mesh-key") {
		cfg.MeshKey = strings.TrimSpace(*flags.MeshKey)
	}
	if stringFlagProvided(fs, "ops") {
		cfg.OpsAddr = strings.TrimSpace(*flags.OpsAddr)
	}
	if stringFlagProvided(fs, "health") {
		cfg.Health = strings.TrimSpace(*flags.HealthAddr)
	}
	if boolFlagProvided(fs, "traffic-persist") {
		cfg.TrafficPersist = *flags.TrafficPersist
	}
	if stringFlagProvided(fs, "traffic-path") {
		cfg.TrafficPath = strings.TrimSpace(*flags.TrafficPath)
	}
	if stringFlagProvided(fs, "traffic-interval") {
		cfg.TrafficInterval = *flags.TrafficInterval
	}
	if stringFlagProvided(fs, "verify-client-urls") {
		for _, part := range strings.Split(*flags.VerifyClientURLs, ",") {
			trimmed := strings.TrimSpace(part)
			if trimmed != "" {
				cfg.VerifyClientURLs = append(cfg.VerifyClientURLs, trimmed)
			}
		}
	}
	if boolFlagProvided(fs, "verify-client-fail-open") {
		cfg.VerifyClientFailOpen = *flags.VerifyClientFailOpen
	}
}

func loadConfig() (*Config, error) {
	return buildConfig(os.Args[1:], parseUCIConfig)
}

func validateConfig(cfg *Config) error {
	if cfg.Listen == "" {
		return fmt.Errorf("listen address is required")
	}
	if cfg.Mesh && cfg.MeshKey == "" {
		return fmt.Errorf("mesh requires a shared key")
	}
	if cfg.CertFile != "" && cfg.KeyFile == "" {
		return fmt.Errorf("certfile requires keyfile")
	}
	if cfg.KeyFile != "" && cfg.CertFile == "" {
		return fmt.Errorf("keyfile requires certfile")
	}
	if err := validateOptionalPortBinding("listen", cfg.Listen); err != nil {
		return err
	}
	if err := validateOptionalPortBinding("ops", cfg.OpsAddr); err != nil {
		return err
	}
	if !isLoopbackOpsAddress(cfg.OpsAddr) {
		return fmt.Errorf("ops must bind to loopback only")
	}
	if err := validateOptionalPortBinding("health", cfg.Health); err != nil {
		return err
	}
	return nil
}

func startDERP(cfg *Config, state *runtimeState, persister *traffic.Persister) error {
	privateKey, err := loadOrCreateNodeKey(defaultNodeKeyPath)
	if err != nil {
		if state != nil {
			state.setError(err)
		}
		return fmt.Errorf("load node key: %w", err)
	}

	server := derp.NewServer(privateKey, log.Printf)
	if cfg.Mesh {
		server.SetMeshKey(cfg.MeshKey)
	}
	server.SetVerifyClient(true)
	opsAddr := cfg.OpsAddr
	if opsAddr == "" {
		opsAddr = defaultOpsAddr
	}
	if strings.HasPrefix(opsAddr, ":") {
		opsAddr = "127.0.0.1" + opsAddr
	}
	admissionURL := fmt.Sprintf("http://%s/verify", opsAddr)
	server.SetVerifyClientURL(admissionURL)
	if cfg.VerifyClientFailOpen {
		server.SetVerifyClientURLFailOpen(true)
	}
	log.Printf("Verify-client always enabled for peer tracking, admission controller at %s (fail-open: %v, external URLs: %d)", admissionURL, cfg.VerifyClientFailOpen, len(cfg.VerifyClientURLs))
	serverExpVar := publishDERPMetrics(server)
	getServerMetrics = func() json.RawMessage {
		return json.RawMessage(serverExpVar.String())
	}
	if persister != nil {
		if err := persister.Load(); err != nil {
			if state != nil {
				state.setError(err)
			}
			return fmt.Errorf("load traffic stats: %w", err)
		}
		trafficCtx, cancelTraffic := context.WithCancel(context.Background())
		defer cancelTraffic()
		defer func() {
			if err := persister.Save(); err != nil {
				log.Printf("Traffic stats final save failed: %v", err)
			}
		}()
		persister.Start(trafficCtx)
	}
	if cfg.STUN {
		stun := stunserver.New(context.Background())
		go func() {
			if err := stun.ListenAndServe(cfg.Listen); err != nil {
				log.Printf("STUN server stopped: %v", err)
			}
		}()
	}

	mux := http.NewServeMux()
	mux.Handle("/derp", derphttp.Handler(server))
	mux.HandleFunc("/derp/probe", derphttp.ProbeHandler)
	mux.HandleFunc("/derp/latency-check", derphttp.ProbeHandler)
	mux.HandleFunc("/generate_204", derphttp.ServeNoContent)

	httpServer := &http.Server{
		Addr:    cfg.Listen,
		Handler: mux,
	}

	log.Printf("Starting DERP server on %s", cfg.Listen)
	if state != nil {
		state.setRunning(true)
		defer state.setRunning(false)
	}
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		httpServer.TLSConfig = &tls.Config{
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				certificate, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
				if err != nil {
					return nil, err
				}
				certificate.Certificate = append(certificate.Certificate, server.MetaCert())
				return &certificate, nil
			},
		}
		err := httpServer.ListenAndServeTLS("", "")
		if state != nil && err != nil {
			state.setError(err)
		}
		return err
	}

	log.Printf("TLS cert/key not configured; serving DERP over plain HTTP for baseline testing only")
	err = httpServer.ListenAndServe()
	if state != nil && err != nil {
		state.setError(err)
	}
	return err
}

func publishDERPMetrics(server *derp.Server) expvar.Var {
	ev := server.ExpVar()
	if expvar.Get("derp") == nil {
		expvar.Publish("derp", ev)
	}
	return ev
}


func loadOrCreateNodeKey(path string) (key.NodePrivate, error) {
	raw, err := os.ReadFile(path)
	if err == nil {
		var parsed key.NodePrivate
		if parseErr := parsed.UnmarshalText(bytes.TrimSpace(raw)); parseErr != nil {
			return key.NodePrivate{}, parseErr
		}
		return parsed, nil
	}
	if !os.IsNotExist(err) {
		return key.NodePrivate{}, err
	}

	privateKey := key.NewNode()
	marshaled, err := privateKey.MarshalText()
	if err != nil {
		return key.NodePrivate{}, err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return key.NodePrivate{}, err
	}
	if err := os.WriteFile(path, append(marshaled, '\n'), 0o600); err != nil {
		return key.NodePrivate{}, err
	}

	return privateKey, nil
}

func allowedAction(action string) bool {
	return service.AllowedAction(action)
}

func runServiceAction(action string) error {
	return service.RunAction(action, serviceScriptPath, serviceActionTimeout)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	httpjson.Write(w, status, payload)
}

func extractMetricInt64(m map[string]json.RawMessage, key string) int64 {
	raw, ok := m[key]
	if !ok {
		return 0
	}

	var v int64
	json.Unmarshal(raw, &v)
	return v
}

func trafficSessionMetrics() (int64, int64, int64) {
	if getServerMetrics == nil {
		return 0, 0, 0
	}

	raw := getServerMetrics()
	if len(raw) == 0 {
		return 0, 0, 0
	}

	var metrics map[string]json.RawMessage
	if err := json.Unmarshal(raw, &metrics); err != nil {
		return 0, 0, 0
	}

	return extractMetricInt64(metrics, "bytes_received"), extractMetricInt64(metrics, "bytes_sent"), extractMetricInt64(metrics, "accepts")
}

func trafficTotalsFunc(persister *traffic.Persister) opsapi.TrafficFunc {
	if persister == nil {
		return nil
	}

	return func() *traffic.Stats {
		total := persister.Total()
		return &total
	}
}

func handleOpsWithExecutor(executor actionExecutor) http.HandlerFunc {
	if executor == nil {
		executor = execServiceAction
	}

	return opsapi.HandleOpsWithExecutor(executor)
}

func handleOps(w http.ResponseWriter, r *http.Request) {
	handleOpsWithExecutor(execServiceAction)(w, r)
}

func statusFromConfig(cfg *Config, state *runtimeState) Status {
	return statusFromConfigWithTraffic(cfg, state, nil)
}

func statusFromConfigWithTraffic(cfg *Config, state *runtimeState, persister *traffic.Persister) Status {
	var snapshot opsapi.Snapshot
	if state != nil {
		snapshot = state.snapshot
	}

	return opsapi.StatusFromConfig(opsConfig(cfg), snapshot, nil, trafficTotalsFunc(persister))
}

func opsConfig(cfg *Config) opsapi.Config {
	return opsapi.Config{
		VerifyClientURLs:     cfg.VerifyClientURLs,
		VerifyClientFailOpen: cfg.VerifyClientFailOpen,
		Version:         version,
		Listen:          cfg.Listen,
		STUN:            cfg.STUN,
		Mesh:            cfg.Mesh,
		OpsAddr:         cfg.OpsAddr,
		Health:          cfg.Health,
		TrafficPersist:  cfg.TrafficPersist,
		TrafficPath:     cfg.TrafficPath,
		TrafficInterval: cfg.TrafficInterval,
	}
}
func handleStatus(cfg *Config, state *runtimeState) http.HandlerFunc {
	return handleStatusWithTraffic(cfg, state, nil)
}

func handleStatusWithTraffic(cfg *Config, state *runtimeState, persister *traffic.Persister) http.HandlerFunc {
	var snapshot opsapi.Snapshot
	if state != nil {
		snapshot = state.snapshot
	}
	return opsapi.HandleStatus(opsConfig(cfg), snapshot, nil, trafficTotalsFunc(persister))
}

func startOps(cfg *Config, state *runtimeState, persister *traffic.Persister) error {
	log.Printf("Starting ops server on %s", cfg.OpsAddr)
	var snapshot opsapi.Snapshot
	if state != nil {
		snapshot = state.snapshot
	}
	t := tracker.NewPeerTracker()
	server := &http.Server{
		Addr:              cfg.OpsAddr,
		Handler:           opsapi.NewMux(opsConfig(cfg), snapshot, execServiceAction, getServerMetrics, t, trafficTotalsFunc(persister)),
		ReadHeaderTimeout: opsReadHeaderTimeout,
		ReadTimeout:       opsReadTimeout,
		WriteTimeout:      opsWriteTimeout,
		IdleTimeout:       opsIdleTimeout,
	}
	return server.ListenAndServe()
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("tailscale-derp %s", version)

	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if err := validateConfig(cfg); err != nil {
		log.Fatalf("Invalid config: %v", err)
	}

	state := &runtimeState{}
	var persister *traffic.Persister

	if !cfg.Enabled {
		log.Println("Service disabled")
		os.Exit(0)
	}

	if cfg.TrafficPersist {
		persister = traffic.New(true, cfg.TrafficPath, time.Duration(cfg.TrafficInterval)*time.Second, trafficSessionMetrics)
	}

	go func() {
		if err := startOps(cfg, state, persister); err != nil {
			log.Fatalf("Ops server failed: %v", err)
		}
	}()

	if err := startDERP(cfg, state, persister); err != nil {
		log.Fatalf("DERP server failed: %v", err)
	}
}
