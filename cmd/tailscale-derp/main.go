package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"expvar"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/LazuliKao/tailscale-derp/internal/cert"
	"github.com/LazuliKao/tailscale-derp/internal/derpserver"
	"github.com/LazuliKao/tailscale-derp/internal/endpoint"
	"github.com/LazuliKao/tailscale-derp/internal/httpjson"
	opsapi "github.com/LazuliKao/tailscale-derp/internal/ops"
	"github.com/LazuliKao/tailscale-derp/internal/portmap"
	"github.com/LazuliKao/tailscale-derp/internal/service"
	"github.com/LazuliKao/tailscale-derp/internal/tracker"
	"github.com/LazuliKao/tailscale-derp/internal/traffic"

	"tailscale.com/net/stunserver"
	"tailscale.com/types/key"
)

var version = "dev"
var getServerMetrics opsapi.MetricsFunc
var admissionTracker = tracker.NewPeerTracker()

const (
	defaultNodeKeyPath     = "/var/lib/tailscale-derp/node.key"
	defaultTLSStateDir     = "/var/lib/tailscale-derp/tls"
	defaultListenAddr      = ":3478"
	defaultOpsSocket       = opsapi.DefaultOpsSocketPath
	defaultHealthAddr      = ":9912"
	defaultTrafficPath     = "/tmp/tailscale-derp-traffic.json"
	defaultTrafficInterval = 60
	serviceActionTimeout   = 15 * time.Second
	opsReadHeaderTimeout   = 5 * time.Second
	opsReadTimeout         = 15 * time.Second
	opsWriteTimeout        = 15 * time.Second
	opsIdleTimeout         = 30 * time.Second
)

type Config struct {
	Verify          opsapi.VerifyConfig
	External        endpoint.Config
	Enabled         bool
	Listen          string
	STUN            bool
	CertFile        string
	KeyFile         string
	TLSMode         string
	TLSStateDir     string
	Mesh            bool
	MeshKey         string
	OpsSocket       string
	Health          string
	TrafficPersist  bool
	TrafficPath     string
	TrafficInterval int
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
	VerifyURLs      *string
	Enabled         *bool
	Listen          *string
	STUN            *bool
	CertFile        *string
	KeyFile         *string
	TLSSelfSigned   *bool
	TLSStateDir     *string
	Mesh            *bool
	MeshKey         *string
	OpsSocket       *string
	HealthAddr      *string
	TrafficPersist  *bool
	TrafficPath     *string
	TrafficInterval *int
	ConfigPath      *string
}

type uciSection struct {
	typ    string
	name   string
	values map[string][]string
}

type uciConfig struct {
	// values preserves the original lookup API used by existing code/tests.
	values   map[string]map[string][]string
	sections []uciSection
}

type actionExecutor = opsapi.Executor

var execServiceAction actionExecutor = runServiceAction

const serviceScriptPath = service.DefaultScriptPath

func newFlagSet(args []string) (*flag.FlagSet, *configFlags, error) {
	fs := flag.NewFlagSet("tailscale-derp", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	flags := &configFlags{
		VerifyURLs:      fs.String("verify-client-urls", "", "comma-separated admission controller URLs for verifying clients"),
		Enabled:         fs.Bool("enabled", false, "enable DERP service"),
		Listen:          fs.String("listen", "", "listen address"),
		STUN:            fs.Bool("stun", false, "enable STUN"),
		CertFile:        fs.String("certfile", "", "TLS certificate file"),
		KeyFile:         fs.String("keyfile", "", "TLS key file"),
		TLSSelfSigned:   fs.Bool("tls-self-signed", false, "generate and manage a self-signed TLS certificate"),
		TLSStateDir:     fs.String("tls-state-dir", "", "automatic TLS certificate state directory"),
		Mesh:            fs.Bool("mesh", false, "enable mesh mode"),
		MeshKey:         fs.String("mesh-key", "", "shared mesh key"),
		OpsSocket:       fs.String("ops-socket", "", "ops server Unix socket path"),
		HealthAddr:      fs.String("health", "", "health server address"),
		TrafficPersist:  fs.Bool("traffic-persist", false, "enable traffic statistics persistence"),
		TrafficPath:     fs.String("traffic-path", "", "path to traffic statistics file"),
		TrafficInterval: fs.Int("traffic-interval", 0, "traffic save interval in seconds"),
		ConfigPath:      fs.String("config", defaultConfigPath(), "UCI config path"),
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
	currentType := ""

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
			if len(fields) < 2 {
				return nil, fmt.Errorf("invalid config declaration on line %d", lineNum)
			}
			currentType = trimQuotes(fields[1])
			currentSection = ""
			if len(fields) >= 3 {
				currentSection = trimQuotes(fields[2])
			}
			if currentSection == "" {
				for index := 1; ; index++ {
					candidate := fmt.Sprintf("%s_%d", currentType, index)
					if _, exists := parsed.values[candidate]; !exists {
						currentSection = candidate
						break
					}
				}
			}
			sectionValues := make(map[string][]string)
			parsed.values[currentSection] = sectionValues
			parsed.sections = append(parsed.sections, uciSection{
				typ:    currentType,
				name:   currentSection,
				values: sectionValues,
			})
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
		Enabled:         false,
		Listen:          defaultListenAddr,
		STUN:            true,
		OpsSocket:       defaultOpsSocket,
		Health:          defaultHealthAddr,
		TrafficPath:     defaultTrafficPath,
		TrafficInterval: defaultTrafficInterval,
		TLSMode:         "manual",
		TLSStateDir:     defaultTLSStateDir,
		Verify: opsapi.VerifyConfig{
			SyncInterval: 5 * time.Minute,
			CacheTTL:     15 * time.Minute,
		},
		External: endpoint.Config{
			Mode:          endpoint.ModeNAT,
			Methods:       []string{"pcp", "natpmp", "upnp"},
			WANInterface:  "auto",
			DERPPort:      "auto",
			STUNPort:      "auto",
			LeaseDuration: 2 * time.Hour,
			RetryInterval: time.Minute,
			SyncInterval:  5 * time.Minute,
		},
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
	cfg.External.STUNEnabled = cfg.STUN
	cfg.External.TLSConfigured = cfg.TLSMode == "self_signed" || (cfg.CertFile != "" && cfg.KeyFile != "")
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
	if value, ok := parsed.first("tls", "mode"); ok && strings.TrimSpace(value) != "" {
		cfg.TLSMode = strings.ToLower(strings.TrimSpace(value))
	}
	if value, ok := parsed.first("tls", "state_dir"); ok && strings.TrimSpace(value) != "" {
		cfg.TLSStateDir = strings.TrimSpace(value)
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

	if value, ok := parsed.first("ops", "socket"); ok && strings.TrimSpace(value) != "" {
		cfg.OpsSocket = strings.TrimSpace(value)
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

	if value, ok := parsed.first("external", "enabled"); ok {
		parsedBool, err := parseBoolValue(value)
		if err != nil {
			return fmt.Errorf("external.enabled: %w", err)
		}
		cfg.External.Enabled = parsedBool
	}
	if value, ok := parsed.first("external", "mode"); ok && strings.TrimSpace(value) != "" {
		cfg.External.Mode = strings.ToLower(strings.TrimSpace(value))
	}
	if methods := parsed.get("external", "method"); len(methods) > 0 {
		cfg.External.Methods = nil
		for _, method := range methods {
			for _, part := range strings.Split(method, ",") {
				if part = strings.ToLower(strings.TrimSpace(part)); part != "" {
					cfg.External.Methods = append(cfg.External.Methods, part)
				}
			}
		}
	}
	if value, ok := parsed.first("external", "wan_interface"); ok && strings.TrimSpace(value) != "" {
		cfg.External.WANInterface = strings.TrimSpace(value)
	}
	if value, ok := parsed.first("external", "derp_port"); ok && strings.TrimSpace(value) != "" {
		cfg.External.DERPPort = strings.TrimSpace(value)
	}
	if value, ok := parsed.first("external", "stun_port"); ok && strings.TrimSpace(value) != "" {
		cfg.External.STUNPort = strings.TrimSpace(value)
	}
	if value, ok := parsed.first("external", "lease_seconds"); ok {
		seconds, err := strconv.Atoi(value)
		if err != nil || seconds <= 0 {
			return fmt.Errorf("external.lease_seconds: must be a positive number")
		}
		cfg.External.LeaseDuration = time.Duration(seconds) * time.Second
	}
	if value, ok := parsed.first("external", "retry_seconds"); ok {
		seconds, err := strconv.Atoi(value)
		if err != nil || seconds <= 0 {
			return fmt.Errorf("external.retry_seconds: must be a positive number")
		}
		cfg.External.RetryInterval = time.Duration(seconds) * time.Second
	}
	if value, ok := parsed.first("external", "sync_interval"); ok {
		seconds, err := strconv.Atoi(value)
		if err != nil || seconds <= 0 {
			return fmt.Errorf("external.sync_interval: must be a positive number")
		}
		cfg.External.SyncInterval = time.Duration(seconds) * time.Second
	}
	if value, ok := parsed.first("external", "validate_endpoint"); ok {
		parsedBool, err := parseBoolValue(value)
		if err != nil {
			return fmt.Errorf("external.validate_endpoint: %w", err)
		}
		cfg.External.ValidateEndpoint = parsedBool
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
	cfg.Verify.URLs = verifyURLs

	verifyEnabledSet := false
	if value, ok := parsed.first("verify", "enabled"); ok {
		parsedBool, err := parseBoolValue(value)
		if err != nil {
			return fmt.Errorf("verify.enabled: %w", err)
		}
		cfg.Verify.Enabled = parsedBool
		verifyEnabledSet = true
	}

	urlEnabledSet := false
	if value, ok := parsed.first("verify", "url_enabled"); ok {
		parsedBool, err := parseBoolValue(value)
		if err != nil {
			return fmt.Errorf("verify.url_enabled: %w", err)
		}
		cfg.Verify.URLsEnabled = parsedBool
		urlEnabledSet = true
	}
	if value, ok := parsed.first("verify", "tailscaled_enabled"); ok {
		parsedBool, err := parseBoolValue(value)
		if err != nil {
			return fmt.Errorf("verify.tailscaled_enabled: %w", err)
		}
		cfg.Verify.TailscaledEnabled = parsedBool
	}
	if value, ok := parsed.first("verify", "tailscaled_socket_enabled"); ok {
		parsedBool, err := parseBoolValue(value)
		if err != nil {
			return fmt.Errorf("verify.tailscaled_socket_enabled: %w", err)
		}
		cfg.Verify.TailscaledSocketEnabled = parsedBool
	}
	if value, ok := parsed.first("verify", "tailscaled_socket"); ok {
		cfg.Verify.TailscaledSocket = strings.TrimSpace(value)
	}
	if value, ok := parsed.first("verify", "api_enabled"); ok {
		parsedBool, err := parseBoolValue(value)
		if err != nil {
			return fmt.Errorf("verify.api_enabled: %w", err)
		}
		cfg.Verify.APIEnabled = parsedBool
	}

	if value, ok := parsed.first("verify", "sync_interval"); ok && value != "" {
		seconds, err := strconv.Atoi(value)
		if err != nil || seconds <= 0 {
			return fmt.Errorf("verify.sync_interval: must be a positive number")
		}
		cfg.Verify.SyncInterval = time.Duration(seconds) * time.Second
	}
	if value, ok := parsed.first("verify", "cache_ttl"); ok && value != "" {
		seconds, err := strconv.Atoi(value)
		if err != nil || seconds <= 0 {
			return fmt.Errorf("verify.cache_ttl: must be a positive number")
		}
		cfg.Verify.CacheTTL = time.Duration(seconds) * time.Second
	}

	for _, section := range parsed.sectionsOfType("verify_api") {
		tailnet := firstSectionValue(section, "tailnet")
		if tailnet == "" {
			tailnet = "-"
		}
		authType := opsapi.APIAuthTypeAPIKey
		if value, ok := section.values["auth_type"]; ok && len(value) > 0 && strings.TrimSpace(value[0]) != "" {
			authType = opsapi.APIAuthType(strings.TrimSpace(value[0]))
		}
		if authType != opsapi.APIAuthTypeAPIKey && authType != opsapi.APIAuthTypeOAuth {
			return fmt.Errorf("verify_api.%s.auth_type: must be api_key or oauth", section.name)
		}
		derpMapSync := false
		if value := firstSectionValue(section, "derpmap_sync"); value != "" {
			parsedBool, err := parseBoolValue(value)
			if err != nil {
				return fmt.Errorf("verify_api.%s.derpmap_sync: %w", section.name, err)
			}
			derpMapSync = parsedBool
		}
		regionID := 0
		if value := firstSectionValue(section, "region_id"); value != "" {
			parsedRegionID, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("verify_api.%s.region_id: must be an integer", section.name)
			}
			regionID = parsedRegionID
		}
		apiConfig := opsapi.APIConfig{
			Name:              section.name,
			Label:             firstSectionValue(section, "label"),
			Tailnet:           tailnet,
			AuthType:          authType,
			APIKey:            firstSectionValue(section, "api_key"),
			OAuthClientID:     firstSectionValue(section, "oauth_client_id"),
			OAuthClientSecret: firstSectionValue(section, "oauth_client_secret"),
			DERPMapSync:       derpMapSync,
			RegionID:          regionID,
			RegionCode:        firstSectionValue(section, "region_code"),
			RegionName:        firstSectionValue(section, "region_name"),
			NodeName:          firstSectionValue(section, "node_name"),
			Hostname:          firstSectionValue(section, "hostname"),
			CertName:          firstSectionValue(section, "cert_name"),
		}
		cfg.Verify.APIs = append(cfg.Verify.APIs, apiConfig)
		if apiConfig.DERPMapSync {
			validationName := apiConfig.CertName
			if cfg.TLSMode == "self_signed" || validationName == "" {
				validationName = apiConfig.Hostname
			}
			cfg.External.ValidationNames = append(cfg.External.ValidationNames, validationName)
		}
	}
	cfg.External.STUNEnabled = cfg.STUN
	cfg.External.TLSConfigured = cfg.TLSMode == "self_signed" || (cfg.CertFile != "" && cfg.KeyFile != "")

	// Existing URL-only configurations remain active without requiring a
	// manual migration. New configurations have no URL and stay disabled.
	if len(verifyURLs) > 0 {
		if !verifyEnabledSet {
			cfg.Verify.Enabled = true
		}
		if !urlEnabledSet {
			cfg.Verify.URLsEnabled = true
		}
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

func (u *uciConfig) sectionsOfType(sectionType string) []uciSection {
	if u == nil {
		return nil
	}
	var sections []uciSection
	for _, section := range u.sections {
		if section.typ == sectionType {
			sections = append(sections, section)
		}
	}
	return sections
}

func firstSectionValue(section uciSection, key string) string {
	values := section.values[key]
	if len(values) == 0 {
		return ""
	}
	return strings.TrimSpace(values[0])
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
	if boolFlagProvided(fs, "tls-self-signed") {
		if *flags.TLSSelfSigned {
			cfg.TLSMode = "self_signed"
		} else {
			cfg.TLSMode = "manual"
		}
	}
	if stringFlagProvided(fs, "tls-state-dir") {
		cfg.TLSStateDir = strings.TrimSpace(*flags.TLSStateDir)
	}
	if boolFlagProvided(fs, "mesh") {
		cfg.Mesh = *flags.Mesh
	}
	if stringFlagProvided(fs, "mesh-key") {
		cfg.MeshKey = strings.TrimSpace(*flags.MeshKey)
	}
	if stringFlagProvided(fs, "ops-socket") {
		cfg.OpsSocket = strings.TrimSpace(*flags.OpsSocket)
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
		for _, part := range strings.Split(*flags.VerifyURLs, ",") {
			trimmed := strings.TrimSpace(part)
			if trimmed != "" {
				cfg.Verify.URLs = append(cfg.Verify.URLs, trimmed)
			}
		}
		cfg.Verify.Enabled = true
		cfg.Verify.URLsEnabled = true
	}
}

func loadConfig() (*Config, error) {
	cfg, err := buildConfig(os.Args[1:], parseUCIConfig)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

func validateConfig(cfg *Config) error {
	if cfg.TLSMode == "" {
		cfg.TLSMode = "manual"
	}
	if cfg.External.Mode == "" {
		cfg.External.Mode = endpoint.ModeNAT
	}
	if cfg.External.WANInterface == "" {
		cfg.External.WANInterface = "auto"
	}
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
	if cfg.TLSMode != "manual" && cfg.TLSMode != "self_signed" {
		return fmt.Errorf("tls.mode must be manual or self_signed")
	}
	if cfg.TLSMode == "self_signed" && (cfg.CertFile != "" || cfg.KeyFile != "") {
		return fmt.Errorf("self_signed TLS does not use certfile or keyfile")
	}
	if cfg.TLSMode == "self_signed" && strings.TrimSpace(cfg.TLSStateDir) == "" {
		return fmt.Errorf("self_signed TLS requires state_dir")
	}
	if err := validateOptionalPortBinding("listen", cfg.Listen); err != nil {
		return err
	}
	if err := validateOptionalPortBinding("health", cfg.Health); err != nil {
		return err
	}
	if err := validateExternalPort("external.derp_port", cfg.External.DERPPort); err != nil {
		return err
	}
	if err := validateExternalPort("external.stun_port", cfg.External.STUNPort); err != nil {
		return err
	}
	allowedMethods := map[string]bool{"pcp": true, "natpmp": true, "upnp": true}
	if cfg.External.Mode != endpoint.ModeNAT && cfg.External.Mode != endpoint.ModeDirect {
		return fmt.Errorf("external.mode must be direct or nat")
	}
	if cfg.External.Enabled && cfg.External.Mode == endpoint.ModeNAT && len(cfg.External.Methods) == 0 {
		return fmt.Errorf("external requires at least one mapping method")
	}
	for _, method := range cfg.External.Methods {
		if !allowedMethods[method] {
			return fmt.Errorf("external.method: unsupported method %q", method)
		}
	}
	for _, api := range cfg.Verify.APIs {
		if !api.DERPMapSync {
			continue
		}
		if !cfg.External.Enabled {
			return fmt.Errorf("verify_api.%s.derpmap_sync requires external.enabled", api.Name)
		}
		if !api.Configured() {
			return fmt.Errorf("verify_api.%s.derpmap_sync requires tailnet and API credentials", api.Name)
		}
		if api.RegionID < 900 || api.RegionID > 999 {
			return fmt.Errorf("verify_api.%s.region_id must be between 900 and 999", api.Name)
		}
		if strings.TrimSpace(api.RegionCode) == "" || strings.TrimSpace(api.RegionName) == "" || strings.TrimSpace(api.NodeName) == "" || strings.TrimSpace(api.Hostname) == "" {
			return fmt.Errorf("verify_api.%s DERP map metadata is incomplete", api.Name)
		}
	}
	if cfg.External.Enabled && !cfg.External.TLSConfigured {
		return fmt.Errorf("external endpoint publishing requires TLS")
	}
	return nil
}

func selfSignedNames(cfg *Config) []string {
	var names []string
	for _, api := range cfg.Verify.APIs {
		if api.DERPMapSync {
			names = append(names, api.Hostname)
		}
	}
	return names
}

func validateExternalPort(name, value string) error {
	if value == "" || strings.EqualFold(value, "auto") {
		return nil
	}
	port, err := strconv.ParseUint(value, 10, 16)
	if err != nil || port == 0 {
		return fmt.Errorf("%s must be auto or an integer from 1 to 65535", name)
	}
	return nil
}

func startDERP(ctx context.Context, cfg *Config, state *runtimeState, persister *traffic.Persister, runtime *opsapi.Runtime, external *endpoint.Manager, automaticTLS *cert.Manager) error {
	privateKey, err := loadOrCreateNodeKey(defaultNodeKeyPath)
	if err != nil {
		if state != nil {
			state.setError(err)
		}
		return fmt.Errorf("load node key: %w", err)
	}

	server := derpserver.New(privateKey, log.Printf)
	if cfg.Mesh {
		if err := server.SetMeshKey(cfg.MeshKey); err != nil {
			if state != nil {
				state.setError(err)
			}
			return fmt.Errorf("parse mesh key: %w", err)
		}
	}
	if cfg.Verify.Enabled {
		if runtime != nil {
			server.SetVerifyClientFunc(runtime.VerifyClientFunc())
		} else {
			server.SetVerifyClientFunc(opsapi.NewVerifyClientFunc(cfg.Verify, admissionTracker))
		}
		log.Printf("Client verification enabled (urls: %v, tailscaled: %v, official API: %v)", cfg.Verify.URLsEnabled, cfg.Verify.TailscaledEnabled, cfg.Verify.APIEnabled)
	} else {
		log.Printf("Client verification disabled")
	}
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
	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen for DERP: %w", err)
	}
	defer listener.Close()
	derpPort, err := addressPort(listener.Addr())
	if err != nil {
		return err
	}
	var stunPort uint16
	if cfg.STUN {
		stun := stunserver.New(ctx)
		if err := stun.Listen(cfg.Listen); err != nil {
			return fmt.Errorf("listen for STUN: %w", err)
		}
		stunPort, err = addressPort(stun.LocalAddr())
		if err != nil {
			return err
		}
		go func() {
			if err := stun.Serve(); err != nil {
				log.Printf("STUN server stopped: %v", err)
			}
		}()
	}
	if external != nil {
		external.SetLocalPorts(derpPort, stunPort)
	}

	mux := http.NewServeMux()
	mux.Handle("/derp", derpserver.Handler(server))
	mux.HandleFunc("/derp/probe", derpserver.ProbeHandler)
	mux.HandleFunc("/derp/latency-check", derpserver.ProbeHandler)
	mux.HandleFunc("/generate_204", derpserver.ServeNoContent)

	httpServer := &http.Server{
		Addr:    cfg.Listen,
		Handler: mux,
	}

	log.Printf("Starting DERP server on %s", cfg.Listen)
	if state != nil {
		state.setRunning(true)
		defer state.setRunning(false)
	}
	if automaticTLS != nil {
		httpServer.TLSConfig = &tls.Config{
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				certificate, err := automaticTLS.GetCertificate(hello)
				if err != nil {
					return nil, err
				}
				copy := *certificate
				copy.Certificate = append(append([][]byte(nil), certificate.Certificate...), server.MetaCert())
				return &copy, nil
			},
		}
		err := httpServer.ServeTLS(listener, "", "")
		if state != nil && err != nil {
			state.setError(err)
		}
		return err
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
		err := httpServer.ServeTLS(listener, "", "")
		if state != nil && err != nil {
			state.setError(err)
		}
		return err
	}

	log.Printf("TLS cert/key not configured; serving DERP over plain HTTP for baseline testing only")
	err = httpServer.Serve(listener)
	if state != nil && err != nil {
		state.setError(err)
	}
	return err
}

func addressPort(address net.Addr) (uint16, error) {
	_, rawPort, err := net.SplitHostPort(address.String())
	if err != nil {
		return 0, fmt.Errorf("parse listener address %q: %w", address, err)
	}
	port, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil || port == 0 {
		return 0, fmt.Errorf("listener returned invalid port %q", rawPort)
	}
	return uint16(port), nil
}

func publishDERPMetrics(server *derpserver.Server) expvar.Var {
	ev := server.ExpVar(false)
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
		Verify:          cfg.Verify,
		Version:         version,
		Listen:          cfg.Listen,
		STUN:            cfg.STUN,
		Mesh:            cfg.Mesh,
		OpsSocket:       cfg.OpsSocket,
		Health:          cfg.Health,
		TrafficPersist:  cfg.TrafficPersist,
		TrafficPath:     cfg.TrafficPath,
		TrafficInterval: cfg.TrafficInterval,
		ExternalEnabled: cfg.External.Enabled,
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

func startOps(cfg *Config, state *runtimeState, persister *traffic.Persister, runtime *opsapi.Runtime, external *endpoint.Manager) error {
	listenAddr := cfg.OpsSocket
	if listenAddr == "" {
		listenAddr = defaultOpsSocket
	}
	log.Printf("Starting ops server on %s", listenAddr)
	var snapshot opsapi.Snapshot
	if state != nil {
		snapshot = state.snapshot
	}
	server := &http.Server{
		Addr:              listenAddr,
		Handler:           opsapi.NewMuxWithRuntime(opsConfig(cfg), snapshot, execServiceAction, getServerMetrics, admissionTracker, trafficTotalsFunc(persister), runtime, external),
		ReadHeaderTimeout: opsReadHeaderTimeout,
		ReadTimeout:       opsReadTimeout,
		WriteTimeout:      opsWriteTimeout,
		IdleTimeout:       opsIdleTimeout,
	}
	listener, err := opsapi.ListenUnix(listenAddr)
	if err != nil {
		if state != nil {
			state.setError(err)
		}
		return err
	}
	defer func() {
		if err := listener.Close(); err != nil {
			log.Printf("Ops Unix socket cleanup failed: %v", err)
		}
	}()
	return server.Serve(listener)
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if !cfg.Enabled {
		log.Println("Service disabled")
		os.Exit(0)
	}

	if cfg.TrafficPersist {
		persister = traffic.New(true, cfg.TrafficPath, time.Duration(cfg.TrafficInterval)*time.Second, trafficSessionMetrics)
	}
	var automaticTLS *cert.Manager
	if cfg.TLSMode == "self_signed" {
		automaticTLS, err = cert.NewManager(cfg.TLSStateDir, selfSignedNames(cfg))
		if err != nil {
			log.Fatalf("Initialize automatic TLS certificate: %v", err)
		}
	}
	if cfg.External.Enabled && automaticTLS == nil {
		if _, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile); err != nil {
			log.Fatalf("Invalid TLS certificate for external endpoint publishing: %v", err)
		}
	}
	runtime := opsapi.NewRuntime(ctx, cfg.Verify, admissionTracker)
	if automaticTLS != nil {
		runtime.SetCertificateNameProvider(automaticTLS)
	}
	validator := endpoint.LocalValidator{}
	if automaticTLS != nil {
		validator.ExpectedCertHash = automaticTLS.ExpectedCertHash
	}
	external := endpoint.NewManager(cfg.External, portmap.NewClient(cfg.External.Methods), validator, runtime, automaticTLS)
	external.Start(ctx)

	go func() {
		if err := startOps(cfg, state, persister, runtime, external); err != nil {
			log.Fatalf("Ops server failed: %v", err)
		}
	}()

	if err := startDERP(ctx, cfg, state, persister, runtime, external, automaticTLS); err != nil {
		log.Fatalf("DERP server failed: %v", err)
	}
}
