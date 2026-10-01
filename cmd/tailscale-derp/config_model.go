package main

import "fmt"

// fileConfig is the JSON and YAML configuration format. Pointer fields retain
// the runtime defaults when an option is omitted from a configuration file.
type fileConfig struct {
	Global    *fileGlobalConfig     `json:"global,omitempty" yaml:"global,omitempty"`
	TLS       *fileTLSConfig        `json:"tls,omitempty" yaml:"tls,omitempty"`
	Mesh      *fileMeshConfig       `json:"mesh,omitempty" yaml:"mesh,omitempty"`
	Ops       *fileOpsConfig        `json:"ops,omitempty" yaml:"ops,omitempty"`
	Traffic   *fileTrafficConfig    `json:"traffic,omitempty" yaml:"traffic,omitempty"`
	External  *fileExternalConfig   `json:"external,omitempty" yaml:"external,omitempty"`
	Verify    *fileVerifyConfig     `json:"verify,omitempty" yaml:"verify,omitempty"`
	VerifyAPI []fileVerifyAPIConfig `json:"verify_api,omitempty" yaml:"verify_api,omitempty"`
}

type fileGlobalConfig struct {
	Enabled *bool   `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	Listen  *string `json:"listen,omitempty" yaml:"listen,omitempty"`
	STUN    *bool   `json:"stun,omitempty" yaml:"stun,omitempty"`
}

type fileTLSConfig struct {
	CertFile *string `json:"certfile,omitempty" yaml:"certfile,omitempty"`
	KeyFile  *string `json:"keyfile,omitempty" yaml:"keyfile,omitempty"`
	Mode     *string `json:"mode,omitempty" yaml:"mode,omitempty" jsonschema:"enum=manual,enum=self_signed"`
	StateDir *string `json:"state_dir,omitempty" yaml:"state_dir,omitempty"`
}

type fileMeshConfig struct {
	Enabled *bool   `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	Key     *string `json:"key,omitempty" yaml:"key,omitempty"`
}

type fileOpsConfig struct {
	Socket *string `json:"socket,omitempty" yaml:"socket,omitempty"`
	Health *string `json:"health,omitempty" yaml:"health,omitempty"`
}

type fileTrafficConfig struct {
	Persist  *bool   `json:"persist,omitempty" yaml:"persist,omitempty"`
	Path     *string `json:"path,omitempty" yaml:"path,omitempty"`
	Interval *int    `json:"interval,omitempty" yaml:"interval,omitempty" jsonschema:"description=Traffic statistics save interval in seconds"`
}

type fileExternalConfig struct {
	Enabled          *bool     `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	Mode             *string   `json:"mode,omitempty" yaml:"mode,omitempty" jsonschema:"enum=nat,enum=direct"`
	AddressFamily    *string   `json:"address_family,omitempty" yaml:"address_family,omitempty" jsonschema:"enum=ipv4,enum=ipv6,enum=dual"`
	Methods          *[]string `json:"methods,omitempty" yaml:"methods,omitempty" jsonschema:"description=Port mapping methods in priority order"`
	WANInterface     *string   `json:"wan_interface,omitempty" yaml:"wan_interface,omitempty"`
	DERPPort         *string   `json:"derp_port,omitempty" yaml:"derp_port,omitempty"`
	STUNPort         *string   `json:"stun_port,omitempty" yaml:"stun_port,omitempty"`
	LeaseSeconds     *int      `json:"lease_seconds,omitempty" yaml:"lease_seconds,omitempty" jsonschema:"description=Port mapping lease duration in seconds"`
	RetrySeconds     *int      `json:"retry_seconds,omitempty" yaml:"retry_seconds,omitempty" jsonschema:"description=Port mapping retry interval in seconds"`
	SyncInterval     *int      `json:"sync_interval,omitempty" yaml:"sync_interval,omitempty" jsonschema:"description=External endpoint synchronization interval in seconds"`
	ValidateEndpoint *bool     `json:"validate_endpoint,omitempty" yaml:"validate_endpoint,omitempty"`
}

type fileVerifyConfig struct {
	URLs                    *[]string `json:"urls,omitempty" yaml:"urls,omitempty" jsonschema:"description=Admission controller URLs"`
	Enabled                 *bool     `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	URLEnabled              *bool     `json:"url_enabled,omitempty" yaml:"url_enabled,omitempty"`
	TailscaledEnabled       *bool     `json:"tailscaled_enabled,omitempty" yaml:"tailscaled_enabled,omitempty"`
	TailscaledSocketEnabled *bool     `json:"tailscaled_socket_enabled,omitempty" yaml:"tailscaled_socket_enabled,omitempty"`
	TailscaledSocket        *string   `json:"tailscaled_socket,omitempty" yaml:"tailscaled_socket,omitempty"`
	APIEnabled              *bool     `json:"api_enabled,omitempty" yaml:"api_enabled,omitempty"`
	SyncInterval            *int      `json:"sync_interval,omitempty" yaml:"sync_interval,omitempty" jsonschema:"description=Device synchronization interval in seconds"`
	CacheTTL                *int      `json:"cache_ttl,omitempty" yaml:"cache_ttl,omitempty" jsonschema:"description=Admission cache TTL in seconds"`
}

type fileVerifyAPIConfig struct {
	Name              string  `json:"name,omitempty" yaml:"name,omitempty" jsonschema:"description=Unique local API instance name"`
	Label             *string `json:"label,omitempty" yaml:"label,omitempty"`
	Tailnet           *string `json:"tailnet,omitempty" yaml:"tailnet,omitempty"`
	AuthType          *string `json:"auth_type,omitempty" yaml:"auth_type,omitempty" jsonschema:"enum=api_key,enum=oauth"`
	APIKey            *string `json:"api_key,omitempty" yaml:"api_key,omitempty" jsonschema:"description=Sensitive Tailscale API key"`
	OAuthClientID     *string `json:"oauth_client_id,omitempty" yaml:"oauth_client_id,omitempty"`
	OAuthClientSecret *string `json:"oauth_client_secret,omitempty" yaml:"oauth_client_secret,omitempty" jsonschema:"description=Sensitive OAuth client secret"`
	DERPMapSync       *bool   `json:"derpmap_sync,omitempty" yaml:"derpmap_sync,omitempty"`
	StunOnly          *bool   `json:"stun_only,omitempty" yaml:"stun_only,omitempty"`
	RegionID          *int    `json:"region_id,omitempty" yaml:"region_id,omitempty"`
	RegionCode        *string `json:"region_code,omitempty" yaml:"region_code,omitempty"`
	RegionName        *string `json:"region_name,omitempty" yaml:"region_name,omitempty"`
	NodeName          *string `json:"node_name,omitempty" yaml:"node_name,omitempty"`
	Hostname          *string `json:"hostname,omitempty" yaml:"hostname,omitempty"`
	CertName          *string `json:"cert_name,omitempty" yaml:"cert_name,omitempty"`
}

func (config *fileConfig) toUCIConfig() *uciConfig {
	parsed := &uciConfig{values: make(map[string]map[string][]string)}
	if config == nil {
		return parsed
	}

	if section := config.Global; section != nil {
		parsed.addSection("global", "global", optionValues(
			optionBool("enabled", section.Enabled), optionString("listen", section.Listen), optionBool("stun", section.STUN),
		))
	}
	if section := config.TLS; section != nil {
		parsed.addSection("tls", "tls", optionValues(
			optionString("certfile", section.CertFile), optionString("keyfile", section.KeyFile), optionString("mode", section.Mode), optionString("state_dir", section.StateDir),
		))
	}
	if section := config.Mesh; section != nil {
		parsed.addSection("mesh", "mesh", optionValues(optionBool("enabled", section.Enabled), optionString("key", section.Key)))
	}
	if section := config.Ops; section != nil {
		parsed.addSection("ops", "ops", optionValues(optionString("socket", section.Socket), optionString("health", section.Health)))
	}
	if section := config.Traffic; section != nil {
		parsed.addSection("traffic", "traffic", optionValues(
			optionBool("persist", section.Persist), optionString("path", section.Path), optionInt("interval", section.Interval),
		))
	}
	if section := config.External; section != nil {
		values := optionValues(
			optionBool("enabled", section.Enabled), optionString("mode", section.Mode), optionString("address_family", section.AddressFamily),
			optionString("wan_interface", section.WANInterface), optionString("derp_port", section.DERPPort), optionString("stun_port", section.STUNPort),
			optionInt("lease_seconds", section.LeaseSeconds), optionInt("retry_seconds", section.RetrySeconds), optionInt("sync_interval", section.SyncInterval),
			optionBool("validate_endpoint", section.ValidateEndpoint),
		)
		if section.Methods != nil {
			values["method"] = append([]string(nil), (*section.Methods)...)
		}
		parsed.addSection("external", "external", values)
	}
	if section := config.Verify; section != nil {
		values := optionValues(
			optionBool("enabled", section.Enabled), optionBool("url_enabled", section.URLEnabled), optionBool("tailscaled_enabled", section.TailscaledEnabled),
			optionBool("tailscaled_socket_enabled", section.TailscaledSocketEnabled), optionString("tailscaled_socket", section.TailscaledSocket),
			optionBool("api_enabled", section.APIEnabled), optionInt("sync_interval", section.SyncInterval), optionInt("cache_ttl", section.CacheTTL),
		)
		if section.URLs != nil {
			values["url"] = append([]string(nil), (*section.URLs)...)
		}
		parsed.addSection("verify", "verify", values)
	}
	for index, section := range config.VerifyAPI {
		name := section.Name
		if name == "" {
			name = fmt.Sprintf("verify_api_%d", index+1)
		}
		parsed.addSection("verify_api", name, optionValues(
			optionString("label", section.Label), optionString("tailnet", section.Tailnet), optionString("auth_type", section.AuthType),
			optionString("api_key", section.APIKey), optionString("oauth_client_id", section.OAuthClientID), optionString("oauth_client_secret", section.OAuthClientSecret),
			optionBool("derpmap_sync", section.DERPMapSync), optionBool("stun_only", section.StunOnly), optionInt("region_id", section.RegionID),
			optionString("region_code", section.RegionCode), optionString("region_name", section.RegionName), optionString("node_name", section.NodeName),
			optionString("hostname", section.Hostname), optionString("cert_name", section.CertName),
		))
	}

	return parsed
}

func (config *uciConfig) addSection(typ, name string, values map[string][]string) {
	config.values[name] = values
	config.sections = append(config.sections, uciSection{typ: typ, name: name, values: values})
}

func optionValues(options ...optionValue) map[string][]string {
	values := make(map[string][]string)
	for _, option := range options {
		if option.set {
			values[option.name] = []string{option.value}
		}
	}
	return values
}

type optionValue struct {
	name  string
	value string
	set   bool
}

func optionString(name string, value *string) optionValue {
	if value == nil {
		return optionValue{}
	}
	return optionValue{name: name, value: *value, set: true}
}

func optionBool(name string, value *bool) optionValue {
	if value == nil {
		return optionValue{}
	}
	if *value {
		return optionValue{name: name, value: "1", set: true}
	}
	return optionValue{name: name, value: "0", set: true}
}

func optionInt(name string, value *int) optionValue {
	if value == nil {
		return optionValue{}
	}
	return optionValue{name: name, value: fmt.Sprintf("%d", *value), set: true}
}
