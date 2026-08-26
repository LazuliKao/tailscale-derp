package ops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"

	"github.com/LazuliKao/tailscale-derp/internal/httpjson"
	tailscaleapi "tailscale.com/client/tailscale/v2"
)

const managementRequestLimit = 4 << 20

var (
	errUnknownAPIInstance      = errors.New("unknown API instance")
	errUnconfiguredAPIInstance = errors.New("API instance is not configured")
)

type APIInstance struct {
	Name       string `json:"name"`
	Label      string `json:"label,omitempty"`
	Tailnet    string `json:"tailnet"`
	AuthType   string `json:"authType,omitempty"`
	Configured bool   `json:"configured"`
}

type policyDocument struct {
	HuJSON string `json:"hujson"`
	ETag   string `json:"etag,omitempty"`
}

type setDeviceIPv4Request struct {
	IPv4 string `json:"ipv4"`
}

func (s *deviceStore) apiInstances() []APIInstance {
	instances := make([]APIInstance, 0, len(s.configs))
	for _, cfg := range s.configs {
		label := cfg.Label
		if label == "" {
			label = cfg.Name
		}
		instances = append(instances, APIInstance{
			Name:       cfg.Name,
			Label:      label,
			Tailnet:    cfg.Tailnet,
			AuthType:   string(cfg.AuthType),
			Configured: cfg.isConfigured(),
		})
	}
	return instances
}

func (s *deviceStore) apiInstance(name string) (APIConfig, error) {
	for _, instance := range s.configs {
		if instance.Name != name {
			continue
		}
		if !instance.isConfigured() {
			return APIConfig{}, errUnconfiguredAPIInstance
		}
		return instance, nil
	}
	return APIConfig{}, errUnknownAPIInstance
}

func (s *deviceStore) setDeviceIPv4(ctx context.Context, instanceName, deviceID, ipv4 string) error {
	instance, err := s.apiInstance(instanceName)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, deviceRequestTimeout)
	defer cancel()
	if err := s.apiClient(instance).Devices().SetIPv4Address(ctx, deviceID, ipv4); err != nil {
		return err
	}
	s.updateCachedIPv4(instance.Name, deviceID, ipv4)
	return nil
}

func (s *deviceStore) updateCachedIPv4(instanceName, deviceID, ipv4 string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.cache[instanceName]
	if !ok {
		return
	}
	for nodeKey, device := range entry.devices {
		if device.NodeID != deviceID {
			continue
		}
		addresses := make([]string, 0, len(device.Addresses)+1)
		replaced := false
		for _, address := range device.Addresses {
			parsed, err := netip.ParseAddr(address)
			if err == nil && parsed.Is4() {
				if !replaced {
					addresses = append(addresses, ipv4)
					replaced = true
				}
				continue
			}
			addresses = append(addresses, address)
		}
		if !replaced {
			addresses = append(addresses, ipv4)
		}
		device.Addresses = addresses
		entry.devices[nodeKey] = device
		break
	}
	s.cache[instanceName] = entry
}

func (s *deviceStore) policyRaw(ctx context.Context, instanceName string) (*tailscaleapi.RawACL, error) {
	instance, err := s.apiInstance(instanceName)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, deviceRequestTimeout)
	defer cancel()
	return s.apiClient(instance).PolicyFile().Raw(ctx)
}

func (s *deviceStore) setPolicy(ctx context.Context, instanceName, hujson, etag string) error {
	instance, err := s.apiInstance(instanceName)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, deviceRequestTimeout)
	defer cancel()
	policy := s.apiClient(instance).PolicyFile()
	if err := policy.Validate(ctx, hujson); err != nil {
		return err
	}
	return policy.Set(ctx, hujson, etag)
}

func (s *deviceStore) validatePolicy(ctx context.Context, instanceName, hujson string) error {
	instance, err := s.apiInstance(instanceName)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, deviceRequestTimeout)
	defer cancel()
	return s.apiClient(instance).PolicyFile().Validate(ctx, hujson)
}

func handleAPIInstances(store *deviceStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			httpjson.Write(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET required"})
			return
		}
		httpjson.Write(w, http.StatusOK, map[string][]APIInstance{"instances": store.apiInstances()})
	}
}

func handleSetDeviceIPv4(store *deviceStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			httpjson.Write(w, http.StatusMethodNotAllowed, map[string]string{"error": "PUT required"})
			return
		}
		var request setDeviceIPv4Request
		if err := decodeManagementRequest(r, &request); err != nil {
			httpjson.Write(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		address, err := netip.ParseAddr(request.IPv4)
		if err != nil || !address.Is4() {
			httpjson.Write(w, http.StatusBadRequest, map[string]string{"error": "a valid IPv4 address is required"})
			return
		}
		if err := store.setDeviceIPv4(r.Context(), r.PathValue("instance"), r.PathValue("deviceID"), address.String()); err != nil {
			writeTailscaleAPIError(w, err)
			return
		}
		httpjson.Write(w, http.StatusOK, map[string]string{"result": "ok"})
	}
}

func handlePolicyGet(store *deviceStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			httpjson.Write(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET required"})
			return
		}
		policy, err := store.policyRaw(r.Context(), r.PathValue("instance"))
		if err != nil {
			writeTailscaleAPIError(w, err)
			return
		}
		httpjson.Write(w, http.StatusOK, policyDocument{HuJSON: policy.HuJSON, ETag: policy.ETag})
	}
}

func handlePolicyValidate(store *deviceStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			httpjson.Write(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
			return
		}
		request, err := decodePolicyDocument(r, false)
		if err != nil {
			httpjson.Write(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if err := store.validatePolicy(r.Context(), r.PathValue("instance"), request.HuJSON); err != nil {
			writeTailscaleAPIError(w, err)
			return
		}
		httpjson.Write(w, http.StatusOK, map[string]bool{"valid": true})
	}
}

func handlePolicySet(store *deviceStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			httpjson.Write(w, http.StatusMethodNotAllowed, map[string]string{"error": "PUT required"})
			return
		}
		request, err := decodePolicyDocument(r, true)
		if err != nil {
			httpjson.Write(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if err := store.setPolicy(r.Context(), r.PathValue("instance"), request.HuJSON, request.ETag); err != nil {
			writeTailscaleAPIError(w, err)
			return
		}
		httpjson.Write(w, http.StatusOK, map[string]string{"result": "ok"})
	}
}

func decodePolicyDocument(r *http.Request, requireETag bool) (policyDocument, error) {
	var document policyDocument
	if err := decodeManagementRequest(r, &document); err != nil {
		return policyDocument{}, err
	}
	if strings.TrimSpace(document.HuJSON) == "" {
		return policyDocument{}, errors.New("HuJSON is required")
	}
	if requireETag && strings.TrimSpace(document.ETag) == "" {
		return policyDocument{}, errors.New("ETag is required")
	}
	return document, nil
}

func decodeManagementRequest(r *http.Request, out any) error {
	decoder := json.NewDecoder(io.LimitReader(r.Body, managementRequestLimit))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return fmt.Errorf("invalid JSON request: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("request body must contain one JSON object")
	}
	return nil
}

func writeTailscaleAPIError(w http.ResponseWriter, err error) {
	status := http.StatusBadGateway
	message := "Tailscale API request failed"
	switch {
	case errors.Is(err, errUnknownAPIInstance):
		status = http.StatusNotFound
		message = err.Error()
	case errors.Is(err, errUnconfiguredAPIInstance):
		status = http.StatusServiceUnavailable
		message = err.Error()
	default:
		var apiErr tailscaleapi.APIError
		if errors.As(err, &apiErr) {
			status = apiErr.Status
			if status == http.StatusPreconditionFailed {
				status = http.StatusConflict
			}
			if apiErr.Message != "" {
				message = apiErr.Message
			}
		}
	}
	httpjson.Write(w, status, map[string]string{"error": message})
}
