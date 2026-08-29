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
	"time"

	"github.com/LazuliKao/tailscale-derp/internal/httpjson"
	tailscaleapi "tailscale.com/client/tailscale/v2"
)

const maxDeviceTags = 64

type setDeviceAuthorizedRequest struct {
	Authorized bool `json:"authorized"`
}

type setDeviceNameRequest struct {
	Name string `json:"name"`
}

type setDeviceTagsRequest struct {
	Tags []string `json:"tags"`
}

type setDeviceKeyRequest struct {
	KeyExpiryDisabled bool `json:"keyExpiryDisabled"`
}

type setDeviceRoutesRequest struct {
	Routes []string `json:"routes"`
}

type setDeviceAttributeRequest struct {
	Key     string          `json:"key"`
	Value   json.RawMessage `json:"value"`
	Expiry  string          `json:"expiry"`
	Comment string          `json:"comment,omitempty"`
}

type deleteDeviceAttributeRequest struct {
	Key string `json:"key"`
}

type badDeviceRequestError struct {
	err error
}

func (e badDeviceRequestError) Error() string {
	return e.err.Error()
}

func invalidDeviceRequest(err error) error {
	return badDeviceRequestError{err: err}
}

func (s *deviceStore) updateCachedDevice(instanceName, deviceID string, update func(*Device)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.cache[instanceName]
	if !ok {
		return
	}
	for nodeKey, device := range entry.devices {
		if device.NodeID == deviceID {
			update(&device)
			entry.devices[nodeKey] = device
			break
		}
	}
	s.cache[instanceName] = entry
}

func (s *deviceStore) removeCachedDevice(instanceName, deviceID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.cache[instanceName]
	if !ok {
		return
	}
	for nodeKey, device := range entry.devices {
		if device.NodeID == deviceID {
			delete(entry.devices, nodeKey)
			break
		}
	}
	s.cache[instanceName] = entry
}

func (s *deviceStore) setDeviceAuthorized(ctx context.Context, instanceName, deviceID string, authorized bool) error {
	instance, err := s.apiInstance(instanceName)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, deviceRequestTimeout)
	defer cancel()
	if err := s.apiClient(instance).Devices().SetAuthorized(ctx, deviceID, authorized); err != nil {
		return err
	}
	s.updateCachedDevice(instanceName, deviceID, func(device *Device) { device.Authorized = authorized })
	return nil
}

func (s *deviceStore) setDeviceName(ctx context.Context, instanceName, deviceID, name string) error {
	instance, err := s.apiInstance(instanceName)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, deviceRequestTimeout)
	defer cancel()
	if err := s.apiClient(instance).Devices().SetName(ctx, deviceID, name); err != nil {
		return err
	}
	s.updateCachedDevice(instanceName, deviceID, func(device *Device) { device.Name = name })
	return nil
}

func (s *deviceStore) setDeviceTags(ctx context.Context, instanceName, deviceID string, tags []string) error {
	instance, err := s.apiInstance(instanceName)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, deviceRequestTimeout)
	defer cancel()
	if err := s.apiClient(instance).Devices().SetTags(ctx, deviceID, tags); err != nil {
		return err
	}
	s.updateCachedDevice(instanceName, deviceID, func(device *Device) { device.Tags = append([]string(nil), tags...) })
	return nil
}

func (s *deviceStore) setDeviceKey(ctx context.Context, instanceName, deviceID string, keyExpiryDisabled bool) error {
	instance, err := s.apiInstance(instanceName)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, deviceRequestTimeout)
	defer cancel()
	if err := s.apiClient(instance).Devices().SetKey(ctx, deviceID, tailscaleapi.DeviceKey{KeyExpiryDisabled: keyExpiryDisabled}); err != nil {
		return err
	}
	s.updateCachedDevice(instanceName, deviceID, func(device *Device) { device.KeyExpiryDisabled = keyExpiryDisabled })
	return nil
}

func (s *deviceStore) deleteDevice(ctx context.Context, instanceName, deviceID string) error {
	instance, err := s.apiInstance(instanceName)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, deviceRequestTimeout)
	defer cancel()
	if err := s.apiClient(instance).Devices().Delete(ctx, deviceID); err != nil {
		return err
	}
	s.removeCachedDevice(instanceName, deviceID)
	return nil
}

func (s *deviceStore) deviceRoutes(ctx context.Context, instanceName, deviceID string) (*tailscaleapi.DeviceRoutes, error) {
	instance, err := s.apiInstance(instanceName)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, deviceRequestTimeout)
	defer cancel()
	return s.apiClient(instance).Devices().SubnetRoutes(ctx, deviceID)
}

func (s *deviceStore) setDeviceRoutes(ctx context.Context, instanceName, deviceID string, routes []string) error {
	instance, err := s.apiInstance(instanceName)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, deviceRequestTimeout)
	defer cancel()
	return s.apiClient(instance).Devices().SetSubnetRoutes(ctx, deviceID, routes)
}

func (s *deviceStore) deviceAttributes(ctx context.Context, instanceName, deviceID string) (*tailscaleapi.DevicePostureAttributes, error) {
	instance, err := s.apiInstance(instanceName)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, deviceRequestTimeout)
	defer cancel()
	return s.apiClient(instance).Devices().GetPostureAttributes(ctx, deviceID)
}

func (s *deviceStore) setDeviceAttribute(ctx context.Context, instanceName, deviceID string, request setDeviceAttributeRequest) error {
	instance, err := s.apiInstance(instanceName)
	if err != nil {
		return err
	}
	expires, err := time.Parse(time.RFC3339, request.Expiry)
	if err != nil {
		return errors.New("a valid RFC3339 expiry is required")
	}
	var value any
	if err := json.Unmarshal(request.Value, &value); err != nil {
		return errors.New("attribute value must be valid JSON")
	}
	ctx, cancel := context.WithTimeout(ctx, deviceRequestTimeout)
	defer cancel()
	return s.apiClient(instance).Devices().SetPostureAttribute(ctx, deviceID, request.Key, tailscaleapi.DevicePostureAttributeRequest{
		Value: value, Expiry: tailscaleapi.Time{Time: expires}, Comment: request.Comment,
	})
}

func (s *deviceStore) deleteDeviceAttribute(ctx context.Context, instanceName, deviceID, attributeKey string) error {
	instance, err := s.apiInstance(instanceName)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, deviceRequestTimeout)
	defer cancel()
	return s.apiClient(instance).Devices().DeletePostureAttribute(ctx, deviceID, attributeKey)
}

func (s *deviceStore) expireDevice(ctx context.Context, instanceName, deviceID string) error {
	instance, err := s.apiInstance(instanceName)
	if err != nil {
		return err
	}
	client := s.apiClient(instance)
	// Initialize the SDK client so its OAuth transport is installed before the
	// unsupported expire endpoint is called directly.
	client.Devices()
	ctx, cancel := context.WithTimeout(ctx, deviceRequestTimeout)
	defer cancel()
	endpoint := client.BaseURL.JoinPath("api", "v2", "device", deviceID, "expire")
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), nil)
	if err != nil {
		return err
	}
	if client.APIKey != "" {
		request.SetBasicAuth(client.APIKey, "")
	}
	response, err := client.HTTP.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices {
		s.updateCachedDevice(instanceName, deviceID, func(device *Device) { device.Expires = time.Now().UTC().Format(time.RFC3339) })
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(response.Body, managementRequestLimit))
	var apiErr tailscaleapi.APIError
	if json.Unmarshal(body, &apiErr) == nil {
		apiErr.Status = response.StatusCode
		return apiErr
	}
	return fmt.Errorf("Tailscale API request failed with status %d", response.StatusCode)
}

func handleDeviceAction(method string, action func(context.Context, string, string, *http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			httpjson.Write(w, http.StatusMethodNotAllowed, map[string]string{"error": method + " required"})
			return
		}
		if err := action(r.Context(), r.PathValue("instance"), r.PathValue("deviceID"), r); err != nil {
			var requestErr badDeviceRequestError
			if errors.As(err, &requestErr) {
				httpjson.Write(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			writeTailscaleAPIError(w, err)
			return
		}
		httpjson.Write(w, http.StatusOK, map[string]string{"result": "ok"})
	}
}

func decodeDeviceRequest(r *http.Request, out any) error {
	if err := decodeManagementRequest(r, out); err != nil {
		return invalidDeviceRequest(err)
	}
	return nil
}

func validateTags(tags []string) error {
	if len(tags) > maxDeviceTags {
		return fmt.Errorf("at most %d tags are allowed", maxDeviceTags)
	}
	for _, tag := range tags {
		if len(tag) > 253 || !strings.HasPrefix(tag, "tag:") || strings.TrimSpace(tag) != tag || len(tag) == len("tag:") {
			return errors.New("tags must be non-empty tag: values")
		}
	}
	return nil
}

func validateRoutes(routes []string) error {
	for _, route := range routes {
		if _, err := netip.ParsePrefix(route); err != nil {
			return fmt.Errorf("invalid route %q", route)
		}
	}
	return nil
}

func validateAttributeKey(key string) error {
	if key == "" || len(key) > 253 || strings.TrimSpace(key) != key {
		return errors.New("a valid attribute key is required")
	}
	return nil
}

func validateDeviceAttribute(request setDeviceAttributeRequest) error {
	if err := validateAttributeKey(request.Key); err != nil {
		return err
	}
	if _, err := time.Parse(time.RFC3339, request.Expiry); err != nil {
		return errors.New("a valid RFC3339 expiry is required")
	}
	if !json.Valid(request.Value) {
		return errors.New("attribute value must be valid JSON")
	}
	return nil
}

func handleSetDeviceAuthorized(store *deviceStore) http.HandlerFunc {
	return handleDeviceAction(http.MethodPut, func(ctx context.Context, instance, deviceID string, r *http.Request) error {
		var request setDeviceAuthorizedRequest
		if err := decodeDeviceRequest(r, &request); err != nil {
			return err
		}
		return store.setDeviceAuthorized(ctx, instance, deviceID, request.Authorized)
	})
}

func handleSetDeviceName(store *deviceStore) http.HandlerFunc {
	return handleDeviceAction(http.MethodPut, func(ctx context.Context, instance, deviceID string, r *http.Request) error {
		var request setDeviceNameRequest
		if err := decodeDeviceRequest(r, &request); err != nil {
			return err
		}
		request.Name = strings.TrimSpace(request.Name)
		if request.Name == "" || len(request.Name) > 256 {
			return invalidDeviceRequest(errors.New("a device name of at most 256 characters is required"))
		}
		return store.setDeviceName(ctx, instance, deviceID, request.Name)
	})
}

func handleSetDeviceTags(store *deviceStore) http.HandlerFunc {
	return handleDeviceAction(http.MethodPut, func(ctx context.Context, instance, deviceID string, r *http.Request) error {
		var request setDeviceTagsRequest
		if err := decodeDeviceRequest(r, &request); err != nil {
			return err
		}
		if err := validateTags(request.Tags); err != nil {
			return invalidDeviceRequest(err)
		}
		return store.setDeviceTags(ctx, instance, deviceID, request.Tags)
	})
}

func handleSetDeviceKey(store *deviceStore) http.HandlerFunc {
	return handleDeviceAction(http.MethodPut, func(ctx context.Context, instance, deviceID string, r *http.Request) error {
		var request setDeviceKeyRequest
		if err := decodeDeviceRequest(r, &request); err != nil {
			return err
		}
		return store.setDeviceKey(ctx, instance, deviceID, request.KeyExpiryDisabled)
	})
}

func handleDeleteDevice(store *deviceStore) http.HandlerFunc {
	return handleDeviceAction(http.MethodDelete, func(ctx context.Context, instance, deviceID string, _ *http.Request) error {
		return store.deleteDevice(ctx, instance, deviceID)
	})
}

func handleDeviceRoutes(store *deviceStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		instance, deviceID := r.PathValue("instance"), r.PathValue("deviceID")
		switch r.Method {
		case http.MethodGet:
			routes, err := store.deviceRoutes(r.Context(), instance, deviceID)
			if err != nil {
				writeTailscaleAPIError(w, err)
				return
			}
			httpjson.Write(w, http.StatusOK, routes)
		case http.MethodPut:
			var request setDeviceRoutesRequest
			if err := decodeDeviceRequest(r, &request); err != nil {
				httpjson.Write(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			if err := validateRoutes(request.Routes); err != nil {
				httpjson.Write(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			if err := store.setDeviceRoutes(r.Context(), instance, deviceID, request.Routes); err != nil {
				writeTailscaleAPIError(w, err)
				return
			}
			httpjson.Write(w, http.StatusOK, map[string]string{"result": "ok"})
		default:
			httpjson.Write(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET or PUT required"})
		}
	}
}

func handleDeviceAttributes(store *deviceStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		instance, deviceID := r.PathValue("instance"), r.PathValue("deviceID")
		switch r.Method {
		case http.MethodGet:
			attributes, err := store.deviceAttributes(r.Context(), instance, deviceID)
			if err != nil {
				writeTailscaleAPIError(w, err)
				return
			}
			httpjson.Write(w, http.StatusOK, attributes)
		case http.MethodPost:
			var request setDeviceAttributeRequest
			if err := decodeDeviceRequest(r, &request); err != nil {
				httpjson.Write(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			if err := validateDeviceAttribute(request); err != nil {
				httpjson.Write(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			if err := store.setDeviceAttribute(r.Context(), instance, deviceID, request); err != nil {
				writeTailscaleAPIError(w, err)
				return
			}
			httpjson.Write(w, http.StatusOK, map[string]string{"result": "ok"})
		case http.MethodDelete:
			var request deleteDeviceAttributeRequest
			if err := decodeDeviceRequest(r, &request); err != nil {
				httpjson.Write(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			if err := validateAttributeKey(request.Key); err != nil {
				httpjson.Write(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			if err := store.deleteDeviceAttribute(r.Context(), instance, deviceID, request.Key); err != nil {
				writeTailscaleAPIError(w, err)
				return
			}
			httpjson.Write(w, http.StatusOK, map[string]string{"result": "ok"})
		default:
			httpjson.Write(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET, POST, or DELETE required"})
		}
	}
}

func handleExpireDevice(store *deviceStore) http.HandlerFunc {
	return handleDeviceAction(http.MethodPost, func(ctx context.Context, instance, deviceID string, _ *http.Request) error {
		return store.expireDevice(ctx, instance, deviceID)
	})
}
