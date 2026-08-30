package ops

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/LazuliKao/tailscale-derp/internal/endpoint"
	"github.com/tailscale/hujson"
	tailscaleapi "tailscale.com/client/tailscale/v2"
)

const policyUpdateAttempts = 3

func (r *Runtime) Publish(ctx context.Context, value endpoint.Endpoint) ([]endpoint.InstanceStatus, error) {
	if r == nil || r.verifier == nil {
		return nil, errors.New("operations runtime is unavailable")
	}
	return r.reconcileDERPMaps(ctx, &value, false)
}

func (r *Runtime) Withdraw(ctx context.Context) ([]endpoint.InstanceStatus, error) {
	if r == nil || r.verifier == nil {
		return nil, errors.New("operations runtime is unavailable")
	}
	return r.reconcileDERPMaps(ctx, nil, true)
}

func (r *Runtime) reconcileDERPMaps(ctx context.Context, value *endpoint.Endpoint, withdraw bool) ([]endpoint.InstanceStatus, error) {
	store := r.verifier.store
	statuses := make([]endpoint.InstanceStatus, 0)
	var errs []error
	for _, cfg := range store.configs {
		if !cfg.DERPMapSync {
			continue
		}
		status := endpoint.InstanceStatus{Name: cfg.Name, Label: cfg.Label, State: "syncing", LastAttempt: time.Now().UTC().Format(time.RFC3339)}
		err := store.reconcileDERPMap(ctx, cfg, value, withdraw)
		if err != nil {
			status.State = "error"
			status.Error = err.Error()
			errs = append(errs, fmt.Errorf("%s: %w", cfg.Name, err))
		} else {
			if withdraw {
				status.State = "withdrawn"
			} else {
				status.State = "published"
			}
			status.LastSuccess = time.Now().UTC().Format(time.RFC3339)
		}
		statuses = append(statuses, status)
	}
	return statuses, errors.Join(errs...)
}

func (s *deviceStore) reconcileDERPMap(ctx context.Context, cfg APIConfig, value *endpoint.Endpoint, withdraw bool) error {
	lock, err := s.policyLock(cfg.Name)
	if err != nil {
		return err
	}
	lock.Lock()
	defer lock.Unlock()

	for attempt := 0; attempt < policyUpdateAttempts; attempt++ {
		policy, err := s.policyRawUnlocked(ctx, cfg.Name)
		if err != nil {
			return err
		}
		updated, changed, err := patchDERPMap(policy.HuJSON, cfg, value, withdraw)
		if err != nil {
			return err
		}
		if !changed {
			return nil
		}
		if err := s.setPolicyUnlocked(ctx, cfg.Name, updated, policy.ETag); err != nil {
			if isPolicyConflict(err) && attempt+1 < policyUpdateAttempts {
				delay := time.Duration(attempt+1) * 50 * time.Millisecond
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(delay):
				}
				continue
			}
			return err
		}
		return nil
	}
	return errors.New("policy update conflicted too many times")
}

func isPolicyConflict(err error) bool {
	var apiErr tailscaleapi.APIError
	return errors.As(err, &apiErr) && (apiErr.Status == http.StatusPreconditionFailed || apiErr.Status == http.StatusConflict)
}

func patchDERPMap(source string, cfg APIConfig, value *endpoint.Endpoint, withdraw bool) (string, bool, error) {
	root, err := hujson.Parse([]byte(source))
	if err != nil {
		return "", false, fmt.Errorf("parse policy HuJSON: %w", err)
	}
	rootObject, ok := root.Value.(*hujson.Object)
	if !ok {
		return "", false, errors.New("policy root must be an object")
	}
	regionKey := strconv.Itoa(cfg.RegionID)
	derpMapValue, derpMapIndex := objectMember(rootObject, "derpMap")
	if derpMapValue == nil {
		if withdraw {
			return source, false, nil
		}
		derpMapValue = appendObjectMember(rootObject, "derpMap", &hujson.Object{})
		derpMapIndex = len(rootObject.Members) - 1
	}
	derpMap, ok := derpMapValue.Value.(*hujson.Object)
	if !ok {
		return "", false, errors.New("derpMap must be an object")
	}
	regionsValue, _ := objectMember(derpMap, "Regions")
	if regionsValue == nil {
		if withdraw {
			return source, false, nil
		}
		regionsValue = appendObjectMember(derpMap, "Regions", &hujson.Object{})
	}
	regions, ok := regionsValue.Value.(*hujson.Object)
	if !ok {
		return "", false, errors.New("derpMap.Regions must be an object")
	}
	regionValue, regionIndex := objectMember(regions, regionKey)
	regionExists := regionValue != nil
	if regionValue == nil {
		if withdraw {
			return source, false, nil
		}
		regionValue = appendObjectMember(regions, regionKey, &hujson.Object{})
		regionIndex = len(regions.Members) - 1
	}
	region, ok := regionValue.Value.(*hujson.Object)
	if !ok {
		return "", false, fmt.Errorf("DERP region %s must be an object", regionKey)
	}
	if regionExists {
		if err := requireOwnedInt(region, "RegionID", cfg.RegionID); err != nil {
			return "", false, err
		}
	}
	nodesValue, _ := objectMember(region, "Nodes")
	if nodesValue == nil {
		if withdraw {
			return source, false, nil
		}
		nodesValue = appendObjectMember(region, "Nodes", &hujson.Array{})
	}
	nodes, ok := nodesValue.Value.(*hujson.Array)
	if !ok {
		return "", false, fmt.Errorf("DERP region %s Nodes must be an array", regionKey)
	}
	node, nodeIndex, err := findNode(nodes, cfg.NodeName)
	if err != nil {
		return "", false, err
	}
	if withdraw {
		if node == nil {
			return source, false, nil
		}
		if err := requireOwnedInt(node, "RegionID", cfg.RegionID); err != nil {
			return "", false, err
		}
		nodes.Elements = append(nodes.Elements[:nodeIndex], nodes.Elements[nodeIndex+1:]...)
		if len(nodes.Elements) == 0 {
			regions.Members = append(regions.Members[:regionIndex], regions.Members[regionIndex+1:]...)
			if len(regions.Members) == 0 {
				removeObjectMember(derpMap, "Regions")
			}
			if len(derpMap.Members) == 0 {
				rootObject.Members = append(rootObject.Members[:derpMapIndex], rootObject.Members[derpMapIndex+1:]...)
			}
		}
		packed := string(root.Pack())
		return packed, packed != source, nil
	}
	if value == nil {
		return "", false, errors.New("mapped endpoint is required")
	}
	if node == nil {
		if regionExists {
			return "", false, fmt.Errorf("DERP region %s already contains nodes not owned by %q", regionKey, cfg.NodeName)
		}
		node = &hujson.Object{}
		nodes.Elements = append(nodes.Elements, hujson.Value{Value: node})
	} else if err := requireOwnedInt(node, "RegionID", cfg.RegionID); err != nil {
		return "", false, err
	}

	setObjectString(region, "RegionCode", cfg.RegionCode)
	setObjectString(region, "RegionName", cfg.RegionName)
	setObjectInt(region, "RegionID", cfg.RegionID)
	setObjectString(node, "Name", cfg.NodeName)
	setObjectInt(node, "RegionID", cfg.RegionID)
	setObjectString(node, "HostName", cfg.Hostname)
	setObjectString(node, "IPv4", value.IPv4)
	setObjectInt(node, "DERPPort", int(value.DERPPort))
	setObjectInt(node, "STUNPort", value.STUNPort)
	if cfg.CertName == "" {
		removeObjectMember(node, "CertName")
	} else {
		setObjectString(node, "CertName", cfg.CertName)
	}
	packed := string(root.Pack())
	return packed, packed != source, nil
}

func objectMember(object *hujson.Object, name string) (*hujson.Value, int) {
	for index := range object.Members {
		literal, ok := object.Members[index].Name.Value.(hujson.Literal)
		if ok && literal.Kind() == '"' && literal.String() == name {
			return &object.Members[index].Value, index
		}
	}
	return nil, -1
}

func appendObjectMember(object *hujson.Object, name string, value hujson.ValueTrimmed) *hujson.Value {
	object.Members = append(object.Members, hujson.ObjectMember{
		Name:  hujson.Value{Value: hujson.String(name)},
		Value: hujson.Value{Value: value},
	})
	return &object.Members[len(object.Members)-1].Value
}

func removeObjectMember(object *hujson.Object, name string) {
	_, index := objectMember(object, name)
	if index >= 0 {
		object.Members = append(object.Members[:index], object.Members[index+1:]...)
	}
}

func setObjectString(object *hujson.Object, name, value string) {
	member, _ := objectMember(object, name)
	if member == nil {
		appendObjectMember(object, name, hujson.String(value))
		return
	}
	member.Value = hujson.String(value)
}

func setObjectInt(object *hujson.Object, name string, value int) {
	member, _ := objectMember(object, name)
	if member == nil {
		appendObjectMember(object, name, hujson.Int(int64(value)))
		return
	}
	member.Value = hujson.Int(int64(value))
}

func requireMatchingInt(object *hujson.Object, name string, expected int) error {
	member, _ := objectMember(object, name)
	if member == nil {
		return nil
	}
	literal, ok := member.Value.(hujson.Literal)
	if !ok || literal.Kind() != '0' || int(literal.Int()) != expected {
		return fmt.Errorf("managed %s does not match configured value %d", name, expected)
	}
	return nil
}

func requireOwnedInt(object *hujson.Object, name string, expected int) error {
	member, _ := objectMember(object, name)
	if member == nil {
		return fmt.Errorf("managed %s is missing; ownership is unclear", name)
	}
	return requireMatchingInt(object, name, expected)
}

func findNode(nodes *hujson.Array, name string) (*hujson.Object, int, error) {
	for index := range nodes.Elements {
		node, ok := nodes.Elements[index].Value.(*hujson.Object)
		if !ok {
			return nil, -1, errors.New("DERP Nodes entries must be objects")
		}
		nameValue, _ := objectMember(node, "Name")
		if nameValue == nil {
			continue
		}
		literal, ok := nameValue.Value.(hujson.Literal)
		if !ok || literal.Kind() != '"' {
			return nil, -1, errors.New("DERP Node Name must be a string")
		}
		if literal.String() == name {
			return node, index, nil
		}
	}
	return nil, -1, nil
}
