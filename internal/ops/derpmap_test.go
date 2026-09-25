package ops

import (
	"strings"
	"testing"

	"github.com/LazuliKao/tailscale-derp/internal/endpoint"
)

func TestPatchDERPMapPreservesUnmanagedHuJSON(t *testing.T) {
	source := `{
  // root comment
  "acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"],}],
  "derpMap": {
    "OmitDefaultRegions": false,
    "Regions": {
      "901": {"RegionID": 901, "RegionCode": "other", "RegionName": "Other", "Nodes": [{"Name": "other-1", "RegionID": 901, "HostName": "other.example"}],},
      "900": {"RegionID": 900, "RegionCode": "old", "RegionName": "Old", "Nodes": [{"Name": "managed", "RegionID": 900, "HostName": "old.example", "Unknown": true}],},
    },
  },
}`
	cfg := APIConfig{RegionID: 900, RegionCode: "home", RegionName: "Home", NodeName: "managed", Hostname: "derp.example.com"}
	updated, changed, err := patchDERPMap(source, cfg, &endpoint.Endpoint{IPv4: "8.8.8.8", DERPPort: 4443, STUNPort: 33478}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("patch reported no change")
	}
	for _, preserved := range []string{"// root comment", `"acls"`, `"901"`, `"other-1"`, `"Unknown": true`, `"OmitDefaultRegions"`} {
		if !strings.Contains(updated, preserved) {
			t.Errorf("updated policy lost %s:\n%s", preserved, updated)
		}
	}
	for _, expected := range []string{`"RegionCode": "home"`, `"HostName": "derp.example.com"`, `"ipv4":"8.8.8.8"`, `"derpPort":4443`, `"stunPort":33478`} {
		if !strings.Contains(updated, expected) {
			t.Errorf("updated policy does not contain %s:\n%s", expected, updated)
		}
	}
}

func TestPatchDERPMapPreservesLowerCamelCaseKeys(t *testing.T) {
	source := `{
  "derpMap": {
    "omitDefaultRegions": false,
    "regions": {
      "900": {
        "regionID": 900,
        "regionCode": "old",
        "regionName": "Old",
        "nodes": [{
          "name": "managed",
          "regionID": 900,
          "hostName": "old.example",
          "ipv4": "192.0.2.1",
          "derpPort": 443,
          "stunPort": 3478,
          "insecureForTests": true,
        }],
      },
    },
  },
}`
	cfg := APIConfig{RegionID: 900, RegionCode: "home", RegionName: "Home", NodeName: "managed", Hostname: "derp.example.com"}
	updated, changed, err := patchDERPMap(source, cfg, &endpoint.Endpoint{IPv4: "8.8.8.8", DERPPort: 4443, STUNPort: 33478}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("patch reported no change")
	}
	for _, key := range []string{"derpMap", "omitDefaultRegions", "regions", "regionID", "regionCode", "regionName", "nodes", "name", "hostName", "ipv4", "derpPort", "stunPort"} {
		if !strings.Contains(updated, `"`+key+`"`) {
			t.Errorf("updated policy does not preserve lower-camel key %q:\n%s", key, updated)
		}
	}
	for _, key := range []string{"Regions", "RegionID", "RegionCode", "RegionName", "Nodes", "Name", "HostName", "IPv4", "DERPPort", "STUNPort"} {
		if strings.Contains(updated, `"`+key+`"`) {
			t.Errorf("updated policy added duplicate PascalCase key %q:\n%s", key, updated)
		}
	}
	for _, preserved := range []string{`"insecureForTests": true`, `"derp.example.com"`, `"8.8.8.8"`, "4443", "33478"} {
		if !strings.Contains(updated, preserved) {
			t.Errorf("updated policy does not contain %s:\n%s", preserved, updated)
		}
	}

	withdrawn, changed, err := patchDERPMap(updated, cfg, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if !changed || strings.Contains(withdrawn, `"900"`) || strings.Contains(withdrawn, `"managed"`) {
		t.Fatalf("withdrawal did not remove the lower-camel managed region:\n%s", withdrawn)
	}
	if !strings.Contains(withdrawn, `"omitDefaultRegions"`) {
		t.Fatalf("withdrawal did not preserve unmanaged DERP map content:\n%s", withdrawn)
	}
}

func TestPatchDERPMapUsesLowerCamelCaseForNewRegion(t *testing.T) {
	source := `{
  "derpMap": {
    "omitDefaultRegions": false,
    "regions": {
      "999": {
        "regionID": 999,
        "regionCode": "aliyun",
        "regionName": "Aliyun",
        "nodes": [{"name": "aliyun", "regionID": 999}],
      },
    },
  },
}`
	cfg := APIConfig{RegionID: 900, RegionCode: "home", RegionName: "Home", NodeName: "managed", Hostname: "derp.example.com"}
	updated, changed, err := patchDERPMap(source, cfg, &endpoint.Endpoint{IPv4: "8.8.8.8", DERPPort: 4443, STUNPort: 33478}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("patch reported no change")
	}
	for _, key := range []string{"regions", "regionID", "regionCode", "regionName", "nodes", "name", "hostName", "ipv4", "derpPort", "stunPort"} {
		if !strings.Contains(updated, `"`+key+`"`) {
			t.Errorf("new region does not contain lower-camel key %q:\n%s", key, updated)
		}
	}
	for _, key := range []string{"Regions", "RegionID", "RegionCode", "RegionName", "Nodes", "Name", "HostName", "IPv4", "DERPPort", "STUNPort"} {
		if strings.Contains(updated, `"`+key+`"`) {
			t.Errorf("new region added PascalCase key %q:\n%s", key, updated)
		}
	}
	if !strings.Contains(updated, `"999"`) || !strings.Contains(updated, `"900"`) {
		t.Fatalf("expected both existing and new regions:\n%s", updated)
	}
}

func TestWithdrawDERPMapRemovesOnlyManagedNode(t *testing.T) {
	source := `{"derpMap":{"Regions":{"900":{"RegionID":900,"Nodes":[{"Name":"managed","RegionID":900},{"Name":"keep","RegionID":900}]}}}}`
	cfg := APIConfig{RegionID: 900, NodeName: "managed"}
	updated, changed, err := patchDERPMap(source, cfg, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if !changed || strings.Contains(updated, `"managed"`) || !strings.Contains(updated, `"keep"`) || !strings.Contains(updated, `"900"`) {
		t.Fatalf("unexpected withdrawal result: %s", updated)
	}
}

func TestPatchDERPMapRejectsOwnershipConflict(t *testing.T) {
	source := `{"derpMap":{"Regions":{"900":{"RegionID":901,"Nodes":[]}}}}`
	_, _, err := patchDERPMap(source, APIConfig{RegionID: 900, NodeName: "managed"}, &endpoint.Endpoint{}, false)
	if err == nil {
		t.Fatal("ownership conflict was accepted")
	}
}

func TestPatchDERPMapRejectsAddingNodeToOccupiedRegion(t *testing.T) {
	source := `{"derpMap":{"Regions":{"900":{"RegionID":900,"Nodes":[{"Name":"someone-else","RegionID":900}]}}}}`
	_, _, err := patchDERPMap(source, APIConfig{RegionID: 900, NodeName: "managed"}, &endpoint.Endpoint{}, false)
	if err == nil {
		t.Fatal("occupied region was accepted without an owned node")
	}
}

func TestPatchDERPMapRejectsClaimingEmptyExistingRegion(t *testing.T) {
	source := `{"derpMap":{"Regions":{"900":{"RegionID":900,"Nodes":[]}}}}`
	_, _, err := patchDERPMap(source, APIConfig{RegionID: 900, NodeName: "managed"}, &endpoint.Endpoint{}, false)
	if err == nil {
		t.Fatal("empty existing region was accepted without an owned node")
	}
}

func TestWithdrawDERPMapRejectsUnclearNodeOwnership(t *testing.T) {
	source := `{"derpMap":{"Regions":{"900":{"RegionID":900,"Nodes":[{"Name":"managed"}]}}}}`
	_, _, err := patchDERPMap(source, APIConfig{RegionID: 900, NodeName: "managed"}, nil, true)
	if err == nil {
		t.Fatal("node without matching RegionID was withdrawn")
	}
}
