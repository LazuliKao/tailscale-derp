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
	for _, expected := range []string{`"RegionCode": "home"`, `"HostName": "derp.example.com"`, `"IPv4":"8.8.8.8"`, `"DERPPort":4443`, `"STUNPort":33478`} {
		if !strings.Contains(updated, expected) {
			t.Errorf("updated policy does not contain %s:\n%s", expected, updated)
		}
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
