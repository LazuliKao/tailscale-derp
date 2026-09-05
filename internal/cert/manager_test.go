package cert

import (
	"crypto/sha256"
	"crypto/x509"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestManagerPersistsSANsAndHash(t *testing.T) {
	dir := t.TempDir()
	manager, err := NewManager(dir, []string{"derp.example.com", "2001:db8::1", "DERP.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.UpdateEndpointIP("8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	certificate, err := manager.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.VerifyHostname("derp.example.com") != nil || leaf.VerifyHostname("8.8.8.8") != nil || leaf.VerifyHostname("2001:db8::1") != nil {
		t.Fatalf("certificate SANs do not cover expected names: DNS=%v IPs=%v", leaf.DNSNames, leaf.IPAddresses)
	}
	if !strings.HasPrefix(manager.CertName(), "sha256-raw:") {
		t.Fatalf("unexpected certificate name %q", manager.CertName())
	}
	want := sha256.Sum256(certificate.Certificate[0])
	if string(want[:]) != string(manager.ExpectedCertHash()) {
		t.Fatal("unexpected expected certificate hash")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(dir, "key.pem"))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("private key permissions = %v, err = %v", info.Mode(), err)
		}
	}

	reloaded, err := NewManager(dir, []string{"derp.example.com", "::1"})
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.CertName() == manager.CertName() {
		t.Fatal("changed SANs should issue a new certificate")
	}
}
