// Package cert manages the automatically generated TLS identity.
package cert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const renewBefore = 30 * 24 * time.Hour

// Manager safely replaces self-signed certificates as their SAN set changes.
// The private key is stable, so replacing a certificate only requires one
// atomic file update after the initial key has been created.
type Manager struct {
	mu        sync.RWMutex
	dir       string
	baseNames []string
	endpoint  string
	current   *tls.Certificate
	certName  string
	expected  [sha256.Size]byte
	validTo   time.Time
}

func NewManager(dir string, names []string) (*Manager, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("TLS state directory is required")
	}
	m := &Manager{dir: dir, baseNames: normalizeNames(names)}
	if certificate, validTo, err := m.loadCurrent(); err == nil && time.Until(validTo) > renewBefore && containsNames(certificate, m.baseNames) {
		m.setCurrent(certificate, validTo, "")
		return m, nil
	}
	if err := m.updateLocked(""); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manager) loadCurrent() (*tls.Certificate, time.Time, error) {
	certificate, err := tls.LoadX509KeyPair(filepath.Join(m.dir, "cert.pem"), filepath.Join(m.dir, "key.pem"))
	if err != nil {
		return nil, time.Time{}, err
	}
	if len(certificate.Certificate) == 0 {
		return nil, time.Time{}, errors.New("certificate has no leaf")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, time.Time{}, err
	}
	return &certificate, leaf.NotAfter, nil
}

func (m *Manager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.current == nil {
		return nil, errors.New("automatic TLS certificate is unavailable")
	}
	return m.current, nil
}

func (m *Manager) CertName() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.certName
}

func (m *Manager) ExpectedCertHash() []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]byte(nil), m.expected[:]...)
}

// UpdateEndpointIP refreshes the certificate before an endpoint is validated
// or published. An empty address removes a previous dynamic IP SAN.
func (m *Manager) UpdateEndpointIP(ip string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ip = strings.TrimSpace(ip)
	if ip == m.endpoint && m.current != nil && time.Until(m.validTo) > renewBefore {
		return nil
	}
	return m.updateLocked(ip)
}

func (m *Manager) updateLocked(endpoint string) error {
	names := append([]string(nil), m.baseNames...)
	if endpoint != "" {
		names = append(names, endpoint)
	}
	names = normalizeNames(names)
	if len(names) == 0 {
		names = []string{"localhost"}
	}

	if certificate, validTo, err := m.loadExisting(names); err == nil && time.Until(validTo) > renewBefore {
		m.setCurrent(certificate, validTo, endpoint)
		return nil
	}

	certificate, validTo, err := m.generate(names)
	if err != nil {
		return err
	}
	if err := m.persist(certificate); err != nil {
		return err
	}
	m.setCurrent(certificate, validTo, endpoint)
	return nil
}

func (m *Manager) setCurrent(certificate *tls.Certificate, validTo time.Time, endpoint string) {
	m.current = certificate
	m.validTo = validTo
	m.endpoint = endpoint
	m.expected = sha256.Sum256(certificate.Certificate[0])
	m.certName = "sha256-raw:" + hex.EncodeToString(m.expected[:])
}

func (m *Manager) loadExisting(names []string) (*tls.Certificate, time.Time, error) {
	certificate, err := tls.LoadX509KeyPair(filepath.Join(m.dir, "cert.pem"), filepath.Join(m.dir, "key.pem"))
	if err != nil {
		return nil, time.Time{}, err
	}
	if len(certificate.Certificate) == 0 {
		return nil, time.Time{}, errors.New("certificate has no leaf")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, time.Time{}, err
	}
	if !sameNames(leaf, names) || time.Now().After(leaf.NotAfter) {
		return nil, time.Time{}, errors.New("certificate SANs or validity do not match")
	}
	return &certificate, leaf.NotAfter, nil
}

func (m *Manager) generate(names []string) (*tls.Certificate, time.Time, error) {
	keyPath := filepath.Join(m.dir, "key.pem")
	key, err := loadKey(keyPath)
	if err != nil && !os.IsNotExist(err) {
		return nil, time.Time{}, fmt.Errorf("load automatic TLS key: %w", err)
	}
	if key == nil {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("generate automatic TLS key: %w", err)
		}
		if err := os.MkdirAll(m.dir, 0o700); err != nil {
			return nil, time.Time{}, err
		}
		if err := writePrivateKey(keyPath, key); err != nil {
			return nil, time.Time{}, err
		}
	}

	now := time.Now().UTC()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, time.Time{}, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: names[0]},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	for _, name := range names {
		if ip, err := netip.ParseAddr(name); err == nil {
			template.IPAddresses = append(template.IPAddresses, net.IP(ip.AsSlice()))
		} else {
			template.DNSNames = append(template.DNSNames, name)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, time.Time{}, err
	}
	certificate := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return certificate, template.NotAfter, nil
}

func (m *Manager) persist(certificate *tls.Certificate) error {
	if len(certificate.Certificate) == 0 {
		return errors.New("automatic TLS certificate has no leaf")
	}
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return err
	}
	return atomicWrite(filepath.Join(m.dir, "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}), 0o644)
}

func loadKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("decode automatic TLS key PEM")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func writePrivateKey(path string, key *ecdsa.PrivateKey) error {
	raw, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	return atomicWrite(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: raw}), 0o600)
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func normalizeNames(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(strings.TrimSuffix(value, "."))
		if value == "" {
			continue
		}
		if ip, err := netip.ParseAddr(value); err == nil {
			value = ip.String()
		} else {
			value = strings.ToLower(value)
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func sameNames(certificate *x509.Certificate, names []string) bool {
	actual := append([]string(nil), certificate.DNSNames...)
	for _, ip := range certificate.IPAddresses {
		actual = append(actual, ip.String())
	}
	return bytes.Equal([]byte(strings.Join(normalizeNames(actual), "\x00")), []byte(strings.Join(normalizeNames(names), "\x00")))
}

func containsNames(certificate *tls.Certificate, names []string) bool {
	if len(certificate.Certificate) == 0 {
		return false
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return false
	}
	actual := make(map[string]struct{})
	for _, name := range normalizeNames(append(append([]string(nil), leaf.DNSNames...), ipStrings(leaf.IPAddresses)...)) {
		actual[name] = struct{}{}
	}
	for _, name := range normalizeNames(names) {
		if _, ok := actual[name]; !ok {
			return false
		}
	}
	return true
}

func ipStrings(values []net.IP) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.String())
	}
	return result
}
