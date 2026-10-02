package ops

import (
	"context"
	"fmt"
	"net/netip"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// Runtime keeps the admission verifier, API clients, and policy locks shared
// by the DERP server and all operations handlers.
type Runtime struct {
	verifier         *verifier
	certificateNames CertificateNameProvider
}

// CertificateNameProvider exposes the current self-signed certificate pin.
type CertificateNameProvider interface {
	CertName() string
}

func NewRuntime(ctx context.Context, cfg VerifyConfig) *Runtime {
	return &Runtime{verifier: newVerifierWithContext(ctx, cfg)}
}

func (r *Runtime) VerifyClientFunc() VerifyClientFunc {
	return func(ctx context.Context, nodeKey key.NodePublic, source netip.Addr) error {
		if r != nil && r.verifier != nil && r.verifier.verify(ctx, tailcfg.DERPAdmitClientRequest{
			NodePublic: nodeKey,
			Source:     source,
		}) {
			return nil
		}
		return fmt.Errorf("client %v not authorized by configured verifier", nodeKey)
	}
}

func (r *Runtime) SetCertificateNameProvider(provider CertificateNameProvider) {
	if r != nil {
		r.certificateNames = provider
	}
}
