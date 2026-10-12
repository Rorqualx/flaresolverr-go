package security

import (
	"errors"
	"testing"
)

// TestValidateOperatorProxyURL verifies the operator's own proxy may live on a
// private or Docker-network address (which the caller-facing check refuses by
// default), while malformed values and metadata endpoints are still refused.
func TestValidateOperatorProxyURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr error // nil means valid
		anyErr  bool
	}{
		{name: "not configured", url: ""},
		{name: "public proxy", url: "http://proxy.example.com:3128"},
		{name: "private address", url: "http://10.0.0.5:3128"},
		{name: "loopback", url: "socks5://127.0.0.1:1080"},
		{name: "docker service name", url: "http://gluetun:8888"},
		{name: "docker bridge gateway", url: "http://172.17.0.1:3128"},
		{name: "metadata IP", url: "http://169.254.169.254:80", wantErr: ErrMetadataBlocked},
		{name: "metadata hostname", url: "http://metadata.google.internal", wantErr: ErrMetadataBlocked},
		{name: "unsupported scheme", url: "ftp://10.0.0.5:21", wantErr: ErrBlockedProxyScheme},
		{name: "port out of range", url: "http://10.0.0.5:99999", anyErr: true},
		{name: "no host", url: "http://", anyErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateOperatorProxyURL(tt.url)
			switch {
			case tt.wantErr != nil:
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("ValidateOperatorProxyURL(%q) = %v, want %v", tt.url, err, tt.wantErr)
				}
			case tt.anyErr:
				if err == nil {
					t.Errorf("ValidateOperatorProxyURL(%q) = nil, want an error", tt.url)
				}
			default:
				if err != nil {
					t.Errorf("ValidateOperatorProxyURL(%q) = %v, want nil", tt.url, err)
				}
			}
		})
	}

	// The same private address is refused when a caller supplies it
	if err := ValidateProxyURL("http://10.0.0.5:3128", false); err == nil {
		t.Error("caller-supplied private proxy must still be refused by default")
	}
}
