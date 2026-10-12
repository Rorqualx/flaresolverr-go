package security

import (
	"errors"
	"net"
	"testing"
)

func TestValidateIP(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		wantErr error
	}{
		{name: "public v4", ip: "93.184.216.34"},
		{name: "public v6", ip: "2606:4700:4700::1111"},
		{name: "loopback", ip: "127.0.0.1", wantErr: ErrLocalhostBlocked},
		{name: "loopback range", ip: "127.9.9.9", wantErr: ErrLocalhostBlocked},
		{name: "v6 loopback", ip: "::1", wantErr: ErrLocalhostBlocked},
		{name: "rfc1918 10", ip: "10.99.0.2", wantErr: ErrPrivateIPBlocked},
		{name: "rfc1918 172", ip: "172.17.0.1", wantErr: ErrPrivateIPBlocked},
		{name: "rfc1918 192", ip: "192.168.50.185", wantErr: ErrPrivateIPBlocked},
		{name: "link local", ip: "169.254.1.1", wantErr: ErrPrivateIPBlocked},
		{name: "metadata", ip: "169.254.169.254", wantErr: ErrPrivateIPBlocked},
		{name: "alibaba metadata", ip: "100.100.100.200", wantErr: ErrMetadataBlocked},
		{name: "cgnat", ip: "100.64.0.1", wantErr: ErrPrivateIPBlocked},
		{name: "unspecified", ip: "0.0.0.0", wantErr: ErrPrivateIPBlocked},
		{name: "multicast", ip: "224.0.0.1", wantErr: ErrPrivateIPBlocked},
		{name: "v4 mapped private", ip: "::ffff:10.0.0.1", wantErr: ErrPrivateIPBlocked},
		{name: "v4 mapped loopback", ip: "::ffff:127.0.0.1", wantErr: ErrLocalhostBlocked},
		{name: "nat64 private", ip: "64:ff9b::a00:1", wantErr: ErrPrivateIPBlocked},
		{name: "unique local v6", ip: "fd00::1", wantErr: ErrPrivateIPBlocked},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateIP(net.ParseIP(tt.ip))
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("ValidateIP(%s) = %v, want nil", tt.ip, err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ValidateIP(%s) = %v, want %v", tt.ip, err, tt.wantErr)
			}
		})
	}

	if err := ValidateIP(nil); err == nil {
		t.Fatal("ValidateIP(nil) = nil, want an error")
	}
}

func TestClassifyEgressHost(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		wantIP  string // "" when the host is a name
		wantErr bool
	}{
		{name: "public name", host: "example.com"},
		{name: "public name trailing dot", host: "example.com."},
		{name: "public literal", host: "93.184.216.34", wantIP: "93.184.216.34"},
		{name: "public v6 literal", host: "2606:4700:4700::1111", wantIP: "2606:4700:4700::1111"},
		{name: "localhost", host: "localhost", wantErr: true},
		{name: "localhost upper", host: "LOCALHOST", wantErr: true},
		{name: "localhost trailing dot", host: "localhost.", wantErr: true},
		{name: "localhost subdomain", host: "foo.localhost", wantErr: true},
		{name: "metadata name", host: "metadata.google.internal", wantErr: true},
		{name: "kubernetes", host: "kubernetes.default.svc", wantErr: true},
		{name: "private literal", host: "10.99.0.2", wantErr: true},
		{name: "loopback literal", host: "127.0.0.1", wantErr: true},
		{name: "octal private", host: "01230600002", wantErr: true},
		{name: "dotted octal loopback", host: "0177.0.0.1", wantErr: true},
		{name: "hex loopback", host: "0x7f000001", wantErr: true},
		{name: "decimal loopback", host: "2130706433", wantErr: true},
		{name: "short loopback", host: "127.1", wantErr: true},
		{name: "literal trailing dot", host: "10.0.0.1.", wantErr: true},
		{name: "mapped private", host: "::ffff:10.0.0.1", wantErr: true},
		{name: "metadata literal", host: "169.254.169.254", wantErr: true},
		{name: "cgnat literal", host: "100.64.0.1", wantErr: true},
		{name: "empty", host: "", wantErr: true},
		{name: "only dot", host: ".", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, err := ClassifyEgressHost(tt.host)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ClassifyEgressHost(%q) = %v, nil; want an error", tt.host, ip)
				}
				return
			}
			if err != nil {
				t.Fatalf("ClassifyEgressHost(%q) error = %v", tt.host, err)
			}
			if tt.wantIP == "" {
				if ip != nil {
					t.Fatalf("ClassifyEgressHost(%q) = %v, want a name (nil)", tt.host, ip)
				}
				return
			}
			if !ip.Equal(net.ParseIP(tt.wantIP)) {
				t.Fatalf("ClassifyEgressHost(%q) = %v, want %s", tt.host, ip, tt.wantIP)
			}
		})
	}
}
