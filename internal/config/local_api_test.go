package config

import (
	"net/netip"
	"testing"
)

func TestParsePrefix(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "10.0.0.0/8", want: "10.0.0.0/8"},
		{in: "10.1.2.3/8", want: "10.0.0.0/8"}, // host bits are masked off
		{in: "172.18.0.1", want: "172.18.0.1/32"},
		{in: "fd00::/8", want: "fd00::/8"},
		{in: "fd00::1", want: "fd00::1/128"},
		{in: "::ffff:10.0.0.1", want: "10.0.0.1/32"},
		{in: "::ffff:10.0.0.0/104", want: "10.0.0.0/8"},
		{in: "::ffff:10.0.0.0/64", wantErr: true},
		{in: "", wantErr: true},
		{in: "proxy.internal", wantErr: true},
		{in: "10.0.0.0/33", wantErr: true},
		{in: "10.0.0.1/", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := parsePrefix(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parsePrefix(%q) = %v, want error", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parsePrefix(%q) error = %v", tt.in, err)
			}
			if got.String() != tt.want {
				t.Errorf("parsePrefix(%q) = %v, want %s", tt.in, got, tt.want)
			}
		})
	}
}

func TestLocalAPIDefaults(t *testing.T) {
	for _, key := range []string{"TRUSTED_PROXIES", "ALLOWED_HOSTS", "STRICT_CONTENT_TYPE"} {
		t.Setenv(key, "")
	}

	cfg := Load()
	if !cfg.StrictContentType {
		t.Error("StrictContentType must default to true")
	}
	if len(cfg.TrustedProxies) != 0 {
		t.Errorf("TrustedProxies = %v, want none by default", cfg.TrustedProxies)
	}
	if len(cfg.AllowedHosts) != 0 {
		t.Errorf("AllowedHosts = %v, want none by default", cfg.AllowedHosts)
	}
}

func TestLocalAPIFromEnv(t *testing.T) {
	t.Setenv("TRUSTED_PROXIES", "10.0.0.0/8, 172.18.0.1 ,not-a-cidr, fd00::/8")
	t.Setenv("ALLOWED_HOSTS", "solver.internal.example, .lan.example")
	t.Setenv("STRICT_CONTENT_TYPE", "false")

	cfg := Load()

	want := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.18.0.1/32"),
		netip.MustParsePrefix("fd00::/8"),
	}
	if len(cfg.TrustedProxies) != len(want) {
		t.Fatalf("TrustedProxies = %v, want %v (invalid entries skipped)", cfg.TrustedProxies, want)
	}
	for i := range want {
		if cfg.TrustedProxies[i] != want[i] {
			t.Errorf("TrustedProxies[%d] = %v, want %v", i, cfg.TrustedProxies[i], want[i])
		}
	}

	if len(cfg.AllowedHosts) != 2 || cfg.AllowedHosts[0] != "solver.internal.example" || cfg.AllowedHosts[1] != ".lan.example" {
		t.Errorf("AllowedHosts = %v", cfg.AllowedHosts)
	}
	if cfg.StrictContentType {
		t.Error("STRICT_CONTENT_TYPE=false was not honored")
	}
}
