package types

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

func TestFingerprintConfig_Timezone(t *testing.T) {
	tests := []struct {
		name   string
		config *FingerprintConfig
		want   string
	}{
		{name: "nil config", config: nil, want: ""},
		{name: "empty config", config: &FingerprintConfig{}, want: ""},
		{name: "timezone set", config: &FingerprintConfig{Overrides: map[string]any{"timezone": "Asia/Tokyo"}}, want: "Asia/Tokyo"},
		{name: "timezone among other overrides", config: &FingerprintConfig{Overrides: map[string]any{"screenWidth": 1280, "timezone": "Europe/Paris"}}, want: "Europe/Paris"},
		{name: "empty timezone", config: &FingerprintConfig{Overrides: map[string]any{"timezone": ""}}, want: ""},
		{name: "timezone of the wrong type", config: &FingerprintConfig{Overrides: map[string]any{"timezone": 9}}, want: ""},
		{name: "null timezone", config: &FingerprintConfig{Overrides: map[string]any{"timezone": nil}}, want: ""},
		{name: "profile only", config: &FingerprintConfig{Profile: "desktop-chrome-windows"}, want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.config.Timezone(); got != tt.want {
				t.Errorf("Timezone() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFingerprintConfig_IgnoredOptions(t *testing.T) {
	manyOverrides := make(map[string]any)
	for i := 0; i < 50; i++ {
		manyOverrides[fmt.Sprintf("key%02d", i)] = i
	}

	tests := []struct {
		name   string
		config *FingerprintConfig
		want   []string
	}{
		{name: "nil config", config: nil, want: nil},
		{name: "empty config", config: &FingerprintConfig{}, want: nil},
		{name: "timezone only is fully honored", config: &FingerprintConfig{Overrides: map[string]any{"timezone": "Asia/Tokyo"}}, want: nil},
		{name: "profile", config: &FingerprintConfig{Profile: "minimal"}, want: []string{"profile"}},
		{name: "disablePatches", config: &FingerprintConfig{DisablePatches: []string{"canvas"}}, want: []string{"disablePatches"}},
		{name: "empty disablePatches is not reported", config: &FingerprintConfig{DisablePatches: []string{}}, want: nil},
		{
			name:   "other overrides are named and sorted",
			config: &FingerprintConfig{Overrides: map[string]any{"timezone": "UTC", "webglVendor": "x", "locale": "fr-FR"}},
			want:   []string{"overrides.locale", "overrides.webglVendor"},
		},
		{
			name: "everything at once",
			config: &FingerprintConfig{
				Profile:        "desktop-chrome-mac",
				Overrides:      map[string]any{"screenWidth": 1280},
				DisablePatches: []string{"audio"},
			},
			want: []string{"profile", "disablePatches", "overrides.screenWidth"},
		},
		{
			name:   "a large overrides object is capped",
			config: &FingerprintConfig{Profile: "default", Overrides: manyOverrides},
			want: []string{
				"profile", "overrides.key00", "overrides.key01", "overrides.key02", "overrides.key03",
				"overrides.key04", "overrides.key05", "overrides.key06", "overrides.key07", "overrides.key08",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.IgnoredOptions()
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("IgnoredOptions() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestRequestAcceptsRemovedFingerprintOptions checks that a request written
// for the removed fingerprint profiles still decodes and validates.
func TestRequestAcceptsRemovedFingerprintOptions(t *testing.T) {
	body := `{
		"cmd": "request.get",
		"url": "https://example.com",
		"fingerprint": {
			"profile": "desktop-chrome-windows",
			"overrides": {"timezone": "Asia/Tokyo", "screenWidth": 1920},
			"disablePatches": ["canvas", "audio"]
		}
	}`

	var req Request
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if err := req.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
	if got := req.Fingerprint.Timezone(); got != "Asia/Tokyo" {
		t.Errorf("Timezone() = %q, want %q", got, "Asia/Tokyo")
	}
	want := []string{"profile", "disablePatches", "overrides.screenWidth"}
	if got := req.Fingerprint.IgnoredOptions(); !reflect.DeepEqual(got, want) {
		t.Errorf("IgnoredOptions() = %v, want %v", got, want)
	}
}
