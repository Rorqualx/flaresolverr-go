package browser

import (
	"strings"
	"testing"
)

func TestBuiltinProfiles(t *testing.T) {
	expected := []string{"default", "desktop-chrome-windows", "desktop-chrome-mac", "minimal"}
	for _, name := range expected {
		if _, ok := BuiltinProfiles[name]; !ok {
			t.Errorf("Expected builtin profile %q to exist", name)
		}
	}
}

func TestResolveProfile_Default(t *testing.T) {
	profile := ResolveProfile("", nil, nil)
	if profile == nil {
		t.Fatal("Expected non-nil profile")
	}
	if profile.ScreenWidth != 1920 {
		t.Errorf("Expected default ScreenWidth 1920, got %d", profile.ScreenWidth)
	}
}

func TestResolveProfile_BuiltinLookup(t *testing.T) {
	profile := ResolveProfile("desktop-chrome-mac", nil, nil)
	if profile.ScreenWidth != 2560 {
		t.Errorf("Expected mac ScreenWidth 2560, got %d", profile.ScreenWidth)
	}
	if profile.WebGLVendor == "" {
		t.Error("Expected non-empty WebGLVendor for mac profile")
	}
}

func TestResolveProfile_Overrides(t *testing.T) {
	overrides := map[string]any{
		"timezone":    "Europe/Paris",
		"screenWidth": float64(1280),
	}
	profile := ResolveProfile("default", overrides, nil)
	if profile.Timezone != "Europe/Paris" {
		t.Errorf("Expected timezone 'Europe/Paris', got %q", profile.Timezone)
	}
	if profile.ScreenWidth != 1280 {
		t.Errorf("Expected screenWidth 1280, got %d", profile.ScreenWidth)
	}
}

func TestResolveProfile_DisablePatches(t *testing.T) {
	profile := ResolveProfile("default", nil, []string{"canvas", "audio"})
	if len(profile.DisabledPatches) != 2 {
		t.Fatalf("Expected 2 disabled patches, got %d", len(profile.DisabledPatches))
	}
	if !profile.isPatchDisabled("canvas") {
		t.Error("Expected 'canvas' to be disabled")
	}
	if !profile.isPatchDisabled("audio") {
		t.Error("Expected 'audio' to be disabled")
	}
	if profile.isPatchDisabled("webdriver") {
		t.Error("Expected 'webdriver' to NOT be disabled")
	}
}

func TestBuildFingerprintOverrides(t *testing.T) {
	tests := []struct {
		name    string
		profile *FingerprintProfile
		want    []string // Strings that should appear in the output
		notWant []string // Strings that should NOT appear
	}{
		{
			name:    "nil profile",
			profile: nil,
			want:    []string{},
		},
		{
			name: "timezone override",
			profile: &FingerprintProfile{
				Timezone:       "America/New_York",
				TimezoneOffset: -300,
			},
			want: []string{
				`window.__stealthTimezone = "America/New_York"`,
				`window.__stealthTimezoneOffset = -300`,
			},
		},
		{
			name: "webgl overrides",
			profile: &FingerprintProfile{
				WebGLVendor:   "Google Inc. (NVIDIA)",
				WebGLRenderer: "ANGLE (NVIDIA)",
			},
			want: []string{
				`window.__stealthWebGLVendor = "Google Inc. (NVIDIA)"`,
				`window.__stealthWebGLRenderer = "ANGLE (NVIDIA)"`,
			},
		},
		{
			name: "disabled patches",
			profile: &FingerprintProfile{
				DisabledPatches: []string{"canvas", "audio"},
			},
			want: []string{
				`window.__stealthDisable_canvas = true`,
				`window.__stealthDisable_audio = true`,
			},
			notWant: []string{
				`window.__stealthDisable_webdriver`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildFingerprintOverrides(tt.profile)
			for _, w := range tt.want {
				if !strings.Contains(got, w) {
					t.Errorf("Expected output to contain %q, got:\n%s", w, got)
				}
			}
			for _, nw := range tt.notWant {
				if strings.Contains(got, nw) {
					t.Errorf("Expected output NOT to contain %q, got:\n%s", nw, got)
				}
			}
		})
	}
}

func TestValidProfileName(t *testing.T) {
	tests := []struct {
		name  string
		valid bool
	}{
		{"default", true},
		{"desktop-chrome-windows", true},
		{"desktop-chrome-mac", true},
		{"minimal", true},
		{"unknown", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := ValidProfileName(tt.name); got != tt.valid {
			t.Errorf("ValidProfileName(%q) = %v, want %v", tt.name, got, tt.valid)
		}
	}
}

func TestValidPatchName(t *testing.T) {
	tests := []struct {
		name  string
		valid bool
	}{
		{"webrtc", true},
		{"webdriver", true},
		{"canvas", true},
		{"audio", true},
		{"timezone", true},
		{"unknown-patch", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := ValidPatchName(tt.name); got != tt.valid {
			t.Errorf("ValidPatchName(%q) = %v, want %v", tt.name, got, tt.valid)
		}
	}
}

func TestAllPatches_Count(t *testing.T) {
	if len(AllPatches) != 20 {
		t.Errorf("Expected 20 patches, got %d", len(AllPatches))
	}
}

func TestMinimalProfile_HasDisabledPatches(t *testing.T) {
	minimal := BuiltinProfiles["minimal"]
	if len(minimal.DisabledPatches) == 0 {
		t.Error("Expected minimal profile to have disabled patches")
	}
}
