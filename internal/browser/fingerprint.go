package browser

import (
	"fmt"
	"strings"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/rs/zerolog/log"
)

// FingerprintProfile defines configurable browser fingerprint dimensions.
type FingerprintProfile struct {
	Name                string
	UserAgent           string // empty = use browser default
	Timezone            string // e.g. "America/New_York"
	TimezoneOffset      int    // minutes from UTC (e.g. -300 for EST)
	Locale              string // e.g. "en-US"
	ScreenWidth         int    // 0 = use default (1920)
	ScreenHeight        int    // 0 = use default (1080)
	ColorDepth          int    // 0 = use default (24)
	DeviceMemory        int    // GB, 0 = use default (8)
	HardwareConcurrency int    // 0 = use default (4)
	WebGLVendor         string // empty = use default
	WebGLRenderer       string // empty = use default
	CanvasNoiseSeed     int    // 0-255, -1 for random, 0 = default
	DisabledPatches     []string
}

// StealthPatch represents a named patch in the stealth script.
type StealthPatch struct {
	Name  string
	Index int // Section number in the stealth script (0-19)
}

// AllPatches lists all available stealth patches by name and index.
var AllPatches = []StealthPatch{
	{Name: "webrtc", Index: 0},
	{Name: "webdriver", Index: 1},
	{Name: "plugins", Index: 2},
	{Name: "languages", Index: 3},
	{Name: "chrome-runtime", Index: 4},
	{Name: "permissions", Index: 5},
	{Name: "connection", Index: 6},
	{Name: "hardware-concurrency", Index: 7},
	{Name: "device-memory", Index: 8},
	{Name: "tostring", Index: 9},
	{Name: "webgl", Index: 10},
	{Name: "notifications", Index: 11},
	{Name: "canvas", Index: 12},
	{Name: "audio", Index: 13},
	{Name: "battery", Index: 14},
	{Name: "speech", Index: 15},
	{Name: "fonts", Index: 16},
	{Name: "timezone", Index: 17},
	{Name: "screen-position", Index: 18},
	{Name: "device-pixel-ratio", Index: 19},
}

// BuiltinProfiles contains preset fingerprint profiles.
var BuiltinProfiles = map[string]*FingerprintProfile{
	"default": {
		Name:                "default",
		ScreenWidth:         1920,
		ScreenHeight:        1080,
		ColorDepth:          24,
		DeviceMemory:        8,
		HardwareConcurrency: 4,
	},
	"desktop-chrome-windows": {
		Name:                "desktop-chrome-windows",
		Timezone:            "America/New_York",
		TimezoneOffset:      -300,
		Locale:              "en-US",
		ScreenWidth:         1920,
		ScreenHeight:        1080,
		ColorDepth:          24,
		DeviceMemory:        16,
		HardwareConcurrency: 8,
		WebGLVendor:         "Google Inc. (NVIDIA)",
		WebGLRenderer:       "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)",
	},
	"desktop-chrome-mac": {
		Name:                "desktop-chrome-mac",
		Timezone:            "America/Los_Angeles",
		TimezoneOffset:      -480,
		Locale:              "en-US",
		ScreenWidth:         2560,
		ScreenHeight:        1440,
		ColorDepth:          30,
		DeviceMemory:        16,
		HardwareConcurrency: 10,
		WebGLVendor:         "Google Inc. (Apple)",
		WebGLRenderer:       "ANGLE (Apple, Apple M1 Pro, OpenGL 4.1)",
	},
	"minimal": {
		Name:            "minimal",
		ScreenWidth:     1920,
		ScreenHeight:    1080,
		DisabledPatches: []string{"canvas", "audio", "battery", "speech", "fonts", "screen-position", "device-pixel-ratio"},
	},
}

// isPatchDisabled checks if a patch is in the disabled list.
func (p *FingerprintProfile) isPatchDisabled(name string) bool {
	for _, disabled := range p.DisabledPatches {
		if disabled == name {
			return true
		}
	}
	return false
}

// BuildFingerprintOverrides generates JavaScript to inject BEFORE the stealth script
// that sets configurable values used by the stealth patches.
func BuildFingerprintOverrides(profile *FingerprintProfile) string {
	if profile == nil {
		return ""
	}

	var sb strings.Builder

	// Set configurable values that stealth patches read
	if profile.Timezone != "" {
		sb.WriteString(fmt.Sprintf("window.__stealthTimezone = %q;\n", profile.Timezone))
		sb.WriteString(fmt.Sprintf("window.__stealthTimezoneOffset = %d;\n", profile.TimezoneOffset))
	}
	if profile.Locale != "" {
		sb.WriteString(fmt.Sprintf("window.__stealthLocale = %q;\n", profile.Locale))
	}
	if profile.ScreenWidth > 0 {
		sb.WriteString(fmt.Sprintf("window.__stealthScreenWidth = %d;\n", profile.ScreenWidth))
		sb.WriteString(fmt.Sprintf("window.__stealthScreenHeight = %d;\n", profile.ScreenHeight))
	}
	if profile.ColorDepth > 0 {
		sb.WriteString(fmt.Sprintf("window.__stealthColorDepth = %d;\n", profile.ColorDepth))
	}
	if profile.DeviceMemory > 0 {
		sb.WriteString(fmt.Sprintf("window.__stealthDeviceMemory = %d;\n", profile.DeviceMemory))
	}
	if profile.HardwareConcurrency > 0 {
		sb.WriteString(fmt.Sprintf("window.__stealthHardwareConcurrency = %d;\n", profile.HardwareConcurrency))
	}
	if profile.WebGLVendor != "" {
		sb.WriteString(fmt.Sprintf("window.__stealthWebGLVendor = %q;\n", profile.WebGLVendor))
	}
	if profile.WebGLRenderer != "" {
		sb.WriteString(fmt.Sprintf("window.__stealthWebGLRenderer = %q;\n", profile.WebGLRenderer))
	}
	if profile.CanvasNoiseSeed > 0 {
		sb.WriteString(fmt.Sprintf("window.__canvasSeed = %d;\n", profile.CanvasNoiseSeed))
	}

	// Set patch disable flags
	for _, patch := range AllPatches {
		if profile.isPatchDisabled(patch.Name) {
			sb.WriteString(fmt.Sprintf("window.__stealthDisable_%s = true;\n", strings.ReplaceAll(patch.Name, "-", "_")))
		}
	}

	return sb.String()
}

// BuildStealthScriptWithProfile wraps the stealth script with patch-disable guards
// and fingerprint overrides. The original stealthScript is used as-is to minimize risk.
func BuildStealthScriptWithProfile(profile *FingerprintProfile) string {
	if profile == nil || len(profile.DisabledPatches) == 0 {
		return BuildFingerprintOverrides(profile) + stealthScript
	}

	// The stealth script checks window.__stealthDisable_<name> flags
	// which are set by BuildFingerprintOverrides.
	// We prepend the overrides before the stealth script.
	return BuildFingerprintOverrides(profile) + stealthScript
}

// ApplyStealthToPageWithProfile applies anti-detection measures with a custom fingerprint profile.
// This should be called after page creation but BEFORE navigation.
func ApplyStealthToPageWithProfile(page *rod.Page, profile *FingerprintProfile) error {
	if profile == nil {
		return ApplyStealthToPage(page)
	}

	log.Debug().Str("profile", profile.Name).Msg("Applying stealth patches with custom fingerprint")

	// Inject fingerprint overrides before the stealth script
	overrides := BuildFingerprintOverrides(profile)
	if overrides != "" {
		_, err := page.Evaluate(rod.Eval(overrides))
		if err != nil {
			log.Warn().Err(err).Msg("Failed to inject fingerprint overrides")
		}
	}

	// Apply the main stealth script
	_, err := page.Evaluate(rod.Eval(stealthScript))
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "SyntaxError") {
			return fmt.Errorf("stealth script syntax error: %w", err)
		}
		if strings.Contains(errStr, "ReferenceError") {
			return fmt.Errorf("stealth script reference error: %w", err)
		}
		log.Warn().Err(err).Msg("Stealth script had non-fatal errors, continuing")
		return nil
	}

	// Apply viewport override if profile specifies screen size
	if profile.ScreenWidth > 0 && profile.ScreenHeight > 0 {
		if err := page.SetViewport(&proto.EmulationSetDeviceMetricsOverride{
			Width:             profile.ScreenWidth,
			Height:            profile.ScreenHeight,
			DeviceScaleFactor: 1,
			Mobile:            false,
		}); err != nil {
			log.Warn().Err(err).Msg("Failed to set viewport from fingerprint profile")
		}
	}

	// Apply user agent override if specified
	if profile.UserAgent != "" {
		if err := SetUserAgent(page, profile.UserAgent); err != nil {
			log.Warn().Err(err).Msg("Failed to set user agent from fingerprint profile")
		}
	}

	return nil
}

// ResolveProfile resolves a FingerprintConfig from the API into a FingerprintProfile.
// It looks up a builtin profile by name and applies any overrides.
func ResolveProfile(profileName string, overrides map[string]any, disablePatches []string) *FingerprintProfile {
	var profile *FingerprintProfile

	if profileName != "" {
		if builtin, ok := BuiltinProfiles[profileName]; ok {
			// Copy the builtin profile
			copy := *builtin
			profile = &copy
		}
	}

	if profile == nil {
		// Start with default profile
		def := *BuiltinProfiles["default"]
		profile = &def
	}

	// Apply overrides
	if overrides != nil {
		if v, ok := overrides["timezone"].(string); ok {
			profile.Timezone = v
		}
		if v, ok := overrides["locale"].(string); ok {
			profile.Locale = v
		}
		if v, ok := overrides["webglVendor"].(string); ok {
			profile.WebGLVendor = v
		}
		if v, ok := overrides["webglRenderer"].(string); ok {
			profile.WebGLRenderer = v
		}
		if v, ok := overrides["screenWidth"].(float64); ok {
			profile.ScreenWidth = int(v)
		}
		if v, ok := overrides["screenHeight"].(float64); ok {
			profile.ScreenHeight = int(v)
		}
		if v, ok := overrides["deviceMemory"].(float64); ok {
			profile.DeviceMemory = int(v)
		}
		if v, ok := overrides["hardwareConcurrency"].(float64); ok {
			profile.HardwareConcurrency = int(v)
		}
		if v, ok := overrides["canvasNoiseSeed"].(float64); ok {
			profile.CanvasNoiseSeed = int(v)
		}
	}

	// Merge disabled patches
	if len(disablePatches) > 0 {
		profile.DisabledPatches = append(profile.DisabledPatches, disablePatches...)
	}

	return profile
}

// ValidProfileName checks if a profile name is a valid builtin profile.
func ValidProfileName(name string) bool {
	_, ok := BuiltinProfiles[name]
	return ok
}

// ValidPatchName checks if a patch name is valid.
func ValidPatchName(name string) bool {
	for _, p := range AllPatches {
		if p.Name == name {
			return true
		}
	}
	return false
}
