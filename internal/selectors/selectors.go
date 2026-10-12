// Package selectors provides challenge detection pattern loading and management.
package selectors

import (
	"embed"
	"sync"

	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
)

//go:embed selectors.yaml
var defaultSelectorsFS embed.FS

// Selectors contains all challenge detection patterns.
type Selectors struct {
	AccessDenied          []string `yaml:"access_denied"`
	Turnstile             []string `yaml:"turnstile"`
	JavaScript            []string `yaml:"javascript"`
	Captcha               []string `yaml:"captcha"` // hCaptcha/reCAPTCHA detection patterns
	TurnstileSelectors    []string `yaml:"turnstile_selectors"`
	TurnstileFramePattern string   `yaml:"turnstile_frame_pattern"`
	ShadowHosts           []string `yaml:"shadow_hosts"`
	ShadowInnerSelectors  []string `yaml:"shadow_inner_selectors"`

	// Challenge-in-progress detection
	ChallengeTitles    []string `yaml:"challenge_titles"`    // Lowercase substrings of the page title
	ChallengeSelectors []string `yaml:"challenge_selectors"` // CSS selectors, checked in order

	// Turnstile widget location
	TurnstileTriggerSelectors   []string `yaml:"turnstile_trigger_selectors"`   // Challenge selectors that start Turnstile solving
	TurnstileWidgetSelectors    []string `yaml:"turnstile_widget_selectors"`    // The widget; the first is the one inspected
	TurnstileClickSelectors     []string `yaml:"turnstile_click_selectors"`     // Elements to click, in order of preference
	TurnstileContainerSelectors []string `yaml:"turnstile_container_selectors"` // Containers for a positional click
	TurnstileLandmarkSelector   string   `yaml:"turnstile_landmark_selector"`   // The hidden response input
}

var (
	instance *Selectors
	once     sync.Once
	loadErr  error
)

// Get returns the singleton Selectors instance.
// Patterns are loaded from the embedded selectors.yaml file.
func Get() *Selectors {
	once.Do(func() {
		instance, loadErr = load()
		if loadErr != nil {
			log.Error().Err(loadErr).Msg("Failed to load selectors, using defaults")
			instance = defaultSelectors()
		}
	})
	return instance
}

// load reads selectors from the embedded YAML file.
func load() (*Selectors, error) {
	data, err := defaultSelectorsFS.ReadFile("selectors.yaml")
	if err != nil {
		return nil, err
	}

	var s Selectors
	if err := yaml.Unmarshal(data, &s); err != nil {
		return nil, err
	}

	log.Debug().
		Int("access_denied_patterns", len(s.AccessDenied)).
		Int("turnstile_patterns", len(s.Turnstile)).
		Int("javascript_patterns", len(s.JavaScript)).
		Msg("Selectors loaded")

	return &s, nil
}

// defaultSelectors returns hardcoded fallback patterns.
func defaultSelectors() *Selectors {
	return &Selectors{
		AccessDenied: []string{
			"access denied",
			"error 1015",
			"error 1012",
			"error 1020",
			"you have been blocked",
			"ray id:",
		},
		Turnstile: []string{
			"cf-turnstile",
			"challenges.cloudflare.com/turnstile",
			"turnstile-wrapper",
		},
		JavaScript: []string{
			"just a moment",
			"checking your browser",
			"please wait",
			"ddos-guard",
			"__cf_chl_opt",
			"_cf_chl_opt",
			"cf-challenge",
			"cf_chl_prog",
		},
		Captcha: []string{
			"hcaptcha.com",
			"h-captcha",
			"hcaptcha-checkbox",
			"recaptcha",
			"grecaptcha",
			"g-recaptcha",
			"recaptcha/api",
		},
		TurnstileSelectors: []string{
			"input[type='checkbox']",
			".cf-turnstile-response",
			"#cf-turnstile-response",
			"[data-testid='cf-turnstile-response']",
		},
		TurnstileFramePattern: "challenges.cloudflare.com",
		ShadowHosts: []string{
			"div.cf-turnstile-wrapper",
			".cf-turnstile",
			"#turnstile-wrapper",
			"[data-sitekey]",
			".turnstile-container",
			"[data-cf-turnstile]",
		},
		ShadowInnerSelectors: []string{
			"input[type='checkbox']",
			"[role='checkbox']",
			".checkbox",
			"#checkbox",
			"[aria-checked]",
			"label input",
		},
		ChallengeTitles: []string{
			"just a moment",
			"checking your browser",
			"ddos-guard",
			"please wait",
			"attention required",
		},
		ChallengeSelectors: []string{
			"#cf-challenge-running",
			".ray_id",
			"#turnstile-wrapper",
			".cf-turnstile",
			"#cf-wrapper",
			"#challenge-running",
			"#challenge-stage",
			"#cf-spinner-please-wait",
			"#cf-spinner-redirecting",
			"iframe[src*='challenges.cloudflare.com']",
		},
		TurnstileTriggerSelectors: []string{
			"#turnstile-wrapper",
			".cf-turnstile",
			"iframe[src*='challenges.cloudflare.com']",
			"#cf-challenge-running",
			"#challenge-stage",
		},
		TurnstileWidgetSelectors: []string{
			".cf-turnstile",
			"#turnstile-wrapper",
		},
		TurnstileClickSelectors: []string{
			".cf-turnstile iframe",
			"[data-sitekey] iframe",
			".cf-turnstile",
			"[data-sitekey]",
		},
		TurnstileContainerSelectors: []string{
			"#turnstile-wrapper",
			".cf-turnstile",
			"[data-sitekey]",
		},
		TurnstileLandmarkSelector: "input[name='cf-turnstile-response']",
	}
}
