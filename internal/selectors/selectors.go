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
	TurnstileSelectors    []string `yaml:"turnstile_selectors"`
	TurnstileFramePattern string   `yaml:"turnstile_frame_pattern"`
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
		TurnstileSelectors: []string{
			"input[type='checkbox']",
			".cf-turnstile-response",
			"#cf-turnstile-response",
			"[data-testid='cf-turnstile-response']",
		},
		TurnstileFramePattern: "challenges.cloudflare.com",
	}
}
