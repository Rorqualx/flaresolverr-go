package selectors

import (
	"reflect"
	"testing"
)

// TestMovedSelectorsKeepTheirValues pins the selectors that used to be
// hardcoded in the solver to the exact values, in the exact order, they had
// there. Moving them into selectors.yaml must not change what is detected; a
// deliberate change to a default belongs here too.
func TestMovedSelectorsKeepTheirValues(t *testing.T) {
	want := map[string]any{
		"ChallengeTitles": []string{
			"just a moment",
			"checking your browser",
			"ddos-guard",
			"please wait",
			"attention required",
		},
		"ChallengeSelectors": []string{
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
		"TurnstileTriggerSelectors": []string{
			"#turnstile-wrapper",
			".cf-turnstile",
			"iframe[src*='challenges.cloudflare.com']",
			"#cf-challenge-running",
			"#challenge-stage",
		},
		"TurnstileWidgetSelectors":    []string{".cf-turnstile", "#turnstile-wrapper"},
		"TurnstileClickSelectors":     []string{".cf-turnstile iframe", "[data-sitekey] iframe", ".cf-turnstile", "[data-sitekey]"},
		"TurnstileContainerSelectors": []string{"#turnstile-wrapper", ".cf-turnstile", "[data-sitekey]"},
		"TurnstileLandmarkSelector":   "input[name='cf-turnstile-response']",
	}

	sources := []struct {
		name string
		sel  *Selectors
	}{
		{name: "embedded selectors.yaml", sel: Get()},
		{name: "fallback defaults", sel: defaultSelectors()},
	}

	for _, src := range sources {
		t.Run(src.name, func(t *testing.T) {
			v := reflect.ValueOf(*src.sel)
			for field, wantValue := range want {
				got := v.FieldByName(field)
				if !got.IsValid() {
					t.Fatalf("Selectors has no field %s", field)
				}
				if !reflect.DeepEqual(got.Interface(), wantValue) {
					t.Errorf("%s = %v, want %v", field, got.Interface(), wantValue)
				}
			}
		})
	}
}
