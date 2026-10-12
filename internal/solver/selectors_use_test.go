package solver

import (
	"testing"

	"github.com/Rorqualx/flaresolverr-go/internal/selectors"
)

func TestTitleHasChallenge(t *testing.T) {
	titles := selectors.Get().ChallengeTitles

	tests := []struct {
		name   string
		title  string
		titles []string
		want   bool
	}{
		{name: "cloudflare interstitial", title: "Just a moment...", titles: titles, want: true},
		{name: "upper case", title: "JUST A MOMENT", titles: titles, want: true},
		{name: "checking your browser", title: "Checking your browser before accessing example.com", titles: titles, want: true},
		{name: "ddos-guard", title: "DDoS-Guard", titles: titles, want: true},
		{name: "please wait", title: "Please Wait... | Cloudflare", titles: titles, want: true},
		{name: "attention required", title: "Attention Required! | Cloudflare", titles: titles, want: true},
		{name: "ordinary page", title: "Example Domain", titles: titles, want: false},
		{name: "empty title", title: "", titles: titles, want: false},
		{name: "no patterns", title: "Just a moment...", titles: nil, want: false},
		{name: "custom pattern", title: "Verifying you are human", titles: []string{"verifying you are human"}, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := titleHasChallenge(tt.title, tt.titles); got != tt.want {
				t.Errorf("titleHasChallenge(%q) = %v, want %v", tt.title, got, tt.want)
			}
		})
	}
}

func TestSelectorListed(t *testing.T) {
	triggers := selectors.Get().TurnstileTriggerSelectors

	tests := []struct {
		name string
		list []string
		s    string
		want bool
	}{
		{name: "turnstile widget triggers solving", list: triggers, s: ".cf-turnstile", want: true},
		{name: "interstitial iframe triggers solving", list: triggers, s: "iframe[src*='challenges.cloudflare.com']", want: true},
		{name: "spinner does not trigger solving", list: triggers, s: "#cf-spinner-please-wait", want: false},
		{name: "no challenge selector found", list: triggers, s: "", want: false},
		{name: "substring is not a match", list: triggers, s: ".cf-turn", want: false},
		{name: "nil list", list: nil, s: ".cf-turnstile", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := selectorListed(tt.list, tt.s); got != tt.want {
				t.Errorf("selectorListed(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}

func TestFirstString(t *testing.T) {
	tests := []struct {
		name string
		list []string
		want string
	}{
		{name: "nil", list: nil, want: ""},
		{name: "empty", list: []string{}, want: ""},
		{name: "one", list: []string{".cf-turnstile"}, want: ".cf-turnstile"},
		{name: "several", list: []string{".cf-turnstile", "#turnstile-wrapper"}, want: ".cf-turnstile"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := firstString(tt.list); got != tt.want {
				t.Errorf("firstString(%v) = %q, want %q", tt.list, got, tt.want)
			}
		})
	}
}

// TestShadowRootTraverser_UsesGivenSelectors checks that the traverser works
// from the selectors it was constructed with, not the process-wide defaults.
func TestShadowRootTraverser_UsesGivenSelectors(t *testing.T) {
	custom := &selectors.Selectors{
		ShadowHosts:               []string{"#custom-host"},
		TurnstileLandmarkSelector: "input[name='custom']",
	}

	tests := []struct {
		name string
		sel  *selectors.Selectors
		want *selectors.Selectors
	}{
		{name: "given selectors are used", sel: custom, want: custom},
		{name: "nil falls back to the embedded defaults", sel: nil, want: selectors.Get()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			traverser := NewShadowRootTraverser(nil, tt.sel)
			if traverser.selectors != tt.want {
				t.Errorf("traverser selectors = %p, want %p", traverser.selectors, tt.want)
			}
		})
	}
}

// TestSolverPassesItsSelectors checks that a Solver with a selectors manager
// reads the moved lists from that manager.
func TestSolverPassesItsSelectors(t *testing.T) {
	manager, err := selectors.NewManager("", false)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	defer func() {
		if err := manager.Close(); err != nil {
			t.Errorf("Close failed: %v", err)
		}
	}()

	s := NewWithSelectors(nil, "", manager)
	if got, want := s.getSelectors(), manager.Get(); got != want {
		t.Fatalf("getSelectors() = %p, want the manager's %p", got, want)
	}
	if len(s.getSelectors().ChallengeSelectors) == 0 {
		t.Error("manager selectors have no challenge selectors")
	}
}
