package captcha

import (
	"strings"
	"testing"

	"github.com/go-rod/rod/lib/proto"
)

// TestIsTurnstileChallengeURL: only Cloudflare's challenge host counts. The old
// check accepted any URL merely containing the word "turnstile".
func TestIsTurnstileChallengeURL(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/g/turnstile/if/ov2/av0/rcv/abc/0x4AAAAAAADnPIDROrmt1Wwj/light/", true},
		{"https://challenges.cloudflare.com/turnstile/v0/api.js", true},
		{"//challenges.cloudflare.com/cdn-cgi/turnstile", true},
		{"https://CHALLENGES.cloudflare.com/x", true},
		{"  https://challenges.cloudflare.com/x  ", true},
		{"https://example.com/turnstile", false},
		{"https://example.com/cf-turnstile?sitekey=0x4AAAAAAADnPIDROrmt1Wwj", false},
		{"https://example.com/?next=https://challenges.cloudflare.com/x", false},
		{"https://challenges.cloudflare.com.evil.example/x", false},
		{"https://evilchallenges.cloudflare.com/x", false},
		{"https://user@example.com:443/challenges.cloudflare.com", false},
		{"javascript:alert('challenges.cloudflare.com')", false},
		{"about:blank", false},
		{"https://example.com/some-page", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			if got := isTurnstileChallengeURL(tt.url); got != tt.want {
				t.Errorf("isTurnstileChallengeURL(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestSitekeyFromChallengeURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{
			name: "managed challenge iframe",
			url:  "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/g/turnstile/f/ov2/av0/rch/zcabn/0x4AAAAAAADnPIDROrmt1Wwj/light/fbE/new/normal?lang=auto",
			want: "0x4AAAAAAADnPIDROrmt1Wwj",
		},
		{
			name: "sitekey path segment",
			url:  "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/g/turnstile/if/ov2/av0/sitekey/0x4AAAAAAADnPIDROrmt1Wwj/",
			want: "0x4AAAAAAADnPIDROrmt1Wwj",
		},
		{
			name: "cloudflare test key without 0x prefix",
			url:  "https://challenges.cloudflare.com/turnstile/if?sitekey=3x00000000000000000000FF&x=1",
			want: "3x00000000000000000000FF",
		},
		{
			name: "same shape on another host is ignored",
			url:  "https://example.com/turnstile/sitekey/0x4AAAAAAADnPIDROrmt1Wwj/",
			want: "",
		},
		{
			name: "challenge host without a sitekey",
			url:  "https://challenges.cloudflare.com/turnstile/v0/api.js",
			want: "",
		},
		{
			name: "implausible sitekey rejected",
			url:  "https://challenges.cloudflare.com/x?sitekey=<script>",
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sitekeyFromChallengeURL(tt.url); got != tt.want {
				t.Errorf("sitekeyFromChallengeURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIsTurnstileSitekey(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want bool
	}{
		{"production key", "0x4AAAAAAADnPIDROrmt1Wwj", true},
		{"test key always passes", "1x00000000000000000000AA", true},
		{"test key always blocks", "2x00000000000000000000AB", true},
		{"test key forces interactive", "3x00000000000000000000FF", true},
		{"key with dash and underscore", "0x4AAAAAAA-abc_DEFghij", true},
		{"hcaptcha uuid", "10000000-ffff-ffff-ffff-000000000001", false},
		{"hcaptcha uuid upper case", "A5F74B19-9E45-40E0-B45D-47FF91B7A6C2", false},
		{"recaptcha v2 key", "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI", false},
		{"too short", "0x4AAAAAAA", false},
		{"empty", "", false},
		{"too long", "0x" + strings.Repeat("A", 120), false},
		{"illegal characters", "0x4AAAAAAA<script>alert", false},
		{"spaces", "0x4AAAAAAA DnPIDROrmt1Wwj", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isTurnstileSitekey(tt.key); got != tt.want {
				t.Errorf("isTurnstileSitekey(%q) = %v, want %v", tt.key, got, tt.want)
			}
		})
	}
}

// TestPickTurnstileWidget covers the scoping rules: the sitekey must come from
// a Turnstile element, and action/cData must come from that same element.
func TestPickTurnstileWidget(t *testing.T) {
	const (
		turnstileKey = "0x4AAAAAAADnPIDROrmt1Wwj"
		otherKey     = "0x4BBBBBBBBnPIDROrmt1Wwj"
		hcaptchaKey  = "10000000-ffff-ffff-ffff-000000000001"
		recaptchaKey = "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI"
	)
	candidate := func(source, key, action, cdata string, foreign bool) widgetCandidate {
		return widgetCandidate{
			TurnstileWidget: TurnstileWidget{SiteKey: key, Action: action, CData: cdata},
			Source:          source,
			Foreign:         foreign,
		}
	}

	tests := []struct {
		name       string
		candidates []widgetCandidate
		want       *TurnstileWidget
	}{
		{
			name:       "nothing on the page",
			candidates: nil,
		},
		{
			name:       "turnstile widget with its own action and cdata",
			candidates: []widgetCandidate{candidate("widget", turnstileKey, "login", "session-1", false)},
			want:       &TurnstileWidget{SiteKey: turnstileKey, Action: "login", CData: "session-1"},
		},
		{
			name: "action of an unrelated element is not borrowed",
			candidates: []widgetCandidate{
				// e.g. <button data-sitekey=... data-action="submit-form"> for another vendor
				candidate("attribute", hcaptchaKey, "submit-form", "", true),
				candidate("widget", turnstileKey, "", "", false),
			},
			want: &TurnstileWidget{SiteKey: turnstileKey},
		},
		{
			name: "hcaptcha widget alone yields nothing",
			candidates: []widgetCandidate{
				candidate("attribute", hcaptchaKey, "", "", true),
			},
		},
		{
			name: "hcaptcha-shaped key yields nothing even outside an hcaptcha element",
			candidates: []widgetCandidate{
				candidate("attribute", hcaptchaKey, "", "", false),
			},
		},
		{
			name: "recaptcha key yields nothing",
			candidates: []widgetCandidate{
				candidate("attribute", recaptchaKey, "", "", false),
				candidate("script", recaptchaKey, "", "", false),
			},
		},
		{
			name: "turnstile-shaped key inside a foreign widget is not used",
			candidates: []widgetCandidate{
				candidate("attribute", turnstileKey, "", "", true),
			},
		},
		{
			name: "widget beats bare attribute and script regardless of order",
			candidates: []widgetCandidate{
				candidate("script", otherKey, "", "", false),
				candidate("attribute", otherKey, "other", "", false),
				candidate("widget", turnstileKey, "real", "", false),
			},
			want: &TurnstileWidget{SiteKey: turnstileKey, Action: "real"},
		},
		{
			name: "bare attribute is used when no widget element exists",
			candidates: []widgetCandidate{
				candidate("script", otherKey, "", "", false),
				candidate("attribute", turnstileKey, "act", "cd", false),
			},
			want: &TurnstileWidget{SiteKey: turnstileKey, Action: "act", CData: "cd"},
		},
		{
			name:       "script sitekey is the last resort and carries no action",
			candidates: []widgetCandidate{candidate("script", turnstileKey, "", "", false)},
			want:       &TurnstileWidget{SiteKey: turnstileKey},
		},
		{
			name:       "widget with an empty sitekey is skipped",
			candidates: []widgetCandidate{candidate("widget", "", "x", "", false), candidate("widget", turnstileKey, "y", "", false)},
			want:       &TurnstileWidget{SiteKey: turnstileKey, Action: "y"},
		},
		{
			name:       "unknown source is ignored",
			candidates: []widgetCandidate{candidate("iframe", turnstileKey, "", "", false)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, found := pickTurnstileWidget(tt.candidates)
			if (tt.want != nil) != found {
				t.Fatalf("found = %v, want %v (got %+v)", found, tt.want != nil, got)
			}
			if found && *got != *tt.want {
				t.Errorf("widget = %+v, want %+v", *got, *tt.want)
			}
		})
	}
}

func TestPickOOPIFSitekey(t *testing.T) {
	const key = "0x4AAAAAAADnPIDROrmt1Wwj"
	tests := []struct {
		name string
		in   oopifCandidates
		want string
	}{
		{"captured key", oopifCandidates{Keys: []string{key}}, key},
		{"hcaptcha key skipped, challenge iframe used", oopifCandidates{
			Keys: []string{"10000000-ffff-ffff-ffff-000000000001"},
			URLs: []string{"https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/g/turnstile/f/ov2/av0/rch/a/" + key + "/light/"},
		}, key},
		{"iframe of another host ignored", oopifCandidates{URLs: []string{"https://ads.example/turnstile?sitekey=" + key}}, ""},
		{"empty", oopifCandidates{}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pickOOPIFSitekey(tt.in); got != tt.want {
				t.Errorf("pickOOPIFSitekey() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestFindChallengeSitekey walks a pierced DOM: only an iframe's src pointing at
// the challenge host counts, however deep it is nested.
func TestFindChallengeSitekey(t *testing.T) {
	const key = "0x4AAAAAAADnPIDROrmt1Wwj"
	challengeSrc := "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/g/turnstile/f/ov2/av0/rch/a/" + key + "/light/"
	iframe := func(src string) *proto.DOMNode {
		return &proto.DOMNode{NodeName: "IFRAME", Attributes: []string{"title", "widget", "src", src}}
	}
	div := func(attrs []string, children ...*proto.DOMNode) *proto.DOMNode {
		return &proto.DOMNode{NodeName: "DIV", Attributes: attrs, Children: children}
	}

	tests := []struct {
		name string
		root *proto.DOMNode
		want string
	}{
		{"nil tree", nil, ""},
		{"iframe in light dom", div(nil, iframe(challengeSrc)), key},
		{"iframe inside a shadow root", &proto.DOMNode{
			NodeName:    "DIV",
			ShadowRoots: []*proto.DOMNode{div(nil, div(nil, iframe(challengeSrc)))},
		}, key},
		{"iframe inside a nested document", &proto.DOMNode{
			NodeName:        "IFRAME",
			Attributes:      []string{"src", "https://example.com/frame"},
			ContentDocument: div(nil, iframe(challengeSrc)),
		}, key},
		{"link mentioning turnstile is not the widget", div(
			[]string{"data-href", "https://example.com/turnstile?sitekey=" + key},
			&proto.DOMNode{NodeName: "A", Attributes: []string{"href", challengeSrc}},
		), ""},
		{"iframe of another host", div(nil, iframe("https://example.com/turnstile/sitekey/"+key+"/")), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := findChallengeSitekey(tt.root, maxPierceNodes)
			if got != tt.want {
				t.Errorf("findChallengeSitekey() = %q, want %q", got, tt.want)
			}
		})
	}

	t.Run("node budget is respected", func(t *testing.T) {
		wide := div(nil)
		for i := 0; i < 100; i++ {
			wide.Children = append(wide.Children, div(nil))
		}
		wide.Children = append(wide.Children, iframe(challengeSrc))
		got, visited := findChallengeSitekey(wide, 10)
		if got != "" {
			t.Errorf("found %q beyond the node budget", got)
		}
		if visited > 110 {
			t.Errorf("visited = %d", visited)
		}
	})
}

func TestExtractSitekeyFromURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{
			name: "sitekey in path",
			url:  "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/g/turnstile/if/ov2/av0/sitekey/0x4AAAAAAA/",
			want: "0x4AAAAAAA",
		},
		{
			name: "sitekey in query string",
			url:  "https://example.com/turnstile?sitekey=0x4BBBBBB&other=value",
			want: "0x4BBBBBB",
		},
		{
			name: "no sitekey",
			url:  "https://example.com/turnstile?other=value",
			want: "",
		},
		{
			name: "empty url",
			url:  "",
			want: "",
		},
		{
			name: "sitekey at end of path",
			url:  "https://challenges.cloudflare.com/sitekey/0x4CCCCCC",
			want: "0x4CCCCCC",
		},
		{
			name: "managed challenge iframe url (sitekey as bare path segment)",
			url:  "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/g/turnstile/f/ov2/av0/rch/zcabn/0x4AAAAAAADnPIDROrmt1Wwj/light/fbE/new/normal?lang=auto",
			want: "0x4AAAAAAADnPIDROrmt1Wwj",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractSitekeyFromURL(tt.url)
			if got != tt.want {
				t.Errorf("extractSitekeyFromURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestContainsSubstring(t *testing.T) {
	tests := []struct {
		s      string
		substr string
		want   bool
	}{
		{"hello world", "world", true},
		{"hello world", "foo", false},
		{"", "test", false},
		{"test", "", true},
		{"test", "test", true},
		{"test", "testing", false},
	}

	for _, tt := range tests {
		got := containsSubstring(tt.s, tt.substr)
		if got != tt.want {
			t.Errorf("containsSubstring(%q, %q) = %v, want %v", tt.s, tt.substr, got, tt.want)
		}
	}
}

func TestFindSubstring(t *testing.T) {
	tests := []struct {
		s      string
		substr string
		want   int
	}{
		{"hello world", "world", 6},
		{"hello world", "hello", 0},
		{"hello world", "foo", -1},
		{"", "test", -1},
		{"test", "test", 0},
		{"aaa", "a", 0},
	}

	for _, tt := range tests {
		got := findSubstring(tt.s, tt.substr)
		if got != tt.want {
			t.Errorf("findSubstring(%q, %q) = %d, want %d", tt.s, tt.substr, got, tt.want)
		}
	}
}

func TestExtractEvalString(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
		want string
	}{
		{
			name: "valid string result",
			raw:  []byte(`{"result":{"value":"0x4AAAAAAADnPIDROrmt1Wwj","type":"string"}}`),
			want: "0x4AAAAAAADnPIDROrmt1Wwj",
		},
		{
			name: "empty string result",
			raw:  []byte(`{"result":{"value":"","type":"string"}}`),
			want: "",
		},
		{
			name: "non-string type",
			raw:  []byte(`{"result":{"value":42,"type":"number"}}`),
			want: "",
		},
		{
			name: "exception details present",
			raw:  []byte(`{"result":{"value":"test","type":"string"},"exceptionDetails":{}}`),
			want: "",
		},
		{
			name: "invalid json",
			raw:  []byte(`not json`),
			want: "",
		},
		{
			name: "nil input",
			raw:  nil,
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractEvalString(tt.raw)
			if got != tt.want {
				t.Errorf("extractEvalString() = %q, want %q", got, tt.want)
			}
		})
	}
}
