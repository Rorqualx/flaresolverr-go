package captcha

import (
	"testing"
)

func TestContainsTurnstilePattern(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{
			url:  "https://challenges.cloudflare.com/cdn-cgi/turnstile",
			want: true,
		},
		{
			url:  "https://example.com/turnstile",
			want: true,
		},
		{
			url:  "https://example.com/cf-turnstile",
			want: true,
		},
		{
			url:  "https://example.com/some-page",
			want: false,
		},
		{
			url:  "",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := containsTurnstilePattern(tt.url)
			if got != tt.want {
				t.Errorf("containsTurnstilePattern(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
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
