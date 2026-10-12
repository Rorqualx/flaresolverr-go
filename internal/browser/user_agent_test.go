package browser

import (
	"reflect"
	"testing"

	"github.com/go-rod/rod/lib/proto"
)

const (
	linuxChrome136   = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"
	windowsChrome124 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
	macChrome120     = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	linuxFirefox     = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
)

// wantEqual fails the test when got differs from want.
func wantEqual(t *testing.T, want, got any) {
	t.Helper()
	if !reflect.DeepEqual(want, got) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestAcceptLanguages(t *testing.T) {
	tests := []struct {
		name   string
		locale string
		want   string
	}{
		{name: "empty uses the default", locale: "", want: "en-US,en"},
		{name: "whitespace uses the default", locale: "  ", want: "en-US,en"},
		{name: "C locale uses the default", locale: "C.UTF-8", want: "en-US,en"},
		{name: "POSIX locale uses the default", locale: "POSIX", want: "en-US,en"},
		{name: "locale with encoding", locale: "fr_FR.UTF-8", want: "fr-FR,fr,en"},
		{name: "locale with modifier", locale: "de_DE@euro", want: "de-DE,de,en"},
		{name: "language tag", locale: "fr-FR", want: "fr-FR,fr,en"},
		{name: "english region adds no second english", locale: "en_GB", want: "en-GB,en"},
		{name: "default locale", locale: "en_US.UTF-8", want: "en-US,en"},
		{name: "bare language", locale: "ja", want: "ja,en"},
		{name: "bare english", locale: "en", want: "en"},
		{name: "script subtag", locale: "zh-Hant-TW", want: "zh-Hant-TW,zh,en"},
		{name: "already a list is rejected", locale: "fr-FR,en;q=0.9", want: "en-US,en"},
		{name: "header injection is rejected", locale: "fr\r\nX-Evil: 1", want: "en-US,en"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantEqual(t, tt.want, AcceptLanguages(tt.locale))
		})
	}
}

func TestChromeMajorVersion(t *testing.T) {
	tests := []struct {
		name      string
		userAgent string
		want      int
		wantOK    bool
	}{
		{name: "chrome", userAgent: linuxChrome136, want: 136, wantOK: true},
		{name: "headless chrome", userAgent: "Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/136.0.7103.113 Safari/537.36", want: 136, wantOK: true},
		{name: "version at end of string", userAgent: "Chrome/99", want: 99, wantOK: true},
		{name: "firefox", userAgent: linuxFirefox},
		{name: "empty", userAgent: ""},
		{name: "no digits", userAgent: "Chrome/abc"},
		{name: "nothing after the slash", userAgent: "Chrome/"},
		{name: "zero", userAgent: "Chrome/0.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := chromeMajorVersion(tt.userAgent)
			wantEqual(t, tt.wantOK, ok)
			wantEqual(t, tt.want, got)
		})
	}
}

// brandStrings renders a brand list the way the Sec-CH-UA header shows it.
func brandStrings(list []*proto.EmulationUserAgentBrandVersion) []string {
	out := make([]string, 0, len(list))
	for _, b := range list {
		out = append(out, b.Brand+";"+b.Version)
	}
	return out
}

// TestUABrands checks the generated list against the Sec-CH-UA header real
// Google Chrome sends for each version.
func TestUABrands(t *testing.T) {
	tests := []struct {
		name        string
		major       int
		fullVersion string
		want        []string
		wantFull    []string
	}{
		{
			name:        "chrome 136 with the real full version",
			major:       136,
			fullVersion: "136.0.7103.113",
			want:        []string{"Chromium;136", "Google Chrome;136", "Not.A/Brand;99"},
			wantFull:    []string{"Chromium;136.0.7103.113", "Google Chrome;136.0.7103.113", "Not.A/Brand;99.0.0.0"},
		},
		{
			name:     "chrome 136 with no full version",
			major:    136,
			want:     []string{"Chromium;136", "Google Chrome;136", "Not.A/Brand;99"},
			wantFull: []string{"Chromium;136.0.0.0", "Google Chrome;136.0.0.0", "Not.A/Brand;99.0.0.0"},
		},
		{
			name:        "full version of another major is not used",
			major:       124,
			fullVersion: "136.0.7103.113",
			want:        []string{"Chromium;124", "Google Chrome;124", "Not-A.Brand;99"},
			wantFull:    []string{"Chromium;124.0.0.0", "Google Chrome;124.0.0.0", "Not-A.Brand;99.0.0.0"},
		},
		{
			name:        "full version sharing only a prefix is not used",
			major:       13,
			fullVersion: "136.0.7103.113",
			want:        []string{"Not:A-Brand;99", "Google Chrome;13", "Chromium;13"},
			wantFull:    []string{"Not:A-Brand;99.0.0.0", "Google Chrome;13.0.0.0", "Chromium;13.0.0.0"},
		},
		{
			name:     "chrome 120",
			major:    120,
			want:     []string{"Not_A Brand;8", "Chromium;120", "Google Chrome;120"},
			wantFull: []string{"Not_A Brand;8.0.0.0", "Chromium;120.0.0.0", "Google Chrome;120.0.0.0"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			brands, fullVersionList := uaBrands(tt.major, tt.fullVersion)
			wantEqual(t, tt.want, brandStrings(brands))
			wantEqual(t, tt.wantFull, brandStrings(fullVersionList))
		})
	}
}

func TestPlatformFor(t *testing.T) {
	tests := []struct {
		name      string
		userAgent string
		goarch    string
		want      uaPlatform
	}{
		{
			name: "linux amd64", userAgent: linuxChrome136, goarch: "amd64",
			want: uaPlatform{navigator: "Linux x86_64", hint: "Linux", hintVersion: linuxPlatformVersion, architecture: "x86", bitness: "64"},
		},
		{
			name: "linux arm64", userAgent: linuxChrome136, goarch: "arm64",
			want: uaPlatform{navigator: "Linux aarch64", hint: "Linux", hintVersion: linuxPlatformVersion, architecture: "arm", bitness: "64"},
		},
		{
			name: "linux arm", userAgent: linuxChrome136, goarch: "arm",
			want: uaPlatform{navigator: "Linux armv7l", hint: "Linux", hintVersion: linuxPlatformVersion, architecture: "arm", bitness: "32"},
		},
		{
			name: "linux 386", userAgent: linuxChrome136, goarch: "386",
			want: uaPlatform{navigator: "Linux i686", hint: "Linux", hintVersion: linuxPlatformVersion, architecture: "x86", bitness: "32"},
		},
		{
			name: "unknown architecture is treated as amd64", userAgent: linuxChrome136, goarch: "riscv64",
			want: uaPlatform{navigator: "Linux x86_64", hint: "Linux", hintVersion: linuxPlatformVersion, architecture: "x86", bitness: "64"},
		},
		{
			name: "windows user agent ignores the host architecture", userAgent: windowsChrome124, goarch: "arm64",
			want: uaPlatform{navigator: "Win32", hint: "Windows", hintVersion: windowsPlatformVersion, architecture: "x86", bitness: "64"},
		},
		{
			name: "mac user agent ignores the host architecture", userAgent: macChrome120, goarch: "amd64",
			want: uaPlatform{navigator: "MacIntel", hint: "macOS", hintVersion: macPlatformVersion, architecture: "arm", bitness: "64"},
		},
		{
			name: "empty user agent is treated as linux", userAgent: "", goarch: "amd64",
			want: uaPlatform{navigator: "Linux x86_64", hint: "Linux", hintVersion: linuxPlatformVersion, architecture: "x86", bitness: "64"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantEqual(t, tt.want, platformFor(tt.userAgent, tt.goarch))
		})
	}
}

func TestBuildUAOverride(t *testing.T) {
	tests := []struct {
		name            string
		userAgent       string
		acceptLanguages string
		goarch          string
		fullVersion     string
		wantLanguages   string
		wantPlatform    string
		wantHints       bool
		wantHintOS      string
		wantArch        string
		wantFullVersion string
	}{
		{
			name: "server user agent on linux amd64", userAgent: linuxChrome136, acceptLanguages: "en-US,en",
			goarch: "amd64", fullVersion: "136.0.7103.113",
			wantLanguages: "en-US,en", wantPlatform: "Linux x86_64",
			wantHints: true, wantHintOS: "Linux", wantArch: "x86", wantFullVersion: "136.0.7103.113",
		},
		{
			name: "empty language list uses the default", userAgent: linuxChrome136,
			goarch: "arm64", fullVersion: "136.0.7103.113",
			wantLanguages: "en-US,en", wantPlatform: "Linux aarch64",
			wantHints: true, wantHintOS: "Linux", wantArch: "arm", wantFullVersion: "136.0.7103.113",
		},
		{
			name: "configured languages are passed through", userAgent: linuxChrome136, acceptLanguages: "fr-FR,fr,en",
			goarch: "amd64", wantLanguages: "fr-FR,fr,en", wantPlatform: "Linux x86_64",
			wantHints: true, wantHintOS: "Linux", wantArch: "x86", wantFullVersion: "136.0.0.0",
		},
		{
			name: "windows user agent of another version", userAgent: windowsChrome124, acceptLanguages: "en-US,en",
			goarch: "amd64", fullVersion: "136.0.7103.113",
			wantLanguages: "en-US,en", wantPlatform: "Win32",
			wantHints: true, wantHintOS: "Windows", wantArch: "x86", wantFullVersion: "124.0.0.0",
		},
		{
			name: "non-chrome user agent gets no client hints", userAgent: linuxFirefox, acceptLanguages: "en-US,en",
			goarch: "amd64", fullVersion: "136.0.7103.113",
			wantLanguages: "en-US,en", wantPlatform: "Linux x86_64",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildUAOverride(tt.userAgent, tt.acceptLanguages, tt.goarch, tt.fullVersion)

			wantEqual(t, tt.userAgent, got.UserAgent)
			wantEqual(t, tt.wantLanguages, got.AcceptLanguage)
			wantEqual(t, tt.wantPlatform, got.Platform)

			if !tt.wantHints {
				if got.UserAgentMetadata != nil {
					t.Errorf("UserAgentMetadata = %+v, want none", got.UserAgentMetadata)
				}
				return
			}
			if got.UserAgentMetadata == nil {
				t.Fatal("UserAgentMetadata is nil, want client hints")
			}
			meta := got.UserAgentMetadata
			wantEqual(t, tt.wantHintOS, meta.Platform)
			wantEqual(t, tt.wantArch, meta.Architecture)
			wantEqual(t, "64", meta.Bitness)
			wantEqual(t, false, meta.Mobile)
			wantEqual(t, 3, len(meta.Brands))

			var chromeFull string
			for _, b := range meta.FullVersionList {
				if b.Brand == "Google Chrome" {
					chromeFull = b.Version
				}
			}
			wantEqual(t, tt.wantFullVersion, chromeFull)
		})
	}
}
