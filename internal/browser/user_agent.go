package browser

import (
	"runtime"
	"strconv"
	"strings"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/rs/zerolog/log"
)

// DefaultAcceptLanguages is the language list used when none is configured.
const DefaultAcceptLanguages = "en-US,en"

// Client-hint platform versions reported for each platform. Windows 11 reports
// 15.0.0; the others are a current release of the platform.
const (
	linuxPlatformVersion   = "6.5.0"
	windowsPlatformVersion = "15.0.0"
	macPlatformVersion     = "14.0.0"
)

// The brand list Chromium sends in Sec-CH-UA is generated from the major
// version: a "greased" brand whose punctuation and version vary, and an order
// that varies, so that sites cannot hard-code the list. These tables are the
// ones Chromium uses (components/embedder_support/user_agent_utils.cc).
var (
	greaseChars    = []string{" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"}
	greaseVersions = []string{"8", "99", "24"}
	brandOrders    = [][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}
)

// AcceptLanguages converts a locale such as "fr_FR.UTF-8" or "fr-FR" into the
// plain, comma-separated language list Chrome expects ("fr-FR,fr,en"). Chrome
// adds the q-values itself; a list that already carries them comes out as
// "en;q=0.9;q=0.9". An empty or unusable locale gives DefaultAcceptLanguages.
func AcceptLanguages(locale string) string {
	lang := strings.TrimSpace(locale)
	if idx := strings.IndexAny(lang, ".@"); idx >= 0 {
		lang = lang[:idx]
	}
	lang = strings.ReplaceAll(lang, "_", "-")
	if lang == "" || lang == "C" || lang == "POSIX" || !isLanguageTag(lang) {
		return DefaultAcceptLanguages
	}

	languages := []string{lang}
	if base, _, found := strings.Cut(lang, "-"); found && base != "" {
		languages = append(languages, base)
	}
	if languages[len(languages)-1] != "en" && languages[0] != "en" {
		languages = append(languages, "en")
	}
	return strings.Join(languages, ",")
}

// isLanguageTag reports whether s is made only of letters, digits and hyphens.
func isLanguageTag(s string) bool {
	for _, r := range s {
		isLetter := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		isDigit := r >= '0' && r <= '9'
		if !isLetter && !isDigit && r != '-' {
			return false
		}
	}
	return true
}

// chromeMajorVersion extracts the major version from a Chrome user agent
// ("... Chrome/136.0.0.0 ..." gives 136). The second result is false when the
// user agent does not name a Chrome version.
func chromeMajorVersion(userAgent string) (int, bool) {
	_, rest, found := strings.Cut(userAgent, "Chrome/")
	if !found {
		return 0, false
	}
	end := 0
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	major, err := strconv.Atoi(rest[:end])
	if err != nil || major <= 0 {
		return 0, false
	}
	return major, true
}

// uaBrands returns the Sec-CH-UA brand list, and its full-version form, that
// Google Chrome of the given major version generates. fullVersion is used for
// the real brands when it belongs to that major version; otherwise the
// version is reported as "<major>.0.0.0", as the reduced user agent does.
func uaBrands(major int, fullVersion string) (brands, fullVersionList []*proto.EmulationUserAgentBrandVersion) {
	majorStr := strconv.Itoa(major)
	if !strings.HasPrefix(fullVersion, majorStr+".") {
		fullVersion = majorStr + ".0.0.0"
	}

	greaseBrand := "Not" + greaseChars[major%len(greaseChars)] + "A" + greaseChars[(major+1)%len(greaseChars)] + "Brand"
	greaseVersion := greaseVersions[major%len(greaseVersions)]

	names := [3]string{greaseBrand, "Chromium", "Google Chrome"}
	versions := [3]string{greaseVersion, majorStr, majorStr}
	fullVersions := [3]string{greaseVersion + ".0.0.0", fullVersion, fullVersion}

	order := brandOrders[major%len(brandOrders)]
	brands = make([]*proto.EmulationUserAgentBrandVersion, len(names))
	fullVersionList = make([]*proto.EmulationUserAgentBrandVersion, len(names))
	for i, position := range order {
		brands[position] = &proto.EmulationUserAgentBrandVersion{Brand: names[i], Version: versions[i]}
		fullVersionList[position] = &proto.EmulationUserAgentBrandVersion{Brand: names[i], Version: fullVersions[i]}
	}
	return brands, fullVersionList
}

// uaPlatform describes the platform a user agent claims, in the three forms a
// site can read it.
type uaPlatform struct {
	navigator    string // navigator.platform
	hint         string // Sec-CH-UA-Platform
	hintVersion  string // Sec-CH-UA-Platform-Version
	architecture string // Sec-CH-UA-Arch: "x86" or "arm"
	bitness      string // Sec-CH-UA-Bitness: "64" or "32"
}

// platformFor returns the platform values Chrome reports for the operating
// system the user agent names. For Linux, which is what the server itself
// runs, the architecture is the host's (goarch). A user agent naming Windows
// or macOS gets the values Chrome reports on a typical machine of that kind.
func platformFor(userAgent, goarch string) uaPlatform {
	switch {
	case strings.Contains(userAgent, "Windows"):
		return uaPlatform{navigator: "Win32", hint: "Windows", hintVersion: windowsPlatformVersion, architecture: "x86", bitness: "64"}
	case strings.Contains(userAgent, "Macintosh"):
		return uaPlatform{navigator: "MacIntel", hint: "macOS", hintVersion: macPlatformVersion, architecture: "arm", bitness: "64"}
	}

	platform := uaPlatform{hint: "Linux", hintVersion: linuxPlatformVersion}
	switch goarch {
	case "arm64":
		platform.navigator, platform.architecture, platform.bitness = "Linux aarch64", "arm", "64"
	case "arm":
		platform.navigator, platform.architecture, platform.bitness = "Linux armv7l", "arm", "32"
	case "386":
		platform.navigator, platform.architecture, platform.bitness = "Linux i686", "x86", "32"
	default:
		platform.navigator, platform.architecture, platform.bitness = "Linux x86_64", "x86", "64"
	}
	return platform
}

// buildUAOverride builds the CDP user-agent override for a page, so that the
// User-Agent and Accept-Language headers, the Sec-CH-UA client hints,
// navigator.platform and navigator.userAgentData all describe the same
// browser. acceptLanguages is a plain language list (see AcceptLanguages);
// goarch is the host architecture; fullVersion is the browser's real version,
// or empty when unknown.
//
// A user agent that does not name a Chrome version gets no client hints:
// browsers other than Chromium do not send them.
func buildUAOverride(userAgent, acceptLanguages, goarch, fullVersion string) *proto.NetworkSetUserAgentOverride {
	if acceptLanguages == "" {
		acceptLanguages = DefaultAcceptLanguages
	}
	platform := platformFor(userAgent, goarch)

	override := &proto.NetworkSetUserAgentOverride{
		UserAgent:      userAgent,
		AcceptLanguage: acceptLanguages,
		Platform:       platform.navigator,
	}

	major, ok := chromeMajorVersion(userAgent)
	if !ok {
		return override
	}

	brands, fullVersionList := uaBrands(major, fullVersion)
	override.UserAgentMetadata = &proto.EmulationUserAgentMetadata{
		Brands:          brands,
		FullVersionList: fullVersionList,
		Platform:        platform.hint,
		PlatformVersion: platform.hintVersion,
		Architecture:    platform.architecture,
		Model:           "",
		Mobile:          false,
		Bitness:         platform.bitness,
	}
	return override
}

// browserFullVersion returns the browser's real version ("136.0.7103.113"),
// or "" when it cannot be read.
func browserFullVersion(page *rod.Page) string {
	version, err := proto.BrowserGetVersion{}.Call(page)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to read browser version")
		return ""
	}
	_, full, found := strings.Cut(version.Product, "/")
	if !found {
		return ""
	}
	return full
}

// SetUserAgent sets the user agent on the page together with the client hints,
// platform and language list that belong to it. acceptLanguages is a plain
// language list (see AcceptLanguages); empty means DefaultAcceptLanguages.
func SetUserAgent(page *rod.Page, userAgent, acceptLanguages string) error {
	override := buildUAOverride(userAgent, acceptLanguages, runtime.GOARCH, browserFullVersion(page))
	return override.Call(page)
}
