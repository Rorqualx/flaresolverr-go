package selectors

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
)

// TestMergeWithEmbedded_KeepsEveryField verifies no field of Selectors is
// dropped by the merge. It walks the struct by reflection so a field added
// later fails here until the merge handles it. Captcha was missing: setting
// SELECTORS_PATH or SELECTORS_REMOTE_URL silently disabled hCaptcha detection.
func TestMergeWithEmbedded_KeepsEveryField(t *testing.T) {
	m := &Manager{embedded: Get()}

	t.Run("external with one field falls back to embedded for the rest", func(t *testing.T) {
		merged := m.mergeWithEmbedded(&Selectors{JavaScript: []string{"custom challenge"}})

		got, want := reflect.ValueOf(*merged), reflect.ValueOf(*m.embedded)
		for i := 0; i < got.NumField(); i++ {
			name := got.Type().Field(i).Name
			if name == "JavaScript" {
				continue
			}
			if got.Field(i).IsZero() {
				t.Errorf("merged.%s is empty; the merge dropped the embedded value", name)
			}
			if !reflect.DeepEqual(got.Field(i).Interface(), want.Field(i).Interface()) {
				t.Errorf("merged.%s = %v, want embedded %v", name, got.Field(i).Interface(), want.Field(i).Interface())
			}
		}
		if len(merged.JavaScript) != 1 || merged.JavaScript[0] != "custom challenge" {
			t.Errorf("merged.JavaScript = %v, want the external value", merged.JavaScript)
		}
	})

	t.Run("external values win for every field", func(t *testing.T) {
		external := &Selectors{}
		v := reflect.ValueOf(external).Elem()
		for i := 0; i < v.NumField(); i++ {
			switch v.Field(i).Kind() {
			case reflect.Slice:
				v.Field(i).Set(reflect.ValueOf([]string{"external-" + v.Type().Field(i).Name}))
			case reflect.String:
				v.Field(i).SetString("external-" + v.Type().Field(i).Name)
			default:
				t.Fatalf("unhandled field kind %s for %s; extend this test", v.Field(i).Kind(), v.Type().Field(i).Name)
			}
		}

		merged := m.mergeWithEmbedded(external)
		if !reflect.DeepEqual(merged, external) {
			t.Errorf("merged = %+v, want every external value %+v", merged, external)
		}
	})
}

func TestDefaultSelectorsHaveEveryField(t *testing.T) {
	v := reflect.ValueOf(*defaultSelectors())
	for i := 0; i < v.NumField(); i++ {
		if v.Field(i).IsZero() {
			t.Errorf("defaultSelectors().%s is empty", v.Type().Field(i).Name)
		}
	}
}

func TestSelectorsValidate_RejectsEmptyPatterns(t *testing.T) {
	valid := func() *Selectors {
		return &Selectors{AccessDenied: []string{"access denied"}, JavaScript: []string{"just a moment"}}
	}

	tests := []struct {
		name    string
		mutate  func(*Selectors)
		wantErr string
	}{
		{name: "valid", mutate: func(*Selectors) {}},
		{name: "no critical patterns at all", mutate: func(s *Selectors) { s.AccessDenied, s.JavaScript = nil, nil }, wantErr: "at least one pattern"},
		{name: "empty javascript pattern", mutate: func(s *Selectors) { s.JavaScript = []string{""} }, wantErr: "javascript[0]"},
		{name: "whitespace access_denied pattern", mutate: func(s *Selectors) { s.AccessDenied = append(s.AccessDenied, "  \t") }, wantErr: "access_denied[1]"},
		{name: "empty turnstile pattern", mutate: func(s *Selectors) { s.Turnstile = []string{"cf-turnstile", ""} }, wantErr: "turnstile[1]"},
		{name: "empty captcha pattern", mutate: func(s *Selectors) { s.Captcha = []string{""} }, wantErr: "captcha[0]"},
		{name: "empty turnstile selector", mutate: func(s *Selectors) { s.TurnstileSelectors = []string{" "} }, wantErr: "turnstile_selectors[0]"},
		{name: "empty shadow host", mutate: func(s *Selectors) { s.ShadowHosts = []string{""} }, wantErr: "shadow_hosts[0]"},
		{name: "empty shadow inner selector", mutate: func(s *Selectors) { s.ShadowInnerSelectors = []string{""} }, wantErr: "shadow_inner_selectors[0]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := valid()
			tt.mutate(s)
			err := s.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() = %v, want an error mentioning %q", err, tt.wantErr)
			}
		})
	}
}

func TestEmbeddedSelectorsAreValid(t *testing.T) {
	if err := Get().Validate(); err != nil {
		t.Fatalf("embedded selectors.yaml fails validation: %v", err)
	}
}

func TestValidateRemoteURL(t *testing.T) {
	tests := []struct {
		url     string
		wantErr bool
	}{
		{url: "https://example.com/selectors.yaml"},
		{url: "HTTPS://example.com/selectors.yaml"},
		{url: "http://127.0.0.1:8080/selectors.yaml"},
		{url: "http://localhost/selectors.yaml"},
		{url: "http://[::1]:9000/selectors.yaml"},
		{url: "http://example.com/selectors.yaml", wantErr: true},
		{url: "http://192.168.1.10/selectors.yaml", wantErr: true},
		{url: "ftp://example.com/selectors.yaml", wantErr: true},
		{url: "file:///etc/selectors.yaml", wantErr: true},
		{url: "https://", wantErr: true},
		{url: "not a url", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			err := validateRemoteURL(tt.url)
			if tt.wantErr && err == nil {
				t.Errorf("validateRemoteURL(%q) = nil, want error", tt.url)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("validateRemoteURL(%q) = %v, want nil", tt.url, err)
			}
		})
	}
}

// TestNewManagerWithRemote_RefusesPlainHTTP verifies an http remote is disabled
// without discarding the rest of the configuration.
func TestNewManagerWithRemote_RefusesPlainHTTP(t *testing.T) {
	m, err := NewManagerWithRemote("", false, "http://selectors.example.com/s.yaml", time.Hour)
	if err != nil {
		t.Fatalf("NewManagerWithRemote: %v", err)
	}
	defer m.Close()

	if m.remoteURL != "" || m.httpClient != nil || m.refreshTicker != nil {
		t.Errorf("plain-http remote was not disabled (url=%q)", m.remoteURL)
	}
	if got := m.Get(); got == nil || len(got.JavaScript) == 0 {
		t.Error("manager has no usable selectors after refusing the remote")
	}
}

func TestIsSelectorsFileEvent(t *testing.T) {
	const watched = "/etc/flaresolverr/selectors.yaml"

	tests := []struct {
		name  string
		event fsnotify.Event
		want  bool
	}{
		{name: "write", event: fsnotify.Event{Name: watched, Op: fsnotify.Write}, want: true},
		{name: "create", event: fsnotify.Event{Name: watched, Op: fsnotify.Create}, want: true},
		{name: "rename", event: fsnotify.Event{Name: watched, Op: fsnotify.Rename}, want: true},
		{name: "chmod only", event: fsnotify.Event{Name: watched, Op: fsnotify.Chmod}, want: false},
		{name: "remove only", event: fsnotify.Event{Name: watched, Op: fsnotify.Remove}, want: false},
		{name: "another file in the directory", event: fsnotify.Event{Name: "/etc/flaresolverr/other.yaml", Op: fsnotify.Write}, want: false},
		{name: "editor temp file", event: fsnotify.Event{Name: watched + ".tmp", Op: fsnotify.Create}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isSelectorsFileEvent(tt.event, watched); got != tt.want {
				t.Errorf("isSelectorsFileEvent(%v) = %v, want %v", tt.event, got, tt.want)
			}
		})
	}
}

// TestHotReload_SurvivesAtomicRename saves the selectors file the way editors
// and config management do (write a temp file, rename it over the original),
// several times. A watch on the file itself stops after the first such save.
func TestHotReload_SurvivesAtomicRename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "selectors.yaml")

	write := func(marker string) {
		t.Helper()
		content := "javascript:\n  - \"" + marker + "\"\n"
		tmp := filepath.Join(dir, ".selectors.yaml.tmp")
		if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
			t.Fatalf("write temp file: %v", err)
		}
		if err := os.Rename(tmp, path); err != nil {
			t.Fatalf("rename: %v", err)
		}
	}
	write("version-0")
	m, err := NewManager(path, true)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer m.Close()

	waitFor := func(marker string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if js := m.Get().JavaScript; len(js) == 1 && js[0] == marker {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("selectors were not reloaded to %q (still %v)", marker, m.Get().JavaScript)
	}

	waitFor("version-0")
	for _, marker := range []string{"version-1", "version-2", "version-3"} {
		write(marker)
		waitFor(marker)
	}
}
