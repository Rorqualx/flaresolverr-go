package captcha

import (
	"testing"

	"github.com/go-rod/rod/lib/proto"
)

func TestParseChallengeParams(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		wantOK  bool
		wantKey string
		wantCD  string
		wantPD  string
		wantAct string
	}{
		{
			name:    "full managed-challenge params",
			json:    `{"sitekey":"0x4AAAAAAADnPIDROrmt1Wwj","action":"managed","cData":"CDATA","chlPageData":"PAGEDATA"}`,
			wantOK:  true,
			wantKey: "0x4AAAAAAADnPIDROrmt1Wwj",
			wantCD:  "CDATA",
			wantPD:  "PAGEDATA",
			wantAct: "managed",
		},
		{
			name:    "sitekey only (explicit widget)",
			json:    `{"sitekey":"0xABC","action":"","cData":"","chlPageData":""}`,
			wantOK:  true,
			wantKey: "0xABC",
		},
		{name: "empty sitekey rejected", json: `{"sitekey":"","cData":"x"}`, wantOK: false},
		{name: "null rejected", json: `null`, wantOK: false},
		{name: "malformed rejected", json: `{not json`, wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, ok := parseChallengeParams([]byte(tt.json))
			if ok != tt.wantOK {
				t.Fatalf("parseChallengeParams ok = %v, want %v", ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if p.SiteKey != tt.wantKey || p.CData != tt.wantCD || p.PageData != tt.wantPD || p.Action != tt.wantAct {
				t.Errorf("got %+v, want sitekey=%q cData=%q chlPageData=%q action=%q",
					p, tt.wantKey, tt.wantCD, tt.wantPD, tt.wantAct)
			}
		})
	}
}

func TestEvalResultString(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
		ok   bool
	}{
		{name: "json string value", raw: `{"result":{"value":"{\"sitekey\":\"0xABC\"}"}}`, want: `{"sitekey":"0xABC"}`, ok: true},
		{name: "null string", raw: `{"result":{"value":"null"}}`, ok: false},
		{name: "empty string", raw: `{"result":{"value":""}}`, ok: false},
		{name: "non-string value", raw: `{"result":{"value":123}}`, ok: false},
		{name: "malformed", raw: `not json`, ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := evalResultString([]byte(tt.raw))
			if ok != tt.ok || got != tt.want {
				t.Errorf("evalResultString = (%q,%v), want (%q,%v)", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestEvalResultBool(t *testing.T) {
	for _, tt := range []struct {
		raw  string
		want bool
	}{
		{`{"result":{"value":true}}`, true},
		{`{"result":{"value":false}}`, false},
		{`{"result":{}}`, false},
		{`garbage`, false},
	} {
		if got := evalResultBool([]byte(tt.raw)); got != tt.want {
			t.Errorf("evalResultBool(%q) = %v, want %v", tt.raw, got, tt.want)
		}
	}
}

func TestOOPIFStateBelongs(t *testing.T) {
	st := &oopifState{
		pageSession: proto.TargetSessionID("PAGE"),
		children:    []proto.TargetSessionID{"CHILD1"},
	}
	tests := []struct {
		name     string
		envelope proto.TargetSessionID
		want     bool
	}{
		{"page session", "PAGE", true},
		{"known child (nested)", "CHILD1", true},
		{"unrelated session", "OTHER", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := st.belongs(tt.envelope); got != tt.want {
				t.Errorf("belongs(%q) = %v, want %v", tt.envelope, got, tt.want)
			}
		})
	}
}

// TestOOPIFStateParamsNilSafe ensures the accessors are safe on a zero/!installed state.
func TestOOPIFStateParamsNilSafe(t *testing.T) {
	var st *oopifState
	if _, ok := st.params(); ok {
		t.Error("nil state params() should be (nil,false)")
	}
	if st.injectCallback("x") {
		t.Error("nil state injectCallback() should be false")
	}
	st.stop() // must not panic

	empty := &oopifState{} // installed but no browser/children
	if _, ok := empty.params(); ok {
		t.Error("empty state params() should be (nil,false)")
	}
}
