package types

import (
	"strings"
	"testing"
)

// TestRequestValidateCaptchaFields covers the per-request external solver
// fields: which combinations are accepted, and that a rejected key is never
// echoed back in the error.
func TestRequestValidateCaptchaFields(t *testing.T) {
	const requestKey = "validation-probe-value-51c2"

	tests := []struct {
		name    string
		solver  string
		apiKey  string
		wantErr string // substring; empty means valid
	}{
		{name: "neither"},
		{name: "none", solver: "none"},
		{name: "provider only", solver: "2captcha"},
		{name: "capsolver only", solver: "capsolver"},
		{name: "anticaptcha only", solver: "anticaptcha"},
		{name: "9kw only", solver: "9kw"},
		{name: "provider with key", solver: "2captcha", apiKey: requestKey},
		{name: "9kw with key", solver: "9kw", apiKey: requestKey},
		{name: "unknown provider", solver: "notaprovider", wantErr: "not a registered provider"},
		{name: "unknown provider with key", solver: "notaprovider", apiKey: requestKey, wantErr: "not a registered provider"},
		{name: "key without provider", apiKey: requestKey, wantErr: "captchaApiKey requires captchaSolver"},
		{name: "key with none", solver: "none", apiKey: requestKey, wantErr: "cannot be combined"},
		{name: "oversized key", solver: "2captcha", apiKey: strings.Repeat("k", MaxCaptchaAPIKeyLength+1), wantErr: "exceeds maximum length"},
		{name: "key at the limit", solver: "2captcha", apiKey: strings.Repeat("k", MaxCaptchaAPIKeyLength)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := Request{
				Cmd:           "request.get",
				URL:           "https://example.com",
				CaptchaSolver: tt.solver,
				CaptchaApiKey: tt.apiKey,
			}
			err := req.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v, want none", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %v, want one containing %q", err, tt.wantErr)
			}
			if tt.apiKey != "" && strings.Contains(err.Error(), tt.apiKey) {
				t.Errorf("validation error echoes the API key: %v", err)
			}
		})
	}
}
