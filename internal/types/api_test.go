package types

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestRequestJSONFieldNames verifies request JSON field names match original FlareSolverr API
func TestRequestJSONFieldNames(t *testing.T) {
	req := Request{
		Cmd:               "request.get",
		URL:               "https://example.com",
		Session:           "test-session",
		SessionTTL:        10,
		MaxTimeout:        60000,
		ReturnOnlyCookies: true,
		PostData:          "key=value",
		ReturnScreenshot:  true,
		DisableMedia:      true,
		WaitInSeconds:     5,
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	jsonStr := string(data)

	// Verify expected field names (matching original FlareSolverr)
	expectedFields := []string{
		`"cmd"`,
		`"url"`,
		`"session"`,
		`"session_ttl_minutes"`,
		`"maxTimeout"`,
		`"returnOnlyCookies"`,
		`"postData"`,
		`"returnScreenshot"`,
		`"disableMedia"`,
		`"waitInSeconds"`,
	}

	for _, field := range expectedFields {
		if !strings.Contains(jsonStr, field) {
			t.Errorf("Expected field %s not found in JSON: %s", field, jsonStr)
		}
	}

	// Verify incorrect field names are NOT present
	incorrectFields := []string{
		`"screenshot"`,          // Should be returnScreenshot
		`"session_ttl"`,         // Should be session_ttl_minutes
		`"return_screenshot"`,   // Should be returnScreenshot (camelCase)
		`"return_only_cookies"`, // Should be returnOnlyCookies (camelCase)
		`"disable_media"`,       // Should be disableMedia (camelCase)
		`"wait_in_seconds"`,     // Should be waitInSeconds (camelCase)
	}

	for _, field := range incorrectFields {
		if strings.Contains(jsonStr, field) {
			t.Errorf("Unexpected field %s found in JSON: %s", field, jsonStr)
		}
	}
}

// TestSolutionJSONFieldNames verifies solution JSON field names match original FlareSolverr API
func TestSolutionJSONFieldNames(t *testing.T) {
	sol := Solution{
		URL:            "https://example.com",
		Status:         200,
		Response:       "<html></html>",
		UserAgent:      "Mozilla/5.0",
		Screenshot:     "base64data",
		TurnstileToken: "token123",
	}

	data, err := json.Marshal(sol)
	if err != nil {
		t.Fatalf("Failed to marshal solution: %v", err)
	}

	jsonStr := string(data)

	// Verify expected field names (matching original FlareSolverr)
	expectedFields := []string{
		`"url"`,
		`"status"`,
		`"response"`,
		`"userAgent"`,
		`"screenshot"`,
		`"turnstile_token"`, // snake_case to match original
	}

	for _, field := range expectedFields {
		if !strings.Contains(jsonStr, field) {
			t.Errorf("Expected field %s not found in JSON: %s", field, jsonStr)
		}
	}

	// Verify incorrect field names are NOT present
	incorrectFields := []string{
		`"turnstileToken"`, // Should be turnstile_token (snake_case)
		`"user_agent"`,     // Should be userAgent (camelCase)
	}

	for _, field := range incorrectFields {
		if strings.Contains(jsonStr, field) {
			t.Errorf("Unexpected field %s found in JSON: %s", field, jsonStr)
		}
	}
}

// TestResponseJSONFieldNames verifies response JSON field names match original FlareSolverr API
func TestResponseJSONFieldNames(t *testing.T) {
	resp := Response{
		Status:    StatusOK,
		Message:   "Challenge solved",
		StartTime: 1705432800000,
		EndTime:   1705432801000,
		Version:   "3.3.21",
		Sessions:  []string{"session1"},
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Failed to marshal response: %v", err)
	}

	jsonStr := string(data)

	// Verify expected field names (matching original FlareSolverr)
	expectedFields := []string{
		`"status"`,
		`"message"`,
		`"startTimestamp"`,
		`"endTimestamp"`,
		`"version"`,
		`"sessions"`,
	}

	for _, field := range expectedFields {
		if !strings.Contains(jsonStr, field) {
			t.Errorf("Expected field %s not found in JSON: %s", field, jsonStr)
		}
	}

	// Verify incorrect field names are NOT present
	incorrectFields := []string{
		`"start_timestamp"`, // Should be startTimestamp (camelCase)
		`"end_timestamp"`,   // Should be endTimestamp (camelCase)
		`"start_time"`,
		`"end_time"`,
	}

	for _, field := range incorrectFields {
		if strings.Contains(jsonStr, field) {
			t.Errorf("Unexpected field %s found in JSON: %s", field, jsonStr)
		}
	}
}

// TestRequestDeserialization verifies requests from original FlareSolverr clients can be parsed
func TestRequestDeserialization(t *testing.T) {
	tests := []struct {
		name            string
		json            string
		wantCmd         string
		wantURL         string
		wantSS          bool
		wantDisable     bool
		wantWaitSeconds int
	}{
		{
			name:    "basic request.get",
			json:    `{"cmd":"request.get","url":"https://example.com"}`,
			wantCmd: "request.get",
			wantURL: "https://example.com",
		},
		{
			name:    "request with returnScreenshot",
			json:    `{"cmd":"request.get","url":"https://example.com","returnScreenshot":true}`,
			wantCmd: "request.get",
			wantURL: "https://example.com",
			wantSS:  true,
		},
		{
			name:        "request with disableMedia",
			json:        `{"cmd":"request.get","url":"https://example.com","disableMedia":true}`,
			wantCmd:     "request.get",
			wantURL:     "https://example.com",
			wantDisable: true,
		},
		{
			name:            "request with waitInSeconds",
			json:            `{"cmd":"request.get","url":"https://example.com","waitInSeconds":5}`,
			wantCmd:         "request.get",
			wantURL:         "https://example.com",
			wantWaitSeconds: 5,
		},
		{
			name:            "request with all options",
			json:            `{"cmd":"request.get","url":"https://example.com","returnScreenshot":true,"disableMedia":true,"waitInSeconds":10}`,
			wantCmd:         "request.get",
			wantURL:         "https://example.com",
			wantSS:          true,
			wantDisable:     true,
			wantWaitSeconds: 10,
		},
		{
			name:    "request.post with postData",
			json:    `{"cmd":"request.post","url":"https://example.com","postData":"key=value"}`,
			wantCmd: "request.post",
			wantURL: "https://example.com",
		},
		{
			name:    "sessions.create",
			json:    `{"cmd":"sessions.create","session":"my-session"}`,
			wantCmd: "sessions.create",
		},
		{
			name:    "sessions.list",
			json:    `{"cmd":"sessions.list"}`,
			wantCmd: "sessions.list",
		},
		{
			name:    "sessions.destroy",
			json:    `{"cmd":"sessions.destroy","session":"my-session"}`,
			wantCmd: "sessions.destroy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req Request
			if err := json.Unmarshal([]byte(tt.json), &req); err != nil {
				t.Fatalf("Failed to unmarshal: %v", err)
			}

			if req.Cmd != tt.wantCmd {
				t.Errorf("Cmd = %q, want %q", req.Cmd, tt.wantCmd)
			}
			if req.URL != tt.wantURL {
				t.Errorf("URL = %q, want %q", req.URL, tt.wantURL)
			}
			if req.ReturnScreenshot != tt.wantSS {
				t.Errorf("ReturnScreenshot = %v, want %v", req.ReturnScreenshot, tt.wantSS)
			}
			if req.DisableMedia != tt.wantDisable {
				t.Errorf("DisableMedia = %v, want %v", req.DisableMedia, tt.wantDisable)
			}
			if req.WaitInSeconds != tt.wantWaitSeconds {
				t.Errorf("WaitInSeconds = %v, want %v", req.WaitInSeconds, tt.wantWaitSeconds)
			}
		})
	}
}

// TestCookieJSONFieldNames verifies cookie JSON field names match original FlareSolverr API
func TestCookieJSONFieldNames(t *testing.T) {
	cookie := Cookie{
		Name:     "cf_clearance",
		Value:    "abc123",
		Domain:   ".example.com",
		Path:     "/",
		Expires:  1705432800,
		Size:     100,
		HTTPOnly: true,
		Secure:   true,
		Session:  true, // Set to true so it appears in JSON (omitempty skips false)
		SameSite: "Lax",
	}

	data, err := json.Marshal(cookie)
	if err != nil {
		t.Fatalf("Failed to marshal cookie: %v", err)
	}

	jsonStr := string(data)

	// Verify expected field names
	expectedFields := []string{
		`"name"`,
		`"value"`,
		`"domain"`,
		`"path"`,
		`"expires"`,
		`"size"`,
		`"httpOnly"`,
		`"secure"`,
		`"session"`,
		`"sameSite"`,
	}

	for _, field := range expectedFields {
		if !strings.Contains(jsonStr, field) {
			t.Errorf("Expected field %s not found in JSON: %s", field, jsonStr)
		}
	}
}
