package security

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateHeaders(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		wantErr error
	}{
		{
			name:    "nil headers",
			headers: nil,
			wantErr: nil,
		},
		{
			name:    "empty headers",
			headers: map[string]string{},
			wantErr: nil,
		},
		{
			name: "valid custom headers",
			headers: map[string]string{
				"X-Custom-Header": "value1",
				"Accept-Language": "en-US",
				"X-Api-Key":       "abc123",
			},
			wantErr: nil,
		},
		{
			name: "blocked host header",
			headers: map[string]string{
				"Host": "evil.com",
			},
			wantErr: ErrBlockedHeader,
		},
		{
			name: "blocked cookie header",
			headers: map[string]string{
				"Cookie": "session=hijacked",
			},
			wantErr: ErrBlockedHeader,
		},
		{
			name: "blocked authorization header",
			headers: map[string]string{
				"Authorization": "Bearer token",
			},
			wantErr: ErrBlockedHeader,
		},
		{
			name: "blocked origin header",
			headers: map[string]string{
				"Origin": "https://evil.com",
			},
			wantErr: ErrBlockedHeader,
		},
		{
			name: "blocked sec- prefix header",
			headers: map[string]string{
				"Sec-Fetch-Mode": "navigate",
			},
			wantErr: ErrBlockedHeader,
		},
		{
			name: "blocked cf- prefix header",
			headers: map[string]string{
				"CF-Ray": "fake-ray-id",
			},
			wantErr: ErrBlockedHeader,
		},
		{
			name: "blocked x-forwarded- prefix header",
			headers: map[string]string{
				"X-Forwarded-For": "1.2.3.4",
			},
			wantErr: ErrBlockedHeader,
		},
		{
			name: "blocked proxy- prefix header",
			headers: map[string]string{
				"Proxy-Connection": "keep-alive",
			},
			wantErr: ErrBlockedHeader,
		},
		{
			name: "case insensitive blocking",
			headers: map[string]string{
				"COOKIE": "session=hijacked",
			},
			wantErr: ErrBlockedHeader,
		},
		{
			name: "header name too long",
			headers: map[string]string{
				strings.Repeat("X", MaxHeaderNameLength+1): "value",
			},
			wantErr: ErrHeaderNameTooLong,
		},
		{
			name: "header value too long",
			headers: map[string]string{
				"X-Custom": strings.Repeat("a", MaxHeaderValueLength+1),
			},
			wantErr: ErrHeaderValueTooLong,
		},
		{
			name: "empty header name",
			headers: map[string]string{
				"": "value",
			},
			wantErr: ErrHeaderNameEmpty,
		},
		{
			name: "header name with space",
			headers: map[string]string{
				"Invalid Header": "value",
			},
			wantErr: ErrInvalidHeaderName,
		},
		{
			name: "header name with colon",
			headers: map[string]string{
				"Invalid:Header": "value",
			},
			wantErr: ErrInvalidHeaderName,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateHeaders(tt.headers)
			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("ValidateHeaders() error = %v, wantErr nil", err)
				}
			} else {
				if err == nil {
					t.Errorf("ValidateHeaders() error = nil, wantErr %v", tt.wantErr)
				} else if !errors.Is(err, tt.wantErr) {
					t.Errorf("ValidateHeaders() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}

func TestValidateHeaders_TooManyHeaders(t *testing.T) {
	// Create more than MaxHeaderCount headers
	headers := make(map[string]string)
	for i := 0; i <= MaxHeaderCount; i++ {
		headers[strings.Repeat("X", i+1)] = "value"
	}

	err := ValidateHeaders(headers)
	if err != ErrTooManyHeaders {
		t.Errorf("ValidateHeaders() error = %v, wantErr %v", err, ErrTooManyHeaders)
	}
}

func TestValidateHeaders_ControlCharacters(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{
			name:    "newline in value",
			value:   "value\nwith newline",
			wantErr: true,
		},
		{
			name:    "carriage return in value",
			value:   "value\rwith cr",
			wantErr: true,
		},
		{
			name:    "null byte in value",
			value:   "value\x00with null",
			wantErr: true,
		},
		{
			// Fix #36: Tabs are now rejected for stricter security
			name:    "tab in value (rejected for security)",
			value:   "value\twith tab",
			wantErr: true,
		},
		{
			name:    "normal value",
			value:   "normal value 123",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := map[string]string{"X-Test": tt.value}
			err := ValidateHeaders(headers)
			if tt.wantErr && err == nil {
				t.Error("ValidateHeaders() expected error for control character, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ValidateHeaders() unexpected error: %v", err)
			}
		})
	}
}
