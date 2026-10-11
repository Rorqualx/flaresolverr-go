package browser

import (
	"testing"

	"github.com/go-rod/rod/lib/proto"
)

// TestAuthChallengeResponse verifies proxy credentials are only offered to a
// first-time proxy challenge, never to an origin server.
func TestAuthChallengeResponse(t *testing.T) {
	proxy := &ProxyConfig{Username: "proxyuser", Password: "proxypass"}

	tests := []struct {
		name      string
		challenge *proto.FetchAuthChallenge
		retried   bool
		wantCreds bool
	}{
		{
			name:      "proxy challenge",
			challenge: &proto.FetchAuthChallenge{Source: proto.FetchAuthChallengeSourceProxy},
			wantCreds: true,
		},
		{
			name:      "proxy challenge repeated after rejection",
			challenge: &proto.FetchAuthChallenge{Source: proto.FetchAuthChallengeSourceProxy},
			retried:   true,
			wantCreds: false,
		},
		{
			name:      "origin server challenge",
			challenge: &proto.FetchAuthChallenge{Source: proto.FetchAuthChallengeSourceServer},
			wantCreds: false,
		},
		{
			name:      "unspecified source",
			challenge: &proto.FetchAuthChallenge{},
			wantCreds: false,
		},
		{
			name:      "nil challenge",
			challenge: nil,
			wantCreds: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := authChallengeResponse(tt.challenge, proxy, tt.retried)
			if tt.wantCreds {
				if got.Response != proto.FetchAuthChallengeResponseResponseProvideCredentials ||
					got.Username != proxy.Username || got.Password != proxy.Password {
					t.Errorf("response = %+v, want proxy credentials", got)
				}
				return
			}
			if got.Response != proto.FetchAuthChallengeResponseResponseCancelAuth {
				t.Errorf("Response = %q, want CancelAuth", got.Response)
			}
			if got.Username != "" || got.Password != "" {
				t.Errorf("credentials leaked in non-proxy response: %+v", got)
			}
		})
	}
}
