package solver

import (
	"reflect"
	"testing"
)

func TestSandboxArgs(t *testing.T) {
	tests := []struct {
		name    string
		sandbox bool
		want    []string
	}{
		{name: "sandbox off (default)", sandbox: false, want: []string{"--no-sandbox"}},
		{name: "sandbox on", sandbox: true, want: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sandboxArgs(tt.sandbox); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("sandboxArgs(%v) = %v, want %v", tt.sandbox, got, tt.want)
			}
		})
	}
}
