package handlers

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Rorqualx/flaresolverr-go/internal/types"
)

// BenchmarkJSONDecode measures JSON request parsing performance.
// This tests the core JSON decoding path that every request goes through.
func BenchmarkJSONDecode(b *testing.B) {
	reqBody := `{"cmd":"request.get","url":"https://example.com","maxTimeout":60000}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var req types.Request
		if err := json.Unmarshal([]byte(reqBody), &req); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkJSONDecodeWithPool measures JSON decoding using pooled buffers.
func BenchmarkJSONDecodeWithPool(b *testing.B) {
	reqBody := `{"cmd":"request.get","url":"https://example.com","maxTimeout":60000}`
	reader := strings.NewReader(reqBody)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader.Reset(reqBody)

		buf := getBuffer()
		_, _ = io.Copy(buf, reader)
		var req types.Request
		if err := json.Unmarshal(buf.Bytes(), &req); err != nil {
			b.Fatal(err)
		}
		putBuffer(buf)
	}
}

// BenchmarkJSONEncode measures JSON response encoding performance.
func BenchmarkJSONEncode(b *testing.B) {
	resp := types.Response{
		Status:    types.StatusOK,
		Message:   "Challenge solved successfully",
		StartTime: 1234567890123,
		EndTime:   1234567890456,
		Version:   "3.0.0",
		Solution: &types.Solution{
			URL:       "https://example.com",
			Status:    200,
			Response:  strings.Repeat("x", 10000), // 10KB HTML
			Cookies:   []types.Cookie{{Name: "cf_clearance", Value: "abc123", Domain: ".example.com"}},
			UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		data, err := json.Marshal(resp)
		if err != nil {
			b.Fatal(err)
		}
		_ = data
	}
}

// BenchmarkBufferPool measures sync.Pool allocation performance.
func BenchmarkBufferPool(b *testing.B) {
	b.Run("WithPool", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			buf := getBuffer()
			buf.WriteString("test data for buffer pool benchmark")
			putBuffer(buf)
		}
	})

	b.Run("WithoutPool", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			buf := bytes.NewBuffer(make([]byte, 0, 4096))
			buf.WriteString("test data for buffer pool benchmark")
			// No return to pool - simulates GC pressure
		}
	})
}

// BenchmarkRequestParsing benchmarks the full request body parsing path.
func BenchmarkRequestParsing(b *testing.B) {
	// Large request with cookies
	reqData := types.Request{
		Cmd:        "request.get",
		URL:        "https://example.com/path?query=value",
		MaxTimeout: 60000,
		Cookies: []types.RequestCookie{
			{Name: "session", Value: "abc123"},
			{Name: "token", Value: "xyz789"},
			{Name: "preference", Value: "dark"},
		},
	}
	reqBody, _ := json.Marshal(reqData)

	b.Run("DirectUnmarshal", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			var req types.Request
			_ = json.Unmarshal(reqBody, &req)
		}
	})

	b.Run("WithPooledBuffer", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			reader := bytes.NewReader(reqBody)
			buf := getBuffer()
			_, _ = io.Copy(buf, reader)
			var req types.Request
			_ = json.Unmarshal(buf.Bytes(), &req)
			putBuffer(buf)
		}
	})
}

// BenchmarkHTTPHandler benchmarks the HTTP handler without actual browser operations.
// This measures middleware + routing overhead.
func BenchmarkHTTPHandler(b *testing.B) {
	// Create a minimal handler that doesn't require a browser pool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate request parsing
		buf := getBuffer()
		defer putBuffer(buf)

		_, _ = io.Copy(buf, r.Body)
		var req types.Request
		_ = json.Unmarshal(buf.Bytes(), &req)

		// Simulate response writing
		resp := types.Response{
			Status:  types.StatusOK,
			Message: "test",
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	reqBody := `{"cmd":"request.get","url":"https://example.com"}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1", strings.NewReader(reqBody))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}
}

// BenchmarkCookieParsing benchmarks cookie array parsing.
func BenchmarkCookieParsing(b *testing.B) {
	// Request with many cookies
	cookies := make([]types.RequestCookie, 20)
	for i := 0; i < 20; i++ {
		cookies[i] = types.RequestCookie{
			Name:   "cookie" + string(rune('a'+i)),
			Value:  strings.Repeat("x", 100),
			Domain: ".example.com",
			Path:   "/",
		}
	}
	reqData := types.Request{
		Cmd:     "request.get",
		URL:     "https://example.com",
		Cookies: cookies,
	}
	reqBody, _ := json.Marshal(reqData)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var req types.Request
		_ = json.Unmarshal(reqBody, &req)
	}
}

// BenchmarkResponseBuffer benchmarks response buffer pool.
func BenchmarkResponseBuffer(b *testing.B) {
	b.Run("WithPool", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			buf := getResponseBuffer()
			buf.WriteString(strings.Repeat("x", 8000)) // Typical HTML size
			putResponseBuffer(buf)
		}
	})

	b.Run("WithoutPool", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			buf := bytes.NewBuffer(make([]byte, 0, 8192))
			buf.WriteString(strings.Repeat("x", 8000))
		}
	})
}
