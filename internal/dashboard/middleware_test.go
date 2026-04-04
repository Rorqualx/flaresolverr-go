package dashboard

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRecordRequests_Middleware(t *testing.T) {
	buf := NewEventBuffer()

	handler := RecordRequests(buf)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))

	// Send a request
	req := httptest.NewRequest("POST", "/v1", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("expected status 201, got %d", rec.Code)
	}

	// Check event was recorded
	events, total := buf.Snapshot(10)
	if total != 1 {
		t.Errorf("expected 1 total event, got %d", total)
	}
	if len(events) != 1 {
		t.Errorf("expected 1 event, got %d", len(events))
	}
	if events[0].Method != "POST" {
		t.Errorf("expected POST, got %s", events[0].Method)
	}
	if events[0].Path != "/v1" {
		t.Errorf("expected /v1, got %s", events[0].Path)
	}
	if events[0].StatusCode != 201 {
		t.Errorf("expected status 201, got %d", events[0].StatusCode)
	}
	if events[0].Latency <= 0 {
		t.Error("expected positive latency")
	}
}

func TestRecordRequests_DefaultStatus(t *testing.T) {
	buf := NewEventBuffer()

	// Handler that writes body without explicit WriteHeader
	handler := RecordRequests(buf)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	events, _ := buf.Snapshot(1)
	if events[0].StatusCode != 200 {
		t.Errorf("expected default status 200, got %d", events[0].StatusCode)
	}
}

func TestRecordRequests_MultipleRequests(t *testing.T) {
	buf := NewEventBuffer()

	handler := RecordRequests(buf)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/health", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}

	_, total := buf.Snapshot(1)
	if total != 5 {
		t.Errorf("expected 5 total events, got %d", total)
	}
}
