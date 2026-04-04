package dashboard

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestEventBuffer_RecordAndSnapshot(t *testing.T) {
	buf := NewEventBuffer()

	// Empty buffer
	events, total := buf.Snapshot(10)
	if len(events) != 0 || total != 0 {
		t.Errorf("empty buffer: got %d events, total %d", len(events), total)
	}

	// Add a few events
	for i := 0; i < 5; i++ {
		buf.Record(RequestEvent{
			Timestamp:  time.Now(),
			Method:     "POST",
			Path:       fmt.Sprintf("/v1/%d", i),
			StatusCode: 200,
			Latency:    time.Duration(i) * time.Millisecond,
		})
	}

	events, total = buf.Snapshot(10)
	if len(events) != 5 {
		t.Errorf("expected 5 events, got %d", len(events))
	}
	if total != 5 {
		t.Errorf("expected total 5, got %d", total)
	}

	// Newest first
	if events[0].Path != "/v1/4" {
		t.Errorf("expected newest first, got %s", events[0].Path)
	}
	if events[4].Path != "/v1/0" {
		t.Errorf("expected oldest last, got %s", events[4].Path)
	}
}

func TestEventBuffer_SnapshotLimit(t *testing.T) {
	buf := NewEventBuffer()
	for i := 0; i < 20; i++ {
		buf.Record(RequestEvent{Path: fmt.Sprintf("/%d", i)})
	}

	// Request fewer than available
	events, _ := buf.Snapshot(3)
	if len(events) != 3 {
		t.Errorf("expected 3 events, got %d", len(events))
	}
	if events[0].Path != "/19" {
		t.Errorf("expected /19, got %s", events[0].Path)
	}
}

func TestEventBuffer_RingWrap(t *testing.T) {
	buf := NewEventBuffer()

	// Fill past capacity
	for i := 0; i < maxEvents+50; i++ {
		buf.Record(RequestEvent{Path: fmt.Sprintf("/%d", i)})
	}

	events, total := buf.Snapshot(5)
	if total != int64(maxEvents+50) {
		t.Errorf("expected total %d, got %d", maxEvents+50, total)
	}
	if len(events) != 5 {
		t.Errorf("expected 5 events, got %d", len(events))
	}

	// Newest should be the last one written
	expected := fmt.Sprintf("/%d", maxEvents+49)
	if events[0].Path != expected {
		t.Errorf("expected %s, got %s", expected, events[0].Path)
	}
}

func TestEventBuffer_ConcurrentAccess(t *testing.T) {
	buf := NewEventBuffer()

	var wg sync.WaitGroup
	// 10 concurrent writers
	for w := 0; w < 10; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				buf.Record(RequestEvent{
					Method: fmt.Sprintf("W%d", id),
					Path:   fmt.Sprintf("/%d", i),
				})
			}
		}(w)
	}

	// Concurrent reader
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			buf.Snapshot(20)
		}
	}()

	wg.Wait()

	_, total := buf.Snapshot(1)
	if total != 1000 {
		t.Errorf("expected total 1000, got %d", total)
	}
}

func TestEventBuffer_Total(t *testing.T) {
	buf := NewEventBuffer()
	buf.Record(RequestEvent{})
	buf.Record(RequestEvent{})
	buf.Record(RequestEvent{})

	if buf.Total() != 3 {
		t.Errorf("expected Total() = 3, got %d", buf.Total())
	}
}
