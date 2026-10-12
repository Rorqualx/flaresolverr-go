package session

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Rorqualx/flaresolverr-go/internal/types"
)

func TestLockOperation_ZeroValueSession(t *testing.T) {
	var s Session // no constructor: the slot must be created on demand

	if err := s.LockOperation(context.Background()); err != nil {
		t.Fatalf("LockOperation on a free session: %v", err)
	}
	s.UnlockOperation()

	if err := s.LockOperation(context.Background()); err != nil {
		t.Fatalf("LockOperation after unlock: %v", err)
	}
	s.UnlockOperation()
}

// TestLockOperation_WaiterGivesUpAtItsDeadline is the defect this lock fixes:
// a request queued behind a long solve must fail at its own deadline rather
// than wait for the holder.
func TestLockOperation_WaiterGivesUpAtItsDeadline(t *testing.T) {
	var s Session
	if err := s.LockOperation(context.Background()); err != nil {
		t.Fatalf("first lock: %v", err)
	}
	defer s.UnlockOperation()

	const wait = 100 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()

	start := time.Now()
	err := s.LockOperation(ctx)
	elapsed := time.Since(start)

	if !errors.Is(err, types.ErrSessionInUse) {
		t.Fatalf("LockOperation on a busy session = %v, want ErrSessionInUse", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error does not wrap the context error: %v", err)
	}
	if elapsed < wait || elapsed > wait+2*time.Second {
		t.Errorf("gave up after %v, want about %v", elapsed, wait)
	}
}

func TestLockOperation_WaiterGetsSlotWhenReleased(t *testing.T) {
	var s Session
	if err := s.LockOperation(context.Background()); err != nil {
		t.Fatalf("first lock: %v", err)
	}

	acquired := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		acquired <- s.LockOperation(ctx)
	}()

	select {
	case err := <-acquired:
		t.Fatalf("second lock returned while the first was held: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	s.UnlockOperation()

	select {
	case err := <-acquired:
		if err != nil {
			t.Fatalf("waiter did not get the released slot: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiter still blocked after the slot was released")
	}
	s.UnlockOperation()
}

func TestLockOperation_FreeSlotWinsOverDoneContext(t *testing.T) {
	var s Session
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// A free session is usable even if the caller's context has just ended;
	// the caller's next step will observe the cancellation.
	for i := 0; i < 50; i++ {
		if err := s.LockOperation(ctx); err != nil {
			t.Fatalf("iteration %d: free slot not taken with a done context: %v", i, err)
		}
		s.UnlockOperation()
	}
}

func TestUnlockOperation_WithoutLockDoesNotBlockOrPanic(t *testing.T) {
	var s Session
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.UnlockOperation()
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("UnlockOperation without a lock blocked")
	}

	// The slot must still work afterwards
	if err := s.LockOperation(context.Background()); err != nil {
		t.Fatalf("lock after stray unlock: %v", err)
	}
	s.UnlockOperation()
}

// TestLockOperation_Queue runs many requests at one session (use -race): the
// slot is exclusive, every request either runs or times out, and none hangs.
func TestLockOperation_Queue(t *testing.T) {
	var s Session
	const (
		workers  = 40
		holdTime = 5 * time.Millisecond
	)

	var (
		inside    atomic.Int32
		maxInside atomic.Int32
		ran       atomic.Int32
		timedOut  atomic.Int32
		wg        sync.WaitGroup
	)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			// Half the workers have a deadline too short to reach the front
			timeout := 10 * time.Second
			if i%2 == 1 {
				timeout = 20 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			if err := s.LockOperation(ctx); err != nil {
				if !errors.Is(err, types.ErrSessionInUse) {
					t.Errorf("unexpected error: %v", err)
				}
				timedOut.Add(1)
				return
			}
			defer s.UnlockOperation()

			now := inside.Add(1)
			for {
				seen := maxInside.Load()
				if now <= seen || maxInside.CompareAndSwap(seen, now) {
					break
				}
			}
			time.Sleep(holdTime)
			inside.Add(-1)
			ran.Add(1)
		}(i)
	}

	finished := make(chan struct{})
	go func() {
		wg.Wait()
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(30 * time.Second):
		t.Fatal("queued requests did not all finish")
	}

	if got := maxInside.Load(); got != 1 {
		t.Errorf("%d requests held the session at once, want 1", got)
	}
	if got := ran.Load() + timedOut.Load(); got != workers {
		t.Errorf("%d of %d requests accounted for", got, workers)
	}
	if ran.Load() < workers/2 {
		t.Errorf("only %d requests ran; the %d with a long deadline must all get through", ran.Load(), workers/2)
	}

	// The slot is free again at the end
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.LockOperation(ctx); err != nil {
		t.Fatalf("slot not free after the queue drained: %v", err)
	}
	s.UnlockOperation()
}
