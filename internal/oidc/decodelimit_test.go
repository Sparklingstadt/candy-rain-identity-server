package oidc

import (
	"context"
	"strings"
	"testing"
	"time"
)

// fakeTimer hands out channels the test fires by hand.
type fakeTimer struct{ fired chan time.Time }

func (f *fakeTimer) after(time.Duration) <-chan time.Time { return f.fired }

func TestDecodeLimiterRejectsThirdDecodeAfterWaiting(t *testing.T) {
	timer := &fakeTimer{fired: make(chan time.Time)}
	l := newDecodeLimiter(2, 5*time.Second)
	l.after = timer.after
	ctx := context.Background()

	if !l.acquire(ctx) || !l.acquire(ctx) {
		t.Fatal("the first two decodes must start at once")
	}
	got := make(chan bool)
	go func() { got <- l.acquire(ctx) }()
	select {
	case ok := <-got:
		t.Fatalf("third decode did not wait: %v", ok)
	case <-time.After(50 * time.Millisecond):
	}
	timer.fired <- time.Now() // the wait (about 5 s) runs out
	if ok := <-got; ok {
		t.Fatal("third decode must be rejected when the wait runs out")
	}

	// When a slot frees up within the wait, the waiting decode gets it.
	go func() { got <- l.acquire(ctx) }()
	time.Sleep(20 * time.Millisecond)
	l.release()
	if ok := <-got; !ok {
		t.Fatal("a waiting decode should get the freed slot")
	}
	l.release()
	l.release()
	if !l.acquire(ctx) {
		t.Fatal("slots are not returned")
	}
}

func TestDecodeLimiterGivesUpWhenTheRequestEnds(t *testing.T) {
	l := newDecodeLimiter(1, time.Hour)
	l.acquire(context.Background())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if l.acquire(ctx) {
		t.Fatal("acquired after the request was cancelled")
	}
}

func TestDefaultDecodeLimit(t *testing.T) {
	l := newServerDecodeLimiter()
	if cap(l.slots) != 2 || l.wait != 5*time.Second {
		t.Fatalf("slots %d wait %v", cap(l.slots), l.wait)
	}
}

// With every slot taken, an upload is turned away with a fixed message
// instead of queueing.
func TestAvatarUploadWhenBusy(t *testing.T) {
	h := newHarness(t)
	timer := &fakeTimer{fired: make(chan time.Time, 1)}
	timer.fired <- time.Now()
	h.srv.decodes = newDecodeLimiter(2, 5*time.Second)
	h.srv.decodes.after = timer.after
	ctx := context.Background()
	h.srv.decodes.acquire(ctx)
	h.srv.decodes.acquire(ctx)

	csrf := h.accountLogin()
	loc, page := h.uploadAndFollow(csrf, pngOf(4, 4))
	if loc != "/account?error=busy" || !strings.Contains(page, msgBusy) {
		t.Fatalf("location %q", loc)
	}
	if _, ok := h.avatar(); ok {
		t.Fatal("stored while busy")
	}

	// Once a slot is free the same upload goes through, and the slot is
	// returned afterwards.
	h.srv.decodes.release()
	if loc, _ := h.uploadAndFollow(csrf, pngOf(4, 4)); loc != "/account?done=updated" {
		t.Fatalf("after release: %q", loc)
	}
	if len(h.srv.decodes.slots) != 1 {
		t.Fatalf("slot leaked: %d in use", len(h.srv.decodes.slots))
	}
}
