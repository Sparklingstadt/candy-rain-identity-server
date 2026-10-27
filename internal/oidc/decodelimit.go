package oidc

import (
	"context"
	"time"
)

const (
	// maxConcurrentDecodes bounds the memory that image decoding can take in
	// one process (Vercel Fluid compute runs many requests per instance).
	maxConcurrentDecodes = 2
	// decodeWait is how long an upload waits for a free slot before it is
	// turned away; uploads never queue without limit.
	decodeWait = 5 * time.Second
)

// decodeLimiter is a counting semaphore with a bounded wait.
type decodeLimiter struct {
	slots chan struct{}
	wait  time.Duration
	// after is time.After, overridable in tests.
	after func(time.Duration) <-chan time.Time
}

func newDecodeLimiter(n int, wait time.Duration) *decodeLimiter {
	return &decodeLimiter{slots: make(chan struct{}, n), wait: wait, after: time.After}
}

// processDecodes is shared by every Server in the process.
var processDecodes = newDecodeLimiter(maxConcurrentDecodes, decodeWait)

func newServerDecodeLimiter() *decodeLimiter { return processDecodes }

// acquire takes a slot, waiting at most l.wait. It returns false when the
// wait runs out or the request ends first; the caller must not release then.
func (l *decodeLimiter) acquire(ctx context.Context) bool {
	select {
	case l.slots <- struct{}{}:
		return true
	default:
	}
	select {
	case l.slots <- struct{}{}:
		return true
	case <-l.after(l.wait):
		return false
	case <-ctx.Done():
		return false
	}
}

func (l *decodeLimiter) release() { <-l.slots }
