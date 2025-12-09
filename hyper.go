package main

import (
	"sync"

	"github.com/Hyper-Solutions/hyper-sdk-go/v2"
)

// HyperRateLimiter limits concurrent Hyper API calls to avoid "access denied" errors.
type HyperRateLimiter struct {
	sem chan struct{}
}

var (
	hyperLimiter     *HyperRateLimiter
	hyperLimiterOnce sync.Once
)

func GetHyperLimiter(maxConcurrent int) *HyperRateLimiter {
	hyperLimiterOnce.Do(func() {
		hyperLimiter = &HyperRateLimiter{
			sem: make(chan struct{}, maxConcurrent),
		}
	})
	return hyperLimiter
}

func (h *HyperRateLimiter) Acquire() {
	h.sem <- struct{}{}
}

func (h *HyperRateLimiter) Release() {
	<-h.sem
}

// NewHyperSession uses HYPER_API_KEY from build-time or environment.
func NewHyperSession() *hyper.Session {
	return hyper.NewSession(GetHyperAPIKey())
}
