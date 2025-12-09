package main

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// TaskResult represents the result of a signup task.
type TaskResult struct {
	Email   string
	Success bool
	Error   error
	Fatal   bool // If true, this is a fatal error and all workers should stop
}

// Worker represents a concurrent worker with its own client session.
type Worker struct {
	id           string // Short UUID (8 chars) for identification
	client       *PKCClient
	proxyManager *ProxyManager
	logger       Logger
}

// Scheduler manages concurrent email signup tasks.
type Scheduler struct {
	workers      []*Worker
	workChan     chan string
	resultsChan  chan TaskResult
	wg           sync.WaitGroup
	captchaKey   string
	proxyManager *ProxyManager
	logger       Logger
	staggerDelay time.Duration      // Delay between starting each worker
	cancel       context.CancelFunc // Cancel function to stop all workers
	fatalOnce    sync.Once          // Ensures fatal error is only sent once
	stopped      atomic.Bool        // Flag to indicate scheduler has been stopped
}

// NewScheduler creates a new task scheduler with the specified number of workers.
func NewScheduler(workerCount int, proxyManager *ProxyManager, captchaKey string, staggerDelay time.Duration, logger Logger) (*Scheduler, error) {
	s := &Scheduler{
		workers:      make([]*Worker, workerCount),
		workChan:     make(chan string, workerCount*2), // Buffer for some emails
		resultsChan:  make(chan TaskResult, workerCount*2),
		captchaKey:   captchaKey,
		proxyManager: proxyManager,
		logger:       logger,
		staggerDelay: staggerDelay,
	}

	// Initialize workers, each with their own client and proxy
	for i := 0; i < workerCount; i++ {
		worker, err := s.createWorker()
		if err != nil {
			return nil, err
		}
		s.workers[i] = worker
	}

	return s, nil
}

// generateWorkerID creates a short UUID (first 8 characters) for worker identification.
func generateWorkerID() string {
	return uuid.New().String()[:8]
}

// createWorker creates a new worker with its own client session.
func (s *Scheduler) createWorker() (*Worker, error) {
	// Generate unique worker ID
	id := generateWorkerID()

	// Get a random proxy for this worker
	proxyURL, proxyIdx := s.proxyManager.Random()

	// Create worker logger that prefixes with worker ID
	workerLogger := &workerLogger{id: id, base: s.logger}
	workerLogger.Log("Using proxy: %s", s.proxyManager.DisplayAt(proxyIdx))

	// Create HTTP client with its own proxy
	client, err := NewClient(nil, proxyURL)
	if err != nil {
		return nil, err
	}

	// Create Hyper session for this worker
	session := NewHyperSession()

	// Create PKC client
	pkc := NewPKCClient(client, session, workerLogger, proxyURL)
	pkc.SetProxyManager(s.proxyManager)

	return &Worker{
		id:           id,
		client:       pkc,
		proxyManager: s.proxyManager,
		logger:       workerLogger,
	}, nil
}

// workerLogger wraps a logger with worker ID prefix.
type workerLogger struct {
	id   string
	base Logger
}

func (w *workerLogger) Log(format string, args ...any) {
	w.base.Log("[%s] "+format, append([]any{w.id}, args...)...)
}

// Start begins processing emails with the worker pool.
// Workers are started with a stagger delay to avoid overwhelming APIs at startup.
func (s *Scheduler) Start(ctx context.Context) {
	ctx, s.cancel = context.WithCancel(ctx)

	for i, worker := range s.workers {
		s.wg.Add(1)
		go s.runWorker(ctx, worker)

		// Stagger worker startup (skip delay for last worker)
		if s.staggerDelay > 0 && i < len(s.workers)-1 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(s.staggerDelay):
			}
		}
	}
}

// handleFatalError is called when a fatal error occurs. It stops all workers.
func (s *Scheduler) handleFatalError(err error) {
	s.fatalOnce.Do(func() {
		s.stopped.Store(true)
		s.logger.Log("FATAL ERROR: %v - stopping all workers", err)

		// Cancel all workers
		if s.cancel != nil {
			s.cancel()
		}

		// Send fatal result to notify main loop
		select {
		case s.resultsChan <- TaskResult{Fatal: true, Error: err}:
		default:
			// Channel full or closed, that's ok
		}
	})
}

// isFatal checks if an error should stop all workers.
func (s *Scheduler) isFatal(err error) bool {
	return IsFatalError(err) || ContainsFatalErrorString(err)
}

// runWorker processes emails from the work channel.
func (s *Scheduler) runWorker(ctx context.Context, worker *Worker) {
	defer s.wg.Done()

	// Initialize this worker's session, retry with fresh proxy on failure
	if err := s.initWorkerWithRetry(ctx, worker, 5); err != nil {
		// Check if it's a fatal error
		if s.isFatal(err) {
			s.handleFatalError(err)
			return
		}
		worker.logger.Log("Failed to initialize after retries: %v", err)
		return // Worker exits if can't initialize
	}

	for {
		select {
		case <-ctx.Done():
			return
		case email, ok := <-s.workChan:
			if !ok {
				return // Channel closed, exit
			}

			// Retry loop - keep trying same email with fresh session/proxy until success
			for {
				// Check if scheduler has been stopped
				if s.stopped.Load() {
					return
				}

				worker.logger.Log("Processing: %s", email)

				signedUpEmail, err := worker.client.EmailSignup(ctx, s.captchaKey, email)

				if err == nil {
					// Success - send result and move to next email
					select {
					case s.resultsChan <- TaskResult{Email: signedUpEmail, Success: true}:
					case <-ctx.Done():
						return
					}
					break // Exit retry loop, get next email
				}

				// Check if it's a fatal error - stop everything
				if s.isFatal(err) {
					s.handleFatalError(err)
					return
				}

				// Non-fatal failure - rotate proxy and session, then retry same email
				worker.logger.Log("Failed: %v, rotating session...", err)
				if err := s.resetWorkerSession(ctx, worker); err != nil {
					// Check if reset resulted in fatal error
					if s.isFatal(err) {
						s.handleFatalError(err)
						return
					}
				}
			}
		}
	}
}

// initWorkerWithRetry attempts to initialize a worker's session, rotating proxies on failure.
// Returns immediately on fatal errors without retrying.
func (s *Scheduler) initWorkerWithRetry(ctx context.Context, worker *Worker, maxRetries int) error {
	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		// Check if scheduler has been stopped
		if s.stopped.Load() {
			return lastErr
		}

		if attempt > 0 {
			// Rotate to a new proxy before retrying
			s.rotateWorkerProxy(worker)
		}

		worker.logger.Log("Initializing session...")
		if err := worker.client.InitializeSession(ctx); err != nil {
			lastErr = err
			worker.logger.Log("Session init failed (attempt %d/%d): %v", attempt+1, maxRetries, err)

			// Don't retry fatal errors
			if s.isFatal(err) {
				return err
			}
			continue
		}
		return nil // Success
	}
	return lastErr
}

// rotateWorkerProxy switches a worker to a new random proxy without initializing.
func (s *Scheduler) rotateWorkerProxy(worker *Worker) {
	proxyURL, proxyIdx := s.proxyManager.Random()
	worker.logger.Log("Rotating to proxy: %s", s.proxyManager.DisplayAt(proxyIdx))

	client, err := NewClient(nil, proxyURL)
	if err != nil {
		worker.logger.Log("Failed to create new client: %v", err)
		return
	}

	session := NewHyperSession()
	pkc := NewPKCClient(client, session, worker.logger, proxyURL)
	pkc.SetProxyManager(s.proxyManager)
	worker.client = pkc
}

// resetWorkerSession creates a fresh client with a new random proxy and initializes it.
// Returns the last error if initialization fails after retries.
func (s *Scheduler) resetWorkerSession(ctx context.Context, worker *Worker) error {
	// Rotate first since current proxy/session already failed
	s.rotateWorkerProxy(worker)

	// Then use retry logic to ensure we get a working session
	if err := s.initWorkerWithRetry(ctx, worker, 3); err != nil {
		worker.logger.Log("Session reset failed after retries: %v", err)
		return err
	}
	return nil
}

// Submit adds an email to the work queue.
func (s *Scheduler) Submit(email string) {
	s.workChan <- email
}

// Results returns the results channel for reading task outcomes.
func (s *Scheduler) Results() <-chan TaskResult {
	return s.resultsChan
}

// Close shuts down the scheduler and waits for workers to finish.
func (s *Scheduler) Close() {
	close(s.workChan)
	s.wg.Wait()
	close(s.resultsChan)
}

// WorkerCount returns the number of workers.
func (s *Scheduler) WorkerCount() int {
	return len(s.workers)
}
