package main

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

type TaskResult struct {
	Email   string
	Success bool
	Error   error
	Fatal   bool
}

type Worker struct {
	id           string
	client       *PKCClient
	proxyManager *ProxyManager
	logger       Logger
}

type Scheduler struct {
	workers        []*Worker
	workChan       chan string
	resultsChan    chan TaskResult
	wg             sync.WaitGroup
	captchaManager *CaptchaProviderManager
	proxyManager   *ProxyManager
	logger         Logger
	staggerDelay   time.Duration
	cancel         context.CancelFunc
	fatalOnce      sync.Once
	stopped        atomic.Bool
}

func NewScheduler(workerCount int, proxyManager *ProxyManager, captchaKey string, staggerDelay time.Duration, logger Logger) (*Scheduler, error) {
	captchaManager := NewCaptchaProviderManager()
	if captchaManager.Count() == 0 {
		logger.Log("WARNING: No captcha providers configured")
	} else {
		logger.Log("Initialized %d captcha provider(s): %v", captchaManager.Count(), captchaManager.Providers())
	}

	s := &Scheduler{
		workers:        make([]*Worker, workerCount),
		workChan:       make(chan string, workerCount*2),
		resultsChan:    make(chan TaskResult, workerCount*2),
		captchaManager: captchaManager,
		proxyManager:   proxyManager,
		logger:         logger,
		staggerDelay:   staggerDelay,
	}

	for i := 0; i < workerCount; i++ {
		worker, err := s.createWorker()
		if err != nil {
			return nil, err
		}
		s.workers[i] = worker
	}

	return s, nil
}

func generateWorkerID() string {
	return uuid.New().String()[:8]
}

func (s *Scheduler) createWorker() (*Worker, error) {
	id := generateWorkerID()
	proxyURL, proxyIdx := s.proxyManager.Random()

	workerLogger := &workerLogger{id: id, base: s.logger}
	workerLogger.Log("Using proxy: %s", s.proxyManager.DisplayAt(proxyIdx))

	client, err := NewClient(nil, proxyURL)
	if err != nil {
		return nil, err
	}

	session := NewHyperSession()
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

func (s *Scheduler) Start(ctx context.Context) {
	ctx, s.cancel = context.WithCancel(ctx)

	for i, worker := range s.workers {
		s.wg.Add(1)
		go s.runWorker(ctx, worker)

		if s.staggerDelay > 0 && i < len(s.workers)-1 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(s.staggerDelay):
			}
		}
	}
}

func (s *Scheduler) handleFatalError(err error) {
	s.fatalOnce.Do(func() {
		s.stopped.Store(true)
		s.logger.Log("FATAL ERROR: %v - stopping all workers", err)

		if s.cancel != nil {
			s.cancel()
		}

		select {
		case s.resultsChan <- TaskResult{Fatal: true, Error: err}:
		default:
		}
	})
}

func (s *Scheduler) isFatal(err error) bool {
	return IsFatalError(err) || ContainsFatalErrorString(err)
}

func (s *Scheduler) runWorker(ctx context.Context, worker *Worker) {
	defer s.wg.Done()

	if err := s.initWorkerWithRetry(ctx, worker, 5); err != nil {
		if s.isFatal(err) {
			s.handleFatalError(err)
			return
		}
		worker.logger.Log("Failed to initialize after retries: %v", err)
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case email, ok := <-s.workChan:
			if !ok {
				return // Channel closed, exit
			}

			for {
				if s.stopped.Load() {
					return
				}

				worker.logger.Log("Processing: %s", email)

				provider := s.captchaManager.Next()
				if provider == nil {
					worker.logger.Log("ERROR: No captcha providers available")
					select {
					case s.resultsChan <- TaskResult{Email: email, Success: false, Error: fmt.Errorf("no captcha providers configured")}:
					case <-ctx.Done():
						return
					}
					break
				}

				signedUpEmail, err := worker.client.EmailSignup(ctx, provider, email)

				if err == nil {
					select {
					case s.resultsChan <- TaskResult{Email: signedUpEmail, Success: true}:
					case <-ctx.Done():
						return
					}
					break
				}

				if s.isFatal(err) {
					s.handleFatalError(err)
					return
				}

				worker.logger.Log("Failed: %v, rotating session...", err)
				if err := s.resetWorkerSession(ctx, worker); err != nil {
					if s.isFatal(err) {
						s.handleFatalError(err)
						return
					}
				}
			}
		}
	}
}

func (s *Scheduler) initWorkerWithRetry(ctx context.Context, worker *Worker, maxRetries int) error {
	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if s.stopped.Load() {
			return lastErr
		}

		if attempt > 0 {
			s.rotateWorkerProxy(worker)
		}

		worker.logger.Log("Initializing session...")
		if err := worker.client.InitializeSession(ctx); err != nil {
			lastErr = err
			worker.logger.Log("Session init failed (attempt %d/%d): %v", attempt+1, maxRetries, err)

			if s.isFatal(err) {
				return err
			}
			continue
		}
		return nil
	}
	return lastErr
}

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
