package main

import (
	"context"
	"io"
	"log"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/joho/godotenv"
)

var (
	targetSignups int
	workerCount   int
	engineLog     *log.Logger
)

const workerStaggerDelay = 50 * time.Millisecond

type moduleLogger struct {
	logger *log.Logger
}

func (m *moduleLogger) Log(format string, args ...any) {
	m.logger.Printf("      "+format, args...)
}

func main() {
	parseArgs()

	engineLogFile, moduleLogFile, modLog := setupLogging()
	defer engineLogFile.Close()
	defer moduleLogFile.Close()

	_ = godotenv.Load()

	proxyManager, captchaKey := loadResources()
	scheduler := createScheduler(proxyManager, captchaKey, modLog)

	exitCode := run(scheduler)
	os.Exit(exitCode)
}

func parseArgs() {
	if len(os.Args) < 3 {
		log.Fatal("Usage: pkc [catchall-domain] <target-signups> <worker-count>\nExamples:\n  pkc fiercloud.com 500 100  (generate emails)\n  pkc 500 100                 (use emails.txt)")
	}

	var err error

	if _, err = strconv.Atoi(os.Args[1]); err == nil {
		if len(os.Args) < 3 {
			log.Fatal("Usage: pkc <target-signups> <worker-count>")
		}
		targetSignups, _ = strconv.Atoi(os.Args[1])
		workerCount, err = strconv.Atoi(os.Args[2])
		if err != nil || workerCount <= 0 {
			log.Fatal("worker-count must be a positive integer")
		}
	} else {
		if len(os.Args) < 4 {
			log.Fatal("Usage: pkc <catchall-domain> <target-signups> <worker-count>")
		}
		catchallDomain = os.Args[1]
		targetSignups, err = strconv.Atoi(os.Args[2])
		if err != nil || targetSignups <= 0 {
			log.Fatal("target-signups must be a positive integer")
		}
		workerCount, err = strconv.Atoi(os.Args[3])
		if err != nil || workerCount <= 0 {
			log.Fatal("worker-count must be a positive integer")
		}
	}

	if targetSignups <= 0 {
		log.Fatal("target-signups must be a positive integer")
	}
}

func setupLogging() (engineLogFile, moduleLogFile *os.File, modLog *log.Logger) {
	var err error

	engineLogFile, err = os.OpenFile("engine.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open engine log file: %v", err)
	}
	engineLog = log.New(io.MultiWriter(os.Stdout, engineLogFile), "", log.LstdFlags)

	moduleLogFile, err = os.OpenFile("pkc.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		engineLog.Fatalf("Failed to open module log file: %v", err)
	}
	modLog = log.New(io.MultiWriter(os.Stdout, moduleLogFile), "", log.LstdFlags)

	return engineLogFile, moduleLogFile, modLog
}

func loadResources() (*ProxyManager, string) {
	proxyManager, err := NewProxyManager("proxies.txt")
	if err != nil {
		engineLog.Fatalf("Failed to load proxies: %v", err)
	}
	engineLog.Printf("Loaded %d proxies", proxyManager.Count())

	hasCapMonster := GetCapMonsterAPIKey() != ""
	has2Captcha := GetCaptchaAPIKey() != ""
	hasCapSolver := GetCapSolverAPIKey() != ""

	if !hasCapMonster && !has2Captcha && !hasCapSolver {
		engineLog.Fatal("No captcha providers configured. Set at least one: CAPMONSTER_KEY, 2CAP_KEY, or CAPSOLVER_KEY")
	}

	return proxyManager, ""
}

func createScheduler(proxyManager *ProxyManager, captchaKey string, modLog *log.Logger) *Scheduler {
	scheduler, err := NewScheduler(workerCount, proxyManager, captchaKey, workerStaggerDelay, &moduleLogger{logger: modLog})
	if err != nil {
		engineLog.Fatalf("Failed to create scheduler: %v", err)
	}
	return scheduler
}

func run(scheduler *Scheduler) int {
	engineLog.Printf("Starting %d concurrent workers (target: %d signups, stagger: %v)...", workerCount, targetSignups, workerStaggerDelay)

	emailGen := NewEmailGenerator()
	if catchallDomain != "" {
		engineLog.Printf("Using catchall domain: %s", catchallDomain)
	} else {
		if emailGen.Count() == 0 {
			engineLog.Fatal("No emails found in emails.txt")
		}
		engineLog.Printf("Using %d emails from emails.txt", emailGen.Count())
	}

	ctx := context.Background()
	scheduler.Start(ctx)

	// Submit emails to workers
	go func() {
		for range targetSignups {
			scheduler.Submit(emailGen.Next())
		}
	}()

	// Collect results
	var successCount int32
	var fatalErr error

	for result := range scheduler.Results() {
		if result.Fatal {
			fatalErr = result.Error
			engineLog.Printf("FATAL ERROR: %v", result.Error)
			break
		}

		if result.Success {
			count := atomic.AddInt32(&successCount, 1)
			engineLog.Printf("[%d/%d] SUCCESS: %s", count, targetSignups, result.Email)
		}

		if int(atomic.LoadInt32(&successCount)) >= targetSignups {
			break
		}
	}

	scheduler.Close()

	if fatalErr != nil {
		engineLog.Printf("=== ABORTED: %d successful signups (fatal error: %v) ===", successCount, fatalErr)
		return 1
	}

	engineLog.Printf("=== Complete: %d successful signups ===", successCount)
	return 0
}
