package main

import (
	"errors"
	"net"
	"strings"
)

// ErrCaptchaScoreTooLow indicates the reCAPTCHA v3 score was too low (identity-based policy denial).
// This error signals that a new captcha token should be fetched, not a session rotation.
var ErrCaptchaScoreTooLow = errors.New("captcha score too low")

// =============================================================================
// Fatal Errors
// =============================================================================

// FatalError represents an error that should stop the task immediately.
// These are typically billing/authentication issues where retrying won't help.
type FatalError struct {
	Err error
}

func (e *FatalError) Error() string {
	return e.Err.Error()
}

func (e *FatalError) Unwrap() error {
	return e.Err
}

// NewFatalError wraps an error as fatal.
func NewFatalError(err error) error {
	return &FatalError{Err: err}
}

// IsFatalError checks if the error is a fatal error that should stop the task.
func IsFatalError(err error) bool {
	if err == nil {
		return false
	}
	var fe *FatalError
	return errors.As(err, &fe)
}

// fatalErrorStrings contains substrings that indicate a fatal error.
var fatalErrorStrings = []string{
	"ERROR_ZERO_BALANCE",
	"ERROR_KEY_DOES_NOT_EXIST",
	"ERROR_WRONG_USER_KEY",
	"ERROR_WRONG_GOOGLEKEY",
	"access denied",
}

// ContainsFatalErrorString checks if an error message contains a fatal error indicator.
func ContainsFatalErrorString(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	for _, s := range fatalErrorStrings {
		if strings.Contains(errStr, strings.ToLower(s)) {
			return true
		}
	}
	return false
}

// =============================================================================
// Retryable Errors
// =============================================================================

// retryableErrorPatterns contains error message substrings that indicate retryable errors.
var retryableErrorPatterns = []string{
	"connection refused",
	"connection reset",
	"no such host",
	"i/o timeout",
	"context deadline exceeded",
	"TLS handshake timeout",
	"EOF",
	"malformed HTTP response",
	"transport connection broken",
	"use of closed network connection",
}

// IsRetryableError checks if the error is temporary and worth retrying with a new proxy.
func IsRetryableError(err error) bool {
	if err == nil {
		return false
	}

	if IsFatalError(err) || ContainsFatalErrorString(err) {
		return false
	}

	if isNetworkTimeout(err) {
		return true
	}

	return containsRetryablePattern(err.Error())
}

func isNetworkTimeout(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout() || netErr.Temporary()
	}
	return false
}

func containsRetryablePattern(errStr string) bool {
	for _, pattern := range retryableErrorPatterns {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}
	return false
}
