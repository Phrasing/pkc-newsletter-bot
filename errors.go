package main

import (
	"errors"
	"net"
	"strings"
)

var (
	ErrCaptchaScoreTooLow = errors.New("captcha score too low")
	ErrRetryNeeded        = errors.New("retry needed")
	ErrProxyBadRequest    = errors.New("proxy bad request")
)

type FatalError struct {
	Err error
}

func (e *FatalError) Error() string {
	return e.Err.Error()
}

func (e *FatalError) Unwrap() error {
	return e.Err
}

func NewFatalError(err error) error {
	return &FatalError{Err: err}
}

func IsFatalError(err error) bool {
	if err == nil {
		return false
	}
	var fe *FatalError
	return errors.As(err, &fe)
}

var fatalErrorStrings = []string{
	"ERROR_ZERO_BALANCE",
	"ERROR_KEY_DOES_NOT_EXIST",
	"ERROR_WRONG_USER_KEY",
	"ERROR_WRONG_GOOGLEKEY",
	"access denied",
}

func ContainsFatalErrorString(err error) bool {
	if err == nil {
		return false
	}
	return containsAnyString(err.Error(), fatalErrorStrings)
}

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

func IsRetryableError(err error) bool {
	if err == nil || IsFatalError(err) || ContainsFatalErrorString(err) {
		return false
	}
	if errors.Is(err, ErrProxyBadRequest) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && (netErr.Timeout() || netErr.Temporary()) {
		return true
	}
	return containsAnyString(err.Error(), retryableErrorPatterns)
}

func containsAnyString(str string, patterns []string) bool {
	str = strings.ToLower(str)
	for _, pattern := range patterns {
		if strings.Contains(str, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}
